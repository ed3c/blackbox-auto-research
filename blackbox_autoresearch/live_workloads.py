"""Disposable integration workloads for advancing domain validation to L2 SANDBOX.

These helpers execute real stdlib-backed processes, HTTP servers and SQLite state in
CI. They intentionally do not claim external-provider L3 LIVE maturity.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
from typing import Callable, Iterator


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class WorkloadEvidence:
    workload: str
    action: str
    outcome_digest: str
    verifier: str
    passed: bool
    metadata: dict[str, str]


class RepositoryCLIWorkload:
    def run(self) -> WorkloadEvidence:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "result.txt"
            subprocess.run(
                [sys.executable, "-c", "from pathlib import Path; Path('result.txt').write_text('fixed\\n')"],
                cwd=root,
                check=True,
            )
            data = target.read_bytes()
            passed = data == b"fixed\n"
            return WorkloadEvidence(
                "repository-cli",
                "subprocess writes externally verified file state",
                sha256_bytes(data),
                "file-content-verifier",
                passed,
                {"exit": "0"},
            )


class _MCPHandler(BaseHTTPRequestHandler):
    calls: list[str] = []

    def log_message(self, *_args) -> None:  # pragma: no cover - silence fixture server
        return

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        tool = payload.get("tool")
        self.__class__.calls.append(str(tool))
        body = json.dumps({"ok": tool == "lookup", "tool": tool}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextmanager
def local_mcp_server() -> Iterator[tuple[str, int]]:
    _MCPHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _MCPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield str(host), int(port)
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def run_mcp_routing_workload() -> WorkloadEvidence:
    with local_mcp_server() as (host, port):
        conn = http.client.HTTPConnection(host, port, timeout=2)
        payload = json.dumps({"tool": "lookup", "arguments": {"q": "probe"}})
        conn.request("POST", "/tools/call", body=payload, headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        body = response.read()
        conn.close()
        passed = response.status == 200 and _MCPHandler.calls == ["lookup"] and json.loads(body)["ok"]
        return WorkloadEvidence(
            "mcp-routing",
            "HTTP tool call to disposable MCP-shaped server",
            sha256_bytes(body),
            "tool-call-log-verifier",
            passed,
            {"calls": json.dumps(_MCPHandler.calls)},
        )


class StatefulAPI:
    def __init__(self) -> None:
        self.state = "created"

    def transition(self, action: str) -> str:
        allowed = {("created", "start"): "running", ("running", "finish"): "finished"}
        key = (self.state, action)
        if key not in allowed:
            raise ValueError(f"invalid transition: {self.state}->{action}")
        self.state = allowed[key]
        return self.state


def run_api_state_machine_workload() -> WorkloadEvidence:
    api = StatefulAPI()
    api.transition("start")
    api.transition("finish")
    final = api.state.encode()
    invalid_rejected = False
    try:
        api.transition("start")
    except ValueError:
        invalid_rejected = True
    return WorkloadEvidence(
        "api-state-machine",
        "execute allowed transitions and reject invalid transition",
        sha256_bytes(final),
        "state-machine-verifier",
        api.state == "finished" and invalid_rejected,
        {"final_state": api.state, "invalid_rejected": str(invalid_rejected).lower()},
    )


def run_sqlite_etl_workload() -> WorkloadEvidence:
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "etl.sqlite3"
        conn = sqlite3.connect(db)
        conn.execute("create table source(id integer primary key, amount integer not null)")
        conn.execute("create table target(id integer primary key, amount integer not null)")
        conn.executemany("insert into source(id, amount) values(?, ?)", [(1, 10), (2, 20), (3, 30)])
        conn.commit()
        source_sum = conn.execute("select sum(amount) from source").fetchone()[0]
        conn.execute("begin")
        conn.execute("insert into target select id, amount from source")
        target_sum = conn.execute("select sum(amount) from target").fetchone()[0]
        invariant = source_sum == target_sum
        conn.rollback()
        rolled_back = conn.execute("select count(*) from target").fetchone()[0] == 0
        conn.close()
        payload = json.dumps({"source_sum": source_sum, "target_sum": target_sum, "rolled_back": rolled_back}, sort_keys=True).encode()
        return WorkloadEvidence(
            "sqlite-etl",
            "transactional ETL with invariant and rollback",
            sha256_bytes(payload),
            "sum-and-rollback-verifier",
            invariant and rolled_back,
            {"source_sum": str(source_sum), "target_sum": str(target_sum), "rolled_back": str(rolled_back).lower()},
        )


def run_ci_remediation_workload() -> WorkloadEvidence:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        test_file = root / "test_target.py"
        test_file.write_text("import unittest\n\nclass T(unittest.TestCase):\n    def test_value(self): self.assertEqual(1 + 1, 3)\n")
        failing = subprocess.run([sys.executable, "-m", "unittest", "-q"], cwd=root, capture_output=True).returncode != 0
        test_file.write_text("import unittest\n\nclass T(unittest.TestCase):\n    def test_value(self): self.assertEqual(1 + 1, 2)\n")
        repaired = subprocess.run([sys.executable, "-m", "unittest", "-q"], cwd=root, capture_output=True).returncode == 0
        data = test_file.read_bytes()
        return WorkloadEvidence(
            "ci-remediation",
            "seed failing disposable test then repair it",
            sha256_bytes(data),
            "before-fails-after-passes-verifier",
            failing and repaired,
            {"seeded_failure": str(failing).lower(), "repaired": str(repaired).lower()},
        )


def differential_check(baseline: Callable[[int], int], candidate: Callable[[int], int], samples: tuple[int, ...]) -> bool:
    return any(baseline(value) != candidate(value) for value in samples)


def metamorphic_check(transform: Callable[[int], int], samples: tuple[int, ...]) -> bool:
    """Checks the declared invariant f(x + 1) == f(x) + 2 for a doubling transform."""
    return all(transform(value + 1) == transform(value) + 2 for value in samples)


def evidence_envelope(items: tuple[WorkloadEvidence, ...]) -> dict[str, object]:
    return {
        "schema": "blackbox-domain-evidence/v1",
        "maturity": "L2_SANDBOX",
        "workloads": [
            {
                "workload": item.workload,
                "action": item.action,
                "outcome_digest": item.outcome_digest,
                "verifier": item.verifier,
                "passed": item.passed,
                "metadata": dict(sorted(item.metadata.items())),
            }
            for item in items
        ],
    }
