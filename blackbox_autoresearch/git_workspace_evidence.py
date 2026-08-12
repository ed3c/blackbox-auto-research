"""Replayable evidence for an independently provisioned disposable Git workspace."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any

from .ci_live_evidence import EvidenceContext, EvidenceVerificationError


EVIDENCE_SCHEMA = "blackbox-git-workspace-evidence/v1"
OUTCOME_SCHEMA = "blackbox-git-workspace-outcome/v1"
VERIFICATION_SCHEMA = "blackbox-git-workspace-verification/v1"
TARGET_MATURITY = "L3 LIVE"
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
BROKEN_SOURCE = "def add(left, right):\n    return left - right\n"
REPAIRED_SOURCE = "def add(left, right):\n    return left + right\n"
TEST_SOURCE = """import unittest

from calculator import add


class CalculatorTests(unittest.TestCase):
    def test_adds_operands(self):
        self.assertEqual(add(2, 3), 5)


if __name__ == "__main__":
    unittest.main()
"""
CANDIDATE_SOURCE = """from pathlib import Path
import sys

workspace = Path(sys.argv[1])
target = workspace / "calculator.py"
expected = "def add(left, right):\\n    return left - right\\n"
if target.read_text() != expected:
    raise SystemExit("candidate refused unexpected seed state")
target.write_text("def add(left, right):\\n    return left + right\\n")
"""


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _digest_file(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise EvidenceVerificationError(f"required regular file is missing: {path.name}")
    return _digest_bytes(path.read_bytes())


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(_canonical_bytes(value) + b"\n")


def _run(*args: str, cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args, cwd=cwd, check=check, capture_output=True, text=True, timeout=15
    )


def _identity_map(
    context: EvidenceContext,
    *,
    harness_path: Path,
    evaluator_path: Path,
    policy_path: Path,
    git_version: str,
    python_version: str,
) -> dict[str, str]:
    return {
        "task": _digest_bytes(b"git-workspace:seeded-red-repaired-green/v1"),
        "candidate": _digest_bytes(CANDIDATE_SOURCE.encode()),
        "environment": _digest_bytes(
            _canonical_bytes(
                {
                    "runner_os": context.runner_os,
                    "runner_arch": context.runner_arch,
                    "runner_image_os": context.runner_image_os,
                    "runner_image_version": context.runner_image_version,
                    "git_version": git_version,
                    "python_version": python_version,
                }
            )
        ),
        "harness": _digest_file(harness_path),
        "evaluator": _digest_file(evaluator_path),
        "policy": _digest_file(policy_path),
    }


def _context_run(context: EvidenceContext, started_at: str, finished_at: str) -> dict[str, str]:
    return {
        "repository": context.repository,
        "run_id": context.run_id,
        "run_attempt": context.run_attempt,
        "source_commit": context.source_commit,
        "workflow_commit": context.workflow_commit,
        "started_at": started_at,
        "finished_at": finished_at,
    }


def produce_git_workspace_evidence(
    output_dir: Path,
    workspace: Path,
    *,
    context: EvidenceContext,
    harness_path: Path,
    evaluator_path: Path,
    policy_path: Path,
) -> dict[str, object]:
    output_dir = output_dir.resolve()
    workspace = workspace.resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    if workspace.exists():
        raise ValueError(f"workspace already exists: {workspace}")
    if output_dir.resolve() == workspace.resolve() or output_dir.resolve().is_relative_to(workspace.resolve()):
        raise ValueError("evidence output must remain outside the disposable workspace")

    candidate_path = output_dir / "candidate.py"
    candidate_path.write_text(CANDIDATE_SOURCE)
    candidate_digest = _digest_file(candidate_path)
    started_at = datetime.now(timezone.utc)
    workspace.mkdir(parents=True)
    try:
        _run("git", "init", "--initial-branch=main", cwd=workspace)
        (workspace / "calculator.py").write_text(BROKEN_SOURCE)
        (workspace / "test_calculator.py").write_text(TEST_SOURCE)
        _run("git", "add", ".", cwd=workspace)
        _run(
            "git", "-c", "user.name=Evidence Harness", "-c", "user.email=evidence@example.invalid",
            "commit", "-m", "Seed failing repository", cwd=workspace,
        )
        initial_head = _run("git", "rev-parse", "HEAD", cwd=workspace).stdout.strip()
        seeded = _run(sys.executable, "-B", "-m", "unittest", cwd=workspace, check=False)
        if seeded.returncode != 1 or "FAILED" not in seeded.stderr:
            raise RuntimeError("seeded repository did not fail with the expected assertion")
        _run(sys.executable, "-B", str(candidate_path), str(workspace), cwd=workspace)
        repaired = _run(sys.executable, "-B", "-m", "unittest", cwd=workspace, check=False)
        if repaired.returncode != 0:
            raise RuntimeError(f"repaired repository is still red: {repaired.stderr}")
        _run("git", "add", "calculator.py", cwd=workspace)
        _run(
            "git", "-c", "user.name=Evidence Harness", "-c", "user.email=evidence@example.invalid",
            "commit", "-m", "Repair calculator behavior", cwd=workspace,
        )
        final_head = _run("git", "rev-parse", "HEAD", cwd=workspace).stdout.strip()
        git_version = _run("git", "--version", cwd=workspace).stdout.strip()
        python_version = _run(sys.executable, "--version", cwd=workspace).stdout.strip()
        bundle_path = output_dir / "repository.bundle"
        _run("git", "bundle", "create", str(bundle_path), "--all", cwd=workspace)
    finally:
        shutil.rmtree(workspace, ignore_errors=False)
    if workspace.exists():
        raise RuntimeError("disposable workspace teardown failed")

    finished_at = datetime.now(timezone.utc)
    outcome = {
        "schema": OUTCOME_SCHEMA,
        "initial_head": initial_head,
        "final_head": final_head,
        "seeded_test_returncode": seeded.returncode,
        "repaired_test_returncode": repaired.returncode,
        "git_version": git_version,
        "python_version": python_version,
        "teardown": "workspace-absent",
    }
    outcome_path = output_dir / "outcome.json"
    _write_json(outcome_path, outcome)
    manifest = {
        "schema": EVIDENCE_SCHEMA,
        "target_maturity": TARGET_MATURITY,
        "status": "candidate-evidence",
        "run": _context_run(context, started_at.isoformat(), finished_at.isoformat()),
        "environment": {
            "runner_os": context.runner_os,
            "runner_arch": context.runner_arch,
            "runner_image_os": context.runner_image_os,
            "runner_image_version": context.runner_image_version,
            "git_version": git_version,
            "python_version": python_version,
        },
        "identities": _identity_map(
            context, harness_path=harness_path, evaluator_path=evaluator_path, policy_path=policy_path,
            git_version=git_version, python_version=python_version,
        ),
        "evidence": {
            "candidate_digest": candidate_digest,
            "outcome_digest": _digest_file(outcome_path),
            "repository_bundle_digest": _digest_file(bundle_path),
        },
    }
    _write_json(output_dir / "manifest.json", manifest)
    return manifest


def _read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceVerificationError(f"invalid evidence file {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceVerificationError(f"{path.name} must contain an object")
    return value


def _require_keys(value: dict[str, Any], expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise EvidenceVerificationError(f"{name} keys drift")


def _require_object(value: object, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceVerificationError(f"{name} must be an object")
    return value


def _timestamp(value: object, name: str) -> datetime:
    if not isinstance(value, str):
        raise EvidenceVerificationError(f"{name} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise EvidenceVerificationError(f"{name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EvidenceVerificationError(f"{name} must include a UTC offset")
    return parsed


def _tree(bundle_clone: Path, revision: str) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in _run("git", "ls-tree", "-r", revision, cwd=bundle_clone).stdout.splitlines():
        metadata, path = line.split("\t", 1)
        mode, kind, _object_id = metadata.split(" ", 2)
        if kind != "blob" or path in entries:
            raise EvidenceVerificationError("repository tree contains an unsupported entry")
        entries[path] = mode
    return entries


def _verify_repository(bundle: Path, outcome: dict[str, Any]) -> None:
    bundle = bundle.resolve()
    heads = _run("git", "bundle", "list-heads", str(bundle), cwd=bundle.parent).stdout.splitlines()
    if heads != [
        f"{outcome.get('final_head')} refs/heads/main",
        f"{outcome.get('final_head')} HEAD",
    ]:
        raise EvidenceVerificationError("repository bundle refs drift")
    with tempfile.TemporaryDirectory() as temporary:
        clone = Path(temporary) / "repository"
        cloned = subprocess.run(
            ["git", "clone", "--quiet", str(bundle), str(clone)], capture_output=True, text=True,
            timeout=15,
        )
        if cloned.returncode != 0:
            raise EvidenceVerificationError(f"repository bundle is not cloneable: {cloned.stderr.strip()}")
        head = _run("git", "rev-parse", "HEAD", cwd=clone).stdout.strip()
        if head != outcome.get("final_head"):
            raise EvidenceVerificationError("final Git HEAD mismatch")
        parent = _run("git", "rev-parse", "HEAD^", cwd=clone).stdout.strip()
        if parent != outcome.get("initial_head"):
            raise EvidenceVerificationError("initial Git HEAD mismatch")
        if _run("git", "rev-list", "--count", "HEAD", cwd=clone).stdout.strip() != "2":
            raise EvidenceVerificationError("repository history must contain exactly two commits")
        expected_tree = {"calculator.py": "100644", "test_calculator.py": "100644"}
        if _tree(clone, "HEAD^") != expected_tree or _tree(clone, "HEAD") != expected_tree:
            raise EvidenceVerificationError("repository tree or file mode mismatch")
        initial_source = _run("git", "show", "HEAD^:calculator.py", cwd=clone).stdout
        if initial_source != BROKEN_SOURCE:
            raise EvidenceVerificationError("seeded source mismatch")
        initial_test = _run("git", "show", "HEAD^:test_calculator.py", cwd=clone).stdout
        final_test = _run("git", "show", "HEAD:test_calculator.py", cwd=clone).stdout
        if initial_test != TEST_SOURCE or final_test != TEST_SOURCE:
            raise EvidenceVerificationError("test source mismatch")
        changed_paths = _run("git", "diff", "--name-only", "HEAD^", "HEAD", cwd=clone).stdout.splitlines()
        if changed_paths != ["calculator.py"]:
            raise EvidenceVerificationError("repair commit changed unexpected paths")
        final_source = _run("git", "show", "HEAD:calculator.py", cwd=clone).stdout
        if final_source != REPAIRED_SOURCE:
            raise EvidenceVerificationError("repaired source mismatch")
        _run("git", "checkout", "--quiet", "--detach", "HEAD^", cwd=clone)
        seeded = _run(sys.executable, "-B", "-m", "unittest", cwd=clone, check=False)
        if seeded.returncode != 1 or "FAILED" not in seeded.stderr:
            raise EvidenceVerificationError("seeded repository failure did not replay")
        if seeded.returncode != outcome.get("seeded_test_returncode"):
            raise EvidenceVerificationError("seeded test return code drift")
        _run("git", "checkout", "--quiet", "--detach", str(outcome["final_head"]), cwd=clone)
        if _run("git", "status", "--porcelain", cwd=clone).stdout:
            raise EvidenceVerificationError("replayed repository is dirty")
        replay = _run(sys.executable, "-B", "-m", "unittest", cwd=clone, check=False)
        if replay.returncode != 0:
            raise EvidenceVerificationError("replayed repository tests failed")
        if replay.returncode != outcome.get("repaired_test_returncode"):
            raise EvidenceVerificationError("repaired test return code drift")


def verify_git_workspace_evidence(
    bundle_dir: Path,
    *,
    expected_context: EvidenceContext,
    harness_path: Path,
    evaluator_path: Path,
    policy_path: Path,
    reported_platform_artifact_digest: str,
    expected_producer_git_version: str,
    expected_producer_python_version: str,
    run_tamper_probe: bool = False,
) -> dict[str, object]:
    manifest = _read_object(bundle_dir / "manifest.json")
    outcome = _read_object(bundle_dir / "outcome.json")
    _require_keys(
        manifest,
        {"schema", "target_maturity", "status", "run", "environment", "identities", "evidence"},
        "manifest",
    )
    _require_keys(
        outcome,
        {"schema", "initial_head", "final_head", "seeded_test_returncode",
         "repaired_test_returncode", "git_version", "python_version", "teardown"},
        "outcome",
    )
    if manifest.get("schema") != EVIDENCE_SCHEMA or outcome.get("schema") != OUTCOME_SCHEMA:
        raise EvidenceVerificationError("evidence schema mismatch")
    if manifest.get("target_maturity") != TARGET_MATURITY or manifest.get("status") != "candidate-evidence":
        raise EvidenceVerificationError("evidence maturity/status mismatch")
    run = _require_object(manifest.get("run"), "run")
    _require_keys(
        run,
        {"repository", "run_id", "run_attempt", "source_commit", "workflow_commit",
         "started_at", "finished_at"},
        "run",
    )
    for name in ("repository", "run_id", "run_attempt", "source_commit", "workflow_commit"):
        if run.get(name) != getattr(expected_context, name):
            raise EvidenceVerificationError(f"{name} drift")
    started_at = _timestamp(run.get("started_at"), "started_at")
    finished_at = _timestamp(run.get("finished_at"), "finished_at")
    if finished_at < started_at:
        raise EvidenceVerificationError("finished_at precedes started_at")
    environment = _require_object(manifest.get("environment"), "environment")
    _require_keys(
        environment,
        {"runner_os", "runner_arch", "runner_image_os", "runner_image_version",
         "git_version", "python_version"},
        "environment",
    )
    for name in ("runner_os", "runner_arch", "runner_image_os", "runner_image_version"):
        if environment.get(name) != getattr(expected_context, name):
            raise EvidenceVerificationError(f"{name} drift")
    for name in ("git_version", "python_version"):
        if not isinstance(environment.get(name), str) or not environment[name].strip():
            raise EvidenceVerificationError(f"{name} must be non-empty")
        if outcome.get(name) != environment[name]:
            raise EvidenceVerificationError(f"{name} outcome drift")
    expected_producer_versions = {
        "git_version": expected_producer_git_version,
        "python_version": expected_producer_python_version,
    }
    for name, expected in expected_producer_versions.items():
        if environment[name] != expected:
            raise EvidenceVerificationError(f"{name} producer output drift")
    identities = _require_object(manifest.get("identities"), "identities")
    _require_keys(identities, {"task", "candidate", "environment", "harness", "evaluator", "policy"}, "identities")
    expected_identities = _identity_map(
        expected_context, harness_path=harness_path, evaluator_path=evaluator_path, policy_path=policy_path,
        git_version=environment["git_version"], python_version=environment["python_version"],
    )
    if identities != expected_identities:
        raise EvidenceVerificationError("identity drift")
    evidence = _require_object(manifest.get("evidence"), "evidence")
    _require_keys(evidence, {"candidate_digest", "outcome_digest", "repository_bundle_digest"}, "evidence")
    for filename, key in (
        ("candidate.py", "candidate_digest"),
        ("outcome.json", "outcome_digest"),
        ("repository.bundle", "repository_bundle_digest"),
    ):
        if evidence.get(key) != _digest_file(bundle_dir / filename):
            raise EvidenceVerificationError(f"{key} mismatch")
    if evidence["candidate_digest"] != identities["candidate"]:
        raise EvidenceVerificationError("candidate identity does not match candidate bytes")
    return_codes = (outcome.get("seeded_test_returncode"), outcome.get("repaired_test_returncode"))
    if any(type(value) is not int for value in return_codes) or return_codes != (1, 0):
        raise EvidenceVerificationError("red/green transition is not proven")
    for name in ("initial_head", "final_head"):
        if not isinstance(outcome.get(name), str) or not _COMMIT_RE.fullmatch(outcome[name]):
            raise EvidenceVerificationError(f"{name} must be a commit SHA")
    if outcome.get("teardown") != "workspace-absent":
        raise EvidenceVerificationError("workspace teardown is not proven")
    _verify_repository(bundle_dir / "repository.bundle", outcome)
    tamper = "not-run"
    if run_tamper_probe:
        forged = dict(outcome)
        forged["final_head"] = "0" * 40
        try:
            _verify_repository(bundle_dir / "repository.bundle", forged)
        except EvidenceVerificationError:
            tamper = "rejected"
        else:
            raise EvidenceVerificationError("planted Git-state tamper was accepted")
    digest = reported_platform_artifact_digest.removeprefix("sha256:")
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise EvidenceVerificationError("reported platform artifact digest is malformed")
    return {
        "schema": VERIFICATION_SCHEMA,
        "verified": True,
        "maturity_decision": "unassessed",
        "verification_scope": "git-bundle-integrity-context-and-replay",
        "target_maturity": TARGET_MATURITY,
        "repository": expected_context.repository,
        "run_id": expected_context.run_id,
        "run_attempt": expected_context.run_attempt,
        "source_commit": expected_context.source_commit,
        "workflow_commit": expected_context.workflow_commit,
        "evidence_manifest_digest": _digest_file(bundle_dir / "manifest.json"),
        "repository_bundle_digest": _digest_file(bundle_dir / "repository.bundle"),
        "reported_platform_artifact_digest": "sha256:" + digest,
        "platform_artifact_digest_verified": False,
        "tamper_probe": tamper,
        "verifier_environment": {
            "git_version": _run("git", "--version", cwd=bundle_dir).stdout.strip(),
            "python_version": _run(sys.executable, "--version", cwd=bundle_dir).stdout.strip(),
        },
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }
