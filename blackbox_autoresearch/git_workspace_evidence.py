"""Replayable evidence for an independently provisioned disposable Git workspace."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any

from .ci_live_evidence import EvidenceContext, EvidenceVerificationError


EVIDENCE_SCHEMA = "blackbox-git-workspace-evidence/v1"
OUTCOME_SCHEMA = "blackbox-git-workspace-outcome/v1"
VERIFICATION_SCHEMA = "blackbox-git-workspace-verification/v1"
TARGET_MATURITY = "L3 LIVE"
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
    return subprocess.run(args, cwd=cwd, check=check, capture_output=True, text=True)


def _identity_map(
    context: EvidenceContext,
    *,
    harness_path: Path,
    evaluator_path: Path,
    policy_path: Path,
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
    output_dir.mkdir(parents=True, exist_ok=False)
    if workspace.exists():
        raise ValueError(f"workspace already exists: {workspace}")
    if output_dir.resolve() == workspace.resolve() or output_dir.resolve().is_relative_to(workspace.resolve()):
        raise ValueError("evidence output must remain outside the disposable workspace")

    candidate_path = output_dir / "candidate.py"
    candidate_path.write_text(CANDIDATE_SOURCE)
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
        seeded = _run("python3", "-B", "-m", "unittest", cwd=workspace, check=False)
        if seeded.returncode == 0:
            raise RuntimeError("seeded repository unexpectedly passed")
        _run("python3", "-B", str(candidate_path), str(workspace), cwd=workspace)
        repaired = _run("python3", "-B", "-m", "unittest", cwd=workspace, check=False)
        if repaired.returncode != 0:
            raise RuntimeError(f"repaired repository is still red: {repaired.stderr}")
        _run("git", "add", "calculator.py", cwd=workspace)
        _run(
            "git", "-c", "user.name=Evidence Harness", "-c", "user.email=evidence@example.invalid",
            "commit", "-m", "Repair calculator behavior", cwd=workspace,
        )
        final_head = _run("git", "rev-parse", "HEAD", cwd=workspace).stdout.strip()
        git_version = _run("git", "--version", cwd=workspace).stdout.strip()
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
        },
        "identities": _identity_map(
            context, harness_path=harness_path, evaluator_path=evaluator_path, policy_path=policy_path
        ),
        "evidence": {
            "candidate_digest": _digest_file(candidate_path),
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


def _verify_repository(bundle: Path, outcome: dict[str, Any]) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        clone = Path(temporary) / "repository"
        cloned = subprocess.run(
            ["git", "clone", "--quiet", str(bundle), str(clone)], capture_output=True, text=True
        )
        if cloned.returncode != 0:
            raise EvidenceVerificationError(f"repository bundle is not cloneable: {cloned.stderr.strip()}")
        head = _run("git", "rev-parse", "HEAD", cwd=clone).stdout.strip()
        if head != outcome.get("final_head"):
            raise EvidenceVerificationError("final Git HEAD mismatch")
        parent = _run("git", "rev-parse", "HEAD^", cwd=clone).stdout.strip()
        if parent != outcome.get("initial_head"):
            raise EvidenceVerificationError("initial Git HEAD mismatch")
        if (clone / "calculator.py").read_text() != REPAIRED_SOURCE:
            raise EvidenceVerificationError("repaired source mismatch")
        if _run("git", "status", "--porcelain", cwd=clone).stdout:
            raise EvidenceVerificationError("replayed repository is dirty")
        replay = _run("python3", "-B", "-m", "unittest", cwd=clone, check=False)
        if replay.returncode != 0:
            raise EvidenceVerificationError("replayed repository tests failed")


def verify_git_workspace_evidence(
    bundle_dir: Path,
    *,
    expected_context: EvidenceContext,
    harness_path: Path,
    evaluator_path: Path,
    policy_path: Path,
    reported_platform_artifact_digest: str,
    run_tamper_probe: bool = False,
) -> dict[str, object]:
    manifest = _read_object(bundle_dir / "manifest.json")
    outcome = _read_object(bundle_dir / "outcome.json")
    if manifest.get("schema") != EVIDENCE_SCHEMA or outcome.get("schema") != OUTCOME_SCHEMA:
        raise EvidenceVerificationError("evidence schema mismatch")
    if manifest.get("target_maturity") != TARGET_MATURITY or manifest.get("status") != "candidate-evidence":
        raise EvidenceVerificationError("evidence maturity/status mismatch")
    run = manifest.get("run", {})
    for name in ("repository", "run_id", "run_attempt", "source_commit", "workflow_commit"):
        if run.get(name) != getattr(expected_context, name):
            raise EvidenceVerificationError(f"{name} drift")
    environment = manifest.get("environment", {})
    for name in ("runner_os", "runner_arch", "runner_image_os", "runner_image_version"):
        if environment.get(name) != getattr(expected_context, name):
            raise EvidenceVerificationError(f"{name} drift")
    expected_identities = _identity_map(
        expected_context, harness_path=harness_path, evaluator_path=evaluator_path, policy_path=policy_path
    )
    if manifest.get("identities") != expected_identities:
        raise EvidenceVerificationError("identity drift")
    evidence = manifest.get("evidence", {})
    for filename, key in (
        ("candidate.py", "candidate_digest"),
        ("outcome.json", "outcome_digest"),
        ("repository.bundle", "repository_bundle_digest"),
    ):
        if evidence.get(key) != _digest_file(bundle_dir / filename):
            raise EvidenceVerificationError(f"{key} mismatch")
    if outcome.get("seeded_test_returncode") == 0 or outcome.get("repaired_test_returncode") != 0:
        raise EvidenceVerificationError("red/green transition is not proven")
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
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }
