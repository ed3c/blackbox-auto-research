"""Content-addressed evidence for a live GitHub Actions CI experiment.

Producing an envelope locally does not prove L3 maturity. The evidence becomes a
candidate for L3 only when a real GitHub Actions run supplies the pinned context
and a separate job re-verifies the uploaded artifact.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any

from .live_workloads import CI_REPAIRED_SOURCE, run_ci_remediation_workload


EVIDENCE_SCHEMA = "blackbox-ci-evidence/v1"
OUTCOME_SCHEMA = "blackbox-ci-outcome/v1"
VERIFICATION_SCHEMA = "blackbox-ci-verification/v1"
TARGET_MATURITY = "L3 LIVE"
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class EvidenceVerificationError(RuntimeError):
    """Raised when stored evidence cannot support the claimed verification."""


@dataclass(frozen=True)
class EvidenceContext:
    repository: str
    run_id: str
    run_attempt: str
    source_commit: str
    workflow_commit: str
    runner_os: str
    runner_arch: str
    runner_image_os: str
    runner_image_version: str

    def __post_init__(self) -> None:
        if not _REPOSITORY_RE.fullmatch(self.repository):
            raise ValueError("repository must be OWNER/REPOSITORY")
        for name in ("run_id", "run_attempt"):
            value = getattr(self, name)
            if not value.isdigit() or int(value) < 1:
                raise ValueError(f"{name} must be a positive integer string")
        for name in ("source_commit", "workflow_commit"):
            if not _COMMIT_RE.fullmatch(getattr(self, name)):
                raise ValueError(f"{name} must be a 40-character lowercase commit SHA")
        for name in ("runner_os", "runner_arch", "runner_image_os", "runner_image_version"):
            if not getattr(self, name).strip():
                raise ValueError(f"{name} must be non-empty")


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _digest_file(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"identity path must be a regular file: {path}")
    return _digest_bytes(path.read_bytes())


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(_canonical_bytes(value) + b"\n")


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise EvidenceVerificationError(f"required regular file is missing: {path.name}")
    try:
        value = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceVerificationError(f"invalid JSON in {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceVerificationError(f"{path.name} must contain a JSON object")
    return value


def _identity_map(
    context: EvidenceContext,
    *,
    candidate_digest: str,
    harness_path: Path,
    evaluator_path: Path,
    policy_path: Path,
) -> dict[str, str]:
    if not _DIGEST_RE.fullmatch(candidate_digest):
        raise ValueError("candidate digest must be sha256:<64 lowercase hex chars>")
    identities = {
        "task": _digest_bytes(b"blackbox-ci-task:seeded-red-repaired-green/v1"),
        "candidate": candidate_digest,
        "environment": _digest_bytes(
            _canonical_bytes(
                {
                    "runner_arch": context.runner_arch,
                    "runner_image_os": context.runner_image_os,
                    "runner_image_version": context.runner_image_version,
                    "runner_os": context.runner_os,
                }
            )
        ),
        "harness": _digest_file(harness_path),
        "evaluator": _digest_file(evaluator_path),
        "policy": _digest_file(policy_path),
    }
    if identities["harness"] == identities["evaluator"]:
        raise ValueError("harness and evaluator identities must differ")
    return identities


def produce_evidence_bundle(
    output_dir: Path,
    *,
    context: EvidenceContext,
    harness_path: Path,
    evaluator_path: Path,
    policy_path: Path,
) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=False)
    started_at = datetime.now(timezone.utc)
    result = run_ci_remediation_workload()
    finished_at = datetime.now(timezone.utc)
    if not result.passed:
        raise RuntimeError(f"CI remediation workload failed: {result.metadata}")

    outcome = {
        "schema": OUTCOME_SCHEMA,
        "workload": result.workload,
        "action": result.action,
        "outcome_digest": result.outcome_digest,
        "verifier": result.verifier,
        "passed": result.passed,
        "metadata": dict(sorted(result.metadata.items())),
    }
    outcome_path = output_dir / "outcome.json"
    _write_json(outcome_path, outcome)
    candidate_path = output_dir / "candidate.py"
    candidate_path.write_text(CI_REPAIRED_SOURCE)
    candidate_digest = _digest_file(candidate_path)
    if candidate_digest != result.outcome_digest:
        raise RuntimeError("candidate bytes do not match workload outcome digest")
    manifest = {
        "schema": EVIDENCE_SCHEMA,
        "target_maturity": TARGET_MATURITY,
        "status": "candidate-evidence",
        "run": {
            "repository": context.repository,
            "run_id": context.run_id,
            "run_attempt": context.run_attempt,
            "source_commit": context.source_commit,
            "workflow_commit": context.workflow_commit,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
        },
        "environment": {
            "runner_os": context.runner_os,
            "runner_arch": context.runner_arch,
            "runner_image_os": context.runner_image_os,
            "runner_image_version": context.runner_image_version,
        },
        "identities": _identity_map(
            context,
            candidate_digest=candidate_digest,
            harness_path=harness_path,
            evaluator_path=evaluator_path,
            policy_path=policy_path,
        ),
        "evidence": {
            "candidate_path": "candidate.py",
            "candidate_digest": candidate_digest,
            "outcome_path": "outcome.json",
            "outcome_digest": _digest_file(outcome_path),
        },
    }
    _write_json(output_dir / "manifest.json", manifest)
    return manifest


def _require_equal(actual: object, expected: object, name: str) -> None:
    if actual != expected:
        raise EvidenceVerificationError(f"{name} drift: expected {expected!r}, got {actual!r}")


def _require_keys(value: dict[str, Any], expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise EvidenceVerificationError(f"{name} keys drift: expected {sorted(expected)}, got {sorted(value)}")


def _parse_timestamp(value: object, name: str) -> datetime:
    if not isinstance(value, str):
        raise EvidenceVerificationError(f"{name} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise EvidenceVerificationError(f"{name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EvidenceVerificationError(f"{name} must include a UTC offset")
    return parsed


def _normalize_reported_platform_digest(value: str) -> str:
    if _HEX_DIGEST_RE.fullmatch(value):
        return "sha256:" + value
    if _DIGEST_RE.fullmatch(value):
        return value
    raise EvidenceVerificationError("reported platform artifact digest must be 64 lowercase hex chars")


def _verify_without_probe(
    bundle_dir: Path,
    *,
    expected_context: EvidenceContext,
    harness_path: Path,
    evaluator_path: Path,
    policy_path: Path,
    reported_platform_artifact_digest: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    _normalize_reported_platform_digest(reported_platform_artifact_digest)
    manifest_path = bundle_dir / "manifest.json"
    outcome_path = bundle_dir / "outcome.json"
    candidate_path = bundle_dir / "candidate.py"
    manifest = _read_json(manifest_path)
    outcome = _read_json(outcome_path)
    _require_keys(
        manifest,
        {"schema", "target_maturity", "status", "run", "environment", "identities", "evidence"},
        "manifest",
    )
    _require_equal(manifest.get("schema"), EVIDENCE_SCHEMA, "evidence schema")
    _require_equal(manifest.get("target_maturity"), TARGET_MATURITY, "target maturity")
    _require_equal(manifest.get("status"), "candidate-evidence", "evidence status")

    run = manifest.get("run")
    if not isinstance(run, dict):
        raise EvidenceVerificationError("manifest run must be an object")
    _require_keys(
        run,
        {"repository", "run_id", "run_attempt", "source_commit", "workflow_commit", "started_at", "finished_at"},
        "run",
    )
    for name in ("repository", "run_id", "run_attempt", "source_commit", "workflow_commit"):
        _require_equal(run.get(name), getattr(expected_context, name), name)
    started_at = _parse_timestamp(run.get("started_at"), "started_at")
    finished_at = _parse_timestamp(run.get("finished_at"), "finished_at")
    if finished_at < started_at:
        raise EvidenceVerificationError("finished_at precedes started_at")

    environment = manifest.get("environment")
    if not isinstance(environment, dict):
        raise EvidenceVerificationError("manifest environment must be an object")
    _require_keys(
        environment,
        {"runner_os", "runner_arch", "runner_image_os", "runner_image_version"},
        "environment",
    )
    for name in ("runner_os", "runner_arch", "runner_image_os", "runner_image_version"):
        _require_equal(environment.get(name), getattr(expected_context, name), name)

    identities = manifest.get("identities")
    if not isinstance(identities, dict):
        raise EvidenceVerificationError("manifest identities must be an object")
    _require_keys(
        outcome,
        {"schema", "workload", "action", "outcome_digest", "verifier", "passed", "metadata"},
        "outcome",
    )
    evidence = manifest.get("evidence")
    if not isinstance(evidence, dict):
        raise EvidenceVerificationError("manifest evidence must be an object")
    _require_keys(
        evidence,
        {"candidate_path", "candidate_digest", "outcome_path", "outcome_digest"},
        "evidence",
    )
    _require_equal(evidence.get("candidate_path"), "candidate.py", "candidate path")
    actual_candidate_digest = _digest_file(candidate_path)
    if evidence.get("candidate_digest") != actual_candidate_digest:
        raise EvidenceVerificationError("candidate digest mismatch")
    _require_equal(outcome.get("outcome_digest"), actual_candidate_digest, "candidate outcome digest")
    expected_identities = _identity_map(
        expected_context,
        candidate_digest=actual_candidate_digest,
        harness_path=harness_path,
        evaluator_path=evaluator_path,
        policy_path=policy_path,
    )
    _require_equal(set(identities), set(expected_identities), "identity set")
    for name, expected in expected_identities.items():
        _require_equal(identities.get(name), expected, f"{name} identity")

    _require_equal(evidence.get("outcome_path"), "outcome.json", "outcome path")
    actual_outcome_digest = _digest_file(outcome_path)
    if evidence.get("outcome_digest") != actual_outcome_digest:
        raise EvidenceVerificationError("outcome digest mismatch")
    _require_equal(outcome.get("schema"), OUTCOME_SCHEMA, "outcome schema")
    _require_equal(outcome.get("workload"), "ci-remediation", "outcome workload")
    _require_equal(outcome.get("passed"), True, "outcome result")
    metadata = outcome.get("metadata")
    if not isinstance(metadata, dict):
        raise EvidenceVerificationError("outcome metadata must be an object")
    _require_equal(metadata.get("seeded_failure"), "true", "seeded failure")
    _require_equal(metadata.get("seeded_source"), "seeded", "seeded source")
    _require_equal(metadata.get("repaired"), "true", "repair result")
    _require_equal(metadata.get("repaired_source"), "repair", "repaired source")
    _require_equal(metadata.get("bytecode_cache_absent"), "true", "bytecode cache")
    return manifest, outcome


def verify_evidence_bundle(
    bundle_dir: Path,
    *,
    expected_context: EvidenceContext,
    harness_path: Path,
    evaluator_path: Path,
    policy_path: Path,
    reported_platform_artifact_digest: str,
    run_tamper_probe: bool = False,
) -> dict[str, object]:
    manifest, _ = _verify_without_probe(
        bundle_dir,
        expected_context=expected_context,
        harness_path=harness_path,
        evaluator_path=evaluator_path,
        policy_path=policy_path,
        reported_platform_artifact_digest=reported_platform_artifact_digest,
    )
    tamper_probe = "not-run"
    if run_tamper_probe:
        with tempfile.TemporaryDirectory() as tmp:
            planted = Path(tmp) / "bundle"
            shutil.copytree(bundle_dir, planted)
            with (planted / "outcome.json").open("ab") as handle:
                handle.write(b"\n")
            try:
                _verify_without_probe(
                    planted,
                    expected_context=expected_context,
                    harness_path=harness_path,
                    evaluator_path=evaluator_path,
                    policy_path=policy_path,
                    reported_platform_artifact_digest=reported_platform_artifact_digest,
                )
            except EvidenceVerificationError as exc:
                if str(exc) != "outcome digest mismatch":
                    raise EvidenceVerificationError(f"tamper probe failed unexpectedly: {exc}") from exc
                tamper_probe = "rejected"
            else:
                raise EvidenceVerificationError("tamper probe was not rejected")

    verified_at = datetime.now(timezone.utc).isoformat()
    return {
        "schema": VERIFICATION_SCHEMA,
        "verified": True,
        "verified_at": verified_at,
        "target_maturity": TARGET_MATURITY,
        "maturity_decision": "unassessed",
        "verification_scope": "bundle-integrity-and-context-match",
        "repository": expected_context.repository,
        "run_id": expected_context.run_id,
        "run_attempt": expected_context.run_attempt,
        "source_commit": expected_context.source_commit,
        "workflow_commit": expected_context.workflow_commit,
        "evidence_manifest_digest": _digest_file(bundle_dir / "manifest.json"),
        "outcome_digest": manifest["evidence"]["outcome_digest"],
        "reported_platform_artifact_digest": _normalize_reported_platform_digest(
            reported_platform_artifact_digest
        ),
        "platform_artifact_digest_verified": False,
        "evaluator_digest": manifest["identities"]["evaluator"],
        "tamper_probe": tamper_probe,
    }
