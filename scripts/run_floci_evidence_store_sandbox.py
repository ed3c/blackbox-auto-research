#!/usr/bin/env python3
"""Build a local Floci clone and execute the #25 L2 SANDBOX S3 experiment."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Callable, TypeVar
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from blackbox_autoresearch.floci_evidence_store import (  # noqa: E402
    FlociEnvironment,
    FlociEvidenceIdentity,
    WORKER_CONFIG_SCHEMA,
)


RUN_SCHEMA = "blackbox-floci-sandbox-run/v2"
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_AWS_ERROR_RE = re.compile(r"An error occurred \(([^)]+)\)")
_T = TypeVar("_T")


@dataclass(frozen=True)
class AwsProbeOutcome:
    status: str
    detail: str


@dataclass(frozen=True)
class TeardownOutcome:
    status: str
    remove_returncode: int
    inspect_returncode: int
    inspect_detail: str


def _run(
    *args: str,
    cwd: Path,
    env: dict[str, str] | None = None,
    check: bool = True,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"command failed ({args[0]} exit {result.returncode}): {detail}")
    return result


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _digest_files(*paths: Path) -> str:
    payload = bytearray()
    for path in paths:
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"identity input must be a regular file: {path.name}")
        payload.extend(path.name.encode() + b"\0" + path.read_bytes() + b"\0")
    return _digest_bytes(bytes(payload))


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _write_json(path: Path, value: object) -> None:
    with path.open("x") as handle:
        json.dump(value, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")


def _export_evidence_file(source: Path, destination: Path) -> dict[str, object]:
    if not source.is_file() or source.is_symlink():
        raise ValueError(f"evidence source must be a regular file: {source.name}")
    payload = source.read_bytes()
    with destination.open("xb") as handle:
        handle.write(payload)
    return {
        "locator": destination.name,
        "sha256": _digest_bytes(payload),
        "size": len(payload),
    }


def _export_evidence_bundle(
    artifacts_dir: Path,
    manifest: Path,
    verification: Path,
    payload: Path,
    policy: Path,
) -> dict[str, dict[str, object]]:
    return {
        "producer_manifest": _export_evidence_file(
            manifest, artifacts_dir / "producer-manifest.json"
        ),
        "verifier_receipt": _export_evidence_file(
            verification, artifacts_dir / "verifier-receipt.json"
        ),
        "input_payload": _export_evidence_file(
            payload, artifacts_dir / "input-payload.json"
        ),
        "iam_policy": _export_evidence_file(policy, artifacts_dir / "iam-policy.json"),
    }


def _validate_output_paths(receipt: Path, artifacts_dir: Path) -> tuple[Path, Path]:
    resolved_receipt = receipt.resolve()
    resolved_artifacts = artifacts_dir.resolve()
    if resolved_receipt.parent != resolved_artifacts:
        raise ValueError("--receipt must be inside --artifacts-dir")
    if resolved_receipt.name != "runner-receipt.json":
        raise ValueError("--receipt filename must be runner-receipt.json")
    if resolved_artifacts.exists():
        raise ValueError("artifacts directory already exists")
    return resolved_receipt, resolved_artifacts


def _run_with_artifact_reservation(
    artifacts_dir: Path, action: Callable[[], _T]
) -> _T:
    artifacts_dir.mkdir(parents=True, exist_ok=False)
    completed = False
    try:
        result = action()
        completed = True
        return result
    finally:
        if not completed:
            shutil.rmtree(artifacts_dir)


def _reproduction_metadata(commit: str, run_id: str) -> dict[str, object]:
    return {
        "reproduction_command": [
            "python3",
            "scripts/run_floci_evidence_store_sandbox.py",
            "--floci-repo",
            "$FLOCI_REPO",
            "--artifacts-dir",
            "$NEW_ARTIFACTS_DIR",
            "--receipt",
            "$NEW_ARTIFACTS_DIR/runner-receipt.json",
            "--run-id",
            run_id,
        ],
        "reproduction_environment": {
            "FLOCI_REPO": {
                "required": True,
                "source_commit": commit,
            },
            "NEW_ARTIFACTS_DIR": {
                "required": True,
                "must_not_exist": True,
            },
        },
    }


def _wait_ready(endpoint: str, ca_bundle: Path, *, timeout: float = 90) -> None:
    deadline = time.monotonic() + timeout
    last_error = "not started"
    while time.monotonic() < deadline:
        if ca_bundle.is_file():
            try:
                with urlopen(endpoint.replace("https://", "http://") + "/_floci/health", timeout=2) as response:
                    if response.status == 200:
                        return
            except (OSError, URLError) as exc:
                last_error = str(exc)
        time.sleep(0.5)
    raise RuntimeError(f"Floci did not become ready: {last_error}")


def _wait_container_ready(name: str, endpoint: str, ca_bundle: Path) -> None:
    try:
        _wait_ready(endpoint, ca_bundle)
    except RuntimeError as exc:
        result = _run("docker", "logs", name, cwd=ROOT, check=False)
        logs = (result.stdout + result.stderr).strip()
        raise RuntimeError(f"{exc}; Floci logs:\n{logs[-8000:]}") from exc


def _aws(
    endpoint: str,
    ca_bundle: Path,
    credentials: dict[str, str],
    *args: str,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    environment = {
        **os.environ,
        **credentials,
        "AWS_DEFAULT_REGION": "us-east-1",
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_PAGER": "",
    }
    return _run(
        "aws",
        "--endpoint-url",
        endpoint,
        "--ca-bundle",
        str(ca_bundle),
        *args,
        cwd=ROOT,
        env=environment,
        check=check,
    )


def _container_endpoint(name: str) -> str:
    mapping = _run("docker", "port", name, "4566/tcp", cwd=ROOT).stdout.strip().splitlines()
    if len(mapping) != 1 or ":" not in mapping[0]:
        raise RuntimeError(f"unexpected Floci port mapping: {mapping}")
    return "https://127.0.0.1:" + mapping[0].rsplit(":", 1)[1]


def _create_container(name: str, image_id: str, data_dir: Path | str) -> None:
    _run(
        "docker",
        "run",
        "-d",
        "--name",
        name,
        "-p",
        "127.0.0.1::4566",
        "-v",
        f"{data_dir}:/app/data",
        "-e",
        "FLOCI_STORAGE_MODE=wal",
        "-e",
        "FLOCI_STORAGE_PERSISTENT_PATH=/app/data",
        "-e",
        "FLOCI_TLS_ENABLED=true",
        "-e",
        "FLOCI_AUTH_VALIDATE_SIGNATURES=true",
        "-e",
        "FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED=true",
        "-e",
        "FLOCI_PROTOCOLS_REJECT_UNKNOWN_SERVICE_SCOPE=true",
        image_id,
        cwd=ROOT,
    )


def _evaluate_aws_probe(
    result: subprocess.CompletedProcess[str],
    expected_error_codes: set[str],
) -> AwsProbeOutcome:
    if result.returncode == 0:
        return AwsProbeOutcome("accepted", "request-succeeded")
    match = _AWS_ERROR_RE.search(result.stdout + result.stderr)
    if match is not None and match.group(1) in expected_error_codes:
        return AwsProbeOutcome("denied", match.group(1))
    return AwsProbeOutcome("inconclusive", "unclassified-cli-error")


def _security_decision(iam_probe: AwsProbeOutcome, signature_probe: AwsProbeOutcome) -> str:
    return "pass" if iam_probe.status == signature_probe.status == "denied" else "quarantine"


def _probe_receipt(
    operation: str,
    result: subprocess.CompletedProcess[str],
    outcome: AwsProbeOutcome,
) -> dict[str, object]:
    return {
        "operation": operation,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "outcome": outcome.__dict__,
    }


def _evaluate_teardown(
    removed: subprocess.CompletedProcess[str],
    inspected: subprocess.CompletedProcess[str],
) -> TeardownOutcome:
    inspect_output = (inspected.stdout + inspected.stderr).strip()
    absent = (
        removed.returncode == 0
        and inspected.returncode != 0
        and "no such object" in inspect_output.lower()
    )
    return TeardownOutcome(
        status="container-absent" if absent else "failed",
        remove_returncode=removed.returncode,
        inspect_returncode=inspected.returncode,
        inspect_detail=inspect_output,
    )


def _bootstrap_iam(endpoint: str, ca_bundle: Path, bucket: str) -> tuple[dict[str, str], dict[str, object]]:
    bootstrap = {"AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test"}
    username = "blackbox-evidence-writer"
    _aws(endpoint, ca_bundle, bootstrap, "iam", "create-user", "--user-name", username)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:CreateBucket", "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": f"arn:aws:s3:::{bucket}/artifacts/*",
            },
        ],
    }
    _aws(
        endpoint,
        ca_bundle,
        bootstrap,
        "iam",
        "put-user-policy",
        "--user-name",
        username,
        "--policy-name",
        "evidence-object-read-write",
        "--policy-document",
        json.dumps(policy, separators=(",", ":")),
    )
    created = _aws(
        endpoint,
        ca_bundle,
        bootstrap,
        "iam",
        "create-access-key",
        "--user-name",
        username,
        "--output",
        "json",
    )
    access = json.loads(created.stdout)["AccessKey"]
    credentials = {
        "AWS_ACCESS_KEY_ID": access["AccessKeyId"],
        "AWS_SECRET_ACCESS_KEY": access["SecretAccessKey"],
    }
    return credentials, policy


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Run the Floci evidence-store L2 SANDBOX experiment")
    value.add_argument("--floci-repo", type=Path, required=True)
    value.add_argument("--artifacts-dir", type=Path, required=True)
    value.add_argument("--receipt", type=Path, required=True)
    value.add_argument("--run-id", required=True)
    return value


def _execute(
    args: argparse.Namespace, receipt_path: Path, artifacts_dir: Path
) -> int:
    floci_repo = args.floci_repo.resolve()
    if not (floci_repo / "docker" / "Dockerfile").is_file():
        raise ValueError("--floci-repo must point to a Floci source clone")
    if _run("git", "status", "--porcelain", cwd=floci_repo).stdout:
        raise ValueError("Floci source clone must be clean so its identity is reproducible")
    commit = _run("git", "rev-parse", "HEAD", cwd=floci_repo).stdout.strip()
    if not _COMMIT_RE.fullmatch(commit):
        raise ValueError("Floci source commit is malformed")
    image_tag = f"blackbox-floci-sandbox:{commit[:12]}"
    print(f"building Floci {commit[:12]} from local clone", flush=True)
    _run(
        "docker",
        "build",
        "--build-arg",
        f"VERSION={commit}",
        "--tag",
        image_tag,
        "--file",
        "docker/Dockerfile",
        ".",
        cwd=floci_repo,
        timeout=1800,
    )
    image_id = _run(
        "docker", "image", "inspect", image_tag, "--format", "{{.Id}}", cwd=ROOT
    ).stdout.strip()
    environment = FlociEnvironment(
        commit=commit,
        image_id=image_id,
        storage_mode="wal",
        endpoint_scheme="https",
        tls_trust="pinned-self-signed-certificate",
        sigv4_validation_configured=True,
        iam_enforcement=True,
    )
    container_name = f"blackbox-floci-{os.getpid()}"
    container_created = False
    teardown = TeardownOutcome("not-run", -1, -1, "not-run")
    started_at = datetime.now(timezone.utc).isoformat()
    verification: dict[str, object] | None = None
    evidence_artifacts: dict[str, dict[str, object]] | None = None
    iam_delete_denied = False
    invalid_signature_denied = False
    iam_probe = AwsProbeOutcome("not-run", "not-run")
    signature_probe = AwsProbeOutcome("not-run", "not-run")
    iam_probe_receipt: dict[str, object] | None = None
    signature_probe_receipt: dict[str, object] | None = None
    restart_receipt: dict[str, object] | None = None
    policy: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="blackbox-floci-") as temporary:
        runtime = Path(temporary)
        data_dir = runtime / "data"
        data_dir.mkdir()
        data_dir.chmod(0o777)
        ca_bundle = data_dir / "tls" / "floci-selfsigned.crt"
        try:
            print("starting strict Floci sandbox", flush=True)
            _create_container(container_name, image_id, data_dir)
            container_created = True
            endpoint = _container_endpoint(container_name)
            _wait_container_ready(container_name, endpoint, ca_bundle)
            print("bootstrapping restricted IAM principal", flush=True)
            credentials, policy = _bootstrap_iam(endpoint, ca_bundle, f"evidence-{commit[:12]}")
            identity = FlociEvidenceIdentity(
                run_id=args.run_id,
                task_digest=_digest_bytes(b"floci-s3-content-addressed-round-trip/v1"),
                candidate_digest=_digest_files(
                    ROOT / "blackbox_autoresearch" / "evidence_lake.py",
                    ROOT / "scripts" / "produce_floci_evidence_store.py",
                ),
                harness_digest=_digest_files(Path(__file__).resolve()),
                evaluator_digest=_digest_files(
                    ROOT / "blackbox_autoresearch" / "floci_evidence_store.py",
                    ROOT / "scripts" / "verify_floci_evidence_store.py",
                ),
                policy_digest=_digest_bytes(_canonical(policy)),
            )
            config = {
                "schema": WORKER_CONFIG_SCHEMA,
                "endpoint": endpoint,
                "bucket": f"evidence-{commit[:12]}",
                "region": "us-east-1",
                "ca_bundle": str(ca_bundle),
                "environment": environment.__dict__,
                "identity": identity.__dict__,
            }
            config_path = runtime / "config.json"
            payload_path = runtime / "payload.json"
            policy_path = runtime / "iam-policy.json"
            manifest_path = runtime / "manifest.json"
            verification_path = runtime / "verification.json"
            _write_json(config_path, config)
            _write_json(
                payload_path,
                {
                    "schema": "blackbox-floci-sandbox-payload/v1",
                    "run_id": args.run_id,
                    "decision": "discard",
                    "reason": "L2 SANDBOX contract probe",
                },
            )
            _write_json(policy_path, policy)
            worker_env = {**os.environ, **credentials}
            _run(
                sys.executable,
                str(ROOT / "scripts" / "produce_floci_evidence_store.py"),
                "--config",
                str(config_path),
                "--payload",
                str(payload_path),
                "--output",
                str(manifest_path),
                cwd=ROOT,
                env=worker_env,
            )
            print("restarting Floci before fresh-process verification", flush=True)
            stopped = _run("docker", "stop", container_name, cwd=ROOT)
            restarted = _run("docker", "start", container_name, cwd=ROOT)
            endpoint = _container_endpoint(container_name)
            _wait_container_ready(container_name, endpoint, ca_bundle)
            verifier_config = {**config, "endpoint": endpoint}
            verifier_config_path = runtime / "verifier-config.json"
            _write_json(verifier_config_path, verifier_config)
            _run(
                sys.executable,
                str(ROOT / "scripts" / "verify_floci_evidence_store.py"),
                "--config",
                str(verifier_config_path),
                "--input",
                str(manifest_path),
                "--receipt",
                str(verification_path),
                "--planted-negative",
                cwd=ROOT,
                env=worker_env,
            )
            restart_receipt = {
                "stop_returncode": stopped.returncode,
                "start_returncode": restarted.returncode,
                "fresh_verifier": "verified",
            }
            print("checking IAM deny and invalid-signature paths", flush=True)
            verification = json.loads(verification_path.read_bytes())
            artifact_digest = str(verification["artifact_digest"]).removeprefix("sha256:")
            key = f"artifacts/{artifact_digest[:2]}/{artifact_digest[2:]}"
            denied = _aws(
                endpoint,
                ca_bundle,
                credentials,
                "s3api",
                "delete-object",
                "--bucket",
                config["bucket"],
                "--key",
                key,
                check=False,
            )
            iam_probe = _evaluate_aws_probe(denied, {"AccessDenied", "AccessDeniedException"})
            iam_probe_receipt = _probe_receipt("s3-delete-object", denied, iam_probe)
            iam_delete_denied = iam_probe.status == "denied"
            wrong_credentials = {
                "AWS_ACCESS_KEY_ID": credentials["AWS_ACCESS_KEY_ID"],
                "AWS_SECRET_ACCESS_KEY": credentials["AWS_SECRET_ACCESS_KEY"] + "-wrong",
            }
            bad_signature = _aws(
                endpoint,
                ca_bundle,
                wrong_credentials,
                "s3api",
                "head-object",
                "--bucket",
                config["bucket"],
                "--key",
                key,
                check=False,
            )
            signature_probe = _evaluate_aws_probe(
                bad_signature,
                {"SignatureDoesNotMatch", "InvalidSignature", "InvalidSignatureException"},
            )
            signature_probe_receipt = _probe_receipt(
                "s3-head-object-with-wrong-secret", bad_signature, signature_probe
            )
            invalid_signature_denied = signature_probe.status == "denied"
            evidence_artifacts = _export_evidence_bundle(
                artifacts_dir,
                manifest_path,
                verification_path,
                payload_path,
                policy_path,
            )
        finally:
            if container_created:
                removed = _run(
                    "docker", "rm", "--force", container_name, cwd=ROOT, check=False
                )
                inspected = _run(
                    "docker", "inspect", container_name, cwd=ROOT, check=False
                )
                teardown = _evaluate_teardown(removed, inspected)
    if (
        verification is None
        or evidence_artifacts is None
        or iam_probe_receipt is None
        or signature_probe_receipt is None
        or restart_receipt is None
        or teardown.status != "container-absent"
    ):
        raise RuntimeError("Floci sandbox did not produce verified evidence and teardown")
    finished_at = datetime.now(timezone.utc).isoformat()
    security_decision = _security_decision(iam_probe, signature_probe)
    verified_scope = ["S3 content-addressed round-trip", "WAL restart", "fresh-process retrieval"]
    if iam_delete_denied:
        verified_scope.append("IAM delete deny")
    receipt = {
        "schema": RUN_SCHEMA,
        "provider_kind": "floci-emulator",
        "maturity": "L2 SANDBOX",
        "production_claim_allowed": False,
        "decision": "verified" if security_decision == "pass" else "quarantine",
        "verified_scope": verified_scope,
        "run_id": args.run_id,
        "started_at": started_at,
        "finished_at": finished_at,
        "source": {"kind": "local-clone", "commit": commit},
        "image_id": image_id,
        "storage_mode": "wal",
        "tls": "pinned-self-signed-certificate",
        "sigv4_configuration": "enabled",
        "sigv4_wrong_secret": signature_probe.status,
        "iam_enforcement": "enabled",
        "security_decision": security_decision,
        "restart_reverification": restart_receipt,
        "iam_delete_denied": iam_delete_denied,
        "invalid_signature_denied": invalid_signature_denied,
        "iam_delete_probe": iam_probe_receipt,
        "invalid_signature_probe": signature_probe_receipt,
        "teardown": teardown.__dict__,
        "verification": verification,
        "evidence_artifacts": evidence_artifacts,
        "limitations": [
            "external production object storage remains unproven",
            "production metadata/index, managed KMS/HSM, backup/restore, and multi-host recovery remain unproven",
        ],
        **_reproduction_metadata(commit, args.run_id),
    }
    _write_json(receipt_path, receipt)
    print(
        json.dumps(
            {
                "schema": RUN_SCHEMA,
                "decision": receipt["decision"],
                "maturity": "L2 SANDBOX",
            },
            sort_keys=True,
        )
    )
    return 0 if security_decision == "pass" else 3


def main() -> int:
    args = parser().parse_args()
    receipt_path, artifacts_dir = _validate_output_paths(
        args.receipt, args.artifacts_dir
    )
    return _run_with_artifact_reservation(
        artifacts_dir,
        lambda: _execute(args, receipt_path, artifacts_dir),
    )


if __name__ == "__main__":
    raise SystemExit(main())
