#!/usr/bin/env python3
"""Replay integrity, provenance and outcome classification for a Floci bundle."""

from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Mapping
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from blackbox_autoresearch.floci_evidence_store import (  # noqa: E402
    EVIDENCE_SCHEMA,
    VERIFICATION_SCHEMA,
    VERIFICATION_LIMITATIONS,
    FlociEnvironment,
)
from scripts.run_floci_evidence_store_sandbox import (  # noqa: E402
    BASE_VERIFIED_SCOPE,
    RUN_SCHEMA,
    RUN_LIMITATIONS,
    _canonical,
    _digest_bytes,
    _digest_files,
    _evaluate_aws_probe,
    _reproduction_metadata,
)


_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ARTIFACT_NAMES = {
    "producer_manifest": "producer-manifest.json",
    "verifier_receipt": "verifier-receipt.json",
    "input_payload": "input-payload.json",
    "iam_policy": "iam-policy.json",
}


def _require(condition: bool, detail: str) -> None:
    if not condition:
        raise ValueError(detail)


def _require_keys(value: Mapping[str, object], expected: set[str], name: str) -> None:
    _require(set(value) == expected, f"{name} keys drift")


def _parse_object(payload: bytes, name: str) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise ValueError(f"cannot parse {name}: {error}") from error
    _require(isinstance(value, dict), f"{name} must contain a JSON object")
    return value


def _read_regular_file(path: Path, name: str) -> bytes:
    absolute = path.absolute()
    directory_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, component in enumerate(absolute.parts[1:]):
            is_last = index == len(absolute.parts[1:]) - 1
            flags = os.O_RDONLY | os.O_NOFOLLOW
            if not is_last:
                flags |= os.O_DIRECTORY
            try:
                next_fd = os.open(component, flags, dir_fd=directory_fd)
            except OSError as error:
                raise ValueError(f"cannot read {name} without symlink traversal: {error}") from error
            os.close(directory_fd)
            directory_fd = next_fd
        _require(stat.S_ISREG(os.fstat(directory_fd).st_mode), f"{name} must be a regular file")
        chunks = []
        while chunk := os.read(directory_fd, 65536):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(directory_fd)


def _load_object(path: Path, name: str) -> dict[str, Any]:
    return _parse_object(_read_regular_file(path, name), name)


def _load_artifact(
    root: Path, name: str, expected_locator: str, record: object
) -> tuple[dict[str, Any], bytes]:
    _require(isinstance(record, dict), f"{name} record must be an object")
    _require_keys(record, {"locator", "sha256", "size"}, f"{name} record")
    locator, digest, size = record["locator"], record["sha256"], record["size"]
    _require(locator == expected_locator, f"{name} locator mismatch")
    _require(
        isinstance(digest, str) and _DIGEST_RE.fullmatch(digest) is not None,
        f"{name} digest is malformed",
    )
    _require(type(size) is int and size >= 0, f"{name} size is malformed")
    payload = _read_regular_file(root / expected_locator, name)
    _require(len(payload) == size, f"{name} size mismatch")
    _require(_digest_bytes(payload) == digest, f"{name} digest mismatch")
    return _parse_object(payload, name), payload


def _parse_timestamp(value: object, name: str) -> datetime:
    _require(isinstance(value, str), f"{name} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{name} must be an ISO-8601 timestamp") from error
    _require(
        parsed.tzinfo is not None and parsed.utcoffset() is not None,
        f"{name} lacks timezone",
    )
    return parsed


def _replay_probe(
    record: object,
    operation: str,
    expected_errors: set[str],
    expected_argv: list[str],
) -> tuple[str, str]:
    _require(isinstance(record, dict), f"{operation} probe must be an object")
    _require_keys(
        record,
        {
            "operation", "argv", "principal_access_key_sha256", "returncode",
            "stdout", "stderr", "outcome",
        },
        f"{operation} probe",
    )
    _require(record["operation"] == operation, f"{operation} name mismatch")
    _require(record["argv"] == expected_argv, f"{operation} probe argv mismatch")
    principal_digest = record["principal_access_key_sha256"]
    _require(
        isinstance(principal_digest, str)
        and _DIGEST_RE.fullmatch(principal_digest) is not None,
        f"{operation} principal digest is malformed",
    )
    _require(type(record["returncode"]) is int, f"{operation} returncode is invalid")
    _require(isinstance(record["stdout"], str), f"{operation} stdout is invalid")
    _require(isinstance(record["stderr"], str), f"{operation} stderr is invalid")
    outcome = record["outcome"]
    _require(isinstance(outcome, dict), f"{operation} outcome must be an object")
    _require_keys(outcome, {"status", "detail"}, f"{operation} outcome")
    replayed = _evaluate_aws_probe(
        subprocess.CompletedProcess(
            ("aws",), record["returncode"], record["stdout"], record["stderr"]
        ),
        expected_errors,
    )
    _require(outcome == replayed.__dict__, f"{operation} outcome replay mismatch")
    return replayed.status, principal_digest


def _verify_common_claims(value: Mapping[str, object], name: str) -> None:
    _require(value["provider_kind"] == "floci-emulator", f"{name} provider mismatch")
    _require(value["maturity"] == "L2 SANDBOX", f"{name} maturity mismatch")
    _require(
        value["production_claim_allowed"] is False,
        f"{name} production claim must remain disabled",
    )


def _probe_argv(
    record: object, action: str, bucket: str, key: str
) -> list[str]:
    _require(isinstance(record, dict), f"{action} probe must be an object")
    argv = record.get("argv")
    _require(isinstance(argv, list) and len(argv) >= 3, f"{action} probe argv is invalid")
    endpoint = argv[2]
    _require(isinstance(endpoint, str), f"{action} endpoint is invalid")
    parsed = urlparse(endpoint)
    _require(
        parsed.scheme == "https"
        and parsed.hostname in {"127.0.0.1", "localhost"}
        and parsed.port is not None
        and parsed.path == "",
        f"{action} endpoint is outside the loopback sandbox",
    )
    return [
        "aws", "--endpoint-url", endpoint, "--ca-bundle", "$RUN_CA_BUNDLE",
        "s3api", action, "--bucket", bucket, "--key", key,
    ]


def _verify_provenance(
    receipt: Mapping[str, object],
    manifest: Mapping[str, object],
    verification: Mapping[str, object],
    policy: Mapping[str, object],
) -> None:
    environment_value = manifest["environment"]
    identities = manifest["identities"]
    _require(isinstance(environment_value, dict), "environment must be an object")
    _require(isinstance(identities, dict), "identities must be an object")
    _require_keys(
        identities,
        {"task", "candidate", "environment", "harness", "evaluator", "policy"},
        "identities",
    )
    try:
        environment = FlociEnvironment(**environment_value)
    except TypeError as error:
        raise ValueError(f"environment fields drift: {error}") from error
    expected = {
        "task": _digest_bytes(b"floci-s3-content-addressed-round-trip/v1"),
        "candidate": _digest_files(
            ROOT / "blackbox_autoresearch/evidence_lake.py",
            ROOT / "scripts/produce_floci_evidence_store.py",
        ),
        "environment": environment.digest,
        "harness": _digest_files(ROOT / "scripts/run_floci_evidence_store_sandbox.py"),
        "evaluator": _digest_files(
            ROOT / "blackbox_autoresearch/floci_evidence_store.py",
            ROOT / "scripts/verify_floci_evidence_store.py",
        ),
        "policy": _digest_bytes(_canonical(policy)),
    }
    _require(identities == expected, "provenance identity mismatch")
    _require(
        verification["environment_digest"] == environment.digest,
        "environment digest mismatch",
    )
    _require(
        receipt["source"] == {"kind": "local-clone", "commit": environment.commit},
        "source identity mismatch",
    )
    _require(receipt["image_id"] == environment.image_id, "image identity mismatch")
    _require(receipt["storage_mode"] == environment.storage_mode == "wal", "storage mismatch")
    _require(
        receipt["tls"] == environment.tls_trust == "pinned-self-signed-certificate",
        "TLS control mismatch",
    )
    _require(
        receipt["sigv4_configuration"] == "enabled"
        and environment.sigv4_validation_configured,
        "SigV4 configuration mismatch",
    )
    _require(
        receipt["iam_enforcement"] == "enabled" and environment.iam_enforcement,
        "IAM configuration mismatch",
    )
    reproduction = _reproduction_metadata(environment.commit, str(receipt["run_id"]))
    _require(
        receipt["reproduction_command"] == reproduction["reproduction_command"],
        "reproduction command mismatch",
    )
    _require(
        receipt["reproduction_environment"]
        == reproduction["reproduction_environment"],
        "reproduction environment mismatch",
    )


def verify_bundle(receipt_path: Path) -> dict[str, object]:
    receipt = _load_object(receipt_path, "runner receipt")
    _require_keys(
        receipt,
        {
            "schema", "provider_kind", "maturity", "production_claim_allowed",
            "decision", "verified_scope", "run_id", "started_at", "finished_at",
            "source", "image_id", "storage_mode", "tls", "sigv4_configuration",
            "sigv4_wrong_secret", "iam_enforcement", "security_decision",
            "restart_reverification", "iam_delete_denied", "invalid_signature_denied",
            "iam_delete_probe", "invalid_signature_probe", "teardown", "verification",
            "evidence_artifacts", "limitations", "reproduction_command",
            "reproduction_environment",
        },
        "runner receipt",
    )
    _require(receipt["schema"] == RUN_SCHEMA, "runner schema mismatch")
    _verify_common_claims(receipt, "runner receipt")
    _require(receipt["limitations"] == list(RUN_LIMITATIONS), "limitations mismatch")

    records = receipt["evidence_artifacts"]
    _require(isinstance(records, dict), "evidence artifacts must be an object")
    _require(set(records) == set(_ARTIFACT_NAMES), "evidence artifact records drift")
    loaded = {
        key: _load_artifact(
            receipt_path.parent, key.replace("_", " "), locator, records[key]
        )
        for key, locator in _ARTIFACT_NAMES.items()
    }
    manifest, _ = loaded["producer_manifest"]
    verification, _ = loaded["verifier_receipt"]
    payload, payload_bytes = loaded["input_payload"]
    policy, _ = loaded["iam_policy"]

    _require_keys(
        manifest,
        {
            "schema", "provider_kind", "maturity", "production_claim_allowed",
            "run", "environment", "identities", "artifact", "produced_at",
        },
        "producer manifest",
    )
    _require(manifest["schema"] == EVIDENCE_SCHEMA, "producer schema mismatch")
    _verify_common_claims(manifest, "producer manifest")
    _require_keys(
        verification,
        {
            "schema", "verified", "provider_kind", "maturity",
            "production_claim_allowed", "run_id", "artifact_digest",
            "environment_digest", "producer_pid", "verifier_pid",
            "process_separation", "local_digest_negative", "limitations",
            "verified_at",
        },
        "verifier receipt",
    )
    _require(verification["schema"] == VERIFICATION_SCHEMA, "verifier schema mismatch")
    _verify_common_claims(verification, "verifier receipt")
    _require(
        verification["limitations"] == list(VERIFICATION_LIMITATIONS),
        "verification limitations mismatch",
    )

    run_id = receipt["run_id"]
    run = manifest["run"]
    _require(isinstance(run_id, str) and bool(run_id), "runner run_id is missing")
    _require(isinstance(run, dict), "producer run must be an object")
    _require_keys(run, {"run_id", "producer_pid"}, "producer run")
    _require(run["run_id"] == verification["run_id"] == run_id, "run_id mismatch")
    _require(type(run["producer_pid"]) is int and run["producer_pid"] > 0, "producer PID invalid")
    _require(type(verification["verifier_pid"]) is int and verification["verifier_pid"] > 0, "verifier PID invalid")
    _require(run["producer_pid"] == verification["producer_pid"], "producer PID mismatch")
    _require(run["producer_pid"] != verification["verifier_pid"], "fresh verifier not proven")
    _require(verification["verified"] is True, "verifier did not verify evidence")
    _require(verification["process_separation"] == "verified", "process separation mismatch")
    _require(verification["local_digest_negative"] == "detected", "local digest negative mismatch")
    _require(receipt["verification"] == verification, "embedded verifier receipt mismatch")

    _require(payload.get("run_id") == run_id, "input payload run_id mismatch")
    artifact = manifest["artifact"]
    _require(isinstance(artifact, dict), "artifact must be an object")
    _require_keys(artifact, {"digest", "size"}, "artifact")
    _require(artifact["digest"] == _digest_bytes(payload_bytes), "input payload digest mismatch")
    _require(artifact["size"] == len(payload_bytes), "input payload size mismatch")
    _require(verification["artifact_digest"] == artifact["digest"], "artifact digest mismatch")
    _verify_provenance(receipt, manifest, verification, policy)

    started = _parse_timestamp(receipt["started_at"], "started_at")
    produced = _parse_timestamp(manifest["produced_at"], "produced_at")
    verified = _parse_timestamp(verification["verified_at"], "verified_at")
    finished = _parse_timestamp(receipt["finished_at"], "finished_at")
    _require(started <= produced <= verified <= finished, "timestamps are out of order")

    _require(
        receipt["restart_reverification"]
        == {"stop_returncode": 0, "start_returncode": 0, "fresh_verifier": "verified"},
        "restart receipt mismatch",
    )
    teardown = receipt["teardown"]
    _require(isinstance(teardown, dict), "teardown must be an object")
    _require_keys(
        teardown,
        {"status", "remove_returncode", "inspect_returncode", "inspect_detail"},
        "teardown",
    )
    _require(teardown["status"] == "container-absent", "teardown is not proven")
    _require(teardown["remove_returncode"] == 0, "container removal failed")
    _require(
        type(teardown["inspect_returncode"]) is int
        and teardown["inspect_returncode"] != 0,
        "container inspect unexpectedly succeeded",
    )
    _require(
        "no such object" in str(teardown["inspect_detail"]).lower(),
        "container absence was not explicit",
    )

    environment_value = manifest["environment"]
    _require(isinstance(environment_value, dict), "environment must be an object")
    commit = environment_value.get("commit")
    _require(isinstance(commit, str), "environment commit is invalid")
    bucket = f"evidence-{commit[:12]}"
    artifact_hex = str(artifact["digest"]).removeprefix("sha256:")
    key = f"artifacts/{artifact_hex[:2]}/{artifact_hex[2:]}"
    iam_record = receipt["iam_delete_probe"]
    signature_record = receipt["invalid_signature_probe"]
    iam_status, iam_principal = _replay_probe(
        iam_record,
        "s3-delete-object",
        {"AccessDenied", "AccessDeniedException"},
        _probe_argv(iam_record, "delete-object", bucket, key),
    )
    signature_status, signature_principal = _replay_probe(
        signature_record,
        "s3-head-object-with-wrong-secret",
        {"SignatureDoesNotMatch", "InvalidSignature", "InvalidSignatureException"},
        _probe_argv(signature_record, "head-object", bucket, key),
    )
    _require(iam_principal == signature_principal, "probe principal identity mismatch")
    _require(receipt["iam_delete_denied"] == (iam_status == "denied"), "IAM probe mismatch")
    _require(receipt["invalid_signature_denied"] == (signature_status == "denied"), "signature probe mismatch")
    _require(receipt["sigv4_wrong_secret"] == signature_status, "wrong-secret summary mismatch")
    security = "pass" if iam_status == signature_status == "denied" else "quarantine"
    decision = "verified" if security == "pass" else "quarantine"
    _require(receipt["security_decision"] == security, "security decision mismatch")
    _require(receipt["decision"] == decision, "runner decision mismatch")
    expected_scope = list(BASE_VERIFIED_SCOPE)
    if iam_status == "denied":
        expected_scope.append("IAM delete deny")
    _require(receipt["verified_scope"] == expected_scope, "verified_scope mismatch")
    return {
        "schema": RUN_SCHEMA,
        "decision": decision,
        "run_id": run_id,
        "bundle_integrity": "verified",
    }


def main() -> int:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--receipt", type=Path, required=True)
    args = value.parse_args()
    try:
        result = verify_bundle(args.receipt.absolute())
    except (OSError, TypeError, ValueError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
