from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from blackbox_autoresearch.floci_evidence_store import VERIFICATION_LIMITATIONS
from scripts.run_floci_evidence_store_sandbox import RUN_LIMITATIONS


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "scripts" / "verify_floci_sandbox_bundle.py"


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def digest_files(*paths: Path) -> str:
    payload = bytearray()
    for path in paths:
        payload.extend(path.name.encode() + b"\0" + path.read_bytes() + b"\0")
    return digest_bytes(bytes(payload))


def write_json(path: Path, value: object) -> bytes:
    payload = canonical(value) + b"\n"
    path.write_bytes(payload)
    return payload


def build_quarantine_bundle(root: Path) -> Path:
    run_id = "floci-sandbox-fixture"
    commit = "a" * 40
    image_id = "sha256:" + "b" * 64
    environment = {
        "commit": commit,
        "image_id": image_id,
        "storage_mode": "wal",
        "endpoint_scheme": "https",
        "tls_trust": "pinned-self-signed-certificate",
        "sigv4_validation_configured": True,
        "iam_enforcement": True,
    }
    environment_digest = digest_bytes(canonical(environment))
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"}],
    }
    payload = {
        "schema": "blackbox-floci-sandbox-payload/v1",
        "run_id": run_id,
        "decision": "discard",
        "reason": "L2 SANDBOX contract probe",
    }
    payload_bytes = canonical(payload) + b"\n"
    identities = {
        "task": digest_bytes(b"floci-s3-content-addressed-round-trip/v1"),
        "candidate": digest_files(
            ROOT / "blackbox_autoresearch/evidence_lake.py",
            ROOT / "scripts/produce_floci_evidence_store.py",
        ),
        "environment": environment_digest,
        "harness": digest_files(ROOT / "scripts/run_floci_evidence_store_sandbox.py"),
        "evaluator": digest_files(
            ROOT / "blackbox_autoresearch/floci_evidence_store.py",
            ROOT / "scripts/verify_floci_evidence_store.py",
        ),
        "policy": digest_bytes(canonical(policy)),
    }
    manifest = {
        "schema": "blackbox-floci-evidence-store/v1",
        "provider_kind": "floci-emulator",
        "maturity": "L2 SANDBOX",
        "production_claim_allowed": False,
        "run": {"run_id": run_id, "producer_pid": 101},
        "environment": environment,
        "identities": identities,
        "artifact": {"digest": digest_bytes(payload_bytes), "size": len(payload_bytes)},
        "produced_at": "2026-08-12T00:00:01+00:00",
    }
    verification = {
        "schema": "blackbox-floci-evidence-store-verification/v2",
        "verified": True,
        "provider_kind": "floci-emulator",
        "maturity": "L2 SANDBOX",
        "production_claim_allowed": False,
        "run_id": run_id,
        "artifact_digest": digest_bytes(payload_bytes),
        "environment_digest": environment_digest,
        "producer_pid": 101,
        "verifier_pid": 102,
        "process_separation": "verified",
        "local_digest_negative": "detected",
        "limitations": list(VERIFICATION_LIMITATIONS),
        "verified_at": "2026-08-12T00:00:02+00:00",
    }
    children = {
        "producer_manifest": ("producer-manifest.json", manifest),
        "verifier_receipt": ("verifier-receipt.json", verification),
        "input_payload": ("input-payload.json", payload),
        "iam_policy": ("iam-policy.json", policy),
    }
    artifact_records = {}
    for key, (name, value) in children.items():
        child = write_json(root / name, value)
        artifact_records[key] = {
            "locator": name,
            "sha256": digest_bytes(child),
            "size": len(child),
        }
    iam_stderr = "An error occurred (AccessDenied) when calling DeleteObject"
    endpoint = "https://127.0.0.1:4566"
    bucket = "evidence-aaaaaaaaaaaa"
    artifact_hex = digest_bytes(payload_bytes).removeprefix("sha256:")
    key = f"artifacts/{artifact_hex[:2]}/{artifact_hex[2:]}"
    principal_digest = digest_bytes(b"fixture-access-key")
    receipt = {
        "schema": "blackbox-floci-sandbox-run/v2",
        "provider_kind": "floci-emulator",
        "maturity": "L2 SANDBOX",
        "production_claim_allowed": False,
        "decision": "quarantine",
        "verified_scope": [
            "S3 content-addressed round-trip",
            "WAL restart",
            "fresh-process retrieval",
            "IAM delete deny",
        ],
        "run_id": run_id,
        "started_at": "2026-08-12T00:00:00+00:00",
        "finished_at": "2026-08-12T00:00:03+00:00",
        "source": {"kind": "local-clone", "commit": commit},
        "image_id": image_id,
        "storage_mode": "wal",
        "tls": "pinned-self-signed-certificate",
        "sigv4_configuration": "enabled",
        "sigv4_wrong_secret": "accepted",
        "iam_enforcement": "enabled",
        "security_decision": "quarantine",
        "restart_reverification": {
            "stop_returncode": 0,
            "start_returncode": 0,
            "fresh_verifier": "verified",
        },
        "iam_delete_denied": True,
        "invalid_signature_denied": False,
        "iam_delete_probe": {
            "operation": "s3-delete-object",
            "argv": [
                "aws", "--endpoint-url", endpoint, "--ca-bundle", "$RUN_CA_BUNDLE",
                "s3api", "delete-object", "--bucket", bucket, "--key", key,
            ],
            "principal_access_key_sha256": principal_digest,
            "returncode": 254,
            "stdout": "",
            "stderr": iam_stderr,
            "outcome": {"status": "denied", "detail": "AccessDenied"},
        },
        "invalid_signature_probe": {
            "operation": "s3-head-object-with-wrong-secret",
            "argv": [
                "aws", "--endpoint-url", endpoint, "--ca-bundle", "$RUN_CA_BUNDLE",
                "s3api", "head-object", "--bucket", bucket, "--key", key,
            ],
            "principal_access_key_sha256": principal_digest,
            "returncode": 0,
            "stdout": "{}\n",
            "stderr": "",
            "outcome": {"status": "accepted", "detail": "request-succeeded"},
        },
        "teardown": {
            "status": "container-absent",
            "remove_returncode": 0,
            "inspect_returncode": 1,
            "inspect_detail": "error: no such object: fixture",
        },
        "verification": verification,
        "evidence_artifacts": artifact_records,
        "limitations": list(RUN_LIMITATIONS),
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
            "FLOCI_REPO": {"required": True, "source_commit": commit},
            "NEW_ARTIFACTS_DIR": {"required": True, "must_not_exist": True},
        },
    }
    receipt_path = root / "runner-receipt.json"
    write_json(receipt_path, receipt)
    return receipt_path


class FlociSandboxBundleVerifierTests(unittest.TestCase):
    def temporary_directory(self) -> tempfile.TemporaryDirectory[str]:
        return tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())

    def run_verifier(self, receipt: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(VERIFIER), "--receipt", str(receipt)],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )

    def test_replays_a_complete_quarantine_bundle_without_network(self) -> None:
        with self.temporary_directory() as raw:
            receipt = build_quarantine_bundle(Path(raw))

            result = self.run_verifier(receipt)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"decision": "quarantine"', result.stdout)
        self.assertIn('"bundle_integrity": "verified"', result.stdout)

    def test_replays_the_committed_quarantine_bundle(self) -> None:
        receipt = (
            ROOT
            / "evidence/floci/floci-sandbox-20260812-05/runner-receipt.json"
        )

        result = self.run_verifier(receipt)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"run_id": "floci-sandbox-20260812-05"', result.stdout)
        self.assertIn('"decision": "quarantine"', result.stdout)

    def test_rejects_a_tampered_child_before_semantic_replay(self) -> None:
        with self.temporary_directory() as raw:
            root = Path(raw)
            receipt = build_quarantine_bundle(root)
            manifest = root / "producer-manifest.json"
            payload = bytearray(manifest.read_bytes())
            payload[0] ^= 1
            manifest.write_bytes(payload)

            result = self.run_verifier(receipt)

        self.assertEqual(result.returncode, 2)
        self.assertIn("producer manifest digest mismatch", result.stderr)

    def test_rejects_provenance_drift_even_when_child_digest_is_updated(self) -> None:
        with self.temporary_directory() as raw:
            root = Path(raw)
            receipt_path = build_quarantine_bundle(root)
            manifest_path = root / "producer-manifest.json"
            manifest = json.loads(manifest_path.read_bytes())
            manifest["identities"]["harness"] = "sha256:" + "0" * 64
            manifest_bytes = write_json(manifest_path, manifest)
            receipt = json.loads(receipt_path.read_bytes())
            receipt["evidence_artifacts"]["producer_manifest"].update(
                sha256=digest_bytes(manifest_bytes), size=len(manifest_bytes)
            )
            write_json(receipt_path, receipt)

            result = self.run_verifier(receipt_path)

        self.assertEqual(result.returncode, 2)
        self.assertIn("provenance identity mismatch", result.stderr)

    def test_rejects_a_probe_classification_that_disagrees_with_raw_output(self) -> None:
        with self.temporary_directory() as raw:
            root = Path(raw)
            receipt_path = build_quarantine_bundle(root)
            receipt = json.loads(receipt_path.read_bytes())
            receipt["invalid_signature_probe"]["outcome"] = {
                "status": "denied",
                "detail": "SignatureDoesNotMatch",
            }
            write_json(receipt_path, receipt)

            result = self.run_verifier(receipt_path)

        self.assertEqual(result.returncode, 2)
        self.assertIn("outcome replay mismatch", result.stderr)

    def test_rejects_probe_target_drift(self) -> None:
        with self.temporary_directory() as raw:
            root = Path(raw)
            receipt_path = build_quarantine_bundle(root)
            receipt = json.loads(receipt_path.read_bytes())
            receipt["iam_delete_probe"]["argv"][-1] = "artifacts/wrong"
            write_json(receipt_path, receipt)

            result = self.run_verifier(receipt_path)

        self.assertEqual(result.returncode, 2)
        self.assertIn("probe argv mismatch", result.stderr)

    def test_rejects_scope_or_limitations_drift(self) -> None:
        for field, value in (
            ("verified_scope", ["L4 production storage"]),
            ("limitations", []),
        ):
            with self.subTest(field=field), self.temporary_directory() as raw:
                root = Path(raw)
                receipt_path = build_quarantine_bundle(root)
                receipt = json.loads(receipt_path.read_bytes())
                receipt[field] = value
                write_json(receipt_path, receipt)

                result = self.run_verifier(receipt_path)

            self.assertEqual(result.returncode, 2)
            self.assertIn(f"{field} mismatch", result.stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_rejects_a_bundle_under_a_symlinked_ancestor(self) -> None:
        with self.temporary_directory() as raw:
            root = Path(raw)
            real = root / "real"
            real.mkdir()
            build_quarantine_bundle(real)
            link = root / "linked"
            link.symlink_to(real, target_is_directory=True)

            result = self.run_verifier(link / "runner-receipt.json")

        self.assertEqual(result.returncode, 2)
        self.assertIn("symlink", result.stderr)


if __name__ == "__main__":
    unittest.main()
