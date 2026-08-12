from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from blackbox_autoresearch.floci_evidence_store import VERIFICATION_SCHEMA
from scripts.run_floci_evidence_store_sandbox import (
    RUN_SCHEMA,
    AwsCredentials,
    AwsProbeOutcome,
    _create_container,
    _aws,
    _evaluate_aws_probe,
    _evaluate_teardown,
    _export_evidence_bundle,
    _probe_receipt,
    _reproduction_metadata,
    _run_with_artifact_reservation,
    _security_decision,
    _snapshot_ca,
    _validate_output_paths,
)


class FlociEvidenceStoreRunnerTests(unittest.TestCase):
    def test_ca_snapshot_is_runner_owned_and_independent_from_provider_source(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "provider-ca.pem"
            destination = root / "snapshot.pem"
            source.write_bytes(b"provider-ca")

            snapshot, payload = _snapshot_ca(source, destination)
            source.write_bytes(b"provider-mutated")

            self.assertEqual(payload, b"provider-ca")
            self.assertEqual(snapshot.read_bytes(), b"provider-ca")
            self.assertEqual(snapshot.stat().st_mode & 0o777, 0o400)

    def test_run_and_verifier_schema_changes_are_explicit(self):
        self.assertEqual(RUN_SCHEMA, "blackbox-floci-sandbox-run/v3")
        self.assertEqual(
            VERIFICATION_SCHEMA,
            "blackbox-floci-evidence-store-verification/v3",
        )

    def test_aws_probe_only_accepts_explicit_expected_service_error(self):
        denied = subprocess.CompletedProcess(
            ("aws",),
            254,
            "",
            "An error occurred (SignatureDoesNotMatch) when calling HeadObject",
        )
        transport = subprocess.CompletedProcess(
            ("aws",),
            255,
            "",
            "Could not connect to the endpoint URL",
        )
        accepted = subprocess.CompletedProcess(("aws",), 0, "{}", "")

        self.assertEqual(
            _evaluate_aws_probe(denied, {"SignatureDoesNotMatch"}),
            AwsProbeOutcome("denied", "SignatureDoesNotMatch"),
        )
        self.assertEqual(
            _evaluate_aws_probe(transport, {"SignatureDoesNotMatch"}),
            AwsProbeOutcome("inconclusive", "unclassified-cli-error"),
        )
        self.assertEqual(
            _evaluate_aws_probe(accepted, {"SignatureDoesNotMatch"}),
            AwsProbeOutcome("accepted", "request-succeeded"),
        )
        self.assertEqual(
            _security_decision(
                AwsProbeOutcome("denied", "AccessDenied"),
                AwsProbeOutcome("accepted", "request-succeeded"),
            ),
            "quarantine",
        )

    def test_container_creation_does_not_hide_cleanup_ownership_behind_port_lookup(self):
        completed = subprocess.CompletedProcess(("docker",), 0, "container-id\n", "")
        with patch(
            "scripts.run_floci_evidence_store_sandbox._run",
            return_value=completed,
        ) as run:
            _create_container("floci-test", "sha256:" + "a" * 64, "/tmp/data")

        self.assertEqual(run.call_args.args[:3], ("docker", "run", "-d"))

    def test_evidence_bundle_preserves_exact_manifest_and_verifier_receipt(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = root / "manifest.json"
            verification = root / "verification.json"
            payload = root / "payload.json"
            policy = root / "policy.json"
            manifest.write_bytes(b'{"schema":"producer"}\n')
            verification.write_bytes(b'{"schema":"verifier"}\n')
            payload.write_bytes(b'{"schema":"payload"}\n')
            policy.write_bytes(b'{"schema":"policy"}\n')
            artifacts = root / "exported"
            artifacts.mkdir()

            exported = _export_evidence_bundle(
                artifacts, manifest, verification, payload, policy
            )

            self.assertEqual(
                (artifacts / "producer-manifest.json").read_bytes(),
                manifest.read_bytes(),
            )
            self.assertEqual(
                (artifacts / "verifier-receipt.json").read_bytes(),
                verification.read_bytes(),
            )
            self.assertEqual(
                exported,
                {
                    "producer_manifest": {
                        "locator": "producer-manifest.json",
                        "sha256": "sha256:39e20f2e5626c8189c77fdc968b7039c4324ce2ad2c7d8803c8ea6dcee3e9e92",
                        "size": 22,
                    },
                    "verifier_receipt": {
                        "locator": "verifier-receipt.json",
                        "sha256": "sha256:7018957b0d988b6443dc1c7709fad25ca087fb4712d72adde714b952483f997a",
                        "size": 22,
                    },
                    "input_payload": {
                        "locator": "input-payload.json",
                        "sha256": "sha256:6d8079379dd182151418f5e4bc582bf98133f04111169c5a7b00182fc801a77b",
                        "size": 21,
                    },
                    "iam_policy": {
                        "locator": "iam-policy.json",
                        "sha256": "sha256:3ae3041e9cebe6c7d13d6d0bc42612c564de9956a1b33aa42574d414c8a6e07a",
                        "size": 20,
                    },
                },
            )

    def test_output_paths_require_a_new_shared_artifact_directory(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            artifacts = root / "evidence"
            receipt = artifacts / "runner-receipt.json"

            self.assertEqual(
                _validate_output_paths(receipt, artifacts),
                (receipt.resolve(), artifacts.resolve()),
            )
            artifacts.mkdir()
            with self.assertRaisesRegex(ValueError, "artifacts directory already exists"):
                _validate_output_paths(receipt, artifacts)
            with self.assertRaisesRegex(ValueError, "inside --artifacts-dir"):
                _validate_output_paths(root / "elsewhere.json", root / "new-evidence")
            with self.assertRaisesRegex(ValueError, "filename must be"):
                _validate_output_paths(
                    root / "third-evidence" / "producer-manifest.json",
                    root / "third-evidence",
                )

    def test_teardown_requires_successful_remove_and_explicit_absence(self):
        removed = subprocess.CompletedProcess(("docker",), 0, "container\n", "")
        absent = subprocess.CompletedProcess(
            ("docker",), 1, "", "error: no such object: container"
        )
        daemon_failure = subprocess.CompletedProcess(
            ("docker",), 1, "", "permission denied connecting to daemon"
        )

        self.assertEqual(_evaluate_teardown(removed, absent).status, "container-absent")
        self.assertEqual(_evaluate_teardown(removed, daemon_failure).status, "failed")

    def test_artifact_reservation_cleans_failure_and_keeps_completed_bundle(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            failed = root / "failed"
            completed = root / "completed"

            def fail_after_partial_write():
                (failed / "partial.json").write_text("partial", encoding="utf-8")
                raise RuntimeError("teardown failed")

            with self.assertRaisesRegex(RuntimeError, "teardown failed"):
                _run_with_artifact_reservation(failed, fail_after_partial_write)
            self.assertFalse(failed.exists())

            result = _run_with_artifact_reservation(
                completed,
                lambda: (completed / "runner-receipt.json").write_text(
                    "complete", encoding="utf-8"
                ),
            )
            self.assertEqual(result, 8)
            self.assertEqual(
                (completed / "runner-receipt.json").read_text(encoding="utf-8"),
                "complete",
            )

    def test_probe_receipt_preserves_raw_result_and_classification(self):
        result = subprocess.CompletedProcess(
            ("aws", "--ca-bundle", "/tmp/ca.pem", "s3api", "delete-object"),
            254, "", "An error occurred (AccessDenied) when calling DeleteObject",
        )
        with tempfile.TemporaryDirectory() as raw:
            ca_bundle = Path(raw) / "ca.pem"
            ca_bundle.write_bytes(b"fixture-ca")
            with patch("scripts.run_floci_evidence_store_sandbox._run", return_value=result):
                execution = _aws(
                    "https://127.0.0.1:4566",
                    ca_bundle,
                    AwsCredentials.configured("fixture-key", "configured").wrong_secret(),
                    "s3api", "delete-object",
                )
        outcome = _evaluate_aws_probe(execution.result, {"AccessDenied"})

        self.assertEqual(
            _probe_receipt("s3-delete-object", execution, outcome),
            {
                "operation": "s3-delete-object",
                "argv": [
                    "aws",
                    "--ca-bundle",
                    "$RUN_CA_BUNDLE",
                    "s3api",
                    "delete-object",
                ],
                "principal_access_key_sha256": "sha256:66e7c82b49bb291dd09c8e020448311c4a7bb96aeb5c5db769f66812b13a50b5",
                "credential_variant": "wrong-secret",
                "ca_bundle_sha256": "sha256:fca046ca96fabdc57856c287f889f3a2a20dc3192abefa0443ae0e6505595fdf",
                "returncode": 254,
                "stdout": "",
                "stderr": "An error occurred (AccessDenied) when calling DeleteObject",
                "outcome": {"status": "denied", "detail": "AccessDenied"},
            },
        )

    def test_wrong_secret_variant_is_derived_from_a_configured_baseline(self):
        configured = AwsCredentials.configured("fixture-key", "fixture-secret")
        wrong = configured.wrong_secret()

        self.assertEqual(wrong.access_key_id, configured.access_key_id)
        self.assertNotEqual(wrong.secret_access_key, configured.secret_access_key)
        self.assertEqual(wrong.variant, "wrong-secret")
        with self.assertRaisesRegex(ValueError, "configured baseline"):
            wrong.wrong_secret()

    def test_reproduction_command_requires_a_new_artifact_directory(self):
        metadata = _reproduction_metadata("a" * 40, "floci-sandbox-example")
        command = metadata["reproduction_command"]

        self.assertEqual(command[5], "$NEW_ARTIFACTS_DIR")
        self.assertEqual(command[7], "$NEW_ARTIFACTS_DIR/runner-receipt.json")
        self.assertEqual(
            metadata["reproduction_environment"],
            {
                "FLOCI_REPO": {"required": True, "source_commit": "a" * 40},
                "NEW_ARTIFACTS_DIR": {"required": True, "must_not_exist": True},
            },
        )

if __name__ == "__main__":
    unittest.main()
