from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from blackbox_autoresearch.ci_live_evidence import (
    EvidenceContext,
    EvidenceVerificationError,
    produce_evidence_bundle,
    verify_evidence_bundle,
)


SOURCE_COMMIT = "1" * 40
WORKFLOW_COMMIT = "2" * 40
REPORTED_PLATFORM_DIGEST = "3" * 64
ROOT = Path(__file__).resolve().parents[1]


class CILiveEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.harness = self.root / "producer.py"
        self.evaluator = self.root / "verifier.py"
        self.policy = self.root / "workflow.yml"
        self.harness.write_text("producer\n")
        self.evaluator.write_text("verifier\n")
        self.policy.write_text("workflow\n")
        self.context = EvidenceContext(
            repository="ed3c/blackbox-auto-research",
            run_id="12345",
            run_attempt="1",
            source_commit=SOURCE_COMMIT,
            workflow_commit=WORKFLOW_COMMIT,
            runner_os="Linux",
            runner_arch="X64",
            runner_image_os="ubuntu24",
            runner_image_version="20260801.1",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def produce(self) -> Path:
        bundle = self.root / "bundle"
        produce_evidence_bundle(
            bundle,
            context=self.context,
            harness_path=self.harness,
            evaluator_path=self.evaluator,
            policy_path=self.policy,
        )
        return bundle

    def verify(self, bundle: Path) -> dict[str, object]:
        return verify_evidence_bundle(
            bundle,
            expected_context=self.context,
            harness_path=self.harness,
            evaluator_path=self.evaluator,
            policy_path=self.policy,
            reported_platform_artifact_digest=REPORTED_PLATFORM_DIGEST,
            run_tamper_probe=True,
        )

    def test_fresh_verifier_replays_content_addressed_bundle(self) -> None:
        bundle = self.produce()

        receipt = self.verify(bundle)

        manifest = json.loads((bundle / "manifest.json").read_text())
        self.assertEqual("blackbox-ci-evidence/v1", manifest["schema"])
        self.assertEqual("L3 LIVE", manifest["target_maturity"])
        self.assertEqual("candidate-evidence", manifest["status"])
        self.assertEqual(6, len(manifest["identities"]))
        self.assertEqual(manifest["evidence"]["candidate_digest"], manifest["identities"]["candidate"])
        self.assertEqual("blackbox-ci-verification/v1", receipt["schema"])
        self.assertTrue(receipt["verified"])
        self.assertEqual("unassessed", receipt["maturity_decision"])
        self.assertEqual("bundle-integrity-and-context-match", receipt["verification_scope"])
        self.assertEqual("sha256:" + REPORTED_PLATFORM_DIGEST, receipt["reported_platform_artifact_digest"])
        self.assertFalse(receipt["platform_artifact_digest_verified"])
        self.assertEqual("rejected", receipt["tamper_probe"])

    def test_outcome_tamper_fails_closed(self) -> None:
        bundle = self.produce()
        outcome = json.loads((bundle / "outcome.json").read_text())
        outcome["metadata"]["repaired_source"] = "forged"
        (bundle / "outcome.json").write_text(json.dumps(outcome, sort_keys=True))

        with self.assertRaisesRegex(EvidenceVerificationError, "outcome digest mismatch"):
            self.verify(bundle)

    def test_candidate_tamper_fails_closed(self) -> None:
        bundle = self.produce()
        (bundle / "candidate.py").write_text("forged\n")

        with self.assertRaisesRegex(EvidenceVerificationError, "candidate digest mismatch"):
            self.verify(bundle)

    def test_run_identity_drift_fails_closed(self) -> None:
        bundle = self.produce()
        drifted = EvidenceContext(**{**self.context.__dict__, "source_commit": "f" * 40})

        with self.assertRaisesRegex(EvidenceVerificationError, "source_commit drift"):
            verify_evidence_bundle(
                bundle,
                expected_context=drifted,
                harness_path=self.harness,
                evaluator_path=self.evaluator,
                policy_path=self.policy,
                reported_platform_artifact_digest=REPORTED_PLATFORM_DIGEST,
            )

    def test_malformed_reported_platform_digest_fails_closed(self) -> None:
        bundle = self.produce()

        with self.assertRaisesRegex(EvidenceVerificationError, "reported platform artifact digest"):
            verify_evidence_bundle(
                bundle,
                expected_context=self.context,
                harness_path=self.harness,
                evaluator_path=self.evaluator,
                policy_path=self.policy,
                reported_platform_artifact_digest="not-a-digest",
            )

    def test_evaluator_identity_tamper_fails_closed(self) -> None:
        bundle = self.produce()
        manifest_path = bundle / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["identities"]["evaluator"] = "sha256:" + "0" * 64
        manifest_path.write_text(json.dumps(manifest, sort_keys=True))

        with self.assertRaisesRegex(EvidenceVerificationError, "evaluator identity drift"):
            self.verify(bundle)

    def test_producer_and_evaluator_must_be_distinct(self) -> None:
        with self.assertRaisesRegex(ValueError, "harness and evaluator identities must differ"):
            produce_evidence_bundle(
                self.root / "bundle",
                context=self.context,
                harness_path=self.harness,
                evaluator_path=self.harness,
                policy_path=self.policy,
            )

    def test_cli_round_trip_writes_verification_receipt(self) -> None:
        bundle = self.root / "cli-bundle"
        receipt = self.root / "receipt.json"
        context_args = [
            "--repository",
            self.context.repository,
            "--run-id",
            self.context.run_id,
            "--run-attempt",
            self.context.run_attempt,
            "--source-commit",
            self.context.source_commit,
            "--workflow-commit",
            self.context.workflow_commit,
            "--runner-os",
            self.context.runner_os,
            "--runner-arch",
            self.context.runner_arch,
            "--runner-image-os",
            self.context.runner_image_os,
            "--runner-image-version",
            self.context.runner_image_version,
        ]

        subprocess.run(
            [sys.executable, "scripts/produce_live_ci_evidence.py", "--output", str(bundle), *context_args],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                sys.executable,
                "scripts/verify_live_ci_evidence.py",
                "--input",
                str(bundle),
                "--receipt",
                str(receipt),
                "--reported-platform-artifact-digest",
                REPORTED_PLATFORM_DIGEST,
                "--tamper-probe",
                *context_args,
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )

        self.assertTrue(json.loads(receipt.read_text())["verified"])

    def test_workflow_pins_actions_and_separates_verifier_job(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "live-ci-evidence.yml").read_text()

        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("verify:\n    needs: produce", workflow)
        self.assertIn("actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02", workflow)
        self.assertIn("actions/download-artifact@634f93cb2916e3fdff6788551b99b062d0335ce0", workflow)
        self.assertIn("--tamper-probe", workflow)


if __name__ == "__main__":
    unittest.main()
