from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from blackbox_autoresearch.ci_live_evidence import EvidenceContext, EvidenceVerificationError
from blackbox_autoresearch.git_workspace_evidence import (
    produce_git_workspace_evidence,
    verify_git_workspace_evidence,
)


ROOT = Path(__file__).resolve().parents[1]
PLATFORM_DIGEST = "3" * 64


class GitWorkspaceEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.harness = self.root / "producer.py"
        self.evaluator = self.root / "verifier.py"
        self.policy = self.root / "workflow.yml"
        self.harness.write_text("producer\n")
        self.evaluator.write_text("verifier\n")
        self.policy.write_text("workflow\n")
        self.context = EvidenceContext(
            repository="ed3c/blackbox-auto-research", run_id="123", run_attempt="1",
            source_commit="1" * 40, workflow_commit="2" * 40,
            runner_os="Linux", runner_arch="X64", runner_image_os="ubuntu24",
            runner_image_version="20260720.1",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def produce(self) -> Path:
        bundle = self.root / "evidence"
        produce_git_workspace_evidence(
            bundle, self.root / "disposable-workspace", context=self.context,
            harness_path=self.harness, evaluator_path=self.evaluator, policy_path=self.policy,
        )
        return bundle

    def verify(self, bundle: Path) -> dict[str, object]:
        return verify_git_workspace_evidence(
            bundle, expected_context=self.context, harness_path=self.harness,
            evaluator_path=self.evaluator, policy_path=self.policy,
            reported_platform_artifact_digest=PLATFORM_DIGEST, run_tamper_probe=True,
        )

    def test_replays_git_bundle_and_rejects_planted_tamper(self) -> None:
        bundle = self.produce()
        receipt = self.verify(bundle)
        outcome = json.loads((bundle / "outcome.json").read_text())

        self.assertNotEqual(outcome["seeded_test_returncode"], 0)
        self.assertEqual(outcome["repaired_test_returncode"], 0)
        self.assertEqual(outcome["teardown"], "workspace-absent")
        self.assertFalse((self.root / "disposable-workspace").exists())
        self.assertTrue(receipt["verified"])
        self.assertEqual(receipt["tamper_probe"], "rejected")
        self.assertEqual(receipt["maturity_decision"], "unassessed")

    def test_repository_bundle_tamper_fails_closed(self) -> None:
        bundle = self.produce()
        with (bundle / "repository.bundle").open("ab") as handle:
            handle.write(b"forged")

        with self.assertRaisesRegex(EvidenceVerificationError, "repository_bundle_digest mismatch"):
            self.verify(bundle)

    def test_context_drift_fails_closed(self) -> None:
        bundle = self.produce()
        drifted = EvidenceContext(**{**self.context.__dict__, "run_id": "999"})

        with self.assertRaisesRegex(EvidenceVerificationError, "run_id drift"):
            verify_git_workspace_evidence(
                bundle, expected_context=drifted, harness_path=self.harness,
                evaluator_path=self.evaluator, policy_path=self.policy,
                reported_platform_artifact_digest=PLATFORM_DIGEST,
            )

    def test_refuses_preexisting_workspace(self) -> None:
        workspace = self.root / "already-present"
        workspace.mkdir()
        with self.assertRaisesRegex(ValueError, "workspace already exists"):
            produce_git_workspace_evidence(
                self.root / "evidence", workspace, context=self.context,
                harness_path=self.harness, evaluator_path=self.evaluator, policy_path=self.policy,
            )

    def test_cli_round_trip_writes_fresh_verification_receipt(self) -> None:
        bundle = self.root / "cli-evidence"
        workspace = self.root / "cli-workspace"
        receipt = self.root / "cli-receipt.json"
        context_args = [
            "--repository", self.context.repository,
            "--run-id", self.context.run_id,
            "--run-attempt", self.context.run_attempt,
            "--source-commit", self.context.source_commit,
            "--workflow-commit", self.context.workflow_commit,
            "--runner-os", self.context.runner_os,
            "--runner-arch", self.context.runner_arch,
            "--runner-image-os", self.context.runner_image_os,
            "--runner-image-version", self.context.runner_image_version,
        ]
        subprocess.run(
            [sys.executable, "scripts/produce_live_git_workspace_evidence.py",
             "--output", str(bundle), "--workspace", str(workspace), *context_args],
            cwd=ROOT, check=True, capture_output=True, text=True,
        )
        subprocess.run(
            [sys.executable, "scripts/verify_live_git_workspace_evidence.py",
             "--input", str(bundle), "--receipt", str(receipt),
             "--reported-platform-artifact-digest", PLATFORM_DIGEST, "--tamper-probe", *context_args],
            cwd=ROOT, check=True, capture_output=True, text=True,
        )

        self.assertTrue(json.loads(receipt.read_text())["verified"])
        self.assertFalse(workspace.exists())

    def test_workflow_uses_separate_jobs_and_runner_temp_workspace(self) -> None:
        workflow = (ROOT / ".github/workflows/live-git-workspace-evidence.yml").read_text()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("verify:\n    needs: produce", workflow)
        self.assertIn('--workspace "$RUNNER_TEMP/blackbox-disposable-repository"', workflow)
        self.assertIn("--tamper-probe", workflow)
        self.assertEqual(workflow.count("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"), 2)
        self.assertEqual(workflow.count("actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"), 1)


if __name__ == "__main__":
    unittest.main()
