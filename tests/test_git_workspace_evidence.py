from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
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
        manifest = json.loads((bundle / "manifest.json").read_text())
        return verify_git_workspace_evidence(
            bundle, expected_context=self.context, harness_path=self.harness,
            evaluator_path=self.evaluator, policy_path=self.policy,
            reported_platform_artifact_digest=PLATFORM_DIGEST, run_tamper_probe=True,
            expected_producer_git_version=manifest["environment"]["git_version"],
            expected_producer_python_version=manifest["environment"]["python_version"],
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
        self.assertIn("git_version", receipt["verifier_environment"])
        self.assertIn("python_version", receipt["verifier_environment"])

    def test_repository_bundle_tamper_fails_closed(self) -> None:
        bundle = self.produce()
        with (bundle / "repository.bundle").open("ab") as handle:
            handle.write(b"forged")

        with self.assertRaisesRegex(EvidenceVerificationError, "repository_bundle_digest mismatch"):
            self.verify(bundle)

    def test_candidate_bytes_cannot_claim_a_different_identity(self) -> None:
        bundle = self.produce()
        (bundle / "candidate.py").write_text("print('forged')\n")
        manifest_path = bundle / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["evidence"]["candidate_digest"] = (
            "sha256:" + hashlib.sha256((bundle / "candidate.py").read_bytes()).hexdigest()
        )
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")

        with self.assertRaisesRegex(EvidenceVerificationError, "candidate identity"):
            self.verify(bundle)

    def test_runtime_fingerprint_drift_fails_closed(self) -> None:
        bundle = self.produce()
        manifest_path = bundle / "manifest.json"
        outcome_path = bundle / "outcome.json"
        manifest = json.loads(manifest_path.read_text())
        outcome = json.loads(outcome_path.read_text())
        manifest["environment"]["git_version"] = "git version forged"
        outcome["git_version"] = "git version forged"
        outcome_path.write_text(json.dumps(outcome, sort_keys=True, separators=(",", ":")) + "\n")
        manifest["evidence"]["outcome_digest"] = (
            "sha256:" + hashlib.sha256(outcome_path.read_bytes()).hexdigest()
        )
        environment_bytes = json.dumps(
            manifest["environment"], sort_keys=True, separators=(",", ":")
        ).encode()
        manifest["identities"]["environment"] = (
            "sha256:" + hashlib.sha256(environment_bytes).hexdigest()
        )
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")

        with self.assertRaisesRegex(EvidenceVerificationError, "git_version producer output drift"):
            verify_git_workspace_evidence(
                bundle, expected_context=self.context, harness_path=self.harness,
                evaluator_path=self.evaluator, policy_path=self.policy,
                reported_platform_artifact_digest=PLATFORM_DIGEST,
                expected_producer_git_version="git version original",
                expected_producer_python_version=outcome["python_version"],
            )

    def test_repository_bundle_rejects_extra_ref(self) -> None:
        bundle = self.produce()
        with tempfile.TemporaryDirectory() as temporary:
            clone = Path(temporary) / "repository"
            subprocess.run(
                ["git", "clone", "--quiet", str(bundle / "repository.bundle"), str(clone)],
                check=True,
            )
            subprocess.run(["git", "branch", "unexpected", "HEAD^"], cwd=clone, check=True)
            (bundle / "repository.bundle").unlink()
            subprocess.run(
                ["git", "bundle", "create", str(bundle / "repository.bundle"), "--all"],
                cwd=clone, check=True,
            )
        manifest_path = bundle / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["evidence"]["repository_bundle_digest"] = (
            "sha256:" + hashlib.sha256((bundle / "repository.bundle").read_bytes()).hexdigest()
        )
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")

        with self.assertRaisesRegex(EvidenceVerificationError, "repository bundle refs drift"):
            self.verify(bundle)

    def test_untrusted_test_change_is_rejected_before_execution(self) -> None:
        bundle = self.produce()
        marker = self.root / "untrusted-test-executed"
        with tempfile.TemporaryDirectory() as temporary:
            clone = Path(temporary) / "repository"
            subprocess.run(
                ["git", "clone", "--quiet", str(bundle / "repository.bundle"), str(clone)],
                check=True,
            )
            (clone / "test_calculator.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n"
            )
            subprocess.run(["git", "add", "test_calculator.py"], cwd=clone, check=True)
            subprocess.run(
                ["git", "-c", "user.name=Forger", "-c", "user.email=forger@example.invalid",
                 "commit", "--amend", "--no-edit"],
                cwd=clone, check=True, capture_output=True, text=True,
            )
            final_head = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=clone, check=True,
                capture_output=True, text=True,
            ).stdout.strip()
            (bundle / "repository.bundle").unlink()
            subprocess.run(
                ["git", "bundle", "create", str(bundle / "repository.bundle"), "--all"],
                cwd=clone, check=True,
            )
        outcome_path = bundle / "outcome.json"
        outcome = json.loads(outcome_path.read_text())
        outcome["final_head"] = final_head
        outcome_path.write_text(json.dumps(outcome, sort_keys=True, separators=(",", ":")) + "\n")
        manifest_path = bundle / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["evidence"]["outcome_digest"] = "sha256:" + hashlib.sha256(outcome_path.read_bytes()).hexdigest()
        manifest["evidence"]["repository_bundle_digest"] = (
            "sha256:" + hashlib.sha256((bundle / "repository.bundle").read_bytes()).hexdigest()
        )
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")

        with self.assertRaises(EvidenceVerificationError):
            self.verify(bundle)
        self.assertFalse(marker.exists())

    def test_manifest_extra_key_fails_closed(self) -> None:
        bundle = self.produce()
        manifest_path = bundle / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["untrusted"] = True
        manifest_path.write_text(json.dumps(manifest, sort_keys=True))

        with self.assertRaisesRegex(EvidenceVerificationError, "manifest keys drift"):
            self.verify(bundle)

    def test_context_drift_fails_closed(self) -> None:
        bundle = self.produce()
        drifted = EvidenceContext(**{**self.context.__dict__, "run_id": "999"})

        with self.assertRaisesRegex(EvidenceVerificationError, "run_id drift"):
            verify_git_workspace_evidence(
                bundle, expected_context=drifted, harness_path=self.harness,
                evaluator_path=self.evaluator, policy_path=self.policy,
                reported_platform_artifact_digest=PLATFORM_DIGEST,
                expected_producer_git_version=json.loads((bundle / "manifest.json").read_text())["environment"]["git_version"],
                expected_producer_python_version=json.loads((bundle / "manifest.json").read_text())["environment"]["python_version"],
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
            [sys.executable, str(ROOT / "scripts/produce_live_git_workspace_evidence.py"),
             "--output", bundle.name, "--workspace", workspace.name, *context_args],
            cwd=self.root, check=True, capture_output=True, text=True,
        )
        produced_manifest = json.loads((bundle / "manifest.json").read_text())
        subprocess.run(
            [sys.executable, str(ROOT / "scripts/verify_live_git_workspace_evidence.py"),
             "--input", bundle.name, "--receipt", receipt.name,
             "--reported-platform-artifact-digest", PLATFORM_DIGEST, "--tamper-probe",
             "--expected-producer-git-version", produced_manifest["environment"]["git_version"],
             "--expected-producer-python-version", produced_manifest["environment"]["python_version"],
             *context_args],
            cwd=self.root, check=True, capture_output=True, text=True,
        )

        self.assertTrue(json.loads(receipt.read_text())["verified"])
        self.assertFalse(workspace.exists())

    def test_workflow_uses_separate_jobs_and_runner_temp_workspace(self) -> None:
        workflow = (ROOT / ".github/workflows/live-git-workspace-evidence.yml").read_text()
        artifact_actions = re.findall(
            r"(?m)^\s*uses:\s+(actions/(?:upload|download)-artifact@\S+)", workflow
        )
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("verify:\n    needs: produce", workflow)
        self.assertIn('--workspace "$RUNNER_TEMP/blackbox-disposable-repository"', workflow)
        self.assertIn("--tamper-probe", workflow)
        self.assertEqual(
            artifact_actions,
            [
                "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
                "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
                "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            ],
        )


if __name__ == "__main__":
    unittest.main()
