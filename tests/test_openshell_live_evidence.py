from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from blackbox_autoresearch.ci_live_evidence import EvidenceVerificationError
from blackbox_autoresearch.openshell_live_evidence import (
    CommandResult,
    OpenShellRunConfig,
    produce_openshell_evidence,
    verify_openshell_evidence,
)


IMAGE = "sha256:" + "a" * 64


class FakeOpenShell:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.exists = False

    def __call__(self, argv: tuple[str, ...]) -> CommandResult:
        code = 0
        stdout = ""
        stderr = ""
        if argv == ("openshell", "--version"):
            stdout = "openshell 0.0.59\n"
        elif argv[1:3] == ("sandbox", "create"):
            self.exists = True
        elif argv[1:3] == ("sandbox", "get") and self.exists:
            stdout = "Id: 11111111-2222-3333-4444-555555555555\nPhase: Ready\n"
        elif argv[1:3] == ("policy", "get"):
            stdout = json.dumps({
                "hash": "1" * 64,
                "status": "effective",
                "policy": {
                    "filesystem_policy": {"read_only": ["/etc"], "read_write": ["/sandbox"]},
                    "network_policies": {
                        "allow": {
                            "binaries": [{"path": "/usr/bin/curl"}],
                            "endpoints": [{"host": "allowed.example", "port": 443}],
                        }
                    },
                },
            })
        elif argv[1:3] == ("sandbox", "exec"):
            if "/sandbox/candidate.sh" in argv:
                stdout = "openshell-live-evidence-v1\n"
            elif "/etc/blackbox-evidence-probe" in argv:
                code, stderr = 1, "permission denied"
            elif "https://denied.example" in argv:
                code, stderr = 22, "proxy denied"
            elif "/bin/sleep" in argv:
                code, stderr = 124, "timeout"
        elif argv[1:3] == ("sandbox", "download"):
            Path(argv[-1]).write_text("openshell-live-evidence-v1\n")
        elif argv[1:3] == ("sandbox", "delete"):
            self.exists = False
        elif argv[1:3] == ("sandbox", "get") and not self.exists:
            code, stderr = 1, "not found"
        return CommandResult(argv, code, stdout, stderr)


class OpenShellLiveEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.harness = self.root / "producer.py"
        self.evaluator = self.root / "verifier.py"
        self.harness.write_text("producer\n")
        self.evaluator.write_text("verifier\n")
        self.config = OpenShellRunConfig(
            run_id="live-1", sandbox_name="test-sandbox", image_digest=IMAGE,
            expected_version="0.0.59", allowed_url="https://allowed.example",
            denied_url="https://denied.example",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def produce(self) -> Path:
        bundle = self.root / "bundle"
        produce_openshell_evidence(
            bundle, config=self.config, harness_path=self.harness,
            evaluator_path=self.evaluator, runner=FakeOpenShell(self.root),
        )
        return bundle

    def verify(self, bundle: Path) -> dict[str, object]:
        return verify_openshell_evidence(
            bundle, expected_config=self.config, harness_path=self.harness,
            evaluator_path=self.evaluator,
        )

    def test_bundle_is_independently_verified_without_inflating_maturity(self) -> None:
        bundle = self.produce()
        receipt = self.verify(bundle)
        outcome = json.loads((bundle / "outcome.json").read_text())
        manifest = json.loads((bundle / "manifest.json").read_text())

        self.assertTrue(receipt["verified"])
        self.assertEqual(receipt["maturity_decision"], "unchanged")
        self.assertEqual(outcome["maturity_after"], "L1 REFERENCE")
        self.assertEqual(outcome["unproven_probes"], ["credential-broker", "evaluator-isolation"])
        self.assertEqual(manifest["run_manifest"]["max_actions"], 14)
        self.assertEqual(
            manifest["runtime"]["sandbox_id"], "11111111-2222-3333-4444-555555555555"
        )

    def test_uses_pinned_image_and_disables_automatic_providers(self) -> None:
        bundle = self.produce()
        events = json.loads((bundle / "trajectory.json").read_text())["events"]
        create = next(event for event in events if event["name"] == "create")

        self.assertIn(IMAGE, create["argv"])
        self.assertIn("--no-auto-providers", create["argv"])
        self.assertNotIn("--auto-providers", create["argv"])

    def test_trajectory_tamper_fails_closed(self) -> None:
        bundle = self.produce()
        trajectory = bundle / "trajectory.json"
        data = json.loads(trajectory.read_text())
        data["events"][0]["returncode"] = 7
        trajectory.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n")

        with self.assertRaisesRegex(EvidenceVerificationError, "trajectory evidence digest mismatch"):
            self.verify(bundle)

    def test_candidate_tamper_cannot_rebind_identity(self) -> None:
        bundle = self.produce()
        candidate = bundle / "candidate.sh"
        candidate.write_text("forged\n")
        manifest_path = bundle / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["evidence"]["candidate"]["digest"] = (
            "sha256:" + hashlib.sha256(candidate.read_bytes()).hexdigest()
        )
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")

        with self.assertRaisesRegex(EvidenceVerificationError, "run manifest drift"):
            self.verify(bundle)

    def test_expected_target_drift_fails_closed(self) -> None:
        bundle = self.produce()
        drifted = OpenShellRunConfig(
            **{**self.config.__dict__, "allowed_url": "https://other.example"}
        )

        with self.assertRaises(EvidenceVerificationError):
            verify_openshell_evidence(
                bundle, expected_config=drifted, harness_path=self.harness,
                evaluator_path=self.evaluator,
            )

    def test_version_drift_fails_before_sandbox_creation(self) -> None:
        fake = FakeOpenShell(self.root)

        def drifted(argv: tuple[str, ...]) -> CommandResult:
            if argv == ("openshell", "--version"):
                return CommandResult(argv, 0, "openshell 0.0.60\n", "")
            return fake(argv)

        with self.assertRaisesRegex(RuntimeError, "version drift"):
            produce_openshell_evidence(
                self.root / "bundle", config=self.config, harness_path=self.harness,
                evaluator_path=self.evaluator, runner=drifted,
            )
        self.assertFalse(fake.exists)


if __name__ == "__main__":
    unittest.main()
