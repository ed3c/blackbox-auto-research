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
DERIVED_IMAGE = "sha256:" + "b" * 64


class FakeOpenShell:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.evaluator_bytes = b""
        self.image_exists = False
        self.tags: set[str] = set()
        self.sandboxes: set[str] = set()

    def __call__(self, argv: tuple[str, ...]) -> CommandResult:
        code = 0
        stdout = ""
        stderr = ""
        if argv == ("openshell", "--version"):
            stdout = "openshell 0.0.59\n"
        elif argv[:2] == ("docker", "build"):
            self.image_exists = True
            source = Path(argv[-1]) / "evaluator-source.txt"
            self.evaluator_bytes = source.read_bytes()
            stdout = DERIVED_IMAGE + "\n"
        elif argv[:3] == ("docker", "image", "tag"):
            self.tags.add(argv[-1])
        elif argv[:3] == ("docker", "image", "rm"):
            if argv[-1] == DERIVED_IMAGE:
                self.image_exists = False
            else:
                self.tags.discard(argv[-1])
        elif argv[:3] == ("docker", "image", "inspect"):
            target = argv[-1]
            if target in self.tags and "--format" in argv:
                stdout = IMAGE + "\n"
            elif target == DERIVED_IMAGE and self.image_exists:
                stdout = DERIVED_IMAGE + "\n"
            else:
                code, stderr = 1, "image not found"
        elif argv[1:3] == ("sandbox", "create"):
            self.sandboxes.add(argv[argv.index("--name") + 1])
        elif argv[1:3] == ("sandbox", "get") and argv[-1] in self.sandboxes:
            sandbox_id = (
                "66666666-7777-8888-9999-aaaaaaaaaaaa"
                if argv[-1].endswith("-verifier")
                else "11111111-2222-3333-4444-555555555555"
            )
            stdout = f"Id: {sandbox_id}\nPhase: Ready\n"
        elif argv[1:3] == ("policy", "get"):
            stdout = json.dumps({
                "hash": "1" * 64,
                "status": "effective",
                "policy": {
                    "filesystem_policy": {
                        "read_only": ["/etc"],
                        "read_write": ["/sandbox", "/tmp"],
                    },
                    "network_policies": {
                        "allow": {
                            "binaries": [{"path": "/usr/bin/curl"}],
                            "endpoints": [{"host": "allowed.example", "port": 443}],
                        }
                    },
                },
            })
        elif argv[1:3] == ("sandbox", "exec"):
            sandbox_name = argv[argv.index("--name") + 1]
            if sandbox_name.endswith("-verifier") and self.evaluator_bytes and argv[-2:] == (
                "/usr/bin/cat", "/evaluator/canary.txt"
            ):
                stdout = self.evaluator_bytes.decode()
            elif "/sandbox/candidate.sh" in argv:
                stdout = "openshell-live-evidence-v1\n"
            elif "/etc/blackbox-evidence-probe" in argv:
                code, stderr = 1, "permission denied"
            elif "https://denied.example" in argv:
                code, stderr = 22, "proxy denied"
            elif "/bin/sleep" in argv:
                code, stderr = 124, "timeout"
            elif any("/evaluator/canary.txt" in value for value in argv):
                code, stderr = 1, "permission denied"
        elif argv[1:3] == ("sandbox", "download"):
            Path(argv[-1]).write_text("openshell-live-evidence-v1\n")
        elif argv[1:3] == ("sandbox", "delete"):
            self.sandboxes.discard(argv[-1])
        elif argv[1:3] == ("sandbox", "get") and argv[-1] not in self.sandboxes:
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
        self.assertEqual(outcome["unproven_probes"], ["credential-broker"])
        self.assertEqual(manifest["run_manifest"]["max_actions"], 30)
        self.assertEqual(
            manifest["runtime"]["candidate_sandbox_id"],
            "11111111-2222-3333-4444-555555555555",
        )
        self.assertEqual(
            manifest["runtime"]["verifier_sandbox_id"],
            "66666666-7777-8888-9999-aaaaaaaaaaaa",
        )
        self.assertEqual(
            (bundle / "evaluator-source.txt").read_bytes(),
            (bundle / "evaluator-after.txt").read_bytes(),
        )

    def test_uses_pinned_image_and_disables_automatic_providers(self) -> None:
        bundle = self.produce()
        events = json.loads((bundle / "trajectory.json").read_text())["events"]
        create = next(event for event in events if event["name"] == "candidate-create")

        self.assertIn(DERIVED_IMAGE, create["argv"])
        self.assertIn("--no-auto-providers", create["argv"])
        self.assertNotIn("--auto-providers", create["argv"])
        dockerfile = (bundle / "Dockerfile.evaluator").read_text()
        self.assertIn("FROM blackbox-openshell-base:", dockerfile)
        self.assertNotIn(f"FROM {IMAGE}", dockerfile)
        self.assertIn("chmod 0777 /evaluator", dockerfile)
        self.assertIn("chmod 0666 /evaluator/canary.txt", dockerfile)

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

    def test_evaluator_artifact_tamper_fails_closed(self) -> None:
        bundle = self.produce()
        (bundle / "evaluator-after.txt").write_text("forged\n")

        with self.assertRaisesRegex(EvidenceVerificationError, "evaluator_after evidence digest mismatch"):
            self.verify(bundle)

    def test_dockerfile_rebinding_fails_closed(self) -> None:
        bundle = self.produce()
        dockerfile = bundle / "Dockerfile.evaluator"
        dockerfile.write_text(dockerfile.read_text().replace("0666", "0444"))
        manifest_path = bundle / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["evidence"]["evaluator_dockerfile"]["digest"] = (
            "sha256:" + hashlib.sha256(dockerfile.read_bytes()).hexdigest()
        )
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")

        with self.assertRaisesRegex(EvidenceVerificationError, "evaluator Dockerfile drift"):
            self.verify(bundle)

    def test_candidate_output_cannot_expose_canary_even_if_trajectory_is_rebound(self) -> None:
        bundle = self.produce()
        canary = (bundle / "evaluator-source.txt").read_text().strip()
        trajectory_path = bundle / "trajectory.json"
        trajectory = json.loads(trajectory_path.read_text())
        read_event = next(
            event for event in trajectory["events"] if event["name"] == "evaluator-read-deny"
        )
        read_event["stdout"] = canary
        trajectory_path.write_text(
            json.dumps(trajectory, sort_keys=True, separators=(",", ":")) + "\n"
        )
        manifest_path = bundle / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["evidence"]["trajectory"]["digest"] = (
            "sha256:" + hashlib.sha256(trajectory_path.read_bytes()).hexdigest()
        )
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")

        with self.assertRaisesRegex(EvidenceVerificationError, "exposed evaluator canary"):
            self.verify(bundle)

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
        self.assertFalse(fake.sandboxes)


if __name__ == "__main__":
    unittest.main()
