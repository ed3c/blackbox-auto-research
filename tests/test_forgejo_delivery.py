import hashlib
import json
import subprocess
import tempfile
import unittest
from datetime import datetime
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
GATE = REPO_ROOT / "scripts" / "gates" / "check_delivery_receipt.py"


class ForgejoDeliveryGateTests(unittest.TestCase):
    @staticmethod
    def digest(value: dict) -> str:
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        return "sha256:" + hashlib.sha256(canonical).hexdigest()

    def run_gate(
        self, registry: dict, receipt: dict | None
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            subprocess.run(["git", "init", "-q", "-b", "main", root], check=True)
            binding = root / ".skill-bindings" / "forgejo-delivery-loop"
            binding.mkdir(parents=True)
            (binding / "registry.json").write_text(
                json.dumps(registry), encoding="utf-8"
            )
            if receipt is not None:
                (root / "delivery.json").write_text(json.dumps(receipt), encoding="utf-8")
            return subprocess.run(
                ["python3", str(GATE), "--root", str(root)],
                text=True,
                capture_output=True,
            )

    def test_materialized_line_requires_a_complete_receipt(self) -> None:
        registry = {
            "required_receipt_fields": [
                "line",
                "repo",
                "issues",
                "pr",
                "milestone_url",
                "synced_at_commit",
            ],
            "lines": [{"line": "evidence-lake", "materialized_path": "."}],
        }
        result = self.run_gate(registry, None)
        self.assertEqual(result.returncode, 2)
        self.assertIn("receipt-missing", result.stderr)

    def test_complete_local_forgejo_receipt_passes(self) -> None:
        registry = {
            "required_receipt_fields": [
                "line",
                "repo",
                "issues",
                "pr",
                "milestone_url",
                "synced_at_commit",
            ],
            "lines": [{"line": "evidence-lake", "materialized_path": "."}],
        }
        receipt = {
            "line": "evidence-lake",
            "repo": "neon/blackbox-auto-research",
            "issues": ["http://localhost:3000/neon/blackbox-auto-research/issues/8"],
            "pr": "not-applicable-tracking-only",
            "milestone_url": "http://localhost:3000/neon/blackbox-auto-research/milestone/3",
            "synced_at_commit": "fe86e1a",
        }
        result = self.run_gate(registry, receipt)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS", result.stdout)

    def test_registry_rejects_cross_forge_urls(self) -> None:
        registry = {
            "required_receipt_fields": ["line"],
            "lines": [
                {
                    "line": "evidence-lake",
                    "materialized_path": ".",
                    "issue_urls": ["https://github.com/ed3c/blackbox-auto-research/issues/25"],
                }
            ],
        }
        result = self.run_gate(registry, {"line": "evidence-lake"})
        self.assertEqual(result.returncode, 2)
        self.assertIn("cross-forge", result.stderr)

    def test_registry_rejects_every_non_local_forge_url(self) -> None:
        registry = {
            "required_receipt_fields": ["line"],
            "lines": [
                {
                    "line": "evidence-lake",
                    "materialized_path": ".",
                    "issue_urls": ["https://gitlab.com/example/project/-/issues/25"],
                }
            ],
        }
        result = self.run_gate(registry, {"line": "evidence-lake"})
        self.assertEqual(result.returncode, 2)
        self.assertIn("cross-forge", result.stderr)

    def test_receipt_missing_a_required_field_fails(self) -> None:
        registry = {
            "required_receipt_fields": ["line", "synced_at_commit"],
            "lines": [{"line": "evidence-lake", "materialized_path": "."}],
        }
        result = self.run_gate(registry, {"line": "evidence-lake"})
        self.assertEqual(result.returncode, 2)
        self.assertIn("receipt-field-missing", result.stderr)

    def test_receipt_rejects_cross_forge_urls(self) -> None:
        registry = {
            "required_receipt_fields": ["line", "issues"],
            "lines": [{"line": "evidence-lake", "materialized_path": "."}],
        }
        receipt = {
            "line": "evidence-lake",
            "issues": ["https://github.com/example/project/issues/25"],
        }
        result = self.run_gate(registry, receipt)
        self.assertEqual(result.returncode, 2)
        self.assertIn("cross-forge-receipt", result.stderr)

    def test_missing_materialized_path_fails_loudly(self) -> None:
        registry = {
            "required_receipt_fields": ["line"],
            "lines": [{"line": "evidence-lake", "materialized_path": "missing"}],
        }
        result = self.run_gate(registry, None)
        self.assertEqual(result.returncode, 2)
        self.assertIn("materialized-path-missing", result.stderr)

    def test_materialized_path_cannot_escape_the_repository(self) -> None:
        registry = {
            "required_receipt_fields": ["line"],
            "lines": [{"line": "evidence-lake", "materialized_path": "../outside"}],
        }
        result = self.run_gate(registry, None)
        self.assertEqual(result.returncode, 2)
        self.assertIn("materialized-path-escape", result.stderr)

    def test_repository_receipt_tracks_the_verified_projection(self) -> None:
        registry = json.loads(
            (REPO_ROOT / ".skill-bindings/forgejo-delivery-loop/registry.json").read_text(
                encoding="utf-8"
            )
        )
        receipt = json.loads(
            (REPO_ROOT / "delivery.json").read_text(encoding="utf-8")
        )
        projected_issues = [
            "http://localhost:3000/neon/blackbox-auto-research/issues/8",
            "http://localhost:3000/neon/blackbox-auto-research/issues/17",
            "http://localhost:3000/neon/blackbox-auto-research/issues/18",
        ]
        registry_line = next(
            line for line in registry["lines"] if line["line"] == receipt["line"]
        )

        self.assertEqual(registry_line["issue_urls"], projected_issues)
        self.assertEqual(receipt["issues"], projected_issues)
        self.assertEqual(
            receipt["synced_at_commit"],
            "710a944f6a9ae72d3cb88ea54af672d5053f23ff",
        )
        commit_object = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "cat-file", "-p", "HEAD"],
            text=True,
            capture_output=True,
        )
        self.assertEqual(commit_object.returncode, 0, commit_object.stderr)
        parent_shas = {
            line.removeprefix("parent ")
            for line in commit_object.stdout.splitlines()
            if line.startswith("parent ")
        }
        self.assertIn(receipt["synced_at_commit"], parent_shas)

    def test_closed_projection_issues_have_typed_live_receipts(self) -> None:
        receipt_dir = (
            REPO_ROOT / ".skill-bindings" / "forgejo-delivery-loop" / "receipts"
        )
        expected = {
            17: "fe86e1a8bc96ca9c70e13038c1cd9801fae958aa",
            18: "ca73dfc0301fd103bbb4ef8ee2ced1f06cdf61f1",
        }
        for issue_number, merge_sha in expected.items():
            request = json.loads(
                (receipt_dir / f"issue-{issue_number}-request.json").read_text(
                    encoding="utf-8"
                )
            )
            receipt = json.loads(
                (receipt_dir / f"issue-{issue_number}-receipt.json").read_text(
                    encoding="utf-8"
                )
            )
            source = json.loads(
                (receipt_dir / f"issue-{issue_number}-source-observation.json").read_text(
                    encoding="utf-8"
                )
            )
            pre = json.loads(
                (receipt_dir / f"issue-{issue_number}-pre-observation.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(request["issue_number"], issue_number)
            self.assertEqual(request["expected_state"], "open")
            self.assertEqual(request["desired_state"], "closed")
            self.assertEqual(receipt["schema_version"], "forgejo-issue-state-readback-receipt@v1")
            self.assertEqual(receipt["status"], "verified")
            self.assertEqual(receipt["state"], "closed")
            self.assertEqual(receipt["issue_number"], issue_number)
            self.assertEqual(receipt["source_merge_sha"], merge_sha)
            self.assertEqual(
                receipt["maturity_effect"], "tracking-only-no-maturity-change"
            )
            self.assertEqual(receipt["request_sha256"], self.digest(request))
            self.assertEqual(source["request_sha256"], receipt["request_sha256"])
            self.assertEqual(pre["request_sha256"], receipt["request_sha256"])
            self.assertEqual(pre["repository"], receipt["repository"])
            self.assertEqual(pre["issue_number"], receipt["issue_number"])
            self.assertEqual(pre["idempotency_marker"], receipt["idempotency_marker"])
            self.assertEqual(
                request["source_receipt"]["issue_url"], receipt["idempotency_marker"]
            )
            self.assertEqual(
                source["issue_url"], request["source_receipt"]["issue_url"]
            )
            self.assertEqual(
                source["pull_request_url"],
                request["source_receipt"]["pull_request_url"],
            )
            self.assertEqual(source["merge_sha"], receipt["source_merge_sha"])
            self.assertEqual(receipt["pre_observation_sha256"], self.digest(pre))
            source_identity = {
                field: value
                for field, value in source.items()
                if field
                not in {
                    "status", "request_sha256", "source_observation_sha256", "observed_at"
                }
            }
            self.assertEqual(
                receipt["source_observation_sha256"], self.digest(source_identity)
            )
            post_identity = {
                "status": "captured",
                "schema_version": "forgejo-issue-state-observation@v1",
                "request_sha256": receipt["request_sha256"],
                "phase": "post",
                "producer": receipt["producer"],
                "forge_url": request["forge_url"],
                "repository": receipt["repository"],
                "issue_number": receipt["issue_number"],
                "state": receipt["state"],
                "idempotency_marker": receipt["idempotency_marker"],
            }
            self.assertEqual(
                receipt["post_observation_sha256"], self.digest(post_identity)
            )
            pre_at = datetime.fromisoformat(pre["observed_at"])
            closed_at = datetime.fromisoformat(receipt["closure_created_at"])
            post_at = datetime.fromisoformat(receipt["observed_at"])
            transition_seconds = (closed_at - pre_at).total_seconds()
            self.assertGreaterEqual(transition_seconds, 0)
            self.assertLessEqual(transition_seconds, 300)
            self.assertLessEqual(closed_at, post_at)
            self.assertTrue(receipt["closure_actor"].strip())


if __name__ == "__main__":
    unittest.main()
