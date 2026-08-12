import json
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
GATE = REPO_ROOT / "scripts" / "gates" / "check_delivery_receipt.py"


class ForgejoDeliveryGateTests(unittest.TestCase):
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
            "ae3d988b0c36bd84ded73d21edffb9b85e5ef15e",
        )


if __name__ == "__main__":
    unittest.main()
