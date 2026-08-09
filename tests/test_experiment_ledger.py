from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "check_experiment_ledger", ROOT / "scripts/check_experiment_ledger.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ExperimentLedgerTests(unittest.TestCase):
    def _load(self, name: str):
        return json.loads((ROOT / "tests/fixtures" / name).read_text(encoding="utf-8"))

    def test_good_ledger_passes(self) -> None:
        self.assertEqual(MODULE.validate(self._load("ledger-good.json")), [])

    def test_hollow_ledger_fails(self) -> None:
        failures = MODULE.validate(self._load("ledger-hollow.json"))
        self.assertTrue(any("non-improvement" in item for item in failures), failures)
        self.assertTrue(any("budget exceeded" in item for item in failures), failures)
        self.assertTrue(any("must be non-empty" in item for item in failures), failures)


if __name__ == "__main__":
    unittest.main()
