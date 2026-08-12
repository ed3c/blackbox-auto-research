from __future__ import annotations

import unittest

from blackbox_autoresearch.live_workloads import (
    differential_check,
    evidence_envelope,
    metamorphic_check,
    run_api_state_machine_workload,
    run_ci_remediation_workload,
    run_mcp_routing_workload,
    run_sqlite_etl_workload,
    RepositoryCLIWorkload,
)


class LiveWorkloadTests(unittest.TestCase):
    def test_disposable_workloads_execute_real_stdlib_boundaries(self) -> None:
        items = (
            RepositoryCLIWorkload().run(),
            run_mcp_routing_workload(),
            run_api_state_machine_workload(),
            run_sqlite_etl_workload(),
            run_ci_remediation_workload(),
        )
        for item in items:
            with self.subTest(workload=item.workload):
                self.assertTrue(item.passed, item.metadata)
                self.assertTrue(item.outcome_digest.startswith("sha256:"))
        envelope = evidence_envelope(items)
        self.assertEqual("blackbox-domain-evidence/v1", envelope["schema"])
        self.assertEqual("L2_SANDBOX", envelope["maturity"])
        self.assertEqual(5, len(envelope["workloads"]))

    def test_differential_verifier_detects_seeded_regression(self) -> None:
        baseline = lambda value: value * 2
        seeded_regression = lambda value: value * 2 + (1 if value == 3 else 0)
        self.assertTrue(differential_check(baseline, seeded_regression, (1, 2, 3, 4)))
        self.assertFalse(differential_check(baseline, baseline, (1, 2, 3, 4)))

    def test_metamorphic_verifier_catches_invariant_violation(self) -> None:
        doubling = lambda value: value * 2
        broken = lambda value: value * 2 + (1 if value >= 3 else 0)
        self.assertTrue(metamorphic_check(doubling, (0, 1, 2, 3)))
        self.assertFalse(metamorphic_check(broken, (0, 1, 2, 3)))


if __name__ == "__main__":
    unittest.main()
