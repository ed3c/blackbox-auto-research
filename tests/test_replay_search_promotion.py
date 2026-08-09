from __future__ import annotations

import hashlib
import unittest

from blackbox_autoresearch.contracts import CandidateRef, EvidenceMode, PromotionStage, RunManifest, TaskSpec, Trajectory
from blackbox_autoresearch.pareto import Objective, pareto_frontier
from blackbox_autoresearch.promotion import PromotionPolicy
from blackbox_autoresearch.replay import reverify
from blackbox_autoresearch.search import GreedySearchController, Hypothesis


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


class EqualsVerifier:
    def evaluate(self, initial_state, final_state, trajectory, hidden_case=None) -> bool:
        return final_state == hidden_case


class ReplaySearchPromotionTests(unittest.TestCase):
    def manifest(self) -> RunManifest:
        return RunManifest(
            "run-1",
            TaskSpec("task", digest("task"), "objective", EvidenceMode.BLACK),
            CandidateRef("candidate", digest("candidate")),
            digest("environment"),
            digest("harness"),
            digest("evaluator"),
            digest("policy"),
            seed=1,
        )

    def test_reverify_uses_stored_trajectory_and_detects_evaluator_drift(self) -> None:
        manifest = self.manifest()
        trajectory = Trajectory("run-1", digest("initial"), digest("final"))
        passed = reverify(
            manifest,
            trajectory,
            EqualsVerifier(),
            verifier_digest=digest("evaluator"),
            initial_state={"value": 0},
            final_state={"value": 2},
            hidden_case={"value": 2},
        )
        self.assertTrue(passed.passed)
        drift = reverify(
            manifest,
            trajectory,
            EqualsVerifier(),
            verifier_digest=digest("changed-evaluator"),
            initial_state={},
            final_state={},
        )
        self.assertTrue(drift.evaluator_drift)
        self.assertFalse(drift.passed)

    def test_invalid_evidence_mode_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            TaskSpec("task", digest("task"), "objective", "BLACK")

    def test_greedy_search_ranks_information_gain_over_cost_and_risk(self) -> None:
        controller = GreedySearchController()
        selected = controller.choose(
            [
                Hypothesis("a", "cheap weak probe", 1.0, 1.0, 1.0),
                Hypothesis("b", "strong probe", 4.0, 1.0, 1.0),
            ]
        )
        self.assertEqual("b", selected.hypothesis_id)

    def test_pareto_frontier_preserves_non_dominated_candidates(self) -> None:
        frontier = pareto_frontier(
            {
                "fast": {"success": 0.90, "latency": 100.0},
                "accurate": {"success": 0.95, "latency": 150.0},
                "bad": {"success": 0.80, "latency": 200.0},
            },
            (Objective("success", "maximize"), Objective("latency", "minimize")),
        )
        self.assertEqual(("accurate", "fast"), frontier)

    def test_irreversible_production_requires_human_actor(self) -> None:
        policy = PromotionPolicy()
        denied = policy.authorize(
            candidate_digest=digest("candidate"),
            stage=PromotionStage.PRODUCTION,
            evaluator_digest=digest("evaluator"),
            environment_digest=digest("environment"),
            all_guardrails_passed=True,
            irreversible=True,
        )
        self.assertFalse(denied.approved)
        approved = policy.authorize(
            candidate_digest=digest("candidate"),
            stage=PromotionStage.PRODUCTION,
            evaluator_digest=digest("evaluator"),
            environment_digest=digest("environment"),
            all_guardrails_passed=True,
            irreversible=True,
            approval_actor="human-reviewer",
        )
        self.assertTrue(approved.approved)


if __name__ == "__main__":
    unittest.main()
