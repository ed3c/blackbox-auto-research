from __future__ import annotations

from dataclasses import replace
import hashlib
import unittest

from blackbox_autoresearch.contracts import CandidateRef, DecisionKind, EvidenceMode, Evaluation, RunManifest, TaskSpec
from blackbox_autoresearch.decision import decide_paired_trials
from blackbox_autoresearch.evidence import EvidenceChain
from blackbox_autoresearch.runtime import DeterministicCounterEnvironment, qualify_verifier


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


class TargetVerifier:
    def __init__(self, target: int) -> None:
        self.target = target

    def evaluate(self, initial_state, final_state, trajectory, hidden_case=None) -> bool:
        expected = self.target if hidden_case is None else hidden_case
        return final_state.get("value") == expected


class RuntimeV2Tests(unittest.TestCase):
    def test_manifest_pins_all_execution_digests(self) -> None:
        task = TaskSpec("task-1", digest("task"), "Reach the externally visible goal", EvidenceMode.BLACK)
        candidate = CandidateRef("candidate-1", digest("candidate"))
        manifest = RunManifest(
            "run-1",
            task,
            candidate,
            digest("environment"),
            digest("harness"),
            digest("evaluator"),
            digest("policy"),
            seed=7,
        )
        encoded = manifest.canonical_json()
        self.assertIn(digest("evaluator"), encoded)
        self.assertIn('"evidence_mode":"BLACK"', encoded)

    def test_invalid_digest_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            TaskSpec("task-1", "latest", "objective")

    def test_evaluation_rejects_self_report_without_evidence(self) -> None:
        with self.assertRaises(ValueError):
            Evaluation(digest("evaluator"), 1.0, True, ())

    def test_environment_reset_prevents_cross_trial_state_leakage(self) -> None:
        env = DeterministicCounterEnvironment()
        self.assertEqual({"value": 1}, env.reset(seed=1))
        env.act("inc")
        env.act("inc")
        self.assertEqual({"value": 3}, env.observe())
        self.assertEqual({"value": 1}, env.reset(seed=1))

    def test_verifier_must_reject_initial_and_planted_bad_states(self) -> None:
        result = qualify_verifier(
            TargetVerifier(2),
            initial_state={"value": 0},
            golden_state={"value": 2},
            planted_bad_state={"value": 1},
        )
        self.assertTrue(result.qualified)
        weak = qualify_verifier(
            TargetVerifier(0),
            initial_state={"value": 0},
            golden_state={"value": 0},
            planted_bad_state={"value": 1},
        )
        self.assertFalse(weak.qualified)

    def test_evidence_chain_detects_tampering(self) -> None:
        chain = EvidenceChain()
        chain.append({"kind": "observation", "value": 1})
        second = chain.append({"kind": "final-state", "value": 2})
        self.assertTrue(chain.verify())
        chain._events[1] = replace(second, payload={"kind": "final-state", "value": 999})
        self.assertFalse(chain.verify())

    def test_statistical_decisions_cover_all_four_states(self) -> None:
        keep = decide_paired_trials([1, 1, 1, 1], [2, 2, 2, 2])
        self.assertEqual(DecisionKind.KEEP, keep.kind)
        discard = decide_paired_trials([2, 2, 2, 2], [1, 1, 1, 1])
        self.assertEqual(DecisionKind.DISCARD, discard.kind)
        inconclusive = decide_paired_trials([1, 1, 1, 1], [0, 2, 0, 2])
        self.assertEqual(DecisionKind.INCONCLUSIVE, inconclusive.kind)
        quarantined = decide_paired_trials([1, 1], [100, 100], hard_guardrails_passed=False)
        self.assertEqual(DecisionKind.QUARANTINE, quarantined.kind)


if __name__ == "__main__":
    unittest.main()
