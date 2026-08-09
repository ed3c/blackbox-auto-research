from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from blackbox_autoresearch.contracts import CandidateRef, EvidenceMode, RunManifest, TaskSpec
from blackbox_autoresearch.qualification import HiddenCaseVault, qualify_with_hidden_cases
from blackbox_autoresearch.sandbox import BudgetExceeded, MemorySandboxProvider, ResourcePolicy, TrustedRuntime
from blackbox_autoresearch.search_strategies import SearchBudget, UCB1Bandit, isolated_rng
from blackbox_autoresearch.stochastic import run_paired_trials
from blackbox_autoresearch.store import FileEvidenceStore


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def manifest(*, max_actions: int = 10, seed: int = 1) -> RunManifest:
    return RunManifest(
        "run-1",
        TaskSpec("task", digest("task"), "reach target", EvidenceMode.BLACK),
        CandidateRef("candidate", digest("candidate")),
        digest("environment"),
        digest("harness"),
        digest("evaluator"),
        digest("policy"),
        seed=seed,
        max_actions=max_actions,
        max_seconds=60,
        max_tokens=100,
        max_cost_usd=1.0,
    )


class TargetVerifier:
    def evaluate(self, initial_state, final_state, trajectory, hidden_case=None) -> bool:
        return final_state == hidden_case


class CompletionCoreTests(unittest.TestCase):
    def test_trusted_runtime_is_manifest_driven_and_sessions_are_isolated(self) -> None:
        provider = MemorySandboxProvider()
        runtime = TrustedRuntime(provider)
        policy = ResourcePolicy(evaluator_read_only=True)
        first = runtime.run(manifest(seed=1), policy, ("inc", "inc"))
        second = runtime.run(manifest(seed=1), policy, ("inc",))
        self.assertEqual({"value": 3}, first.final_state)
        self.assertEqual({"value": 2}, second.final_state)
        self.assertIsNot(provider.sessions[0], provider.sessions[1])

    def test_runtime_enforces_budget_and_evaluator_is_read_only(self) -> None:
        runtime = TrustedRuntime(MemorySandboxProvider())
        with self.assertRaises(BudgetExceeded):
            runtime.run(manifest(max_actions=1), ResourcePolicy(), ("inc", "inc"))
        with self.assertRaises(PermissionError):
            runtime.run(manifest(), ResourcePolicy(), ("mutate-evaluator",))

    def test_resource_policy_is_explicit(self) -> None:
        policy = ResourcePolicy(
            readable_paths=("/input",),
            writable_paths=("/output",),
            network_allowlist=("api.example.com",),
            credential_names=("test-token",),
        )
        self.assertTrue(policy.permits_network("api.example.com"))
        self.assertFalse(policy.permits_network("evil.example"))
        self.assertTrue(policy.permits_credential("test-token"))

    def test_hidden_cases_are_judge_only_and_qualification_binds_digest(self) -> None:
        vault = HiddenCaseVault(({"value": 2},))
        self.assertEqual({"hidden_case_count": 1}, vault.candidate_view())
        self.assertFalse(hasattr(vault, "cases"))
        result = qualify_with_hidden_cases(
            TargetVerifier(),
            evaluator_digest=digest("evaluator"),
            initial_state={"value": 0},
            golden_state={"value": 2},
            planted_bad_state={"value": 1},
            vault=vault,
        )
        self.assertTrue(result.qualified)
        self.assertEqual(digest("evaluator"), result.evaluator_digest)

    def test_content_addressed_store_replays_queries_and_detects_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = FileEvidenceStore(tmp)
            artifact = store.put_bytes(b"trajectory")
            self.assertEqual(b"trajectory", store.get_bytes(artifact.digest))
            store.append_event("run-a", "decision", {"decision": "discard"})
            store.append_event("run-a", "evidence", {"digest": artifact.digest})
            self.assertTrue(store.verify_run("run-a"))
            self.assertEqual(1, len(store.query_decisions()))

            event_path = Path(tmp) / "events" / "run-a.jsonl"
            lines = event_path.read_text().splitlines()
            record = json.loads(lines[0])
            record["payload"]["decision"] = "keep"
            lines[0] = json.dumps(record, sort_keys=True, separators=(",", ":"))
            event_path.write_text("\n".join(lines) + "\n")
            self.assertFalse(store.verify_run("run-a"))

    def test_paired_seeds_and_four_way_decision_inputs(self) -> None:
        result = run_paired_trials(
            (1, 2, 3, 4),
            lambda seed: float(seed),
            lambda seed: float(seed + 2),
            minimum_effect=1.0,
        )
        self.assertEqual("keep", result.decision.kind.value)
        self.assertEqual((1, 2, 3, 4), tuple(item.seed for item in result.trials))
        quarantined = run_paired_trials(
            (1, 2), lambda seed: 1.0, lambda seed: 100.0, hard_guardrails_passed=False
        )
        self.assertEqual("quarantine", quarantined.decision.kind.value)

    def test_bandit_budget_and_worker_rng_are_isolated(self) -> None:
        bandit = UCB1Bandit()
        self.assertEqual("a", bandit.choose(("a", "b")))
        bandit.observe("a", 0.1)
        self.assertEqual("b", bandit.choose(("a", "b")))
        bandit.observe("b", 1.0)
        self.assertIn(bandit.choose(("a", "b")), {"a", "b"})

        budget = SearchBudget(max_trials=2, max_cost=1.0, per_candidate_max_trials=1)
        budget.charge("a", 0.2)
        with self.assertRaises(RuntimeError):
            budget.charge("a", 0.2)

        left = isolated_rng(7, "left")
        right = isolated_rng(7, "right")
        self.assertNotEqual(left.random(), right.random())


if __name__ == "__main__":
    unittest.main()
