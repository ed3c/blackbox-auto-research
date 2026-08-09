from __future__ import annotations

import hashlib
import unittest

from blackbox_autoresearch.contracts import CandidateRef, EvidenceMode, PromotionStage, RunManifest, TaskSpec
from blackbox_autoresearch.domain_fixtures import (
    APITransition,
    CIRemediation,
    CommandOutcome,
    MCPCall,
    differential_verify,
    metamorphic_verify,
    verify_api_state_machine,
    verify_ci_remediation,
    verify_data_invariants,
    verify_mcp_route,
    verify_terminal,
)
from blackbox_autoresearch.mobile import (
    CAPABILITY_MATRIX,
    DeviceDescriptor,
    DeviceLeaseScheduler,
    MobilePlatform,
    capture_mobile_evidence,
    qualify_reset,
    requires_human_gate,
)
from blackbox_autoresearch.nemo_bridge import (
    BridgeCompatibility,
    SANDBOX_MAPPINGS,
    export_trajectory,
    import_rollout,
    manifest_to_gym_config,
    verify_bridge_provenance,
)
from blackbox_autoresearch.promotion import PromotionPipeline
from blackbox_autoresearch.provider_adapters import EnrootAdapter, OpenShellAdapter
from blackbox_autoresearch.sandbox import ResourcePolicy


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def manifest() -> RunManifest:
    return RunManifest(
        "run-provider",
        TaskSpec("task", digest("task"), "objective", EvidenceMode.BLACK),
        CandidateRef("skill-v2", digest("candidate")),
        digest("environment"),
        digest("harness"),
        digest("evaluator"),
        digest("policy"),
        seed=42,
    )


class ProviderDomainPromotionTests(unittest.TestCase):
    def test_nemo_bridge_is_version_isolated_and_preserves_provenance(self) -> None:
        compatibility = BridgeCompatibility()
        self.assertTrue(compatibility.accepts("0.4.0"))
        self.assertTrue(compatibility.accepts("v0.5.1"))
        self.assertFalse(compatibility.accepts("1.0.0"))

        run = manifest()
        config = manifest_to_gym_config(
            run,
            agent="codex",
            dataset="tasks.jsonl",
            verifier="state-verifier",
            sandbox="openshell",
            skills_path="skills/candidate",
        )
        self.assertEqual(run.candidate.digest, config["skills"]["candidate_digest"])
        self.assertTrue(verify_bridge_provenance(run, config))
        self.assertEqual("policy-isolated", SANDBOX_MAPPINGS["openshell"].trust_level)
        self.assertEqual("filesystem-separated", SANDBOX_MAPPINGS["enroot"].trust_level)

        trajectory = import_rollout(
            run.run_id,
            {
                "initial_state": {"ready": False},
                "final_state": {"ready": True},
                "trajectory": [{"action": "tool", "observation": "ok", "side_effects": ["changed-state"]}],
            },
        )
        exported = export_trajectory(trajectory)
        self.assertEqual(run.run_id, exported["run_id"])
        self.assertEqual("tool", exported["trajectory"][0]["action"])

    def test_provider_adapters_fail_explicitly_at_boundary_and_generate_policy(self) -> None:
        openshell = OpenShellAdapter()
        command = openshell.create_command(agent="codex", source="base")
        self.assertEqual(("openshell", "sandbox", "create", "--from", "base", "--", "codex"), command.argv)
        policy = openshell.policy_document(
            ResourcePolicy(
                readable_paths=("/workspace/input",),
                writable_paths=("/workspace/output",),
                network_allowlist=("api.github.com",),
                credential_names=("github",),
            )
        )
        self.assertEqual(["api.github.com"], policy["network"]["allow"])

        enroot = EnrootAdapter()
        self.assertEqual(("enroot", "start", "candidate", "python", "task.py"), enroot.start_command(container_name="candidate", command=("python", "task.py")).argv)
        self.assertIn("not be treated as a strong", enroot.security_warning)

    def test_mobile_capability_reset_scheduler_and_evidence(self) -> None:
        self.assertFalse(CAPABILITY_MATRIX[MobilePlatform.IOS_SIMULATOR].hardware_dependent)
        self.assertTrue(CAPABILITY_MATRIX[MobilePlatform.IOS_DEVICE].hardware_dependent)
        devices = (
            DeviceDescriptor("sim-1", MobilePlatform.IOS_SIMULATOR, "26.0", "iPhone"),
            DeviceDescriptor("android-1", MobilePlatform.ANDROID_EMULATOR, "17", "Pixel"),
        )
        scheduler = DeviceLeaseScheduler(devices)
        first = scheduler.acquire("run-a", platform=MobilePlatform.IOS_SIMULATOR)
        with self.assertRaises(RuntimeError):
            scheduler.acquire("run-b", platform=MobilePlatform.IOS_SIMULATOR)
        scheduler.release(first)
        second = scheduler.acquire("run-b", platform=MobilePlatform.IOS_SIMULATOR)
        self.assertEqual("run-b", second.owner)

        qualified = qualify_reset(
            MobilePlatform.IOS_DEVICE,
            app_data_cleared=True,
            keychain_or_keystore_checked=True,
            permissions_reset=True,
            process_restarted=True,
        )
        self.assertTrue(qualified.passed)
        self.assertTrue(qualified.caveats)
        evidence = capture_mobile_evidence("ui-tree", {"screen": "home"})
        self.assertTrue(evidence.digest.startswith("sha256:"))
        self.assertTrue(requires_human_gate("purchase", real_device=True))
        self.assertFalse(requires_human_gate("purchase", real_device=False))

    def test_terminal_mcp_api_data_ci_and_meta_verifiers(self) -> None:
        self.assertTrue(verify_terminal(CommandOutcome(0, "PASS"), stdout_contains="PASS"))
        self.assertTrue(verify_mcp_route(MCPCall("search", {"query": "x"}), expected_tool="search", required_arguments=("query",)))
        transitions = (APITransition("new", "POST", "/activate", 200, "active"),)
        self.assertTrue(verify_api_state_machine(transitions, {("new", "POST", "/activate"): (200, "active")}))
        self.assertTrue(verify_data_invariants(({"id": 1}, {"id": 2}), (lambda row: row["id"] > 0,)))
        self.assertTrue(verify_ci_remediation(CIRemediation(("unit",), (), ("src/fix.py",)), allowed_paths=("src/",)))
        self.assertTrue(differential_verify({"a": 1}, {"a": 1}))
        self.assertTrue(metamorphic_verify(2, lambda value: value + 1, lambda value: value * 2, lambda base, changed: changed == base + 2))

    def test_promotion_pipeline_requires_order_human_gate_rollback_and_detects_drift(self) -> None:
        pipeline = PromotionPipeline(digest("candidate"), digest("evaluator"), digest("environment"))
        with self.assertRaises(RuntimeError):
            pipeline.advance(PromotionStage.CANARY, all_guardrails_passed=True)
        self.assertTrue(pipeline.advance(PromotionStage.OFFLINE, all_guardrails_passed=True).approved)
        self.assertTrue(pipeline.advance(PromotionStage.SHADOW, all_guardrails_passed=True).approved)
        self.assertTrue(pipeline.advance(PromotionStage.CANARY, all_guardrails_passed=True).approved)
        denied = pipeline.advance(
            PromotionStage.PRODUCTION,
            all_guardrails_passed=True,
            irreversible=True,
        )
        self.assertFalse(denied.approved)

        second = PromotionPipeline(digest("candidate-2"), digest("evaluator"), digest("environment"))
        second.advance(PromotionStage.OFFLINE, all_guardrails_passed=True)
        second.advance(PromotionStage.SHADOW, all_guardrails_passed=True)
        second.advance(PromotionStage.CANARY, all_guardrails_passed=True)
        approved = second.advance(
            PromotionStage.PRODUCTION,
            all_guardrails_passed=True,
            irreversible=True,
            approval_actor="human-reviewer",
        )
        self.assertTrue(approved.approved)
        self.assertTrue(second.production_drifted(evaluator_digest=digest("changed"), environment_digest=digest("environment")))
        rollback = second.rollback(failed_candidate_digest=digest("candidate-2"), approval_actor="operator")
        self.assertEqual(PromotionStage.ROLLBACK, rollback.stage)
        self.assertEqual(digest("candidate-2"), rollback.rollback_of)


if __name__ == "__main__":
    unittest.main()
