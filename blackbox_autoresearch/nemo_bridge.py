"""Compatibility bridge for NeMo Gym without importing its evolving API.

NeMo Gym is intentionally treated as an external execution/evaluation substrate.
This module maps stable blackbox-auto-research contracts to provider-neutral
configuration dictionaries and imports rollout-shaped records back into the
trusted trajectory model. No NeMo Gym types leak into core contracts.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any

from .contracts import RunManifest, Trajectory, TrajectoryStep


@dataclass(frozen=True)
class BridgeCompatibility:
    bridge_schema: str = "blackbox-nemo-bridge/v1"
    supported_gym_major: int = 0
    minimum_gym_minor: int = 4

    def accepts(self, version: str) -> bool:
        clean = version.lstrip("v")
        parts = clean.split(".")
        if len(parts) < 2 or not all(part.isdigit() for part in parts[:2]):
            return False
        major, minor = int(parts[0]), int(parts[1])
        return major == self.supported_gym_major and minor >= self.minimum_gym_minor


@dataclass(frozen=True)
class SandboxMapping:
    name: str
    trust_level: str
    notes: str


SANDBOX_MAPPINGS = {
    "openshell": SandboxMapping(
        "openshell",
        "policy-isolated",
        "Prefer for untrusted agent execution with explicit filesystem/network/process policy.",
    ),
    "enroot": SandboxMapping(
        "enroot",
        "filesystem-separated",
        "HPC/rootless compatibility backend; not equivalent to a strong security sandbox.",
    ),
}


def manifest_to_gym_config(
    manifest: RunManifest,
    *,
    agent: str,
    dataset: str,
    verifier: str,
    sandbox: str = "openshell",
    skills_path: str | None = None,
) -> dict[str, Any]:
    if sandbox not in SANDBOX_MAPPINGS:
        raise ValueError(f"unsupported sandbox mapping: {sandbox}")
    config: dict[str, Any] = {
        "bridge_schema": "blackbox-nemo-bridge/v1",
        "run_id": manifest.run_id,
        "agent": agent,
        "dataset": dataset,
        "verifier": verifier,
        "sandbox_provider": sandbox,
        "num_repeats": 1,
        "seed": manifest.seed,
        "provenance": {
            "task_digest": manifest.task.digest,
            "candidate_digest": manifest.candidate.digest,
            "environment_digest": manifest.environment_digest,
            "harness_digest": manifest.harness_digest,
            "evaluator_digest": manifest.evaluator_digest,
            "policy_digest": manifest.policy_digest,
        },
    }
    if skills_path:
        config["skills"] = {"path": skills_path, "candidate_digest": manifest.candidate.digest}
    return config


def _digest_state(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def import_rollout(run_id: str, rollout: dict[str, Any]) -> Trajectory:
    """Import a normalized rollout-shaped record into the trusted trajectory."""
    messages = rollout.get("trajectory") or rollout.get("messages") or []
    if not isinstance(messages, list):
        raise ValueError("rollout trajectory/messages must be a list")
    initial = rollout.get("initial_state", {})
    final = rollout.get("final_state", rollout.get("state", {}))
    steps: list[TrajectoryStep] = []
    for index, item in enumerate(messages):
        if isinstance(item, dict):
            action = str(item.get("action", item.get("role", "step")))
            observation = item.get("observation", item.get("content"))
            effects = tuple(str(value) for value in item.get("side_effects", ()))
        else:
            action, observation, effects = "step", item, ()
        steps.append(TrajectoryStep(index, action, observation, effects))
    return Trajectory(run_id, _digest_state(initial), _digest_state(final), tuple(steps))


def export_trajectory(trajectory: Trajectory) -> dict[str, Any]:
    return {
        "run_id": trajectory.run_id,
        "initial_state_digest": trajectory.initial_state_digest,
        "final_state_digest": trajectory.final_state_digest,
        "trajectory": [asdict(step) for step in trajectory.steps],
    }


def verify_bridge_provenance(manifest: RunManifest, gym_result: dict[str, Any]) -> bool:
    provenance = gym_result.get("provenance")
    if not isinstance(provenance, dict):
        return False
    expected = manifest_to_gym_config(
        manifest,
        agent=str(gym_result.get("agent", "agent")),
        dataset=str(gym_result.get("dataset", "dataset")),
        verifier=str(gym_result.get("verifier", "verifier")),
        sandbox=str(gym_result.get("sandbox_provider", "openshell")),
    )["provenance"]
    return provenance == expected
