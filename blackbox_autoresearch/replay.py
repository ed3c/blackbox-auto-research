"""Replay stored outcomes through a pinned verifier without rerunning the candidate."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .contracts import RunManifest, Trajectory
from .runtime import Verifier


@dataclass(frozen=True)
class ReplayResult:
    passed: bool
    evaluator_drift: bool
    reason: str


def reverify(
    manifest: RunManifest,
    trajectory: Trajectory,
    verifier: Verifier,
    *,
    verifier_digest: str,
    initial_state: Any,
    final_state: Any,
    hidden_case: Any = None,
) -> ReplayResult:
    if trajectory.run_id != manifest.run_id:
        return ReplayResult(False, False, "trajectory run_id does not match manifest")
    if verifier_digest != manifest.evaluator_digest:
        return ReplayResult(False, True, "evaluator digest drift detected")
    passed = bool(verifier.evaluate(initial_state, final_state, trajectory.steps, hidden_case))
    return ReplayResult(passed, False, "reverified from stored trajectory")
