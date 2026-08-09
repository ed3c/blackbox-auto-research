"""Conservative decisions for noisy paired black-box trials."""

from __future__ import annotations

from dataclasses import dataclass
import math
import statistics

from .contracts import DecisionKind


@dataclass(frozen=True)
class TrialDecision:
    kind: DecisionKind
    mean_delta: float
    lower_bound: float
    upper_bound: float
    trials: int
    reason: str


def decide_paired_trials(
    baseline: list[float] | tuple[float, ...],
    candidate: list[float] | tuple[float, ...],
    *,
    direction: str = "maximize",
    minimum_effect: float = 0.0,
    hard_guardrails_passed: bool = True,
    quarantine: bool = False,
    z_value: float = 1.96,
) -> TrialDecision:
    """Return keep/discard/inconclusive/quarantine from paired repeated trials.

    Positive deltas always mean improvement. For minimize metrics, the raw
    baseline-candidate difference is used. A one-sample normal approximation
    over paired deltas is intentionally conservative for the stdlib-only MVP;
    callers with richer statistics can replace this policy behind the same
    decision contract.
    """

    if quarantine or not hard_guardrails_passed:
        return TrialDecision(
            DecisionKind.QUARANTINE,
            0.0,
            0.0,
            0.0,
            0,
            "hard guardrail or safety anomaly",
        )
    if direction not in {"maximize", "minimize"}:
        raise ValueError("direction must be maximize or minimize")
    if len(baseline) != len(candidate) or len(baseline) < 2:
        raise ValueError("paired trials require equal-length samples with at least two observations")
    if minimum_effect < 0:
        raise ValueError("minimum_effect must be non-negative")

    if direction == "maximize":
        deltas = [new - old for old, new in zip(baseline, candidate)]
    else:
        deltas = [old - new for old, new in zip(baseline, candidate)]

    mean_delta = statistics.fmean(deltas)
    stderr = statistics.stdev(deltas) / math.sqrt(len(deltas))
    lower = mean_delta - z_value * stderr
    upper = mean_delta + z_value * stderr

    if lower > minimum_effect:
        kind = DecisionKind.KEEP
        reason = "lower confidence bound exceeds minimum effect"
    elif upper <= 0:
        kind = DecisionKind.DISCARD
        reason = "upper confidence bound shows no improvement"
    else:
        kind = DecisionKind.INCONCLUSIVE
        reason = "confidence interval crosses the decision boundary"

    return TrialDecision(kind, mean_delta, lower, upper, len(deltas), reason)
