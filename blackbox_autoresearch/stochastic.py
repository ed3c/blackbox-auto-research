"""Repeated paired-seed evaluation helpers for noisy black-box tasks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .decision import TrialDecision, decide_paired_trials


@dataclass(frozen=True)
class PairedTrial:
    seed: int
    baseline_score: float
    candidate_score: float


@dataclass(frozen=True)
class PairedEvaluation:
    trials: tuple[PairedTrial, ...]
    decision: TrialDecision


def run_paired_trials(
    seeds: tuple[int, ...] | list[int],
    baseline_runner: Callable[[int], float],
    candidate_runner: Callable[[int], float],
    *,
    direction: str = "maximize",
    minimum_effect: float = 0.0,
    hard_guardrails_passed: bool = True,
    quarantine: bool = False,
) -> PairedEvaluation:
    if len(seeds) < 2:
        raise ValueError("at least two paired seeds are required")
    if len(set(seeds)) != len(seeds):
        raise ValueError("paired seeds must be unique")
    trials = tuple(
        PairedTrial(seed, float(baseline_runner(seed)), float(candidate_runner(seed)))
        for seed in seeds
    )
    decision = decide_paired_trials(
        [trial.baseline_score for trial in trials],
        [trial.candidate_score for trial in trials],
        direction=direction,
        minimum_effect=minimum_effect,
        hard_guardrails_passed=hard_guardrails_passed,
        quarantine=quarantine,
    )
    return PairedEvaluation(trials, decision)
