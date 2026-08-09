"""Pluggable search strategies above the trusted execution/evaluation layer."""

from __future__ import annotations

from dataclasses import dataclass, field
import math
import random
from typing import Protocol

from .search import Hypothesis


@dataclass(frozen=True)
class CandidateScore:
    candidate_id: str
    reward: float
    cost: float = 0.0


class SearchStrategy(Protocol):
    def choose(self, candidates: tuple[str, ...] | list[str]) -> str: ...
    def observe(self, candidate_id: str, reward: float) -> None: ...


class UCB1Bandit:
    """Small deterministic UCB1 implementation for noisy discrete candidates."""

    def __init__(self) -> None:
        self.counts: dict[str, int] = {}
        self.means: dict[str, float] = {}
        self.total = 0

    def choose(self, candidates: tuple[str, ...] | list[str]) -> str:
        if not candidates:
            raise ValueError("at least one candidate is required")
        unseen = sorted(candidate for candidate in candidates if self.counts.get(candidate, 0) == 0)
        if unseen:
            return unseen[0]
        return max(
            candidates,
            key=lambda candidate: (
                self.means[candidate]
                + math.sqrt(2.0 * math.log(self.total) / self.counts[candidate]),
                candidate,
            ),
        )

    def observe(self, candidate_id: str, reward: float) -> None:
        count = self.counts.get(candidate_id, 0)
        mean = self.means.get(candidate_id, 0.0)
        new_count = count + 1
        self.counts[candidate_id] = new_count
        self.means[candidate_id] = mean + (reward - mean) / new_count
        self.total += 1


class SurrogateStrategy(Protocol):
    """Extension point for Bayesian optimization without importing a BO library."""

    def suggest(self, observations: tuple[CandidateScore, ...]) -> str: ...


class PopulationOperator(Protocol):
    """Extension point for evolutionary/population search."""

    def mutate(self, parent_id: str) -> str: ...
    def crossover(self, left_id: str, right_id: str) -> str: ...


@dataclass
class SearchBudget:
    max_trials: int
    max_cost: float
    per_candidate_max_trials: int
    trials: int = 0
    cost: float = 0.0
    candidate_trials: dict[str, int] = field(default_factory=dict)

    def charge(self, candidate_id: str, cost: float = 0.0) -> None:
        if cost < 0:
            raise ValueError("cost cannot be negative")
        if self.trials + 1 > self.max_trials:
            raise RuntimeError("global trial budget exceeded")
        if self.cost + cost > self.max_cost:
            raise RuntimeError("global cost budget exceeded")
        count = self.candidate_trials.get(candidate_id, 0) + 1
        if count > self.per_candidate_max_trials:
            raise RuntimeError("per-candidate trial budget exceeded")
        self.trials += 1
        self.cost += cost
        self.candidate_trials[candidate_id] = count


def rank_hypotheses(hypotheses: tuple[Hypothesis, ...] | list[Hypothesis]) -> tuple[Hypothesis, ...]:
    return tuple(sorted(hypotheses, key=lambda item: (-item.priority(), item.hypothesis_id)))


def derive_worker_seed(base_seed: int, candidate_id: str) -> int:
    """Stable per-candidate seed so parallel workers do not share mutable RNG state."""
    value = base_seed & 0xFFFFFFFF
    for byte in candidate_id.encode("utf-8"):
        value = ((value * 16777619) ^ byte) & 0xFFFFFFFF
    return value


def isolated_rng(base_seed: int, candidate_id: str) -> random.Random:
    return random.Random(derive_worker_seed(base_seed, candidate_id))
