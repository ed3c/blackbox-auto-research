"""Search-policy primitives above the trusted execution layer."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Hypothesis:
    hypothesis_id: str
    claim: str
    expected_information_gain: float
    cost: float
    risk: float

    def priority(self) -> float:
        denominator = self.cost + self.risk
        if denominator <= 0:
            raise ValueError("cost + risk must be positive")
        return self.expected_information_gain / denominator


@dataclass(frozen=True)
class CandidateNode:
    digest: str
    parent_digest: str | None
    mutation: str


class GreedySearchController:
    """Deterministic baseline that picks the highest information-gain ratio."""

    def choose(self, hypotheses: list[Hypothesis] | tuple[Hypothesis, ...]) -> Hypothesis:
        if not hypotheses:
            raise ValueError("at least one hypothesis is required")
        return max(hypotheses, key=lambda item: (item.priority(), item.hypothesis_id))
