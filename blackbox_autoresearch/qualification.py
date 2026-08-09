"""Producer-judge qualification with hidden-case and evaluator identity separation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .runtime import Verifier, QualificationResult, qualify_verifier


@dataclass(frozen=True)
class QualifiedVerifier:
    evaluator_digest: str
    result: QualificationResult
    hidden_case_count: int

    @property
    def qualified(self) -> bool:
        return self.result.qualified


class HiddenCaseVault:
    """Judge-only storage. Candidate-facing APIs intentionally expose no getter."""

    def __init__(self, cases: tuple[Any, ...] | list[Any]) -> None:
        if not cases:
            raise ValueError("at least one hidden case is required")
        self.__cases = tuple(cases)

    def _judge_cases(self) -> tuple[Any, ...]:
        return self.__cases

    def candidate_view(self) -> dict[str, int]:
        return {"hidden_case_count": len(self.__cases)}


def qualify_with_hidden_cases(
    verifier: Verifier,
    *,
    evaluator_digest: str,
    initial_state: Any,
    golden_state: Any,
    planted_bad_state: Any,
    vault: HiddenCaseVault,
) -> QualifiedVerifier:
    """All hidden cases must independently satisfy golden/negative separation."""

    aggregate: QualificationResult | None = None
    for hidden_case in vault._judge_cases():
        current = qualify_verifier(
            verifier,
            initial_state=initial_state,
            golden_state=golden_state,
            planted_bad_state=planted_bad_state,
            hidden_case=hidden_case,
        )
        if aggregate is None:
            aggregate = current
        else:
            aggregate = QualificationResult(
                qualified=aggregate.qualified and current.qualified,
                golden_passed=aggregate.golden_passed and current.golden_passed,
                initial_rejected=aggregate.initial_rejected and current.initial_rejected,
                planted_bad_rejected=aggregate.planted_bad_rejected and current.planted_bad_rejected,
            )
    assert aggregate is not None
    return QualifiedVerifier(evaluator_digest, aggregate, len(vault._judge_cases()))
