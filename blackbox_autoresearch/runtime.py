"""Execution boundaries for opaque targets and independent verifiers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from ._content_addressing import canonical_json_bytes, sha256_digest


class EnvironmentAdapter(Protocol):
    def reset(self, seed: int) -> Any: ...
    def act(self, action: str) -> Any: ...
    def observe(self) -> Any: ...
    def snapshot(self) -> Any: ...
    def teardown(self) -> None: ...


class Verifier(Protocol):
    def evaluate(self, initial_state: Any, final_state: Any, trajectory: tuple[Any, ...], hidden_case: Any = None) -> bool: ...


@dataclass(frozen=True)
class QualificationResult:
    qualified: bool
    golden_passed: bool
    initial_rejected: bool
    planted_bad_rejected: bool


class DeterministicCounterEnvironment:
    """Small fake target used to prove reset and verifier separation semantics."""

    def __init__(self) -> None:
        self._value = 0
        self._closed = False

    def reset(self, seed: int) -> dict[str, int]:
        self._closed = False
        self._value = seed % 3
        return self.snapshot()

    def act(self, action: str) -> dict[str, int]:
        if self._closed:
            raise RuntimeError("environment is torn down")
        if action == "inc":
            self._value += 1
        elif action == "dec":
            self._value -= 1
        else:
            raise ValueError(f"unsupported action: {action}")
        return self.observe()

    def observe(self) -> dict[str, int]:
        return {"value": self._value}

    def snapshot(self) -> dict[str, int]:
        return dict(self.observe())

    def state_digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.snapshot()))

    def teardown(self) -> None:
        self._closed = True


def qualify_verifier(
    verifier: Verifier,
    *,
    initial_state: Any,
    golden_state: Any,
    planted_bad_state: Any,
    hidden_case: Any = None,
) -> QualificationResult:
    """Fail closed unless the verifier separates golden from two negative states."""

    golden = bool(verifier.evaluate(initial_state, golden_state, (), hidden_case))
    initial = bool(verifier.evaluate(initial_state, initial_state, (), hidden_case))
    planted_bad = bool(verifier.evaluate(initial_state, planted_bad_state, (), hidden_case))
    return QualificationResult(
        qualified=golden and not initial and not planted_bad,
        golden_passed=golden,
        initial_rejected=not initial,
        planted_bad_rejected=not planted_bad,
    )
