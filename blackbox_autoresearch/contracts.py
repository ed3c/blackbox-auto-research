"""Versioned contracts for trusted black-box experiment execution."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import json
import re
from typing import Any

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class EvidenceMode(str, Enum):
    BLACK = "BLACK"
    GRAY = "GRAY"
    WHITE = "WHITE"


class DecisionKind(str, Enum):
    KEEP = "keep"
    DISCARD = "discard"
    INCONCLUSIVE = "inconclusive"
    QUARANTINE = "quarantine"


def _require_digest(name: str, value: str) -> None:
    if not _DIGEST_RE.fullmatch(value):
        raise ValueError(f"{name} must be sha256:<64 lowercase hex chars>")


@dataclass(frozen=True)
class TaskSpec:
    task_id: str
    digest: str
    objective: str
    evidence_mode: EvidenceMode = EvidenceMode.BLACK

    def __post_init__(self) -> None:
        if not self.task_id.strip() or not self.objective.strip():
            raise ValueError("task_id and objective must be non-empty")
        _require_digest("task.digest", self.digest)


@dataclass(frozen=True)
class CandidateRef:
    candidate_id: str
    digest: str
    parent_digest: str | None = None

    def __post_init__(self) -> None:
        if not self.candidate_id.strip():
            raise ValueError("candidate_id must be non-empty")
        _require_digest("candidate.digest", self.digest)
        if self.parent_digest is not None:
            _require_digest("candidate.parent_digest", self.parent_digest)


@dataclass(frozen=True)
class RunManifest:
    run_id: str
    task: TaskSpec
    candidate: CandidateRef
    environment_digest: str
    harness_digest: str
    evaluator_digest: str
    policy_digest: str
    seed: int
    max_actions: int = 100
    max_seconds: float = 300.0
    max_tokens: int = 100_000
    max_cost_usd: float = 5.0

    def __post_init__(self) -> None:
        if not self.run_id.strip():
            raise ValueError("run_id must be non-empty")
        for name in ("environment_digest", "harness_digest", "evaluator_digest", "policy_digest"):
            _require_digest(name, getattr(self, name))
        if self.max_actions < 1 or self.max_seconds <= 0 or self.max_tokens < 1 or self.max_cost_usd < 0:
            raise ValueError("run budgets must be positive, except cost may be zero")

    def canonical_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"), default=lambda value: value.value)


@dataclass(frozen=True)
class TrajectoryStep:
    index: int
    action: str
    observation: Any
    side_effects: tuple[str, ...] = ()


@dataclass(frozen=True)
class Trajectory:
    run_id: str
    initial_state_digest: str
    final_state_digest: str
    steps: tuple[TrajectoryStep, ...] = ()

    def __post_init__(self) -> None:
        _require_digest("trajectory.initial_state_digest", self.initial_state_digest)
        _require_digest("trajectory.final_state_digest", self.final_state_digest)
        if any(step.index != index for index, step in enumerate(self.steps)):
            raise ValueError("trajectory step indexes must be contiguous from zero")


@dataclass(frozen=True)
class EvidenceArtifact:
    kind: str
    digest: str
    locator: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.kind.strip() or not self.locator.strip():
            raise ValueError("evidence kind and locator must be non-empty")
        _require_digest("evidence.digest", self.digest)


@dataclass(frozen=True)
class Evaluation:
    evaluator_digest: str
    primary_score: float
    hard_guardrails_passed: bool
    evidence_digests: tuple[str, ...]
    secondary_metrics: dict[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_digest("evaluation.evaluator_digest", self.evaluator_digest)
        if not self.evidence_digests:
            raise ValueError("evaluation requires independent evidence")
        for digest in self.evidence_digests:
            _require_digest("evaluation.evidence_digest", digest)
