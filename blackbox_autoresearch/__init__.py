"""Trusted primitives for black-box autoresearch."""

from .contracts import (
    CandidateRef,
    DecisionKind,
    EvidenceArtifact,
    EvidenceMode,
    Evaluation,
    RunManifest,
    TaskSpec,
    Trajectory,
    TrajectoryStep,
)
from .decision import decide_paired_trials
from .evidence import EvidenceChain
from .runtime import DeterministicCounterEnvironment, EnvironmentAdapter, Verifier, qualify_verifier

__all__ = [
    "CandidateRef",
    "DecisionKind",
    "DeterministicCounterEnvironment",
    "EnvironmentAdapter",
    "EvidenceArtifact",
    "EvidenceChain",
    "EvidenceMode",
    "Evaluation",
    "RunManifest",
    "TaskSpec",
    "Trajectory",
    "TrajectoryStep",
    "Verifier",
    "decide_paired_trials",
    "qualify_verifier",
]
