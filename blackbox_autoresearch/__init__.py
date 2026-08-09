"""Trusted primitives for black-box autoresearch."""

from .contracts import (
    CandidateRef,
    DecisionKind,
    EvidenceArtifact,
    EvidenceMode,
    Evaluation,
    PromotionReceipt,
    PromotionStage,
    RunManifest,
    TaskSpec,
    Trajectory,
    TrajectoryStep,
)
from .decision import decide_paired_trials
from .evidence import EvidenceChain
from .qualification import HiddenCaseVault, QualifiedVerifier, qualify_with_hidden_cases
from .runtime import DeterministicCounterEnvironment, EnvironmentAdapter, Verifier, qualify_verifier
from .sandbox import (
    BudgetExceeded,
    BudgetMeter,
    MemorySandboxProvider,
    ResourcePolicy,
    TrustedRuntime,
)
from .search_strategies import SearchBudget, SearchStrategy, UCB1Bandit
from .stochastic import PairedEvaluation, PairedTrial, run_paired_trials
from .store import FileEvidenceStore

__all__ = [
    "BudgetExceeded",
    "BudgetMeter",
    "CandidateRef",
    "DecisionKind",
    "DeterministicCounterEnvironment",
    "EnvironmentAdapter",
    "EvidenceArtifact",
    "EvidenceChain",
    "EvidenceMode",
    "Evaluation",
    "FileEvidenceStore",
    "HiddenCaseVault",
    "MemorySandboxProvider",
    "PairedEvaluation",
    "PairedTrial",
    "PromotionReceipt",
    "PromotionStage",
    "QualifiedVerifier",
    "ResourcePolicy",
    "RunManifest",
    "SearchBudget",
    "SearchStrategy",
    "TaskSpec",
    "Trajectory",
    "TrajectoryStep",
    "TrustedRuntime",
    "UCB1Bandit",
    "Verifier",
    "decide_paired_trials",
    "qualify_verifier",
    "qualify_with_hidden_cases",
    "run_paired_trials",
]
