"""Provider-neutral trusted sandbox orchestration.

The core runtime never executes ambient configuration. Every run is driven by a
pinned RunManifest and an explicit ResourcePolicy. Concrete providers (local
fake, OpenShell, NeMo Gym, device farms) implement SandboxProvider behind this
boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import time
from typing import Any, Callable, Protocol

from .contracts import RunManifest


@dataclass(frozen=True)
class ResourcePolicy:
    readable_paths: tuple[str, ...] = ()
    writable_paths: tuple[str, ...] = ()
    network_allowlist: tuple[str, ...] = ()
    credential_names: tuple[str, ...] = ()
    evaluator_read_only: bool = True

    def permits_network(self, host: str) -> bool:
        return host in self.network_allowlist

    def permits_credential(self, name: str) -> bool:
        return name in self.credential_names


@dataclass
class BudgetMeter:
    max_actions: int
    max_seconds: float
    max_tokens: int
    max_cost_usd: float
    actions: int = 0
    tokens: int = 0
    cost_usd: float = 0.0
    started_at: float = field(default_factory=time.monotonic)

    @classmethod
    def from_manifest(cls, manifest: RunManifest) -> "BudgetMeter":
        return cls(
            manifest.max_actions,
            manifest.max_seconds,
            manifest.max_tokens,
            manifest.max_cost_usd,
        )

    def charge(self, *, actions: int = 0, tokens: int = 0, cost_usd: float = 0.0) -> None:
        if actions < 0 or tokens < 0 or cost_usd < 0:
            raise ValueError("budget charges cannot be negative")
        self.actions += actions
        self.tokens += tokens
        self.cost_usd += cost_usd
        self.check()

    def check(self) -> None:
        elapsed = time.monotonic() - self.started_at
        if self.actions > self.max_actions:
            raise BudgetExceeded("action budget exceeded")
        if elapsed > self.max_seconds:
            raise BudgetExceeded("time budget exceeded")
        if self.tokens > self.max_tokens:
            raise BudgetExceeded("token budget exceeded")
        if self.cost_usd > self.max_cost_usd:
            raise BudgetExceeded("cost budget exceeded")


class BudgetExceeded(RuntimeError):
    pass


class SandboxSession(Protocol):
    def execute(self, action: str) -> Any: ...
    def snapshot(self) -> Any: ...
    def close(self) -> None: ...


class SandboxProvider(Protocol):
    def open(self, manifest: RunManifest, policy: ResourcePolicy) -> SandboxSession: ...


@dataclass(frozen=True)
class RuntimeResult:
    initial_state: Any
    final_state: Any
    observations: tuple[Any, ...]
    actions: tuple[str, ...]


class TrustedRuntime:
    """Executes one candidate session under manifest and policy budgets."""

    def __init__(self, provider: SandboxProvider) -> None:
        self._provider = provider

    def run(
        self,
        manifest: RunManifest,
        policy: ResourcePolicy,
        actions: tuple[str, ...] | list[str],
        *,
        usage: Callable[[str, Any], tuple[int, float]] | None = None,
    ) -> RuntimeResult:
        meter = BudgetMeter.from_manifest(manifest)
        session = self._provider.open(manifest, policy)
        initial = session.snapshot()
        observations: list[Any] = []
        performed: list[str] = []
        try:
            for action in actions:
                meter.charge(actions=1)
                observation = session.execute(action)
                tokens, cost = usage(action, observation) if usage else (0, 0.0)
                meter.charge(tokens=tokens, cost_usd=cost)
                observations.append(observation)
                performed.append(action)
            final = session.snapshot()
            return RuntimeResult(initial, final, tuple(observations), tuple(performed))
        finally:
            session.close()


class MemorySandboxSession:
    """Deterministic provider fixture with an evaluator object kept read-only."""

    def __init__(self, *, seed: int, evaluator_artifact: bytes = b"evaluator") -> None:
        self.state = {"value": seed % 3}
        self._closed = False
        self._evaluator = evaluator_artifact

    @property
    def evaluator_artifact(self) -> bytes:
        return self._evaluator

    def execute(self, action: str) -> dict[str, int]:
        if self._closed:
            raise RuntimeError("sandbox session closed")
        if action == "inc":
            self.state["value"] += 1
        elif action == "dec":
            self.state["value"] -= 1
        elif action.startswith("mutate-evaluator"):
            raise PermissionError("evaluator artifact is read-only")
        else:
            raise ValueError(f"unsupported action: {action}")
        return dict(self.state)

    def snapshot(self) -> dict[str, int]:
        return dict(self.state)

    def close(self) -> None:
        self._closed = True


class MemorySandboxProvider:
    """Reference provider proving session isolation without external dependencies."""

    def __init__(self) -> None:
        self.sessions: list[MemorySandboxSession] = []

    def open(self, manifest: RunManifest, policy: ResourcePolicy) -> MemorySandboxSession:
        if not policy.evaluator_read_only:
            raise ValueError("trusted runtime requires evaluator_read_only")
        session = MemorySandboxSession(seed=manifest.seed)
        self.sessions.append(session)
        return session
