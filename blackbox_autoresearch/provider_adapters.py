"""Command-level provider adapters for OpenShell and Enroot.

These adapters generate explicit commands/policies and expose installation probes.
They do not silently fall back to host execution when a provider is missing.
"""

from __future__ import annotations

from dataclasses import dataclass
import shutil
from typing import Any

from .sandbox import ResourcePolicy


@dataclass(frozen=True)
class ProviderCommand:
    argv: tuple[str, ...]
    trust_level: str


class OpenShellAdapter:
    executable = "openshell"

    def available(self) -> bool:
        return shutil.which(self.executable) is not None

    def create_command(self, *, agent: str = "codex", source: str | None = None) -> ProviderCommand:
        argv = [self.executable, "sandbox", "create"]
        if source:
            argv += ["--from", source]
        argv += ["--", agent]
        return ProviderCommand(tuple(argv), "policy-isolated")

    def policy_document(self, policy: ResourcePolicy) -> dict[str, Any]:
        return {
            "filesystem": {
                "read": list(policy.readable_paths),
                "write": list(policy.writable_paths),
            },
            "network": {"allow": list(policy.network_allowlist)},
            "credentials": {"providers": list(policy.credential_names)},
            "evaluator": {"read_only": policy.evaluator_read_only},
        }


class EnrootAdapter:
    executable = "enroot"

    def available(self) -> bool:
        return shutil.which(self.executable) is not None

    def start_command(self, *, container_name: str, command: tuple[str, ...] = ()) -> ProviderCommand:
        if not container_name.strip():
            raise ValueError("container_name must be non-empty")
        argv = (self.executable, "start", container_name, *command)
        return ProviderCommand(argv, "filesystem-separated")

    @property
    def security_warning(self) -> str:
        return "Enroot provides rootless filesystem/container separation but must not be treated as a strong untrusted-code security boundary."
