"""Deterministic non-UI domain fixtures and verifier helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class CommandOutcome:
    exit_code: int
    stdout: str
    stderr: str = ""


def verify_terminal(outcome: CommandOutcome, *, expected_exit: int = 0, stdout_contains: str | None = None) -> bool:
    if outcome.exit_code != expected_exit:
        return False
    return stdout_contains is None or stdout_contains in outcome.stdout


@dataclass(frozen=True)
class MCPCall:
    tool: str
    arguments: dict[str, Any]


def verify_mcp_route(call: MCPCall, *, expected_tool: str, required_arguments: tuple[str, ...] = ()) -> bool:
    return call.tool == expected_tool and all(name in call.arguments for name in required_arguments)


@dataclass(frozen=True)
class APITransition:
    before: str
    method: str
    path: str
    status: int
    after: str


def verify_api_state_machine(
    transitions: tuple[APITransition, ...] | list[APITransition],
    allowed: dict[tuple[str, str, str], tuple[int, str]],
) -> bool:
    for item in transitions:
        expected = allowed.get((item.before, item.method.upper(), item.path))
        if expected != (item.status, item.after):
            return False
    return True


def verify_data_invariants(rows: tuple[dict[str, Any], ...] | list[dict[str, Any]], invariants: tuple[Callable[[dict[str, Any]], bool], ...]) -> bool:
    return all(invariant(row) for row in rows for invariant in invariants)


@dataclass(frozen=True)
class CIRemediation:
    failing_checks_before: tuple[str, ...]
    failing_checks_after: tuple[str, ...]
    changed_files: tuple[str, ...]


def verify_ci_remediation(result: CIRemediation, *, allowed_paths: tuple[str, ...] = ()) -> bool:
    if result.failing_checks_after:
        return False
    if allowed_paths and any(not any(path.startswith(prefix) for prefix in allowed_paths) for path in result.changed_files):
        return False
    return bool(result.failing_checks_before)


def differential_verify(reference: Any, candidate: Any, normalize: Callable[[Any], Any] | None = None) -> bool:
    fn = normalize or (lambda value: value)
    return fn(reference) == fn(candidate)


def metamorphic_verify(
    base_input: Any,
    transform: Callable[[Any], Any],
    execute: Callable[[Any], Any],
    relation: Callable[[Any, Any], bool],
) -> bool:
    base_output = execute(base_input)
    transformed_output = execute(transform(base_input))
    return bool(relation(base_output, transformed_output))
