#!/usr/bin/env python3
"""Validate zero-network Forgejo delivery bindings and receipts."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


REGISTRY_REL = Path(".skill-bindings/forgejo-delivery-loop/registry.json")


def discover_root(start: Path) -> Path:
    result = subprocess.run(
        ["git", "-C", str(start), "rev-parse", "--show-toplevel"],
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise ValueError("not inside a Git worktree")
    return Path(result.stdout.strip())


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def contains_github(value: Any) -> bool:
    if isinstance(value, str):
        return "github.com" in value.lower()
    if isinstance(value, list):
        return any(contains_github(item) for item in value)
    if isinstance(value, dict):
        return any(contains_github(item) for item in value.values())
    return False


def validate(root: Path) -> list[str]:
    registry_path = root / REGISTRY_REL
    try:
        registry = load_json(registry_path)
    except ValueError as error:
        return [f"registry-invalid: {error}"]

    failures: list[str] = []
    if contains_github(registry):
        failures.append("cross-forge: registry contains github.com")

    required = registry.get("required_receipt_fields")
    lines = registry.get("lines")
    required_is_valid = (
        isinstance(required, list)
        and bool(required)
        and all(isinstance(item, str) for item in required)
    )
    if not required_is_valid:
        failures.append(
            "registry-invalid: required_receipt_fields must be a non-empty string list"
        )
        return failures
    if not isinstance(lines, list) or not lines:
        failures.append("registry-invalid: lines must be a non-empty list")
        return failures

    for line in lines:
        if not isinstance(line, dict) or not isinstance(line.get("line"), str):
            failures.append("registry-invalid: every line needs a string line id")
            continue
        line_id = line["line"]
        materialized = line.get("materialized_path")
        if materialized is None:
            continue
        if not isinstance(materialized, str) or not materialized:
            failures.append(f"registry-invalid: {line_id} has invalid materialized_path")
            continue
        target = root / materialized
        if not target.is_dir():
            continue
        receipt_path = target / "delivery.json"
        if not receipt_path.is_file():
            failures.append(f"receipt-missing: {line_id}: {receipt_path}")
            continue
        try:
            receipt = load_json(receipt_path)
        except ValueError as error:
            failures.append(f"receipt-invalid: {line_id}: {error}")
            continue
        for field in required:
            if receipt.get(field) in (None, "", []):
                failures.append(f"receipt-field-missing: {line_id}: {field}")
        if receipt.get("line") != line_id:
            failures.append(f"receipt-line-mismatch: {line_id}")
        if (
            line.get("forgejo_repo") is not None
            and receipt.get("repo") != line.get("forgejo_repo")
        ):
            failures.append(f"receipt-repo-mismatch: {line_id}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path)
    args = parser.parse_args()
    try:
        root = args.root.resolve() if args.root else discover_root(Path(__file__).parent)
    except ValueError as error:
        print(f"FATAL {error}", file=sys.stderr)
        return 64
    failures = validate(root)
    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        return 2
    print("PASS: Forgejo delivery registry and receipts are complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
