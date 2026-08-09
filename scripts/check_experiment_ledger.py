#!/usr/bin/env python3
"""Validate an autoresearch experiment ledger and its stop-loss semantics."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


DIRECTIONS = {"maximize", "minimize"}
DECISIONS = {"keep", "discard"}


def validate(data: object) -> list[str]:
    if not isinstance(data, dict):
        return ["ledger root must be an object"]
    failures: list[str] = []
    if data.get("schema") != "autoresearch-ledger/v1":
        failures.append("schema must be autoresearch-ledger/v1")
    metric = data.get("metric")
    if not isinstance(metric, dict):
        failures.append("metric must be an object")
        metric = {}
    direction = metric.get("direction")
    if direction not in DIRECTIONS:
        failures.append("metric.direction must be maximize or minimize")
    baseline = metric.get("baseline")
    if not isinstance(baseline, (int, float)):
        failures.append("metric.baseline must be numeric")
    stop_loss = data.get("stop_loss")
    if not isinstance(stop_loss, dict):
        failures.append("stop_loss must be an object")
        stop_loss = {}
    max_iterations = stop_loss.get("max_iterations")
    max_no_progress = stop_loss.get("max_no_progress")
    if not isinstance(max_iterations, int) or max_iterations < 1:
        failures.append("max_iterations must be a positive integer")
    if not isinstance(max_no_progress, int) or max_no_progress < 1:
        failures.append("max_no_progress must be a positive integer")
    iterations = data.get("iterations")
    if not isinstance(iterations, list) or not iterations:
        failures.append("iterations must be a non-empty list")
        return failures
    if isinstance(max_iterations, int) and len(iterations) > max_iterations:
        failures.append("iteration budget exceeded")
    best = baseline if isinstance(baseline, (int, float)) else None
    no_progress = 0
    for index, item in enumerate(iterations):
        if not isinstance(item, dict):
            failures.append(f"iterations[{index}] must be an object")
            continue
        for field in ("hypothesis", "change", "verify", "decision", "failure_signature"):
            if not isinstance(item.get(field), str) or not item.get(field, "").strip():
                failures.append(f"iterations[{index}].{field} must be non-empty")
        result = item.get("result")
        decision = item.get("decision")
        if not isinstance(result, (int, float)):
            failures.append(f"iterations[{index}].result must be numeric")
            continue
        if decision not in DECISIONS:
            failures.append(f"iterations[{index}].decision must be keep or discard")
            continue
        improved = (
            best is not None
            and ((direction == "maximize" and result > best) or (direction == "minimize" and result < best))
        )
        if decision == "keep" and not improved:
            failures.append(f"iterations[{index}] keeps a non-improvement")
        if decision == "discard" and improved:
            failures.append(f"iterations[{index}] discards an improvement")
        if decision == "keep" and improved:
            best = result
            no_progress = 0
        else:
            no_progress += 1
        if isinstance(max_no_progress, int) and no_progress > max_no_progress:
            failures.append(f"iterations[{index}] exceeds no-progress stop-loss")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ledger", type=Path)
    args = parser.parse_args(argv)
    try:
        data = json.loads(args.ledger.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"EXPERIMENT-LEDGER FAIL: {error}", file=sys.stderr)
        return 2
    failures = validate(data)
    if failures:
        for failure in failures:
            print(f"EXPERIMENT-LEDGER FAIL: {failure}", file=sys.stderr)
        return 2
    print("EXPERIMENT-LEDGER PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
