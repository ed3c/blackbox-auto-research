#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from blackbox_autoresearch.floci_evidence_store import (  # noqa: E402
    FlociWorkerConfig,
    verify_floci_evidence,
)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Verify L2 SANDBOX evidence from a fresh process")
    value.add_argument("--config", type=Path, required=True)
    value.add_argument("--input", type=Path, required=True)
    value.add_argument("--receipt", type=Path, required=True)
    value.add_argument("--planted-negative", action="store_true")
    return value


def main() -> int:
    args = parser().parse_args()
    config = FlociWorkerConfig.load(args.config)
    try:
        manifest = json.loads(args.input.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid Floci evidence manifest: {exc}") from exc
    if not isinstance(manifest, dict):
        raise ValueError("Floci evidence manifest must be an object")
    receipt = verify_floci_evidence(
        config.store(),
        manifest,
        expected_environment=config.environment,
        expected_producer_phase_target=config.producer_phase_target,
        verifier_phase_target=config.phase_target,
        expected_identity=config.identity,
        run_planted_negative=args.planted_negative,
    )
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    with args.receipt.open("x") as handle:
        json.dump(receipt, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
    print(json.dumps({"schema": receipt["schema"], "verified": receipt["verified"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
