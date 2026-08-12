#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from blackbox_autoresearch.openshell_live_evidence import (  # noqa: E402
    OpenShellRunConfig,
    verify_openshell_evidence,
)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Independently verify partial live OpenShell evidence")
    value.add_argument("--input", type=Path, required=True)
    value.add_argument("--receipt", type=Path, required=True)
    value.add_argument("--run-id", required=True)
    value.add_argument("--sandbox-name", required=True)
    value.add_argument("--image-digest", required=True)
    value.add_argument("--expected-version", required=True)
    value.add_argument("--allowed-url", required=True)
    value.add_argument("--denied-url", required=True)
    return value


def main() -> int:
    args = parser().parse_args()
    config = OpenShellRunConfig(
        run_id=args.run_id, sandbox_name=args.sandbox_name, image_digest=args.image_digest,
        expected_version=args.expected_version, allowed_url=args.allowed_url,
        denied_url=args.denied_url,
    )
    receipt = verify_openshell_evidence(
        args.input, expected_config=config,
        harness_path=ROOT / "scripts" / "produce_live_openshell_evidence.py",
        evaluator_path=Path(__file__).resolve(),
    )
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    with args.receipt.open("x") as handle:
        json.dump(receipt, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
