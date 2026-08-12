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
    produce_openshell_evidence,
)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Produce partial live OpenShell evidence")
    value.add_argument("--output", type=Path, required=True)
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
    manifest = produce_openshell_evidence(
        args.output, config=config, harness_path=Path(__file__).resolve(),
        evaluator_path=ROOT / "scripts" / "verify_live_openshell_evidence.py",
    )
    print(json.dumps({"schema": manifest["schema"], "status": manifest["status"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
