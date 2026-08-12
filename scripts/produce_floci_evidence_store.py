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
    produce_floci_evidence,
)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Produce L2 SANDBOX evidence through Floci S3")
    value.add_argument("--config", type=Path, required=True)
    value.add_argument("--payload", type=Path, required=True)
    value.add_argument("--output", type=Path, required=True)
    return value


def main() -> int:
    args = parser().parse_args()
    config = FlociWorkerConfig.load(args.config)
    payload = args.payload.read_bytes()
    store = config.store()
    store.create_bucket()
    manifest = produce_floci_evidence(
        store,
        payload,
        environment=config.environment,
        identity=config.identity,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as handle:
        json.dump(manifest, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
    print(json.dumps({"schema": manifest["schema"], "maturity": manifest["maturity"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
