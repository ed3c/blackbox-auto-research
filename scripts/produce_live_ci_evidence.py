#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from blackbox_autoresearch.ci_live_evidence import EvidenceContext, produce_evidence_bundle  # noqa: E402


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Produce a pinned GitHub Actions CI evidence bundle")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--workflow-commit", required=True)
    parser.add_argument("--runner-os", required=True)
    parser.add_argument("--runner-arch", required=True)
    parser.add_argument("--runner-image-os", required=True)
    parser.add_argument("--runner-image-version", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    context = EvidenceContext(
        repository=args.repository,
        run_id=args.run_id,
        run_attempt=args.run_attempt,
        source_commit=args.source_commit,
        workflow_commit=args.workflow_commit,
        runner_os=args.runner_os,
        runner_arch=args.runner_arch,
        runner_image_os=args.runner_image_os,
        runner_image_version=args.runner_image_version,
    )
    manifest = produce_evidence_bundle(
        args.output,
        context=context,
        harness_path=Path(__file__).resolve(),
        evaluator_path=ROOT / "scripts" / "verify_live_ci_evidence.py",
        policy_path=ROOT / ".github" / "workflows" / "live-ci-evidence.yml",
    )
    print(json.dumps({"schema": manifest["schema"], "status": manifest["status"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
