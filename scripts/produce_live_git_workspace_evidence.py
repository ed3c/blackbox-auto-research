#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from blackbox_autoresearch.ci_live_evidence import EvidenceContext  # noqa: E402
from blackbox_autoresearch.git_workspace_evidence import produce_git_workspace_evidence  # noqa: E402


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Produce live disposable Git workspace evidence")
    value.add_argument("--output", type=Path, required=True)
    value.add_argument("--workspace", type=Path, required=True)
    for name in (
        "repository", "run-id", "run-attempt", "source-commit", "workflow-commit",
        "runner-os", "runner-arch", "runner-image-os", "runner-image-version",
    ):
        value.add_argument("--" + name, required=True)
    return value


def main() -> int:
    args = parser().parse_args()
    context = EvidenceContext(
        repository=args.repository, run_id=args.run_id, run_attempt=args.run_attempt,
        source_commit=args.source_commit, workflow_commit=args.workflow_commit,
        runner_os=args.runner_os, runner_arch=args.runner_arch,
        runner_image_os=args.runner_image_os, runner_image_version=args.runner_image_version,
    )
    manifest = produce_git_workspace_evidence(
        args.output, args.workspace, context=context, harness_path=Path(__file__).resolve(),
        evaluator_path=ROOT / "scripts" / "verify_live_git_workspace_evidence.py",
        policy_path=ROOT / ".github" / "workflows" / "live-git-workspace-evidence.yml",
    )
    print(json.dumps({"schema": manifest["schema"], "status": manifest["status"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
