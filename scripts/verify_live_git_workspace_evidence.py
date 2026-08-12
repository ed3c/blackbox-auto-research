#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from blackbox_autoresearch.ci_live_evidence import EvidenceContext  # noqa: E402
from blackbox_autoresearch.git_workspace_evidence import verify_git_workspace_evidence  # noqa: E402


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Verify live disposable Git workspace evidence")
    value.add_argument("--input", type=Path, required=True)
    value.add_argument("--receipt", type=Path, required=True)
    value.add_argument("--reported-platform-artifact-digest", required=True)
    value.add_argument("--tamper-probe", action="store_true")
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
    receipt = verify_git_workspace_evidence(
        args.input, expected_context=context,
        harness_path=ROOT / "scripts" / "produce_live_git_workspace_evidence.py",
        evaluator_path=Path(__file__).resolve(),
        policy_path=ROOT / ".github" / "workflows" / "live-git-workspace-evidence.yml",
        reported_platform_artifact_digest=args.reported_platform_artifact_digest,
        run_tamper_probe=args.tamper_probe,
    )
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    with args.receipt.open("x") as handle:
        json.dump(receipt, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
    print(json.dumps({"schema": receipt["schema"], "verified": receipt["verified"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
