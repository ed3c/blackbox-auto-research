from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from scripts.run_floci_evidence_store_sandbox import (
    AwsProbeOutcome,
    _create_container,
    _evaluate_aws_probe,
    _security_decision,
)


class FlociEvidenceStoreRunnerTests(unittest.TestCase):
    def test_aws_probe_only_accepts_explicit_expected_service_error(self):
        denied = subprocess.CompletedProcess(
            ("aws",),
            254,
            "",
            "An error occurred (SignatureDoesNotMatch) when calling HeadObject",
        )
        transport = subprocess.CompletedProcess(
            ("aws",),
            255,
            "",
            "Could not connect to the endpoint URL",
        )
        accepted = subprocess.CompletedProcess(("aws",), 0, "{}", "")

        self.assertEqual(
            _evaluate_aws_probe(denied, {"SignatureDoesNotMatch"}),
            AwsProbeOutcome("denied", "SignatureDoesNotMatch"),
        )
        self.assertEqual(
            _evaluate_aws_probe(transport, {"SignatureDoesNotMatch"}),
            AwsProbeOutcome("inconclusive", "unclassified-cli-error"),
        )
        self.assertEqual(
            _evaluate_aws_probe(accepted, {"SignatureDoesNotMatch"}),
            AwsProbeOutcome("accepted", "request-succeeded"),
        )
        self.assertEqual(
            _security_decision(
                AwsProbeOutcome("denied", "AccessDenied"),
                AwsProbeOutcome("accepted", "request-succeeded"),
            ),
            "quarantine",
        )

    def test_container_creation_does_not_hide_cleanup_ownership_behind_port_lookup(self):
        completed = subprocess.CompletedProcess(("docker",), 0, "container-id\n", "")
        with patch(
            "scripts.run_floci_evidence_store_sandbox._run",
            return_value=completed,
        ) as run:
            _create_container("floci-test", "sha256:" + "a" * 64, "/tmp/data")

        self.assertEqual(run.call_args.args[:3], ("docker", "run", "-d"))


if __name__ == "__main__":
    unittest.main()
