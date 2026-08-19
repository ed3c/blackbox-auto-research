from __future__ import annotations

import hashlib
import json
import unittest

from blackbox_autoresearch._content_addressing import canonical_json_bytes, sha256_digest
from blackbox_autoresearch.evidence import EvidenceChain
from blackbox_autoresearch.runtime import DeterministicCounterEnvironment


def baseline_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def baseline_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class ContentAddressingCanaryTests(unittest.TestCase):
    def test_shared_primitive_matches_pre_refactor_ascii_and_unicode_bytes(self) -> None:
        for value in (
            {"b": 2, "a": 1},
            {"text": "台灣", "nested": {"z": True, "a": None}},
        ):
            expected = baseline_bytes(value)
            self.assertEqual(expected, canonical_json_bytes(value))
            self.assertEqual(baseline_digest(expected), sha256_digest(expected))

    def test_runtime_state_digest_matches_pre_refactor_formula(self) -> None:
        env = DeterministicCounterEnvironment()
        env.reset(seed=4)
        env.act("inc")
        expected = baseline_digest(baseline_bytes(env.snapshot()))
        self.assertEqual(expected, env.state_digest())

    def test_evidence_event_digest_matches_pre_refactor_formula(self) -> None:
        chain = EvidenceChain()
        payload = {"kind": "observation", "value": "台灣"}
        event = chain.append(payload)
        expected = baseline_digest(
            baseline_bytes(
                {
                    "sequence": 0,
                    "previous_hash": EvidenceChain.GENESIS,
                    "payload": payload,
                }
            )
        )
        self.assertEqual(expected, event.event_hash)
        self.assertTrue(chain.verify())


if __name__ == "__main__":
    unittest.main()
