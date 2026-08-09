import sqlite3
import tempfile
from pathlib import Path
import unittest

from blackbox_autoresearch.evidence_lake import (
    DirectoryBlobStore,
    HMACSigner,
    SQLiteEvidenceIndex,
)


KEY_A = b"0123456789abcdef0123456789abcdef"
KEY_B = b"fedcba9876543210fedcba9876543210"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


class EvidenceLakeTests(unittest.TestCase):
    def test_fresh_process_style_reopen_verifies_signed_chain_and_blob(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            blob = DirectoryBlobStore(root / "blobs")
            artifact = blob.put(b"verified-outcome")
            index = SQLiteEvidenceIndex(root / "index.db", HMACSigner(KEY_A))
            index.register_run(
                "run-1",
                candidate_digest=DIGEST_A,
                evaluator_digest=DIGEST_B,
                environment_digest=DIGEST_C,
            )
            index.append("run-1", "artifact", {"digest": artifact.digest})
            index.append("run-1", "decision", {"decision": "keep"})

            reopened_blob = DirectoryBlobStore(root / "blobs")
            reopened_index = SQLiteEvidenceIndex(root / "index.db", HMACSigner(KEY_A))
            self.assertEqual(reopened_blob.get(artifact.digest), b"verified-outcome")
            self.assertTrue(reopened_index.verify("run-1"))
            self.assertEqual(
                reopened_index.find_runs(evaluator_digest=DIGEST_B),
                ("run-1",),
            )

    def test_tamper_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            index = SQLiteEvidenceIndex(root / "index.db", HMACSigner(KEY_A))
            index.register_run(
                "run-1",
                candidate_digest=DIGEST_A,
                evaluator_digest=DIGEST_B,
                environment_digest=DIGEST_C,
            )
            index.append("run-1", "decision", {"decision": "discard"})
            with sqlite3.connect(root / "index.db") as db:
                db.execute(
                    "UPDATE events SET payload=? WHERE run_id=?",
                    ('{"decision":"keep"}', "run-1"),
                )
            self.assertFalse(index.verify("run-1"))

    def test_wrong_signing_key_fails_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            index = SQLiteEvidenceIndex(root / "index.db", HMACSigner(KEY_A))
            index.register_run(
                "run-1",
                candidate_digest=DIGEST_A,
                evaluator_digest=DIGEST_B,
                environment_digest=DIGEST_C,
            )
            index.append("run-1", "decision", {"decision": "keep"})
            wrong = SQLiteEvidenceIndex(root / "index.db", HMACSigner(KEY_B))
            self.assertFalse(wrong.verify("run-1"))


if __name__ == "__main__":
    unittest.main()
