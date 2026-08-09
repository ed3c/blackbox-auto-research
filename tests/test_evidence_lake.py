import tempfile
from pathlib import Path
import unittest

from blackbox_autoresearch.evidence_lake import DirectoryBlobStore, HMACSigner, SQLiteEvidenceIndex


class EvidenceLakeTests(unittest.TestCase):
    def test_fresh_process_style_reopen_verifies_signed_chain_and_blob(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            blob = DirectoryBlobStore(root / "blobs")
            artifact = blob.put(b"verified-outcome")
            key = b"0123456789abcdef0123456789abcdef"
            index = SQLiteEvidenceIndex(root / "index.db", HMACSigner(key))
            index.register_run("run-1", candidate_digest="sha256:candidate", evaluator_digest="sha256:evaluator", environment_digest="sha256:environment")
            index.append("run-1", "artifact", {"digest": artifact.digest})
            index.append("run-1", "decision", {"decision": "keep"})

            reopened_blob = DirectoryBlobStore(root / "blobs")
            reopened_index = SQLiteEvidenceIndex(root / "index.db", HMACSigner(key))
            self.assertEqual(reopened_blob.get(artifact.digest), b"verified-outcome")
            self.assertTrue(reopened_index.verify("run-1"))
            self.assertEqual(reopened_index.find_runs(evaluator_digest="sha256:evaluator"), ("run-1",))

    def test_tamper_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key = b"0123456789abcdef0123456789abcdef"
            index = SQLiteEvidenceIndex(root / "index.db", HMACSigner(key))
            index.register_run("run-1", candidate_digest="c", evaluator_digest="e", environment_digest="x")
            index.append("run-1", "decision", {"decision": "discard"})
            import sqlite3
            with sqlite3.connect(root / "index.db") as db:
                db.execute("UPDATE events SET payload=? WHERE run_id=?", ('{"decision":"keep"}', "run-1"))
            self.assertFalse(index.verify("run-1"))

    def test_wrong_signing_key_fails_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            index = SQLiteEvidenceIndex(root / "index.db", HMACSigner(b"0123456789abcdef0123456789abcdef"))
            index.register_run("run-1", candidate_digest="c", evaluator_digest="e", environment_digest="x")
            index.append("run-1", "decision", {"decision": "keep"})
            wrong = SQLiteEvidenceIndex(root / "index.db", HMACSigner(b"fedcba9876543210fedcba9876543210"))
            self.assertFalse(wrong.verify("run-1"))


if __name__ == "__main__":
    unittest.main()
