import sqlite3
import tempfile
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import unittest

from blackbox_autoresearch.evidence_lake import (
    ArtifactRecord,
    DirectoryBlobStore,
    HMACSigner,
    S3CompatibleBlobStore,
    SQLiteEvidenceIndex,
)
from blackbox_autoresearch.floci_evidence_store import (
    FlociEvidenceIdentity,
    FlociEnvironment,
    produce_floci_evidence,
    verify_floci_evidence,
)


KEY_A = b"0123456789abcdef0123456789abcdef"
KEY_B = b"fedcba9876543210fedcba9876543210"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


class _S3Handler(BaseHTTPRequestHandler):
    objects: dict[str, bytes] = {}
    requests: list[dict[str, str]] = []

    def log_message(self, *_args) -> None:
        return

    def do_PUT(self) -> None:  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.__class__.requests.append(
            {
                "authorization": self.headers.get("Authorization", ""),
                "date": self.headers.get("X-Amz-Date", ""),
                "if_none_match": self.headers.get("If-None-Match", ""),
                "path": self.path,
            }
        )
        if self.path == "/evidence":
            self.send_response(200)
            self.end_headers()
            return
        if self.headers.get("If-None-Match") == "*" and self.path in self.__class__.objects:
            self.send_response(412)
            self.end_headers()
            return
        self.__class__.objects[self.path] = body
        self.send_response(200)
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        body = self.__class__.objects[self.path]
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _S3Server:
    def __enter__(self) -> str:
        _S3Handler.objects = {}
        _S3Handler.requests = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _S3Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    def __exit__(self, *_args) -> None:
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()


class _MemoryBlobStore:
    def __init__(self) -> None:
        self.data: dict[str, bytes] = {}

    def put(self, data: bytes) -> ArtifactRecord:
        digest = S3CompatibleBlobStore.digest(data)
        self.data[digest] = data
        return ArtifactRecord(digest, len(data))

    def get(self, digest: str) -> bytes:
        return self.data[digest]


class EvidenceLakeTests(unittest.TestCase):
    def test_floci_environment_rejects_string_boolean_flags(self):
        with self.assertRaisesRegex(ValueError, "boolean"):
            FlociEnvironment(
                commit="a" * 40,
                image_id="sha256:" + "b" * 64,
                storage_mode="wal",
                endpoint_scheme="https",
                tls_trust="pinned-self-signed-certificate",
                sigv4_validation_configured="false",  # type: ignore[arg-type]
                iam_enforcement=True,
            )

    def test_floci_receipt_is_l2_only_and_rejects_a_production_relabel(self):
        store = _MemoryBlobStore()
        environment = FlociEnvironment(
            commit="a" * 40,
            image_id="sha256:" + "b" * 64,
            storage_mode="wal",
            endpoint_scheme="https",
            tls_trust="pinned-self-signed-certificate",
            sigv4_validation_configured=True,
            iam_enforcement=True,
        )
        identity = FlociEvidenceIdentity(
            run_id="floci-sandbox-1",
            task_digest=DIGEST_A,
            candidate_digest=DIGEST_B,
            harness_digest=DIGEST_C,
            evaluator_digest="sha256:" + "d" * 64,
            policy_digest="sha256:" + "e" * 64,
        )
        manifest = produce_floci_evidence(
            store,
            b"verified-outcome",
            environment=environment,
            identity=identity,
            producer_pid=101,
        )
        receipt = verify_floci_evidence(
            store,
            manifest,
            expected_environment=environment,
            expected_identity=identity,
            verifier_pid=202,
            run_planted_negative=True,
        )

        self.assertEqual(receipt["provider_kind"], "floci-emulator")
        self.assertEqual(receipt["maturity"], "L2 SANDBOX")
        self.assertFalse(receipt["production_claim_allowed"])
        self.assertEqual(receipt["process_separation"], "verified")
        self.assertEqual(receipt["local_digest_negative"], "detected")

        forged = {**manifest, "maturity": "L4 PRODUCTION"}
        with self.assertRaisesRegex(ValueError, "maturity"):
            verify_floci_evidence(
                store,
                forged,
                expected_environment=environment,
                expected_identity=identity,
                verifier_pid=202,
            )

        malformed_time = {**manifest, "produced_at": "not-a-timestamp"}
        with self.assertRaisesRegex(ValueError, "produced_at"):
            verify_floci_evidence(
                store,
                malformed_time,
                expected_environment=environment,
                expected_identity=identity,
                verifier_pid=202,
            )

        future_time = {**manifest, "produced_at": "2026-08-13T00:00:00+00:00"}
        with self.assertRaisesRegex(ValueError, "later than verification"):
            verify_floci_evidence(
                store,
                future_time,
                expected_environment=environment,
                expected_identity=identity,
                verifier_pid=202,
                clock=lambda: datetime(2026, 8, 12, tzinfo=timezone.utc),
            )

    def test_s3_compatible_store_round_trips_content_addressed_blob_with_sigv4(self):
        with _S3Server() as endpoint:
            store = S3CompatibleBlobStore(
                endpoint=endpoint,
                bucket="evidence",
                region="us-east-1",
                access_key="sandbox-access",
                secret_key="sandbox-secret",
                clock=lambda: datetime(2026, 8, 12, tzinfo=timezone.utc),
            )
            store.create_bucket()
            first = store.put(b"verified-outcome")
            second = store.put(b"verified-outcome")

            self.assertEqual(first, second)
            self.assertEqual(store.get(first.digest), b"verified-outcome")
            object_request = _S3Handler.requests[1]
            self.assertEqual(object_request["date"], "20260812T000000Z")
            self.assertEqual(object_request["if_none_match"], "*")
            self.assertTrue(
                object_request["authorization"].startswith(
                    "AWS4-HMAC-SHA256 Credential=sandbox-access/20260812/us-east-1/s3/aws4_request, "
                )
            )

    def test_sigv4_signing_matches_botocore_derived_golden_vector(self):
        store = S3CompatibleBlobStore(
            endpoint="http://example.test",
            bucket="evidence",
            region="us-east-1",
            access_key="sandbox-access",
            secret_key="sandbox-secret",
            clock=lambda: datetime(2026, 8, 12, tzinfo=timezone.utc),
        )
        payload = b"verified-outcome"
        digest = store.digest(payload).removeprefix("sha256:")
        headers = store._signed_headers(
            "PUT",
            f"/evidence/artifacts/{digest[:2]}/{digest[2:]}",
            payload,
            {
                "Content-Type": "application/octet-stream",
                "If-None-Match": "*",
                "X-Amz-Meta-Sha256": digest,
                "X-Amz-Object-Lock-Legal-Hold": "ON",
            },
        )

        self.assertEqual(
            headers["Authorization"],
            "AWS4-HMAC-SHA256 "
            "Credential=sandbox-access/20260812/us-east-1/s3/aws4_request, "
            "SignedHeaders=content-type;host;if-none-match;x-amz-content-sha256;"
            "x-amz-date;x-amz-meta-sha256;x-amz-object-lock-legal-hold, "
            "Signature=018b7527c9ca3530c4d910d6b530f72bed346ea45e84ac0ef0b7fac35c0a91ac",
        )

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
