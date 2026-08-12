"""Provider-neutral production evidence lake primitives.

The SQLite backend is a durable same-host reference implementation. It proves
atomic metadata/event semantics and fresh-process re-verification, but it is not
claimed to be a multi-host production object store.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import sqlite3
import ssl
from typing import Any, Callable, Mapping, Protocol, Optional, Union
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class ArtifactRecord:
    digest: str
    size: int


class BlobStore(Protocol):
    def put(self, data: bytes) -> ArtifactRecord: ...

    def get(self, digest: str) -> bytes: ...


class ProvenanceSigner(Protocol):
    def sign(self, payload: bytes) -> str: ...

    def verify(self, payload: bytes, signature: str) -> bool: ...


class HMACSigner:
    """Reference signer; production deployments should use KMS/HSM signing."""

    def __init__(self, key: bytes) -> None:
        if len(key) < 16:
            raise ValueError("signing key must be at least 16 bytes")
        self._key = key

    def sign(self, payload: bytes) -> str:
        digest = hmac.new(self._key, payload, hashlib.sha256).hexdigest()
        return "hmac-sha256:" + digest

    def verify(self, payload: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


class DirectoryBlobStore:
    def __init__(self, root: Union[str, Path]) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def digest(data: bytes) -> str:
        return "sha256:" + hashlib.sha256(data).hexdigest()

    def _path(self, digest: str) -> Path:
        prefix, value = digest.split(":", 1)
        if prefix != "sha256" or len(value) != 64:
            raise ValueError("invalid digest")
        return self.root / value[:2] / value[2:]

    def put(self, data: bytes) -> ArtifactRecord:
        digest = self.digest(data)
        path = self._path(digest)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.read_bytes() != data:
            raise RuntimeError("content-address collision or corruption")
        if not path.exists():
            path.write_bytes(data)
        return ArtifactRecord(digest, len(data))

    def get(self, digest: str) -> bytes:
        data = self._path(digest).read_bytes()
        if self.digest(data) != digest:
            raise RuntimeError("artifact digest mismatch")
        return data


class EvidenceStoreError(RuntimeError):
    """An external evidence-store request failed closed."""


class S3CompatibleBlobStore:
    """Content-addressed evidence blobs over the AWS S3 HTTP contract.

    The adapter is provider-neutral: callers inject an AWS-compatible endpoint.
    A local emulator can exercise this boundary at L2 SANDBOX, but adapter
    existence is not evidence of a LIVE or PRODUCTION deployment.
    """

    _BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
    _DIGEST_RE = re.compile(r"^sha256:([0-9a-f]{64})$")

    def __init__(
        self,
        *,
        endpoint: str,
        bucket: str,
        region: str,
        access_key: str,
        secret_key: str,
        session_token: str | None = None,
        timeout: float = 10,
        ssl_context: ssl.SSLContext | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("endpoint must be an http(s) origin without credentials or query")
        if parsed.path not in {"", "/"}:
            raise ValueError("endpoint must not contain a path")
        if not self._BUCKET_RE.fullmatch(bucket):
            raise ValueError("bucket must be a valid path-style S3 bucket name")
        if not region.strip() or not access_key.strip() or not secret_key:
            raise ValueError("region and credentials must be non-empty")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if parsed.scheme == "http" and ssl_context is not None:
            raise ValueError("ssl_context requires an https endpoint")
        self.endpoint = endpoint.rstrip("/")
        self.bucket = bucket
        self.region = region
        self._access_key = access_key
        self._secret_key = secret_key
        self._session_token = session_token
        self._timeout = timeout
        self._ssl_context = ssl_context
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._host = parsed.netloc

    @staticmethod
    def digest(data: bytes) -> str:
        return "sha256:" + hashlib.sha256(data).hexdigest()

    @staticmethod
    def _hmac(key: bytes, value: str) -> bytes:
        return hmac.new(key, value.encode(), hashlib.sha256).digest()

    def _signed_headers(
        self,
        method: str,
        path: str,
        payload: bytes,
        headers: Mapping[str, str],
    ) -> dict[str, str]:
        instant = self._clock()
        if instant.tzinfo is None or instant.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware datetime")
        instant = instant.astimezone(timezone.utc)
        date = instant.strftime("%Y%m%d")
        timestamp = instant.strftime("%Y%m%dT%H%M%SZ")
        payload_hash = hashlib.sha256(payload).hexdigest()
        canonical_headers = {
            "host": self._host,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": timestamp,
            **{name.lower(): " ".join(value.split()) for name, value in headers.items()},
        }
        if self._session_token is not None:
            canonical_headers["x-amz-security-token"] = self._session_token
        signed_names = ";".join(sorted(canonical_headers))
        canonical_block = "".join(
            f"{name}:{canonical_headers[name]}\n" for name in sorted(canonical_headers)
        )
        canonical_request = "\n".join(
            (method, quote(path, safe="/-_.~"), "", canonical_block, signed_names, payload_hash)
        )
        scope = f"{date}/{self.region}/s3/aws4_request"
        string_to_sign = "\n".join(
            (
                "AWS4-HMAC-SHA256",
                timestamp,
                scope,
                hashlib.sha256(canonical_request.encode()).hexdigest(),
            )
        )
        date_key = self._hmac(("AWS4" + self._secret_key).encode(), date)
        region_key = self._hmac(date_key, self.region)
        service_key = self._hmac(region_key, "s3")
        signing_key = self._hmac(service_key, "aws4_request")
        signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
        result = {name: value for name, value in headers.items()}
        result.update(
            {
                "Host": self._host,
                "X-Amz-Content-SHA256": payload_hash,
                "X-Amz-Date": timestamp,
                "Authorization": (
                    f"AWS4-HMAC-SHA256 Credential={self._access_key}/{scope}, "
                    f"SignedHeaders={signed_names}, Signature={signature}"
                ),
            }
        )
        if self._session_token is not None:
            result["X-Amz-Security-Token"] = self._session_token
        return result

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: bytes = b"",
        headers: Mapping[str, str] | None = None,
        allowed: tuple[int, ...] = (200,),
    ) -> tuple[int, bytes]:
        signed = self._signed_headers(method, path, payload, headers or {})
        request = Request(self.endpoint + path, data=payload if method in {"PUT", "POST"} else None,
                          headers=signed, method=method)
        try:
            with urlopen(request, timeout=self._timeout, context=self._ssl_context) as response:
                status, body = response.status, response.read()
        except HTTPError as exc:
            with exc:
                status, body = exc.code, exc.read()
        except URLError as exc:
            raise EvidenceStoreError(f"S3 {method} request failed: {exc.reason}") from exc
        if status not in allowed:
            raise EvidenceStoreError(f"S3 {method} request failed with HTTP {status}")
        return status, body

    def create_bucket(self) -> None:
        self._request(
            "PUT",
            f"/{self.bucket}",
            headers={"X-Amz-Bucket-Object-Lock-Enabled": "true"},
        )

    def _path(self, digest: str) -> str:
        match = self._DIGEST_RE.fullmatch(digest)
        if match is None:
            raise ValueError("invalid sha256 digest")
        value = match.group(1)
        return f"/{self.bucket}/artifacts/{value[:2]}/{value[2:]}"

    def put(self, data: bytes) -> ArtifactRecord:
        digest = self.digest(data)
        status, _ = self._request(
            "PUT",
            self._path(digest),
            payload=data,
            headers={
                "Content-Type": "application/octet-stream",
                "If-None-Match": "*",
                "X-Amz-Meta-Sha256": digest.removeprefix("sha256:"),
                "X-Amz-Object-Lock-Legal-Hold": "ON",
            },
            allowed=(200, 412),
        )
        if status == 412 and self.get(digest) != data:
            raise EvidenceStoreError("content-address collision or corruption")
        return ArtifactRecord(digest, len(data))

    def get(self, digest: str) -> bytes:
        _, data = self._request("GET", self._path(digest))
        if self.digest(data) != digest:
            raise EvidenceStoreError("artifact digest mismatch")
        return data


class SQLiteEvidenceIndex:
    GENESIS = "sha256:" + "0" * 64

    def __init__(self, path: Union[str, Path], signer: ProvenanceSigner) -> None:
        self.path = Path(path)
        self.signer = signer
        with self._connect() as db:
            db.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS runs(
                  run_id TEXT PRIMARY KEY,
                  candidate_digest TEXT NOT NULL,
                  evaluator_digest TEXT NOT NULL,
                  environment_digest TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events(
                  run_id TEXT NOT NULL,
                  sequence INTEGER NOT NULL,
                  kind TEXT NOT NULL,
                  payload TEXT NOT NULL,
                  previous_hash TEXT NOT NULL,
                  event_hash TEXT NOT NULL,
                  signature TEXT NOT NULL,
                  PRIMARY KEY(run_id, sequence)
                );
                """
            )

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10)
        db.execute("PRAGMA foreign_keys=ON")
        return db

    @staticmethod
    def _canonical(
        run_id: str,
        sequence: int,
        kind: str,
        payload: dict[str, Any],
        previous: str,
    ) -> bytes:
        record = {
            "run_id": run_id,
            "sequence": sequence,
            "kind": kind,
            "payload": payload,
            "previous_hash": previous,
        }
        return json.dumps(record, sort_keys=True, separators=(",", ":")).encode()

    def register_run(
        self,
        run_id: str,
        *,
        candidate_digest: str,
        evaluator_digest: str,
        environment_digest: str,
    ) -> None:
        with self._connect() as db:
            db.execute(
                "INSERT INTO runs VALUES(?,?,?,?)",
                (run_id, candidate_digest, evaluator_digest, environment_digest),
            )

    def append(
        self,
        run_id: str,
        kind: str,
        payload: dict[str, Any],
    ) -> tuple[int, str, str]:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT sequence,event_hash FROM events "
                "WHERE run_id=? ORDER BY sequence DESC LIMIT 1",
                (run_id,),
            ).fetchone()
            sequence = 0 if row is None else int(row[0]) + 1
            previous = self.GENESIS if row is None else str(row[1])
            canonical = self._canonical(run_id, sequence, kind, payload, previous)
            event_hash = "sha256:" + hashlib.sha256(canonical).hexdigest()
            signature = self.signer.sign(canonical + event_hash.encode())
            db.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?)",
                (
                    run_id,
                    sequence,
                    kind,
                    json.dumps(payload, sort_keys=True),
                    previous,
                    event_hash,
                    signature,
                ),
            )
            return sequence, event_hash, signature

    def verify(self, run_id: str) -> bool:
        previous = self.GENESIS
        with self._connect() as db:
            rows = db.execute(
                "SELECT sequence,kind,payload,previous_hash,event_hash,signature "
                "FROM events WHERE run_id=? ORDER BY sequence",
                (run_id,),
            ).fetchall()
        for expected, row in enumerate(rows):
            sequence, kind, raw_payload, stored_previous, event_hash, signature = row
            payload = json.loads(raw_payload)
            if sequence != expected or stored_previous != previous:
                return False
            canonical = self._canonical(run_id, sequence, kind, payload, previous)
            expected_hash = "sha256:" + hashlib.sha256(canonical).hexdigest()
            signed = canonical + event_hash.encode()
            if event_hash != expected_hash or not self.signer.verify(signed, signature):
                return False
            previous = event_hash
        return True

    def find_runs(
        self,
        *,
        candidate_digest: Optional[str] = None,
        evaluator_digest: Optional[str] = None,
        environment_digest: Optional[str] = None,
    ) -> tuple[str, ...]:
        clauses: list[str] = []
        values: list[str] = []
        filters = (
            ("candidate_digest", candidate_digest),
            ("evaluator_digest", evaluator_digest),
            ("environment_digest", environment_digest),
        )
        for column, value in filters:
            if value is not None:
                clauses.append(f"{column}=?")
                values.append(value)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        query = "SELECT run_id FROM runs" + where + " ORDER BY run_id"
        with self._connect() as db:
            return tuple(str(row[0]) for row in db.execute(query, values))
