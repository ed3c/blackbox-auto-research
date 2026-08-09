"""Provider-neutral production evidence lake primitives.

The SQLite backend is a durable same-host reference implementation. It proves
atomic metadata/event semantics and fresh-process re-verification, but it is not
claimed to be a multi-host production object store.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
from typing import Any, Protocol


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
    """Test/reference signer. Production deployments should use KMS/HSM signing."""

    def __init__(self, key: bytes) -> None:
        if len(key) < 16:
            raise ValueError("signing key must be at least 16 bytes")
        self._key = key

    def sign(self, payload: bytes) -> str:
        return "hmac-sha256:" + hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


class DirectoryBlobStore:
    def __init__(self, root: str | Path) -> None:
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


class SQLiteEvidenceIndex:
    GENESIS = "sha256:" + "0" * 64

    def __init__(self, path: str | Path, signer: ProvenanceSigner) -> None:
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
    def _canonical(run_id: str, sequence: int, kind: str, payload: dict[str, Any], previous: str) -> bytes:
        return json.dumps({"run_id": run_id, "sequence": sequence, "kind": kind, "payload": payload, "previous_hash": previous}, sort_keys=True, separators=(",", ":")).encode()

    def register_run(self, run_id: str, *, candidate_digest: str, evaluator_digest: str, environment_digest: str) -> None:
        with self._connect() as db:
            db.execute("INSERT INTO runs VALUES(?,?,?,?)", (run_id, candidate_digest, evaluator_digest, environment_digest))

    def append(self, run_id: str, kind: str, payload: dict[str, Any]) -> tuple[int, str, str]:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT sequence,event_hash FROM events WHERE run_id=? ORDER BY sequence DESC LIMIT 1", (run_id,)).fetchone()
            sequence = 0 if row is None else int(row[0]) + 1
            previous = self.GENESIS if row is None else str(row[1])
            canonical = self._canonical(run_id, sequence, kind, payload, previous)
            event_hash = "sha256:" + hashlib.sha256(canonical).hexdigest()
            signature = self.signer.sign(canonical + event_hash.encode())
            db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?)", (run_id, sequence, kind, json.dumps(payload, sort_keys=True), previous, event_hash, signature))
            return sequence, event_hash, signature

    def verify(self, run_id: str) -> bool:
        previous = self.GENESIS
        with self._connect() as db:
            rows = db.execute("SELECT sequence,kind,payload,previous_hash,event_hash,signature FROM events WHERE run_id=? ORDER BY sequence", (run_id,)).fetchall()
        for expected, row in enumerate(rows):
            sequence, kind, raw_payload, stored_previous, event_hash, signature = row
            payload = json.loads(raw_payload)
            if sequence != expected or stored_previous != previous:
                return False
            canonical = self._canonical(run_id, sequence, kind, payload, previous)
            expected_hash = "sha256:" + hashlib.sha256(canonical).hexdigest()
            if event_hash != expected_hash or not self.signer.verify(canonical + event_hash.encode(), signature):
                return False
            previous = event_hash
        return True

    def find_runs(self, *, candidate_digest: str | None = None, evaluator_digest: str | None = None, environment_digest: str | None = None) -> tuple[str, ...]:
        clauses: list[str] = []
        values: list[str] = []
        for column, value in (("candidate_digest", candidate_digest), ("evaluator_digest", evaluator_digest), ("environment_digest", environment_digest)):
            if value is not None:
                clauses.append(f"{column}=?")
                values.append(value)
        query = "SELECT run_id FROM runs" + ((" WHERE " + " AND ".join(clauses)) if clauses else "") + " ORDER BY run_id"
        with self._connect() as db:
            return tuple(str(row[0]) for row in db.execute(query, values))
