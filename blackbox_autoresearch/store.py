"""Durable content-addressed evidence and append-only run event storage."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class StoredArtifact:
    digest: str
    path: str
    size: int


@dataclass(frozen=True)
class RunEvent:
    sequence: int
    run_id: str
    kind: str
    payload: dict[str, Any]
    previous_hash: str
    event_hash: str


class FileEvidenceStore:
    """Filesystem reference store suitable for replay tests and local runners.

    Artifacts are content-addressed by SHA-256. Run events are JSONL records with
    a per-run hash chain. Existing event logs are only opened in append mode.
    """

    GENESIS = "sha256:" + "0" * 64

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.artifacts = self.root / "artifacts"
        self.events = self.root / "events"
        self.artifacts.mkdir(parents=True, exist_ok=True)
        self.events.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def digest_bytes(data: bytes) -> str:
        return "sha256:" + hashlib.sha256(data).hexdigest()

    def put_bytes(self, data: bytes) -> StoredArtifact:
        digest = self.digest_bytes(data)
        hex_digest = digest.split(":", 1)[1]
        path = self.artifacts / hex_digest[:2] / hex_digest[2:]
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if path.read_bytes() != data:
                raise RuntimeError("content-address collision or store corruption")
        else:
            path.write_bytes(data)
        return StoredArtifact(digest, str(path.relative_to(self.root)), len(data))

    def get_bytes(self, digest: str) -> bytes:
        prefix, hex_digest = digest.split(":", 1)
        if prefix != "sha256" or len(hex_digest) != 64:
            raise ValueError("invalid sha256 digest")
        path = self.artifacts / hex_digest[:2] / hex_digest[2:]
        data = path.read_bytes()
        if self.digest_bytes(data) != digest:
            raise RuntimeError("artifact digest mismatch")
        return data

    @staticmethod
    def _event_hash(sequence: int, run_id: str, kind: str, payload: dict[str, Any], previous_hash: str) -> str:
        canonical = json.dumps(
            {
                "sequence": sequence,
                "run_id": run_id,
                "kind": kind,
                "payload": payload,
                "previous_hash": previous_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return "sha256:" + hashlib.sha256(canonical).hexdigest()

    def _event_path(self, run_id: str) -> Path:
        if not run_id or "/" in run_id or ".." in run_id:
            raise ValueError("unsafe run_id")
        return self.events / f"{run_id}.jsonl"

    def read_events(self, run_id: str) -> tuple[RunEvent, ...]:
        path = self._event_path(run_id)
        if not path.exists():
            return ()
        result: list[RunEvent] = []
        for raw in path.read_text(encoding="utf-8").splitlines():
            data = json.loads(raw)
            result.append(RunEvent(**data))
        return tuple(result)

    def append_event(self, run_id: str, kind: str, payload: dict[str, Any]) -> RunEvent:
        prior = self.read_events(run_id)
        sequence = len(prior)
        previous_hash = prior[-1].event_hash if prior else self.GENESIS
        event_hash = self._event_hash(sequence, run_id, kind, payload, previous_hash)
        event = RunEvent(sequence, run_id, kind, dict(payload), previous_hash, event_hash)
        with self._event_path(run_id).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(event), sort_keys=True, separators=(",", ":")) + "\n")
        return event

    def verify_run(self, run_id: str) -> bool:
        previous = self.GENESIS
        for sequence, event in enumerate(self.read_events(run_id)):
            expected = self._event_hash(sequence, run_id, event.kind, event.payload, previous)
            if event.sequence != sequence or event.previous_hash != previous or event.event_hash != expected:
                return False
            previous = event.event_hash
        return True

    def query(self, *, kind: str | None = None) -> tuple[RunEvent, ...]:
        result: list[RunEvent] = []
        for path in sorted(self.events.glob("*.jsonl")):
            for event in self.read_events(path.stem):
                if kind is None or event.kind == kind:
                    result.append(event)
        return tuple(result)

    def query_decisions(self, decisions: Iterable[str] = ("discard", "quarantine")) -> tuple[RunEvent, ...]:
        wanted = set(decisions)
        return tuple(
            event
            for event in self.query(kind="decision")
            if str(event.payload.get("decision")) in wanted
        )
