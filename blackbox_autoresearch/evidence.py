"""Content-addressed, hash-chained evidence records."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ._content_addressing import canonical_json_bytes, sha256_digest


@dataclass(frozen=True)
class EvidenceEvent:
    sequence: int
    previous_hash: str
    payload: dict[str, Any]
    event_hash: str


class EvidenceChain:
    GENESIS = "sha256:" + "0" * 64

    def __init__(self) -> None:
        self._events: list[EvidenceEvent] = []

    @staticmethod
    def _digest(sequence: int, previous_hash: str, payload: dict[str, Any]) -> str:
        canonical = canonical_json_bytes(
            {"sequence": sequence, "previous_hash": previous_hash, "payload": payload}
        )
        return sha256_digest(canonical)

    def append(self, payload: dict[str, Any]) -> EvidenceEvent:
        sequence = len(self._events)
        previous = self._events[-1].event_hash if self._events else self.GENESIS
        event = EvidenceEvent(sequence, previous, dict(payload), self._digest(sequence, previous, payload))
        self._events.append(event)
        return event

    def verify(self) -> bool:
        previous = self.GENESIS
        for sequence, event in enumerate(self._events):
            if event.sequence != sequence or event.previous_hash != previous:
                return False
            if event.event_hash != self._digest(sequence, previous, event.payload):
                return False
            previous = event.event_hash
        return True

    def events(self) -> tuple[EvidenceEvent, ...]:
        return tuple(self._events)
