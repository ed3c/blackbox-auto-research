"""Private content-addressing primitives shared inside blackbox_autoresearch."""
from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json_bytes(value: Any) -> bytes:
    """Return the package's canonical compact JSON representation as UTF-8 bytes."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def sha256_digest(data: bytes) -> str:
    """Return the canonical content-addressed SHA-256 string."""
    return "sha256:" + hashlib.sha256(data).hexdigest()
