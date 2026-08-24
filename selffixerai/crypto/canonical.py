"""Canonical JSON serialization for signed authority records."""

from __future__ import annotations

import json
from typing import Any


def canonical_bytes(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes suitable for hashing/signing."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
