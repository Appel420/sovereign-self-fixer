"""Immutable, hash-chained audit log with signed Merkle checkpoints.

Design
------
Each ``LogEntry`` includes:
- a monotonically increasing index
- ISO-8601 UTC timestamp
- event type and actor
- arbitrary (non-secret) metadata dict
- ``previous_hash`` — SHA3-512 digest of the prior entry
- ``entry_hash``    — SHA3-512 digest of this entry's canonical payload

Periodic checkpoints sign a Merkle root over a window of entry hashes
using the local Ed25519 key.  This makes the log independently verifiable
without access to the application's runtime state.

Rules
-----
- Plaintext secrets must **never** be passed as ``data`` to ``append()``.
- The log is append-only; entries are never modified or deleted.
- ``verify_chain()`` re-derives every hash from genesis and returns
  ``False`` on the first discrepancy.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _sha3_512(data: bytes) -> str:
    return hashlib.sha3_512(data).hexdigest()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class LogEntry:
    index: int
    timestamp: str
    event_type: str
    actor: str
    data: dict[str, Any]
    previous_hash: str
    entry_hash: str = field(default="")

    def compute_hash(self) -> str:
        """Deterministically hash this entry's immutable fields."""
        payload = {
            "index": self.index,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "actor": self.actor,
            "data": self.data,
            "previous_hash": self.previous_hash,
        }
        return _sha3_512(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())


@dataclass
class Checkpoint:
    start_index: int
    end_index: int
    merkle_root: str
    timestamp: str
    signature: str = ""


class ImmutableLog:
    """Append-only hash-chained event log with periodic signed checkpoints.

    Parameters
    ----------
    log_path:
        Path to the JSON log file.  Created on first write.
    key_path:
        Path to the raw Ed25519 private key used to sign checkpoints.
        Generated automatically if absent; stored with 0o600 permissions.
    checkpoint_interval:
        Number of appended entries between automatic checkpoint creation.
    """

    GENESIS_HASH = "0" * 128  # 512-bit zero sentinel for the first entry

    def __init__(
        self,
        log_path: Path,
        key_path: Path | None = None,
        checkpoint_interval: int = 100,
    ) -> None:
        self.log_path = log_path
        self.key_path = key_path or log_path.with_suffix(".ed25519")
        self.checkpoint_interval = checkpoint_interval
        self._lock = Lock()
        self._entries: list[LogEntry] = []
        self._checkpoints: list[Checkpoint] = []
        self._private_key: Ed25519PrivateKey | None = None
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self._load_or_init_key()
        self._load()

    # ------------------------------------------------------------------
    # Key management
    # ------------------------------------------------------------------

    def _load_or_init_key(self) -> None:
        if self.key_path.exists():
            self._private_key = Ed25519PrivateKey.from_private_bytes(self.key_path.read_bytes())
        else:
            self._private_key = Ed25519PrivateKey.generate()
            self.key_path.write_bytes(
                self._private_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
            try:
                os.chmod(self.key_path, 0o600)
            except OSError:  # pragma: no cover - platform specific
                pass

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if not self.log_path.exists():
            return
        raw = json.loads(self.log_path.read_text(encoding="utf-8"))
        self._entries = [LogEntry(**e) for e in raw.get("entries", [])]
        self._checkpoints = [Checkpoint(**c) for c in raw.get("checkpoints", [])]

    def _save(self) -> None:
        payload = {
            "entries": [asdict(e) for e in self._entries],
            "checkpoints": [asdict(c) for c in self._checkpoints],
        }
        self.log_path.write_text(
            json.dumps(payload, indent=2, separators=(",", ": ")),
            encoding="utf-8",
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def append(
        self, event_type: str, actor: str, data: dict[str, Any] | None = None
    ) -> LogEntry:
        """Append an event.  *data* must never contain plaintext secrets."""
        with self._lock:
            prev_hash = self._entries[-1].entry_hash if self._entries else self.GENESIS_HASH
            entry = LogEntry(
                index=len(self._entries),
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type=event_type,
                actor=actor,
                data=data or {},
                previous_hash=prev_hash,
            )
            entry.entry_hash = entry.compute_hash()
            self._entries.append(entry)
            self._save()
            if len(self._entries) % self.checkpoint_interval == 0:
                self._make_checkpoint()
            return entry

    def force_checkpoint(self) -> Checkpoint | None:
        """Create a checkpoint immediately regardless of interval."""
        with self._lock:
            if not self._entries:
                return None
            last_cp_end = self._checkpoints[-1].end_index if self._checkpoints else -1
            if self._entries[-1].index <= last_cp_end:
                return None
            return self._make_checkpoint()

    def verify_chain(self) -> bool:
        """Re-derive every hash from genesis.  Returns ``False`` on any discrepancy."""
        prev = self.GENESIS_HASH
        for entry in self._entries:
            if entry.previous_hash != prev:
                return False
            computed = entry.compute_hash()
            if computed != entry.entry_hash:
                return False
            prev = entry.entry_hash
        return True

    def get_entries(self, event_type: str | None = None) -> list[LogEntry]:
        if event_type is None:
            return list(self._entries)
        return [e for e in self._entries if e.event_type == event_type]

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    @property
    def checkpoint_count(self) -> int:
        return len(self._checkpoints)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_checkpoint(self) -> Checkpoint:
        last_cp_end = self._checkpoints[-1].end_index if self._checkpoints else -1
        window = [e for e in self._entries if e.index > last_cp_end]
        root = self._merkle_root([e.entry_hash for e in window])
        timestamp = datetime.now(timezone.utc).isoformat()
        payload = (
            f"{window[0].index}:{window[-1].index}:{root}:{timestamp}"
        ).encode()
        sig = ""
        if self._private_key:
            sig = base64.b64encode(self._private_key.sign(payload)).decode("ascii")
        cp = Checkpoint(
            start_index=window[0].index,
            end_index=window[-1].index,
            merkle_root=root,
            timestamp=timestamp,
            signature=sig,
        )
        self._checkpoints.append(cp)
        self._save()
        return cp

    @staticmethod
    def _merkle_root(hashes: list[str]) -> str:
        if not hashes:
            return _sha256(b"empty")
        layer = [h.encode() for h in hashes]
        while len(layer) > 1:
            if len(layer) % 2 == 1:
                layer.append(layer[-1])  # duplicate last node for odd count
            layer = [
                _sha256(layer[i] + layer[i + 1]).encode()
                for i in range(0, len(layer), 2)
            ]
        return layer[0].decode()
