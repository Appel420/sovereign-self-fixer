"""Tamper-evident state locking."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .encryption import EncryptionManager
from .tpm import TPMManager


@dataclass(slots=True)
class LockSnapshot:
    code_hash: str
    previous_hash: str | None
    timestamp: str
    signature: str


class TamperHardLock:
    """Persist and verify a chained digest of the monitored source file."""

    def __init__(
        self,
        code_file: str | Path,
        state_file: str | Path | None = None,
        key_file: str | Path | None = None,
        tpm_manager: TPMManager | None = None,
    ) -> None:
        self.code_file = Path(code_file)
        self.state_file = Path(state_file) if state_file else self.code_file.with_suffix(".state.json.enc")
        self.key_file = Path(key_file) if key_file else self.state_file.with_suffix(".ed25519")
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.key_file.parent.mkdir(parents=True, exist_ok=True)
        self.encryption = EncryptionManager()
        self.tpm = tpm_manager or TPMManager()
        self._private_key = self._load_or_create_private_key()
        self._public_key = self._private_key.public_key()
        self._previous_hash: str | None = None

    def _load_or_create_private_key(self) -> Ed25519PrivateKey:
        if self.key_file.exists():
            return Ed25519PrivateKey.from_private_bytes(self.key_file.read_bytes())
        private_key = Ed25519PrivateKey.generate()
        self.key_file.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        try:
            os.chmod(self.key_file, 0o600)
        except OSError:  # pragma: no cover - platform specific
            pass
        return private_key

    def _code_bytes(self) -> bytes:
        return self.code_file.read_bytes() if self.code_file.exists() else b""

    def current_hash(self) -> str:
        return sha256(self._code_bytes()).hexdigest()

    def seal(self) -> LockSnapshot:
        payload = {
            "code_hash": self.current_hash(),
            "previous_hash": self._previous_hash,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tpm": self.tpm.quote().digest,
        }
        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        signature = self._private_key.sign(payload_bytes)
        snapshot = LockSnapshot(
            code_hash=payload["code_hash"],
            previous_hash=payload["previous_hash"],
            timestamp=payload["timestamp"],
            signature=base64.b64encode(signature).decode("ascii"),
        )
        state_payload = {"payload": payload, "signature": snapshot.signature}
        self.state_file.write_bytes(self.encryption.encrypt_bytes(json.dumps(state_payload).encode("utf-8")))
        self._previous_hash = snapshot.code_hash
        return snapshot

    def load_snapshot(self) -> LockSnapshot | None:
        if not self.state_file.exists():
            return None
        raw = self.encryption.decrypt_bytes(self.state_file.read_bytes())
        state_payload = json.loads(raw.decode("utf-8"))
        payload = state_payload["payload"]
        return LockSnapshot(
            code_hash=payload["code_hash"],
            previous_hash=payload.get("previous_hash"),
            timestamp=payload["timestamp"],
            signature=state_payload["signature"],
        )

    def verify(self) -> bool:
        snapshot = self.load_snapshot()
        if snapshot is None:
            return False
        payload = {
            "code_hash": snapshot.code_hash,
            "previous_hash": snapshot.previous_hash,
            "timestamp": snapshot.timestamp,
            "tpm": self.tpm.quote().digest,
        }
        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        try:
            self._public_key.verify(base64.b64decode(snapshot.signature), payload_bytes)
        except InvalidSignature:
            return False
        return snapshot.code_hash == self.current_hash()

    def refresh(self) -> LockSnapshot:
        return self.seal()
