"""Encrypted storage utilities."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Final

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

DEFAULT_KEY_PATH: Final = Path.home() / ".local" / "share" / "sovereign-self-fixer" / "encryption.key"


class EncryptionError(RuntimeError):
    """Raised when encrypted storage operations fail."""


def _normalize_key(material: bytes | str | None) -> bytes:
    if material is None:
        return b""
    if isinstance(material, str):
        material = material.encode("utf-8")
    return sha256(material).digest()


@dataclass(slots=True)
class EncryptedBlob:
    nonce: bytes
    ciphertext: bytes

    def to_bytes(self) -> bytes:
        payload = {
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "ciphertext": base64.b64encode(self.ciphertext).decode("ascii"),
        }
        return json.dumps(payload, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_bytes(cls, blob: bytes) -> "EncryptedBlob":
        payload = json.loads(blob.decode("utf-8"))
        return cls(
            nonce=base64.b64decode(payload["nonce"]),
            ciphertext=base64.b64decode(payload["ciphertext"]),
        )


class EncryptionManager:
    """Create and manage a persistent application encryption key."""

    def __init__(self, key_material: bytes | str | None = None, key_path: Path | None = None) -> None:
        self.key_path = key_path or DEFAULT_KEY_PATH
        self.key_path.parent.mkdir(parents=True, exist_ok=True)

        if key_material is not None:
            self._key = _normalize_key(key_material)
        else:
            self._key = self._load_or_create_key()
        self._cipher = ChaCha20Poly1305(self._key)

    def _load_or_create_key(self) -> bytes:
        if self.key_path.exists():
            return self.key_path.read_bytes()
        key = os.urandom(32)
        self.key_path.write_bytes(key)
        try:
            os.chmod(self.key_path, 0o600)
        except OSError:  # pragma: no cover - platform specific
            pass
        return key

    def encrypt_bytes(self, data: bytes, associated_data: bytes | None = None) -> bytes:
        nonce = os.urandom(12)
        ciphertext = self._cipher.encrypt(nonce, data, associated_data)
        return EncryptedBlob(nonce=nonce, ciphertext=ciphertext).to_bytes()

    def decrypt_bytes(self, blob: bytes, associated_data: bytes | None = None) -> bytes:
        encrypted = EncryptedBlob.from_bytes(blob)
        try:
            return self._cipher.decrypt(encrypted.nonce, encrypted.ciphertext, associated_data)
        except Exception as exc:  # pragma: no cover - cryptography failure path
            raise EncryptionError("decryption failed") from exc

    def encrypt_file(
        self,
        source: Path,
        destination: Path | None = None,
        associated_data: bytes | None = None,
    ) -> Path:
        destination = destination or source.with_suffix(source.suffix + ".enc")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(self.encrypt_bytes(source.read_bytes(), associated_data=associated_data))
        return destination

    def decrypt_file(
        self,
        source: Path,
        destination: Path | None = None,
        associated_data: bytes | None = None,
    ) -> Path:
        destination = destination or source.with_suffix("")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(self.decrypt_bytes(source.read_bytes(), associated_data=associated_data))
        return destination
