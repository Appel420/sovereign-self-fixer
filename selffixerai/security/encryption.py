     # main
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

#!/usr/bin/env python3
"""Encryption Module — XChaCha20-Poly1305 + ML-KEM + ML-DSA-87"""

import os
import logging
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305

try:
    import oqs
    HAS_OQS = True
except ImportError:
    HAS_OQS = False
    logging.warning("python-oqs not installed. ML-KEM / ML-DSA-87 will be unavailable.")

class CodeCryptor:
    def __init__(self, key_file: str = "master.key"):
        self.key_file = key_file
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                key = f.read()
        else:
            key = XChaCha20Poly1305.generate_key()
            with open(key_file, "wb") as f:
                f.write(key)
        self.key = key
        self.cipher = XChaCha20Poly1305(self.key)

    def encrypt(self, content: str) -> bytes:
        nonce = os.urandom(24)
        ciphertext = self.cipher.encrypt(nonce, content.encode(), None)
        return nonce + ciphertext

    def decrypt(self, blob: bytes) -> str:
        nonce, ciphertext = blob[:24], blob[24:]
        return self.cipher.decrypt(nonce, ciphertext, None).decode()

class PQCHybrid:
    def __init__(self):
        self.ml_kem = None
        self.ml_dsa = None
        if HAS_OQS:
            try:
                self.ml_kem = oqs.KeyEncapsulation("ML-KEM-768")
                self.ml_dsa = oqs.Signature("ML-DSA-87")
            except Exception as e:
                logging.error(f"Failed to initialize PQC: {e}")

    def generate_kem_keypair(self) -> Optional[Tuple[bytes, bytes]]:
        if not self.ml_kem: return None
        public_key = self.ml_kem.generate_keypair()
        secret_key = self.ml_kem.export_secret_key()
        return public_key, secret_key

    def sign(self, message: bytes, secret_key: bytes) -> Optional[bytes]:
        if not self.ml_dsa: return None
        self.ml_dsa.import_secret_key(secret_key)
        return self.ml_dsa.sign(message)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        if not self.ml_dsa: return False
        try:
            verifier = oqs.Signature("ML-DSA-87")
            return verifier.verify(message, signature, public_key)
        except Exception:
            return False
         # Ara-hardened
