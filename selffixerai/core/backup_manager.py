"""Encrypted, integrity-checked, policy-governed backup manager.

Backup flow
-----------
1. Serialize source bytes.
2. Encrypt with ``EncryptionManager`` (ChaCha20-Poly1305 by default).
3. Compute SHA3-512 over both the plaintext and the ciphertext blob.
4. Build a ``BackupManifest`` and sign it with the local Ed25519 key.
5. Write ``<backup_id>.blob`` and ``<backup_id>.manifest``.
6. Prune old backups according to the ``BackupPolicy.retention_count``.

Restore flow
------------
1. Load and parse the manifest.
2. If signing is enabled, verify the Ed25519 signature.
3. Verify the blob hash against the stored ``blob_hash``.
4. Decrypt the blob.
5. Verify the decrypted bytes against the stored ``source_hash``.
6. Return the verified plaintext bytes.

Plaintext secrets must **never** be passed to ``create_backup()``
directly — always encrypt the secret at the application layer first.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from selffixerai.core.policy import BackupPolicy
from selffixerai.security.encryption import EncryptionManager


@dataclass
class BackupManifest:
    backup_id: str
    timestamp: str
    source_hash: str   # SHA3-512 of plaintext bytes
    blob_hash: str     # SHA3-512 of the encrypted blob
    encryption_algo: str
    policy: dict[str, Any] = field(default_factory=dict)
    signature: str = ""

    def _signable_json(self) -> str:
        """Return the canonical JSON string that the signature covers."""
        d = {k: v for k, v in asdict(self).items() if k != "signature"}
        return json.dumps(d, sort_keys=True, separators=(",", ":"))

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> "BackupManifest":
        return cls(**json.loads(raw))


class BackupManager:
    """Create, verify, and restore encrypted backups.

    Parameters
    ----------
    backup_dir:
        Directory that will hold ``.blob`` and ``.manifest`` files.
    encryption:
        ``EncryptionManager`` instance.  A new one is created if omitted.
    policy:
        ``BackupPolicy`` that controls encryption, signing, and retention.
    key_path:
        Path to the signing key.  Auto-generated if absent.
    """

    def __init__(
        self,
        backup_dir: Path,
        encryption: EncryptionManager | None = None,
        policy: BackupPolicy | None = None,
        key_path: Path | None = None,
    ) -> None:
        self.backup_dir = backup_dir
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.encryption = encryption or EncryptionManager(key_path=backup_dir / "backup.key")
        self.policy = policy or BackupPolicy()
        self.key_path = key_path or backup_dir / "backup_sign.ed25519"
        self._sign_key = self._load_or_create_sign_key()

    def _load_or_create_sign_key(self) -> Ed25519PrivateKey:
        if self.key_path.exists():
            return Ed25519PrivateKey.from_private_bytes(self.key_path.read_bytes())
        key = Ed25519PrivateKey.generate()
        self.key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        try:
            os.chmod(self.key_path, 0o600)
        except OSError:  # pragma: no cover - platform specific
            pass
        return key

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_backup(self, source: bytes, label: str = "backup") -> Path:
        """Encrypt and sign *source*, write blob + manifest, prune old backups.

        Returns the path to the newly written manifest file.
        """
        backup_id = (
            f"{label}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{secrets.token_hex(4)}"
        )
        source_hash = hashlib.sha3_512(source).hexdigest()

        blob = self.encryption.encrypt_bytes(source) if self.policy.encrypt else source
        blob_hash = hashlib.sha3_512(blob).hexdigest()

        blob_path = self.backup_dir / f"{backup_id}.blob"
        blob_path.write_bytes(blob)

        manifest = BackupManifest(
            backup_id=backup_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            source_hash=source_hash,
            blob_hash=blob_hash,
            encryption_algo="chacha20poly1305" if self.policy.encrypt else "none",
            policy={"encrypt": self.policy.encrypt, "sign": self.policy.sign},
        )

        if self.policy.sign:
            sig_bytes = self._sign_key.sign(manifest._signable_json().encode())
            manifest.signature = base64.b64encode(sig_bytes).decode("ascii")

        manifest_path = self.backup_dir / f"{backup_id}.manifest"
        manifest_path.write_text(manifest.to_json(), encoding="utf-8")

        self._prune()
        return manifest_path

    def restore_backup(self, manifest_path: Path) -> bytes:
        """Verify integrity and signature, then decrypt and return source bytes.

        Raises
        ------
        InvalidSignature
            If the manifest signature fails verification.
        ValueError
            If any hash check fails.
        """
        manifest = BackupManifest.from_json(manifest_path.read_text(encoding="utf-8"))

        if self.policy.sign and manifest.signature:
            pub = self._sign_key.public_key()
            sig_bytes = base64.b64decode(manifest.signature)
            pub.verify(sig_bytes, manifest._signable_json().encode())

        blob_path = self.backup_dir / f"{manifest.backup_id}.blob"
        blob = blob_path.read_bytes()

        actual_blob_hash = hashlib.sha3_512(blob).hexdigest()
        if actual_blob_hash != manifest.blob_hash:
            raise ValueError(f"Blob integrity check failed for backup: {manifest.backup_id}")

        source = (
            self.encryption.decrypt_bytes(blob)
            if manifest.encryption_algo != "none"
            else blob
        )

        actual_source_hash = hashlib.sha3_512(source).hexdigest()
        if actual_source_hash != manifest.source_hash:
            raise ValueError(
                f"Source integrity check failed after decryption: {manifest.backup_id}"
            )

        return source

    def list_backups(self) -> list[Path]:
        """Return manifest paths sorted oldest-first."""
        return sorted(self.backup_dir.glob("*.manifest"))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _prune(self) -> None:
        manifests = self.list_backups()
        keep = self.policy.retention_count
        to_remove = manifests[:-keep] if len(manifests) > keep else []
        for manifest_path in to_remove:
            backup_id = manifest_path.stem
            blob_path = self.backup_dir / f"{backup_id}.blob"
            manifest_path.unlink(missing_ok=True)
            blob_path.unlink(missing_ok=True)
