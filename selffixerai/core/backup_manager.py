"""Encrypted backup management for monitored source files."""

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

DEFAULT_BACKUP_DIR = Path.home() / ".local" / "share" / "sovereign-self-fixer" / "backups"


@dataclass(slots=True)
class BackupEntry:
    path: str
    source: str
    created_at: str


@dataclass(slots=True)
class BackupManifest:
    backup_id: str
    timestamp: str
    source_hash: str
    blob_hash: str
    encryption_algo: str
    policy: dict[str, Any] = field(default_factory=dict)
    signature: str = ""

    def _signable_json(self) -> str:
        payload = {k: v for k, v in asdict(self).items() if k != "signature"}
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> "BackupManifest":
        return cls(**json.loads(raw))


class BackupManager:
    """Create encrypted backups and retain a bounded history."""

    def __init__(
        self,
        backup_dir: str | Path | None = None,
        retention: int = 10,
        encryption: EncryptionManager | None = None,
        policy: BackupPolicy | None = None,
        key_path: Path | None = None,
    ) -> None:
        self.backup_dir = Path(backup_dir) if backup_dir else DEFAULT_BACKUP_DIR
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.policy = policy or BackupPolicy(retention_count=retention)
        self.retention = self.policy.retention_count if policy is not None else retention
        self.encryption = encryption or EncryptionManager(key_path=key_path or self.backup_dir / "backup.key")
        self.key_path = key_path or self.backup_dir / "backup_sign.ed25519"
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

    def create_backup(self, source: bytes | str | Path, label: str = "backup") -> Path:
        if isinstance(source, (bytes, bytearray)):
            return self._create_manifest_backup(bytes(source), label=label)
        return self._create_legacy_backup(Path(source))

    def restore_backup(self, backup: str | Path, destination: str | Path | None = None) -> bytes | Path:
        backup_path = Path(backup)
        if not backup_path.exists():
            raise FileNotFoundError(backup_path)

        if backup_path.name.endswith(".manifest"):
            source = self._restore_manifest_backup(backup_path)
        elif backup_path.name.endswith(".bak.enc"):
            source = self._restore_legacy_backup(backup_path)
        else:
            raise ValueError(f"Unsupported backup format: {backup_path}")

        if destination is None:
            return source

        destination_path = Path(destination)
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        destination_path.write_bytes(source)
        return destination_path

    def latest_backup(self) -> Path | None:
        backups = self.list_backups()
        return backups[-1] if backups else None

    def list_backups(self) -> list[Path]:
        return sorted(
            [
                *self.backup_dir.glob("*.manifest"),
                *self.backup_dir.glob("*.bak.enc"),
            ],
            key=lambda path: (path.stat().st_mtime, path.name),
        )

    def _create_manifest_backup(self, source: bytes, label: str) -> Path:
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

    def _create_legacy_backup(self, source_path: Path) -> Path:
        if not source_path.exists():
            raise FileNotFoundError(source_path)

        created_at = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_path = self.backup_dir / f"{source_path.stem}.{created_at}.bak.enc"
        payload = source_path.read_bytes()
        if self.policy.encrypt:
            payload = self.encryption.encrypt_bytes(payload)
        backup_path.write_bytes(payload)
        self._prune()
        return backup_path

    def _restore_manifest_backup(self, manifest_path: Path) -> bytes:
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

        source = self.encryption.decrypt_bytes(blob) if manifest.encryption_algo != "none" else blob
        actual_source_hash = hashlib.sha3_512(source).hexdigest()
        if actual_source_hash != manifest.source_hash:
            raise ValueError(
                f"Source integrity check failed after decryption: {manifest.backup_id}"
            )
        return source

    def _restore_legacy_backup(self, backup_path: Path) -> bytes:
        payload = backup_path.read_bytes()
        if self.policy.encrypt:
            return self.encryption.decrypt_bytes(payload)
        return payload

    def _prune(self) -> None:
        if self.retention <= 0:
            return
        backups = self.list_backups()
        excess = len(backups) - self.retention
        for path in backups[: max(excess, 0)]:
            self._remove_backup(path)

    def _remove_backup(self, path: Path) -> None:
        if path.name.endswith(".manifest"):
            path.unlink(missing_ok=True)
            (self.backup_dir / f"{path.stem}.blob").unlink(missing_ok=True)
        else:
            path.unlink(missing_ok=True)
