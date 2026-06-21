"""Encrypted backup management for monitored source files."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from selffixerai.security.encryption import EncryptionManager


@dataclass(slots=True)
class BackupEntry:
    path: str
    source: str
    created_at: str


class BackupManager:
    """Create encrypted backups and retain a bounded history."""

    def __init__(
        self,
        backup_dir: str | Path | None = None,
        retention: int = 10,
        encryption: EncryptionManager | None = None,
    ) -> None:
        self.backup_dir = Path(backup_dir) if backup_dir else Path.home() / ".local" / "share" / "sovereign-self-fixer" / "backups"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.retention = retention
        self.encryption = encryption or EncryptionManager()

    def create_backup(self, source: str | Path) -> Path:
        source_path = Path(source)
        if not source_path.exists():
            raise FileNotFoundError(source_path)

        created_at = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_path = self.backup_dir / f"{source_path.stem}.{created_at}.bak.enc"
        backup_path.write_bytes(self.encryption.encrypt_bytes(source_path.read_bytes()))
        self._prune()
        return backup_path

    def restore_backup(self, backup: str | Path, destination: str | Path | None = None) -> Path:
        backup_path = Path(backup)
        if not backup_path.exists():
            raise FileNotFoundError(backup_path)

        destination_path = Path(destination) if destination else backup_path.with_suffix("").with_suffix("")
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        destination_path.write_bytes(self.encryption.decrypt_bytes(backup_path.read_bytes()))
        return destination_path

    def latest_backup(self) -> Path | None:
        backups = self.list_backups()
        return backups[-1] if backups else None

    def list_backups(self) -> list[Path]:
        return sorted(
            (path for path in self.backup_dir.glob("*.bak.enc") if path.is_file()),
            key=lambda path: path.stat().st_mtime,
        )

    def _prune(self) -> None:
        if self.retention <= 0:
            return
        backups = self.list_backups()
        excess = len(backups) - self.retention
        for path in backups[: max(excess, 0)]:
            path.unlink(missing_ok=True)
