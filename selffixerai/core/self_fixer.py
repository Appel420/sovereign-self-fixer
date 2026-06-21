"""Core repair loop for Sovereign Self-Fixer."""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from pathlib import Path

from selffixerai.analysis.deep_scanner import DeepScanner, Finding, ScanReport
from selffixerai.core.backup_manager import BackupManager
from selffixerai.memory.repmhl import REPMHL
from selffixerai.notifications import Notifier
from selffixerai.security.tamper_lock import TamperHardLock


@dataclass(slots=True)
class RepairReport:
    path: str
    scanned: bool
    changed: bool
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class SelfFixer:
    """Scan a target file and maintain a tamper-evident audit trail."""

    def __init__(
        self,
        lock: TamperHardLock,
        scanner: DeepScanner,
        notifier: Notifier,
        memory: REPMHL | None = None,
        backup_manager: BackupManager | None = None,
        replica_backup_manager: BackupManager | None = None,
        target_path: str | Path | None = None,
        scan_interval: float = 5.0,
    ) -> None:
        self.lock = lock
        self.scanner = scanner
        self.notifier = notifier
        self.memory = memory
        self.backup_manager = backup_manager
        self.replica_backup_manager = replica_backup_manager
        self.target_path = Path(target_path) if target_path else self.lock.code_file
        self.scan_interval = scan_interval

    async def run(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            self.scan_once()
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=self.scan_interval)
            except asyncio.TimeoutError:
                continue

    def scan_once(self) -> RepairReport:
        changed = False
        notes: list[str] = []

        if not self.target_path.exists():
            notes.extend(self._restore_missing_target())
            changed = True

        scan = self.scanner.scan_file(self.target_path)

        if not scan.has_findings:
            if self.backup_manager is not None:
                backup_path = self.backup_manager.create_backup(self.target_path)
                notes.append(f"backup {backup_path.name}")
            if self.replica_backup_manager is not None:
                replica_path = self.replica_backup_manager.create_backup(self.target_path)
                notes.append(f"replica {replica_path.name}")
            snapshot = self.lock.refresh()
            notes.append(f"sealed {snapshot.code_hash}")
        else:
            notes.extend(self._describe_findings(scan))

        self.notifier.send_notification(
            "scan_complete",
            {"path": str(self.target_path), "findings": len(scan.findings), "changed": changed},
        )

        if self.memory is not None:
            self.memory.add_turn(
                "assistant",
                f"scan_complete path={self.target_path} findings={len(scan.findings)} changed={changed}",
                metadata={"findings": [asdict(finding) for finding in scan.findings]},
            )

        return RepairReport(
            path=str(self.target_path),
            scanned=True,
            changed=changed,
            findings=scan.findings,
            notes=notes,
        )

    def _describe_findings(self, scan: ScanReport) -> list[str]:
        notes = []
        for finding in scan.findings:
            notes.append(f"{finding.severity}:{finding.line}:{finding.message}")
        return notes

    def heal_text(self, text: str) -> str:
        return text if text.endswith("\n") else f"{text}\n"

    def _restore_missing_target(self) -> list[str]:
        notes: list[str] = []
        latest_backup = self._latest_backup()
        if latest_backup is not None:
            restored = self._restore_backup(latest_backup)
            notes.append(f"restored {restored.name} from {latest_backup.name}")
            return notes

        self.target_path.parent.mkdir(parents=True, exist_ok=True)
        self.target_path.write_text("", encoding="utf-8")
        notes.append(f"initialized {self.target_path.name}")
        return notes

    def _latest_backup(self) -> Path | None:
        primary = self.backup_manager.latest_backup() if self.backup_manager is not None else None
        replica = (
            self.replica_backup_manager.latest_backup()
            if self.replica_backup_manager is not None
            else None
        )
        if primary is None:
            return replica
        if replica is None:
            return primary
        return max((primary, replica), key=lambda path: path.stat().st_mtime)

    def _restore_backup(self, backup: Path) -> Path:
        if self.backup_manager is not None and backup.is_relative_to(self.backup_manager.backup_dir):
            return self.backup_manager.restore_backup(backup, destination=self.target_path)
        if self.replica_backup_manager is not None and backup.is_relative_to(
            self.replica_backup_manager.backup_dir
        ):
            return self.replica_backup_manager.restore_backup(backup, destination=self.target_path)
        if self.backup_manager is not None:
            return self.backup_manager.restore_backup(backup, destination=self.target_path)
        if self.replica_backup_manager is not None:
            return self.replica_backup_manager.restore_backup(backup, destination=self.target_path)
        raise FileNotFoundError(backup)
