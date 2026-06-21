"""Core repair loop for Sovereign Self-Fixer."""

from __future__ import annotations

import asyncio
from dataclasses import asdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from selffixerai.analysis.deep_scanner import DeepScanner, Finding, ScanReport
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
        target_path: str | Path | None = None,
        scan_interval: float = 5.0,
    ) -> None:
        self.lock = lock
        self.scanner = scanner
        self.notifier = notifier
        self.memory = memory
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
        if not self.target_path.exists():
            report = RepairReport(path=str(self.target_path), scanned=False, changed=False)
            self.notifier.send_notification("scan_skipped", {"path": report.path})
            return report

        scan = self.scanner.scan_file(self.target_path)
        changed = False
        notes: list[str] = []

        if not scan.has_findings:
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
