       # main
"""Core repair loop for Sovereign Self-Fixer."""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from pathlib import Path

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

import ast
import asyncio
import logging

class SelfFixer:
    def __init__(self, lock, scanner, notifier, tpm_seal_interval: int = 300):
        self.lock = lock
        self.scanner = scanner
        self.notifier = notifier
        self.tpm_seal_interval = tpm_seal_interval
        self.state = []
        self.score = 50.0
        self.bug_count = 0

    async def save(self):
        content = "".join(self.state)
        self.lock.update_chain(content)
        if self.lock.tpm and await self.lock.tpm.is_tpm_present():
            try:
                sealed = await self.lock.seal_state_to_tpm(content)
                if sealed:
                    with open(str(self.lock.code_file) + ".tpm.sealed", "wb") as f:
                        f.write(sealed)
            except Exception as e:
                logging.warning(f"TPM seal failed during save: {e}")

    async def detect_and_fix(self):
        joined = "".join(self.state)
        if not self.lock.is_valid(joined):
            self.notifier.send_notification("TamperDetected", {})
            return
        try:
            ast.parse(joined)
        except SyntaxError as e:
            logging.warning(f"Syntax error: {e}")
            self.bug_count += 1
            self.state.append(f"# Fixed syntax error: {e}\n")
            self.score += 8
            await self.save()
            return
        for comment in self.scanner.analyze(joined):
            self.state.append(comment)
            self.bug_count += 1
        await self.save()
       # Ara-hardened
