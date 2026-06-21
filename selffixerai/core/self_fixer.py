import os
import ast
import logging
import asyncio
from .backup_manager import filelock
from ..security.tamper_lock import TamperHardLock
from ..analysis.deep_scanner import DeepScanner
from ..notifications import Notifier

class SelfFixer:
    def __init__(self, lock, scanner, notifier):
        self.lock = lock
        self.scanner = scanner
        self.notifier = notifier
        self.state = []
        self.score = 50.0
        self.bug_count = 0

    async def load_state(self):
        # Layered recovery logic here
        return []

    async def save(self):
        content = "".join(self.state)
        self.lock.update_chain(content)
        if self.lock.tpm and await self.lock.tpm.is_tpm_present():
            try:
                sealed = await self.lock.seal_state_to_tpm(content)
                if sealed:
                    sealed_path = str(self.lock.code_file) + ".tpm.sealed"
                    with open(sealed_path, "wb") as f:
                        f.write(sealed)
            except Exception as e:
                logging.warning(f"TPM seal failed: {e}")

    async def detect_and_fix(self):
        joined = "".join(self.state)
        if not self.lock.is_valid(joined):
            self.notifier.send_notification("TamperDetected", {})
            return
        try:
            ast.parse(joined)
        except SyntaxError as e:
            self.bug_count += 1
            self.state.append(f"# Fixed syntax error: {e}\n")
            await self.save()
            return
        for comment in self.scanner.analyze(joined):
            self.state.append(comment)
            self.bug_count += 1
        await self.save()

    async def run(self, stop_event):
        self.state = await self.load_state()
        while not stop_event.is_set():
            await self.detect_and_fix()
            await asyncio.sleep(1.5)