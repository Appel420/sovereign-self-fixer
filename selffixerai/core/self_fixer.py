import os
import ast
import logging
import asyncio
from .backup_manager import filelock
from ..security.tamper_lock import TamperHardLock
from ..analysis.deep_scanner import DeepScanner
from ..notifications import Notifier

class SelfFixer:
    def __init__(self, lock: TamperHardLock, scanner: DeepScanner, notifier: Notifier):
        self.lock = lock
        self.scanner = scanner
        self.notifier = notifier
        self.state: list[str] = []
        self.score = 50.0
        self.bug_count = 0

    async def load_state(self) -> list[str]:
        # Layered recovery logic (simplified for push)
        if os.path.exists(self.lock.code_file):
            try:
                with filelock(), open(self.lock.code_file, "rb") as f:
                    encrypted = f.read()
                content = self.lock.cryptor.decrypt(encrypted)
                return [line if line.endswith("\n") else line + "\n" for line in content.splitlines()]
            except Exception:
                pass
        return ["print('I am alive.')\n"]

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
                logging.warning(f"TPM seal failed: {e}")

    async def detect_and_fix(self):
        joined = "".join(self.state)
        if not self.lock.is_valid(joined):
            self.notifier.send_notification("TamperDetected", {})
            return
        try:
            ast.parse(joined)
        except SyntaxError as e:
            self.state.append(f"# Fixed syntax error: {e}\n")
            await self.save()
            return
        for comment in self.scanner.analyze(joined):
            self.state.append(comment)
        await self.save()

    async def run(self, stop_event: asyncio.Event):
        self.state = await self.load_state()
        while not stop_event.is_set():
            await self.detect_and_fix()
            await asyncio.sleep(1.5)
