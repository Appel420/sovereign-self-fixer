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