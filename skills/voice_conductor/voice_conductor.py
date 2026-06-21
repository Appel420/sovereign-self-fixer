      # main
"""Voice conduit used by the runtime."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class VoiceEvent:
    message: str
    timestamp: str


class VoiceConductor:
    def __init__(self) -> None:
        self._ready = False
        self._events: list[VoiceEvent] = []

    async def initialize(self) -> None:
        self._ready = True
        logger.info("Voice conductor ready")

    async def announce(self, message: str) -> None:
        if not self._ready:
            await self.initialize()
        self._events.append(VoiceEvent(message=message, timestamp=datetime.now(timezone.utc).isoformat()))
        logger.info("VOICE: %s", message)
        await asyncio.sleep(0)

    async def shutdown(self) -> None:
        self._ready = False
        await asyncio.sleep(0)

    @property
    def ready(self) -> bool:
        return self._ready

    @property
    def events(self) -> list[VoiceEvent]:
        return list(self._events)


voice_conductor = VoiceConductor()

import asyncio
import logging
import subprocess
import os
from typing import Optional, Dict, Any
from pathlib import Path

def _get_self_fixer():
    try:
        from selffixerai.core.self_fixer import SelfFixer
        from selffixerai.security.tamper_lock import TamperHardLock
        return SelfFixer, TamperHardLock
    except ImportError:
        return None, None

class VoiceConductor:
    def __init__(self):
        self.lock = None
        self.fixer = None
        self.initialized = False
        self.command_history: list[str] = []

    async def initialize(self):
        if self.initialized:
            return
        SelfFixer, TamperHardLock = _get_self_fixer()
        if TamperHardLock:
            self.lock = TamperHardLock(code_file="state.code")
        if SelfFixer and self.lock:
            self.fixer = SelfFixer(lock=self.lock, scanner=None, notifier=None)
        self.initialized = True
        logging.info("[VoiceConductor] Initialized.")

    async def process_command(self, command: str) -> Dict[str, Any]:
        if not self.initialized:
            await self.initialize()
        cmd = command.lower().strip()
        self.command_history.append(cmd)
        if any(x in cmd for x in ["push", "github"]):
            return await self._push_to_github()
        return {"status": "ok", "message": f"Command processed: {command}"}

    async def _push_to_github(self):
        try:
            subprocess.run(["git", "add", "."], check=True, cwd=Path.cwd())
            subprocess.run(["git", "commit", "-m", "chore: voice conductor push"], capture_output=True, text=True, cwd=Path.cwd())
            push = subprocess.run(["git", "push", "origin", "Ara-hardened"], capture_output=True, text=True, cwd=Path.cwd())
            return {"status": "success" if push.returncode == 0 else "error", "message": push.stdout or push.stderr}
        except Exception as e:
            return {"status": "error", "message": str(e)}

voice_conductor = VoiceConductor()
       # Ara-hardened
