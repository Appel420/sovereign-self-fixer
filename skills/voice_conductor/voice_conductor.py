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
