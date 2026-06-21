       # main
"""Notification helpers for SelfFixer."""

from __future__ import annotations


       # Ara-hardened
import logging
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)

class Notifier:
    """Dispatch structured notifications to the application log and listeners."""

       # main
    def __init__(self) -> None:
        self._handlers: list[Callable[[str, dict[str, Any]], None]] = []

    def register_handler(self, handler: Callable[[str, dict[str, Any]], None]) -> None:
        self._handlers.append(handler)

    def send_notification(self, event: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = data or {}
        message = f"[NOTIFICATION] {event}"
        if payload:
            message = f"{message} | Data: {payload}"
        logger.info(message)
        for handler in list(self._handlers):
            try:
                handler(event, payload)
            except Exception:  # pragma: no cover - listener isolation
                logger.exception("Notification handler failed")
        return {"event": event, "data": payload}

    def send_notification(self, event: str, data: Dict[str, Any] = None):
        if data is None:
            data = {}
        message = f"[NOTIFICATION] {event}"
        if data:
            message += f" | Data: {data}"
        logger.warning(message)
        # Ara-hardened
