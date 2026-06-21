from typing import Any, Dict

import logging


class Notifier:
    """Real notification handler for SelfFixer."""

    def __init__(self, log_level: str = "INFO"):
        self.logger = logging.getLogger("selffixerai.notifier")
        self.logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    def send_notification(self, event: str, data: Dict[str, Any]):
        self.logger.warning(f"[NOTIFY] {event}: {data}")

    def info(self, msg: str):
        self.logger.info(msg)

    def error(self, msg: str):
        self.logger.error(msg)