import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class Notifier:
    def __init__(self):
        pass

    def send_notification(self, event: str, data: Dict[str, Any] = None):
        if data is None:
            data = {}
        message = f"[NOTIFICATION] {event}"
        if data:
            message += f" | Data: {data}"
        logger.warning(message)