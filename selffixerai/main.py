#!/usr/bin/env python3
"""
Main entry point for Sovereign Self-Fixer (Ara-hardened)
"""

import asyncio
import logging
import signal
import sys

from selffixerai.core.self_fixer import SelfFixer
from selffixerai.security.tamper_lock import TamperHardLock
from selffixerai.analysis.deep_scanner import DeepScanner
from selffixerai.notifications import Notifier

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(name)s | %(message)s'
)
logger = logging.getLogger("main")


async def main():
    logger.info("Starting Sovereign Self-Fixer (Ara-hardened)")

    try:
        lock = TamperHardLock(code_file="state.code")
        scanner = DeepScanner()
        notifier = Notifier()

        fixer = SelfFixer(lock=lock, scanner=scanner, notifier=notifier)
    except Exception as e:
        logger.exception(f"Failed to initialize components: {e}")
        return

    stop_event = asyncio.Event()

    # Graceful shutdown
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop_event.set)

    try:
        await fixer.run(stop_event)
    except Exception as e:
        logger.exception(f"Error in main loop: {e}")
        stop_event.set()
    finally:
        logger.info("Shutdown complete.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Application stopped by user.")
    except Exception as e:
        logger.critical(f"Fatal error: {e}")
        sys.exit(1)