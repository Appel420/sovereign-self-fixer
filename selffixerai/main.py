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
from selffixerai.memory.repmhl import REPMHL
from skills.voice_conductor.voice_conductor import voice_conductor

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s')
logger = logging.getLogger("main")

async def main():
    logger.info("Starting Sovereign Self-Fixer")

    try:
        lock = TamperHardLock(code_file="state.code")
        scanner = DeepScanner()
        notifier = Notifier()
        fixer = SelfFixer(lock=lock, scanner=scanner, notifier=notifier)

        repmhl = REPMHL()
        await voice_conductor.initialize()
        repmhl.start_session()

    except Exception as e:
        logger.exception(f"Initialization failed: {e}")
        return

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop_event.set)

    try:
        await fixer.run(stop_event)
    except Exception as e:
        logger.exception(f"Runtime error: {e}")
    finally:
        repmhl.shutdown()
        logger.info("Shutdown complete")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Stopped by user")
    except Exception as e:
        logger.critical(f"Fatal: {e}")
        sys.exit(1)
