#!/usr/bin/env python3
"""Main entry point for Sovereign Self-Fixer."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import sys
from pathlib import Path

from selffixerai.analysis.deep_scanner import DeepScanner
from selffixerai.core.backup_manager import BackupManager
from selffixerai.core.policy import RuntimePolicy
from selffixerai.core.self_fixer import SelfFixer
from selffixerai.memory.repmhl import REPMHL
from selffixerai.notifications import Notifier
from selffixerai.security.tamper_lock import TamperHardLock
from skills.voice_conductor.voice_conductor import voice_conductor

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s")
logger = logging.getLogger(__name__)


async def main() -> None:
    """Run the service loop."""

    logger.info("Starting Sovereign Self-Fixer")

    target_file = Path(__file__).resolve()
    policy = RuntimePolicy.from_env()

    lock = TamperHardLock(code_file=target_file, state_file=policy.state_path)
    scanner = DeepScanner()
    notifier = Notifier()
    repmhl = REPMHL(storage_path=policy.memory_path)
    backup_manager = BackupManager(backup_dir=policy.backup_dir, retention=10)
    fixer = SelfFixer(
        lock=lock,
        scanner=scanner,
        notifier=notifier,
        memory=repmhl,
        backup_manager=backup_manager,
        target_path=target_file,
    )

    await voice_conductor.initialize()
    repmhl.start_session()

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop_event.set)

    try:
        await fixer.run(stop_event)
    except Exception:  # pragma: no cover - runtime guard
        logger.exception("Runtime error")
    finally:
        repmhl.shutdown()
        await voice_conductor.shutdown()
        logger.info("Shutdown complete")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Stopped by user")
    except Exception as exc:  # pragma: no cover - runtime guard
        logger.critical("Fatal: %s", exc)
        sys.exit(1)
