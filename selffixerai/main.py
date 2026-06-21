#!/usr/bin/env python3
"""Main entry point for Sovereign Self-Fixer.

Runtime mode is selected via the ``SOVEREIGN_MODE`` environment variable:
- ``ghost``  (default) — fully offline / airgapped
- ``hybrid``           — local-first with encrypted cloud assistance
- ``online``           — connected but still locally-sovereign

The ``ModeOrchestrator`` is the first object constructed; it governs all
security-critical service creation for the selected mode.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
import sys
from pathlib import Path

from selffixerai.analysis.deep_scanner import DeepScanner
from selffixerai.core.orchestrator import ModeOrchestrator
from selffixerai.core.policy import RuntimeMode
from selffixerai.core.self_fixer import SelfFixer
from selffixerai.memory.repmhl import REPMHL
from selffixerai.notifications import Notifier
from skills.voice_conductor.voice_conductor import voice_conductor

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s")
logger = logging.getLogger(__name__)


def _resolve_mode() -> RuntimeMode:
    raw = os.environ.get("SOVEREIGN_MODE", "ghost").strip().lower()
    try:
        return RuntimeMode(raw)
    except ValueError:
        logger.warning("Unknown SOVEREIGN_MODE=%r — defaulting to ghost", raw)
        return RuntimeMode.GHOST


async def main() -> None:
    """Run the service loop."""
    mode = _resolve_mode()
    logger.info("Starting Sovereign Self-Fixer | mode=%s", mode.value)

    base_dir = Path.home() / ".local" / "share" / "sovereign-self-fixer"
    orchestrator = ModeOrchestrator(mode=mode, base_dir=base_dir)

    target_file = Path(__file__).resolve()
    memory_path = base_dir / "memory.json"

    lock = orchestrator.tamper_lock(code_file=target_file)
    backup_mgr = orchestrator.backup_manager()
    scanner = DeepScanner()
    notifier = Notifier()
    repmhl = REPMHL(storage_path=memory_path)

    fixer = SelfFixer(
        lock=lock,
        scanner=scanner,
        notifier=notifier,
        memory=repmhl,
        target_path=target_file,
        backup_manager=backup_mgr,
    )

    orchestrator.log_event("startup", data={"mode": mode.value, "version": "0.3.0"})

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
        orchestrator.log_event("shutdown", data={"mode": mode.value})
        orchestrator.audit_log().force_checkpoint()
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
