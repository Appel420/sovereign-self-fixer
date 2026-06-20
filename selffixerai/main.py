import asyncio
import logging
from selffixerai.core.self_fixer import SelfFixer
from selffixerai.security.tamper_lock import TamperHardLock
from selffixerai.analysis.deep_scanner import DeepScanner
from selffixerai.notifications import Notifier
from skills.voice_conductor.voice_conductor import voice_conductor

async def main():
    logging.basicConfig(level=logging.INFO)
    logging.info("Starting Sovereign Self-Fixer (Ara-hardened)")

    await voice_conductor.initialize()

    lock = TamperHardLock(code_file="state.code")
    scanner = DeepScanner()
    notifier = Notifier()

    fixer = SelfFixer(lock=lock, scanner=scanner, notifier=notifier)
    stop_event = asyncio.Event()

    try:
        await fixer.run(stop_event)
    except KeyboardInterrupt:
        logging.info("Shutdown requested.")
        stop_event.set()

if __name__ == "__main__":
    asyncio.run(main())
