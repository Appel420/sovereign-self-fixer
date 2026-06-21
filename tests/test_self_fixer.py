       # main
from __future__ import annotations

import contextlib
import asyncio
from pathlib import Path

import pytest

from selffixerai.analysis.deep_scanner import DeepScanner
from selffixerai.core.self_fixer import SelfFixer
from selffixerai.memory.repmhl import REPMHL
from selffixerai.notifications import Notifier
from selffixerai.security.encryption import EncryptionManager
from selffixerai.security.tamper_lock import TamperHardLock


def test_encryption_round_trip(tmp_path: Path) -> None:
    manager = EncryptionManager(key_path=tmp_path / "key.bin")
    blob = manager.encrypt_bytes(b"hello world")
    assert manager.decrypt_bytes(blob) == b"hello world"


def test_scanner_finds_eval(tmp_path: Path) -> None:
    source = tmp_path / "bad.py"
    source.write_text("result = eval('1 + 1')\n", encoding="utf-8")
    report = DeepScanner().scan_file(source)
    assert report.has_findings
    assert any("Unsafe call" in finding.message for finding in report.findings)


def test_memory_retrieval(tmp_path: Path) -> None:
    memory = REPMHL(storage_path=tmp_path / "memory.json")
    memory.start_session("session-1")
    memory.add_turn("user", "repair the parser")
    memory.add_turn("assistant", "parser repaired")
    assert any(turn.text == "repair the parser" for turn in memory.retrieve_relevant_memory("parser"))
    memory.shutdown()
    assert (tmp_path / "memory.json").exists()


def test_self_fixer_scan_once(tmp_path: Path) -> None:
    target = tmp_path / "target.py"
    target.write_text("print('ok')\n", encoding="utf-8")
    lock = TamperHardLock(code_file=target, state_file=tmp_path / "state.enc", key_file=tmp_path / "lock.key")
    fixer = SelfFixer(lock=lock, scanner=DeepScanner(), notifier=Notifier(), memory=REPMHL(), target_path=target)
    report = fixer.scan_once()
    assert report.scanned
    assert report.changed is False
    assert lock.verify()


def test_main_module_importable() -> None:
    import selffixerai

    assert selffixerai.__version__ == "0.2.0"


def test_async_main_entrypoint_smoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)

    from selffixerai.main import main

    async def runner() -> None:
        stop = asyncio.Event()
        task = asyncio.create_task(main())
        await asyncio.sleep(0.1)
        stop.set()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    asyncio.run(runner())

full tests with docstrings
       # Ara-hardened
