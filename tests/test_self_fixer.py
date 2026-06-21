from __future__ import annotations

import contextlib
import asyncio
from pathlib import Path

import pytest

from selffixerai.analysis.deep_scanner import DeepScanner
from selffixerai.core.backup_manager import BackupManager
from selffixerai.core.policy import RuntimePolicy
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


def test_backup_manager_round_trip(tmp_path: Path) -> None:
    source = tmp_path / "source.py"
    source.write_text("print('backup')\n", encoding="utf-8")
    backup_manager = BackupManager(backup_dir=tmp_path / "backups", encryption=EncryptionManager(key_path=tmp_path / "key.bin"))

    backup_path = backup_manager.create_backup(source)
    restored = backup_manager.restore_backup(backup_path, destination=tmp_path / "restored.py")

    assert restored.read_text(encoding="utf-8") == "print('backup')\n"


def test_self_fixer_scan_once(tmp_path: Path) -> None:
    target = tmp_path / "target.py"
    target.write_text("print('ok')\n", encoding="utf-8")
    lock = TamperHardLock(code_file=target, state_file=tmp_path / "state.enc", key_file=tmp_path / "lock.key")
    fixer = SelfFixer(
        lock=lock,
        scanner=DeepScanner(),
        notifier=Notifier(),
        memory=REPMHL(),
        backup_manager=BackupManager(backup_dir=tmp_path / "backups", encryption=EncryptionManager(key_path=tmp_path / "backup.key")),
        target_path=target,
    )
    report = fixer.scan_once()
    assert report.scanned
    assert report.changed is False
    assert lock.verify()
    assert any(note.startswith("backup ") for note in report.notes)


def test_self_fixer_restores_missing_target(tmp_path: Path) -> None:
    target = tmp_path / "target.py"
    target.write_text("print('restore me')\n", encoding="utf-8")

    backup_manager = BackupManager(
        backup_dir=tmp_path / "backups",
        encryption=EncryptionManager(key_path=tmp_path / "backup.key"),
    )
    backup_manager.create_backup(target)
    target.unlink()

    lock = TamperHardLock(code_file=target, state_file=tmp_path / "state.enc", key_file=tmp_path / "lock.key")
    fixer = SelfFixer(
        lock=lock,
        scanner=DeepScanner(),
        notifier=Notifier(),
        memory=REPMHL(),
        backup_manager=backup_manager,
        target_path=target,
    )
    report = fixer.scan_once()

    assert report.scanned and report.changed
    assert target.read_text(encoding="utf-8") == "print('restore me')\n"
    assert lock.verify()
    assert any(note.startswith("restored ") for note in report.notes)


def test_main_module_importable() -> None:
    import selffixerai

    assert selffixerai.__version__ == "0.3.0"


def test_runtime_policy_from_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOVEREIGN_MODE", "hybrid")
    monkeypatch.setenv("SOVEREIGN_BASE_DIR", str(tmp_path / "runtime"))

    policy = RuntimePolicy.from_env()

    assert policy.mode == "hybrid"
    assert policy.base_dir == tmp_path / "runtime"
    assert policy.memory_path == tmp_path / "runtime" / "memory.json"
    assert policy.state_path == tmp_path / "runtime" / "state.json.enc"
    assert policy.backup_dir == tmp_path / "runtime" / "backups"
    assert policy.backup_retention == 20
    assert policy.scan_interval == 3.0
    assert policy.replica_backup_dir == tmp_path / "runtime" / "replicas" / "hybrid"
    assert policy.is_hybrid
    assert not policy.is_ghost
    assert not policy.is_online


def test_runtime_policy_profiles(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOVEREIGN_BASE_DIR", str(tmp_path / "runtime"))

    monkeypatch.setenv("SOVEREIGN_MODE", "ghost")
    ghost_policy = RuntimePolicy.from_env()
    assert ghost_policy.replica_backup_dir is None
    assert ghost_policy.backup_retention == 10
    assert ghost_policy.scan_interval == 5.0

    monkeypatch.setenv("SOVEREIGN_MODE", "online")
    online_policy = RuntimePolicy.from_env()
    assert online_policy.replica_backup_dir == tmp_path / "runtime" / "replicas" / "online"
    assert online_policy.is_online
    assert not online_policy.is_ghost
    assert not online_policy.is_hybrid


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
