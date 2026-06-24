"""Tests for Sovereign Self-Fixer — core runtime, security, and policy subsystems."""

from __future__ import annotations

import asyncio
import contextlib
import json
from pathlib import Path

import pytest

from selffixerai.analysis.deep_scanner import DeepScanner
from selffixerai.core.backup_manager import BackupManager
from selffixerai.core.immutable_log import ImmutableLog
from selffixerai.core.orchestrator import ModeOrchestrator
from selffixerai.core.policy import (
    BackupPolicy,
    PolicyEngine,
    RuntimeMode,
    RuntimePolicy,
    SovereignPolicy,
)
from selffixerai.core.self_fixer import SelfFixer
from selffixerai.crypto.profiles import get_profile, hash_bytes
from selffixerai.memory.repmhl import REPMHL
from selffixerai.notifications import Notifier
from selffixerai.security.encryption import EncryptionError, EncryptionManager
from selffixerai.security.tamper_lock import TamperHardLock

# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------


def test_encryption_round_trip(tmp_path: Path) -> None:
    manager = EncryptionManager(key_path=tmp_path / "key.bin")
    blob = manager.encrypt_bytes(b"hello world")
    assert manager.decrypt_bytes(blob) == b"hello world"


def test_encryption_with_associated_data(tmp_path: Path) -> None:
    manager = EncryptionManager(key_path=tmp_path / "key.bin")
    aad = b"context-label"
    blob = manager.encrypt_bytes(b"secret", associated_data=aad)
    assert manager.decrypt_bytes(blob, associated_data=aad) == b"secret"


def test_encryption_wrong_key_raises(tmp_path: Path) -> None:
    enc1 = EncryptionManager(key_path=tmp_path / "k1.bin")
    enc2 = EncryptionManager(key_path=tmp_path / "k2.bin")
    blob = enc1.encrypt_bytes(b"data")
    with pytest.raises(EncryptionError):
        enc2.decrypt_bytes(blob)


# ---------------------------------------------------------------------------
# Static scanner
# ---------------------------------------------------------------------------


def test_scanner_finds_eval(tmp_path: Path) -> None:
    source = tmp_path / "bad.py"
    source.write_text("result = eval('1 + 1')\n", encoding="utf-8")
    report = DeepScanner().scan_file(source)
    assert report.has_findings
    assert any("Unsafe call" in f.message for f in report.findings)


def test_scanner_clean_file(tmp_path: Path) -> None:
    source = tmp_path / "ok.py"
    source.write_text("print('hello')\n", encoding="utf-8")
    report = DeepScanner().scan_file(source)
    assert not report.has_findings


# ---------------------------------------------------------------------------
# Memory / REPMHL
# ---------------------------------------------------------------------------


def test_memory_retrieval(tmp_path: Path) -> None:
    memory = REPMHL(storage_path=tmp_path / "memory.json")
    memory.start_session("session-1")
    memory.add_turn("user", "repair the parser")
    memory.add_turn("assistant", "parser repaired")
    assert any(t.text == "repair the parser" for t in memory.retrieve_relevant_memory("parser"))
    memory.shutdown()
    assert (tmp_path / "memory.json").exists()


# ---------------------------------------------------------------------------
# TamperHardLock
# ---------------------------------------------------------------------------


def test_tamper_lock_seal_and_verify(tmp_path: Path) -> None:
    target = tmp_path / "target.py"
    target.write_text("print('ok')\n", encoding="utf-8")
    lock = TamperHardLock(
        code_file=target,
        state_file=tmp_path / "state.enc",
        key_file=tmp_path / "lock.key",
    )
    snap = lock.seal()
    assert snap.code_hash
    assert lock.verify()


def test_tamper_lock_detects_modification(tmp_path: Path) -> None:
    target = tmp_path / "target.py"
    target.write_text("x = 1\n", encoding="utf-8")
    lock = TamperHardLock(
        code_file=target,
        state_file=tmp_path / "state.enc",
        key_file=tmp_path / "lock.key",
    )
    lock.seal()
    target.write_text("x = 999\n", encoding="utf-8")
    assert not lock.verify()


# ---------------------------------------------------------------------------
# SelfFixer
# ---------------------------------------------------------------------------


def test_self_fixer_scan_once(tmp_path: Path) -> None:
    target = tmp_path / "target.py"
    target.write_text("print('ok')\n", encoding="utf-8")
    lock = TamperHardLock(
        code_file=target,
        state_file=tmp_path / "state.enc",
        key_file=tmp_path / "lock.key",
    )
    fixer = SelfFixer(
        lock=lock,
        scanner=DeepScanner(),
        notifier=Notifier(),
        memory=REPMHL(),
        backup_manager=BackupManager(
            backup_dir=tmp_path / "backups",
            encryption=EncryptionManager(key_path=tmp_path / "backup.key"),
        ),
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

    lock = TamperHardLock(
        code_file=target,
        state_file=tmp_path / "state.enc",
        key_file=tmp_path / "lock.key",
    )
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


def test_self_fixer_scan_missing_file(tmp_path: Path) -> None:
    target = tmp_path / "missing.py"
    lock = TamperHardLock(
        code_file=target,
        state_file=tmp_path / "state.enc",
        key_file=tmp_path / "lock.key",
    )
    fixer = SelfFixer(lock=lock, scanner=DeepScanner(), notifier=Notifier(), target_path=target)
    report = fixer.scan_once()
    assert not report.scanned


# ---------------------------------------------------------------------------
# BackupManager
# ---------------------------------------------------------------------------


def test_backup_round_trip(tmp_path: Path) -> None:
    mgr = BackupManager(backup_dir=tmp_path / "backups")
    payload = b"sovereign state snapshot v1"
    manifest_path = mgr.create_backup(payload, label="test")
    assert manifest_path.exists()
    restored = mgr.restore_backup(manifest_path)
    assert restored == payload


def test_backup_manifest_signed(tmp_path: Path) -> None:
    mgr = BackupManager(
        backup_dir=tmp_path / "backups",
        policy=BackupPolicy(encrypt=True, sign=True),
    )
    manifest_path = mgr.create_backup(b"data", label="signed")
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert raw["signature"]


def test_backup_unsigned_still_verifies(tmp_path: Path) -> None:
    mgr = BackupManager(
        backup_dir=tmp_path / "backups",
        policy=BackupPolicy(encrypt=True, sign=False),
    )
    payload = b"unsigned data"
    manifest_path = mgr.create_backup(payload)
    assert mgr.restore_backup(manifest_path) == payload


def test_backup_retention_prunes(tmp_path: Path) -> None:
    mgr = BackupManager(
        backup_dir=tmp_path / "backups",
        policy=BackupPolicy(retention_count=2, sign=False),
    )
    for i in range(5):
        mgr.create_backup(f"snap {i}".encode())
    remaining = mgr.list_backups()
    assert len(remaining) == 2


def test_backup_blob_tamper_detected(tmp_path: Path) -> None:
    mgr = BackupManager(backup_dir=tmp_path / "backups")
    manifest_path = mgr.create_backup(b"original")
    blobs = list((tmp_path / "backups").glob("*.blob"))
    assert blobs
    blobs[0].write_bytes(b"corrupted")
    with pytest.raises(ValueError, match="Blob integrity check failed"):
        mgr.restore_backup(manifest_path)


def test_backup_no_encryption(tmp_path: Path) -> None:
    mgr = BackupManager(
        backup_dir=tmp_path / "backups",
        policy=BackupPolicy(encrypt=False, sign=False),
    )
    payload = b"plaintext backup"
    manifest_path = mgr.create_backup(payload)
    assert mgr.restore_backup(manifest_path) == payload


# ---------------------------------------------------------------------------
# ImmutableLog
# ---------------------------------------------------------------------------


def test_immutable_log_chain_valid(tmp_path: Path) -> None:
    log = ImmutableLog(log_path=tmp_path / "audit.log.json", checkpoint_interval=50)
    log.append("startup", "runtime", {"mode": "ghost"})
    log.append("scan", "scanner", {"findings": 0})
    log.append("seal", "tamper_lock", {})
    assert log.verify_chain()


def test_immutable_log_genesis(tmp_path: Path) -> None:
    log = ImmutableLog(log_path=tmp_path / "audit.log.json")
    assert log.verify_chain()


def test_immutable_log_tamper_detected(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.log.json"
    log = ImmutableLog(log_path=log_path, checkpoint_interval=50)
    log.append("startup", "runtime")
    log.append("scan", "scanner", {"ok": True})
    raw = json.loads(log_path.read_text(encoding="utf-8"))
    raw["entries"][1]["data"]["ok"] = False
    log_path.write_text(json.dumps(raw), encoding="utf-8")
    log2 = ImmutableLog(log_path=log_path, checkpoint_interval=50)
    assert not log2.verify_chain()


def test_immutable_log_checkpoint(tmp_path: Path) -> None:
    log = ImmutableLog(log_path=tmp_path / "audit.log.json", checkpoint_interval=3)
    for i in range(3):
        log.append("event", "test", {"i": i})
    assert log.checkpoint_count == 1


def test_immutable_log_force_checkpoint(tmp_path: Path) -> None:
    log = ImmutableLog(log_path=tmp_path / "audit.log.json", checkpoint_interval=100)
    log.append("startup", "runtime")
    cp = log.force_checkpoint()
    assert cp is not None
    assert cp.merkle_root


def test_immutable_log_persists(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.log.json"
    log = ImmutableLog(log_path=log_path, checkpoint_interval=50)
    log.append("startup", "runtime")
    log2 = ImmutableLog(log_path=log_path, checkpoint_interval=50)
    assert log2.entry_count == 1
    assert log2.verify_chain()


# ---------------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------------


def test_policy_ghost_forbids_network() -> None:
    policy = SovereignPolicy.for_mode(RuntimeMode.GHOST)
    assert not policy.network.allow_outbound
    with pytest.raises(PermissionError):
        policy.enforce_network()


def test_policy_hybrid_allows_network() -> None:
    policy = SovereignPolicy.for_mode(RuntimeMode.HYBRID)
    assert policy.network.allow_outbound
    policy.enforce_network()


def test_policy_online_allows_network() -> None:
    policy = SovereignPolicy.for_mode(RuntimeMode.ONLINE)
    assert policy.network.allow_outbound
    policy.enforce_network()


def test_policy_ghost_no_cloud() -> None:
    policy = SovereignPolicy.for_mode(RuntimeMode.GHOST)
    assert not policy.storage.allow_cloud


def test_policy_engine_mode() -> None:
    engine = PolicyEngine(policy=SovereignPolicy.for_mode(RuntimeMode.HYBRID))
    assert engine.mode == RuntimeMode.HYBRID
    assert engine.allow_network()
    assert engine.allow_cloud()


def test_policy_engine_ghost_check_network_raises() -> None:
    engine = PolicyEngine(policy=SovereignPolicy.for_mode(RuntimeMode.GHOST))
    with pytest.raises(PermissionError):
        engine.check_network()


def test_policy_load_from_file(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps({"mode": "hybrid"}), encoding="utf-8")
    engine = PolicyEngine(policy_file=policy_file)
    assert engine.mode == RuntimeMode.HYBRID


def test_policy_to_dict_no_secrets() -> None:
    policy = SovereignPolicy.for_mode(RuntimeMode.GHOST)
    d = policy.to_dict()
    assert "key" not in str(d).lower()
    assert d["mode"] == "ghost"


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


# ---------------------------------------------------------------------------
# Crypto profiles
# ---------------------------------------------------------------------------


def test_crypto_profile_ghost() -> None:
    p = get_profile("sovereign-offline")
    assert p.symmetric == "chacha20poly1305"
    assert p.kem == "none"
    assert not p.allow_pqc


def test_crypto_profile_hybrid() -> None:
    p = get_profile("sovereign-hybrid")
    assert p.kem == "ml-kem-768"
    assert p.allow_pqc


def test_crypto_profile_online() -> None:
    p = get_profile("sovereign-online")
    assert p.symmetric == "aes256gcm"


def test_crypto_profile_unknown_raises() -> None:
    with pytest.raises(ValueError, match="Unknown crypto profile"):
        get_profile("bogus-profile")


def test_hash_bytes_sha3_512() -> None:
    digest = hash_bytes(b"data", algo="sha3_512")
    assert len(digest) == 128


def test_hash_bytes_sha256() -> None:
    digest = hash_bytes(b"data", algo="sha256")
    assert len(digest) == 64


def test_hash_bytes_unknown_raises() -> None:
    with pytest.raises(ValueError, match="Unsupported hash algorithm"):
        hash_bytes(b"x", algo="md5")


# ---------------------------------------------------------------------------
# ModeOrchestrator
# ---------------------------------------------------------------------------


def test_orchestrator_ghost_mode(tmp_path: Path) -> None:
    orch = ModeOrchestrator(mode="ghost", base_dir=tmp_path)
    assert orch.mode == RuntimeMode.GHOST
    with pytest.raises(PermissionError):
        orch.check_network_allowed()


def test_orchestrator_hybrid_mode(tmp_path: Path) -> None:
    orch = ModeOrchestrator(mode="hybrid", base_dir=tmp_path)
    assert orch.mode == RuntimeMode.HYBRID
    orch.check_network_allowed()


def test_orchestrator_online_mode(tmp_path: Path) -> None:
    orch = ModeOrchestrator(mode="online", base_dir=tmp_path)
    assert orch.mode == RuntimeMode.ONLINE
    orch.check_network_allowed()


def test_orchestrator_services_created(tmp_path: Path) -> None:
    orch = ModeOrchestrator(mode="ghost", base_dir=tmp_path)
    enc = orch.encryption()
    assert enc is not None
    assert orch.encryption() is enc


def test_orchestrator_log_event(tmp_path: Path) -> None:
    orch = ModeOrchestrator(mode="ghost", base_dir=tmp_path)
    orch.log_event("startup", data={"mode": "ghost"})
    assert orch.audit_log().entry_count == 1


def test_orchestrator_backup_round_trip(tmp_path: Path) -> None:
    orch = ModeOrchestrator(mode="ghost", base_dir=tmp_path)
    mgr = orch.backup_manager()
    payload = b"orchestrated backup payload"
    manifest_path = mgr.create_backup(payload, label="orch_test")
    restored = mgr.restore_backup(manifest_path)
    assert restored == payload


def test_orchestrator_invalid_mode() -> None:
    with pytest.raises(ValueError):
        ModeOrchestrator(mode="phantom")


# ---------------------------------------------------------------------------
# Package metadata
# ---------------------------------------------------------------------------


def test_main_module_importable() -> None:
    import selffixerai

    assert selffixerai.__version__ == "0.3.0"


# ---------------------------------------------------------------------------
# Async smoke test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_main_entrypoint_smoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SOVEREIGN_MODE", "ghost")
    base_dir = tmp_path / "sov"

    monkeypatch.setenv("SOVEREIGN_BASE_DIR", str(base_dir))
    base_dir.mkdir(parents=True, exist_ok=True)

    from selffixerai.main import main

    task = asyncio.create_task(main())
    await asyncio.sleep(0.15)
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task

    audit_log_files = list(base_dir.glob("audit.log.json"))
    assert audit_log_files, "Expected audit log to be written during startup"
    raw = json.loads(audit_log_files[0].read_text(encoding="utf-8"))
    event_types = [e["event_type"] for e in raw.get("entries", [])]
    assert "startup" in event_types, f"Expected 'startup' in audit events; got {event_types}"
