"""Mode orchestrator — bootstraps and governs the service graph for a runtime mode.

The ``ModeOrchestrator`` is the first object constructed by ``main()``.  It
owns the ``PolicyEngine`` and acts as a factory/registry for all security-
critical services:

- ``encryption()``      — ``EncryptionManager`` (ChaCha20-Poly1305)
- ``audit_log()``       — ``ImmutableLog`` (hash-chained, signed checkpoints)
- ``backup_manager()``  — ``BackupManager`` (encrypted, signed, pruned)
- ``tamper_lock()``     — ``TamperHardLock`` (code-integrity seal)

Services are created lazily and cached.  Callers must use the orchestrator
as the single source of truth rather than constructing services directly.

Ghost mode
----------
- ``check_network_allowed()`` always raises ``PermissionError``.
- No cloud storage is configured.
- All services operate on the local filesystem only.

Hybrid mode
-----------
- Outbound network is allowed; cloud storage may be used.
- Cloud receives only encrypted blobs; the plaintext master key stays local.
- The local audit log remains canonical.

Online mode
-----------
- Full connectivity; AES-256-GCM replaces ChaCha20-Poly1305 for HW paths.
- Local policy is still canonical — the cloud is never authoritative.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from selffixerai.core.backup_manager import BackupManager
from selffixerai.core.immutable_log import ImmutableLog
from selffixerai.core.policy import DEFAULT_BASE_DIR, PolicyEngine, RuntimeMode, SovereignPolicy
from selffixerai.security.encryption import EncryptionManager
from selffixerai.security.tamper_lock import TamperHardLock

logger = logging.getLogger(__name__)


class ModeOrchestrator:
    """Bootstrap and govern the service graph for a given runtime mode.

    Parameters
    ----------
    mode:
        One of ``"ghost"``, ``"hybrid"``, or ``"online"``; or a
        ``RuntimeMode`` enum value.
    base_dir:
        Root directory for all local state.  Defaults to
        ``~/.local/share/sovereign-self-fixer``.
    policy:
        Supply an explicit ``SovereignPolicy`` to override the default
        for the selected mode.  Useful in tests.
    """

    def __init__(
        self,
        mode: RuntimeMode | str,
        base_dir: Path | None = None,
        policy: SovereignPolicy | None = None,
    ) -> None:
        if isinstance(mode, str):
            mode = RuntimeMode(mode)
        self.base_dir = base_dir or DEFAULT_BASE_DIR
        self.base_dir.mkdir(parents=True, exist_ok=True)

        _policy = policy or SovereignPolicy.for_mode(mode)
        self.policy_engine = PolicyEngine(policy=_policy)

        self._encryption: EncryptionManager | None = None
        self._audit_log: ImmutableLog | None = None
        self._backup_manager: BackupManager | None = None
        self._tamper_lock: TamperHardLock | None = None

        logger.info(
            "ModeOrchestrator initialized | mode=%s | base_dir=%s",
            self.mode.value,
            self.base_dir,
        )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def mode(self) -> RuntimeMode:
        return self.policy_engine.mode

    @property
    def policy(self) -> SovereignPolicy:
        return self.policy_engine.policy

    # ------------------------------------------------------------------
    # Service factories (lazy, cached)
    # ------------------------------------------------------------------

    def encryption(self) -> EncryptionManager:
        """Return the shared ``EncryptionManager`` for this runtime."""
        if self._encryption is None:
            self._encryption = EncryptionManager(key_path=self.base_dir / "master.key")
        return self._encryption

    def audit_log(self) -> ImmutableLog:
        """Return the shared ``ImmutableLog`` instance."""
        if self._audit_log is None:
            self._audit_log = ImmutableLog(
                log_path=self.base_dir / "audit.log.json",
                key_path=self.base_dir / "audit.ed25519",
                checkpoint_interval=self.policy.log.checkpoint_interval,
            )
        return self._audit_log

    def backup_manager(self) -> BackupManager:
        """Return the shared ``BackupManager`` instance."""
        if self._backup_manager is None:
            self._backup_manager = BackupManager(
                backup_dir=self.base_dir / "backups",
                encryption=self.encryption(),
                policy=self.policy.backup,
            )
        return self._backup_manager

    def tamper_lock(self, code_file: Path) -> TamperHardLock:
        """Return a ``TamperHardLock`` for *code_file*, cached after first call."""
        if self._tamper_lock is None:
            self._tamper_lock = TamperHardLock(
                code_file=code_file,
                state_file=self.base_dir / "state.json.enc",
                key_file=self.base_dir / "lock.ed25519",
            )
        return self._tamper_lock

    # ------------------------------------------------------------------
    # Policy enforcement helpers
    # ------------------------------------------------------------------

    def check_network_allowed(self) -> None:
        """Raise ``PermissionError`` if outbound networking is forbidden."""
        self.policy_engine.check_network()

    def log_event(
        self,
        event_type: str,
        actor: str = "runtime",
        data: dict[str, Any] | None = None,
    ) -> None:
        """Append an event to the immutable audit log (no-op if logging is off)."""
        if self.policy.log.enabled:
            self.audit_log().append(event_type, actor, data)
