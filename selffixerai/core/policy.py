"""Runtime policy engine — governs mode, networking, crypto, storage, and retention.

A ``SovereignPolicy`` is the canonical source of truth for what is allowed
at runtime.  It is loaded once by the ``PolicyEngine`` and never overridden
by remote control paths.  The cloud is never authoritative over policy.
"""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field
from pathlib import Path


class RuntimeMode(str, enum.Enum):
    """Explicit runtime execution profile."""

    GHOST = "ghost"    # fully offline / airgapped — zero outbound dependency
    HYBRID = "hybrid"  # local-first with encrypted cloud assistance
    ONLINE = "online"  # connected but still locally-sovereign


@dataclass
class NetworkPolicy:
    """Governs outbound network access."""

    allow_outbound: bool = False
    allowed_hosts: list[str] = field(default_factory=list)
    require_tls: bool = True


@dataclass
class StoragePolicy:
    """Governs local and cloud storage behavior."""

    allow_cloud: bool = False
    local_path: Path = field(
        default_factory=lambda: Path.home() / ".local" / "share" / "sovereign-self-fixer"
    )
    retention_count: int = 10
    retention_days: int = 90


@dataclass
class CryptoPolicy:
    """Selects which algorithms are permitted for this mode.

    Algorithm identifiers:
    - symmetric_algo: ``"chacha20poly1305"`` | ``"aes256gcm"``
    - hash_algo:      ``"sha3_512"`` | ``"sha256"``
    - signing_algo:   ``"ed25519"`` | ``"ml-dsa-87"``
    - kem_algo:       ``"none"`` | ``"ml-kem-768"``
    """

    profile: str = "sovereign-offline"
    symmetric_algo: str = "chacha20poly1305"
    hash_algo: str = "sha3_512"
    signing_algo: str = "ed25519"
    kem_algo: str = "none"
    allow_pqc: bool = False


@dataclass
class BackupPolicy:
    """Governs backup creation, encryption, signing, and retention."""

    enabled: bool = True
    encrypt: bool = True
    sign: bool = True
    retention_count: int = 10
    retention_days: int = 90


@dataclass
class LogPolicy:
    """Governs the immutable audit log."""

    enabled: bool = True
    append_only: bool = True
    hash_chain: bool = True
    sign_checkpoints: bool = True
    checkpoint_interval: int = 100  # entries between signed Merkle checkpoints
    log_path: Path | None = None


@dataclass
class SovereignPolicy:
    """Complete runtime policy.  Constructed once; never mutated by remote callers."""

    mode: RuntimeMode = RuntimeMode.GHOST
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    storage: StoragePolicy = field(default_factory=StoragePolicy)
    crypto: CryptoPolicy = field(default_factory=CryptoPolicy)
    backup: BackupPolicy = field(default_factory=BackupPolicy)
    log: LogPolicy = field(default_factory=LogPolicy)

    # ------------------------------------------------------------------
    # Factory constructors
    # ------------------------------------------------------------------

    @classmethod
    def for_mode(cls, mode: RuntimeMode) -> "SovereignPolicy":
        """Return a well-formed policy pre-configured for *mode*."""
        if mode == RuntimeMode.GHOST:
            return cls(
                mode=mode,
                network=NetworkPolicy(allow_outbound=False),
                storage=StoragePolicy(allow_cloud=False),
                crypto=CryptoPolicy(
                    profile="sovereign-offline",
                    symmetric_algo="chacha20poly1305",
                    hash_algo="sha3_512",
                    signing_algo="ed25519",
                    kem_algo="none",
                    allow_pqc=False,
                ),
                backup=BackupPolicy(enabled=True, encrypt=True, sign=True),
                log=LogPolicy(enabled=True, hash_chain=True, sign_checkpoints=True),
            )
        if mode == RuntimeMode.HYBRID:
            return cls(
                mode=mode,
                network=NetworkPolicy(allow_outbound=True, require_tls=True),
                storage=StoragePolicy(allow_cloud=True),
                crypto=CryptoPolicy(
                    profile="sovereign-hybrid",
                    symmetric_algo="chacha20poly1305",
                    hash_algo="sha3_512",
                    signing_algo="ed25519",
                    kem_algo="ml-kem-768",
                    allow_pqc=True,
                ),
                backup=BackupPolicy(enabled=True, encrypt=True, sign=True),
                log=LogPolicy(enabled=True, hash_chain=True, sign_checkpoints=True),
            )
        # ONLINE
        return cls(
            mode=mode,
            network=NetworkPolicy(allow_outbound=True, require_tls=True),
            storage=StoragePolicy(allow_cloud=True),
            crypto=CryptoPolicy(
                profile="sovereign-online",
                symmetric_algo="aes256gcm",
                hash_algo="sha3_512",
                signing_algo="ed25519",
                kem_algo="ml-kem-768",
                allow_pqc=True,
            ),
            backup=BackupPolicy(enabled=True, encrypt=True, sign=True),
            log=LogPolicy(enabled=True, hash_chain=True, sign_checkpoints=True),
        )

    # ------------------------------------------------------------------
    # Enforcement helpers
    # ------------------------------------------------------------------

    def enforce_network(self) -> None:
        """Raise ``PermissionError`` if outbound networking is forbidden."""
        if not self.network.allow_outbound:
            raise PermissionError(
                f"Runtime mode '{self.mode.value}' forbids outbound network access"
            )

    def to_dict(self) -> dict[str, object]:
        """Return a redacted summary safe to include in audit logs."""
        return {
            "mode": self.mode.value,
            "network": {"allow_outbound": self.network.allow_outbound},
            "crypto": {
                "profile": self.crypto.profile,
                "symmetric": self.crypto.symmetric_algo,
                "hash": self.crypto.hash_algo,
                "signing": self.crypto.signing_algo,
            },
            "backup": {
                "enabled": self.backup.enabled,
                "encrypt": self.backup.encrypt,
            },
        }


class PolicyEngine:
    """Load, validate, and enforce sovereign runtime policy.

    The policy engine is the single authoritative holder of the current
    ``SovereignPolicy``.  External services must query it rather than
    holding their own policy copies.
    """

    def __init__(
        self,
        policy: SovereignPolicy | None = None,
        policy_file: Path | None = None,
    ) -> None:
        if policy is not None:
            self._policy = policy
        elif policy_file is not None:
            self._policy = self._load_from_file(policy_file)
        else:
            self._policy = SovereignPolicy.for_mode(RuntimeMode.GHOST)

    @property
    def policy(self) -> SovereignPolicy:
        return self._policy

    @property
    def mode(self) -> RuntimeMode:
        return self._policy.mode

    def allow_network(self) -> bool:
        return self._policy.network.allow_outbound

    def allow_cloud(self) -> bool:
        return self._policy.storage.allow_cloud

    def check_network(self) -> None:
        """Raise if outbound networking is not allowed."""
        self._policy.enforce_network()

    @staticmethod
    def _load_from_file(policy_file: Path) -> SovereignPolicy:
        raw = json.loads(policy_file.read_text(encoding="utf-8"))
        mode = RuntimeMode(raw.get("mode", "ghost"))
        policy = SovereignPolicy.for_mode(mode)
        if "crypto" in raw:
            c = raw["crypto"]
            policy.crypto.symmetric_algo = c.get("symmetric_algo", policy.crypto.symmetric_algo)
            policy.crypto.hash_algo = c.get("hash_algo", policy.crypto.hash_algo)
            policy.crypto.signing_algo = c.get("signing_algo", policy.crypto.signing_algo)
            policy.crypto.kem_algo = c.get("kem_algo", policy.crypto.kem_algo)
        if "backup" in raw:
            b = raw["backup"]
            policy.backup.retention_count = b.get("retention_count", policy.backup.retention_count)
            policy.backup.retention_days = b.get("retention_days", policy.backup.retention_days)
        if "log" in raw:
            lg = raw["log"]
            policy.log.checkpoint_interval = lg.get(
                "checkpoint_interval", policy.log.checkpoint_interval
            )
        return policy
