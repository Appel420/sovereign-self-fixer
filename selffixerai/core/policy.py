"""Runtime policy and filesystem layout for Sovereign Self-Fixer."""

from __future__ import annotations

import enum
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar, Final

DEFAULT_BASE_DIR: Final[Path] = Path.home() / ".local" / "share" / "sovereign-self-fixer"


class RuntimeMode(str, enum.Enum):
    """Explicit runtime execution profile."""

    GHOST = "ghost"
    HYBRID = "hybrid"
    ONLINE = "online"


@dataclass(slots=True)
class RuntimePolicy:
    """Resolve runtime mode and on-disk paths from the environment."""

    _MODE_SETTINGS: ClassVar[dict[str, dict[str, int | float | bool]]] = {
        "ghost": {
            "backup_retention": 10,
            "scan_interval": 5.0,
            "has_replica_backup": False,
        },
        "hybrid": {
            "backup_retention": 20,
            "scan_interval": 3.0,
            "has_replica_backup": True,
        },
        "online": {
            "backup_retention": 50,
            "scan_interval": 2.0,
            "has_replica_backup": True,
        },
    }

    mode: str
    base_dir: Path

    def __post_init__(self) -> None:
        if isinstance(self.mode, RuntimeMode):
            self.mode = self.mode.value
        if self.mode not in self._MODE_SETTINGS:
            raise ValueError(f"invalid runtime mode: {self.mode}")

    @classmethod
    def from_env(cls) -> "RuntimePolicy":
        mode = os.environ.get("SOVEREIGN_MODE", "ghost").strip().lower()
        if mode not in {"ghost", "hybrid", "online"}:
            mode = "ghost"

        base_dir = Path(
            os.environ.get(
                "SOVEREIGN_BASE_DIR",
                DEFAULT_BASE_DIR,
            )
        ).expanduser()
        base_dir.mkdir(parents=True, exist_ok=True)
        return cls(mode=mode, base_dir=base_dir)

    @property
    def is_ghost(self) -> bool:
        return self.mode == "ghost"

    @property
    def is_hybrid(self) -> bool:
        return self.mode == "hybrid"

    @property
    def is_online(self) -> bool:
        return self.mode == "online"

    @property
    def memory_path(self) -> Path:
        return self.base_dir / "memory.json"

    @property
    def state_path(self) -> Path:
        return self.base_dir / "state.json.enc"

    @property
    def backup_dir(self) -> Path:
        return self.base_dir / "backups"

    @property
    def backup_retention(self) -> int:
        return int(self._MODE_SETTINGS[self.mode]["backup_retention"])

    @property
    def scan_interval(self) -> float:
        return float(self._MODE_SETTINGS[self.mode]["scan_interval"])

    @property
    def replica_backup_dir(self) -> Path | None:
        if not bool(self._MODE_SETTINGS[self.mode]["has_replica_backup"]):
            return None
        return self.base_dir / "replicas" / self.mode


@dataclass(slots=True)
class NetworkPolicy:
    """Governs outbound network access."""

    allow_outbound: bool = False
    allowed_hosts: list[str] = field(default_factory=list)
    require_tls: bool = True


@dataclass(slots=True)
class StoragePolicy:
    """Governs local and cloud storage behavior."""

    allow_cloud: bool = False
    local_path: Path = field(default_factory=lambda: DEFAULT_BASE_DIR)
    retention_count: int = 10
    retention_days: int = 90


@dataclass(slots=True)
class CryptoPolicy:
    """Selects which algorithms are permitted for this mode."""

    profile: str = "sovereign-offline"
    symmetric_algo: str = "chacha20poly1305"
    hash_algo: str = "sha3_512"
    signing_algo: str = "ed25519"
    kem_algo: str = "none"
    allow_pqc: bool = False


@dataclass(slots=True)
class BackupPolicy:
    """Governs backup creation, encryption, signing, and retention."""

    enabled: bool = True
    encrypt: bool = True
    sign: bool = True
    retention_count: int = 10
    retention_days: int = 90


@dataclass(slots=True)
class LogPolicy:
    """Governs the immutable audit log."""

    enabled: bool = True
    append_only: bool = True
    hash_chain: bool = True
    sign_checkpoints: bool = True
    checkpoint_interval: int = 100
    log_path: Path | None = None


@dataclass(slots=True)
class SovereignPolicy:
    """Complete runtime policy for a selected mode."""

    mode: RuntimeMode = RuntimeMode.GHOST
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    storage: StoragePolicy = field(default_factory=StoragePolicy)
    crypto: CryptoPolicy = field(default_factory=CryptoPolicy)
    backup: BackupPolicy = field(default_factory=BackupPolicy)
    log: LogPolicy = field(default_factory=LogPolicy)

    @classmethod
    def for_mode(cls, mode: RuntimeMode) -> "SovereignPolicy":
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
                backup=BackupPolicy(enabled=True, encrypt=True, sign=True, retention_count=10),
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
                backup=BackupPolicy(enabled=True, encrypt=True, sign=True, retention_count=20),
                log=LogPolicy(enabled=True, hash_chain=True, sign_checkpoints=True),
            )
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
            backup=BackupPolicy(enabled=True, encrypt=True, sign=True, retention_count=50),
            log=LogPolicy(enabled=True, hash_chain=True, sign_checkpoints=True),
        )

    def enforce_network(self) -> None:
        if not self.network.allow_outbound:
            raise PermissionError(
                f"Runtime mode '{self.mode.value}' forbids outbound network access"
            )

    def to_dict(self) -> dict[str, object]:
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
    """Load, validate, and enforce sovereign runtime policy."""

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
        self._policy.enforce_network()

    @staticmethod
    def _load_from_file(policy_file: Path) -> SovereignPolicy:
        raw = json.loads(policy_file.read_text(encoding="utf-8"))
        try:
            mode = RuntimeMode(raw.get("mode", "ghost"))
        except ValueError:
            mode = RuntimeMode.GHOST
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
