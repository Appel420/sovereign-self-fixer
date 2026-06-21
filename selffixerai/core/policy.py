"""Runtime policy and filesystem layout for Sovereign Self-Fixer."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar


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
                Path.home() / ".local" / "share" / "sovereign-self-fixer",
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
