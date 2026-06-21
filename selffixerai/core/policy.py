"""Runtime policy and filesystem layout for Sovereign Self-Fixer."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import ClassVar
from pathlib import Path


@dataclass(slots=True)
class RuntimePolicy:
    """Resolve runtime mode and on-disk paths from the environment."""

    _MODE_SETTINGS: ClassVar[dict[str, tuple[int, float, bool]]] = {
        "ghost": (10, 5.0, False),
        "hybrid": (20, 3.0, True),
        "online": (50, 2.0, True),
    }

    mode: str
    base_dir: Path

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
        return self._MODE_SETTINGS[self.mode][0]

    @property
    def scan_interval(self) -> float:
        return self._MODE_SETTINGS[self.mode][1]

    @property
    def replica_backup_dir(self) -> Path | None:
        if not self._MODE_SETTINGS[self.mode][2]:
            return None
        return self.base_dir / "replicas" / self.mode
