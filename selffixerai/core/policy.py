"""Runtime policy and filesystem layout for Sovereign Self-Fixer."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class RuntimePolicy:
    """Resolve runtime mode and on-disk paths from the environment."""

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
        return {"ghost": 10, "hybrid": 20, "online": 50}[self.mode]

    @property
    def scan_interval(self) -> float:
        return {"ghost": 5.0, "hybrid": 3.0, "online": 2.0}[self.mode]

    @property
    def replica_backup_dir(self) -> Path | None:
        if self.is_ghost:
            return None
        return self.base_dir / "replicas" / self.mode
