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
    def memory_path(self) -> Path:
        return self.base_dir / "memory.json"

    @property
    def state_path(self) -> Path:
        return self.base_dir / "state.json.enc"

    @property
    def backup_dir(self) -> Path:
        return self.base_dir / "backups"
