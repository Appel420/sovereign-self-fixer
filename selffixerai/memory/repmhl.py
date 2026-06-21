"""REPMHL memory store."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any


@dataclass(slots=True)
class MemoryTurn:
    role: str
    text: str
    timestamp: str
    metadata: dict[str, Any] = field(default_factory=dict)


class REPMHL:
    """Persist and retrieve interaction memory."""

    def __init__(self, storage_path: str | Path | None = None, max_turns: int = 5_000) -> None:
        self.storage_path = Path(storage_path) if storage_path else None
        self.max_turns = max_turns
        self.memory: list[MemoryTurn] = []
        self._lock = Lock()
        self._session_id = ""
        if self.storage_path and self.storage_path.exists():
            self._load()

    def start_session(self, session_id: str | None = None) -> str:
        self._session_id = session_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return self._session_id

    def add_turn(self, role: str, text: str, metadata: dict[str, Any] | None = None) -> MemoryTurn:
        turn = MemoryTurn(
            role=role,
            text=text,
            timestamp=datetime.now(timezone.utc).isoformat(),
            metadata=metadata or {},
        )
        with self._lock:
            self.memory.append(turn)
            self.memory = self.memory[-self.max_turns :]
        return turn

    def retrieve_relevant_memory(self, query: str, top_k: int = 5) -> list[MemoryTurn]:
        query_tokens = set(self._tokenize(query))
        scored: list[tuple[float, MemoryTurn]] = []
        for turn in self.memory:
            tokens = set(self._tokenize(turn.text))
            if not tokens:
                continue
            overlap = len(query_tokens & tokens)
            score = overlap / len(query_tokens | tokens) if query_tokens else 0.0
            if score:
                scored.append((score, turn))
        scored.sort(key=lambda item: item[0], reverse=True)
        return [turn for _, turn in scored[:top_k]]

    def shutdown(self) -> None:
        if not self.storage_path:
            return
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "session_id": self._session_id,
            "memory": [asdict(turn) for turn in self.memory],
        }
        self.storage_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _load(self) -> None:
        assert self.storage_path is not None
        payload = json.loads(self.storage_path.read_text(encoding="utf-8"))
        self._session_id = payload.get("session_id", "")
        self.memory = [MemoryTurn(**item) for item in payload.get("memory", [])]

@staticmethod
def _tokenize(text: str) -> list[str]:
    return re.findall(r"[a-z0-9']+", text.lower())
