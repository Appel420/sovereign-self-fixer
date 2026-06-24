"""Production REPMHL memory store.

REPMHL = Resilient Engine for Persistent Memory Hydration Layer.

This module is intentionally local-first. Optional vector search is enabled only when
``sentence-transformers`` and ``faiss-cpu`` are installed. The default path remains
fully offline, deterministic, and dependency-light.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any

try:  # pragma: no cover - optional dependency
    import faiss  # type: ignore[import-not-found]
    import numpy as np

    FAISS_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    faiss = None
    np = None
    FAISS_AVAILABLE = False

logger = logging.getLogger(__name__)

DEFAULT_CONFIG: dict[str, Any] = {
    "base_max_tokens": 8_000,
    "force_rotation_every": 12_000,
    "warning_threshold_percent": 80,
    "auto_extend_amount": 2_000,
    "memory_persist_turns": 5_000,
    "hydration_timeout_minutes": 240,
    "user_learning_enabled": True,
    "max_text_chars": 4_000,
    "model_chain": [
        {"name": "sovereign-local-primary", "provider": "local"},
        {"name": "sovereign-local-fallback", "provider": "local"},
    ],
}


@dataclass(slots=True)
class MemoryTurn:
    role: str
    text: str
    timestamp: str
    metadata: dict[str, Any] = field(default_factory=dict)
    model: str = "sovereign-local-primary"
    tokens: int = 0
    importance: float = 0.5
    user_feedback: Any | None = None
    embedding: list[float] | None = None


@dataclass(slots=True)
class UserLearningProfile:
    preferences: dict[str, Any] = field(default_factory=dict)
    corrections: list[Any] = field(default_factory=list)
    medical_context: dict[str, Any] = field(default_factory=dict)
    tone_profile: dict[str, Any] = field(default_factory=dict)
    total_turns: int = 0
    last_updated: str = ""


class REPMHL:
    """Persist and retrieve memory with optional FAISS-backed semantic search.

    The public API is backward-compatible with the existing service:
    ``start_session()``, ``add_turn()``, ``retrieve_relevant_memory()``, and
    ``shutdown()``. It also accepts the richer ``process_turn()`` flow used by the
    standalone REPMHL engine.
    """

    def __init__(
        self,
        storage_path: str | Path | None = None,
        max_turns: int | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        self.config = {**DEFAULT_CONFIG, **(config or {})}
        self.max_turns = int(max_turns or self.config["memory_persist_turns"])
        self.storage_path = Path(storage_path) if storage_path else self._default_storage_path()
        self.base_dir = self.storage_path.parent
        self.profile_path = self.base_dir / "user_learning_profile.json"
        self.faiss_index_path = self.base_dir / "memory_index.faiss"

        self.memory: list[MemoryTurn] = []
        self.profile = UserLearningProfile(last_updated=self._now())
        self._lock = RLock()
        self._session_id = ""
        self._active = False
        self._embedding_model: Any | None | bool = None
        self._faiss_index: Any | None = None
        self._faiss_memory_indices: list[int] = []
        self.current_model_index = 0
        self.token_count = 0
        self.max_tokens = int(self.config["base_max_tokens"])

        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._load()
        self._load_profile()
        self._rebuild_faiss_index()

    @property
    def session_id(self) -> str:
        return self._session_id

    def start_session(self, session_id: str | None = None) -> str:
        with self._lock:
            self._session_id = session_id or f"repmhl-{int(time.time())}"
            self._active = True
            self._save()
            return self._session_id

    def add_turn(self, role: str, text: str, metadata: dict[str, Any] | None = None) -> MemoryTurn:
        tokens = self._estimate_tokens(text)
        return self._append_turn(role=role, text=text, tokens=tokens, metadata=metadata or {})

    def process_turn(
        self,
        tokens: int,
        text: str,
        role: str = "user",
        feedback: Any | None = None,
    ) -> dict[str, Any]:
        if not self._active:
            raise RuntimeError("REPMHL session not active")

        self.token_count += int(tokens)
        turn = self._append_turn(role=role, text=text, tokens=tokens, feedback=feedback)
        rotation_triggered = False

        if self.token_count >= self.max_tokens or self.token_count >= int(self.config["force_rotation_every"]):
            self._rotate_model()
            rotation_triggered = True
        elif (self.token_count / max(self.max_tokens, 1)) * 100 >= int(self.config["warning_threshold_percent"]):
            self.max_tokens += int(self.config["auto_extend_amount"])
            self._save()

        return {"status": "processed", "rotation_triggered": rotation_triggered, "turn": asdict(turn)}

    def retrieve_relevant_memory(self, query: str, top_k: int = 5) -> list[MemoryTurn]:
        with self._lock:
            if not self.memory:
                return []
            vector_results = self._semantic_search(query=query, top_k=top_k)
            if vector_results:
                return vector_results
            return self._lexical_search(query=query, top_k=top_k)

    def prune_memory(self, max_turns: int | None = None) -> None:
        max_turns = int(max_turns or self.max_turns)
        with self._lock:
            if len(self.memory) <= max_turns:
                return

            now = datetime.now(timezone.utc)
            scored: list[tuple[float, MemoryTurn]] = []
            for turn in self.memory:
                try:
                    ts = datetime.fromisoformat(turn.timestamp.replace("Z", "+00:00"))
                    age_hours = max((now - ts).total_seconds() / 3600, 0.0)
                    recency = max(0.0, 1.0 - (age_hours / (24 * 30)))
                except Exception:
                    recency = 0.5
                score = (float(turn.importance) * 0.65) + (recency * 0.35)
                scored.append((score, turn))

            scored.sort(key=lambda item: item[0], reverse=True)
            kept = [turn for _, turn in scored[:max_turns]]
            self.memory = sorted(self._dedupe_semantic(kept), key=lambda turn: turn.timestamp)
            self._rebuild_faiss_index()
            self._save()

    def get_context(self, max_turns: int = 69) -> str:
        with self._lock:
            recent = self.memory[-max_turns:]
            return "\n".join(f"{turn.role.title()}: {turn.text}" for turn in recent)

    def get_system_prompt(self) -> str:
        base = "You are a highly intelligent, direct, and helpful assistant."
        if self.profile.tone_profile.get("politeness", 0) > 0.3:
            base += " Speak in a polite and respectful tone."
        if self.profile.medical_context.get("focus") == "clinical":
            base += " You are in a medical context. Be precise and cautious."
        return base

    def end_session(self) -> None:
        with self._lock:
            self._active = False
            self._save()

    def shutdown(self) -> None:
        with self._lock:
            self._active = False
            self._save()
            self._save_profile()
            self._save_faiss_index()

    def _append_turn(
        self,
        role: str,
        text: str,
        tokens: int,
        metadata: dict[str, Any] | None = None,
        feedback: Any | None = None,
    ) -> MemoryTurn:
        clean_text = self._sanitize_text(text)
        importance = self._importance(clean_text, tokens)
        turn = MemoryTurn(
            role=role,
            text=clean_text,
            timestamp=self._now(),
            metadata=metadata or {},
            model=self._current_model()["name"],
            tokens=int(tokens),
            importance=importance,
            user_feedback=feedback,
            embedding=self._embed_text(clean_text),
        )

        with self._lock:
            self.memory.append(turn)
            self.memory = self.memory[-self.max_turns :]
            if self.config.get("user_learning_enabled"):
                self._update_user_learning(clean_text, feedback)
            self._rebuild_faiss_index()
            self._save()
            return turn

    def _semantic_search(self, query: str, top_k: int) -> list[MemoryTurn]:
        if not FAISS_AVAILABLE or self._faiss_index is None or not self._faiss_memory_indices:
            return []
        query_vec = self._embed_text(query)
        if query_vec is None or np is None or faiss is None:
            return []
        query_array = np.array([query_vec], dtype="float32")
        faiss.normalize_L2(query_array)
        distances, indices = self._faiss_index.search(query_array, min(top_k, self._faiss_index.ntotal))
        results: list[MemoryTurn] = []
        for score, vector_idx in zip(distances[0], indices[0], strict=False):
            if vector_idx == -1 or score <= 0:
                continue
            memory_idx = self._faiss_memory_indices[int(vector_idx)]
            if 0 <= memory_idx < len(self.memory):
                results.append(self.memory[memory_idx])
        return results

    def _lexical_search(self, query: str, top_k: int) -> list[MemoryTurn]:
        query_tokens = set(self._tokenize(query))
        scored: list[tuple[float, MemoryTurn]] = []
        for turn in self.memory:
            tokens = set(self._tokenize(turn.text))
            if not tokens:
                continue
            overlap = len(query_tokens & tokens)
            jaccard = overlap / len(query_tokens | tokens) if query_tokens else 0.0
            score = jaccard + (float(turn.importance) * 0.05)
            if score > 0:
                scored.append((score, turn))
        if not scored:
            return self.memory[-top_k:]
        scored.sort(key=lambda item: item[0], reverse=True)
        return [turn for _, turn in scored[:top_k]]

    def _rebuild_faiss_index(self) -> None:
        if not FAISS_AVAILABLE or np is None or faiss is None:
            self._faiss_index = None
            self._faiss_memory_indices = []
            return

        vectors: list[list[float]] = []
        memory_indices: list[int] = []
        for idx, turn in enumerate(self.memory):
            if turn.embedding:
                vectors.append(turn.embedding)
                memory_indices.append(idx)
        if not vectors:
            self._faiss_index = None
            self._faiss_memory_indices = []
            return

        matrix = np.array(vectors, dtype="float32")
        faiss.normalize_L2(matrix)
        index = faiss.IndexFlatIP(matrix.shape[1])
        index.add(matrix)
        self._faiss_index = index
        self._faiss_memory_indices = memory_indices

    def _save_faiss_index(self) -> None:
        if not FAISS_AVAILABLE or faiss is None or self._faiss_index is None:
            return
        try:
            faiss.write_index(self._faiss_index, str(self.faiss_index_path))
        except Exception as exc:  # pragma: no cover - filesystem edge
            logger.warning("failed to save FAISS index: %s", exc)

    def _embed_text(self, text: str) -> list[float] | None:
        model = self._get_embedding_model()
        if model is None:
            return None
        try:  # pragma: no cover - optional dependency path
            embedding = model.encode(text, convert_to_numpy=True)
            return embedding.astype("float32").tolist()
        except Exception as exc:
            logger.warning("embedding failed: %s", exc)
            return None

    def _get_embedding_model(self) -> Any | None:
        if self._embedding_model is False:
            return None
        if self._embedding_model is None:
            try:  # pragma: no cover - optional dependency path
                from sentence_transformers import SentenceTransformer

                self._embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
            except Exception:
                self._embedding_model = False
                return None
        return self._embedding_model

    def _dedupe_semantic(self, turns: list[MemoryTurn]) -> list[MemoryTurn]:
        final: list[MemoryTurn] = []
        for turn in turns:
            duplicate = False
            for existing in final:
                if turn.embedding and existing.embedding:
                    if self._cosine_similarity(turn.embedding, existing.embedding) > 0.93:
                        duplicate = True
                        break
            if not duplicate:
                final.append(turn)
        return final

    @staticmethod
    def _cosine_similarity(a: list[float], b: list[float]) -> float:
        if np is None:
            return 0.0
        av = np.array(a)
        bv = np.array(b)
        return float(np.dot(av, bv) / ((np.linalg.norm(av) * np.linalg.norm(bv)) + 1e-8))

    def _save(self) -> None:
        payload = {
            "schema": "repmhl.v2",
            "session_id": self._session_id,
            "active": self._active,
            "current_model_index": self.current_model_index,
            "token_count": self.token_count,
            "max_tokens": self.max_tokens,
            "last_activity": self._now(),
            "memory": [asdict(turn) for turn in self.memory[-self.max_turns :]],
        }
        self._atomic_write_json(self.storage_path, payload)

    def _load(self) -> None:
        if not self.storage_path.exists():
            return
        try:
            payload = json.loads(self.storage_path.read_text(encoding="utf-8"))
            self._session_id = str(payload.get("session_id", ""))
            self._active = bool(payload.get("active", False))
            self.current_model_index = int(payload.get("current_model_index", 0))
            self.token_count = int(payload.get("token_count", 0))
            self.max_tokens = int(payload.get("max_tokens", self.config["base_max_tokens"]))
            self.memory = [self._turn_from_dict(item) for item in payload.get("memory", [])]
        except Exception as exc:
            backup = self.storage_path.with_suffix(self.storage_path.suffix + f".corrupt-{int(time.time())}")
            self.storage_path.replace(backup)
            logger.error("memory store was corrupt and has been quarantined at %s: %s", backup, exc)
            self.memory = []

    def _load_profile(self) -> None:
        if not self.profile_path.exists():
            return
        try:
            payload = json.loads(self.profile_path.read_text(encoding="utf-8"))
            self.profile = UserLearningProfile(**payload)
        except Exception as exc:
            logger.warning("profile hydration failed: %s", exc)

    def _save_profile(self) -> None:
        self._atomic_write_json(self.profile_path, asdict(self.profile))

    @staticmethod
    def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.write("\n")
            os.replace(tmp_name, path)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)

    def _turn_from_dict(self, item: dict[str, Any]) -> MemoryTurn:
        allowed = {field.name for field in MemoryTurn.__dataclass_fields__.values()}
        clean = {key: value for key, value in item.items() if key in allowed}
        clean.setdefault("role", "assistant")
        clean.setdefault("text", "")
        clean.setdefault("timestamp", self._now())
        clean.setdefault("metadata", {})
        clean.setdefault("model", self._current_model()["name"])
        clean.setdefault("tokens", self._estimate_tokens(str(clean["text"])))
        clean.setdefault("importance", 0.5)
        return MemoryTurn(**clean)

    def _update_user_learning(self, text: str, feedback: Any | None) -> None:
        self.profile.total_turns += 1
        lowered = text.lower()
        if any(term in lowered for term in ("patient", "diagnosis", "medical")):
            self.profile.medical_context["focus"] = "clinical"
        if feedback is not None:
            self.profile.corrections.append(feedback)
            self.profile.corrections = self.profile.corrections[-250:]
        if any(term in lowered for term in ("please", "thank you")):
            self.profile.tone_profile["politeness"] = self.profile.tone_profile.get("politeness", 0.0) + 0.1
        self.profile.last_updated = self._now()

    def _importance(self, text: str, tokens: int) -> float:
        boosted = any(term in text.lower() for term in ("medical", "patient", "diagnosis", "security", "tamper", "deploy"))
        return min(1.0, (max(tokens, 1) / 1_000.0) + (0.3 if boosted else 0.0))

    def _rotate_model(self) -> None:
        self.current_model_index = (self.current_model_index + 1) % len(self.config["model_chain"])
        self.token_count = 0
        self.max_tokens = int(self.config["base_max_tokens"])
        self._save()

    def _current_model(self) -> dict[str, Any]:
        return self.config["model_chain"][self.current_model_index]

    def _default_storage_path(self) -> Path:
        raw = os.environ.get("REPMHL_STORAGE_PATH")
        if raw:
            return Path(raw)
        raw_base = os.environ.get("SOVEREIGN_BASE_DIR")
        if raw_base:
            return Path(raw_base) / "memory.json"
        return Path.home() / ".local" / "share" / "sovereign-self-fixer" / "memory.json"

    @staticmethod
    def _sanitize_text(text: str) -> str:
        return str(text).replace("\x00", "").strip()[: int(DEFAULT_CONFIG["max_text_chars"])]

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        return max(1, len(text.split()))

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        return re.findall(r"[a-z0-9']+", text.lower())

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()
