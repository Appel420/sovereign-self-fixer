"""RAG prompt augmentation built on REPMHL."""

from __future__ import annotations

from typing import Optional

from .repmhl import REPMHL


class RAGPipeline:
    def __init__(self, repmhl: Optional[REPMHL] = None):
        self.repmhl = repmhl or REPMHL()

    def retrieve_context(self, query: str, top_k: int = 5) -> str:
        if not self.repmhl.memory:
            return ""
        relevant = self.repmhl.retrieve_relevant_memory(query, top_k=top_k)
        if not relevant:
            return ""
        context_parts = []
        for turn in relevant:
            prefix = "User" if turn.role == "user" else "Assistant"
            context_parts.append(f"{prefix}: {turn.text}")
        return "\n".join(context_parts)

def get_augmented_prompt(self, query: str, top_k: int = 5) -> str:
    context = self.retrieve_context(query, top_k=top_k)
    return f"Relevant previous context:\n{context}\n\nCurrent query: {query}" if context else query
