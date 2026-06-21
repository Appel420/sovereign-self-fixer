"""Simple RAG Pipeline wrapper on top of REPMHL"""

from typing import Optional
from .repmhl import REPMHL


class RAGPipeline:
    def __init__(self, repmhl: Optional[REPMHL] = None):
        self.repmhl = repmhl or REPMHL()

    def retrieve_context(self, query: str, top_k: int = 5) -> str:
        """Retrieve relevant memory turns as context string."""
        if not self.repmhl or not self.repmhl.memory:
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
        """Return query with relevant context prepended."""
        context = self.retrieve_context(query, top_k=top_k)
        if context:
            return f"Relevant previous context:\n{context}\n\nCurrent query: {query}"
        return query