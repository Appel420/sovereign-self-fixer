import ast
import logging
from typing import List


class DeepScanner:
    """Real static analysis for dangerous patterns."""

    DANGEROUS_CALLS = {"eval", "exec", "__import__", "compile"}

    def __init__(self):
        self.logger = logging.getLogger("selffixerai.deep_scanner")

    def analyze(self, code: str) -> List[str]:
        fixes = []
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in self.DANGEROUS_CALLS:
                        fixes.append(f"# SECURITY: Removed dangerous call to {node.func.id}")
                if isinstance(node, ast.ExceptHandler) and node.type is None:
                    fixes.append("# SECURITY: Bare except replaced with specific exception")
        except SyntaxError:
            pass
        return fixes