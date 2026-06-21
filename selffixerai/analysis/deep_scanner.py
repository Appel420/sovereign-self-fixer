"""Deep static analysis for SelfFixer (real implementation)"""

import ast
import logging
from typing import List

logger = logging.getLogger(__name__)


class DeepScanner:
    def __init__(self):
        self.issues: List[str] = []

    def analyze(self, code: str) -> List[str]:
        """Analyze code and return list of issues/comments to fix."""
        self.issues = []
        try:
            tree = ast.parse(code)
            self._check_for_dangerous_patterns(tree)
            self._check_for_common_mistakes(tree)
        except SyntaxError as e:
            self.issues.append(f"# Syntax error detected: {e}")
        except Exception as e:
            logger.warning(f"Deep scan failed: {e}")

        return self.issues

    def _check_for_dangerous_patterns(self, tree: ast.AST):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                    self.issues.append("# Warning: Use of eval/exec detected. Consider safer alternatives.")

    def _check_for_common_mistakes(self, tree: ast.AST):
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                self.issues.append("# Warning: Bare except clause detected. Be more specific.")