import ast
import logging

class DeepScanner:
    DANGEROUS_CALLS = {'eval', 'exec', '__import__', 'compile'}

    def analyze(self, code: str):
        fixes = []
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in self.DANGEROUS_CALLS:
                        fixes.append(f"# SECURITY: Dangerous call to {node.func.id}()")
                if isinstance(node, ast.ExceptHandler) and node.type is None:
                    fixes.append("# SECURITY: Bare except detected")
        except SyntaxError:
            pass
        return fixes