"""Static analysis for monitored source files."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


@dataclass(slots=True)
class Finding:
    path: str
    line: int
    column: int
    severity: str
    message: str


@dataclass(slots=True)
class ScanReport:
    path: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)


class _IssueVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[Finding] = []

    def visit_Call(self, node: ast.Call) -> None:
        name = self._call_name(node.func)
        if name in {"eval", "exec", "compile", "input"}:
            self.findings.append(
                Finding(self.path, node.lineno, node.col_offset, "high", f"Unsafe call to {name}")
            )
        if name in {"os.system", "subprocess.call", "subprocess.run", "subprocess.Popen"}:
            if any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value for keyword in node.keywords):
                self.findings.append(
                    Finding(self.path, node.lineno, node.col_offset, "high", "shell=True subprocess call")
                )
        self.generic_visit(node)

    @staticmethod
    def _call_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = _IssueVisitor._call_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""


class DeepScanner:
    """Perform source analysis on Python files."""

    def scan_source(self, source: str, path: str = "<memory>") -> ScanReport:
        report = ScanReport(path=path)
        try:
            tree = ast.parse(source, filename=path)
        except SyntaxError as exc:
            report.findings.append(
                Finding(path, exc.lineno or 0, exc.offset or 0, "critical", f"Syntax error: {exc.msg}")
            )
            return report
        visitor = _IssueVisitor(path)
        visitor.visit(tree)
        report.findings.extend(visitor.findings)
        return report

    def scan_file(self, path: str | Path) -> ScanReport:
        path = Path(path)
        return self.scan_source(path.read_text(encoding="utf-8"), path=str(path))

    def scan_paths(self, paths: Iterable[str | Path]) -> list[ScanReport]:
        return [self.scan_file(path) for path in paths]

    def scan_directory(self, path: str | Path) -> list[ScanReport]:
        root = Path(path)
        return [self.scan_file(file_path) for file_path in root.rglob("*.py") if file_path.is_file()]
