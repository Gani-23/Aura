from __future__ import annotations

import ast
from pathlib import Path


def extract_test_assertions(root: Path) -> dict[str, list[str]]:
    assertions: dict[str, list[str]] = {}
    for file_path in sorted(root.rglob("test*.py")):
        if "__pycache__" in file_path.parts or ".venv" in file_path.parts:
            continue
        tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                text = ast.unparse(node.test)
                for name in _referenced_names(node.test):
                    assertions.setdefault(name, []).append(text)
    return assertions


def _referenced_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.add(child.id)
    return names
