from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


HTTP_CALL_NAMES = {"get", "post", "put", "patch", "delete", "request", "urlopen"}


@dataclass(slots=True)
class ParsedFunction:
    name: str
    qualname: str
    lineno: int
    end_lineno: int
    docstring: str | None
    calls: list[str]
    external_hosts: list[str]


@dataclass(slots=True)
class ParsedModule:
    module: str
    path: Path
    functions: list[ParsedFunction]


class FunctionVisitor(ast.NodeVisitor):
    def __init__(self, module: str) -> None:
        self.module = module
        self.scope: list[str] = []
        self.functions: list[ParsedFunction] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qualname = ".".join([*self.scope, node.name]) if self.scope else node.name
        visitor = CallVisitor()
        for child in node.body:
            visitor.visit(child)

        parsed = ParsedFunction(
            name=node.name,
            qualname=qualname,
            lineno=node.lineno,
            end_lineno=getattr(node, "end_lineno", node.lineno),
            docstring=ast.get_docstring(node),
            calls=sorted(visitor.calls),
            external_hosts=sorted(visitor.external_hosts),
        )
        self.functions.append(parsed)

        self.scope.append(node.name)
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.visit(child)
        self.scope.pop()


class CallVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.calls: set[str] = set()
        self.external_hosts: set[str] = set()

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self._call_name(node.func)
        if call_name:
            self.calls.add(call_name)
            if call_name.split(".")[-1] in HTTP_CALL_NAMES:
                host = self._extract_host(node)
                if host:
                    self.external_hosts.add(host)
        self.generic_visit(node)

    def _call_name(self, func: ast.AST) -> str | None:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            base = self._call_name(func.value)
            return f"{base}.{func.attr}" if base else func.attr
        return None

    def _extract_host(self, node: ast.Call) -> str | None:
        if not node.args:
            return None
        first_arg = node.args[0]
        if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
            parsed = urlparse(first_arg.value)
            return parsed.netloc or None
        return None


def module_name_from_path(root: Path, file_path: Path) -> str:
    relative = file_path.relative_to(root).with_suffix("")
    return ".".join(relative.parts)


def parse_python_file(root: Path, file_path: Path) -> ParsedModule:
    tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
    module = module_name_from_path(root, file_path)
    visitor = FunctionVisitor(module=module)
    visitor.visit(tree)
    return ParsedModule(module=module, path=file_path, functions=visitor.functions)


def discover_python_files(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*.py")
        if "__pycache__" not in path.parts and ".venv" not in path.parts
    )
