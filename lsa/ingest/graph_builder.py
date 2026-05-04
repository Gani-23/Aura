from __future__ import annotations

from pathlib import Path

from lsa.core.models import FunctionIntent, GraphEdge, IntentGraphSnapshot
from lsa.ingest.ast_parser import discover_python_files, parse_python_file
from lsa.ingest.doc_extractor import infer_invariants, summarize_intent
from lsa.ingest.test_analyzer import extract_test_assertions


class GraphBuilder:
    def build(self, root: Path) -> IntentGraphSnapshot:
        root = root.resolve()
        test_assertions = extract_test_assertions(root)
        functions: dict[str, FunctionIntent] = {}
        edges: list[GraphEdge] = []

        for file_path in discover_python_files(root):
            parsed_module = parse_python_file(root, file_path)
            for parsed_function in parsed_module.functions:
                intent = FunctionIntent(
                    name=parsed_function.name,
                    module=parsed_module.module,
                    qualname=parsed_function.qualname,
                    lineno=parsed_function.lineno,
                    end_lineno=parsed_function.end_lineno,
                    docstring=parsed_function.docstring,
                    calls=parsed_function.calls,
                    external_hosts=parsed_function.external_hosts,
                    tests=test_assertions.get(parsed_function.name, []),
                )
                intent.intent_summary = summarize_intent(intent)
                intent.invariants = infer_invariants(intent)
                functions[intent.qualname] = intent

        known_functions = set(functions)
        for function in functions.values():
            for call_name in function.calls:
                if call_name in known_functions:
                    edges.append(GraphEdge(source=function.qualname, target=call_name, kind="calls"))
            for host in function.external_hosts:
                edges.append(GraphEdge(source=function.qualname, target=host, kind="calls_external"))

        return IntentGraphSnapshot(root_path=str(root), functions=functions, edges=edges)
