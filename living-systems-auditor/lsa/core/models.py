from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class FunctionIntent:
    name: str
    module: str
    qualname: str
    lineno: int
    end_lineno: int
    docstring: str | None = None
    calls: list[str] = field(default_factory=list)
    external_hosts: list[str] = field(default_factory=list)
    tests: list[str] = field(default_factory=list)
    intent_summary: str | None = None
    invariants: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "module": self.module,
            "qualname": self.qualname,
            "lineno": self.lineno,
            "end_lineno": self.end_lineno,
            "docstring": self.docstring,
            "calls": list(self.calls),
            "external_hosts": list(self.external_hosts),
            "tests": list(self.tests),
            "intent_summary": self.intent_summary,
            "invariants": list(self.invariants),
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "FunctionIntent":
        return cls(
            name=payload["name"],
            module=payload["module"],
            qualname=payload["qualname"],
            lineno=payload["lineno"],
            end_lineno=payload["end_lineno"],
            docstring=payload.get("docstring"),
            calls=list(payload.get("calls", [])),
            external_hosts=list(payload.get("external_hosts", [])),
            tests=list(payload.get("tests", [])),
            intent_summary=payload.get("intent_summary"),
            invariants=list(payload.get("invariants", [])),
        )


@dataclass(slots=True)
class GraphEdge:
    source: str
    target: str
    kind: str

    def to_dict(self) -> dict:
        return {"source": self.source, "target": self.target, "kind": self.kind}

    @classmethod
    def from_dict(cls, payload: dict) -> "GraphEdge":
        return cls(source=payload["source"], target=payload["target"], kind=payload["kind"])


@dataclass(slots=True)
class IntentGraphSnapshot:
    root_path: str
    functions: dict[str, FunctionIntent]
    edges: list[GraphEdge]

    @property
    def node_count(self) -> int:
        return len(self.functions)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    def to_dict(self) -> dict:
        return {
            "root_path": self.root_path,
            "functions": {key: value.to_dict() for key, value in self.functions.items()},
            "edges": [edge.to_dict() for edge in self.edges],
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "IntentGraphSnapshot":
        return cls(
            root_path=payload["root_path"],
            functions={
                key: FunctionIntent.from_dict(value)
                for key, value in payload.get("functions", {}).items()
            },
            edges=[GraphEdge.from_dict(edge) for edge in payload.get("edges", [])],
        )
