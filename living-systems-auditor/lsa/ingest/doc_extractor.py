from __future__ import annotations

from lsa.core.models import FunctionIntent


def summarize_intent(function: FunctionIntent) -> str:
    if function.docstring:
        return function.docstring.strip().splitlines()[0]
    if function.external_hosts:
        hosts = ", ".join(function.external_hosts)
        return f"{function.qualname} interacts with external hosts: {hosts}."
    if function.calls:
        calls = ", ".join(function.calls[:3])
        return f"{function.qualname} coordinates calls to: {calls}."
    return f"{function.qualname} has no extracted docstring yet."


def infer_invariants(function: FunctionIntent) -> list[str]:
    invariants: list[str] = []
    if function.docstring:
        invariants.append("Function should continue to satisfy its documented contract.")
    if function.external_hosts:
        invariants.append("Outbound network activity should stay within known external hosts.")
    if not invariants:
        invariants.append("Function behavior should remain consistent across deployments.")
    return invariants
