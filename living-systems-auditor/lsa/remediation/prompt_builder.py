from __future__ import annotations

from lsa.core.models import FunctionIntent
from lsa.drift.models import DriftAlert, TraceSessionSummary


def build_prompt(
    function: FunctionIntent,
    alert: DriftAlert,
    session: TraceSessionSummary | None = None,
) -> str:
    invariants = "; ".join(function.invariants) or "No invariants recorded."
    expected = ", ".join(alert.expected_targets) or "No known outbound targets."
    session_context = "No correlated session summary available."
    if session is not None:
        session_context = (
            f"Session key: {session.session_key}; "
            f"event count: {session.event_count}; "
            f"targets seen: {', '.join(session.targets) or 'none'}; "
            f"processes: {', '.join(session.processes) or 'none'}; "
            f"correlation fields: {', '.join(session.correlation_fields) or 'none'}."
        )
    return (
        "You are analyzing a semantic drift alert.\n"
        f"Function: {function.qualname}\n"
        f"Documented intent: {function.intent_summary}\n"
        f"Known invariants: {invariants}\n"
        f"Expected outbound targets: {expected}\n"
        f"Observed outbound target: {alert.observed_target}\n"
        f"Correlated session summary: {session_context}\n"
        f"Alert severity: {alert.severity}\n"
        "Produce a concise explanation, risk assessment, immediate action, and long-term fix."
    )
