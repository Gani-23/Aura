from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from lsa.drift.function_resolution import correlation_binding_keys
from lsa.drift.models import AuditExplanation, DriftAlert, ObservedEvent, TraceSessionSummary


@dataclass(slots=True)
class _SessionAccumulator:
    session_key: str
    function: str
    resolution_reason: str
    targets: list[str] = field(default_factory=list)
    processes: list[str] = field(default_factory=list)
    correlation_fields: list[str] = field(default_factory=list)
    drift_targets: list[str] = field(default_factory=list)
    event_count: int = 0


def summarize_sessions(events: list[ObservedEvent], alerts: list[DriftAlert]) -> list[TraceSessionSummary]:
    grouped: dict[str, _SessionAccumulator] = {}
    alert_index = {(alert.function, alert.observed_target) for alert in alerts}

    for idx, event in enumerate(events):
        session_key = select_session_key(event, idx)
        correlation_fields = [key.split(":", 1)[0] for key in correlation_binding_keys(event)]
        acc = grouped.setdefault(
            session_key,
            _SessionAccumulator(
                session_key=session_key,
                function=event.function,
                resolution_reason=event.metadata.get("resolution_reason", "unknown"),
            ),
        )
        acc.event_count += 1
        acc.function = event.function
        acc.resolution_reason = event.metadata.get("resolution_reason", acc.resolution_reason)
        _append_unique(acc.targets, event.target)
        process_label = event.metadata.get("process") or event.metadata.get("comm") or event.function
        if process_label:
            _append_unique(acc.processes, process_label)
        for field in correlation_fields:
            _append_unique(acc.correlation_fields, field)
        if (event.function, event.target) in alert_index:
            _append_unique(acc.drift_targets, event.target)

    return [
        TraceSessionSummary(
            session_key=acc.session_key,
            function=acc.function,
            resolution_reason=acc.resolution_reason,
            event_count=acc.event_count,
            targets=acc.targets,
            processes=acc.processes,
            correlation_fields=acc.correlation_fields,
            drift_targets=acc.drift_targets,
        )
        for acc in grouped.values()
    ]


def build_audit_explanation(
    sessions: list[TraceSessionSummary],
    alerts: list[DriftAlert],
) -> AuditExplanation:
    impacted_functions = _unique_preserving_order(
        [alert.function for alert in alerts] or [session.function for session in sessions]
    )
    unexpected_targets = _unique_preserving_order([alert.observed_target for alert in alerts])
    expected_targets = _unique_preserving_order(
        target for alert in alerts for target in alert.expected_targets
    )
    primary_alert = alerts[0] if alerts else None
    primary_session = find_relevant_session(sessions, primary_alert) if primary_alert else None

    if primary_alert is not None:
        summary = (
            f"Detected {len(alerts)} unexpected outbound event(s) across "
            f"{len(impacted_functions) or 1} function(s). Primary drift: "
            f"{primary_alert.function} reached {primary_alert.observed_target}."
        )
        evidence = [
            f"Unexpected targets: {', '.join(unexpected_targets)}",
            f"Impacted functions: {', '.join(impacted_functions)}",
        ]
        if expected_targets:
            evidence.append(f"Closest expected targets: {', '.join(expected_targets)}")
        if primary_session is not None:
            evidence.append(
                f"Primary session {primary_session.session_key} linked "
                f"{primary_session.event_count} event(s) across targets: "
                f"{', '.join(primary_session.targets)}"
            )
        return AuditExplanation(
            status="drift_detected",
            summary=summary,
            alert_count=len(alerts),
            session_count=len(sessions),
            impacted_functions=impacted_functions,
            unexpected_targets=unexpected_targets,
            expected_targets=expected_targets,
            primary_function=primary_alert.function,
            primary_session_key=primary_session.session_key if primary_session else None,
            evidence=evidence,
        )

    summary = (
        f"No drift alerts detected across {len(sessions)} correlated session(s). "
        "Observed outbound activity remained within the known intent graph."
    )
    evidence = []
    if impacted_functions:
        evidence.append(f"Observed functions: {', '.join(impacted_functions)}")
    observed_targets = _unique_preserving_order(target for session in sessions for target in session.targets)
    if observed_targets:
        evidence.append(f"Observed targets: {', '.join(observed_targets)}")
    return AuditExplanation(
        status="clean",
        summary=summary,
        alert_count=0,
        session_count=len(sessions),
        impacted_functions=impacted_functions,
        unexpected_targets=[],
        expected_targets=[],
        primary_function=impacted_functions[0] if impacted_functions else None,
        primary_session_key=sessions[0].session_key if sessions else None,
        evidence=evidence,
    )


def find_relevant_session(
    sessions: list[TraceSessionSummary],
    alert: DriftAlert,
) -> TraceSessionSummary | None:
    exact = [
        session
        for session in sessions
        if session.function == alert.function and alert.observed_target in session.targets
    ]
    if exact:
        return exact[0]
    same_function = [session for session in sessions if session.function == alert.function]
    if same_function:
        return same_function[0]
    return None


def select_session_key(event: ObservedEvent, fallback_index: int) -> str:
    keys = correlation_binding_keys(event)
    if keys:
        return keys[0]
    return f"event-sequence:{event.function}:{fallback_index}"


def _append_unique(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def _unique_preserving_order(values: Iterable[str]) -> list[str]:
    items: list[str] = []
    for value in values:
        if value not in items:
            items.append(value)
    return items
