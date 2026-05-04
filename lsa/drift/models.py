from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class ObservedEvent:
    function: str
    event_type: str
    target: str
    metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "function": self.function,
            "event_type": self.event_type,
            "target": self.target,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "ObservedEvent":
        return cls(
            function=payload["function"],
            event_type=payload["event_type"],
            target=payload["target"],
            metadata=dict(payload.get("metadata", {})),
        )


@dataclass(slots=True)
class DriftAlert:
    function: str
    observed_target: str
    expected_targets: list[str]
    severity: str
    reason: str

    def to_dict(self) -> dict:
        return {
            "function": self.function,
            "observed_target": self.observed_target,
            "expected_targets": list(self.expected_targets),
            "severity": self.severity,
            "reason": self.reason,
        }


@dataclass(slots=True)
class RemediationReport:
    function: str
    title: str
    summary: str
    risk: str
    immediate_action: str
    long_term_fix: str
    supporting_facts: list[str]

    def to_markdown(self) -> str:
        facts = "\n".join(f"- {fact}" for fact in self.supporting_facts)
        return (
            f"# {self.title}\n\n"
            f"## Summary\n{self.summary}\n\n"
            f"## Risk\n{self.risk}\n\n"
            f"## Recommended Immediate Action\n{self.immediate_action}\n\n"
            f"## Recommended Long-Term Fix\n{self.long_term_fix}\n\n"
            f"## Supporting Facts\n{facts}\n"
        )

    def to_dict(self) -> dict:
        return {
            "function": self.function,
            "title": self.title,
            "summary": self.summary,
            "risk": self.risk,
            "immediate_action": self.immediate_action,
            "long_term_fix": self.long_term_fix,
            "supporting_facts": list(self.supporting_facts),
        }


@dataclass(slots=True)
class AuditExplanation:
    status: str
    summary: str
    alert_count: int
    session_count: int
    impacted_functions: list[str] = field(default_factory=list)
    unexpected_targets: list[str] = field(default_factory=list)
    expected_targets: list[str] = field(default_factory=list)
    primary_function: str | None = None
    primary_session_key: str | None = None
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "summary": self.summary,
            "alert_count": self.alert_count,
            "session_count": self.session_count,
            "impacted_functions": list(self.impacted_functions),
            "unexpected_targets": list(self.unexpected_targets),
            "expected_targets": list(self.expected_targets),
            "primary_function": self.primary_function,
            "primary_session_key": self.primary_session_key,
            "evidence": list(self.evidence),
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "AuditExplanation":
        return cls(
            status=payload["status"],
            summary=payload["summary"],
            alert_count=payload["alert_count"],
            session_count=payload["session_count"],
            impacted_functions=list(payload.get("impacted_functions", [])),
            unexpected_targets=list(payload.get("unexpected_targets", [])),
            expected_targets=list(payload.get("expected_targets", [])),
            primary_function=payload.get("primary_function"),
            primary_session_key=payload.get("primary_session_key"),
            evidence=list(payload.get("evidence", [])),
        )


@dataclass(slots=True)
class TraceSessionSummary:
    session_key: str
    function: str
    resolution_reason: str
    event_count: int
    targets: list[str]
    processes: list[str]
    correlation_fields: list[str]
    drift_targets: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "session_key": self.session_key,
            "function": self.function,
            "resolution_reason": self.resolution_reason,
            "event_count": self.event_count,
            "targets": list(self.targets),
            "processes": list(self.processes),
            "correlation_fields": list(self.correlation_fields),
            "drift_targets": list(self.drift_targets),
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "TraceSessionSummary":
        return cls(
            session_key=payload["session_key"],
            function=payload["function"],
            resolution_reason=payload["resolution_reason"],
            event_count=payload["event_count"],
            targets=list(payload.get("targets", [])),
            processes=list(payload.get("processes", [])),
            correlation_fields=list(payload.get("correlation_fields", [])),
            drift_targets=list(payload.get("drift_targets", [])),
        )
