from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from lsa.core.intent_graph import IntentGraph
from lsa.drift.comparator import DriftComparator
from lsa.drift.destination_resolution import load_destination_aliases, resolve_destination_events
from lsa.drift.function_resolution import resolve_events
from lsa.drift.models import AuditExplanation, DriftAlert, ObservedEvent, RemediationReport, TraceSessionSummary
from lsa.drift.signal_processor import normalize_events
from lsa.drift.session_summary import build_audit_explanation, find_relevant_session, summarize_sessions
from lsa.remediation.llm_client import RuleBasedLLMClient
from lsa.remediation.prompt_builder import build_prompt
from lsa.remediation.report_writer import write_report
from lsa.settings import WorkspaceSettings
from lsa.storage.files import AuditRepository, SnapshotRepository
from lsa.storage.models import AuditRecord, SnapshotRecord


@dataclass(slots=True)
class AuditResult:
    alerts: list[DriftAlert]
    normalized_events: list[ObservedEvent]
    report_paths: list[str]
    reports: list[RemediationReport]
    sessions: list[TraceSessionSummary]
    explanation: AuditExplanation
    record: AuditRecord | None = None
    snapshot_record: SnapshotRecord | None = None
    snapshot_path: str | None = None


class AuditService:
    def __init__(
        self,
        graph: IntentGraph,
        snapshot_repository: SnapshotRepository,
        audit_repository: AuditRepository,
        drift_comparator: DriftComparator,
        remediation_client: RuleBasedLLMClient,
        settings: WorkspaceSettings,
    ) -> None:
        self.graph = graph
        self.snapshot_repository = snapshot_repository
        self.audit_repository = audit_repository
        self.drift_comparator = drift_comparator
        self.remediation_client = remediation_client
        self.settings = settings

    def audit(
        self,
        *,
        events: list[ObservedEvent],
        snapshot_id: str | None = None,
        snapshot_path: str | None = None,
        persist: bool = True,
        report_dir: str | None = None,
        audit_id: str | None = None,
    ) -> AuditResult:
        if not snapshot_id and not snapshot_path:
            raise ValueError("Either snapshot_id or snapshot_path must be provided.")

        effective_audit_id = audit_id or uuid4().hex[:12]
        snapshot_record = self.snapshot_repository.get(snapshot_id) if snapshot_id else None
        resolved_snapshot_path = snapshot_record.snapshot_path if snapshot_record else snapshot_path
        assert resolved_snapshot_path is not None

        snapshot = self.graph.load_snapshot(resolved_snapshot_path)
        normalized_events = normalize_events(events)
        function_resolved_events = resolve_events(snapshot, normalized_events)
        alias_map = load_destination_aliases(self.settings.destination_aliases_path)
        resolved_events = resolve_destination_events(snapshot, function_resolved_events, alias_map=alias_map)
        alerts = self.drift_comparator.compare(snapshot, resolved_events)
        sessions = summarize_sessions(resolved_events, alerts)
        explanation = build_audit_explanation(sessions, alerts)

        output_dir = report_dir or str(self.settings.reports_dir / effective_audit_id)
        report_paths: list[str] = []
        reports: list[RemediationReport] = []
        for alert in alerts:
            function = snapshot.functions.get(alert.function)
            if function is None:
                continue
            session = find_relevant_session(sessions, alert)
            prompt = build_prompt(function, alert, session=session)
            report = self.remediation_client.analyze(function, alert, prompt, session=session)
            reports.append(report)
            report_paths.append(str(write_report(report, output_dir)))

        record = None
        if persist:
            record = self.audit_repository.create(
                snapshot_id=snapshot_record.snapshot_id if snapshot_record else None,
                snapshot_path=resolved_snapshot_path,
                alerts=[alert.to_dict() for alert in alerts],
                events=[event.to_dict() for event in resolved_events],
                sessions=[session.to_dict() for session in sessions],
                explanation=explanation.to_dict(),
                report_paths=report_paths,
                audit_id=effective_audit_id,
            )

        return AuditResult(
            alerts=alerts,
            normalized_events=resolved_events,
            report_paths=report_paths,
            reports=reports,
            sessions=sessions,
            explanation=explanation,
            record=record,
            snapshot_record=snapshot_record,
            snapshot_path=resolved_snapshot_path,
        )
