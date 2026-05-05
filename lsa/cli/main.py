from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path

from lsa.core.intent_graph import IntentGraph
from lsa.drift.comparator import DriftComparator
from lsa.drift.ebpf_observer import ObservationResult
from lsa.drift.models import ObservedEvent
from lsa.drift.signal_processor import load_events
from lsa.drift.trace_parser import load_trace_events
from lsa.remediation.llm_client import RuleBasedLLMClient
from lsa.services.audit_service import AuditService
from lsa.services.analytics_service import AnalyticsService, ControlPlaneAlertThresholds
from lsa.services.control_plane_alert_service import ControlPlaneAlertService
from lsa.services.control_plane_backup_service import ControlPlaneBackupService
from lsa.services.ingest_service import IngestService
from lsa.services.job_service import JobService
from lsa.services.metrics_service import ControlPlaneMetricsService
from lsa.services.trace_collection_service import TraceCollectionRequest, TraceCollectionService
from lsa.settings import resolve_workspace_settings
from lsa.storage.files import AuditRepository, JobRepository, SnapshotRepository


settings = resolve_workspace_settings()
graph = IntentGraph()
snapshot_repository = SnapshotRepository(settings, graph=graph)
audit_repository = AuditRepository(settings)
job_repository = JobRepository(settings)
ingest_service = IngestService(graph=graph, snapshot_repository=snapshot_repository)
audit_service = AuditService(
    graph=graph,
    snapshot_repository=snapshot_repository,
    audit_repository=audit_repository,
    drift_comparator=DriftComparator(),
    remediation_client=RuleBasedLLMClient(),
    settings=settings,
)
trace_collection_service = TraceCollectionService(settings=settings)
analytics_service = AnalyticsService(
    job_repository=job_repository,
    default_environment_name=settings.environment_name,
    heartbeat_timeout_seconds=settings.worker_heartbeat_timeout_seconds,
    default_thresholds=ControlPlaneAlertThresholds(
        queue_warning_threshold=settings.analytics_queue_warning_threshold,
        queue_critical_threshold=settings.analytics_queue_critical_threshold,
        stale_worker_warning_threshold=settings.analytics_stale_worker_warning_threshold,
        stale_worker_critical_threshold=settings.analytics_stale_worker_critical_threshold,
        expired_lease_warning_threshold=settings.analytics_expired_lease_warning_threshold,
        expired_lease_critical_threshold=settings.analytics_expired_lease_critical_threshold,
        job_failure_rate_warning_threshold=settings.analytics_job_failure_rate_warning_threshold,
        job_failure_rate_critical_threshold=settings.analytics_job_failure_rate_critical_threshold,
        job_failure_rate_min_samples=settings.analytics_job_failure_rate_min_samples,
        oncall_conflict_warning_threshold=settings.analytics_oncall_conflict_warning_threshold,
        oncall_conflict_critical_threshold=settings.analytics_oncall_conflict_critical_threshold,
        oncall_pending_review_warning_threshold=settings.analytics_oncall_pending_review_warning_threshold,
        oncall_pending_review_critical_threshold=settings.analytics_oncall_pending_review_critical_threshold,
        oncall_pending_review_sla_hours=settings.analytics_oncall_pending_review_sla_hours,
    ),
)
control_plane_alert_service = ControlPlaneAlertService(
    job_repository=job_repository,
    analytics_service=analytics_service,
    default_environment_name=settings.environment_name,
    window_days=settings.control_plane_alert_window_days,
    dedup_window_seconds=settings.control_plane_alert_dedup_window_seconds,
    reminder_interval_seconds=settings.control_plane_alert_reminder_interval_seconds,
    escalation_interval_seconds=settings.control_plane_alert_escalation_interval_seconds,
    policy_path=str(settings.oncall_policy_path),
    required_approver_roles=settings.oncall_approval_required_roles,
    allow_self_approval=settings.oncall_allow_self_approval,
    sink_path=str(settings.control_plane_alert_sink_path),
    webhook_url=settings.control_plane_alert_webhook_url,
    escalation_webhook_url=settings.control_plane_alert_escalation_webhook_url,
)
control_plane_backup_service = ControlPlaneBackupService(
    settings=settings,
    snapshot_repository=snapshot_repository,
    audit_repository=audit_repository,
    job_repository=job_repository,
)
job_service = JobService(
    job_repository=job_repository,
    audit_service=audit_service,
    trace_collection_service=trace_collection_service,
    worker_mode="standalone",
    heartbeat_timeout_seconds=settings.worker_heartbeat_timeout_seconds,
    worker_history_retention_days=settings.worker_history_retention_days,
    job_lease_history_retention_days=settings.job_lease_history_retention_days,
    history_prune_interval_seconds=settings.history_prune_interval_seconds,
    control_plane_alert_service=control_plane_alert_service,
    control_plane_alert_interval_seconds=settings.control_plane_alert_interval_seconds,
    control_plane_alerts_enabled=settings.control_plane_alerts_enabled,
)
metrics_service = ControlPlaneMetricsService(
    job_repository=job_repository,
    job_service=job_service,
    analytics_service=analytics_service,
    environment_name=settings.environment_name,
    worker_mode="standalone",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lsa", description="Living Systems Auditor CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    ingest = subparsers.add_parser("ingest", help="Build an intent graph snapshot from a codebase.")
    ingest.add_argument("repo_path")
    ingest.add_argument("--out", dest="output_path", required=False)
    ingest.add_argument("--no-persist", action="store_true")
    ingest.add_argument("--snapshot-id", required=False)

    audit = subparsers.add_parser("audit", help="Compare observed events against a saved snapshot.")
    audit.add_argument("snapshot_ref")
    audit.add_argument("events_path")
    audit.add_argument("--snapshot-id", action="store_true")
    audit.add_argument("--out-dir", default=None)
    audit.add_argument("--no-persist", action="store_true")
    audit.add_argument("--audit-id", required=False)

    audit_trace = subparsers.add_parser("audit-trace", help="Audit a raw trace file against a snapshot.")
    audit_trace.add_argument("snapshot_ref")
    audit_trace.add_argument("trace_path")
    audit_trace.add_argument("--snapshot-id", action="store_true")
    audit_trace.add_argument("--trace-format", default="auto")
    audit_trace.add_argument("--out-dir", default=None)
    audit_trace.add_argument("--no-persist", action="store_true")
    audit_trace.add_argument("--audit-id", required=False)

    collect_trace = subparsers.add_parser("collect-trace", help="Collect raw trace lines from an observer command.")
    collect_trace.add_argument("pid", type=int)
    collect_trace.add_argument("--program", default="ebpf/network_observer.bt")
    collect_trace.add_argument("--duration", type=float, default=None)
    collect_trace.add_argument("--max-events", type=int, default=None)
    collect_trace.add_argument("--out", required=False)
    collect_trace.add_argument("--symbol-map", required=False)

    collect_audit = subparsers.add_parser(
        "collect-audit",
        help="Collect a trace from a live PID and immediately audit it against a snapshot.",
    )
    collect_audit.add_argument("snapshot_ref")
    collect_audit.add_argument("pid", type=int)
    collect_audit.add_argument("--snapshot-id", action="store_true")
    collect_audit.add_argument("--program", default="ebpf/network_observer.bt")
    collect_audit.add_argument("--duration", type=float, default=None)
    collect_audit.add_argument("--max-events", type=int, default=None)
    collect_audit.add_argument("--trace-format", default="bpftrace")
    collect_audit.add_argument("--out", required=False)
    collect_audit.add_argument("--symbol-map", required=False)
    collect_audit.add_argument("--audit-id", required=False)
    collect_audit.add_argument("--no-persist", action="store_true")

    parse_trace = subparsers.add_parser("parse-trace", help="Convert a trace file into normalized JSON events.")
    parse_trace.add_argument("trace_path")
    parse_trace.add_argument("--trace-format", default="auto")
    parse_trace.add_argument("--out", required=False)

    worker = subparsers.add_parser("worker", help="Run a standalone queue worker for persisted audit jobs.")
    worker.add_argument("--poll-interval", type=float, default=0.1)
    worker.add_argument("--idle-timeout", type=float, default=None)
    worker.add_argument("--max-jobs", type=int, default=None)
    worker.add_argument("--once", action="store_true")

    subparsers.add_parser("list-snapshots", help="List persisted snapshot records.")
    subparsers.add_parser("list-audits", help="List persisted audit records.")
    subparsers.add_parser("list-jobs", help="List persisted job records.")
    subparsers.add_parser("list-workers", help="List persisted worker records.")
    worker_heartbeats = subparsers.add_parser("list-worker-heartbeats", help="List recorded heartbeats for a worker.")
    worker_heartbeats.add_argument("worker_id")
    worker_heartbeat_rollups = subparsers.add_parser(
        "list-worker-heartbeat-rollups",
        help="List daily heartbeat rollups for a worker.",
    )
    worker_heartbeat_rollups.add_argument("worker_id")
    job_lease_events = subparsers.add_parser("list-job-lease-events", help="List recorded lease events for a job.")
    job_lease_events.add_argument("job_id")
    job_lease_event_rollups = subparsers.add_parser(
        "list-job-lease-event-rollups",
        help="List daily lease-event rollups for a job.",
    )
    job_lease_event_rollups.add_argument("job_id")
    control_plane_analytics = subparsers.add_parser(
        "control-plane-analytics",
        help="Show operational trends for queue, workers, and lease activity.",
    )
    control_plane_analytics.add_argument("--days", type=int, default=30)
    control_plane_metrics = subparsers.add_parser(
        "control-plane-metrics",
        help="Render Prometheus-style control-plane metrics.",
    )
    control_plane_metrics.add_argument("--days", type=int, default=1)
    subparsers.add_parser(
        "control-plane-maintenance-mode",
        help="Show the current control-plane maintenance mode state.",
    )
    list_control_plane_maintenance_events = subparsers.add_parser(
        "list-control-plane-maintenance-events",
        help="List persisted control-plane maintenance events.",
    )
    list_control_plane_maintenance_events.add_argument("--limit", type=int, default=50)
    enable_control_plane_maintenance_mode = subparsers.add_parser(
        "enable-control-plane-maintenance-mode",
        help="Enable control-plane maintenance mode to pause worker job execution.",
    )
    enable_control_plane_maintenance_mode.add_argument("--by", required=True)
    enable_control_plane_maintenance_mode.add_argument("--reason", default=None)
    disable_control_plane_maintenance_mode = subparsers.add_parser(
        "disable-control-plane-maintenance-mode",
        help="Disable control-plane maintenance mode and resume normal API mutations and worker execution.",
    )
    disable_control_plane_maintenance_mode.add_argument("--by", required=True)
    disable_control_plane_maintenance_mode.add_argument("--reason", default=None)
    emit_control_plane_alerts = subparsers.add_parser(
        "emit-control-plane-alerts",
        help="Force emission of current control-plane alerts through configured targets.",
    )
    emit_control_plane_alerts.add_argument("--force", action="store_true")
    process_control_plane_alert_followups = subparsers.add_parser(
        "process-control-plane-alert-followups",
        help="Force reminder/escalation follow-up processing for active control-plane alerts.",
    )
    process_control_plane_alert_followups.add_argument("--force", action="store_true")
    list_control_plane_alerts = subparsers.add_parser(
        "list-control-plane-alerts",
        help="List persisted control-plane alert emissions.",
    )
    list_control_plane_alerts.add_argument("--limit", type=int, default=50)
    acknowledge_control_plane_alert = subparsers.add_parser(
        "acknowledge-control-plane-alert",
        help="Acknowledge a persisted control-plane alert.",
    )
    acknowledge_control_plane_alert.add_argument("alert_id")
    acknowledge_control_plane_alert.add_argument("--by", required=True)
    acknowledge_control_plane_alert.add_argument("--note", default=None)
    create_control_plane_alert_silence = subparsers.add_parser(
        "create-control-plane-alert-silence",
        help="Silence future control-plane alerts by alert key or finding code for a fixed duration.",
    )
    create_control_plane_alert_silence.add_argument("--by", required=True)
    create_control_plane_alert_silence.add_argument("--reason", required=True)
    create_control_plane_alert_silence.add_argument("--duration-minutes", type=int, required=True)
    create_control_plane_alert_silence.add_argument("--alert-key", default=None)
    create_control_plane_alert_silence.add_argument("--finding-code", default=None)
    list_control_plane_alert_silences = subparsers.add_parser(
        "list-control-plane-alert-silences",
        help="List control-plane alert silences.",
    )
    list_control_plane_alert_silences.add_argument("--active-only", action="store_true")
    cancel_control_plane_alert_silence = subparsers.add_parser(
        "cancel-control-plane-alert-silence",
        help="Cancel a control-plane alert silence.",
    )
    cancel_control_plane_alert_silence.add_argument("silence_id")
    cancel_control_plane_alert_silence.add_argument("--by", required=True)
    create_control_plane_oncall_schedule = subparsers.add_parser(
        "create-control-plane-oncall-schedule",
        help="Create a timezone-aware on-call route for control-plane alerts.",
    )
    create_control_plane_oncall_schedule.add_argument("--by", required=True)
    create_control_plane_oncall_schedule.add_argument("--environment", default=None)
    create_control_plane_oncall_schedule.add_argument("--creator-team", default=None)
    create_control_plane_oncall_schedule.add_argument("--creator-role", default=None)
    create_control_plane_oncall_schedule.add_argument("--change-reason", default=None)
    create_control_plane_oncall_schedule.add_argument("--approved-by", default=None)
    create_control_plane_oncall_schedule.add_argument("--approver-team", default=None)
    create_control_plane_oncall_schedule.add_argument("--approver-role", default=None)
    create_control_plane_oncall_schedule.add_argument("--approval-note", default=None)
    create_control_plane_oncall_schedule.add_argument("--team", required=True)
    create_control_plane_oncall_schedule.add_argument("--timezone", required=True)
    create_control_plane_oncall_schedule.add_argument("--weekdays", nargs="+", type=int, required=True)
    create_control_plane_oncall_schedule.add_argument("--start-time", required=True)
    create_control_plane_oncall_schedule.add_argument("--end-time", required=True)
    create_control_plane_oncall_schedule.add_argument("--priority", type=int, default=100)
    create_control_plane_oncall_schedule.add_argument("--rotation", default=None)
    create_control_plane_oncall_schedule.add_argument("--effective-start-date", default=None)
    create_control_plane_oncall_schedule.add_argument("--effective-end-date", default=None)
    create_control_plane_oncall_schedule.add_argument("--webhook-url", default=None)
    create_control_plane_oncall_schedule.add_argument("--escalation-webhook-url", default=None)
    submit_control_plane_oncall_change_request = subparsers.add_parser(
        "submit-control-plane-oncall-change-request",
        help="Submit a governed control-plane on-call change request.",
    )
    submit_control_plane_oncall_change_request.add_argument("--by", required=True)
    submit_control_plane_oncall_change_request.add_argument("--environment", default=None)
    submit_control_plane_oncall_change_request.add_argument("--creator-team", default=None)
    submit_control_plane_oncall_change_request.add_argument("--creator-role", default=None)
    submit_control_plane_oncall_change_request.add_argument("--change-reason", required=True)
    submit_control_plane_oncall_change_request.add_argument("--team", required=True)
    submit_control_plane_oncall_change_request.add_argument("--timezone", required=True)
    submit_control_plane_oncall_change_request.add_argument("--weekdays", nargs="+", type=int, required=True)
    submit_control_plane_oncall_change_request.add_argument("--start-time", required=True)
    submit_control_plane_oncall_change_request.add_argument("--end-time", required=True)
    submit_control_plane_oncall_change_request.add_argument("--priority", type=int, default=100)
    submit_control_plane_oncall_change_request.add_argument("--rotation", default=None)
    submit_control_plane_oncall_change_request.add_argument("--effective-start-date", default=None)
    submit_control_plane_oncall_change_request.add_argument("--effective-end-date", default=None)
    submit_control_plane_oncall_change_request.add_argument("--webhook-url", default=None)
    submit_control_plane_oncall_change_request.add_argument("--escalation-webhook-url", default=None)
    list_control_plane_oncall_change_requests = subparsers.add_parser(
        "list-control-plane-oncall-change-requests",
        help="List control-plane on-call change requests.",
    )
    list_control_plane_oncall_change_requests.add_argument("--status", default=None)
    review_control_plane_oncall_change_request = subparsers.add_parser(
        "review-control-plane-oncall-change-request",
        help="Approve or reject a pending control-plane on-call change request.",
    )
    review_control_plane_oncall_change_request.add_argument("request_id")
    review_control_plane_oncall_change_request.add_argument("--decision", required=True)
    review_control_plane_oncall_change_request.add_argument("--by", required=True)
    review_control_plane_oncall_change_request.add_argument("--reviewer-team", default=None)
    review_control_plane_oncall_change_request.add_argument("--reviewer-role", default=None)
    review_control_plane_oncall_change_request.add_argument("--note", default=None)
    assign_control_plane_oncall_change_request = subparsers.add_parser(
        "assign-control-plane-oncall-change-request",
        help="Assign a pending control-plane on-call change request to an owner.",
    )
    assign_control_plane_oncall_change_request.add_argument("request_id")
    assign_control_plane_oncall_change_request.add_argument("--assigned-to", required=True)
    assign_control_plane_oncall_change_request.add_argument("--assigned-team", default=None)
    assign_control_plane_oncall_change_request.add_argument("--by", required=True)
    assign_control_plane_oncall_change_request.add_argument("--note", default=None)
    list_control_plane_oncall_schedules = subparsers.add_parser(
        "list-control-plane-oncall-schedules",
        help="List control-plane on-call schedules.",
    )
    list_control_plane_oncall_schedules.add_argument("--active-only", action="store_true")
    resolve_control_plane_oncall_route = subparsers.add_parser(
        "resolve-control-plane-oncall-route",
        help="Preview the effective on-call route and ranked active candidates.",
    )
    resolve_control_plane_oncall_route.add_argument("--at", default=None)
    cancel_control_plane_oncall_schedule = subparsers.add_parser(
        "cancel-control-plane-oncall-schedule",
        help="Cancel a control-plane on-call schedule.",
    )
    cancel_control_plane_oncall_schedule.add_argument("schedule_id")
    cancel_control_plane_oncall_schedule.add_argument("--by", required=True)
    subparsers.add_parser(
        "control-plane-schema",
        help="Show the current control-plane schema version and applied migrations.",
    )
    subparsers.add_parser(
        "migrate-control-plane-schema",
        help="Apply idempotent control-plane schema migrations and report the resulting version state.",
    )
    export_control_plane_backup = subparsers.add_parser(
        "export-control-plane-backup",
        help="Export the full control-plane state into a versioned JSON backup bundle.",
    )
    export_control_plane_backup.add_argument("--out", required=True)
    import_control_plane_backup = subparsers.add_parser(
        "import-control-plane-backup",
        help="Restore the full control-plane state from a versioned JSON backup bundle.",
    )
    import_control_plane_backup.add_argument("input_path")
    import_control_plane_backup.add_argument("--replace-existing", action="store_true")
    subparsers.add_parser("prune-history", help="Prune retained worker heartbeat and lease-event history.")

    return parser


def run_ingest(
    repo_path: str,
    output_path: str | None,
    *,
    persist: bool,
    snapshot_id: str | None,
) -> int:
    result = ingest_service.ingest(
        repo_path,
        persist=persist,
        output_path=output_path,
        snapshot_id=snapshot_id,
    )
    payload = {
        "node_count": result.snapshot.node_count,
        "edge_count": result.snapshot.edge_count,
    }
    if result.snapshot_path:
        payload["snapshot_path"] = result.snapshot_path
    if result.record:
        payload["snapshot_id"] = result.record.snapshot_id
        payload["created_at"] = result.record.created_at
    print(json.dumps(payload, indent=2))
    return 0


def run_audit(
    snapshot_ref: str,
    events_path: str,
    *,
    snapshot_is_id: bool,
    out_dir: str | None,
    persist: bool,
    audit_id: str | None,
) -> int:
    result = audit_service.audit(
        snapshot_id=snapshot_ref if snapshot_is_id else None,
        snapshot_path=None if snapshot_is_id else snapshot_ref,
        events=[ObservedEvent.from_dict(item.to_dict()) for item in load_events(events_path)],
        persist=persist,
        report_dir=out_dir,
        audit_id=audit_id,
    )
    payload = {
        "alert_count": len(result.alerts),
        "alerts": [alert.to_dict() for alert in result.alerts],
        "report_paths": result.report_paths,
        "snapshot_path": result.snapshot_path,
        "sessions": [session.to_dict() for session in result.sessions],
        "explanation": result.explanation.to_dict(),
    }
    if result.record:
        payload["audit_id"] = result.record.audit_id
    print(json.dumps(payload, indent=2))
    return 0


def run_audit_trace(
    snapshot_ref: str,
    trace_path: str,
    *,
    snapshot_is_id: bool,
    trace_format: str,
    out_dir: str | None,
    persist: bool,
    audit_id: str | None,
) -> int:
    result = audit_service.audit(
        snapshot_id=snapshot_ref if snapshot_is_id else None,
        snapshot_path=None if snapshot_is_id else snapshot_ref,
        events=load_trace_events(trace_path, trace_format=trace_format),
        persist=persist,
        report_dir=out_dir,
        audit_id=audit_id,
    )
    payload = {
        "alert_count": len(result.alerts),
        "alerts": [alert.to_dict() for alert in result.alerts],
        "report_paths": result.report_paths,
        "snapshot_path": result.snapshot_path,
        "sessions": [session.to_dict() for session in result.sessions],
        "explanation": result.explanation.to_dict(),
    }
    if result.record:
        payload["audit_id"] = result.record.audit_id
    print(json.dumps(payload, indent=2))
    return 0


def run_parse_trace(trace_path: str, trace_format: str, output_path: str | None) -> int:
    events = load_trace_events(trace_path, trace_format=trace_format)
    payload = [event.to_dict() for event in events]
    rendered = json.dumps(payload, indent=2)
    if output_path:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    print(rendered)
    return 0


def run_collect_trace(
    pid: int,
    program: str,
    *,
    output_path: str | None,
    duration: float | None,
    max_events: int | None,
    symbol_map_path: str | None = None,
) -> int:
    result = trace_collection_service.collect(
        _build_trace_collection_request(
            pid=pid,
            program=program,
            output_path=output_path,
            duration=duration,
            max_events=max_events,
            symbol_map_path=symbol_map_path,
        )
    )
    _print_observation_result(result)
    return 0


def run_collect_audit(
    snapshot_ref: str,
    pid: int,
    *,
    snapshot_is_id: bool,
    program: str,
    duration: float | None,
    max_events: int | None,
    trace_format: str,
    output_path: str | None,
    persist: bool,
    audit_id: str | None,
    symbol_map_path: str | None = None,
) -> int:
    observation = trace_collection_service.collect(
        _build_trace_collection_request(
            pid=pid,
            program=program,
            output_path=output_path,
            duration=duration,
            max_events=max_events,
            symbol_map_path=symbol_map_path,
        )
    )
    result = audit_service.audit(
        snapshot_id=snapshot_ref if snapshot_is_id else None,
        snapshot_path=None if snapshot_is_id else snapshot_ref,
        events=load_trace_events(observation.trace_path, trace_format=trace_format),
        persist=persist,
        audit_id=audit_id,
    )
    payload = {
        "trace_path": observation.trace_path,
        "trace_metadata_path": observation.metadata_path,
        "trace_symbol_map_path": observation.symbol_map_path,
        "trace_context_map_path": observation.context_map_path,
        "line_count": observation.line_count,
        "alert_count": len(result.alerts),
        "alerts": [alert.to_dict() for alert in result.alerts],
        "report_paths": result.report_paths,
        "sessions": [session.to_dict() for session in result.sessions],
        "explanation": result.explanation.to_dict(),
    }
    if result.record:
        payload["audit_id"] = result.record.audit_id
    print(json.dumps(payload, indent=2))
    return 0


def run_worker(
    *,
    poll_interval: float,
    idle_timeout: float | None,
    max_jobs: int | None,
    once: bool,
) -> int:
    job_service.poll_interval_seconds = poll_interval
    processed_jobs = job_service.run_foreground(
        max_jobs=1 if once else max_jobs,
        idle_timeout_seconds=idle_timeout,
    )
    payload = {
        "worker_mode": "standalone",
        "worker_id": job_service.worker_id(),
        "processed_jobs": processed_jobs,
        "active_workers": job_service.active_worker_count(),
        "queued_jobs": job_service.count_jobs_by_status("queued"),
        "running_jobs": job_service.count_jobs_by_status("running"),
        "completed_jobs": job_service.count_jobs_by_status("completed"),
        "failed_jobs": job_service.count_jobs_by_status("failed"),
    }
    print(json.dumps(payload, indent=2))
    return 0


def run_prune_history() -> int:
    payload = job_service.prune_history(force=True)
    print(json.dumps(payload, indent=2))
    return 0


def run_control_plane_schema() -> int:
    print(json.dumps(job_repository.schema_status(), indent=2))
    return 0


def run_migrate_control_plane_schema() -> int:
    print(json.dumps(job_repository.migrate_schema(), indent=2))
    return 0


def run_export_control_plane_backup(*, output_path: str) -> int:
    summary = control_plane_backup_service.export_bundle(output_path)
    print(json.dumps(summary.to_dict(), indent=2))
    return 0


def run_import_control_plane_backup(*, input_path: str, replace_existing: bool) -> int:
    summary = control_plane_backup_service.import_bundle(input_path, replace_existing=replace_existing)
    print(json.dumps(summary.to_dict(), indent=2))
    return 0


def run_control_plane_analytics(*, days: int) -> int:
    payload = analytics_service.build_control_plane_analytics(days=days).to_dict()
    print(json.dumps(payload, indent=2))
    return 0


def run_control_plane_metrics(*, days: int) -> int:
    print(metrics_service.render_prometheus(days=days), end="")
    return 0


def run_control_plane_maintenance_mode() -> int:
    print(json.dumps(job_repository.maintenance_mode_status(), indent=2))
    return 0


def run_list_control_plane_maintenance_events(*, limit: int) -> int:
    print(json.dumps([record.to_dict() for record in job_service.list_control_plane_maintenance_events(limit=limit)], indent=2))
    return 0


def run_enable_control_plane_maintenance_mode(*, changed_by: str, reason: str | None) -> int:
    print(json.dumps(job_service.enable_maintenance_mode(changed_by=changed_by, reason=reason), indent=2))
    return 0


def run_disable_control_plane_maintenance_mode(*, changed_by: str, reason: str | None) -> int:
    print(json.dumps(job_service.disable_maintenance_mode(changed_by=changed_by, reason=reason), indent=2))
    return 0


def run_emit_control_plane_alerts(*, force: bool) -> int:
    alerts = job_service.emit_control_plane_alerts(force=force)
    payload = {
        "emitted_count": len(alerts),
        "alerts": [record.to_dict() for record in alerts],
    }
    print(json.dumps(payload, indent=2))
    return 0


def run_process_control_plane_alert_followups(*, force: bool) -> int:
    alerts = job_service.process_control_plane_alert_follow_ups(force=force)
    payload = {
        "emitted_count": len(alerts),
        "alerts": [record.to_dict() for record in alerts],
    }
    print(json.dumps(payload, indent=2))
    return 0


def run_list_control_plane_alerts(*, limit: int) -> int:
    print(json.dumps([record.to_dict() for record in job_service.list_control_plane_alerts(limit)], indent=2))
    return 0


def run_acknowledge_control_plane_alert(*, alert_id: str, acknowledged_by: str, acknowledgement_note: str | None) -> int:
    record = job_service.acknowledge_control_plane_alert(
        alert_id=alert_id,
        acknowledged_by=acknowledged_by,
        acknowledgement_note=acknowledgement_note,
    )
    print(json.dumps(record.to_dict(), indent=2))
    return 0


def run_create_control_plane_alert_silence(
    *,
    created_by: str,
    reason: str,
    duration_minutes: int,
    match_alert_key: str | None,
    match_finding_code: str | None,
) -> int:
    record = job_service.create_control_plane_alert_silence(
        created_by=created_by,
        reason=reason,
        duration_minutes=duration_minutes,
        match_alert_key=match_alert_key,
        match_finding_code=match_finding_code,
    )
    print(json.dumps(record.to_dict(), indent=2))
    return 0


def run_list_control_plane_alert_silences(*, active_only: bool) -> int:
    print(
        json.dumps(
            [record.to_dict() for record in job_service.list_control_plane_alert_silences(active_only=active_only)],
            indent=2,
        )
    )
    return 0


def run_cancel_control_plane_alert_silence(*, silence_id: str, cancelled_by: str) -> int:
    record = job_service.cancel_control_plane_alert_silence(
        silence_id=silence_id,
        cancelled_by=cancelled_by,
    )
    print(json.dumps(record.to_dict(), indent=2))
    return 0


def run_create_control_plane_oncall_schedule(
    *,
    created_by: str,
    environment_name: str | None,
    created_by_team: str | None,
    created_by_role: str | None,
    change_reason: str | None,
    approved_by: str | None,
    approved_by_team: str | None,
    approved_by_role: str | None,
    approval_note: str | None,
    team_name: str,
    timezone_name: str,
    weekdays: list[int],
    start_time: str,
    end_time: str,
    priority: int,
    rotation_name: str | None,
    effective_start_date: str | None,
    effective_end_date: str | None,
    webhook_url: str | None,
    escalation_webhook_url: str | None,
) -> int:
    record = control_plane_alert_service.create_oncall_schedule(
        created_by=created_by,
        environment_name=environment_name,
        created_by_team=created_by_team,
        created_by_role=created_by_role,
        change_reason=change_reason,
        approved_by=approved_by,
        approved_by_team=approved_by_team,
        approved_by_role=approved_by_role,
        approval_note=approval_note,
        team_name=team_name,
        timezone_name=timezone_name,
        weekdays=weekdays,
        start_time=start_time,
        end_time=end_time,
        priority=priority,
        rotation_name=rotation_name,
        effective_start_date=effective_start_date,
        effective_end_date=effective_end_date,
        webhook_url=webhook_url,
        escalation_webhook_url=escalation_webhook_url,
    )
    print(json.dumps(record.to_dict(), indent=2))
    return 0


def run_submit_control_plane_oncall_change_request(
    *,
    created_by: str,
    environment_name: str | None,
    created_by_team: str | None,
    created_by_role: str | None,
    change_reason: str,
    team_name: str,
    timezone_name: str,
    weekdays: list[int],
    start_time: str,
    end_time: str,
    priority: int,
    rotation_name: str | None,
    effective_start_date: str | None,
    effective_end_date: str | None,
    webhook_url: str | None,
    escalation_webhook_url: str | None,
) -> int:
    record = control_plane_alert_service.submit_oncall_change_request(
        created_by=created_by,
        environment_name=environment_name,
        created_by_team=created_by_team,
        created_by_role=created_by_role,
        change_reason=change_reason,
        team_name=team_name,
        timezone_name=timezone_name,
        weekdays=weekdays,
        start_time=start_time,
        end_time=end_time,
        priority=priority,
        rotation_name=rotation_name,
        effective_start_date=effective_start_date,
        effective_end_date=effective_end_date,
        webhook_url=webhook_url,
        escalation_webhook_url=escalation_webhook_url,
    )
    print(json.dumps(record.to_dict(), indent=2))
    return 0


def run_list_control_plane_oncall_change_requests(*, status: str | None) -> int:
    print(
        json.dumps(
            [record.to_dict() for record in control_plane_alert_service.list_oncall_change_requests(status=status)],
            indent=2,
        )
    )
    return 0


def run_review_control_plane_oncall_change_request(
    *,
    request_id: str,
    decision: str,
    reviewed_by: str,
    reviewed_by_team: str | None,
    reviewed_by_role: str | None,
    review_note: str | None,
) -> int:
    record = control_plane_alert_service.review_oncall_change_request(
        request_id=request_id,
        decision=decision,
        reviewed_by=reviewed_by,
        reviewed_by_team=reviewed_by_team,
        reviewed_by_role=reviewed_by_role,
        review_note=review_note,
    )
    print(json.dumps(record.to_dict(), indent=2))
    return 0


def run_assign_control_plane_oncall_change_request(
    *,
    request_id: str,
    assigned_to: str,
    assigned_to_team: str | None,
    assigned_by: str,
    assignment_note: str | None,
) -> int:
    record = control_plane_alert_service.assign_oncall_change_request(
        request_id=request_id,
        assigned_to=assigned_to,
        assigned_to_team=assigned_to_team,
        assigned_by=assigned_by,
        assignment_note=assignment_note,
    )
    print(json.dumps(record.to_dict(), indent=2))
    return 0


def run_list_control_plane_oncall_schedules(*, active_only: bool) -> int:
    print(
        json.dumps(
            [record.to_dict() for record in control_plane_alert_service.list_oncall_schedules(active_only=active_only)],
            indent=2,
        )
    )
    return 0


def run_resolve_control_plane_oncall_route(*, at: str | None) -> int:
    preview = control_plane_alert_service.preview_oncall_route(
        reference_timestamp=_parse_timestamp_argument(at),
    )
    print(json.dumps(preview, indent=2))
    return 0


def run_cancel_control_plane_oncall_schedule(*, schedule_id: str, cancelled_by: str) -> int:
    record = control_plane_alert_service.cancel_oncall_schedule(
        schedule_id=schedule_id,
        cancelled_by=cancelled_by,
    )
    print(json.dumps(record.to_dict(), indent=2))
    return 0


def _print_observation_result(result: ObservationResult) -> None:
    payload = {
        "command": result.command,
        "trace_path": result.trace_path,
        "trace_metadata_path": result.metadata_path,
        "trace_symbol_map_path": result.symbol_map_path,
        "trace_context_map_path": result.context_map_path,
        "line_count": result.line_count,
        "return_code": result.return_code,
    }
    print(json.dumps(payload, indent=2))


def _build_trace_collection_request(
    *,
    pid: int,
    program: str,
    output_path: str | None,
    duration: float | None,
    max_events: int | None,
    symbol_map_path: str | None,
) -> TraceCollectionRequest:
    program_path = Path(program)
    if program_path.suffix == ".bt":
        return TraceCollectionRequest(
            pid=pid,
            program_path=str(program_path),
            output_path=output_path,
            duration_seconds=duration,
            max_events=max_events,
            symbol_map_path=symbol_map_path,
        )
    return TraceCollectionRequest(
        pid=pid,
        program_path=str(program_path),
        output_path=output_path,
        duration_seconds=duration,
        max_events=max_events,
        command=["/bin/sh", str(program_path)],
        symbol_map_path=symbol_map_path,
    )


def _parse_timestamp_argument(raw_value: str | None) -> datetime | None:
    if raw_value is None:
        return None
    parsed = datetime.fromisoformat(raw_value)
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include a timezone offset.")
    return parsed


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "ingest":
        return run_ingest(
            args.repo_path,
            args.output_path,
            persist=not args.no_persist,
            snapshot_id=args.snapshot_id,
        )
    if args.command == "audit":
        if args.out_dir:
            Path(args.out_dir).mkdir(parents=True, exist_ok=True)
        return run_audit(
            args.snapshot_ref,
            args.events_path,
            snapshot_is_id=args.snapshot_id,
            out_dir=args.out_dir,
            persist=not args.no_persist,
            audit_id=args.audit_id,
        )
    if args.command == "audit-trace":
        if args.out_dir:
            Path(args.out_dir).mkdir(parents=True, exist_ok=True)
        return run_audit_trace(
            args.snapshot_ref,
            args.trace_path,
            snapshot_is_id=args.snapshot_id,
            trace_format=args.trace_format,
            out_dir=args.out_dir,
            persist=not args.no_persist,
            audit_id=args.audit_id,
        )
    if args.command == "collect-trace":
        return run_collect_trace(
            args.pid,
            args.program,
            output_path=args.out,
            duration=args.duration,
            max_events=args.max_events,
            symbol_map_path=args.symbol_map,
        )
    if args.command == "collect-audit":
        return run_collect_audit(
            args.snapshot_ref,
            args.pid,
            snapshot_is_id=args.snapshot_id,
            program=args.program,
            duration=args.duration,
            max_events=args.max_events,
            trace_format=args.trace_format,
            output_path=args.out,
            persist=not args.no_persist,
            audit_id=args.audit_id,
            symbol_map_path=args.symbol_map,
        )
    if args.command == "parse-trace":
        return run_parse_trace(args.trace_path, args.trace_format, args.out)
    if args.command == "worker":
        return run_worker(
            poll_interval=args.poll_interval,
            idle_timeout=args.idle_timeout,
            max_jobs=args.max_jobs,
            once=args.once,
        )
    if args.command == "list-snapshots":
        print(json.dumps([record.to_dict() for record in snapshot_repository.list()], indent=2))
        return 0
    if args.command == "list-audits":
        print(json.dumps([record.to_dict() for record in audit_repository.list()], indent=2))
        return 0
    if args.command == "list-jobs":
        print(json.dumps([record.to_dict() for record in job_repository.list()], indent=2))
        return 0
    if args.command == "list-workers":
        print(json.dumps([record.to_dict() for record in job_repository.list_workers()], indent=2))
        return 0
    if args.command == "list-worker-heartbeats":
        print(json.dumps([record.to_dict() for record in job_repository.list_worker_heartbeats(args.worker_id)], indent=2))
        return 0
    if args.command == "list-worker-heartbeat-rollups":
        print(json.dumps([record.to_dict() for record in job_repository.list_worker_heartbeat_rollups(args.worker_id)], indent=2))
        return 0
    if args.command == "list-job-lease-events":
        print(json.dumps([record.to_dict() for record in job_repository.list_job_lease_events(args.job_id)], indent=2))
        return 0
    if args.command == "list-job-lease-event-rollups":
        print(json.dumps([record.to_dict() for record in job_repository.list_job_lease_event_rollups(args.job_id)], indent=2))
        return 0
    if args.command == "control-plane-analytics":
        return run_control_plane_analytics(days=args.days)
    if args.command == "control-plane-metrics":
        return run_control_plane_metrics(days=args.days)
    if args.command == "control-plane-maintenance-mode":
        return run_control_plane_maintenance_mode()
    if args.command == "list-control-plane-maintenance-events":
        return run_list_control_plane_maintenance_events(limit=args.limit)
    if args.command == "enable-control-plane-maintenance-mode":
        return run_enable_control_plane_maintenance_mode(changed_by=args.by, reason=args.reason)
    if args.command == "disable-control-plane-maintenance-mode":
        return run_disable_control_plane_maintenance_mode(changed_by=args.by, reason=args.reason)
    if args.command == "emit-control-plane-alerts":
        return run_emit_control_plane_alerts(force=args.force)
    if args.command == "process-control-plane-alert-followups":
        return run_process_control_plane_alert_followups(force=args.force)
    if args.command == "list-control-plane-alerts":
        return run_list_control_plane_alerts(limit=args.limit)
    if args.command == "acknowledge-control-plane-alert":
        return run_acknowledge_control_plane_alert(
            alert_id=args.alert_id,
            acknowledged_by=args.by,
            acknowledgement_note=args.note,
        )
    if args.command == "create-control-plane-alert-silence":
        return run_create_control_plane_alert_silence(
            created_by=args.by,
            reason=args.reason,
            duration_minutes=args.duration_minutes,
            match_alert_key=args.alert_key,
            match_finding_code=args.finding_code,
        )
    if args.command == "list-control-plane-alert-silences":
        return run_list_control_plane_alert_silences(active_only=args.active_only)
    if args.command == "cancel-control-plane-alert-silence":
        return run_cancel_control_plane_alert_silence(
            silence_id=args.silence_id,
            cancelled_by=args.by,
        )
    if args.command == "create-control-plane-oncall-schedule":
        return run_create_control_plane_oncall_schedule(
            created_by=args.by,
            environment_name=args.environment,
            created_by_team=args.creator_team,
            created_by_role=args.creator_role,
            change_reason=args.change_reason,
            approved_by=args.approved_by,
            approved_by_team=args.approver_team,
            approved_by_role=args.approver_role,
            approval_note=args.approval_note,
            team_name=args.team,
            timezone_name=args.timezone,
            weekdays=args.weekdays,
            start_time=args.start_time,
            end_time=args.end_time,
            priority=args.priority,
            rotation_name=args.rotation,
            effective_start_date=args.effective_start_date,
            effective_end_date=args.effective_end_date,
            webhook_url=args.webhook_url,
            escalation_webhook_url=args.escalation_webhook_url,
        )
    if args.command == "submit-control-plane-oncall-change-request":
        return run_submit_control_plane_oncall_change_request(
            created_by=args.by,
            environment_name=args.environment,
            created_by_team=args.creator_team,
            created_by_role=args.creator_role,
            change_reason=args.change_reason,
            team_name=args.team,
            timezone_name=args.timezone,
            weekdays=args.weekdays,
            start_time=args.start_time,
            end_time=args.end_time,
            priority=args.priority,
            rotation_name=args.rotation,
            effective_start_date=args.effective_start_date,
            effective_end_date=args.effective_end_date,
            webhook_url=args.webhook_url,
            escalation_webhook_url=args.escalation_webhook_url,
        )
    if args.command == "list-control-plane-oncall-change-requests":
        return run_list_control_plane_oncall_change_requests(status=args.status)
    if args.command == "review-control-plane-oncall-change-request":
        return run_review_control_plane_oncall_change_request(
            request_id=args.request_id,
            decision=args.decision,
            reviewed_by=args.by,
            reviewed_by_team=args.reviewer_team,
            reviewed_by_role=args.reviewer_role,
            review_note=args.note,
        )
    if args.command == "assign-control-plane-oncall-change-request":
        return run_assign_control_plane_oncall_change_request(
            request_id=args.request_id,
            assigned_to=args.assigned_to,
            assigned_to_team=args.assigned_team,
            assigned_by=args.by,
            assignment_note=args.note,
        )
    if args.command == "list-control-plane-oncall-schedules":
        return run_list_control_plane_oncall_schedules(active_only=args.active_only)
    if args.command == "resolve-control-plane-oncall-route":
        return run_resolve_control_plane_oncall_route(at=args.at)
    if args.command == "cancel-control-plane-oncall-schedule":
        return run_cancel_control_plane_oncall_schedule(
            schedule_id=args.schedule_id,
            cancelled_by=args.by,
        )
    if args.command == "control-plane-schema":
        return run_control_plane_schema()
    if args.command == "migrate-control-plane-schema":
        return run_migrate_control_plane_schema()
    if args.command == "export-control-plane-backup":
        return run_export_control_plane_backup(output_path=args.out)
    if args.command == "import-control-plane-backup":
        return run_import_control_plane_backup(
            input_path=args.input_path,
            replace_existing=args.replace_existing,
        )
    if args.command == "prune-history":
        return run_prune_history()
    parser.error(f"Unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
