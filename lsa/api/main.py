from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException, Header
from fastapi import Query

from lsa.api.models import (
    AcknowledgeControlPlaneAlertRequest,
    AuditRecordPayload,
    AuditRequest,
    AuditResponse,
    AuditTraceRequest,
    CancelControlPlaneAlertSilenceRequest,
    CancelControlPlaneOnCallScheduleRequest,
    CollectAuditRequest,
    CollectAuditResponse,
    CollectTraceRequest,
    CollectTraceResponse,
    ControlPlaneAnalyticsResponse,
    ControlPlaneAlertRecordPayload,
    ControlPlaneAlertSilencePayload,
    ControlPlaneOnCallChangeRequestPayload,
    ControlPlaneOnCallRouteResolutionPayload,
    ControlPlaneOnCallSchedulePayload,
    CreateControlPlaneAlertSilenceRequest,
    CreateControlPlaneOnCallChangeRequest,
    CreateControlPlaneOnCallScheduleRequest,
    EmitControlPlaneAlertsResponse,
    HealthResponse,
    IngestRequest,
    IngestResponse,
    JobLeaseEventPayload,
    JobLeaseEventRollupPayload,
    JobRecordPayload,
    PruneHistoryResponse,
    ReviewControlPlaneOnCallChangeRequest,
    SnapshotRecordPayload,
    WorkerHeartbeatPayload,
    WorkerHeartbeatRollupPayload,
    WorkerRecordPayload,
)
from lsa.core.intent_graph import IntentGraph
from lsa.drift.comparator import DriftComparator
from lsa.drift.models import ObservedEvent
from lsa.drift.trace_parser import load_trace_events
from lsa.remediation.llm_client import RuleBasedLLMClient
from lsa.services.audit_service import AuditService
from lsa.services.analytics_service import AnalyticsService, ControlPlaneAlertThresholds
from lsa.services.control_plane_alert_service import ControlPlaneAlertService
from lsa.services.ingest_service import IngestService
from lsa.services.job_service import JobService
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
job_service = JobService(
    job_repository=job_repository,
    audit_service=audit_service,
    trace_collection_service=trace_collection_service,
    worker_mode="embedded",
    heartbeat_timeout_seconds=settings.worker_heartbeat_timeout_seconds,
    worker_history_retention_days=settings.worker_history_retention_days,
    job_lease_history_retention_days=settings.job_lease_history_retention_days,
    history_prune_interval_seconds=settings.history_prune_interval_seconds,
    control_plane_alert_service=control_plane_alert_service,
    control_plane_alert_interval_seconds=settings.control_plane_alert_interval_seconds,
    control_plane_alerts_enabled=settings.control_plane_alerts_enabled,
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.run_embedded_worker:
        job_service.start()
    try:
        yield
    finally:
        if settings.run_embedded_worker:
            job_service.stop()


app = FastAPI(title="Living Systems Auditor API", version="0.1.0", lifespan=lifespan)


def _parse_timestamp_query(raw_value: str | None) -> datetime | None:
    if raw_value is None:
        return None
    try:
        parsed = datetime.fromisoformat(raw_value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Timestamp must use ISO 8601 format.") from exc
    if parsed.tzinfo is None:
        raise HTTPException(status_code=400, detail="Timestamp must include a timezone offset.")
    return parsed


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    active_workers = job_service.active_worker_count()
    return HealthResponse(
        status="ok",
        environment_name=settings.environment_name,
        auth_enabled=settings.api_key is not None,
        worker_mode="embedded" if settings.run_embedded_worker else "external",
        database_path=str(settings.database_path),
        database_ready=settings.database_path.exists(),
        worker_running=active_workers > 0 if not settings.run_embedded_worker else job_service.is_worker_running(),
        active_workers=active_workers,
        queued_jobs=job_service.count_jobs_by_status("queued"),
        running_jobs=job_service.count_jobs_by_status("running"),
        snapshots_dir=str(settings.snapshots_dir),
        audits_dir=str(settings.audits_dir),
        reports_dir=str(settings.reports_dir),
        traces_dir=str(settings.traces_dir),
    )


def require_api_key(
    x_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> None:
    if settings.api_key is None:
        return
    if x_api_key == settings.api_key:
        return
    if authorization is not None and authorization.startswith("Bearer "):
        if authorization[len("Bearer ") :].strip() == settings.api_key:
            return
    raise HTTPException(status_code=401, detail="Valid API key required.")


@app.get("/snapshots", response_model=list[SnapshotRecordPayload], dependencies=[Depends(require_api_key)])
async def list_snapshots() -> list[SnapshotRecordPayload]:
    return [SnapshotRecordPayload(**record.to_dict()) for record in snapshot_repository.list()]


@app.get("/snapshots/{snapshot_id}", response_model=SnapshotRecordPayload, dependencies=[Depends(require_api_key)])
async def get_snapshot(snapshot_id: str) -> SnapshotRecordPayload:
    try:
        record = snapshot_repository.get(snapshot_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"Snapshot '{snapshot_id}' was not found.") from exc
    return SnapshotRecordPayload(**record.to_dict())


@app.get("/audits", response_model=list[AuditRecordPayload], dependencies=[Depends(require_api_key)])
async def list_audits() -> list[AuditRecordPayload]:
    return [AuditRecordPayload(**record.to_dict()) for record in audit_repository.list()]


@app.get("/audits/{audit_id}", response_model=AuditRecordPayload, dependencies=[Depends(require_api_key)])
async def get_audit(audit_id: str) -> AuditRecordPayload:
    try:
        record = audit_repository.get(audit_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"Audit '{audit_id}' was not found.") from exc
    return AuditRecordPayload(**record.to_dict())


@app.get("/jobs", response_model=list[JobRecordPayload], dependencies=[Depends(require_api_key)])
async def list_jobs() -> list[JobRecordPayload]:
    return [JobRecordPayload(**record.to_dict()) for record in job_service.list_jobs()]


@app.get("/jobs/{job_id}", response_model=JobRecordPayload, dependencies=[Depends(require_api_key)])
async def get_job(job_id: str) -> JobRecordPayload:
    try:
        record = job_service.get_job(job_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' was not found.") from exc
    return JobRecordPayload(**record.to_dict())


@app.get("/jobs/{job_id}/lease-events", response_model=list[JobLeaseEventPayload], dependencies=[Depends(require_api_key)])
async def list_job_lease_events(job_id: str) -> list[JobLeaseEventPayload]:
    try:
        job_service.get_job(job_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' was not found.") from exc
    return [JobLeaseEventPayload(**record.to_dict()) for record in job_service.list_job_lease_events(job_id)]


@app.get("/jobs/{job_id}/lease-event-rollups", response_model=list[JobLeaseEventRollupPayload], dependencies=[Depends(require_api_key)])
async def list_job_lease_event_rollups(job_id: str) -> list[JobLeaseEventRollupPayload]:
    try:
        job_service.get_job(job_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' was not found.") from exc
    return [JobLeaseEventRollupPayload(**record.to_dict()) for record in job_repository.list_job_lease_event_rollups(job_id)]


@app.get("/workers", response_model=list[WorkerRecordPayload], dependencies=[Depends(require_api_key)])
async def list_workers() -> list[WorkerRecordPayload]:
    return [WorkerRecordPayload(**record.to_dict()) for record in job_service.list_workers()]


@app.get("/workers/{worker_id}", response_model=WorkerRecordPayload, dependencies=[Depends(require_api_key)])
async def get_worker(worker_id: str) -> WorkerRecordPayload:
    try:
        record = job_service.get_worker(worker_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"Worker '{worker_id}' was not found.") from exc
    return WorkerRecordPayload(**record.to_dict())


@app.get("/workers/{worker_id}/heartbeats", response_model=list[WorkerHeartbeatPayload], dependencies=[Depends(require_api_key)])
async def list_worker_heartbeats(worker_id: str) -> list[WorkerHeartbeatPayload]:
    try:
        job_service.get_worker(worker_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"Worker '{worker_id}' was not found.") from exc
    return [WorkerHeartbeatPayload(**record.to_dict()) for record in job_service.list_worker_heartbeats(worker_id)]


@app.get("/workers/{worker_id}/heartbeat-rollups", response_model=list[WorkerHeartbeatRollupPayload], dependencies=[Depends(require_api_key)])
async def list_worker_heartbeat_rollups(worker_id: str) -> list[WorkerHeartbeatRollupPayload]:
    try:
        job_service.get_worker(worker_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"Worker '{worker_id}' was not found.") from exc
    return [WorkerHeartbeatRollupPayload(**record.to_dict()) for record in job_repository.list_worker_heartbeat_rollups(worker_id)]


@app.post("/maintenance/prune-history", response_model=PruneHistoryResponse, dependencies=[Depends(require_api_key)])
async def prune_history() -> PruneHistoryResponse:
    result = job_service.prune_history(force=True)
    return PruneHistoryResponse(**result)


@app.post(
    "/maintenance/emit-control-plane-alerts",
    response_model=EmitControlPlaneAlertsResponse,
    dependencies=[Depends(require_api_key)],
)
async def emit_control_plane_alerts() -> EmitControlPlaneAlertsResponse:
    alerts = job_service.emit_control_plane_alerts(force=True)
    return EmitControlPlaneAlertsResponse(
        emitted_count=len(alerts),
        alerts=[ControlPlaneAlertRecordPayload(**record.to_dict()) for record in alerts],
    )


@app.post(
    "/maintenance/process-control-plane-alert-followups",
    response_model=EmitControlPlaneAlertsResponse,
    dependencies=[Depends(require_api_key)],
)
async def process_control_plane_alert_followups() -> EmitControlPlaneAlertsResponse:
    alerts = job_service.process_control_plane_alert_follow_ups(force=True)
    return EmitControlPlaneAlertsResponse(
        emitted_count=len(alerts),
        alerts=[ControlPlaneAlertRecordPayload(**record.to_dict()) for record in alerts],
    )


@app.get(
    "/analytics/control-plane",
    response_model=ControlPlaneAnalyticsResponse,
    dependencies=[Depends(require_api_key)],
)
async def get_control_plane_analytics(days: int = Query(default=30, ge=1, le=365)) -> ControlPlaneAnalyticsResponse:
    report = analytics_service.build_control_plane_analytics(days=days)
    return ControlPlaneAnalyticsResponse(**report.to_dict())


@app.get(
    "/control-plane-alerts",
    response_model=list[ControlPlaneAlertRecordPayload],
    dependencies=[Depends(require_api_key)],
)
async def list_control_plane_alerts(limit: int = Query(default=50, ge=1, le=500)) -> list[ControlPlaneAlertRecordPayload]:
    return [ControlPlaneAlertRecordPayload(**record.to_dict()) for record in job_service.list_control_plane_alerts(limit)]


@app.post(
    "/control-plane-alerts/{alert_id}/acknowledge",
    response_model=ControlPlaneAlertRecordPayload,
    dependencies=[Depends(require_api_key)],
)
async def acknowledge_control_plane_alert(
    alert_id: str,
    request: AcknowledgeControlPlaneAlertRequest,
) -> ControlPlaneAlertRecordPayload:
    try:
        record = job_service.acknowledge_control_plane_alert(
            alert_id=alert_id,
            acknowledged_by=request.acknowledged_by,
            acknowledgement_note=request.acknowledgement_note,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"Control-plane alert '{alert_id}' was not found.") from exc
    return ControlPlaneAlertRecordPayload(**record.to_dict())


@app.get(
    "/control-plane-alert-silences",
    response_model=list[ControlPlaneAlertSilencePayload],
    dependencies=[Depends(require_api_key)],
)
async def list_control_plane_alert_silences(
    active_only: bool = Query(default=False),
) -> list[ControlPlaneAlertSilencePayload]:
    return [
        ControlPlaneAlertSilencePayload(**record.to_dict())
        for record in job_service.list_control_plane_alert_silences(active_only=active_only)
    ]


@app.post(
    "/control-plane-alert-silences",
    response_model=ControlPlaneAlertSilencePayload,
    dependencies=[Depends(require_api_key)],
)
async def create_control_plane_alert_silence(
    request: CreateControlPlaneAlertSilenceRequest,
) -> ControlPlaneAlertSilencePayload:
    record = job_service.create_control_plane_alert_silence(
        created_by=request.created_by,
        reason=request.reason,
        duration_minutes=request.duration_minutes,
        match_alert_key=request.match_alert_key,
        match_finding_code=request.match_finding_code,
    )
    return ControlPlaneAlertSilencePayload(**record.to_dict())


@app.post(
    "/control-plane-alert-silences/{silence_id}/cancel",
    response_model=ControlPlaneAlertSilencePayload,
    dependencies=[Depends(require_api_key)],
)
async def cancel_control_plane_alert_silence(
    silence_id: str,
    request: CancelControlPlaneAlertSilenceRequest,
) -> ControlPlaneAlertSilencePayload:
    try:
        record = job_service.cancel_control_plane_alert_silence(
            silence_id=silence_id,
            cancelled_by=request.cancelled_by,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"Control-plane alert silence '{silence_id}' was not found.") from exc
    return ControlPlaneAlertSilencePayload(**record.to_dict())


@app.get(
    "/control-plane-oncall-change-requests",
    response_model=list[ControlPlaneOnCallChangeRequestPayload],
    dependencies=[Depends(require_api_key)],
)
async def list_control_plane_oncall_change_requests(
    status: str | None = Query(default=None),
) -> list[ControlPlaneOnCallChangeRequestPayload]:
    return [
        ControlPlaneOnCallChangeRequestPayload(**record.to_dict())
        for record in control_plane_alert_service.list_oncall_change_requests(status=status)
    ]


@app.get(
    "/control-plane-oncall-change-requests/{request_id}",
    response_model=ControlPlaneOnCallChangeRequestPayload,
    dependencies=[Depends(require_api_key)],
)
async def get_control_plane_oncall_change_request(
    request_id: str,
) -> ControlPlaneOnCallChangeRequestPayload:
    try:
        record = control_plane_alert_service.get_oncall_change_request(request_id)
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=f"Control-plane on-call change request '{request_id}' was not found.",
        ) from exc
    return ControlPlaneOnCallChangeRequestPayload(**record.to_dict())


@app.post(
    "/control-plane-oncall-change-requests",
    response_model=ControlPlaneOnCallChangeRequestPayload,
    dependencies=[Depends(require_api_key)],
)
async def create_control_plane_oncall_change_request(
    request: CreateControlPlaneOnCallChangeRequest,
) -> ControlPlaneOnCallChangeRequestPayload:
    try:
        record = control_plane_alert_service.submit_oncall_change_request(
            created_by=request.created_by,
            environment_name=request.environment_name,
            created_by_team=request.created_by_team,
            created_by_role=request.created_by_role,
            change_reason=request.change_reason,
            team_name=request.team_name,
            timezone_name=request.timezone_name,
            weekdays=request.weekdays,
            start_time=request.start_time,
            end_time=request.end_time,
            priority=request.priority,
            rotation_name=request.rotation_name,
            effective_start_date=request.effective_start_date,
            effective_end_date=request.effective_end_date,
            webhook_url=request.webhook_url,
            escalation_webhook_url=request.escalation_webhook_url,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ControlPlaneOnCallChangeRequestPayload(**record.to_dict())


@app.post(
    "/control-plane-oncall-change-requests/{request_id}/review",
    response_model=ControlPlaneOnCallChangeRequestPayload,
    dependencies=[Depends(require_api_key)],
)
async def review_control_plane_oncall_change_request(
    request_id: str,
    request: ReviewControlPlaneOnCallChangeRequest,
) -> ControlPlaneOnCallChangeRequestPayload:
    try:
        record = control_plane_alert_service.review_oncall_change_request(
            request_id=request_id,
            decision=request.decision,
            reviewed_by=request.reviewed_by,
            reviewed_by_team=request.reviewed_by_team,
            reviewed_by_role=request.reviewed_by_role,
            review_note=request.review_note,
        )
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=f"Control-plane on-call change request '{request_id}' was not found.",
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ControlPlaneOnCallChangeRequestPayload(**record.to_dict())


@app.get(
    "/control-plane-oncall-schedules",
    response_model=list[ControlPlaneOnCallSchedulePayload],
    dependencies=[Depends(require_api_key)],
)
async def list_control_plane_oncall_schedules(
    active_only: bool = Query(default=False),
) -> list[ControlPlaneOnCallSchedulePayload]:
    return [
        ControlPlaneOnCallSchedulePayload(**record.to_dict())
        for record in control_plane_alert_service.list_oncall_schedules(active_only=active_only)
    ]


@app.get(
    "/control-plane-oncall-schedules/resolve",
    response_model=ControlPlaneOnCallRouteResolutionPayload,
    dependencies=[Depends(require_api_key)],
)
async def resolve_control_plane_oncall_schedule(
    at: str | None = Query(default=None),
) -> ControlPlaneOnCallRouteResolutionPayload:
    preview = control_plane_alert_service.preview_oncall_route(
        reference_timestamp=_parse_timestamp_query(at),
    )
    return ControlPlaneOnCallRouteResolutionPayload(**preview)


@app.post(
    "/control-plane-oncall-schedules",
    response_model=ControlPlaneOnCallSchedulePayload,
    dependencies=[Depends(require_api_key)],
)
async def create_control_plane_oncall_schedule(
    request: CreateControlPlaneOnCallScheduleRequest,
) -> ControlPlaneOnCallSchedulePayload:
    try:
        record = control_plane_alert_service.create_oncall_schedule(
            created_by=request.created_by,
            environment_name=request.environment_name,
            created_by_team=request.created_by_team,
            created_by_role=request.created_by_role,
            change_reason=request.change_reason,
            approved_by=request.approved_by,
            approved_by_team=request.approved_by_team,
            approved_by_role=request.approved_by_role,
            approval_note=request.approval_note,
            team_name=request.team_name,
            timezone_name=request.timezone_name,
            weekdays=request.weekdays,
            start_time=request.start_time,
            end_time=request.end_time,
            priority=request.priority,
            rotation_name=request.rotation_name,
            effective_start_date=request.effective_start_date,
            effective_end_date=request.effective_end_date,
            webhook_url=request.webhook_url,
            escalation_webhook_url=request.escalation_webhook_url,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ControlPlaneOnCallSchedulePayload(**record.to_dict())


@app.post(
    "/control-plane-oncall-schedules/{schedule_id}/cancel",
    response_model=ControlPlaneOnCallSchedulePayload,
    dependencies=[Depends(require_api_key)],
)
async def cancel_control_plane_oncall_schedule(
    schedule_id: str,
    request: CancelControlPlaneOnCallScheduleRequest,
) -> ControlPlaneOnCallSchedulePayload:
    try:
        record = control_plane_alert_service.cancel_oncall_schedule(
            schedule_id=schedule_id,
            cancelled_by=request.cancelled_by,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"Control-plane on-call schedule '{schedule_id}' was not found.") from exc
    return ControlPlaneOnCallSchedulePayload(**record.to_dict())


@app.post("/ingest", response_model=IngestResponse, dependencies=[Depends(require_api_key)])
async def ingest_codebase(request: IngestRequest) -> IngestResponse:
    result = ingest_service.ingest(
        request.repo_path,
        persist=request.persist,
        output_path=request.output_path,
        snapshot_id=request.snapshot_id,
    )
    return IngestResponse(
        node_count=result.snapshot.node_count,
        edge_count=result.snapshot.edge_count,
        snapshot_path=result.snapshot_path,
        snapshot_id=result.record.snapshot_id if result.record else None,
        created_at=result.record.created_at if result.record else None,
    )


@app.post("/audit", response_model=AuditResponse, dependencies=[Depends(require_api_key)])
async def audit_runtime(request: AuditRequest) -> AuditResponse:
    try:
        result = audit_service.audit(
            snapshot_id=request.snapshot_id,
            snapshot_path=request.snapshot_path,
            events=[ObservedEvent.from_dict(item.model_dump()) for item in request.events],
            persist=request.persist,
            report_dir=request.report_dir,
            audit_id=request.audit_id,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Snapshot reference could not be resolved.") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AuditResponse(
        alert_count=len(result.alerts),
        report_paths=result.report_paths,
        alerts=[alert.to_dict() for alert in result.alerts],
        sessions=[session.to_dict() for session in result.sessions],
        explanation=result.explanation.to_dict(),
        audit_id=result.record.audit_id if result.record else None,
        snapshot_id=result.snapshot_record.snapshot_id if result.snapshot_record else None,
        snapshot_path=result.snapshot_path or "",
    )


@app.post("/audit-trace", response_model=AuditResponse, dependencies=[Depends(require_api_key)])
async def audit_trace(request: AuditTraceRequest) -> AuditResponse:
    try:
        trace_events = load_trace_events(request.trace_path, trace_format=request.trace_format)
        result = audit_service.audit(
            snapshot_id=request.snapshot_id,
            snapshot_path=request.snapshot_path,
            events=trace_events,
            persist=request.persist,
            report_dir=request.report_dir,
            audit_id=request.audit_id,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Snapshot or trace path could not be resolved.") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AuditResponse(
        alert_count=len(result.alerts),
        report_paths=result.report_paths,
        alerts=[alert.to_dict() for alert in result.alerts],
        sessions=[session.to_dict() for session in result.sessions],
        explanation=result.explanation.to_dict(),
        audit_id=result.record.audit_id if result.record else None,
        snapshot_id=result.snapshot_record.snapshot_id if result.snapshot_record else None,
        snapshot_path=result.snapshot_path or "",
    )


@app.post("/jobs/audit-trace", response_model=JobRecordPayload, status_code=202, dependencies=[Depends(require_api_key)])
async def submit_audit_trace_job(request: AuditTraceRequest) -> JobRecordPayload:
    job = job_service.submit_audit_trace(request.model_dump())
    return JobRecordPayload(**job.to_dict())


@app.post("/collect-trace", response_model=CollectTraceResponse, dependencies=[Depends(require_api_key)])
async def collect_trace(request: CollectTraceRequest) -> CollectTraceResponse:
    try:
        result = trace_collection_service.collect(_build_trace_collection_request(request))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Collector program or symbol map path could not be resolved.") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return CollectTraceResponse(
        command=result.command,
        trace_path=result.trace_path,
        trace_metadata_path=result.metadata_path,
        trace_symbol_map_path=result.symbol_map_path,
        trace_context_map_path=result.context_map_path,
        line_count=result.line_count,
        return_code=result.return_code,
    )


@app.post("/jobs/collect-audit", response_model=JobRecordPayload, status_code=202, dependencies=[Depends(require_api_key)])
async def submit_collect_audit_job(request: CollectAuditRequest) -> JobRecordPayload:
    job = job_service.submit_collect_audit(request.model_dump())
    return JobRecordPayload(**job.to_dict())


@app.post("/collect-audit", response_model=CollectAuditResponse, dependencies=[Depends(require_api_key)])
async def collect_audit(request: CollectAuditRequest) -> CollectAuditResponse:
    try:
        observation = trace_collection_service.collect(_build_trace_collection_request(request))
        result = audit_service.audit(
            snapshot_id=request.snapshot_id,
            snapshot_path=request.snapshot_path,
            events=load_trace_events(observation.trace_path, trace_format=request.trace_format),
            persist=request.persist,
            audit_id=request.audit_id,
        )
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail="Snapshot, collector program, trace, or symbol map path could not be resolved.",
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return CollectAuditResponse(
        trace_path=observation.trace_path,
        trace_metadata_path=observation.metadata_path,
        trace_symbol_map_path=observation.symbol_map_path,
        trace_context_map_path=observation.context_map_path,
        line_count=observation.line_count,
        alert_count=len(result.alerts),
        report_paths=result.report_paths,
        alerts=[alert.to_dict() for alert in result.alerts],
        sessions=[session.to_dict() for session in result.sessions],
        explanation=result.explanation.to_dict(),
        audit_id=result.record.audit_id if result.record else None,
        snapshot_id=result.snapshot_record.snapshot_id if result.snapshot_record else None,
        snapshot_path=result.snapshot_path or "",
    )


def _build_trace_collection_request(
    request: CollectTraceRequest | CollectAuditRequest,
) -> TraceCollectionRequest:
    return TraceCollectionRequest(
        pid=request.pid,
        program_path=request.program,
        output_path=request.output_path,
        duration_seconds=request.duration,
        max_events=request.max_events,
        symbol_map_path=request.symbol_map_path,
        context_map_path=request.context_map_path,
        command=None if request.program.endswith(".bt") else ["/bin/sh", request.program],
    )
