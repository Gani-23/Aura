from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime
import json

from fastapi import Depends, FastAPI, HTTPException, Header
from fastapi import Query
from fastapi.responses import PlainTextResponse

from lsa.api.models import (
    AcknowledgeControlPlaneAlertRequest,
    AssignRuntimeValidationReviewRequest,
    AssignControlPlaneOnCallChangeRequest,
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
    ControlPlaneBackupResponse,
    ControlPlaneAnalyticsResponse,
    ControlPlaneAlertRecordPayload,
    ControlPlaneAlertSilencePayload,
    ControlPlaneCutoverPreflightResponse,
    ControlPlaneCutoverPromotionResponse,
    ControlPlaneCutoverReadinessResponse,
    ControlPlaneMaintenanceEventPayload,
    ControlPlaneMaintenancePreflightResponse,
    ControlPlaneRuntimeRehearsalResponse,
    ControlPlaneOnCallChangeRequestPayload,
    ControlPlaneOnCallRouteResolutionPayload,
    ControlPlaneOnCallSchedulePayload,
    ControlPlaneMaintenanceModeResponse,
    ControlPlaneSchemaContractResponse,
    ControlPlaneSchemaStatusResponse,
    ControlPlaneRuntimeBackendResponse,
    ControlPlaneRuntimeSmokeResponse,
    ControlPlaneRuntimeValidationResponse,
    ControlPlaneRuntimeValidationReviewPayload,
    CreateControlPlaneAlertSilenceRequest,
    CreateControlPlaneOnCallChangeRequest,
    CreateControlPlaneOnCallScheduleRequest,
    BuildPostgresBootstrapExecutionPlanRequest,
    DecideControlPlaneCutoverRequest,
    EmitControlPlaneAlertsResponse,
    EvaluateControlPlaneCutoverReadinessRequest,
    ExecutePostgresBootstrapPackageRequest,
    ExecutePostgresBootstrapPackageResponse,
    ExportControlPlaneBackupRequest,
    HealthResponse,
    IngestRequest,
    IngestResponse,
    ImportControlPlaneBackupRequest,
    InspectControlPlaneRuntimeBackendRequest,
    JobLeaseEventPayload,
    JobLeaseEventRollupPayload,
    JobRecordPayload,
    InspectPostgresTargetRequest,
    InspectPostgresBootstrapPackageRequest,
    PostgresBootstrapExecutionPlanResponse,
    PostgresBootstrapPackageInspectionResponse,
    PostgresCutoverRehearsalResponse,
    PostgresRuntimeShadowSyncResponse,
    PostgresTargetInspectionResponse,
    ProcessRuntimeValidationReviewsRequest,
    PruneHistoryResponse,
    PrepareControlPlaneCutoverBundleRequest,
    PrepareControlPlaneCutoverBundleResponse,
    ReviewControlPlaneOnCallChangeRequest,
    ResolveRuntimeValidationReviewRequest,
    RunPostgresCutoverRehearsalRequest,
    RunControlPlaneMaintenanceWorkflowRequest,
    RunControlPlaneMaintenanceWorkflowResponse,
    RunControlPlaneRuntimeRehearsalRequest,
    RunControlPlaneRuntimeSmokeRequest,
    SetControlPlaneMaintenanceModeRequest,
    SnapshotRecordPayload,
    SyncPostgresRuntimeShadowRequest,
    VerifyPostgresBootstrapPackageRequest,
    VerifyPostgresBootstrapPackageResponse,
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
from lsa.services.control_plane_backup_service import ControlPlaneBackupService
from lsa.services.control_plane_cutover_promotion_service import ControlPlaneCutoverPromotionService
from lsa.services.control_plane_cutover_service import ControlPlaneCutoverService
from lsa.services.control_plane_cutover_readiness_service import ControlPlaneCutoverReadinessService
from lsa.services.control_plane_maintenance_service import ControlPlaneMaintenanceService
from lsa.services.control_plane_runtime_rehearsal_service import ControlPlaneRuntimeRehearsalService
from lsa.services.control_plane_runtime_smoke_service import ControlPlaneRuntimeSmokeService
from lsa.services.control_plane_runtime_validation_service import ControlPlaneRuntimeValidationService
from lsa.services.control_plane_runtime_validation_review_service import (
    ControlPlaneRuntimeValidationReviewService,
)
from lsa.services.ingest_service import IngestService
from lsa.services.job_service import JobService
from lsa.services.metrics_service import ControlPlaneMetricsService
from lsa.services.postgres_bootstrap_service import PostgresBootstrapService
from lsa.services.postgres_cutover_rehearsal_service import PostgresCutoverRehearsalService
from lsa.services.postgres_runtime_shadow_service import PostgresRuntimeShadowService
from lsa.services.postgres_target_service import PostgresTargetService
from lsa.services.runtime_validation_policy import RuntimeValidationPolicy, load_runtime_validation_policy_bundle
from lsa.services.trace_collection_service import TraceCollectionRequest, TraceCollectionService
from lsa.settings import resolve_workspace_settings
from lsa.storage.files import AuditRepository, JobRepository, SnapshotRepository, build_control_plane_runtime_bundle
from lsa.storage.database import inspect_database_runtime_support


settings = resolve_workspace_settings()
graph = IntentGraph()
runtime_bundle = build_control_plane_runtime_bundle(settings, graph=graph)
snapshot_repository = runtime_bundle.snapshot_repository
audit_repository = runtime_bundle.audit_repository
job_repository = runtime_bundle.job_repository
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
        runtime_rehearsal_due_soon_age_hours=settings.analytics_runtime_rehearsal_due_soon_age_hours,
        runtime_rehearsal_warning_age_hours=settings.analytics_runtime_rehearsal_warning_age_hours,
        runtime_rehearsal_critical_age_hours=settings.analytics_runtime_rehearsal_critical_age_hours,
    ),
    runtime_validation_policy_path=str(settings.runtime_validation_policy_path),
    runtime_validation_reminder_interval_seconds=settings.control_plane_alert_reminder_interval_seconds,
    runtime_validation_escalation_interval_seconds=settings.control_plane_alert_escalation_interval_seconds,
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
    runtime_validation_policy_path=str(settings.runtime_validation_policy_path),
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
    worker_mode="embedded",
    heartbeat_timeout_seconds=settings.worker_heartbeat_timeout_seconds,
    worker_history_retention_days=settings.worker_history_retention_days,
    job_lease_history_retention_days=settings.job_lease_history_retention_days,
    history_prune_interval_seconds=settings.history_prune_interval_seconds,
    control_plane_alert_service=control_plane_alert_service,
    control_plane_alert_interval_seconds=settings.control_plane_alert_interval_seconds,
    control_plane_alerts_enabled=settings.control_plane_alerts_enabled,
)
runtime_validation_review_service = ControlPlaneRuntimeValidationReviewService(
    settings=settings,
    job_service=job_service,
    job_repository=job_repository,
)
job_service.runtime_validation_review_service = runtime_validation_review_service
control_plane_alert_service.runtime_validation_review_service = runtime_validation_review_service
metrics_service = ControlPlaneMetricsService(
    job_repository=job_repository,
    job_service=job_service,
    analytics_service=analytics_service,
    environment_name=settings.environment_name,
    worker_mode="embedded" if settings.run_embedded_worker else "external",
)
control_plane_maintenance_service = ControlPlaneMaintenanceService(
    settings=settings,
    job_repository=job_repository,
    job_service=job_service,
    backup_service=control_plane_backup_service,
    worker_mode="embedded" if settings.run_embedded_worker else "external",
)
control_plane_cutover_service = ControlPlaneCutoverService(
    settings=settings,
    maintenance_service=control_plane_maintenance_service,
)
postgres_bootstrap_service = PostgresBootstrapService()
postgres_target_service = PostgresTargetService(bootstrap_service=postgres_bootstrap_service)
def _postgres_cutover_rehearsal_service() -> PostgresCutoverRehearsalService:
    return PostgresCutoverRehearsalService(
        job_service=job_service,
        bootstrap_service=postgres_bootstrap_service,
        target_service=postgres_target_service,
    )


def _control_plane_cutover_readiness_service() -> ControlPlaneCutoverReadinessService:
    return ControlPlaneCutoverReadinessService(
        settings=settings,
        job_repository=job_repository,
        bootstrap_service=postgres_bootstrap_service,
    )


def _control_plane_cutover_promotion_service() -> ControlPlaneCutoverPromotionService:
    return ControlPlaneCutoverPromotionService(
        settings=settings,
        job_service=job_service,
        readiness_service=_control_plane_cutover_readiness_service(),
    )


def _control_plane_runtime_smoke_service() -> ControlPlaneRuntimeSmokeService:
    snapshot_backend = str(snapshot_repository.database.config.backend)
    audit_backend = str(audit_repository.database.config.backend)
    job_backend = str(job_repository.database.config.backend)
    backends = {snapshot_backend, audit_backend, job_backend}
    return ControlPlaneRuntimeSmokeService(
        settings=settings,
        snapshot_repository=snapshot_repository,
        audit_repository=audit_repository,
        job_repository=job_repository,
        job_service=job_service,
        repository_layout="mixed" if len(backends) > 1 else "shared",
        mixed_backends=len(backends) > 1,
        now_factory=lambda: datetime.now().astimezone().isoformat(),
    )


def _control_plane_runtime_rehearsal_service() -> ControlPlaneRuntimeRehearsalService:
    return ControlPlaneRuntimeRehearsalService(
        settings=settings,
        job_repository=job_repository,
        job_service=job_service,
        runtime_smoke_service=_control_plane_runtime_smoke_service(),
        now_factory=lambda: datetime.now().astimezone().isoformat(),
    )


def _control_plane_runtime_validation_service() -> ControlPlaneRuntimeValidationService:
    runtime_policy_bundle = load_runtime_validation_policy_bundle(settings.runtime_validation_policy_path)
    runtime_policy = runtime_policy_bundle.resolve(
        environment_name=settings.environment_name,
        fallback=RuntimeValidationPolicy(
            due_soon_age_hours=settings.analytics_runtime_rehearsal_due_soon_age_hours,
            warning_age_hours=settings.analytics_runtime_rehearsal_warning_age_hours,
            critical_age_hours=settings.analytics_runtime_rehearsal_critical_age_hours,
            reminder_interval_seconds=settings.control_plane_alert_reminder_interval_seconds,
            escalation_interval_seconds=settings.control_plane_alert_escalation_interval_seconds,
        ),
    )
    return ControlPlaneRuntimeValidationService(
        job_repository=job_repository,
        environment_name=settings.environment_name,
        due_soon_age_hours=runtime_policy.due_soon_age_hours
        or settings.analytics_runtime_rehearsal_due_soon_age_hours,
        warning_age_hours=runtime_policy.warning_age_hours
        or settings.analytics_runtime_rehearsal_warning_age_hours,
        critical_age_hours=runtime_policy.critical_age_hours
        or settings.analytics_runtime_rehearsal_critical_age_hours,
        policy_source=runtime_policy_bundle.source_for(environment_name=settings.environment_name),
        reminder_interval_seconds=runtime_policy.reminder_interval_seconds,
        escalation_interval_seconds=runtime_policy.escalation_interval_seconds,
    )


def _postgres_runtime_shadow_service() -> PostgresRuntimeShadowService:
    return PostgresRuntimeShadowService(
        settings=settings,
        source_job_repository=job_repository,
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
    database_status = job_repository.database_status()
    maintenance_mode = job_repository.maintenance_mode_status()
    snapshot_backend = str(snapshot_repository.database.config.backend)
    audit_backend = str(audit_repository.database.config.backend)
    job_backend = str(job_repository.database.config.backend)
    repository_backends = {snapshot_backend, audit_backend, job_backend}
    return HealthResponse(
        status="ok",
        environment_name=settings.environment_name,
        auth_enabled=settings.api_key is not None,
        worker_mode="embedded" if settings.run_embedded_worker else "external",
        database_backend=str(database_status["backend"]),
        database_url=str(database_status["url"]),
        database_path=str(database_status["path"]),
        snapshot_repository_backend=snapshot_backend,
        audit_repository_backend=audit_backend,
        job_repository_backend=job_backend,
        control_plane_repository_layout="mixed" if len(repository_backends) > 1 else "shared",
        control_plane_mixed_backends=len(repository_backends) > 1,
        snapshots_audits_repository_runtime_enabled=settings.enable_postgres_runtime_snapshots_audits,
        snapshots_audits_repository_runtime_active=(
            snapshot_backend == "postgres" and audit_backend == "postgres"
        ),
        job_repository_runtime_enabled=settings.enable_postgres_runtime_jobs,
        job_repository_runtime_active=bool(
            settings.enable_postgres_runtime_jobs and job_repository.database.config.backend == "postgres"
        ),
        database_runtime_supported=bool(database_status["runtime_supported"]),
        database_runtime_driver=str(database_status["runtime_driver"]),
        database_runtime_dependency_installed=bool(database_status["runtime_dependency_installed"]),
        database_runtime_available=bool(database_status["runtime_available"]),
        database_runtime_blockers=[str(item) for item in database_status["runtime_blockers"]],
        database_ready=bool(database_status["ready"]),
        database_writable=bool(database_status["writable"]),
        database_schema_version=int(database_status["schema_version"]),
        database_expected_schema_version=int(database_status["expected_schema_version"]),
        database_schema_ready=bool(database_status["schema_ready"]),
        database_pending_migration_count=int(database_status["pending_migration_count"]),
        maintenance_mode_active=bool(maintenance_mode["active"]),
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


def require_control_plane_mutation_allowed() -> None:
    if job_repository.maintenance_mode_status()["active"]:
        raise HTTPException(status_code=503, detail="Control-plane maintenance mode is active.")


@app.get("/metrics", response_class=PlainTextResponse, dependencies=[Depends(require_api_key)])
async def metrics(days: int = Query(default=1, ge=1, le=30)) -> PlainTextResponse:
    return PlainTextResponse(metrics_service.render_prometheus(days=days), media_type="text/plain; version=0.0.4")


@app.get(
    "/maintenance/mode",
    response_model=ControlPlaneMaintenanceModeResponse,
    dependencies=[Depends(require_api_key)],
)
async def get_control_plane_maintenance_mode() -> ControlPlaneMaintenanceModeResponse:
    return ControlPlaneMaintenanceModeResponse(**job_repository.maintenance_mode_status())


@app.get(
    "/maintenance/control-plane-preflight",
    response_model=ControlPlaneMaintenancePreflightResponse,
    dependencies=[Depends(require_api_key)],
)
async def get_control_plane_preflight() -> ControlPlaneMaintenancePreflightResponse:
    return ControlPlaneMaintenancePreflightResponse(**control_plane_maintenance_service.build_preflight().to_dict())


@app.post(
    "/maintenance/control-plane-runtime-smoke",
    response_model=ControlPlaneRuntimeSmokeResponse,
    dependencies=[Depends(require_api_key)],
)
async def run_control_plane_runtime_smoke(
    request: RunControlPlaneRuntimeSmokeRequest,
) -> ControlPlaneRuntimeSmokeResponse:
    summary = _control_plane_runtime_smoke_service().run(
        changed_by=request.changed_by,
        reason=request.reason,
        cleanup=request.cleanup,
    )
    return ControlPlaneRuntimeSmokeResponse(**summary.to_dict())


@app.post(
    "/maintenance/control-plane-runtime-rehearsal",
    response_model=ControlPlaneRuntimeRehearsalResponse,
    dependencies=[Depends(require_api_key)],
)
async def run_control_plane_runtime_rehearsal(
    request: RunControlPlaneRuntimeRehearsalRequest,
) -> ControlPlaneRuntimeRehearsalResponse:
    summary = _control_plane_runtime_rehearsal_service().run(
        changed_by=request.changed_by,
        expected_backend=request.expected_backend,
        expected_repository_layout=request.expected_repository_layout,
        reason=request.reason,
        cleanup=request.cleanup,
    )
    return ControlPlaneRuntimeRehearsalResponse(**summary.to_dict())


@app.get(
    "/maintenance/control-plane-runtime-validation",
    response_model=ControlPlaneRuntimeValidationResponse,
    dependencies=[Depends(require_api_key)],
)
async def get_control_plane_runtime_validation() -> ControlPlaneRuntimeValidationResponse:
    return ControlPlaneRuntimeValidationResponse(**_control_plane_runtime_validation_service().build_summary().to_dict())


@app.get(
    "/maintenance/control-plane-runtime-validation-reviews",
    response_model=list[ControlPlaneRuntimeValidationReviewPayload],
    dependencies=[Depends(require_api_key)],
)
async def list_control_plane_runtime_validation_reviews(
    status: str | None = Query(default=None),
) -> list[ControlPlaneRuntimeValidationReviewPayload]:
    return [
        ControlPlaneRuntimeValidationReviewPayload(**record.to_dict())
        for record in job_service.list_runtime_validation_reviews(status=status)
    ]


@app.post(
    "/maintenance/control-plane-runtime-validation-reviews/process",
    response_model=list[ControlPlaneRuntimeValidationReviewPayload],
    dependencies=[Depends(require_api_key)],
)
async def process_control_plane_runtime_validation_reviews(
    request: ProcessRuntimeValidationReviewsRequest,
) -> list[ControlPlaneRuntimeValidationReviewPayload]:
    return [
        ControlPlaneRuntimeValidationReviewPayload(**record.to_dict())
        for record in job_service.process_runtime_validation_reviews(
            changed_by=request.changed_by,
            reason=request.reason,
            force=request.force,
        )
    ]


@app.post(
    "/maintenance/control-plane-runtime-validation-reviews/{review_id}/assign",
    response_model=ControlPlaneRuntimeValidationReviewPayload,
    dependencies=[Depends(require_api_key)],
)
async def assign_control_plane_runtime_validation_review(
    review_id: str,
    request: AssignRuntimeValidationReviewRequest,
) -> ControlPlaneRuntimeValidationReviewPayload:
    try:
        record = job_service.assign_runtime_validation_review(
            review_id=review_id,
            assigned_to=request.assigned_to,
            assigned_to_team=request.assigned_to_team,
            assigned_by=request.assigned_by,
            assignment_note=request.assignment_note,
        )
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ControlPlaneRuntimeValidationReviewPayload(**record.to_dict())


@app.post(
    "/maintenance/control-plane-runtime-validation-reviews/{review_id}/resolve",
    response_model=ControlPlaneRuntimeValidationReviewPayload,
    dependencies=[Depends(require_api_key)],
)
async def resolve_control_plane_runtime_validation_review(
    review_id: str,
    request: ResolveRuntimeValidationReviewRequest,
) -> ControlPlaneRuntimeValidationReviewPayload:
    try:
        record = job_service.resolve_runtime_validation_review(
            review_id=review_id,
            resolved_by=request.resolved_by,
            resolution_note=request.resolution_note,
            resolution_reason=request.resolution_reason,
        )
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ControlPlaneRuntimeValidationReviewPayload(**record.to_dict())


@app.get(
    "/maintenance/control-plane-cutover-preflight",
    response_model=ControlPlaneCutoverPreflightResponse,
    dependencies=[Depends(require_api_key)],
)
async def get_control_plane_cutover_preflight(
    target_database_url: str = Query(..., min_length=1),
) -> ControlPlaneCutoverPreflightResponse:
    try:
        summary = control_plane_cutover_service.build_preflight(target_database_url=target_database_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ControlPlaneCutoverPreflightResponse(**summary.to_dict())


@app.get(
    "/maintenance/control-plane-runtime-backend",
    response_model=ControlPlaneRuntimeBackendResponse,
    dependencies=[Depends(require_api_key)],
)
async def get_control_plane_runtime_backend() -> ControlPlaneRuntimeBackendResponse:
    database_status = job_repository.database_status()
    return ControlPlaneRuntimeBackendResponse(
        backend=str(database_status["backend"]),
        url=str(database_status["url"]),
        redacted_url=str(database_status["redacted_url"]),
        runtime_supported=bool(database_status["runtime_supported"]),
        runtime_driver=str(database_status["runtime_driver"]),
        runtime_dependency_installed=bool(database_status["runtime_dependency_installed"]),
        runtime_available=bool(database_status["runtime_available"]),
        runtime_blockers=[str(item) for item in database_status["runtime_blockers"]],
    )


@app.post(
    "/maintenance/control-plane-runtime-backend/inspect",
    response_model=ControlPlaneRuntimeBackendResponse,
    dependencies=[Depends(require_api_key)],
)
async def inspect_control_plane_runtime_backend(
    request: InspectControlPlaneRuntimeBackendRequest,
) -> ControlPlaneRuntimeBackendResponse:
    try:
        summary = inspect_database_runtime_support(
            root_dir=settings.root_dir,
            default_path=settings.database_path,
            raw_url=request.database_url,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ControlPlaneRuntimeBackendResponse(**summary.to_dict())


@app.post(
    "/maintenance/postgres-runtime-shadow-sync",
    response_model=PostgresRuntimeShadowSyncResponse,
    dependencies=[Depends(require_api_key)],
)
async def sync_postgres_runtime_shadow(
    request: SyncPostgresRuntimeShadowRequest,
) -> PostgresRuntimeShadowSyncResponse:
    try:
        summary = _postgres_runtime_shadow_service().sync_control_plane_slice(
            target_database_url=request.target_database_url,
            changed_by=request.changed_by,
            reason=request.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return PostgresRuntimeShadowSyncResponse(**summary.to_dict())


@app.get(
    "/maintenance/events",
    response_model=list[ControlPlaneMaintenanceEventPayload],
    dependencies=[Depends(require_api_key)],
)
async def list_control_plane_maintenance_events(
    limit: int = Query(default=50, ge=1, le=500),
) -> list[ControlPlaneMaintenanceEventPayload]:
    return [
        ControlPlaneMaintenanceEventPayload(**record.to_dict())
        for record in job_service.list_control_plane_maintenance_events(limit=limit)
    ]


@app.post(
    "/maintenance/mode/enable",
    response_model=ControlPlaneMaintenanceModeResponse,
    dependencies=[Depends(require_api_key)],
)
async def enable_control_plane_maintenance_mode(
    request: SetControlPlaneMaintenanceModeRequest,
) -> ControlPlaneMaintenanceModeResponse:
    return ControlPlaneMaintenanceModeResponse(
        **job_service.enable_maintenance_mode(changed_by=request.changed_by, reason=request.reason)
    )


@app.post(
    "/maintenance/mode/disable",
    response_model=ControlPlaneMaintenanceModeResponse,
    dependencies=[Depends(require_api_key)],
)
async def disable_control_plane_maintenance_mode(
    request: SetControlPlaneMaintenanceModeRequest,
) -> ControlPlaneMaintenanceModeResponse:
    return ControlPlaneMaintenanceModeResponse(
        **job_service.disable_maintenance_mode(changed_by=request.changed_by, reason=request.reason)
    )


@app.post(
    "/maintenance/control-plane-runbook",
    response_model=RunControlPlaneMaintenanceWorkflowResponse,
    dependencies=[Depends(require_api_key)],
)
async def run_control_plane_maintenance_workflow(
    request: RunControlPlaneMaintenanceWorkflowRequest,
) -> RunControlPlaneMaintenanceWorkflowResponse:
    try:
        summary = control_plane_maintenance_service.execute_workflow(
            output_path=request.output_path,
            changed_by=request.changed_by,
            reason=request.reason,
            allow_running_jobs=request.allow_running_jobs,
            disable_maintenance_on_success=request.disable_maintenance_on_success,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return RunControlPlaneMaintenanceWorkflowResponse(**summary.to_dict())


@app.post(
    "/maintenance/control-plane-cutover-bundle",
    response_model=PrepareControlPlaneCutoverBundleResponse,
    dependencies=[Depends(require_api_key)],
)
async def prepare_control_plane_cutover_bundle(
    request: PrepareControlPlaneCutoverBundleRequest,
) -> PrepareControlPlaneCutoverBundleResponse:
    try:
        summary = control_plane_cutover_service.prepare_cutover_bundle(
            output_path=request.output_path,
            target_database_url=request.target_database_url,
            changed_by=request.changed_by,
            reason=request.reason,
            allow_running_jobs=request.allow_running_jobs,
            disable_maintenance_on_success=request.disable_maintenance_on_success,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return PrepareControlPlaneCutoverBundleResponse(**summary.to_dict())


@app.post(
    "/maintenance/postgres-bootstrap-package/inspect",
    response_model=PostgresBootstrapPackageInspectionResponse,
    dependencies=[Depends(require_api_key)],
)
async def inspect_postgres_bootstrap_package(
    request: InspectPostgresBootstrapPackageRequest,
) -> PostgresBootstrapPackageInspectionResponse:
    try:
        summary = postgres_bootstrap_service.inspect_package(package_dir=request.package_dir)
    except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return PostgresBootstrapPackageInspectionResponse(**summary.to_dict())


@app.post(
    "/maintenance/postgres-bootstrap-package/plan",
    response_model=PostgresBootstrapExecutionPlanResponse,
    dependencies=[Depends(require_api_key)],
)
async def build_postgres_bootstrap_execution_plan(
    request: BuildPostgresBootstrapExecutionPlanRequest,
) -> PostgresBootstrapExecutionPlanResponse:
    try:
        summary = postgres_bootstrap_service.build_execution_plan(
            package_dir=request.package_dir,
            target_database_url=request.target_database_url,
            artifact_target_root=request.artifact_target_root,
            psql_executable=request.psql_executable,
        )
    except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return PostgresBootstrapExecutionPlanResponse(**summary.to_dict())


@app.post(
    "/maintenance/postgres-bootstrap-package/execute",
    response_model=ExecutePostgresBootstrapPackageResponse,
    dependencies=[Depends(require_api_key)],
)
async def execute_postgres_bootstrap_package(
    request: ExecutePostgresBootstrapPackageRequest,
) -> ExecutePostgresBootstrapPackageResponse:
    try:
        summary = postgres_bootstrap_service.execute_package(
            package_dir=request.package_dir,
            target_database_url=request.target_database_url,
            artifact_target_root=request.artifact_target_root,
            psql_executable=request.psql_executable,
            dry_run=request.dry_run,
        )
    except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ExecutePostgresBootstrapPackageResponse(**summary.to_dict())


@app.post(
    "/maintenance/postgres-target/inspect",
    response_model=PostgresTargetInspectionResponse,
    dependencies=[Depends(require_api_key)],
)
async def inspect_postgres_target(
    request: InspectPostgresTargetRequest,
) -> PostgresTargetInspectionResponse:
    try:
        summary = postgres_target_service.inspect_target(
            target_database_url=request.target_database_url,
            psql_executable=request.psql_executable,
        )
    except (json.JSONDecodeError, ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return PostgresTargetInspectionResponse(**summary.to_dict())


@app.post(
    "/maintenance/postgres-bootstrap-package/verify-target",
    response_model=VerifyPostgresBootstrapPackageResponse,
    dependencies=[Depends(require_api_key)],
)
async def verify_postgres_bootstrap_package_target(
    request: VerifyPostgresBootstrapPackageRequest,
) -> VerifyPostgresBootstrapPackageResponse:
    try:
        summary = postgres_target_service.verify_bootstrap_package_against_target(
            package_dir=request.package_dir,
            target_database_url=request.target_database_url,
            psql_executable=request.psql_executable,
        )
    except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return VerifyPostgresBootstrapPackageResponse(**summary.to_dict())


@app.post(
    "/maintenance/postgres-cutover-rehearsal",
    response_model=PostgresCutoverRehearsalResponse,
    dependencies=[Depends(require_api_key)],
)
async def run_postgres_cutover_rehearsal(
    request: RunPostgresCutoverRehearsalRequest,
) -> PostgresCutoverRehearsalResponse:
    try:
        summary = _postgres_cutover_rehearsal_service().execute_rehearsal(
            package_dir=request.package_dir,
            target_database_url=request.target_database_url,
            changed_by=request.changed_by,
            reason=request.reason,
            psql_executable=request.psql_executable,
            artifact_target_root=request.artifact_target_root,
            apply_to_target=request.apply_to_target,
        )
    except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return PostgresCutoverRehearsalResponse(**summary.to_dict())


@app.post(
    "/maintenance/control-plane-cutover-readiness",
    response_model=ControlPlaneCutoverReadinessResponse,
    dependencies=[Depends(require_api_key)],
)
async def evaluate_control_plane_cutover_readiness(
    request: EvaluateControlPlaneCutoverReadinessRequest,
) -> ControlPlaneCutoverReadinessResponse:
    try:
        summary = _control_plane_cutover_readiness_service().evaluate(
            target_database_url=request.target_database_url,
            package_dir=request.package_dir,
            rehearsal_max_age_hours=request.rehearsal_max_age_hours,
            require_apply_rehearsal=request.require_apply_rehearsal,
            require_runtime_validation=request.require_runtime_validation,
        )
    except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ControlPlaneCutoverReadinessResponse(**summary.to_dict())


@app.post(
    "/maintenance/control-plane-cutover-decision",
    response_model=ControlPlaneCutoverPromotionResponse,
    dependencies=[Depends(require_api_key)],
)
async def decide_control_plane_cutover(
    request: DecideControlPlaneCutoverRequest,
) -> ControlPlaneCutoverPromotionResponse:
    try:
        summary = _control_plane_cutover_promotion_service().decide(
            target_database_url=request.target_database_url,
            package_dir=request.package_dir,
            changed_by=request.changed_by,
            requested_decision=request.requested_decision,
            reason=request.reason,
            decision_note=request.decision_note,
            rehearsal_max_age_hours=request.rehearsal_max_age_hours,
            require_apply_rehearsal=request.require_apply_rehearsal,
            require_runtime_validation=request.require_runtime_validation,
            allow_override=request.allow_override,
        )
    except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ControlPlaneCutoverPromotionResponse(**summary.to_dict())


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


@app.get(
    "/maintenance/control-plane-schema/contract",
    response_model=ControlPlaneSchemaContractResponse,
    dependencies=[Depends(require_api_key)],
)
async def get_control_plane_schema_contract() -> ControlPlaneSchemaContractResponse:
    return ControlPlaneSchemaContractResponse(**job_repository.schema_contract())


@app.get(
    "/maintenance/control-plane-schema",
    response_model=ControlPlaneSchemaStatusResponse,
    dependencies=[Depends(require_api_key)],
)
async def get_control_plane_schema_status() -> ControlPlaneSchemaStatusResponse:
    return ControlPlaneSchemaStatusResponse(**job_repository.schema_status())


@app.post(
    "/maintenance/control-plane-schema/migrate",
    response_model=ControlPlaneSchemaStatusResponse,
    dependencies=[Depends(require_api_key)],
)
async def migrate_control_plane_schema() -> ControlPlaneSchemaStatusResponse:
    result = job_repository.migrate_schema()
    job_service.record_maintenance_event(
        event_type="schema_migrated",
        changed_by="api",
        details=result,
    )
    return ControlPlaneSchemaStatusResponse(**result)


@app.post(
    "/maintenance/export-control-plane-backup",
    response_model=ControlPlaneBackupResponse,
    dependencies=[Depends(require_api_key)],
)
async def export_control_plane_backup(request: ExportControlPlaneBackupRequest) -> ControlPlaneBackupResponse:
    summary = control_plane_backup_service.export_bundle(request.output_path)
    job_service.record_maintenance_event(
        event_type="backup_exported",
        changed_by="api",
        details=summary.to_dict(),
    )
    return ControlPlaneBackupResponse(**summary.to_dict())


@app.post(
    "/maintenance/import-control-plane-backup",
    response_model=ControlPlaneBackupResponse,
    dependencies=[Depends(require_api_key)],
)
async def import_control_plane_backup(request: ImportControlPlaneBackupRequest) -> ControlPlaneBackupResponse:
    try:
        summary = control_plane_backup_service.import_bundle(
            request.input_path,
            replace_existing=request.replace_existing,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    job_service.record_maintenance_event(
        event_type="backup_imported",
        changed_by="api",
        details=summary.to_dict(),
    )
    return ControlPlaneBackupResponse(**summary.to_dict())


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
    dependencies=[Depends(require_api_key), Depends(require_control_plane_mutation_allowed)],
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
    dependencies=[Depends(require_api_key), Depends(require_control_plane_mutation_allowed)],
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
    dependencies=[Depends(require_api_key), Depends(require_control_plane_mutation_allowed)],
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
    dependencies=[Depends(require_api_key), Depends(require_control_plane_mutation_allowed)],
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
    "/control-plane-oncall-change-requests/{request_id}/assign",
    response_model=ControlPlaneOnCallChangeRequestPayload,
    dependencies=[Depends(require_api_key), Depends(require_control_plane_mutation_allowed)],
)
async def assign_control_plane_oncall_change_request(
    request_id: str,
    request: AssignControlPlaneOnCallChangeRequest,
) -> ControlPlaneOnCallChangeRequestPayload:
    try:
        record = control_plane_alert_service.assign_oncall_change_request(
            request_id=request_id,
            assigned_to=request.assigned_to,
            assigned_to_team=request.assigned_to_team,
            assigned_by=request.assigned_by,
            assignment_note=request.assignment_note,
        )
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=f"Control-plane on-call change request '{request_id}' was not found.",
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ControlPlaneOnCallChangeRequestPayload(**record.to_dict())


@app.post(
    "/control-plane-oncall-change-requests/{request_id}/review",
    response_model=ControlPlaneOnCallChangeRequestPayload,
    dependencies=[Depends(require_api_key), Depends(require_control_plane_mutation_allowed)],
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
    dependencies=[Depends(require_api_key), Depends(require_control_plane_mutation_allowed)],
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
    dependencies=[Depends(require_api_key), Depends(require_control_plane_mutation_allowed)],
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


@app.post(
    "/ingest",
    response_model=IngestResponse,
    dependencies=[Depends(require_api_key), Depends(require_control_plane_mutation_allowed)],
)
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


@app.post(
    "/audit",
    response_model=AuditResponse,
    dependencies=[Depends(require_api_key), Depends(require_control_plane_mutation_allowed)],
)
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


@app.post(
    "/audit-trace",
    response_model=AuditResponse,
    dependencies=[Depends(require_api_key), Depends(require_control_plane_mutation_allowed)],
)
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


@app.post(
    "/jobs/audit-trace",
    response_model=JobRecordPayload,
    status_code=202,
    dependencies=[Depends(require_api_key), Depends(require_control_plane_mutation_allowed)],
)
async def submit_audit_trace_job(request: AuditTraceRequest) -> JobRecordPayload:
    job = job_service.submit_audit_trace(request.model_dump())
    return JobRecordPayload(**job.to_dict())


@app.post(
    "/collect-trace",
    response_model=CollectTraceResponse,
    dependencies=[Depends(require_api_key), Depends(require_control_plane_mutation_allowed)],
)
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


@app.post(
    "/jobs/collect-audit",
    response_model=JobRecordPayload,
    status_code=202,
    dependencies=[Depends(require_api_key), Depends(require_control_plane_mutation_allowed)],
)
async def submit_collect_audit_job(request: CollectAuditRequest) -> JobRecordPayload:
    job = job_service.submit_collect_audit(request.model_dump())
    return JobRecordPayload(**job.to_dict())


@app.post(
    "/collect-audit",
    response_model=CollectAuditResponse,
    dependencies=[Depends(require_api_key), Depends(require_control_plane_mutation_allowed)],
)
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
