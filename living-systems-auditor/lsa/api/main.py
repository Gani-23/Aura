from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Header

from lsa.api.models import (
    AuditRecordPayload,
    AuditRequest,
    AuditResponse,
    AuditTraceRequest,
    CollectAuditRequest,
    CollectAuditResponse,
    CollectTraceRequest,
    CollectTraceResponse,
    HealthResponse,
    IngestRequest,
    IngestResponse,
    JobRecordPayload,
    SnapshotRecordPayload,
    WorkerRecordPayload,
)
from lsa.core.intent_graph import IntentGraph
from lsa.drift.comparator import DriftComparator
from lsa.drift.models import ObservedEvent
from lsa.drift.trace_parser import load_trace_events
from lsa.remediation.llm_client import RuleBasedLLMClient
from lsa.services.audit_service import AuditService
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
job_service = JobService(
    job_repository=job_repository,
    audit_service=audit_service,
    trace_collection_service=trace_collection_service,
    worker_mode="embedded",
    heartbeat_timeout_seconds=settings.worker_heartbeat_timeout_seconds,
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


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    active_workers = job_service.active_worker_count()
    return HealthResponse(
        status="ok",
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
