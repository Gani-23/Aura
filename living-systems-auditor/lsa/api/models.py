from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, model_validator


class ObservedEventPayload(BaseModel):
    function: str
    event_type: str
    target: str
    metadata: dict[str, str] = Field(default_factory=dict)


class DriftAlertPayload(BaseModel):
    function: str
    observed_target: str
    expected_targets: list[str]
    severity: str
    reason: str


class SnapshotRecordPayload(BaseModel):
    snapshot_id: str
    created_at: str
    repo_path: str
    node_count: int
    edge_count: int
    snapshot_path: str


class HealthResponse(BaseModel):
    status: str
    auth_enabled: bool
    worker_mode: str
    database_path: str
    database_ready: bool
    worker_running: bool
    active_workers: int
    queued_jobs: int
    running_jobs: int
    snapshots_dir: str
    audits_dir: str
    reports_dir: str
    traces_dir: str


class AuditExplanationPayload(BaseModel):
    status: str
    summary: str
    alert_count: int
    session_count: int
    impacted_functions: list[str]
    unexpected_targets: list[str]
    expected_targets: list[str]
    primary_function: str | None = None
    primary_session_key: str | None = None
    evidence: list[str]


class AuditRecordPayload(BaseModel):
    audit_id: str
    created_at: str
    snapshot_id: str | None = None
    snapshot_path: str
    alert_count: int
    report_paths: list[str]
    alerts: list[DriftAlertPayload]
    events: list[ObservedEventPayload]
    sessions: list[dict]
    explanation: AuditExplanationPayload


class IngestRequest(BaseModel):
    repo_path: str = Field(..., description="Local repository path to ingest.")
    output_path: str | None = Field(default=None, description="Optional JSON snapshot path.")
    persist: bool = Field(default=True, description="Persist the snapshot in the local workspace store.")
    snapshot_id: str | None = Field(default=None, description="Optional explicit snapshot identifier.")


class IngestResponse(BaseModel):
    node_count: int
    edge_count: int
    snapshot_path: str | None = None
    snapshot_id: str | None = None
    created_at: str | None = None


class AuditRequest(BaseModel):
    snapshot_id: str | None = None
    snapshot_path: str | None = None
    events: list[ObservedEventPayload]
    report_dir: str | None = None
    persist: bool = Field(default=True, description="Persist the audit result in the local workspace store.")
    audit_id: str | None = Field(default=None, description="Optional explicit audit identifier.")

    @model_validator(mode="after")
    def validate_snapshot_reference(self) -> "AuditRequest":
        if not self.snapshot_id and not self.snapshot_path:
            raise ValueError("Either snapshot_id or snapshot_path must be provided.")
        return self


class AuditTraceRequest(BaseModel):
    snapshot_id: str | None = None
    snapshot_path: str | None = None
    trace_path: str
    trace_format: str = Field(default="auto", description="Trace format: auto, jsonl, logfmt, kv, or bpftrace.")
    report_dir: str | None = None
    persist: bool = Field(default=True, description="Persist the audit result in the local workspace store.")
    audit_id: str | None = Field(default=None, description="Optional explicit audit identifier.")

    @model_validator(mode="after")
    def validate_snapshot_reference(self) -> "AuditTraceRequest":
        if not self.snapshot_id and not self.snapshot_path:
            raise ValueError("Either snapshot_id or snapshot_path must be provided.")
        return self


class CollectTraceRequest(BaseModel):
    pid: int
    program: str = Field(default="ebpf/network_observer.bt")
    duration: float | None = None
    max_events: int | None = None
    output_path: str | None = None
    symbol_map_path: str | None = None
    context_map_path: str | None = None


class CollectAuditRequest(BaseModel):
    snapshot_id: str | None = None
    snapshot_path: str | None = None
    pid: int
    program: str = Field(default="ebpf/network_observer.bt")
    duration: float | None = None
    max_events: int | None = None
    trace_format: str = Field(default="bpftrace", description="Trace format: auto, jsonl, logfmt, kv, or bpftrace.")
    output_path: str | None = None
    symbol_map_path: str | None = None
    context_map_path: str | None = None
    persist: bool = Field(default=True, description="Persist the audit result in the local workspace store.")
    audit_id: str | None = Field(default=None, description="Optional explicit audit identifier.")

    @model_validator(mode="after")
    def validate_snapshot_reference(self) -> "CollectAuditRequest":
        if not self.snapshot_id and not self.snapshot_path:
            raise ValueError("Either snapshot_id or snapshot_path must be provided.")
        return self


class AuditResponse(BaseModel):
    alert_count: int
    report_paths: list[str]
    alerts: list[DriftAlertPayload]
    sessions: list[dict]
    explanation: AuditExplanationPayload
    audit_id: str | None = None
    snapshot_id: str | None = None
    snapshot_path: str


class CollectTraceResponse(BaseModel):
    command: list[str]
    trace_path: str
    trace_metadata_path: str | None = None
    trace_symbol_map_path: str | None = None
    trace_context_map_path: str | None = None
    line_count: int
    return_code: int


class CollectAuditResponse(BaseModel):
    trace_path: str
    trace_metadata_path: str | None = None
    trace_symbol_map_path: str | None = None
    trace_context_map_path: str | None = None
    line_count: int
    alert_count: int
    report_paths: list[str]
    alerts: list[DriftAlertPayload]
    sessions: list[dict]
    explanation: AuditExplanationPayload
    audit_id: str | None = None
    snapshot_id: str | None = None
    snapshot_path: str


class JobRecordPayload(BaseModel):
    job_id: str
    created_at: str
    job_type: str
    status: str
    request_payload: dict[str, Any]
    result_payload: dict[str, Any]
    error: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    claimed_by_worker_id: str | None = None
    lease_expires_at: str | None = None


class WorkerRecordPayload(BaseModel):
    worker_id: str
    mode: str
    status: str
    started_at: str
    last_heartbeat_at: str
    host_name: str
    process_id: int
    current_job_id: str | None = None
