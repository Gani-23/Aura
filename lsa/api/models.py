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
    environment_name: str
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


class WorkerHeartbeatPayload(BaseModel):
    heartbeat_id: str
    worker_id: str
    recorded_at: str
    status: str
    current_job_id: str | None = None


class JobLeaseEventPayload(BaseModel):
    event_id: str
    job_id: str
    worker_id: str | None = None
    event_type: str
    recorded_at: str
    details: dict[str, Any]


class PruneHistoryResponse(BaseModel):
    worker_heartbeats_compacted: int
    job_lease_events_compacted: int
    worker_heartbeats_pruned: int
    job_lease_events_pruned: int


class ControlPlaneAlertRecordPayload(BaseModel):
    alert_id: str
    created_at: str
    alert_key: str
    status: str
    severity: str
    summary: str
    finding_codes: list[str]
    delivery_state: str
    payload: dict[str, Any]
    error: str | None = None
    acknowledged_at: str | None = None
    acknowledged_by: str | None = None
    acknowledgement_note: str | None = None


class EmitControlPlaneAlertsResponse(BaseModel):
    emitted_count: int
    alerts: list[ControlPlaneAlertRecordPayload]


class AcknowledgeControlPlaneAlertRequest(BaseModel):
    acknowledged_by: str
    acknowledgement_note: str | None = None


class ControlPlaneAlertSilencePayload(BaseModel):
    silence_id: str
    created_at: str
    created_by: str
    reason: str
    match_alert_key: str | None = None
    match_finding_code: str | None = None
    starts_at: str | None = None
    expires_at: str | None = None
    cancelled_at: str | None = None
    cancelled_by: str | None = None


class CreateControlPlaneAlertSilenceRequest(BaseModel):
    created_by: str
    reason: str
    duration_minutes: int = Field(..., ge=1)
    match_alert_key: str | None = None
    match_finding_code: str | None = None

    @model_validator(mode="after")
    def validate_matcher(self) -> "CreateControlPlaneAlertSilenceRequest":
        if not self.match_alert_key and not self.match_finding_code:
            raise ValueError("Either match_alert_key or match_finding_code must be provided.")
        return self


class CancelControlPlaneAlertSilenceRequest(BaseModel):
    cancelled_by: str


class ControlPlaneOnCallSchedulePayload(BaseModel):
    schedule_id: str
    created_at: str
    created_by: str
    environment_name: str = "default"
    created_by_team: str | None = None
    created_by_role: str | None = None
    change_reason: str | None = None
    approved_by: str | None = None
    approved_by_team: str | None = None
    approved_by_role: str | None = None
    approved_at: str | None = None
    approval_note: str | None = None
    team_name: str
    timezone_name: str
    weekdays: list[int]
    start_time: str
    end_time: str
    priority: int = 100
    rotation_name: str | None = None
    effective_start_date: str | None = None
    effective_end_date: str | None = None
    webhook_url: str | None = None
    escalation_webhook_url: str | None = None
    cancelled_at: str | None = None
    cancelled_by: str | None = None


class CreateControlPlaneOnCallScheduleRequest(BaseModel):
    created_by: str
    environment_name: str | None = None
    created_by_team: str | None = None
    created_by_role: str | None = None
    change_reason: str | None = None
    approved_by: str | None = None
    approved_by_team: str | None = None
    approved_by_role: str | None = None
    approval_note: str | None = None
    team_name: str
    timezone_name: str
    weekdays: list[int]
    start_time: str
    end_time: str
    priority: int = Field(default=100, ge=0)
    rotation_name: str | None = None
    effective_start_date: str | None = None
    effective_end_date: str | None = None
    webhook_url: str | None = None
    escalation_webhook_url: str | None = None


class CancelControlPlaneOnCallScheduleRequest(BaseModel):
    cancelled_by: str


class ControlPlaneOnCallChangeRequestPayload(BaseModel):
    request_id: str
    created_at: str
    created_by: str
    environment_name: str = "default"
    created_by_team: str | None = None
    created_by_role: str | None = None
    change_reason: str | None = None
    status: str
    review_required: bool
    review_reasons: list[str]
    team_name: str
    timezone_name: str
    weekdays: list[int]
    start_time: str
    end_time: str
    priority: int = 100
    rotation_name: str | None = None
    effective_start_date: str | None = None
    effective_end_date: str | None = None
    webhook_url: str | None = None
    escalation_webhook_url: str | None = None
    decision_at: str | None = None
    decided_by: str | None = None
    decided_by_team: str | None = None
    decided_by_role: str | None = None
    decision_note: str | None = None
    applied_schedule_id: str | None = None


class CreateControlPlaneOnCallChangeRequest(BaseModel):
    created_by: str
    environment_name: str | None = None
    created_by_team: str | None = None
    created_by_role: str | None = None
    change_reason: str
    team_name: str
    timezone_name: str
    weekdays: list[int]
    start_time: str
    end_time: str
    priority: int = Field(default=100, ge=0)
    rotation_name: str | None = None
    effective_start_date: str | None = None
    effective_end_date: str | None = None
    webhook_url: str | None = None
    escalation_webhook_url: str | None = None


class ReviewControlPlaneOnCallChangeRequest(BaseModel):
    decision: str
    reviewed_by: str
    reviewed_by_team: str | None = None
    reviewed_by_role: str | None = None
    review_note: str | None = None


class ControlPlaneOnCallRouteCandidatePayload(BaseModel):
    rank: int
    selected: bool
    priority: int
    specificity: int
    window_span_days: int
    reasons: list[str]
    route: ControlPlaneOnCallSchedulePayload


class ControlPlaneOnCallRouteResolutionPayload(BaseModel):
    reference_timestamp: str
    resolved_route: ControlPlaneOnCallSchedulePayload | None = None
    active_candidate_count: int
    active_candidates: list[ControlPlaneOnCallRouteCandidatePayload]


class WorkerHeartbeatRollupPayload(BaseModel):
    day_bucket: str
    worker_id: str
    status: str
    current_job_id: str | None = None
    event_count: int


class JobLeaseEventRollupPayload(BaseModel):
    day_bucket: str
    job_id: str
    worker_id: str | None = None
    event_type: str
    event_count: int


class QueueAnalyticsPayload(BaseModel):
    total_jobs: int
    queued_jobs: int
    running_jobs: int
    completed_jobs: int
    failed_jobs: int


class WorkerDailyAnalyticsPayload(BaseModel):
    day_bucket: str
    total_heartbeats: int
    active_worker_count: int
    busy_worker_count: int
    stopped_worker_count: int


class WorkerAnalyticsPayload(BaseModel):
    active_workers: int
    busy_workers: int
    idle_workers: int
    stale_workers: int
    total_workers_seen: int
    days: list[WorkerDailyAnalyticsPayload]


class LeaseDailyAnalyticsPayload(BaseModel):
    day_bucket: str
    total_events: int
    claimed_count: int
    renewed_count: int
    expired_requeue_count: int
    completed_count: int
    failed_count: int
    affected_job_count: int
    affected_worker_count: int


class LeaseAnalyticsPayload(BaseModel):
    total_events: int
    claimed_count: int
    renewed_count: int
    expired_requeue_count: int
    completed_count: int
    failed_count: int
    days: list[LeaseDailyAnalyticsPayload]


class JobDailyAnalyticsPayload(BaseModel):
    day_bucket: str
    created_count: int
    started_count: int
    completed_count: int
    failed_count: int


class JobAnalyticsPayload(BaseModel):
    submitted_count: int
    started_count: int
    completed_count: int
    failed_count: int
    success_rate: float | None = None
    days: list[JobDailyAnalyticsPayload]


class OnCallConflictPayload(BaseModel):
    schedule_ids: list[str]
    team_names: list[str]
    rotation_names: list[str]
    sample_timestamp: str
    priority: int
    specificity: int
    window_span_days: int
    occurrence_count: int


class OnCallAnalyticsPayload(BaseModel):
    total_schedules: int
    active_schedules: int
    conflict_count: int
    conflicts: list[OnCallConflictPayload]


class ControlPlaneAlertThresholdsPayload(BaseModel):
    queue_warning_threshold: int
    queue_critical_threshold: int
    stale_worker_warning_threshold: int
    stale_worker_critical_threshold: int
    expired_lease_warning_threshold: int
    expired_lease_critical_threshold: int
    job_failure_rate_warning_threshold: float
    job_failure_rate_critical_threshold: float
    job_failure_rate_min_samples: int
    oncall_conflict_warning_threshold: int
    oncall_conflict_critical_threshold: int


class ControlPlaneFindingPayload(BaseModel):
    severity: str
    code: str
    metric: str
    summary: str
    observed_value: float
    threshold_value: float | None = None
    context: dict[str, Any] = Field(default_factory=dict)


class ControlPlaneEvaluationPayload(BaseModel):
    status: str
    findings: list[ControlPlaneFindingPayload]
    thresholds: ControlPlaneAlertThresholdsPayload


class ControlPlaneAnalyticsResponse(BaseModel):
    generated_at: str
    window_days: int
    window_start_day: str
    window_end_day: str
    queue: QueueAnalyticsPayload
    workers: WorkerAnalyticsPayload
    leases: LeaseAnalyticsPayload
    jobs: JobAnalyticsPayload
    oncall: OnCallAnalyticsPayload
    evaluation: ControlPlaneEvaluationPayload
