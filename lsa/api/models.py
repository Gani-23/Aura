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
    database_backend: str
    database_url: str
    database_path: str
    snapshot_repository_backend: str
    audit_repository_backend: str
    job_repository_backend: str
    control_plane_repository_layout: str
    control_plane_mixed_backends: bool
    snapshots_audits_repository_runtime_enabled: bool
    snapshots_audits_repository_runtime_active: bool
    job_repository_runtime_enabled: bool
    job_repository_runtime_active: bool
    database_runtime_supported: bool
    database_runtime_driver: str
    database_runtime_dependency_installed: bool
    database_runtime_available: bool
    database_runtime_blockers: list[str]
    database_ready: bool
    database_writable: bool
    database_schema_version: int
    database_expected_schema_version: int
    database_schema_ready: bool
    database_pending_migration_count: int
    maintenance_mode_active: bool
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


class ExportControlPlaneBackupRequest(BaseModel):
    output_path: str


class ImportControlPlaneBackupRequest(BaseModel):
    input_path: str
    replace_existing: bool = False


class ControlPlaneBackupResponse(BaseModel):
    bundle_version: int
    exported_at: str
    environment_name: str
    database_backend: str
    database_url: str
    counts: dict[str, int]
    artifact_counts: dict[str, int]
    path: str
    replace_existing: bool | None = None


class ControlPlaneSchemaMigrationPayload(BaseModel):
    migration_id: str
    schema_version: int
    applied_at: str
    description: str


class ControlPlaneSchemaStatusResponse(BaseModel):
    schema_version: int
    expected_schema_version: int
    schema_ready: bool
    pending_migration_count: int
    migrations: list[ControlPlaneSchemaMigrationPayload]


class ControlPlaneSchemaContractResponse(BaseModel):
    schema_version: int
    migration_id: str
    migration_description: str
    runtime_supported_backends: list[str]
    bootstrap_supported_backends: list[str]
    table_names: list[str]


class ControlPlaneRuntimeBackendResponse(BaseModel):
    backend: str
    url: str
    redacted_url: str
    runtime_supported: bool
    runtime_driver: str
    runtime_dependency_installed: bool
    runtime_available: bool
    runtime_blockers: list[str]


class InspectControlPlaneRuntimeBackendRequest(BaseModel):
    database_url: str


class SyncPostgresRuntimeShadowRequest(BaseModel):
    target_database_url: str
    changed_by: str
    reason: str | None = None


class PostgresRuntimeShadowSyncResponse(BaseModel):
    synced_at: str
    environment_name: str
    changed_by: str
    reason: str | None = None
    target_database_url: str
    target_database_redacted_url: str
    runtime_supported: bool
    runtime_driver: str
    runtime_dependency_installed: bool
    runtime_available: bool
    runtime_blockers: list[str]
    source_event_count: int
    target_event_count: int
    synced_event_count: int
    source_job_count: int
    target_job_count: int
    synced_job_count: int
    source_worker_count: int
    target_worker_count: int
    synced_worker_count: int
    source_worker_heartbeat_count: int
    target_worker_heartbeat_count: int
    synced_worker_heartbeat_count: int
    source_job_lease_event_count: int
    target_job_lease_event_count: int
    synced_job_lease_event_count: int
    maintenance_mode: dict[str, Any]
    latest_target_event_id: str | None = None
    warnings: list[str]


class SetControlPlaneMaintenanceModeRequest(BaseModel):
    changed_by: str
    reason: str | None = None


class ControlPlaneMaintenanceModeResponse(BaseModel):
    active: bool
    changed_at: str | None = None
    changed_by: str | None = None
    reason: str | None = None


class RunControlPlaneRuntimeSmokeRequest(BaseModel):
    changed_by: str
    reason: str | None = None
    cleanup: bool = True


class ControlPlaneRuntimeSmokeResponse(BaseModel):
    smoke_id: str
    executed_at: str
    changed_by: str
    reason: str | None = None
    snapshot_repository_backend: str
    audit_repository_backend: str
    job_repository_backend: str
    repository_layout: str
    mixed_backends: bool
    snapshot_id: str
    audit_id: str
    job_id: str
    snapshot_path: str
    report_path: str
    snapshot_round_trip_ok: bool
    audit_round_trip_ok: bool
    job_round_trip_ok: bool
    cleanup_requested: bool
    cleanup_completed: bool
    maintenance_event_id: str | None = None


class RunControlPlaneRuntimeRehearsalRequest(BaseModel):
    changed_by: str
    expected_backend: str = "postgres"
    expected_repository_layout: str = "shared"
    reason: str | None = None
    cleanup: bool = True


class ControlPlaneRuntimeRehearsalResponse(BaseModel):
    rehearsal_id: str
    executed_at: str
    changed_by: str
    reason: str | None = None
    environment_name: str
    expected_backend: str
    expected_repository_layout: str
    database_backend: str
    snapshot_repository_backend: str
    audit_repository_backend: str
    job_repository_backend: str
    repository_layout: str
    mixed_backends: bool
    snapshots_audits_repository_runtime_enabled: bool
    snapshots_audits_repository_runtime_active: bool
    job_repository_runtime_enabled: bool
    job_repository_runtime_active: bool
    database_runtime_available: bool
    database_runtime_blockers: list[str]
    deployment_readiness: "ControlPlaneDeploymentReadinessResponse"
    checks: dict[str, bool]
    status: str
    smoke: dict[str, Any]
    maintenance_event_id: str | None = None


class ControlPlaneMaintenancePreflightResponse(BaseModel):
    generated_at: str
    environment_name: str
    worker_mode: str
    maintenance_mode_active: bool
    maintenance_mode_changed_at: str | None = None
    maintenance_mode_changed_by: str | None = None
    maintenance_mode_reason: str | None = None
    database_backend: str
    database_url: str
    database_path: str
    database_ready: bool
    database_writable: bool
    database_schema_version: int
    database_expected_schema_version: int
    database_schema_ready: bool
    database_pending_migration_count: int
    worker_running: bool
    active_workers: int
    queued_jobs: int
    running_jobs: int
    completed_jobs: int
    failed_jobs: int
    runtime_validation: ControlPlaneRuntimeValidationResponse
    deployment_readiness: "ControlPlaneDeploymentReadinessResponse"
    runtime_validation_change_control_requests: list["ControlPlaneRuntimeValidationChangeControlPayload"] = Field(default_factory=list)
    blockers: list[str]
    warnings: list[str]
    can_execute: bool


class ControlPlaneDeploymentReadinessResponse(BaseModel):
    evaluated_at: str
    environment_name: str
    runtime_validation: "ControlPlaneRuntimeValidationResponse"
    runtime_validation_change_control_requests: list["ControlPlaneRuntimeValidationChangeControlPayload"] = Field(default_factory=list)
    owner_team_rollups: list[dict[str, Any]] = Field(default_factory=list)
    blocked_owner_team_count: int = 0
    oldest_rejected_age_hours: float | None = None
    blockers: list[str]
    warnings: list[str]
    ready: bool


class RunControlPlaneMaintenanceWorkflowRequest(BaseModel):
    output_path: str
    changed_by: str
    reason: str | None = None
    allow_running_jobs: bool = False
    disable_maintenance_on_success: bool = True


class RunControlPlaneMaintenanceWorkflowResponse(BaseModel):
    started_at: str
    completed_at: str
    changed_by: str
    reason: str | None = None
    backup_path: str
    disable_maintenance_on_success: bool
    maintenance_enabled_by_workflow: bool
    steps: list[str]
    preflight: ControlPlaneMaintenancePreflightResponse
    maintenance_before: ControlPlaneMaintenanceModeResponse
    maintenance_after_enable: ControlPlaneMaintenanceModeResponse | None = None
    maintenance_final: ControlPlaneMaintenanceModeResponse
    backup: ControlPlaneBackupResponse
    schema_status: ControlPlaneSchemaStatusResponse


class ControlPlaneCutoverTargetResponse(BaseModel):
    backend: str
    url: str
    redacted_url: str
    runtime_supported: bool
    host: str | None = None
    port: int | None = None
    database_name: str | None = None
    username: str | None = None


class PostgresBootstrapPackageResponse(BaseModel):
    package_version: int
    generated_from_cutover_bundle: str
    generated_from_backup_bundle: str
    output_dir: str
    schema_sql_path: str
    data_sql_path: str
    manifest_path: str
    artifact_root: str
    snapshot_artifact_count: int
    report_artifact_count: int
    table_counts: dict[str, int]
    file_checksums: dict[str, str]


class InspectPostgresBootstrapPackageRequest(BaseModel):
    package_dir: str


class PostgresBootstrapPackageInspectionResponse(BaseModel):
    package_version: int
    manifest_path: str
    output_dir: str
    target_backend: str | None = None
    file_checksums: dict[str, str]
    files_present: list[str]
    missing_files: list[str]
    checksum_mismatches: list[str]
    table_counts: dict[str, int]
    artifact_counts: dict[str, int]
    valid: bool


class BuildPostgresBootstrapExecutionPlanRequest(BaseModel):
    package_dir: str
    target_database_url: str
    artifact_target_root: str | None = None
    psql_executable: str = "psql"


class PostgresBootstrapExecutionPlanResponse(BaseModel):
    package_dir: str
    target_database_url: str
    psql_executable: str
    artifact_target_root: str | None = None
    commands: list[list[str]]
    copy_artifacts: bool
    valid_package: bool
    blockers: list[str]
    executable: bool


class ExecutePostgresBootstrapPackageRequest(BaseModel):
    package_dir: str
    target_database_url: str
    artifact_target_root: str | None = None
    psql_executable: str = "psql"
    dry_run: bool = False


class ExecutePostgresBootstrapPackageResponse(BaseModel):
    package_dir: str
    target_database_url: str
    psql_executable: str
    artifact_target_root: str | None = None
    dry_run: bool
    executed_commands: list[list[str]]
    copied_artifacts: bool
    verification_passed: bool


class InspectPostgresTargetRequest(BaseModel):
    target_database_url: str
    psql_executable: str = "psql"


class PostgresTargetInspectionResponse(BaseModel):
    target: ControlPlaneCutoverTargetResponse
    psql_executable: str
    reachable: bool
    schema_version: int | None = None
    expected_schema_version: int
    schema_ready: bool
    maintenance_mode_active: bool | None = None
    table_presence: dict[str, bool]
    row_counts: dict[str, int | None]
    blockers: list[str]
    warnings: list[str]
    inspectable: bool


class VerifyPostgresBootstrapPackageRequest(BaseModel):
    package_dir: str
    target_database_url: str
    psql_executable: str = "psql"


class VerifyPostgresBootstrapPackageResponse(BaseModel):
    package_dir: str
    target_database_url: str
    psql_executable: str
    package_valid: bool
    target_reachable: bool
    schema_contract_match: bool
    schema_version_match: bool
    row_counts_match: bool
    missing_tables: list[str]
    row_count_mismatches: dict[str, dict[str, int | None]]
    blockers: list[str]
    package_inspection: PostgresBootstrapPackageInspectionResponse
    target_inspection: PostgresTargetInspectionResponse
    valid: bool


class RunPostgresCutoverRehearsalRequest(BaseModel):
    package_dir: str
    target_database_url: str
    changed_by: str
    reason: str | None = None
    psql_executable: str = "psql"
    artifact_target_root: str | None = None
    apply_to_target: bool = False


class PostgresCutoverRehearsalResponse(BaseModel):
    started_at: str
    completed_at: str
    changed_by: str
    reason: str | None = None
    package_dir: str
    target_database_url: str
    psql_executable: str
    artifact_target_root: str | None = None
    apply_to_target: bool
    steps: list[str]
    blockers: list[str]
    warnings: list[str]
    package_inspection: PostgresBootstrapPackageInspectionResponse
    target_before: PostgresTargetInspectionResponse
    execution_result: ExecutePostgresBootstrapPackageResponse | None = None
    target_after: PostgresTargetInspectionResponse | None = None
    verification: VerifyPostgresBootstrapPackageResponse | None = None
    valid: bool


class EvaluateControlPlaneCutoverReadinessRequest(BaseModel):
    target_database_url: str
    package_dir: str
    rehearsal_max_age_hours: float = 24.0
    require_apply_rehearsal: bool = False
    require_runtime_validation: bool | None = None


class ControlPlaneCutoverReadinessResponse(BaseModel):
    evaluated_at: str
    environment_name: str
    target_database_url: str
    target_database_redacted_url: str
    package_dir: str
    rehearsal_max_age_hours: float
    require_apply_rehearsal: bool
    require_runtime_validation: bool
    latest_bundle_event: ControlPlaneMaintenanceEventPayload | None = None
    latest_rehearsal_event: ControlPlaneMaintenanceEventPayload | None = None
    runtime_validation: ControlPlaneRuntimeValidationResponse
    runtime_validation_change_control_requests: list["ControlPlaneRuntimeValidationChangeControlPayload"] = Field(default_factory=list)
    package_inspection: PostgresBootstrapPackageInspectionResponse | None = None
    blockers: list[str]
    warnings: list[str]
    ready: bool


class DecideControlPlaneCutoverRequest(BaseModel):
    target_database_url: str
    package_dir: str
    changed_by: str
    requested_decision: str = "approve"
    reason: str | None = None
    decision_note: str | None = None
    rehearsal_max_age_hours: float = 24.0
    require_apply_rehearsal: bool = False
    require_runtime_validation: bool | None = None
    allow_override: bool = False

    @model_validator(mode="after")
    def validate_requested_decision(self) -> "DecideControlPlaneCutoverRequest":
        if self.requested_decision not in {"approve", "reject"}:
            raise ValueError("requested_decision must be 'approve' or 'reject'.")
        if self.requested_decision != "approve" and self.allow_override:
            raise ValueError("allow_override is only supported when requested_decision='approve'.")
        if self.allow_override and not self.decision_note:
            raise ValueError("decision_note is required when allow_override is enabled.")
        return self


class ControlPlaneCutoverPromotionResponse(BaseModel):
    decided_at: str
    environment_name: str
    requested_decision: str
    final_decision: str
    approved: bool
    changed_by: str
    reason: str | None = None
    decision_note: str | None = None
    package_dir: str
    target_database_url: str
    target_database_redacted_url: str
    rehearsal_max_age_hours: float
    require_apply_rehearsal: bool
    require_runtime_validation: bool
    allow_override: bool
    override_applied: bool
    readiness: ControlPlaneCutoverReadinessResponse
    blockers: list[str]
    warnings: list[str]
    maintenance_event: "ControlPlaneMaintenanceEventPayload"


class ControlPlaneCutoverPreflightResponse(BaseModel):
    generated_at: str
    environment_name: str
    source_database_backend: str
    source_database_url: str
    source_database_redacted_url: str
    target: ControlPlaneCutoverTargetResponse
    maintenance_preflight: ControlPlaneMaintenancePreflightResponse
    blockers: list[str]
    warnings: list[str]
    can_prepare: bool


class PrepareControlPlaneCutoverBundleRequest(BaseModel):
    output_path: str
    target_database_url: str
    changed_by: str
    reason: str | None = None
    allow_running_jobs: bool = False
    disable_maintenance_on_success: bool = True


class PrepareControlPlaneCutoverBundleResponse(BaseModel):
    bundle_version: int
    generated_at: str
    environment_name: str
    source_database_backend: str
    source_database_url: str
    source_database_redacted_url: str
    target: ControlPlaneCutoverTargetResponse
    path: str
    maintenance_workflow: RunControlPlaneMaintenanceWorkflowResponse
    recommended_restore_order: list[str]
    postgres_bootstrap_package: PostgresBootstrapPackageResponse | None = None


class ControlPlaneMaintenanceEventPayload(BaseModel):
    event_id: str
    recorded_at: str
    event_type: str
    changed_by: str
    reason: str | None = None
    details: dict[str, Any]


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
    assigned_to: str | None = None
    assigned_to_team: str | None = None
    assigned_at: str | None = None
    assigned_by: str | None = None
    assignment_note: str | None = None
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


class AssignControlPlaneOnCallChangeRequest(BaseModel):
    assigned_to: str
    assigned_to_team: str | None = None
    assigned_by: str
    assignment_note: str | None = None


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


class OnCallPendingReviewSamplePayload(BaseModel):
    request_id: str
    created_at: str
    team_name: str
    rotation_name: str | None = None
    age_hours: float
    change_reason: str | None = None
    assigned_to: str | None = None
    assigned_to_team: str | None = None


class OnCallAnalyticsPayload(BaseModel):
    total_schedules: int
    active_schedules: int
    conflict_count: int
    pending_review_count: int
    stale_pending_review_count: int
    oldest_pending_review_age_hours: float | None = None
    conflicts: list[OnCallConflictPayload]
    pending_review_samples: list[OnCallPendingReviewSamplePayload]


class RuntimeValidationReviewSamplePayload(BaseModel):
    review_id: str
    opened_at: str
    status: str
    age_hours: float
    owner_team: str | None = None
    assigned_to: str | None = None
    assigned_to_team: str | None = None
    policy_source: str
    summary: str | None = None


class RuntimeValidationReviewOwnerRollupPayload(BaseModel):
    owner_team: str
    active_review_count: int
    assigned_review_count: int
    unassigned_review_count: int
    stale_review_count: int


class RuntimeValidationReviewAnalyticsPayload(BaseModel):
    active_review_count: int
    assigned_review_count: int
    unassigned_review_count: int
    stale_review_count: int
    stale_unassigned_review_count: int
    oldest_review_age_hours: float | None = None
    review_samples: list[RuntimeValidationReviewSamplePayload]
    owner_team_rollups: list[RuntimeValidationReviewOwnerRollupPayload]


class DeploymentReadinessAnalyticsPayload(BaseModel):
    evaluated_at: str
    environment_name: str
    ready: bool
    blocker_count: int
    warning_count: int
    pending_change_control_count: int
    rejected_change_control_count: int
    blocked_owner_team_count: int
    oldest_rejected_age_hours: float | None = None
    owner_team_rollups: list[dict[str, Any]]
    blockers: list[str]
    warnings: list[str]


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
    oncall_pending_review_warning_threshold: int
    oncall_pending_review_critical_threshold: int
    oncall_pending_review_sla_hours: float
    runtime_validation_review_warning_threshold: int
    runtime_validation_review_critical_threshold: int
    runtime_rehearsal_due_soon_age_hours: float
    runtime_rehearsal_warning_age_hours: float
    runtime_rehearsal_critical_age_hours: float


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


class ControlPlaneRuntimeValidationResponse(BaseModel):
    generated_at: str
    environment_name: str
    status: str
    severity: str
    cadence_status: str
    policy_source: str
    due_soon_age_hours: float
    warning_age_hours: float
    critical_age_hours: float
    reminder_interval_seconds: float | None = None
    escalation_interval_seconds: float | None = None
    latest_rehearsal_event_id: str | None = None
    latest_rehearsal_recorded_at: str | None = None
    latest_rehearsal_changed_by: str | None = None
    latest_rehearsal_reason: str | None = None
    latest_rehearsal_status: str | None = None
    latest_expected_backend: str | None = None
    latest_expected_repository_layout: str | None = None
    latest_database_backend: str | None = None
    latest_repository_layout: str | None = None
    latest_mixed_backends: bool | None = None
    latest_checks: dict[str, bool] = Field(default_factory=dict)
    age_hours: float | None = None
    next_due_at: str | None = None
    due_in_hours: float | None = None
    blockers: list[str] = Field(default_factory=list)


class ControlPlaneRuntimeValidationReviewPayload(BaseModel):
    review_id: str
    opened_at: str
    opened_by: str
    environment_name: str
    status: str
    evidence_key: str
    trigger_status: str
    trigger_cadence_status: str
    summary: str
    latest_rehearsal_event_id: str | None = None
    latest_rehearsal_recorded_at: str | None = None
    due_in_hours: float | None = None
    next_due_at: str | None = None
    owner_team: str | None = None
    allowed_assignee_teams: list[str] | None = None
    assigned_to: str | None = None
    assigned_to_team: str | None = None
    assigned_at: str | None = None
    assigned_by: str | None = None
    assignment_note: str | None = None
    resolved_at: str | None = None
    resolved_by: str | None = None
    resolution_note: str | None = None
    resolution_reason: str | None = None
    policy_source: str


class ControlPlaneRuntimeValidationReviewOwnerQueueRollupPayload(BaseModel):
    owner_team: str
    total_reviews: int
    assigned_reviews: int
    unassigned_reviews: int
    stale_reviews: int


class ControlPlaneRuntimeValidationReviewQueuePayload(BaseModel):
    environment_name: str
    total_reviews: int
    assigned_reviews: int
    unassigned_reviews: int
    stale_reviews: int
    stale_unassigned_reviews: int
    oldest_review_age_hours: float | None = None
    owner_team_rollups: list[ControlPlaneRuntimeValidationReviewOwnerQueueRollupPayload]
    reviews: list[ControlPlaneRuntimeValidationReviewPayload]


class ControlPlaneRuntimeValidationReviewBulkActionPayload(BaseModel):
    environment_name: str
    action: str
    matched_count: int
    changed_count: int
    reviews: list[ControlPlaneRuntimeValidationReviewPayload]


class ControlPlaneRuntimeValidationGovernancePayload(BaseModel):
    request_id: str
    opened_at: str
    opened_by: str
    environment_name: str
    review_id: str
    owner_team: str | None = None
    review_opened_at: str
    summary: str
    status: str
    trigger_code: str
    policy_source: str
    assigned_to: str | None = None
    assigned_to_team: str | None = None
    resolved_at: str | None = None
    resolved_by: str | None = None
    resolution_note: str | None = None
    resolution_reason: str | None = None


class ControlPlaneRuntimeValidationChangeControlPayload(BaseModel):
    request_id: str
    opened_at: str
    opened_by: str
    environment_name: str
    governance_request_id: str
    review_id: str
    owner_team: str | None = None
    summary: str
    status: str
    trigger_code: str
    policy_source: str
    assigned_to: str | None = None
    assigned_to_team: str | None = None
    assigned_at: str | None = None
    assigned_by: str | None = None
    assignment_note: str | None = None
    resolved_at: str | None = None
    resolved_by: str | None = None
    resolution_note: str | None = None
    resolution_reason: str | None = None


class ControlPlaneRuntimeValidationChangeControlQueuePayload(BaseModel):
    environment_name: str
    total_requests: int
    assigned_requests: int
    unassigned_requests: int
    pending_review_count: int
    rejected_count: int
    owner_team_rollups: list[dict[str, Any]]
    requests: list["ControlPlaneRuntimeValidationChangeControlPayload"]


class ControlPlaneRuntimeValidationChangeControlBulkActionPayload(BaseModel):
    environment_name: str
    action: str
    matched_count: int
    changed_count: int
    requests: list["ControlPlaneRuntimeValidationChangeControlPayload"]


class ProcessRuntimeValidationReviewsRequest(BaseModel):
    changed_by: str = "system"
    reason: str | None = None
    force: bool = False


class ProcessRuntimeValidationGovernanceRequest(BaseModel):
    changed_by: str = "system"
    reason: str | None = None
    force: bool = False


class ProcessRuntimeValidationChangeControlRequest(BaseModel):
    changed_by: str = "system"
    reason: str | None = None
    force: bool = False


class AssignRuntimeValidationChangeControlRequest(BaseModel):
    assigned_to: str
    assigned_to_team: str | None = None
    assigned_by: str
    assignment_note: str | None = None


class ReviewRuntimeValidationChangeControlRequest(BaseModel):
    decision: str
    decided_by: str
    decision_note: str | None = None


class BulkAssignRuntimeValidationChangeControlRequest(BaseModel):
    assigned_to: str
    assigned_to_team: str | None = None
    assigned_by: str
    assignment_note: str | None = None
    status: str | None = None
    owner_team: str | None = None
    assignment_state: str | None = None


class BulkReviewRuntimeValidationChangeControlRequest(BaseModel):
    decision: str
    decided_by: str
    decision_note: str | None = None
    status: str | None = None
    owner_team: str | None = None
    assignment_state: str | None = None


class AssignRuntimeValidationReviewRequest(BaseModel):
    assigned_to: str
    assigned_to_team: str | None = None
    assigned_by: str
    assignment_note: str | None = None


class ResolveRuntimeValidationReviewRequest(BaseModel):
    resolved_by: str
    resolution_note: str | None = None
    resolution_reason: str = "manual_resolution"


class BulkAssignRuntimeValidationReviewsRequest(BaseModel):
    assigned_to: str
    assigned_to_team: str | None = None
    assigned_by: str
    assignment_note: str | None = None
    status: str | None = None
    owner_team: str | None = None
    assignment_state: str | None = None


class BulkResolveRuntimeValidationReviewsRequest(BaseModel):
    resolved_by: str
    resolution_note: str | None = None
    resolution_reason: str = "manual_resolution"
    status: str | None = None
    owner_team: str | None = None
    assignment_state: str | None = None


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
    runtime_validation: ControlPlaneRuntimeValidationResponse
    deployment_readiness: DeploymentReadinessAnalyticsPayload
    runtime_validation_reviews: RuntimeValidationReviewAnalyticsPayload
    evaluation: ControlPlaneEvaluationPayload
