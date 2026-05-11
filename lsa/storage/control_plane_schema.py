from __future__ import annotations


CONTROL_PLANE_SCHEMA_VERSION = 1
CONTROL_PLANE_SCHEMA_MIGRATION_ID = "2026-05-05-control-plane-schema-v1"
CONTROL_PLANE_SCHEMA_MIGRATION_DESCRIPTION = "Bootstrap schema version tracking for the control-plane database."
CONTROL_PLANE_RUNTIME_BACKENDS = ("sqlite",)
CONTROL_PLANE_BOOTSTRAP_BACKENDS = ("postgres",)
CONTROL_PLANE_TABLE_NAMES = (
    "control_plane_schema_metadata",
    "control_plane_schema_migrations",
    "snapshots",
    "audits",
    "jobs",
    "workers",
    "worker_heartbeats",
    "worker_heartbeat_rollups",
    "job_lease_events",
    "job_lease_event_rollups",
    "control_plane_maintenance_events",
    "control_plane_alerts",
    "control_plane_alert_silences",
    "control_plane_oncall_schedules",
    "control_plane_oncall_change_requests",
)


def control_plane_schema_contract() -> dict[str, object]:
    return {
        "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
        "migration_id": CONTROL_PLANE_SCHEMA_MIGRATION_ID,
        "migration_description": CONTROL_PLANE_SCHEMA_MIGRATION_DESCRIPTION,
        "runtime_supported_backends": list(CONTROL_PLANE_RUNTIME_BACKENDS),
        "bootstrap_supported_backends": list(CONTROL_PLANE_BOOTSTRAP_BACKENDS),
        "table_names": list(CONTROL_PLANE_TABLE_NAMES),
    }


def sqlite_control_plane_schema_script() -> str:
    return """CREATE TABLE IF NOT EXISTS control_plane_schema_metadata (
    metadata_key TEXT PRIMARY KEY,
    metadata_value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS control_plane_schema_migrations (
    migration_id TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL,
    applied_at TEXT NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    repo_path TEXT NOT NULL,
    node_count INTEGER NOT NULL,
    edge_count INTEGER NOT NULL,
    snapshot_path TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapshots_created_at ON snapshots (created_at DESC);

CREATE TABLE IF NOT EXISTS audits (
    audit_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    snapshot_id TEXT,
    snapshot_path TEXT NOT NULL,
    alert_count INTEGER NOT NULL,
    report_paths_json TEXT NOT NULL,
    alerts_json TEXT NOT NULL,
    events_json TEXT NOT NULL,
    sessions_json TEXT NOT NULL,
    explanation_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audits_created_at ON audits (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audits_snapshot_id ON audits (snapshot_id);

CREATE TABLE IF NOT EXISTS jobs (
    job_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    job_type TEXT NOT NULL,
    status TEXT NOT NULL,
    request_payload_json TEXT NOT NULL,
    result_payload_json TEXT NOT NULL,
    error TEXT,
    started_at TEXT,
    completed_at TEXT,
    claimed_by_worker_id TEXT,
    lease_expires_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs (status);

CREATE TABLE IF NOT EXISTS workers (
    worker_id TEXT PRIMARY KEY,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    last_heartbeat_at TEXT NOT NULL,
    host_name TEXT NOT NULL,
    process_id INTEGER NOT NULL,
    current_job_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_workers_last_heartbeat_at ON workers (last_heartbeat_at DESC);

CREATE TABLE IF NOT EXISTS worker_heartbeats (
    heartbeat_id TEXT PRIMARY KEY,
    worker_id TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    status TEXT NOT NULL,
    current_job_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_worker_heartbeats_worker_id ON worker_heartbeats (worker_id, recorded_at DESC);

CREATE TABLE IF NOT EXISTS worker_heartbeat_rollups (
    day_bucket TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    status TEXT NOT NULL,
    current_job_id TEXT,
    event_count INTEGER NOT NULL,
    PRIMARY KEY (day_bucket, worker_id, status, current_job_id)
);

CREATE TABLE IF NOT EXISTS job_lease_events (
    event_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    worker_id TEXT,
    event_type TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    details_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_job_lease_events_job_id ON job_lease_events (job_id, recorded_at DESC);

CREATE TABLE IF NOT EXISTS job_lease_event_rollups (
    day_bucket TEXT NOT NULL,
    job_id TEXT NOT NULL,
    worker_id TEXT,
    event_type TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    PRIMARY KEY (day_bucket, job_id, worker_id, event_type)
);

CREATE TABLE IF NOT EXISTS control_plane_maintenance_events (
    event_id TEXT PRIMARY KEY,
    recorded_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    changed_by TEXT NOT NULL,
    reason TEXT,
    details_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_control_plane_maintenance_events_recorded_at
    ON control_plane_maintenance_events (recorded_at DESC);

CREATE TABLE IF NOT EXISTS control_plane_alerts (
    alert_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    alert_key TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    summary TEXT NOT NULL,
    finding_codes_json TEXT NOT NULL,
    delivery_state TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    error TEXT,
    acknowledged_at TEXT,
    acknowledged_by TEXT,
    acknowledgement_note TEXT
);
CREATE INDEX IF NOT EXISTS idx_control_plane_alerts_created_at ON control_plane_alerts (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_control_plane_alerts_alert_key ON control_plane_alerts (alert_key, created_at DESC);

CREATE TABLE IF NOT EXISTS control_plane_alert_silences (
    silence_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    match_alert_key TEXT,
    match_finding_code TEXT,
    starts_at TEXT,
    expires_at TEXT,
    cancelled_at TEXT,
    cancelled_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_control_plane_alert_silences_created_at
    ON control_plane_alert_silences (created_at DESC);

CREATE TABLE IF NOT EXISTS control_plane_oncall_schedules (
    schedule_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    environment_name TEXT NOT NULL DEFAULT 'default',
    created_by_team TEXT,
    created_by_role TEXT,
    change_reason TEXT,
    approved_by TEXT,
    approved_by_team TEXT,
    approved_by_role TEXT,
    approved_at TEXT,
    approval_note TEXT,
    team_name TEXT NOT NULL,
    timezone_name TEXT NOT NULL,
    weekdays_json TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 100,
    rotation_name TEXT,
    effective_start_date TEXT,
    effective_end_date TEXT,
    webhook_url TEXT,
    escalation_webhook_url TEXT,
    cancelled_at TEXT,
    cancelled_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_control_plane_oncall_schedules_created_at
    ON control_plane_oncall_schedules (created_at DESC);

CREATE TABLE IF NOT EXISTS control_plane_oncall_change_requests (
    request_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    environment_name TEXT NOT NULL DEFAULT 'default',
    created_by_team TEXT,
    created_by_role TEXT,
    change_reason TEXT,
    status TEXT NOT NULL,
    review_required INTEGER NOT NULL,
    review_reasons_json TEXT NOT NULL,
    team_name TEXT NOT NULL,
    timezone_name TEXT NOT NULL,
    weekdays_json TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 100,
    rotation_name TEXT,
    effective_start_date TEXT,
    effective_end_date TEXT,
    webhook_url TEXT,
    escalation_webhook_url TEXT,
    assigned_to TEXT,
    assigned_to_team TEXT,
    assigned_at TEXT,
    assigned_by TEXT,
    assignment_note TEXT,
    decision_at TEXT,
    decided_by TEXT,
    decided_by_team TEXT,
    decided_by_role TEXT,
    decision_note TEXT,
    applied_schedule_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_control_plane_oncall_change_requests_created_at
    ON control_plane_oncall_change_requests (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_control_plane_oncall_change_requests_status
    ON control_plane_oncall_change_requests (status, created_at DESC);
"""


def postgres_control_plane_schema_script() -> str:
    return """BEGIN;

CREATE TABLE IF NOT EXISTS control_plane_schema_metadata (
    metadata_key TEXT PRIMARY KEY,
    metadata_value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS control_plane_schema_migrations (
    migration_id TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    repo_path TEXT NOT NULL,
    node_count INTEGER NOT NULL,
    edge_count INTEGER NOT NULL,
    snapshot_path TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapshots_created_at ON snapshots (created_at DESC);

CREATE TABLE IF NOT EXISTS audits (
    audit_id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    snapshot_id TEXT,
    snapshot_path TEXT NOT NULL,
    alert_count INTEGER NOT NULL,
    report_paths_json JSONB NOT NULL,
    alerts_json JSONB NOT NULL,
    events_json JSONB NOT NULL,
    sessions_json JSONB NOT NULL,
    explanation_json JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audits_created_at ON audits (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audits_snapshot_id ON audits (snapshot_id);

CREATE TABLE IF NOT EXISTS jobs (
    job_id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    job_type TEXT NOT NULL,
    status TEXT NOT NULL,
    request_payload_json JSONB NOT NULL,
    result_payload_json JSONB NOT NULL,
    error TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    claimed_by_worker_id TEXT,
    lease_expires_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs (status);

CREATE TABLE IF NOT EXISTS workers (
    worker_id TEXT PRIMARY KEY,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    last_heartbeat_at TIMESTAMPTZ NOT NULL,
    host_name TEXT NOT NULL,
    process_id INTEGER NOT NULL,
    current_job_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_workers_last_heartbeat_at ON workers (last_heartbeat_at DESC);

CREATE TABLE IF NOT EXISTS worker_heartbeats (
    heartbeat_id TEXT PRIMARY KEY,
    worker_id TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL,
    current_job_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_worker_heartbeats_worker_id ON worker_heartbeats (worker_id, recorded_at DESC);

CREATE TABLE IF NOT EXISTS worker_heartbeat_rollups (
    day_bucket TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    status TEXT NOT NULL,
    current_job_id TEXT,
    event_count INTEGER NOT NULL,
    PRIMARY KEY (day_bucket, worker_id, status, current_job_id)
);

CREATE TABLE IF NOT EXISTS job_lease_events (
    event_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    worker_id TEXT,
    event_type TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    details_json JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_job_lease_events_job_id ON job_lease_events (job_id, recorded_at DESC);

CREATE TABLE IF NOT EXISTS job_lease_event_rollups (
    day_bucket TEXT NOT NULL,
    job_id TEXT NOT NULL,
    worker_id TEXT,
    event_type TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    PRIMARY KEY (day_bucket, job_id, worker_id, event_type)
);

CREATE TABLE IF NOT EXISTS control_plane_maintenance_events (
    event_id TEXT PRIMARY KEY,
    recorded_at TIMESTAMPTZ NOT NULL,
    event_type TEXT NOT NULL,
    changed_by TEXT NOT NULL,
    reason TEXT,
    details_json JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_control_plane_maintenance_events_recorded_at
    ON control_plane_maintenance_events (recorded_at DESC);

CREATE TABLE IF NOT EXISTS control_plane_alerts (
    alert_id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    alert_key TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    summary TEXT NOT NULL,
    finding_codes_json JSONB NOT NULL,
    delivery_state TEXT NOT NULL,
    payload_json JSONB NOT NULL,
    error TEXT,
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by TEXT,
    acknowledgement_note TEXT
);
CREATE INDEX IF NOT EXISTS idx_control_plane_alerts_created_at ON control_plane_alerts (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_control_plane_alerts_alert_key ON control_plane_alerts (alert_key, created_at DESC);

CREATE TABLE IF NOT EXISTS control_plane_alert_silences (
    silence_id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    match_alert_key TEXT,
    match_finding_code TEXT,
    starts_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,
    cancelled_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_control_plane_alert_silences_created_at
    ON control_plane_alert_silences (created_at DESC);

CREATE TABLE IF NOT EXISTS control_plane_oncall_schedules (
    schedule_id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL,
    team_name TEXT NOT NULL,
    timezone_name TEXT NOT NULL,
    environment_name TEXT NOT NULL,
    created_by_team TEXT,
    created_by_role TEXT,
    change_reason TEXT,
    approved_by TEXT,
    approved_by_team TEXT,
    approved_by_role TEXT,
    approved_at TIMESTAMPTZ,
    approval_note TEXT,
    weekdays_json JSONB NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    priority INTEGER NOT NULL,
    rotation_name TEXT,
    effective_start_date TEXT,
    effective_end_date TEXT,
    webhook_url TEXT,
    escalation_webhook_url TEXT,
    cancelled_at TIMESTAMPTZ,
    cancelled_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_control_plane_oncall_schedules_created_at
    ON control_plane_oncall_schedules (created_at DESC);

CREATE TABLE IF NOT EXISTS control_plane_oncall_change_requests (
    request_id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL,
    team_name TEXT NOT NULL,
    timezone_name TEXT NOT NULL,
    status TEXT NOT NULL,
    environment_name TEXT NOT NULL,
    created_by_team TEXT,
    created_by_role TEXT,
    change_reason TEXT,
    review_required BOOLEAN NOT NULL,
    review_reasons_json JSONB NOT NULL,
    weekdays_json JSONB NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    priority INTEGER NOT NULL,
    rotation_name TEXT,
    effective_start_date TEXT,
    effective_end_date TEXT,
    webhook_url TEXT,
    escalation_webhook_url TEXT,
    assigned_to TEXT,
    assigned_to_team TEXT,
    assigned_at TIMESTAMPTZ,
    assigned_by TEXT,
    assignment_note TEXT,
    decision_at TIMESTAMPTZ,
    decided_by TEXT,
    decided_by_team TEXT,
    decided_by_role TEXT,
    decision_note TEXT,
    applied_schedule_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_control_plane_oncall_change_requests_created_at
    ON control_plane_oncall_change_requests (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_control_plane_oncall_change_requests_status
    ON control_plane_oncall_change_requests (status, created_at DESC);

COMMIT;
"""
