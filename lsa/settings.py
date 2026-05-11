from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from lsa.storage.database import resolve_database_config


@dataclass(slots=True)
class WorkspaceSettings:
    root_dir: Path
    data_dir: Path
    database_path: Path
    database_url: str
    database_backend: str
    enable_postgres_runtime_snapshots_audits: bool
    postgres_runtime_snapshots_audits_database_url: str | None
    enable_postgres_runtime_jobs: bool
    postgres_runtime_jobs_database_url: str | None
    sqlite_busy_timeout_ms: int
    environment_name: str
    api_key: str | None
    run_embedded_worker: bool
    worker_heartbeat_timeout_seconds: float
    worker_history_retention_days: int
    job_lease_history_retention_days: int
    history_prune_interval_seconds: float
    analytics_queue_warning_threshold: int
    analytics_queue_critical_threshold: int
    analytics_stale_worker_warning_threshold: int
    analytics_stale_worker_critical_threshold: int
    analytics_expired_lease_warning_threshold: int
    analytics_expired_lease_critical_threshold: int
    analytics_job_failure_rate_warning_threshold: float
    analytics_job_failure_rate_critical_threshold: float
    analytics_job_failure_rate_min_samples: int
    analytics_oncall_conflict_warning_threshold: int
    analytics_oncall_conflict_critical_threshold: int
    analytics_oncall_pending_review_warning_threshold: int
    analytics_oncall_pending_review_critical_threshold: int
    analytics_oncall_pending_review_sla_hours: float
    analytics_runtime_rehearsal_due_soon_age_hours: float
    analytics_runtime_rehearsal_warning_age_hours: float
    analytics_runtime_rehearsal_critical_age_hours: float
    runtime_validation_policy_path: Path
    maintenance_runtime_validation_required: bool
    cutover_runtime_validation_required: bool
    oncall_policy_path: Path
    oncall_approval_required_roles: tuple[str, ...]
    oncall_allow_self_approval: bool
    control_plane_alerts_enabled: bool
    control_plane_alert_window_days: int
    control_plane_alert_interval_seconds: float
    control_plane_alert_dedup_window_seconds: float
    control_plane_alert_reminder_interval_seconds: float
    control_plane_alert_escalation_interval_seconds: float
    control_plane_alert_webhook_url: str | None
    control_plane_alert_escalation_webhook_url: str | None
    control_plane_alert_sink_path: Path
    snapshots_dir: Path
    audits_dir: Path
    reports_dir: Path
    traces_dir: Path
    destination_aliases_path: Path


def resolve_workspace_settings(base_dir: str | Path | None = None) -> WorkspaceSettings:
    root = Path(base_dir).resolve() if base_dir else Path.cwd().resolve()
    data_dir = root / "data"
    database_config = resolve_database_config(
        root_dir=root,
        default_path=data_dir / "control_plane.db",
        raw_url=os.environ.get("LSA_DATABASE_URL"),
    )
    return WorkspaceSettings(
        root_dir=root,
        data_dir=data_dir,
        database_path=database_config.sqlite_path,
        database_url=database_config.url,
        database_backend=database_config.backend,
        enable_postgres_runtime_snapshots_audits=_env_flag(
            "LSA_ENABLE_POSTGRES_RUNTIME_SNAPSHOTS_AUDITS",
            default=False,
        ),
        postgres_runtime_snapshots_audits_database_url=os.environ.get(
            "LSA_POSTGRES_RUNTIME_SNAPSHOTS_AUDITS_DATABASE_URL"
        ),
        enable_postgres_runtime_jobs=_env_flag("LSA_ENABLE_POSTGRES_RUNTIME_JOBS", default=False),
        postgres_runtime_jobs_database_url=os.environ.get("LSA_POSTGRES_RUNTIME_JOBS_DATABASE_URL"),
        sqlite_busy_timeout_ms=_env_int("LSA_SQLITE_BUSY_TIMEOUT_MS", default=5000),
        environment_name=os.environ.get("LSA_ENVIRONMENT_NAME", "default").strip().lower() or "default",
        api_key=os.environ.get("LSA_API_KEY"),
        run_embedded_worker=_env_flag("LSA_RUN_EMBEDDED_WORKER", default=False),
        worker_heartbeat_timeout_seconds=_env_float("LSA_WORKER_HEARTBEAT_TIMEOUT_SECONDS", default=5.0),
        worker_history_retention_days=_env_int("LSA_WORKER_HISTORY_RETENTION_DAYS", default=14),
        job_lease_history_retention_days=_env_int("LSA_JOB_LEASE_HISTORY_RETENTION_DAYS", default=30),
        history_prune_interval_seconds=_env_float("LSA_HISTORY_PRUNE_INTERVAL_SECONDS", default=300.0),
        analytics_queue_warning_threshold=_env_int("LSA_ANALYTICS_QUEUE_WARNING_THRESHOLD", default=5),
        analytics_queue_critical_threshold=_env_int("LSA_ANALYTICS_QUEUE_CRITICAL_THRESHOLD", default=20),
        analytics_stale_worker_warning_threshold=_env_int("LSA_ANALYTICS_STALE_WORKER_WARNING_THRESHOLD", default=1),
        analytics_stale_worker_critical_threshold=_env_int("LSA_ANALYTICS_STALE_WORKER_CRITICAL_THRESHOLD", default=3),
        analytics_expired_lease_warning_threshold=_env_int("LSA_ANALYTICS_EXPIRED_LEASE_WARNING_THRESHOLD", default=1),
        analytics_expired_lease_critical_threshold=_env_int("LSA_ANALYTICS_EXPIRED_LEASE_CRITICAL_THRESHOLD", default=3),
        analytics_job_failure_rate_warning_threshold=_env_float(
            "LSA_ANALYTICS_JOB_FAILURE_RATE_WARNING_THRESHOLD",
            default=0.1,
        ),
        analytics_job_failure_rate_critical_threshold=_env_float(
            "LSA_ANALYTICS_JOB_FAILURE_RATE_CRITICAL_THRESHOLD",
            default=0.25,
        ),
        analytics_job_failure_rate_min_samples=_env_int("LSA_ANALYTICS_JOB_FAILURE_RATE_MIN_SAMPLES", default=3),
        analytics_oncall_conflict_warning_threshold=_env_int(
            "LSA_ANALYTICS_ONCALL_CONFLICT_WARNING_THRESHOLD",
            default=1,
        ),
        analytics_oncall_conflict_critical_threshold=_env_int(
            "LSA_ANALYTICS_ONCALL_CONFLICT_CRITICAL_THRESHOLD",
            default=3,
        ),
        analytics_oncall_pending_review_warning_threshold=_env_int(
            "LSA_ANALYTICS_ONCALL_PENDING_REVIEW_WARNING_THRESHOLD",
            default=1,
        ),
        analytics_oncall_pending_review_critical_threshold=_env_int(
            "LSA_ANALYTICS_ONCALL_PENDING_REVIEW_CRITICAL_THRESHOLD",
            default=3,
        ),
        analytics_oncall_pending_review_sla_hours=_env_float(
            "LSA_ANALYTICS_ONCALL_PENDING_REVIEW_SLA_HOURS",
            default=24.0,
        ),
        analytics_runtime_rehearsal_due_soon_age_hours=_env_float(
            "LSA_ANALYTICS_RUNTIME_REHEARSAL_DUE_SOON_AGE_HOURS",
            default=18.0,
        ),
        analytics_runtime_rehearsal_warning_age_hours=_env_float(
            "LSA_ANALYTICS_RUNTIME_REHEARSAL_WARNING_AGE_HOURS",
            default=24.0,
        ),
        analytics_runtime_rehearsal_critical_age_hours=_env_float(
            "LSA_ANALYTICS_RUNTIME_REHEARSAL_CRITICAL_AGE_HOURS",
            default=72.0,
        ),
        runtime_validation_policy_path=Path(
            os.environ.get(
                "LSA_RUNTIME_VALIDATION_POLICY_PATH",
                str(data_dir / "runtime_validation_policy.json"),
            )
        ),
        maintenance_runtime_validation_required=_env_flag(
            "LSA_MAINTENANCE_RUNTIME_VALIDATION_REQUIRED",
            default=False,
        ),
        cutover_runtime_validation_required=_env_flag(
            "LSA_CUTOVER_RUNTIME_VALIDATION_REQUIRED",
            default=True,
        ),
        oncall_policy_path=Path(
            os.environ.get("LSA_ONCALL_POLICY_PATH", str(data_dir / "oncall_policy.json"))
        ),
        oncall_approval_required_roles=_env_csv(
            "LSA_ONCALL_APPROVAL_REQUIRED_ROLES",
            default=("manager", "director", "admin"),
        ),
        oncall_allow_self_approval=_env_flag("LSA_ONCALL_ALLOW_SELF_APPROVAL", default=False),
        control_plane_alerts_enabled=_env_flag("LSA_CONTROL_PLANE_ALERTS_ENABLED", default=True),
        control_plane_alert_window_days=_env_int("LSA_CONTROL_PLANE_ALERT_WINDOW_DAYS", default=7),
        control_plane_alert_interval_seconds=_env_float("LSA_CONTROL_PLANE_ALERT_INTERVAL_SECONDS", default=60.0),
        control_plane_alert_dedup_window_seconds=_env_float(
            "LSA_CONTROL_PLANE_ALERT_DEDUP_WINDOW_SECONDS",
            default=300.0,
        ),
        control_plane_alert_reminder_interval_seconds=_env_float(
            "LSA_CONTROL_PLANE_ALERT_REMINDER_INTERVAL_SECONDS",
            default=900.0,
        ),
        control_plane_alert_escalation_interval_seconds=_env_float(
            "LSA_CONTROL_PLANE_ALERT_ESCALATION_INTERVAL_SECONDS",
            default=1800.0,
        ),
        control_plane_alert_webhook_url=os.environ.get("LSA_CONTROL_PLANE_ALERT_WEBHOOK_URL"),
        control_plane_alert_escalation_webhook_url=os.environ.get("LSA_CONTROL_PLANE_ALERT_ESCALATION_WEBHOOK_URL"),
        control_plane_alert_sink_path=data_dir / "control_plane_alerts.jsonl",
        snapshots_dir=data_dir / "intent_graphs",
        audits_dir=data_dir / "audits",
        reports_dir=data_dir / "reports",
        traces_dir=data_dir / "traces",
        destination_aliases_path=data_dir / "destination_aliases.json",
    )


def _env_flag(name: str, *, default: bool) -> bool:
    raw_value = os.environ.get(name)
    if raw_value is None:
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, *, default: float) -> float:
    raw_value = os.environ.get(name)
    if raw_value is None:
        return default
    try:
        return float(raw_value)
    except ValueError:
        return default


def _env_int(name: str, *, default: int) -> int:
    raw_value = os.environ.get(name)
    if raw_value is None:
        return default
    try:
        return int(raw_value)
    except ValueError:
        return default


def _env_csv(name: str, *, default: tuple[str, ...]) -> tuple[str, ...]:
    raw_value = os.environ.get(name)
    if raw_value is None:
        return default
    values = tuple(item.strip().lower() for item in raw_value.split(",") if item.strip())
    return values or default
