from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class WorkspaceSettings:
    root_dir: Path
    data_dir: Path
    database_path: Path
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
    return WorkspaceSettings(
        root_dir=root,
        data_dir=data_dir,
        database_path=data_dir / "control_plane.db",
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
