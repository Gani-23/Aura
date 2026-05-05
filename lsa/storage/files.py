from __future__ import annotations

import json
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from lsa.core.intent_graph import IntentGraph
from lsa.core.models import IntentGraphSnapshot
from lsa.settings import WorkspaceSettings
from lsa.storage.database import resolve_database_config
from lsa.storage.models import (
    AuditRecord,
    ControlPlaneAlertRecord,
    ControlPlaneMaintenanceEventRecord,
    ControlPlaneOnCallChangeRequestRecord,
    ControlPlaneOnCallScheduleRecord,
    ControlPlaneAlertSilenceRecord,
    JobLeaseEventRecord,
    JobLeaseEventRollupRecord,
    JobRecord,
    SnapshotRecord,
    WorkerHeartbeatRecord,
    WorkerHeartbeatRollupRecord,
    WorkerRecord,
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _json_dumps(value: object) -> str:
    return json.dumps(value, sort_keys=True)


CONTROL_PLANE_SCHEMA_VERSION = 1
CONTROL_PLANE_SCHEMA_MIGRATION_ID = "2026-05-05-control-plane-schema-v1"
CONTROL_PLANE_SCHEMA_MIGRATION_DESCRIPTION = "Bootstrap schema version tracking for the control-plane database."


class _ControlPlaneDatabase:
    def __init__(self, settings: WorkspaceSettings) -> None:
        self.settings = settings
        self.config = resolve_database_config(
            root_dir=self.settings.root_dir,
            default_path=self.settings.database_path,
            raw_url=self.settings.database_url,
        )
        self.settings.data_dir.mkdir(parents=True, exist_ok=True)
        self.config.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()
        self._import_legacy_records()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.config.sqlite_target,
            timeout=self.settings.sqlite_busy_timeout_ms / 1000,
            uri=self.config.sqlite_uri,
        )
        connection.row_factory = sqlite3.Row
        self._configure_connection(connection)
        return connection

    def _configure_connection(self, connection: sqlite3.Connection) -> None:
        connection.execute(f"PRAGMA busy_timeout = {int(self.settings.sqlite_busy_timeout_ms)}")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = NORMAL")
        connection.execute("PRAGMA temp_store = MEMORY")

    def status(self) -> dict[str, object]:
        ready = False
        writable = False
        schema_version = 0
        expected_schema_version = CONTROL_PLANE_SCHEMA_VERSION
        schema_ready = False
        try:
            with self._connect() as connection:
                ready = bool(connection.execute("SELECT 1").fetchone()[0])
                query_only_row = connection.execute("PRAGMA query_only").fetchone()
                writable = bool(query_only_row is not None and int(query_only_row[0]) == 0)
                schema_version = self._read_schema_version(connection)
                schema_ready = schema_version == expected_schema_version
        except sqlite3.Error:
            ready = False
            writable = False
            schema_version = 0
            schema_ready = False

        path_target = self.config.sqlite_path if self.config.sqlite_path.exists() else self.config.sqlite_path.parent
        writable = writable and os.access(path_target, os.W_OK)
        return {
            "backend": self.config.backend,
            "url": self.config.url,
            "path": str(self.config.sqlite_path),
            "ready": ready,
            "writable": writable,
            "schema_version": schema_version,
            "expected_schema_version": expected_schema_version,
            "schema_ready": schema_ready,
            "pending_migration_count": max(0, expected_schema_version - schema_version),
        }

    def schema_status(self) -> dict[str, object]:
        with self._connect() as connection:
            version = self._read_schema_version(connection)
            rows = connection.execute(
                """
                SELECT migration_id, schema_version, applied_at, description
                FROM control_plane_schema_migrations
                ORDER BY applied_at ASC, migration_id ASC
                """
            ).fetchall()
        return {
            "schema_version": version,
            "expected_schema_version": CONTROL_PLANE_SCHEMA_VERSION,
            "schema_ready": version == CONTROL_PLANE_SCHEMA_VERSION,
            "pending_migration_count": max(0, CONTROL_PLANE_SCHEMA_VERSION - version),
            "migrations": [
                {
                    "migration_id": row["migration_id"],
                    "schema_version": row["schema_version"],
                    "applied_at": row["applied_at"],
                    "description": row["description"],
                }
                for row in rows
            ],
        }

    def migrate_schema(self) -> dict[str, object]:
        self._initialize()
        return self.schema_status()

    def maintenance_mode_status(self) -> dict[str, object]:
        with self._connect() as connection:
            active = self._read_metadata(connection, "maintenance_mode_active") == "1"
            changed_at = self._read_metadata(connection, "maintenance_mode_changed_at")
            changed_by = self._read_metadata(connection, "maintenance_mode_changed_by")
            reason = self._read_metadata(connection, "maintenance_mode_reason")
        return {
            "active": active,
            "changed_at": changed_at,
            "changed_by": changed_by,
            "reason": reason,
        }

    def set_maintenance_mode(self, *, active: bool, changed_by: str, reason: str | None) -> dict[str, object]:
        with self._connect() as connection:
            self._upsert_metadata(connection, "maintenance_mode_active", "1" if active else "0")
            self._upsert_metadata(connection, "maintenance_mode_changed_at", _utc_now())
            self._upsert_metadata(connection, "maintenance_mode_changed_by", changed_by)
            self._upsert_metadata(connection, "maintenance_mode_reason", reason or "")
        return self.maintenance_mode_status()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS control_plane_schema_metadata (
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

                CREATE INDEX IF NOT EXISTS idx_snapshots_created_at
                    ON snapshots (created_at DESC);

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

                CREATE INDEX IF NOT EXISTS idx_audits_created_at
                    ON audits (created_at DESC);

                CREATE INDEX IF NOT EXISTS idx_audits_snapshot_id
                    ON audits (snapshot_id);

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

                CREATE INDEX IF NOT EXISTS idx_jobs_created_at
                    ON jobs (created_at DESC);

                CREATE INDEX IF NOT EXISTS idx_jobs_status
                    ON jobs (status);

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

                CREATE INDEX IF NOT EXISTS idx_workers_last_heartbeat_at
                    ON workers (last_heartbeat_at DESC);

                CREATE TABLE IF NOT EXISTS worker_heartbeats (
                    heartbeat_id TEXT PRIMARY KEY,
                    worker_id TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    current_job_id TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_worker_heartbeats_worker_id
                    ON worker_heartbeats (worker_id, recorded_at DESC);

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

                CREATE INDEX IF NOT EXISTS idx_job_lease_events_job_id
                    ON job_lease_events (job_id, recorded_at DESC);

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
                    error TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_control_plane_alerts_created_at
                    ON control_plane_alerts (created_at DESC);

                CREATE INDEX IF NOT EXISTS idx_control_plane_alerts_alert_key
                    ON control_plane_alerts (alert_key, created_at DESC);

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
            )
            self._initialize_schema_metadata(connection)
        self._ensure_job_columns()
        self._ensure_control_plane_alert_columns()
        self._ensure_control_plane_oncall_schedule_columns()
        self._ensure_control_plane_oncall_change_request_columns()

    def _initialize_schema_metadata(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            INSERT INTO control_plane_schema_metadata (metadata_key, metadata_value)
            VALUES ('schema_version', ?)
            ON CONFLICT(metadata_key) DO NOTHING
            """,
            (str(CONTROL_PLANE_SCHEMA_VERSION),),
        )
        connection.execute(
            """
            INSERT INTO control_plane_schema_migrations (
                migration_id,
                schema_version,
                applied_at,
                description
            ) VALUES (?, ?, ?, ?)
            ON CONFLICT(migration_id) DO NOTHING
            """,
            (
                CONTROL_PLANE_SCHEMA_MIGRATION_ID,
                CONTROL_PLANE_SCHEMA_VERSION,
                _utc_now(),
                CONTROL_PLANE_SCHEMA_MIGRATION_DESCRIPTION,
            ),
        )
        connection.execute(
            """
            UPDATE control_plane_schema_metadata
            SET metadata_value = ?
            WHERE metadata_key = 'schema_version'
              AND CAST(metadata_value AS INTEGER) < ?
            """,
            (str(CONTROL_PLANE_SCHEMA_VERSION), CONTROL_PLANE_SCHEMA_VERSION),
        )

    def _read_schema_version(self, connection: sqlite3.Connection) -> int:
        row = connection.execute(
            """
            SELECT metadata_value
            FROM control_plane_schema_metadata
            WHERE metadata_key = 'schema_version'
            """
        ).fetchone()
        if row is None:
            return 0
        try:
            return int(row["metadata_value"])
        except (TypeError, ValueError):
            return 0

    def _read_metadata(self, connection: sqlite3.Connection, key: str) -> str | None:
        row = connection.execute(
            """
            SELECT metadata_value
            FROM control_plane_schema_metadata
            WHERE metadata_key = ?
            """,
            (key,),
        ).fetchone()
        if row is None:
            return None
        return str(row["metadata_value"])

    def _upsert_metadata(self, connection: sqlite3.Connection, key: str, value: str) -> None:
        connection.execute(
            """
            INSERT INTO control_plane_schema_metadata (metadata_key, metadata_value)
            VALUES (?, ?)
            ON CONFLICT(metadata_key)
            DO UPDATE SET metadata_value = excluded.metadata_value
            """,
            (key, value),
        )

    def _ensure_job_columns(self) -> None:
        existing_columns = self._table_columns("jobs")
        additions = {
            "claimed_by_worker_id": "TEXT",
            "lease_expires_at": "TEXT",
        }
        with self._connect() as connection:
            for column_name, column_type in additions.items():
                if column_name in existing_columns:
                    continue
                connection.execute(f"ALTER TABLE jobs ADD COLUMN {column_name} {column_type}")

    def _table_columns(self, table_name: str) -> set[str]:
        with self._connect() as connection:
            rows = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
        return {str(row["name"]) for row in rows}

    def _ensure_control_plane_alert_columns(self) -> None:
        existing_columns = self._table_columns("control_plane_alerts")
        additions = {
            "acknowledged_at": "TEXT",
            "acknowledged_by": "TEXT",
            "acknowledgement_note": "TEXT",
        }
        with self._connect() as connection:
            for column_name, column_type in additions.items():
                if column_name in existing_columns:
                    continue
                connection.execute(f"ALTER TABLE control_plane_alerts ADD COLUMN {column_name} {column_type}")

    def _ensure_control_plane_oncall_schedule_columns(self) -> None:
        existing_columns = self._table_columns("control_plane_oncall_schedules")
        additions = {
            "environment_name": "TEXT NOT NULL DEFAULT 'default'",
            "priority": "INTEGER NOT NULL DEFAULT 100",
            "rotation_name": "TEXT",
            "effective_start_date": "TEXT",
            "effective_end_date": "TEXT",
            "created_by_team": "TEXT",
            "created_by_role": "TEXT",
            "change_reason": "TEXT",
            "approved_by": "TEXT",
            "approved_by_team": "TEXT",
            "approved_by_role": "TEXT",
            "approved_at": "TEXT",
            "approval_note": "TEXT",
        }
        with self._connect() as connection:
            for column_name, column_type in additions.items():
                if column_name in existing_columns:
                    continue
                connection.execute(
                    f"ALTER TABLE control_plane_oncall_schedules ADD COLUMN {column_name} {column_type}"
                )

    def _ensure_control_plane_oncall_change_request_columns(self) -> None:
        existing_columns = self._table_columns("control_plane_oncall_change_requests")
        additions = {
            "environment_name": "TEXT NOT NULL DEFAULT 'default'",
            "assigned_to": "TEXT",
            "assigned_to_team": "TEXT",
            "assigned_at": "TEXT",
            "assigned_by": "TEXT",
            "assignment_note": "TEXT",
        }
        with self._connect() as connection:
            for column_name, column_type in additions.items():
                if column_name in existing_columns:
                    continue
                connection.execute(
                    f"ALTER TABLE control_plane_oncall_change_requests ADD COLUMN {column_name} {column_type}"
                )

    def _import_legacy_records(self) -> None:
        self._import_legacy_snapshots()
        self._import_legacy_audits()

    def _import_legacy_snapshots(self) -> None:
        if not self.settings.snapshots_dir.exists():
            return

        legacy_paths = sorted(self.settings.snapshots_dir.glob("*.meta.json"))
        if not legacy_paths:
            return

        records = [
            SnapshotRecord.from_dict(json.loads(path.read_text(encoding="utf-8")))
            for path in legacy_paths
        ]
        with self._connect() as connection:
            connection.executemany(
                """
                INSERT OR IGNORE INTO snapshots (
                    snapshot_id,
                    created_at,
                    repo_path,
                    node_count,
                    edge_count,
                    snapshot_path
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        record.snapshot_id,
                        record.created_at,
                        record.repo_path,
                        record.node_count,
                        record.edge_count,
                        record.snapshot_path,
                    )
                    for record in records
                ],
            )

    def _import_legacy_audits(self) -> None:
        if not self.settings.audits_dir.exists():
            return

        legacy_paths = sorted(self.settings.audits_dir.glob("*.json"))
        if not legacy_paths:
            return

        records = [
            AuditRecord.from_dict(json.loads(path.read_text(encoding="utf-8")))
            for path in legacy_paths
        ]
        with self._connect() as connection:
            connection.executemany(
                """
                INSERT OR IGNORE INTO audits (
                    audit_id,
                    created_at,
                    snapshot_id,
                    snapshot_path,
                    alert_count,
                    report_paths_json,
                    alerts_json,
                    events_json,
                    sessions_json,
                    explanation_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        record.audit_id,
                        record.created_at,
                        record.snapshot_id,
                        record.snapshot_path,
                        record.alert_count,
                        _json_dumps(record.report_paths),
                        _json_dumps(record.alerts),
                        _json_dumps(record.events),
                        _json_dumps(record.sessions),
                        _json_dumps(record.explanation),
                    )
                    for record in records
                ],
            )

    def upsert_snapshot(self, record: SnapshotRecord) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO snapshots (
                    snapshot_id,
                    created_at,
                    repo_path,
                    node_count,
                    edge_count,
                    snapshot_path
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(snapshot_id) DO UPDATE SET
                    created_at = excluded.created_at,
                    repo_path = excluded.repo_path,
                    node_count = excluded.node_count,
                    edge_count = excluded.edge_count,
                    snapshot_path = excluded.snapshot_path
                """,
                (
                    record.snapshot_id,
                    record.created_at,
                    record.repo_path,
                    record.node_count,
                    record.edge_count,
                    record.snapshot_path,
                ),
            )

    def fetch_snapshot(self, snapshot_id: str) -> SnapshotRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT snapshot_id, created_at, repo_path, node_count, edge_count, snapshot_path
                FROM snapshots
                WHERE snapshot_id = ?
                """,
                (snapshot_id,),
            ).fetchone()
        if row is None:
            return None
        return SnapshotRecord(
            snapshot_id=row["snapshot_id"],
            created_at=row["created_at"],
            repo_path=row["repo_path"],
            node_count=row["node_count"],
            edge_count=row["edge_count"],
            snapshot_path=row["snapshot_path"],
        )

    def list_snapshots(self) -> list[SnapshotRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT snapshot_id, created_at, repo_path, node_count, edge_count, snapshot_path
                FROM snapshots
                ORDER BY created_at DESC
                """
            ).fetchall()
        return [
            SnapshotRecord(
                snapshot_id=row["snapshot_id"],
                created_at=row["created_at"],
                repo_path=row["repo_path"],
                node_count=row["node_count"],
                edge_count=row["edge_count"],
                snapshot_path=row["snapshot_path"],
            )
            for row in rows
        ]

    def upsert_audit(self, record: AuditRecord) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO audits (
                    audit_id,
                    created_at,
                    snapshot_id,
                    snapshot_path,
                    alert_count,
                    report_paths_json,
                    alerts_json,
                    events_json,
                    sessions_json,
                    explanation_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(audit_id) DO UPDATE SET
                    created_at = excluded.created_at,
                    snapshot_id = excluded.snapshot_id,
                    snapshot_path = excluded.snapshot_path,
                    alert_count = excluded.alert_count,
                    report_paths_json = excluded.report_paths_json,
                    alerts_json = excluded.alerts_json,
                    events_json = excluded.events_json,
                    sessions_json = excluded.sessions_json,
                    explanation_json = excluded.explanation_json
                """,
                (
                    record.audit_id,
                    record.created_at,
                    record.snapshot_id,
                    record.snapshot_path,
                    record.alert_count,
                    _json_dumps(record.report_paths),
                    _json_dumps(record.alerts),
                    _json_dumps(record.events),
                    _json_dumps(record.sessions),
                    _json_dumps(record.explanation),
                ),
            )

    def fetch_audit(self, audit_id: str) -> AuditRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    audit_id,
                    created_at,
                    snapshot_id,
                    snapshot_path,
                    alert_count,
                    report_paths_json,
                    alerts_json,
                    events_json,
                    sessions_json,
                    explanation_json
                FROM audits
                WHERE audit_id = ?
                """,
                (audit_id,),
            ).fetchone()
        if row is None:
            return None
        return AuditRecord(
            audit_id=row["audit_id"],
            created_at=row["created_at"],
            snapshot_id=row["snapshot_id"],
            snapshot_path=row["snapshot_path"],
            alert_count=row["alert_count"],
            report_paths=list(json.loads(row["report_paths_json"])),
            alerts=list(json.loads(row["alerts_json"])),
            events=list(json.loads(row["events_json"])),
            sessions=list(json.loads(row["sessions_json"])),
            explanation=dict(json.loads(row["explanation_json"])),
        )

    def list_audits(self) -> list[AuditRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    audit_id,
                    created_at,
                    snapshot_id,
                    snapshot_path,
                    alert_count,
                    report_paths_json,
                    alerts_json,
                    events_json,
                    sessions_json,
                    explanation_json
                FROM audits
                ORDER BY created_at DESC
                """
            ).fetchall()
        return [
            AuditRecord(
                audit_id=row["audit_id"],
                created_at=row["created_at"],
                snapshot_id=row["snapshot_id"],
                snapshot_path=row["snapshot_path"],
                alert_count=row["alert_count"],
                report_paths=list(json.loads(row["report_paths_json"])),
                alerts=list(json.loads(row["alerts_json"])),
                events=list(json.loads(row["events_json"])),
                sessions=list(json.loads(row["sessions_json"])),
                explanation=dict(json.loads(row["explanation_json"])),
            )
            for row in rows
        ]

    def upsert_job(self, record: JobRecord) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO jobs (
                    job_id,
                    created_at,
                    job_type,
                    status,
                    request_payload_json,
                    result_payload_json,
                    error,
                    started_at,
                    completed_at,
                    claimed_by_worker_id,
                    lease_expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    created_at = excluded.created_at,
                    job_type = excluded.job_type,
                    status = excluded.status,
                    request_payload_json = excluded.request_payload_json,
                    result_payload_json = excluded.result_payload_json,
                    error = excluded.error,
                    started_at = excluded.started_at,
                    completed_at = excluded.completed_at,
                    claimed_by_worker_id = excluded.claimed_by_worker_id,
                    lease_expires_at = excluded.lease_expires_at
                """,
                (
                    record.job_id,
                    record.created_at,
                    record.job_type,
                    record.status,
                    _json_dumps(record.request_payload),
                    _json_dumps(record.result_payload),
                    record.error,
                    record.started_at,
                    record.completed_at,
                    record.claimed_by_worker_id,
                    record.lease_expires_at,
                ),
            )

    def fetch_job(self, job_id: str) -> JobRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    job_id,
                    created_at,
                    job_type,
                    status,
                    request_payload_json,
                    result_payload_json,
                    error,
                    started_at,
                    completed_at,
                    claimed_by_worker_id,
                    lease_expires_at
                FROM jobs
                WHERE job_id = ?
                """,
                (job_id,),
            ).fetchone()
        if row is None:
            return None
        return JobRecord(
            job_id=row["job_id"],
            created_at=row["created_at"],
            job_type=row["job_type"],
            status=row["status"],
            request_payload=dict(json.loads(row["request_payload_json"])),
            result_payload=dict(json.loads(row["result_payload_json"])),
            error=row["error"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            claimed_by_worker_id=row["claimed_by_worker_id"],
            lease_expires_at=row["lease_expires_at"],
        )

    def list_jobs(self) -> list[JobRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    job_id,
                    created_at,
                    job_type,
                    status,
                    request_payload_json,
                    result_payload_json,
                    error,
                    started_at,
                    completed_at,
                    claimed_by_worker_id,
                    lease_expires_at
                FROM jobs
                ORDER BY created_at DESC
                """
            ).fetchall()
        return [
            JobRecord(
                job_id=row["job_id"],
                created_at=row["created_at"],
                job_type=row["job_type"],
                status=row["status"],
                request_payload=dict(json.loads(row["request_payload_json"])),
                result_payload=dict(json.loads(row["result_payload_json"])),
                error=row["error"],
                started_at=row["started_at"],
                completed_at=row["completed_at"],
                claimed_by_worker_id=row["claimed_by_worker_id"],
                lease_expires_at=row["lease_expires_at"],
            )
            for row in rows
        ]

    def claim_next_queued_job(
        self,
        *,
        started_at: str,
        worker_id: str,
        lease_expires_at: str,
    ) -> JobRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    job_id,
                    created_at,
                    job_type,
                    status,
                    request_payload_json,
                    result_payload_json,
                    error,
                    started_at,
                    completed_at,
                    claimed_by_worker_id,
                    lease_expires_at
                FROM jobs
                WHERE status = 'queued'
                ORDER BY created_at ASC
                LIMIT 1
                """
            ).fetchone()
            if row is None:
                return None
            cursor = connection.execute(
                """
                UPDATE jobs
                SET status = 'running',
                    started_at = ?,
                    claimed_by_worker_id = ?,
                    lease_expires_at = ?,
                    completed_at = NULL,
                    error = NULL
                WHERE job_id = ?
                  AND status = 'queued'
                """,
                (started_at, worker_id, lease_expires_at, row["job_id"]),
            )
            if cursor.rowcount == 0:
                return None
        return self.fetch_job(row["job_id"])

    def requeue_jobs_with_status(self, statuses: tuple[str, ...]) -> int:
        if not statuses:
            return 0
        placeholders = ", ".join("?" for _ in statuses)
        with self._connect() as connection:
            cursor = connection.execute(
                f"""
                UPDATE jobs
                SET status = 'queued',
                    started_at = NULL,
                    completed_at = NULL,
                    error = NULL,
                    claimed_by_worker_id = NULL,
                    lease_expires_at = NULL
                WHERE status IN ({placeholders})
                """,
                statuses,
            )
        return cursor.rowcount

    def requeue_expired_leases(self, reference_timestamp: str) -> list[JobRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    job_id,
                    created_at,
                    job_type,
                    status,
                    request_payload_json,
                    result_payload_json,
                    error,
                    started_at,
                    completed_at,
                    claimed_by_worker_id,
                    lease_expires_at
                FROM jobs
                WHERE status = 'running'
                  AND lease_expires_at IS NOT NULL
                  AND lease_expires_at < ?
                ORDER BY lease_expires_at ASC
                """,
                (reference_timestamp,),
            ).fetchall()
            if not rows:
                return []
            cursor = connection.execute(
                """
                UPDATE jobs
                SET status = 'queued',
                    started_at = NULL,
                    error = NULL,
                    claimed_by_worker_id = NULL,
                    lease_expires_at = NULL
                WHERE status = 'running'
                  AND lease_expires_at IS NOT NULL
                  AND lease_expires_at < ?
                """,
                (reference_timestamp,),
            )
        if cursor.rowcount == 0:
            return []
        return [
            JobRecord(
                job_id=row["job_id"],
                created_at=row["created_at"],
                job_type=row["job_type"],
                status=row["status"],
                request_payload=dict(json.loads(row["request_payload_json"])),
                result_payload=dict(json.loads(row["result_payload_json"])),
                error=row["error"],
                started_at=row["started_at"],
                completed_at=row["completed_at"],
                claimed_by_worker_id=row["claimed_by_worker_id"],
                lease_expires_at=row["lease_expires_at"],
            )
            for row in rows
        ]

    def renew_job_lease(self, *, job_id: str, worker_id: str, lease_expires_at: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE jobs
                SET lease_expires_at = ?
                WHERE job_id = ?
                  AND status = 'running'
                  AND claimed_by_worker_id = ?
                """,
                (lease_expires_at, job_id, worker_id),
            )
        return cursor.rowcount > 0

    def count_jobs_with_status(self, status: str) -> int:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM jobs
                WHERE status = ?
                """,
                (status,),
            ).fetchone()
        assert row is not None
        return int(row["count"])

    def upsert_worker(self, record: WorkerRecord) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO workers (
                    worker_id,
                    mode,
                    status,
                    started_at,
                    last_heartbeat_at,
                    host_name,
                    process_id,
                    current_job_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(worker_id) DO UPDATE SET
                    mode = excluded.mode,
                    status = excluded.status,
                    started_at = excluded.started_at,
                    last_heartbeat_at = excluded.last_heartbeat_at,
                    host_name = excluded.host_name,
                    process_id = excluded.process_id,
                    current_job_id = excluded.current_job_id
                """,
                (
                    record.worker_id,
                    record.mode,
                    record.status,
                    record.started_at,
                    record.last_heartbeat_at,
                    record.host_name,
                    record.process_id,
                    record.current_job_id,
                ),
            )

    def fetch_worker(self, worker_id: str) -> WorkerRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    worker_id,
                    mode,
                    status,
                    started_at,
                    last_heartbeat_at,
                    host_name,
                    process_id,
                    current_job_id
                FROM workers
                WHERE worker_id = ?
                """,
                (worker_id,),
            ).fetchone()
        if row is None:
            return None
        return WorkerRecord(
            worker_id=row["worker_id"],
            mode=row["mode"],
            status=row["status"],
            started_at=row["started_at"],
            last_heartbeat_at=row["last_heartbeat_at"],
            host_name=row["host_name"],
            process_id=row["process_id"],
            current_job_id=row["current_job_id"],
        )

    def list_workers(self) -> list[WorkerRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    worker_id,
                    mode,
                    status,
                    started_at,
                    last_heartbeat_at,
                    host_name,
                    process_id,
                    current_job_id
                FROM workers
                ORDER BY last_heartbeat_at DESC
                """
            ).fetchall()
        return [
            WorkerRecord(
                worker_id=row["worker_id"],
                mode=row["mode"],
                status=row["status"],
                started_at=row["started_at"],
                last_heartbeat_at=row["last_heartbeat_at"],
                host_name=row["host_name"],
                process_id=row["process_id"],
                current_job_id=row["current_job_id"],
            )
            for row in rows
        ]

    def count_workers_seen_since(self, threshold_timestamp: str) -> int:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM workers
                WHERE status = 'running'
                  AND last_heartbeat_at >= ?
                """,
                (threshold_timestamp,),
            ).fetchone()
        assert row is not None
        return int(row["count"])

    def append_worker_heartbeat(self, record: WorkerHeartbeatRecord) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO worker_heartbeats (
                    heartbeat_id,
                    worker_id,
                    recorded_at,
                    status,
                    current_job_id
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    record.heartbeat_id,
                    record.worker_id,
                    record.recorded_at,
                    record.status,
                    record.current_job_id,
                ),
            )

    def list_worker_heartbeats(self, worker_id: str | None = None) -> list[WorkerHeartbeatRecord]:
        with self._connect() as connection:
            if worker_id is None:
                rows = connection.execute(
                    """
                    SELECT
                        heartbeat_id,
                        worker_id,
                        recorded_at,
                        status,
                        current_job_id
                    FROM worker_heartbeats
                    ORDER BY recorded_at DESC
                    """
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT
                        heartbeat_id,
                        worker_id,
                        recorded_at,
                        status,
                        current_job_id
                    FROM worker_heartbeats
                    WHERE worker_id = ?
                    ORDER BY recorded_at DESC
                    """,
                    (worker_id,),
                ).fetchall()
        return [
            WorkerHeartbeatRecord(
                heartbeat_id=row["heartbeat_id"],
                worker_id=row["worker_id"],
                recorded_at=row["recorded_at"],
                status=row["status"],
                current_job_id=row["current_job_id"],
            )
            for row in rows
        ]

    def append_job_lease_event(self, record: JobLeaseEventRecord) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO job_lease_events (
                    event_id,
                    job_id,
                    worker_id,
                    event_type,
                    recorded_at,
                    details_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    record.event_id,
                    record.job_id,
                    record.worker_id,
                    record.event_type,
                    record.recorded_at,
                    _json_dumps(record.details),
                ),
            )

    def list_job_lease_events(self, job_id: str | None = None) -> list[JobLeaseEventRecord]:
        with self._connect() as connection:
            if job_id is None:
                rows = connection.execute(
                    """
                    SELECT
                        event_id,
                        job_id,
                        worker_id,
                        event_type,
                        recorded_at,
                        details_json
                    FROM job_lease_events
                    ORDER BY recorded_at DESC
                    """
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT
                        event_id,
                        job_id,
                        worker_id,
                        event_type,
                        recorded_at,
                        details_json
                    FROM job_lease_events
                    WHERE job_id = ?
                    ORDER BY recorded_at DESC
                    """,
                    (job_id,),
                ).fetchall()
        return [
            JobLeaseEventRecord(
                event_id=row["event_id"],
                job_id=row["job_id"],
                worker_id=row["worker_id"],
                event_type=row["event_type"],
                recorded_at=row["recorded_at"],
                details=dict(json.loads(row["details_json"])),
            )
            for row in rows
        ]

    def prune_worker_heartbeats_before(self, cutoff_timestamp: str) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                DELETE FROM worker_heartbeats
                WHERE recorded_at < ?
                """,
                (cutoff_timestamp,),
            )
        return cursor.rowcount

    def prune_job_lease_events_before(self, cutoff_timestamp: str) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                DELETE FROM job_lease_events
                WHERE recorded_at < ?
                """,
                (cutoff_timestamp,),
            )
        return cursor.rowcount

    def compact_worker_heartbeats_before(self, cutoff_timestamp: str) -> int:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    substr(recorded_at, 1, 10) AS day_bucket,
                    worker_id,
                    status,
                    current_job_id,
                    COUNT(*) AS event_count
                FROM worker_heartbeats
                WHERE recorded_at < ?
                GROUP BY substr(recorded_at, 1, 10), worker_id, status, current_job_id
                """,
                (cutoff_timestamp,),
            ).fetchall()
            if not rows:
                return 0
            connection.executemany(
                """
                INSERT INTO worker_heartbeat_rollups (
                    day_bucket,
                    worker_id,
                    status,
                    current_job_id,
                    event_count
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(day_bucket, worker_id, status, current_job_id) DO UPDATE SET
                    event_count = worker_heartbeat_rollups.event_count + excluded.event_count
                """,
                [
                    (
                        row["day_bucket"],
                        row["worker_id"],
                        row["status"],
                        row["current_job_id"],
                        row["event_count"],
                    )
                    for row in rows
                ],
            )
            cursor = connection.execute(
                """
                DELETE FROM worker_heartbeats
                WHERE recorded_at < ?
                """,
                (cutoff_timestamp,),
            )
        return cursor.rowcount

    def compact_job_lease_events_before(self, cutoff_timestamp: str) -> int:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    substr(recorded_at, 1, 10) AS day_bucket,
                    job_id,
                    worker_id,
                    event_type,
                    COUNT(*) AS event_count
                FROM job_lease_events
                WHERE recorded_at < ?
                GROUP BY substr(recorded_at, 1, 10), job_id, worker_id, event_type
                """,
                (cutoff_timestamp,),
            ).fetchall()
            if not rows:
                return 0
            connection.executemany(
                """
                INSERT INTO job_lease_event_rollups (
                    day_bucket,
                    job_id,
                    worker_id,
                    event_type,
                    event_count
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(day_bucket, job_id, worker_id, event_type) DO UPDATE SET
                    event_count = job_lease_event_rollups.event_count + excluded.event_count
                """,
                [
                    (
                        row["day_bucket"],
                        row["job_id"],
                        row["worker_id"],
                        row["event_type"],
                        row["event_count"],
                    )
                    for row in rows
                ],
            )
            cursor = connection.execute(
                """
                DELETE FROM job_lease_events
                WHERE recorded_at < ?
                """,
                (cutoff_timestamp,),
            )
        return cursor.rowcount

    def list_worker_heartbeat_rollups(self, worker_id: str | None = None) -> list[WorkerHeartbeatRollupRecord]:
        with self._connect() as connection:
            if worker_id is None:
                rows = connection.execute(
                    """
                    SELECT day_bucket, worker_id, status, current_job_id, event_count
                    FROM worker_heartbeat_rollups
                    ORDER BY day_bucket DESC, worker_id ASC
                    """
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT day_bucket, worker_id, status, current_job_id, event_count
                    FROM worker_heartbeat_rollups
                    WHERE worker_id = ?
                    ORDER BY day_bucket DESC, worker_id ASC
                    """,
                    (worker_id,),
                ).fetchall()
        return [
            WorkerHeartbeatRollupRecord(
                day_bucket=row["day_bucket"],
                worker_id=row["worker_id"],
                status=row["status"],
                current_job_id=row["current_job_id"],
                event_count=row["event_count"],
            )
            for row in rows
        ]

    def upsert_worker_heartbeat_rollup(self, record: WorkerHeartbeatRollupRecord) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO worker_heartbeat_rollups (
                    day_bucket,
                    worker_id,
                    status,
                    current_job_id,
                    event_count
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(day_bucket, worker_id, status, current_job_id)
                DO UPDATE SET event_count = excluded.event_count
                """,
                (
                    record.day_bucket,
                    record.worker_id,
                    record.status,
                    record.current_job_id,
                    record.event_count,
                ),
            )

    def list_job_lease_event_rollups(self, job_id: str | None = None) -> list[JobLeaseEventRollupRecord]:
        with self._connect() as connection:
            if job_id is None:
                rows = connection.execute(
                    """
                    SELECT day_bucket, job_id, worker_id, event_type, event_count
                    FROM job_lease_event_rollups
                    ORDER BY day_bucket DESC, job_id ASC
                    """
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT day_bucket, job_id, worker_id, event_type, event_count
                    FROM job_lease_event_rollups
                    WHERE job_id = ?
                    ORDER BY day_bucket DESC, job_id ASC
                    """,
                    (job_id,),
                ).fetchall()
        return [
            JobLeaseEventRollupRecord(
                day_bucket=row["day_bucket"],
                job_id=row["job_id"],
                worker_id=row["worker_id"],
                event_type=row["event_type"],
                event_count=row["event_count"],
            )
            for row in rows
        ]

    def upsert_job_lease_event_rollup(self, record: JobLeaseEventRollupRecord) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO job_lease_event_rollups (
                    day_bucket,
                    job_id,
                    worker_id,
                    event_type,
                    event_count
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(day_bucket, job_id, worker_id, event_type)
                DO UPDATE SET event_count = excluded.event_count
                """,
                (
                    record.day_bucket,
                    record.job_id,
                    record.worker_id,
                    record.event_type,
                    record.event_count,
                ),
            )

    def append_control_plane_maintenance_event(self, record: ControlPlaneMaintenanceEventRecord) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO control_plane_maintenance_events (
                    event_id,
                    recorded_at,
                    event_type,
                    changed_by,
                    reason,
                    details_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    record.event_id,
                    record.recorded_at,
                    record.event_type,
                    record.changed_by,
                    record.reason,
                    _json_dumps(record.details),
                ),
            )

    def list_control_plane_maintenance_events(
        self,
        *,
        limit: int | None = None,
    ) -> list[ControlPlaneMaintenanceEventRecord]:
        query = """
            SELECT
                event_id,
                recorded_at,
                event_type,
                changed_by,
                reason,
                details_json
            FROM control_plane_maintenance_events
            ORDER BY recorded_at DESC
        """
        parameters: tuple[object, ...] = ()
        if limit is not None:
            query += "\nLIMIT ?"
            parameters = (limit,)
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [
            ControlPlaneMaintenanceEventRecord(
                event_id=row["event_id"],
                recorded_at=row["recorded_at"],
                event_type=row["event_type"],
                changed_by=row["changed_by"],
                reason=row["reason"],
                details=dict(json.loads(row["details_json"])),
            )
            for row in rows
        ]

    def insert_control_plane_alert(self, record: ControlPlaneAlertRecord) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO control_plane_alerts (
                    alert_id,
                    created_at,
                    alert_key,
                    status,
                    severity,
                    summary,
                    finding_codes_json,
                    delivery_state,
                    payload_json,
                    error,
                    acknowledged_at,
                    acknowledged_by,
                    acknowledgement_note
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.alert_id,
                    record.created_at,
                    record.alert_key,
                    record.status,
                    record.severity,
                    record.summary,
                    _json_dumps(record.finding_codes),
                    record.delivery_state,
                    _json_dumps(record.payload),
                    record.error,
                    record.acknowledged_at,
                    record.acknowledged_by,
                    record.acknowledgement_note,
                ),
            )

    def list_control_plane_alerts(self, limit: int | None = None) -> list[ControlPlaneAlertRecord]:
        query = """
            SELECT
                alert_id,
                created_at,
                alert_key,
                status,
                severity,
                summary,
                finding_codes_json,
                delivery_state,
                payload_json,
                error,
                acknowledged_at,
                acknowledged_by,
                acknowledgement_note
            FROM control_plane_alerts
            ORDER BY created_at DESC
        """
        parameters: tuple[object, ...] = ()
        if limit is not None:
            query += "\nLIMIT ?"
            parameters = (limit,)
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [
            ControlPlaneAlertRecord(
                alert_id=row["alert_id"],
                created_at=row["created_at"],
                alert_key=row["alert_key"],
                status=row["status"],
                severity=row["severity"],
                summary=row["summary"],
                finding_codes=list(json.loads(row["finding_codes_json"])),
                delivery_state=row["delivery_state"],
                payload=dict(json.loads(row["payload_json"])),
                error=row["error"],
                acknowledged_at=row["acknowledged_at"],
                acknowledged_by=row["acknowledged_by"],
                acknowledgement_note=row["acknowledgement_note"],
            )
            for row in rows
        ]

    def fetch_control_plane_alert(self, alert_id: str) -> ControlPlaneAlertRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    alert_id,
                    created_at,
                    alert_key,
                    status,
                    severity,
                    summary,
                    finding_codes_json,
                    delivery_state,
                    payload_json,
                    error,
                    acknowledged_at,
                    acknowledged_by,
                    acknowledgement_note
                FROM control_plane_alerts
                WHERE alert_id = ?
                """,
                (alert_id,),
            ).fetchone()
        if row is None:
            return None
        return ControlPlaneAlertRecord(
            alert_id=row["alert_id"],
            created_at=row["created_at"],
            alert_key=row["alert_key"],
            status=row["status"],
            severity=row["severity"],
            summary=row["summary"],
            finding_codes=list(json.loads(row["finding_codes_json"])),
            delivery_state=row["delivery_state"],
            payload=dict(json.loads(row["payload_json"])),
            error=row["error"],
            acknowledged_at=row["acknowledged_at"],
            acknowledged_by=row["acknowledged_by"],
            acknowledgement_note=row["acknowledgement_note"],
        )

    def fetch_latest_control_plane_alert(self) -> ControlPlaneAlertRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    alert_id,
                    created_at,
                    alert_key,
                    status,
                    severity,
                    summary,
                    finding_codes_json,
                    delivery_state,
                    payload_json,
                    error,
                    acknowledged_at,
                    acknowledged_by,
                    acknowledgement_note
                FROM control_plane_alerts
                ORDER BY created_at DESC
                LIMIT 1
                """
            ).fetchone()
        if row is None:
            return None
        return ControlPlaneAlertRecord(
            alert_id=row["alert_id"],
            created_at=row["created_at"],
            alert_key=row["alert_key"],
            status=row["status"],
            severity=row["severity"],
            summary=row["summary"],
            finding_codes=list(json.loads(row["finding_codes_json"])),
            delivery_state=row["delivery_state"],
            payload=dict(json.loads(row["payload_json"])),
            error=row["error"],
            acknowledged_at=row["acknowledged_at"],
            acknowledged_by=row["acknowledged_by"],
            acknowledgement_note=row["acknowledgement_note"],
        )

    def fetch_latest_control_plane_alert_by_key(self, alert_key: str) -> ControlPlaneAlertRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    alert_id,
                    created_at,
                    alert_key,
                    status,
                    severity,
                    summary,
                    finding_codes_json,
                    delivery_state,
                    payload_json,
                    error,
                    acknowledged_at,
                    acknowledged_by,
                    acknowledgement_note
                FROM control_plane_alerts
                WHERE alert_key = ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (alert_key,),
            ).fetchone()
        if row is None:
            return None
        return ControlPlaneAlertRecord(
            alert_id=row["alert_id"],
            created_at=row["created_at"],
            alert_key=row["alert_key"],
            status=row["status"],
            severity=row["severity"],
            summary=row["summary"],
            finding_codes=list(json.loads(row["finding_codes_json"])),
            delivery_state=row["delivery_state"],
            payload=dict(json.loads(row["payload_json"])),
            error=row["error"],
            acknowledged_at=row["acknowledged_at"],
            acknowledged_by=row["acknowledged_by"],
            acknowledgement_note=row["acknowledgement_note"],
        )

    def acknowledge_control_plane_alert(
        self,
        *,
        alert_id: str,
        acknowledged_at: str,
        acknowledged_by: str,
        acknowledgement_note: str | None,
    ) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE control_plane_alerts
                SET acknowledged_at = ?,
                    acknowledged_by = ?,
                    acknowledgement_note = ?
                WHERE alert_id = ?
                """,
                (acknowledged_at, acknowledged_by, acknowledgement_note, alert_id),
            )
        return cursor.rowcount > 0

    def insert_control_plane_alert_silence(self, record: ControlPlaneAlertSilenceRecord) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO control_plane_alert_silences (
                    silence_id,
                    created_at,
                    created_by,
                    reason,
                    match_alert_key,
                    match_finding_code,
                    starts_at,
                    expires_at,
                    cancelled_at,
                    cancelled_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.silence_id,
                    record.created_at,
                    record.created_by,
                    record.reason,
                    record.match_alert_key,
                    record.match_finding_code,
                    record.starts_at,
                    record.expires_at,
                    record.cancelled_at,
                    record.cancelled_by,
                ),
            )

    def list_control_plane_alert_silences(self) -> list[ControlPlaneAlertSilenceRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    silence_id,
                    created_at,
                    created_by,
                    reason,
                    match_alert_key,
                    match_finding_code,
                    starts_at,
                    expires_at,
                    cancelled_at,
                    cancelled_by
                FROM control_plane_alert_silences
                ORDER BY created_at DESC
                """
            ).fetchall()
        return [
            ControlPlaneAlertSilenceRecord(
                silence_id=row["silence_id"],
                created_at=row["created_at"],
                created_by=row["created_by"],
                reason=row["reason"],
                match_alert_key=row["match_alert_key"],
                match_finding_code=row["match_finding_code"],
                starts_at=row["starts_at"],
                expires_at=row["expires_at"],
                cancelled_at=row["cancelled_at"],
                cancelled_by=row["cancelled_by"],
            )
            for row in rows
        ]

    def fetch_control_plane_alert_silence(self, silence_id: str) -> ControlPlaneAlertSilenceRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    silence_id,
                    created_at,
                    created_by,
                    reason,
                    match_alert_key,
                    match_finding_code,
                    starts_at,
                    expires_at,
                    cancelled_at,
                    cancelled_by
                FROM control_plane_alert_silences
                WHERE silence_id = ?
                """,
                (silence_id,),
            ).fetchone()
        if row is None:
            return None
        return ControlPlaneAlertSilenceRecord(
            silence_id=row["silence_id"],
            created_at=row["created_at"],
            created_by=row["created_by"],
            reason=row["reason"],
            match_alert_key=row["match_alert_key"],
            match_finding_code=row["match_finding_code"],
            starts_at=row["starts_at"],
            expires_at=row["expires_at"],
            cancelled_at=row["cancelled_at"],
            cancelled_by=row["cancelled_by"],
        )

    def cancel_control_plane_alert_silence(
        self,
        *,
        silence_id: str,
        cancelled_at: str,
        cancelled_by: str,
    ) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE control_plane_alert_silences
                SET cancelled_at = ?,
                    cancelled_by = ?
                WHERE silence_id = ?
                  AND cancelled_at IS NULL
                """,
                (cancelled_at, cancelled_by, silence_id),
            )
        return cursor.rowcount > 0

    def insert_control_plane_oncall_schedule(self, record: ControlPlaneOnCallScheduleRecord) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO control_plane_oncall_schedules (
                    schedule_id,
                    created_at,
                    created_by,
                    environment_name,
                    created_by_team,
                    created_by_role,
                    change_reason,
                    approved_by,
                    approved_by_team,
                    approved_by_role,
                    approved_at,
                    approval_note,
                    team_name,
                    timezone_name,
                    weekdays_json,
                    start_time,
                    end_time,
                    priority,
                    rotation_name,
                    effective_start_date,
                    effective_end_date,
                    webhook_url,
                    escalation_webhook_url,
                    cancelled_at,
                    cancelled_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.schedule_id,
                    record.created_at,
                    record.created_by,
                    record.environment_name,
                    record.created_by_team,
                    record.created_by_role,
                    record.change_reason,
                    record.approved_by,
                    record.approved_by_team,
                    record.approved_by_role,
                    record.approved_at,
                    record.approval_note,
                    record.team_name,
                    record.timezone_name,
                    _json_dumps(record.weekdays),
                    record.start_time,
                    record.end_time,
                    record.priority,
                    record.rotation_name,
                    record.effective_start_date,
                    record.effective_end_date,
                    record.webhook_url,
                    record.escalation_webhook_url,
                    record.cancelled_at,
                    record.cancelled_by,
                ),
            )

    def list_control_plane_oncall_schedules(self) -> list[ControlPlaneOnCallScheduleRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    schedule_id,
                    created_at,
                    created_by,
                    environment_name,
                    created_by_team,
                    created_by_role,
                    change_reason,
                    approved_by,
                    approved_by_team,
                    approved_by_role,
                    approved_at,
                    approval_note,
                    team_name,
                    timezone_name,
                    weekdays_json,
                    start_time,
                    end_time,
                    priority,
                    rotation_name,
                    effective_start_date,
                    effective_end_date,
                    webhook_url,
                    escalation_webhook_url,
                    cancelled_at,
                    cancelled_by
                FROM control_plane_oncall_schedules
                ORDER BY priority DESC, created_at DESC
                """
            ).fetchall()
        return [
            ControlPlaneOnCallScheduleRecord(
                schedule_id=row["schedule_id"],
                created_at=row["created_at"],
                created_by=row["created_by"],
                environment_name=row["environment_name"],
                created_by_team=row["created_by_team"],
                created_by_role=row["created_by_role"],
                change_reason=row["change_reason"],
                approved_by=row["approved_by"],
                approved_by_team=row["approved_by_team"],
                approved_by_role=row["approved_by_role"],
                approved_at=row["approved_at"],
                approval_note=row["approval_note"],
                team_name=row["team_name"],
                timezone_name=row["timezone_name"],
                weekdays=list(json.loads(row["weekdays_json"])),
                start_time=row["start_time"],
                end_time=row["end_time"],
                priority=row["priority"],
                rotation_name=row["rotation_name"],
                effective_start_date=row["effective_start_date"],
                effective_end_date=row["effective_end_date"],
                webhook_url=row["webhook_url"],
                escalation_webhook_url=row["escalation_webhook_url"],
                cancelled_at=row["cancelled_at"],
                cancelled_by=row["cancelled_by"],
            )
            for row in rows
        ]

    def fetch_control_plane_oncall_schedule(self, schedule_id: str) -> ControlPlaneOnCallScheduleRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    schedule_id,
                    created_at,
                    created_by,
                    environment_name,
                    created_by_team,
                    created_by_role,
                    change_reason,
                    approved_by,
                    approved_by_team,
                    approved_by_role,
                    approved_at,
                    approval_note,
                    team_name,
                    timezone_name,
                    weekdays_json,
                    start_time,
                    end_time,
                    priority,
                    rotation_name,
                    effective_start_date,
                    effective_end_date,
                    webhook_url,
                    escalation_webhook_url,
                    cancelled_at,
                    cancelled_by
                FROM control_plane_oncall_schedules
                WHERE schedule_id = ?
                """,
                (schedule_id,),
            ).fetchone()
        if row is None:
            return None
        return ControlPlaneOnCallScheduleRecord(
            schedule_id=row["schedule_id"],
            created_at=row["created_at"],
            created_by=row["created_by"],
            environment_name=row["environment_name"],
            created_by_team=row["created_by_team"],
            created_by_role=row["created_by_role"],
            change_reason=row["change_reason"],
            approved_by=row["approved_by"],
            approved_by_team=row["approved_by_team"],
            approved_by_role=row["approved_by_role"],
            approved_at=row["approved_at"],
            approval_note=row["approval_note"],
            team_name=row["team_name"],
            timezone_name=row["timezone_name"],
            weekdays=list(json.loads(row["weekdays_json"])),
            start_time=row["start_time"],
            end_time=row["end_time"],
            priority=row["priority"],
            rotation_name=row["rotation_name"],
            effective_start_date=row["effective_start_date"],
            effective_end_date=row["effective_end_date"],
            webhook_url=row["webhook_url"],
            escalation_webhook_url=row["escalation_webhook_url"],
            cancelled_at=row["cancelled_at"],
            cancelled_by=row["cancelled_by"],
        )

    def cancel_control_plane_oncall_schedule(
        self,
        *,
        schedule_id: str,
        cancelled_at: str,
        cancelled_by: str,
    ) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE control_plane_oncall_schedules
                SET cancelled_at = ?,
                    cancelled_by = ?
                WHERE schedule_id = ?
                  AND cancelled_at IS NULL
                """,
                (cancelled_at, cancelled_by, schedule_id),
            )
        return cursor.rowcount > 0

    def insert_control_plane_oncall_change_request(
        self,
        record: ControlPlaneOnCallChangeRequestRecord,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO control_plane_oncall_change_requests (
                    request_id,
                    created_at,
                    created_by,
                    environment_name,
                    created_by_team,
                    created_by_role,
                    change_reason,
                    status,
                    review_required,
                    review_reasons_json,
                    team_name,
                    timezone_name,
                    weekdays_json,
                    start_time,
                    end_time,
                    priority,
                    rotation_name,
                    effective_start_date,
                    effective_end_date,
                    webhook_url,
                    escalation_webhook_url,
                    assigned_to,
                    assigned_to_team,
                    assigned_at,
                    assigned_by,
                    assignment_note,
                    decision_at,
                    decided_by,
                    decided_by_team,
                    decided_by_role,
                    decision_note,
                    applied_schedule_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.request_id,
                    record.created_at,
                    record.created_by,
                    record.environment_name,
                    record.created_by_team,
                    record.created_by_role,
                    record.change_reason,
                    record.status,
                    1 if record.review_required else 0,
                    _json_dumps(record.review_reasons),
                    record.team_name,
                    record.timezone_name,
                    _json_dumps(record.weekdays),
                    record.start_time,
                    record.end_time,
                    record.priority,
                    record.rotation_name,
                    record.effective_start_date,
                    record.effective_end_date,
                    record.webhook_url,
                    record.escalation_webhook_url,
                    record.assigned_to,
                    record.assigned_to_team,
                    record.assigned_at,
                    record.assigned_by,
                    record.assignment_note,
                    record.decision_at,
                    record.decided_by,
                    record.decided_by_team,
                    record.decided_by_role,
                    record.decision_note,
                    record.applied_schedule_id,
                ),
            )

    def list_control_plane_oncall_change_requests(
        self,
        *,
        status: str | None = None,
    ) -> list[ControlPlaneOnCallChangeRequestRecord]:
        query = """
            SELECT
                request_id,
                created_at,
                created_by,
                environment_name,
                created_by_team,
                created_by_role,
                change_reason,
                status,
                review_required,
                review_reasons_json,
                team_name,
                timezone_name,
                weekdays_json,
                start_time,
                end_time,
                priority,
                rotation_name,
                effective_start_date,
                effective_end_date,
                webhook_url,
                escalation_webhook_url,
                assigned_to,
                assigned_to_team,
                assigned_at,
                assigned_by,
                assignment_note,
                decision_at,
                decided_by,
                decided_by_team,
                decided_by_role,
                decision_note,
                applied_schedule_id
            FROM control_plane_oncall_change_requests
        """
        params: tuple[object, ...] = ()
        if status is not None:
            query += " WHERE status = ?"
            params = (status,)
        query += " ORDER BY created_at DESC"
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [self._row_to_control_plane_oncall_change_request(row) for row in rows]

    def fetch_control_plane_oncall_change_request(
        self,
        request_id: str,
    ) -> ControlPlaneOnCallChangeRequestRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    request_id,
                    created_at,
                    created_by,
                    environment_name,
                    created_by_team,
                    created_by_role,
                    change_reason,
                    status,
                    review_required,
                    review_reasons_json,
                    team_name,
                    timezone_name,
                    weekdays_json,
                    start_time,
                    end_time,
                    priority,
                    rotation_name,
                    effective_start_date,
                    effective_end_date,
                    webhook_url,
                    escalation_webhook_url,
                    assigned_to,
                    assigned_to_team,
                    assigned_at,
                    assigned_by,
                    assignment_note,
                    decision_at,
                    decided_by,
                    decided_by_team,
                    decided_by_role,
                    decision_note,
                    applied_schedule_id
                FROM control_plane_oncall_change_requests
                WHERE request_id = ?
                """,
                (request_id,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_control_plane_oncall_change_request(row)

    def update_control_plane_oncall_change_request_decision(
        self,
        *,
        request_id: str,
        status: str,
        decision_at: str,
        decided_by: str,
        decided_by_team: str | None,
        decided_by_role: str | None,
        decision_note: str | None,
        applied_schedule_id: str | None,
    ) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE control_plane_oncall_change_requests
                SET status = ?,
                    assigned_to = NULL,
                    assigned_to_team = NULL,
                    assigned_at = NULL,
                    assigned_by = NULL,
                    assignment_note = NULL,
                    decision_at = ?,
                    decided_by = ?,
                    decided_by_team = ?,
                    decided_by_role = ?,
                    decision_note = ?,
                    applied_schedule_id = ?
                WHERE request_id = ?
                """,
                (
                    status,
                    decision_at,
                    decided_by,
                    decided_by_team,
                    decided_by_role,
                    decision_note,
                    applied_schedule_id,
                    request_id,
                ),
            )
        return cursor.rowcount > 0

    def update_control_plane_oncall_change_request_assignment(
        self,
        *,
        request_id: str,
        assigned_to: str,
        assigned_to_team: str | None,
        assigned_at: str,
        assigned_by: str,
        assignment_note: str | None,
    ) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE control_plane_oncall_change_requests
                SET assigned_to = ?,
                    assigned_to_team = ?,
                    assigned_at = ?,
                    assigned_by = ?,
                    assignment_note = ?
                WHERE request_id = ?
                """,
                (
                    assigned_to,
                    assigned_to_team,
                    assigned_at,
                    assigned_by,
                    assignment_note,
                    request_id,
                ),
            )
        return cursor.rowcount > 0

    def _row_to_control_plane_oncall_change_request(
        self,
        row: sqlite3.Row,
    ) -> ControlPlaneOnCallChangeRequestRecord:
        return ControlPlaneOnCallChangeRequestRecord(
            request_id=row["request_id"],
            created_at=row["created_at"],
            created_by=row["created_by"],
            environment_name=row["environment_name"],
            created_by_team=row["created_by_team"],
            created_by_role=row["created_by_role"],
            change_reason=row["change_reason"],
            status=row["status"],
            review_required=bool(row["review_required"]),
            review_reasons=list(json.loads(row["review_reasons_json"])),
            team_name=row["team_name"],
            timezone_name=row["timezone_name"],
            weekdays=list(json.loads(row["weekdays_json"])),
            start_time=row["start_time"],
            end_time=row["end_time"],
            priority=row["priority"],
            rotation_name=row["rotation_name"],
            effective_start_date=row["effective_start_date"],
            effective_end_date=row["effective_end_date"],
            webhook_url=row["webhook_url"],
            escalation_webhook_url=row["escalation_webhook_url"],
            assigned_to=row["assigned_to"],
            assigned_to_team=row["assigned_to_team"],
            assigned_at=row["assigned_at"],
            assigned_by=row["assigned_by"],
            assignment_note=row["assignment_note"],
            decision_at=row["decision_at"],
            decided_by=row["decided_by"],
            decided_by_team=row["decided_by_team"],
            decided_by_role=row["decided_by_role"],
            decision_note=row["decision_note"],
            applied_schedule_id=row["applied_schedule_id"],
        )

    def clear_all_records(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                DELETE FROM control_plane_oncall_change_requests;
                DELETE FROM control_plane_oncall_schedules;
                DELETE FROM control_plane_alert_silences;
                DELETE FROM control_plane_alerts;
                DELETE FROM control_plane_maintenance_events;
                DELETE FROM job_lease_event_rollups;
                DELETE FROM job_lease_events;
                DELETE FROM worker_heartbeat_rollups;
                DELETE FROM worker_heartbeats;
                DELETE FROM workers;
                DELETE FROM jobs;
                DELETE FROM audits;
                DELETE FROM snapshots;
                """
            )


class SnapshotRepository:
    def __init__(self, settings: WorkspaceSettings, graph: IntentGraph | None = None) -> None:
        self.settings = settings
        self.graph = graph or IntentGraph()
        self.database = _ControlPlaneDatabase(settings)

    def save(self, snapshot: IntentGraphSnapshot, repo_path: str, snapshot_id: str | None = None) -> SnapshotRecord:
        self.settings.snapshots_dir.mkdir(parents=True, exist_ok=True)
        record_id = snapshot_id or uuid4().hex[:12]
        snapshot_path = self.settings.snapshots_dir / f"{record_id}.json"
        self.graph.save_snapshot(snapshot, snapshot_path)
        record = SnapshotRecord(
            snapshot_id=record_id,
            created_at=_utc_now(),
            repo_path=repo_path,
            node_count=snapshot.node_count,
            edge_count=snapshot.edge_count,
            snapshot_path=str(snapshot_path),
        )
        self.database.upsert_snapshot(record)
        return record

    def get(self, snapshot_id: str) -> SnapshotRecord:
        record = self.database.fetch_snapshot(snapshot_id)
        if record is not None:
            return record

        legacy_path = self.settings.snapshots_dir / f"{snapshot_id}.meta.json"
        if legacy_path.exists():
            record = SnapshotRecord.from_dict(json.loads(legacy_path.read_text(encoding="utf-8")))
            self.database.upsert_snapshot(record)
            return record
        raise FileNotFoundError(f"Snapshot '{snapshot_id}' was not found.")

    def list(self) -> list[SnapshotRecord]:
        return self.database.list_snapshots()


class AuditRepository:
    def __init__(self, settings: WorkspaceSettings) -> None:
        self.settings = settings
        self.database = _ControlPlaneDatabase(settings)

    def save(self, record: AuditRecord) -> AuditRecord:
        self.settings.audits_dir.mkdir(parents=True, exist_ok=True)
        self.database.upsert_audit(record)
        return record

    def create(
        self,
        snapshot_id: str | None,
        snapshot_path: str,
        alerts: list[dict],
        events: list[dict],
        sessions: list[dict],
        explanation: dict,
        report_paths: list[str],
        audit_id: str | None = None,
    ) -> AuditRecord:
        record = AuditRecord(
            audit_id=audit_id or uuid4().hex[:12],
            created_at=_utc_now(),
            snapshot_id=snapshot_id,
            snapshot_path=snapshot_path,
            alert_count=len(alerts),
            report_paths=report_paths,
            alerts=alerts,
            events=events,
            sessions=sessions,
            explanation=explanation,
        )
        return self.save(record)

    def get(self, audit_id: str) -> AuditRecord:
        record = self.database.fetch_audit(audit_id)
        if record is not None:
            return record

        legacy_path = self.settings.audits_dir / f"{audit_id}.json"
        if legacy_path.exists():
            record = AuditRecord.from_dict(json.loads(legacy_path.read_text(encoding="utf-8")))
            self.database.upsert_audit(record)
            return record
        raise FileNotFoundError(f"Audit '{audit_id}' was not found.")

    def list(self) -> list[AuditRecord]:
        return self.database.list_audits()


class JobRepository:
    def __init__(self, settings: WorkspaceSettings) -> None:
        self.settings = settings
        self.database = _ControlPlaneDatabase(settings)

    def save(self, record: JobRecord) -> JobRecord:
        self.database.upsert_job(record)
        return record

    def create(self, job_type: str, request_payload: dict, job_id: str | None = None) -> JobRecord:
        record = JobRecord(
            job_id=job_id or uuid4().hex[:12],
            created_at=_utc_now(),
            job_type=job_type,
            status="queued",
            request_payload=request_payload,
        )
        return self.save(record)

    def get(self, job_id: str) -> JobRecord:
        record = self.database.fetch_job(job_id)
        if record is None:
            raise FileNotFoundError(f"Job '{job_id}' was not found.")
        return record

    def list(self) -> list[JobRecord]:
        return self.database.list_jobs()

    def database_status(self) -> dict[str, object]:
        return self.database.status()

    def schema_status(self) -> dict[str, object]:
        return self.database.schema_status()

    def migrate_schema(self) -> dict[str, object]:
        return self.database.migrate_schema()

    def maintenance_mode_status(self) -> dict[str, object]:
        return self.database.maintenance_mode_status()

    def set_maintenance_mode(self, *, active: bool, changed_by: str, reason: str | None) -> dict[str, object]:
        return self.database.set_maintenance_mode(active=active, changed_by=changed_by, reason=reason)

    def claim_next_queued(self, *, started_at: str, worker_id: str, lease_expires_at: str) -> JobRecord | None:
        return self.database.claim_next_queued_job(
            started_at=started_at,
            worker_id=worker_id,
            lease_expires_at=lease_expires_at,
        )

    def requeue_incomplete(self) -> int:
        return self.database.requeue_jobs_with_status(("running",))

    def count_by_status(self, status: str) -> int:
        return self.database.count_jobs_with_status(status)

    def requeue_expired_leases(self, reference_timestamp: str) -> list[JobRecord]:
        return self.database.requeue_expired_leases(reference_timestamp)

    def renew_lease(self, *, job_id: str, worker_id: str, lease_expires_at: str) -> bool:
        return self.database.renew_job_lease(
            job_id=job_id,
            worker_id=worker_id,
            lease_expires_at=lease_expires_at,
        )

    def save_worker(self, record: WorkerRecord) -> WorkerRecord:
        self.database.upsert_worker(record)
        return record

    def get_worker(self, worker_id: str) -> WorkerRecord:
        record = self.database.fetch_worker(worker_id)
        if record is None:
            raise FileNotFoundError(f"Worker '{worker_id}' was not found.")
        return record

    def list_workers(self) -> list[WorkerRecord]:
        return self.database.list_workers()

    def count_workers_seen_since(self, threshold_timestamp: str) -> int:
        return self.database.count_workers_seen_since(threshold_timestamp)

    def append_worker_heartbeat(self, record: WorkerHeartbeatRecord) -> WorkerHeartbeatRecord:
        self.database.append_worker_heartbeat(record)
        return record

    def list_worker_heartbeats(self, worker_id: str | None = None) -> list[WorkerHeartbeatRecord]:
        return self.database.list_worker_heartbeats(worker_id)

    def append_job_lease_event(self, record: JobLeaseEventRecord) -> JobLeaseEventRecord:
        self.database.append_job_lease_event(record)
        return record

    def list_job_lease_events(self, job_id: str | None = None) -> list[JobLeaseEventRecord]:
        return self.database.list_job_lease_events(job_id)

    def prune_worker_heartbeats_before(self, cutoff_timestamp: str) -> int:
        return self.database.prune_worker_heartbeats_before(cutoff_timestamp)

    def prune_job_lease_events_before(self, cutoff_timestamp: str) -> int:
        return self.database.prune_job_lease_events_before(cutoff_timestamp)

    def compact_worker_heartbeats_before(self, cutoff_timestamp: str) -> int:
        return self.database.compact_worker_heartbeats_before(cutoff_timestamp)

    def compact_job_lease_events_before(self, cutoff_timestamp: str) -> int:
        return self.database.compact_job_lease_events_before(cutoff_timestamp)

    def list_worker_heartbeat_rollups(self, worker_id: str | None = None) -> list[WorkerHeartbeatRollupRecord]:
        return self.database.list_worker_heartbeat_rollups(worker_id)

    def list_job_lease_event_rollups(self, job_id: str | None = None) -> list[JobLeaseEventRollupRecord]:
        return self.database.list_job_lease_event_rollups(job_id)

    def save_worker_heartbeat_rollup(self, record: WorkerHeartbeatRollupRecord) -> WorkerHeartbeatRollupRecord:
        self.database.upsert_worker_heartbeat_rollup(record)
        return record

    def save_job_lease_event_rollup(self, record: JobLeaseEventRollupRecord) -> JobLeaseEventRollupRecord:
        self.database.upsert_job_lease_event_rollup(record)
        return record

    def append_control_plane_maintenance_event(
        self,
        record: ControlPlaneMaintenanceEventRecord,
    ) -> ControlPlaneMaintenanceEventRecord:
        self.database.append_control_plane_maintenance_event(record)
        return record

    def list_control_plane_maintenance_events(
        self,
        limit: int | None = None,
    ) -> list[ControlPlaneMaintenanceEventRecord]:
        return self.database.list_control_plane_maintenance_events(limit=limit)

    def append_control_plane_alert(self, record: ControlPlaneAlertRecord) -> ControlPlaneAlertRecord:
        self.database.insert_control_plane_alert(record)
        return record

    def list_control_plane_alerts(self, limit: int | None = None) -> list[ControlPlaneAlertRecord]:
        return self.database.list_control_plane_alerts(limit)

    def latest_control_plane_alert(self) -> ControlPlaneAlertRecord | None:
        return self.database.fetch_latest_control_plane_alert()

    def latest_control_plane_alert_by_key(self, alert_key: str) -> ControlPlaneAlertRecord | None:
        return self.database.fetch_latest_control_plane_alert_by_key(alert_key)

    def get_control_plane_alert(self, alert_id: str) -> ControlPlaneAlertRecord:
        record = self.database.fetch_control_plane_alert(alert_id)
        if record is None:
            raise FileNotFoundError(f"Control-plane alert '{alert_id}' was not found.")
        return record

    def acknowledge_control_plane_alert(
        self,
        *,
        alert_id: str,
        acknowledged_at: str,
        acknowledged_by: str,
        acknowledgement_note: str | None,
    ) -> ControlPlaneAlertRecord:
        updated = self.database.acknowledge_control_plane_alert(
            alert_id=alert_id,
            acknowledged_at=acknowledged_at,
            acknowledged_by=acknowledged_by,
            acknowledgement_note=acknowledgement_note,
        )
        if not updated:
            raise FileNotFoundError(f"Control-plane alert '{alert_id}' was not found.")
        return self.get_control_plane_alert(alert_id)

    def append_control_plane_alert_silence(
        self,
        record: ControlPlaneAlertSilenceRecord,
    ) -> ControlPlaneAlertSilenceRecord:
        self.database.insert_control_plane_alert_silence(record)
        return record

    def list_control_plane_alert_silences(self) -> list[ControlPlaneAlertSilenceRecord]:
        return self.database.list_control_plane_alert_silences()

    def get_control_plane_alert_silence(self, silence_id: str) -> ControlPlaneAlertSilenceRecord:
        record = self.database.fetch_control_plane_alert_silence(silence_id)
        if record is None:
            raise FileNotFoundError(f"Control-plane alert silence '{silence_id}' was not found.")
        return record

    def cancel_control_plane_alert_silence(
        self,
        *,
        silence_id: str,
        cancelled_at: str,
        cancelled_by: str,
    ) -> ControlPlaneAlertSilenceRecord:
        updated = self.database.cancel_control_plane_alert_silence(
            silence_id=silence_id,
            cancelled_at=cancelled_at,
            cancelled_by=cancelled_by,
        )
        if not updated:
            raise FileNotFoundError(f"Control-plane alert silence '{silence_id}' was not found.")
        return self.get_control_plane_alert_silence(silence_id)

    def append_control_plane_oncall_schedule(
        self,
        record: ControlPlaneOnCallScheduleRecord,
    ) -> ControlPlaneOnCallScheduleRecord:
        self.database.insert_control_plane_oncall_schedule(record)
        return record

    def list_control_plane_oncall_schedules(self) -> list[ControlPlaneOnCallScheduleRecord]:
        return self.database.list_control_plane_oncall_schedules()

    def get_control_plane_oncall_schedule(self, schedule_id: str) -> ControlPlaneOnCallScheduleRecord:
        record = self.database.fetch_control_plane_oncall_schedule(schedule_id)
        if record is None:
            raise FileNotFoundError(f"Control-plane on-call schedule '{schedule_id}' was not found.")
        return record

    def cancel_control_plane_oncall_schedule(
        self,
        *,
        schedule_id: str,
        cancelled_at: str,
        cancelled_by: str,
    ) -> ControlPlaneOnCallScheduleRecord:
        updated = self.database.cancel_control_plane_oncall_schedule(
            schedule_id=schedule_id,
            cancelled_at=cancelled_at,
            cancelled_by=cancelled_by,
        )
        if not updated:
            raise FileNotFoundError(f"Control-plane on-call schedule '{schedule_id}' was not found.")
        return self.get_control_plane_oncall_schedule(schedule_id)

    def append_control_plane_oncall_change_request(
        self,
        record: ControlPlaneOnCallChangeRequestRecord,
    ) -> ControlPlaneOnCallChangeRequestRecord:
        self.database.insert_control_plane_oncall_change_request(record)
        return record

    def list_control_plane_oncall_change_requests(
        self,
        *,
        status: str | None = None,
    ) -> list[ControlPlaneOnCallChangeRequestRecord]:
        return self.database.list_control_plane_oncall_change_requests(status=status)

    def reset_control_plane(self) -> None:
        self.database.clear_all_records()

    def get_control_plane_oncall_change_request(
        self,
        request_id: str,
    ) -> ControlPlaneOnCallChangeRequestRecord:
        record = self.database.fetch_control_plane_oncall_change_request(request_id)
        if record is None:
            raise FileNotFoundError(
                f"Control-plane on-call change request '{request_id}' was not found."
            )
        return record

    def decide_control_plane_oncall_change_request(
        self,
        *,
        request_id: str,
        status: str,
        decision_at: str,
        decided_by: str,
        decided_by_team: str | None,
        decided_by_role: str | None,
        decision_note: str | None,
        applied_schedule_id: str | None,
    ) -> ControlPlaneOnCallChangeRequestRecord:
        updated = self.database.update_control_plane_oncall_change_request_decision(
            request_id=request_id,
            status=status,
            decision_at=decision_at,
            decided_by=decided_by,
            decided_by_team=decided_by_team,
            decided_by_role=decided_by_role,
            decision_note=decision_note,
            applied_schedule_id=applied_schedule_id,
        )
        if not updated:
            raise FileNotFoundError(
                f"Control-plane on-call change request '{request_id}' was not found."
            )
        return self.get_control_plane_oncall_change_request(request_id)

    def assign_control_plane_oncall_change_request(
        self,
        *,
        request_id: str,
        assigned_to: str,
        assigned_to_team: str | None,
        assigned_at: str,
        assigned_by: str,
        assignment_note: str | None,
    ) -> ControlPlaneOnCallChangeRequestRecord:
        updated = self.database.update_control_plane_oncall_change_request_assignment(
            request_id=request_id,
            assigned_to=assigned_to,
            assigned_to_team=assigned_to_team,
            assigned_at=assigned_at,
            assigned_by=assigned_by,
            assignment_note=assignment_note,
        )
        if not updated:
            raise FileNotFoundError(
                f"Control-plane on-call change request '{request_id}' was not found."
            )
        return self.get_control_plane_oncall_change_request(request_id)
