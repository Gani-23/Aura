from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from lsa.core.intent_graph import IntentGraph
from lsa.core.models import IntentGraphSnapshot
from lsa.settings import WorkspaceSettings
from lsa.storage.models import AuditRecord, JobRecord, SnapshotRecord, WorkerRecord


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _json_dumps(value: object) -> str:
    return json.dumps(value, sort_keys=True)


class _ControlPlaneDatabase:
    def __init__(self, settings: WorkspaceSettings) -> None:
        self.settings = settings
        self.settings.data_dir.mkdir(parents=True, exist_ok=True)
        self.settings.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()
        self._import_legacy_records()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.settings.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
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
                """
            )
        self._ensure_job_columns()

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
