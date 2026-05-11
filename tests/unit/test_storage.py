import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from lsa.core.intent_graph import IntentGraph
from lsa.ingest.graph_builder import GraphBuilder
from lsa.settings import resolve_workspace_settings
from lsa.storage.database import inspect_database_config, inspect_database_runtime_support
from lsa.storage.files import (
    AuditRepository,
    JobRepository,
    SnapshotRepository,
    _PostgresControlPlaneDatabase,
    build_control_plane_runtime_bundle,
    build_job_repository,
)
from lsa.storage.models import (
    ControlPlaneAlertRecord,
    ControlPlaneAlertSilenceRecord,
    ControlPlaneOnCallChangeRequestRecord,
    ControlPlaneOnCallScheduleRecord,
    JobLeaseEventRecord,
    WorkerHeartbeatRecord,
    WorkerRecord,
)
from lsa.storage.models import AuditRecord


class _FakePostgresCursor:
    def __init__(self, *, row=None, rows=None, rowcount: int = 0) -> None:
        self._row = row
        self._rows = rows or []
        self.rowcount = rowcount

    def fetchone(self):
        return self._row

    def fetchall(self):
        return list(self._rows)


class _FakePostgresConnection:
    def __init__(
        self,
        *,
        jobs: dict[str, dict],
        workers: dict[str, dict],
        alerts: dict[str, dict] | None = None,
        silences: dict[str, dict] | None = None,
        schedules: dict[str, dict] | None = None,
        change_requests: dict[str, dict] | None = None,
    ) -> None:
        self.jobs = jobs
        self.workers = workers
        self.alerts = alerts or {}
        self.silences = silences or {}
        self.schedules = schedules or {}
        self.change_requests = change_requests or {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def execute(self, sql: str, params=()):
        normalized = " ".join(sql.split())
        if "SELECT job_id FROM jobs" in normalized and "FOR UPDATE SKIP LOCKED" in normalized:
            queued_jobs = sorted(
                (job for job in self.jobs.values() if job["status"] == "queued"),
                key=lambda job: job["created_at"],
            )
            if not queued_jobs:
                return _FakePostgresCursor(row=None)
            return _FakePostgresCursor(row=(queued_jobs[0]["job_id"],))

        if "UPDATE jobs SET status = 'running'" in normalized and "RETURNING" in normalized:
            started_at, worker_id, lease_expires_at, job_id = params
            job = self.jobs.get(job_id)
            if job is None or job["status"] != "queued":
                return _FakePostgresCursor(row=None, rowcount=0)
            job["status"] = "running"
            job["started_at"] = started_at
            job["claimed_by_worker_id"] = worker_id
            job["lease_expires_at"] = lease_expires_at
            job["completed_at"] = None
            job["error"] = None
            return _FakePostgresCursor(row=self._job_tuple(job), rowcount=1)

        if "UPDATE jobs SET status = 'queued'" in normalized and "WHERE status IN" in normalized:
            statuses = set(params)
            count = 0
            for job in self.jobs.values():
                if job["status"] not in statuses:
                    continue
                job["status"] = "queued"
                job["started_at"] = None
                job["completed_at"] = None
                job["error"] = None
                job["claimed_by_worker_id"] = None
                job["lease_expires_at"] = None
                count += 1
            return _FakePostgresCursor(rowcount=count)

        if "FROM jobs" in normalized and "lease_expires_at < %s" in normalized and "FOR UPDATE" in normalized:
            reference_timestamp = params[0]
            rows = [
                self._job_tuple(job)
                for job in sorted(self.jobs.values(), key=lambda item: item.get("lease_expires_at") or "")
                if job["status"] == "running"
                and job.get("lease_expires_at") is not None
                and job["lease_expires_at"] < reference_timestamp
            ]
            return _FakePostgresCursor(rows=rows)

        if "UPDATE jobs SET status = 'queued'" in normalized and "WHERE job_id IN" in normalized:
            count = 0
            for job_id in params:
                job = self.jobs.get(job_id)
                if job is None:
                    continue
                job["status"] = "queued"
                job["started_at"] = None
                job["error"] = None
                job["claimed_by_worker_id"] = None
                job["lease_expires_at"] = None
                count += 1
            return _FakePostgresCursor(rowcount=count)

        if "UPDATE jobs SET lease_expires_at = %s" in normalized:
            lease_expires_at, job_id, worker_id = params
            job = self.jobs.get(job_id)
            if job is None or job["status"] != "running" or job.get("claimed_by_worker_id") != worker_id:
                return _FakePostgresCursor(rowcount=0)
            job["lease_expires_at"] = lease_expires_at
            return _FakePostgresCursor(rowcount=1)

        if "SELECT COUNT(*) FROM jobs WHERE status = %s" in normalized:
            status = params[0]
            count = sum(1 for job in self.jobs.values() if job["status"] == status)
            return _FakePostgresCursor(row=(count,))

        if "SELECT COUNT(*) FROM workers" in normalized and "last_heartbeat_at >= %s" in normalized:
            threshold_timestamp = params[0]
            count = sum(
                1
                for worker in self.workers.values()
                if worker["status"] == "running" and worker["last_heartbeat_at"] >= threshold_timestamp
            )
            return _FakePostgresCursor(row=(count,))

        if "INSERT INTO control_plane_alerts" in normalized:
            self.alerts.setdefault(
                params[0],
                {
                    "alert_id": params[0],
                    "created_at": params[1],
                    "alert_key": params[2],
                    "status": params[3],
                    "severity": params[4],
                    "summary": params[5],
                    "finding_codes": json.loads(params[6]),
                    "delivery_state": params[7],
                    "payload": json.loads(params[8]),
                    "error": params[9],
                    "acknowledged_at": params[10],
                    "acknowledged_by": params[11],
                    "acknowledgement_note": params[12],
                },
            )
            return _FakePostgresCursor(rowcount=1)

        if "FROM control_plane_alerts" in normalized and "WHERE alert_key = %s" in normalized:
            alert_key = params[0]
            rows = [alert for alert in self.alerts.values() if alert["alert_key"] == alert_key]
            rows.sort(key=lambda item: item["created_at"], reverse=True)
            row = self._alert_tuple(rows[0]) if rows else None
            return _FakePostgresCursor(row=row)

        if "FROM control_plane_alerts" in normalized and "WHERE alert_id = %s" in normalized:
            alert = self.alerts.get(params[0])
            return _FakePostgresCursor(row=None if alert is None else self._alert_tuple(alert))

        if "FROM control_plane_alerts" in normalized and "ORDER BY created_at DESC LIMIT 1" in normalized:
            rows = sorted(self.alerts.values(), key=lambda item: item["created_at"], reverse=True)
            row = self._alert_tuple(rows[0]) if rows else None
            return _FakePostgresCursor(row=row)

        if "FROM control_plane_alerts" in normalized and "ORDER BY created_at DESC" in normalized:
            rows = sorted(self.alerts.values(), key=lambda item: item["created_at"], reverse=True)
            if params:
                rows = rows[: int(params[0])]
            return _FakePostgresCursor(rows=[self._alert_tuple(row) for row in rows])

        if "UPDATE control_plane_alerts" in normalized and "acknowledged_at = %s" in normalized:
            acknowledged_at, acknowledged_by, acknowledgement_note, alert_id = params
            alert = self.alerts.get(alert_id)
            if alert is None:
                return _FakePostgresCursor(rowcount=0)
            alert["acknowledged_at"] = acknowledged_at
            alert["acknowledged_by"] = acknowledged_by
            alert["acknowledgement_note"] = acknowledgement_note
            return _FakePostgresCursor(rowcount=1)

        if "INSERT INTO control_plane_alert_silences" in normalized:
            self.silences.setdefault(
                params[0],
                {
                    "silence_id": params[0],
                    "created_at": params[1],
                    "created_by": params[2],
                    "reason": params[3],
                    "match_alert_key": params[4],
                    "match_finding_code": params[5],
                    "starts_at": params[6],
                    "expires_at": params[7],
                    "cancelled_at": params[8],
                    "cancelled_by": params[9],
                },
            )
            return _FakePostgresCursor(rowcount=1)

        if "FROM control_plane_alert_silences" in normalized and "WHERE silence_id = %s" in normalized:
            silence = self.silences.get(params[0])
            return _FakePostgresCursor(row=None if silence is None else self._silence_tuple(silence))

        if "FROM control_plane_alert_silences" in normalized and "ORDER BY created_at DESC" in normalized:
            rows = sorted(self.silences.values(), key=lambda item: item["created_at"], reverse=True)
            return _FakePostgresCursor(rows=[self._silence_tuple(row) for row in rows])

        if "UPDATE control_plane_alert_silences" in normalized and "cancelled_at = %s" in normalized:
            cancelled_at, cancelled_by, silence_id = params
            silence = self.silences.get(silence_id)
            if silence is None or silence.get("cancelled_at") is not None:
                return _FakePostgresCursor(rowcount=0)
            silence["cancelled_at"] = cancelled_at
            silence["cancelled_by"] = cancelled_by
            return _FakePostgresCursor(rowcount=1)

        if "INSERT INTO control_plane_oncall_schedules" in normalized:
            self.schedules.setdefault(
                params[0],
                {
                    "schedule_id": params[0],
                    "created_at": params[1],
                    "created_by": params[2],
                    "environment_name": params[3],
                    "created_by_team": params[4],
                    "created_by_role": params[5],
                    "change_reason": params[6],
                    "approved_by": params[7],
                    "approved_by_team": params[8],
                    "approved_by_role": params[9],
                    "approved_at": params[10],
                    "approval_note": params[11],
                    "team_name": params[12],
                    "timezone_name": params[13],
                    "weekdays": json.loads(params[14]),
                    "start_time": params[15],
                    "end_time": params[16],
                    "priority": params[17],
                    "rotation_name": params[18],
                    "effective_start_date": params[19],
                    "effective_end_date": params[20],
                    "webhook_url": params[21],
                    "escalation_webhook_url": params[22],
                    "cancelled_at": params[23],
                    "cancelled_by": params[24],
                },
            )
            return _FakePostgresCursor(rowcount=1)

        if "FROM control_plane_oncall_schedules" in normalized and "WHERE schedule_id = %s" in normalized:
            schedule = self.schedules.get(params[0])
            return _FakePostgresCursor(row=None if schedule is None else self._schedule_tuple(schedule))

        if "FROM control_plane_oncall_schedules" in normalized and "ORDER BY priority DESC, created_at DESC" in normalized:
            rows = sorted(self.schedules.values(), key=lambda item: (item["priority"], item["created_at"]), reverse=True)
            return _FakePostgresCursor(rows=[self._schedule_tuple(row) for row in rows])

        if "UPDATE control_plane_oncall_schedules" in normalized and "cancelled_at = %s" in normalized:
            cancelled_at, cancelled_by, schedule_id = params
            schedule = self.schedules.get(schedule_id)
            if schedule is None or schedule.get("cancelled_at") is not None:
                return _FakePostgresCursor(rowcount=0)
            schedule["cancelled_at"] = cancelled_at
            schedule["cancelled_by"] = cancelled_by
            return _FakePostgresCursor(rowcount=1)

        if "INSERT INTO control_plane_oncall_change_requests" in normalized:
            self.change_requests.setdefault(
                params[0],
                {
                    "request_id": params[0],
                    "created_at": params[1],
                    "created_by": params[2],
                    "environment_name": params[3],
                    "created_by_team": params[4],
                    "created_by_role": params[5],
                    "change_reason": params[6],
                    "status": params[7],
                    "review_required": params[8],
                    "review_reasons": json.loads(params[9]),
                    "team_name": params[10],
                    "timezone_name": params[11],
                    "weekdays": json.loads(params[12]),
                    "start_time": params[13],
                    "end_time": params[14],
                    "priority": params[15],
                    "rotation_name": params[16],
                    "effective_start_date": params[17],
                    "effective_end_date": params[18],
                    "webhook_url": params[19],
                    "escalation_webhook_url": params[20],
                    "assigned_to": params[21],
                    "assigned_to_team": params[22],
                    "assigned_at": params[23],
                    "assigned_by": params[24],
                    "assignment_note": params[25],
                    "decision_at": params[26],
                    "decided_by": params[27],
                    "decided_by_team": params[28],
                    "decided_by_role": params[29],
                    "decision_note": params[30],
                    "applied_schedule_id": params[31],
                },
            )
            return _FakePostgresCursor(rowcount=1)

        if "FROM control_plane_oncall_change_requests" in normalized and "WHERE request_id = %s" in normalized:
            request = self.change_requests.get(params[0])
            return _FakePostgresCursor(row=None if request is None else self._change_request_tuple(request))

        if "FROM control_plane_oncall_change_requests" in normalized and "ORDER BY created_at DESC" in normalized:
            rows = list(self.change_requests.values())
            if "WHERE status = %s" in normalized:
                rows = [row for row in rows if row["status"] == params[0]]
            rows.sort(key=lambda item: item["created_at"], reverse=True)
            return _FakePostgresCursor(rows=[self._change_request_tuple(row) for row in rows])

        if "UPDATE control_plane_oncall_change_requests" in normalized and "SET status = %s" in normalized:
            (
                status,
                decision_at,
                decided_by,
                decided_by_team,
                decided_by_role,
                decision_note,
                applied_schedule_id,
                request_id,
            ) = params
            request = self.change_requests.get(request_id)
            if request is None:
                return _FakePostgresCursor(rowcount=0)
            request["status"] = status
            request["assigned_to"] = None
            request["assigned_to_team"] = None
            request["assigned_at"] = None
            request["assigned_by"] = None
            request["assignment_note"] = None
            request["decision_at"] = decision_at
            request["decided_by"] = decided_by
            request["decided_by_team"] = decided_by_team
            request["decided_by_role"] = decided_by_role
            request["decision_note"] = decision_note
            request["applied_schedule_id"] = applied_schedule_id
            return _FakePostgresCursor(rowcount=1)

        if "UPDATE control_plane_oncall_change_requests" in normalized and "SET assigned_to = %s" in normalized:
            assigned_to, assigned_to_team, assigned_at, assigned_by, assignment_note, request_id = params
            request = self.change_requests.get(request_id)
            if request is None:
                return _FakePostgresCursor(rowcount=0)
            request["assigned_to"] = assigned_to
            request["assigned_to_team"] = assigned_to_team
            request["assigned_at"] = assigned_at
            request["assigned_by"] = assigned_by
            request["assignment_note"] = assignment_note
            return _FakePostgresCursor(rowcount=1)

        raise AssertionError(f"Unhandled SQL in fake Postgres connection: {normalized}")

    @staticmethod
    def _job_tuple(job: dict) -> tuple:
        return (
            job["job_id"],
            job["created_at"],
            job["job_type"],
            job["status"],
            json.dumps(job["request_payload"], sort_keys=True),
            json.dumps(job["result_payload"], sort_keys=True),
            job.get("error"),
            job.get("started_at"),
            job.get("completed_at"),
            job.get("claimed_by_worker_id"),
            job.get("lease_expires_at"),
        )

    @staticmethod
    def _alert_tuple(alert: dict) -> tuple:
        return (
            alert["alert_id"],
            alert["created_at"],
            alert["alert_key"],
            alert["status"],
            alert["severity"],
            alert["summary"],
            json.dumps(alert["finding_codes"], sort_keys=True),
            alert["delivery_state"],
            json.dumps(alert["payload"], sort_keys=True),
            alert.get("error"),
            alert.get("acknowledged_at"),
            alert.get("acknowledged_by"),
            alert.get("acknowledgement_note"),
        )

    @staticmethod
    def _silence_tuple(silence: dict) -> tuple:
        return (
            silence["silence_id"],
            silence["created_at"],
            silence["created_by"],
            silence["reason"],
            silence.get("match_alert_key"),
            silence.get("match_finding_code"),
            silence.get("starts_at"),
            silence.get("expires_at"),
            silence.get("cancelled_at"),
            silence.get("cancelled_by"),
        )

    @staticmethod
    def _schedule_tuple(schedule: dict) -> tuple:
        return (
            schedule["schedule_id"],
            schedule["created_at"],
            schedule["created_by"],
            schedule["environment_name"],
            schedule.get("created_by_team"),
            schedule.get("created_by_role"),
            schedule.get("change_reason"),
            schedule.get("approved_by"),
            schedule.get("approved_by_team"),
            schedule.get("approved_by_role"),
            schedule.get("approved_at"),
            schedule.get("approval_note"),
            schedule["team_name"],
            schedule["timezone_name"],
            json.dumps(schedule["weekdays"], sort_keys=True),
            schedule["start_time"],
            schedule["end_time"],
            schedule["priority"],
            schedule.get("rotation_name"),
            schedule.get("effective_start_date"),
            schedule.get("effective_end_date"),
            schedule.get("webhook_url"),
            schedule.get("escalation_webhook_url"),
            schedule.get("cancelled_at"),
            schedule.get("cancelled_by"),
        )

    @staticmethod
    def _change_request_tuple(request: dict) -> tuple:
        return (
            request["request_id"],
            request["created_at"],
            request["created_by"],
            request["environment_name"],
            request.get("created_by_team"),
            request.get("created_by_role"),
            request.get("change_reason"),
            request["status"],
            request["review_required"],
            json.dumps(request["review_reasons"], sort_keys=True),
            request["team_name"],
            request["timezone_name"],
            json.dumps(request["weekdays"], sort_keys=True),
            request["start_time"],
            request["end_time"],
            request["priority"],
            request.get("rotation_name"),
            request.get("effective_start_date"),
            request.get("effective_end_date"),
            request.get("webhook_url"),
            request.get("escalation_webhook_url"),
            request.get("assigned_to"),
            request.get("assigned_to_team"),
            request.get("assigned_at"),
            request.get("assigned_by"),
            request.get("assignment_note"),
            request.get("decision_at"),
            request.get("decided_by"),
            request.get("decided_by_team"),
            request.get("decided_by_role"),
            request.get("decision_note"),
            request.get("applied_schedule_id"),
        )


class _StubPostgresControlPlaneDatabase(_PostgresControlPlaneDatabase):
    def __init__(
        self,
        *,
        jobs: dict[str, dict],
        workers: dict[str, dict],
        alerts: dict[str, dict] | None = None,
        silences: dict[str, dict] | None = None,
        schedules: dict[str, dict] | None = None,
        change_requests: dict[str, dict] | None = None,
    ) -> None:
        self._connection = _FakePostgresConnection(
            jobs=jobs,
            workers=workers,
            alerts=alerts,
            silences=silences,
            schedules=schedules,
            change_requests=change_requests,
        )

    def _connect(self):
        return self._connection


class StorageTests(unittest.TestCase):
    def test_resolve_workspace_settings_supports_database_url_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            database_path = (Path(tmpdir) / "state" / "lsa.db").resolve()
            database_url = f"sqlite:///{database_path.as_posix()}"
            with patch.dict(
                "os.environ",
                {
                    "LSA_DATABASE_URL": database_url,
                    "LSA_SQLITE_BUSY_TIMEOUT_MS": "9000",
                },
                clear=False,
            ):
                settings = resolve_workspace_settings(tmpdir)

            self.assertEqual(settings.database_backend, "sqlite")
            self.assertEqual(settings.database_url, database_url)
            self.assertEqual(settings.database_path, database_path)
            self.assertEqual(settings.sqlite_busy_timeout_ms, 9000)

    def test_inspect_database_config_supports_postgres_target_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = inspect_database_config(
                root_dir=Path(tmpdir),
                default_path=Path(tmpdir) / "data" / "control_plane.db",
                raw_url="postgresql://lsa:secret@db.example.com:5433/lsa_prod?sslmode=require",
            )

            self.assertEqual(config.backend, "postgres")
            self.assertEqual(config.host, "db.example.com")
            self.assertEqual(config.port, 5433)
            self.assertEqual(config.database_name, "lsa_prod")
            self.assertEqual(config.username, "lsa")
            self.assertFalse(config.runtime_supported)
            self.assertEqual(
                config.redacted_url,
                "postgresql://lsa:***@db.example.com:5433/lsa_prod?sslmode=require",
            )

    def test_inspect_database_runtime_support_reports_missing_postgres_driver(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            support = inspect_database_runtime_support(
                root_dir=Path(tmpdir),
                default_path=Path(tmpdir) / "data" / "control_plane.db",
                raw_url="postgresql://lsa:secret@db.example.com:5432/lsa_prod",
            )

            self.assertEqual(support.backend, "postgres")
            self.assertEqual(support.runtime_driver, "psycopg")
            self.assertFalse(support.runtime_supported)
            self.assertFalse(support.runtime_dependency_installed)
            self.assertFalse(support.runtime_available)
            self.assertIn("unsupported_runtime_backend:postgres", support.blockers)
            self.assertIn("missing_runtime_dependency:psycopg", support.blockers)

    def test_resolve_workspace_settings_supports_postgres_runtime_job_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(
                "os.environ",
                {
                    "LSA_ENABLE_POSTGRES_RUNTIME_JOBS": "1",
                    "LSA_POSTGRES_RUNTIME_JOBS_DATABASE_URL": "postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                },
                clear=False,
            ):
                settings = resolve_workspace_settings(tmpdir)

            self.assertTrue(settings.enable_postgres_runtime_jobs)
            self.assertEqual(
                settings.postgres_runtime_jobs_database_url,
                "postgresql://lsa:secret@db.example.com:5432/lsa_prod",
            )

    def test_resolve_workspace_settings_supports_postgres_runtime_snapshot_audit_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(
                "os.environ",
                {
                    "LSA_ENABLE_POSTGRES_RUNTIME_SNAPSHOTS_AUDITS": "1",
                    "LSA_POSTGRES_RUNTIME_SNAPSHOTS_AUDITS_DATABASE_URL": "postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                },
                clear=False,
            ):
                settings = resolve_workspace_settings(tmpdir)

            self.assertTrue(settings.enable_postgres_runtime_snapshots_audits)
            self.assertEqual(
                settings.postgres_runtime_snapshots_audits_database_url,
                "postgresql://lsa:secret@db.example.com:5432/lsa_prod",
            )

    def test_build_job_repository_activates_feature_gated_postgres_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            settings.enable_postgres_runtime_jobs = True
            settings.postgres_runtime_jobs_database_url = "postgresql://lsa:secret@db.example.com:5432/lsa_prod"

            sentinel_database = object()

            repository = build_job_repository(
                settings,
                runtime_support_inspector=lambda **_: type(
                    "Support",
                    (),
                    {
                        "runtime_available": True,
                        "blockers": [],
                    },
                )(),
                database_builder=lambda settings, raw_url: sentinel_database,
            )

            self.assertIs(repository.database, sentinel_database)

    def test_build_job_repository_rejects_unavailable_feature_gated_postgres_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            settings.enable_postgres_runtime_jobs = True
            settings.postgres_runtime_jobs_database_url = "postgresql://lsa:secret@db.example.com:5432/lsa_prod"

            with self.assertRaisesRegex(ValueError, "missing_runtime_dependency:psycopg"):
                build_job_repository(
                    settings,
                    runtime_support_inspector=lambda **_: type(
                        "Support",
                        (),
                        {
                            "runtime_available": False,
                            "blockers": ["missing_runtime_dependency:psycopg"],
                        },
                    )(),
                    database_builder=lambda settings, raw_url: object(),
                )

    def test_build_control_plane_runtime_bundle_defaults_to_shared_sqlite_backend(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            bundle = build_control_plane_runtime_bundle(settings, graph=IntentGraph())

            self.assertEqual(bundle.snapshot_repository_backend, "sqlite")
            self.assertEqual(bundle.audit_repository_backend, "sqlite")
            self.assertEqual(bundle.job_repository_backend, "sqlite")
            self.assertEqual(bundle.repository_layout, "shared")
            self.assertFalse(bundle.mixed_backends)
            self.assertIs(bundle.snapshot_repository.database, bundle.audit_repository.database)
            self.assertIs(bundle.snapshot_repository.database, bundle.job_repository.database)

    def test_build_control_plane_runtime_bundle_reports_mixed_backends_when_jobs_use_postgres(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            settings.enable_postgres_runtime_jobs = True
            settings.postgres_runtime_jobs_database_url = "postgresql://lsa:secret@db.example.com:5432/lsa_prod"

            sentinel_database = type(
                "SentinelDatabase",
                (),
                {"config": type("Config", (), {"backend": "postgres"})()},
            )()
            bundle = build_control_plane_runtime_bundle(
                settings,
                graph=IntentGraph(),
                runtime_support_inspector=lambda **_: type(
                    "Support",
                    (),
                    {
                        "runtime_available": True,
                        "blockers": [],
                    },
                )(),
                database_builder=lambda settings, raw_url: sentinel_database,
            )

            self.assertEqual(bundle.snapshot_repository_backend, "sqlite")
            self.assertEqual(bundle.audit_repository_backend, "sqlite")
            self.assertEqual(bundle.job_repository_backend, "postgres")
            self.assertEqual(bundle.repository_layout, "mixed")
            self.assertTrue(bundle.mixed_backends)
            self.assertIs(bundle.job_repository.database, sentinel_database)

    def test_build_control_plane_runtime_bundle_supports_shared_postgres_layout(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            settings.enable_postgres_runtime_snapshots_audits = True
            settings.postgres_runtime_snapshots_audits_database_url = "postgresql://lsa:secret@db.example.com:5432/lsa_prod"
            settings.enable_postgres_runtime_jobs = True
            settings.postgres_runtime_jobs_database_url = "postgresql://lsa:secret@db.example.com:5432/lsa_prod"

            sentinel_database = type(
                "SentinelDatabase",
                (),
                {"config": type("Config", (), {"backend": "postgres"})()},
            )()
            bundle = build_control_plane_runtime_bundle(
                settings,
                graph=IntentGraph(),
                runtime_support_inspector=lambda **_: type(
                    "Support",
                    (),
                    {
                        "runtime_available": True,
                        "blockers": [],
                    },
                )(),
                database_builder=lambda settings, raw_url: sentinel_database,
            )

            self.assertEqual(bundle.snapshot_repository_backend, "postgres")
            self.assertEqual(bundle.audit_repository_backend, "postgres")
            self.assertEqual(bundle.job_repository_backend, "postgres")
            self.assertEqual(bundle.repository_layout, "shared")
            self.assertFalse(bundle.mixed_backends)
            self.assertIs(bundle.snapshot_repository.database, sentinel_database)
            self.assertIs(bundle.audit_repository.database, sentinel_database)
            self.assertIs(bundle.job_repository.database, sentinel_database)

    def test_snapshot_repository_persists_and_lists_records(self) -> None:
        root = Path("tests/fixtures/sample_service").resolve()
        snapshot = GraphBuilder().build(root)

        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = SnapshotRepository(settings, graph=IntentGraph())
            record = repo.save(snapshot, repo_path=str(root), snapshot_id="snap-test")

            self.assertEqual(record.snapshot_id, "snap-test")
            self.assertTrue(settings.database_path.exists())
            listed = repo.list()
            self.assertEqual(len(listed), 1)
            self.assertEqual(listed[0].snapshot_id, "snap-test")
            with sqlite3.connect(settings.database_path) as connection:
                row = connection.execute(
                    "SELECT snapshot_id, repo_path FROM snapshots WHERE snapshot_id = ?",
                    ("snap-test",),
                ).fetchone()
            assert row is not None
            self.assertEqual(row[0], "snap-test")
            self.assertEqual(row[1], str(root))

            with repo.database._connect() as connection:
                foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]
                journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
                busy_timeout = connection.execute("PRAGMA busy_timeout").fetchone()[0]
            self.assertEqual(foreign_keys, 1)
            self.assertEqual(journal_mode.lower(), "wal")
            self.assertEqual(busy_timeout, settings.sqlite_busy_timeout_ms)
            schema_status = repo.database.status()
            self.assertEqual(schema_status["schema_version"], 1)
            self.assertEqual(schema_status["expected_schema_version"], 1)
            self.assertTrue(schema_status["schema_ready"])
            detailed_schema_status = repo.database.schema_status()
            self.assertEqual(detailed_schema_status["schema_version"], 1)
            self.assertEqual(len(detailed_schema_status["migrations"]), 1)
            with repo.database._connect() as connection:
                connection.execute(
                    """
                    UPDATE control_plane_schema_metadata
                    SET metadata_value = '0'
                    WHERE metadata_key = 'schema_version'
                    """
                )
                connection.execute(
                    """
                    DELETE FROM control_plane_schema_migrations
                    WHERE migration_id = ?
                    """,
                    ("2026-05-05-control-plane-schema-v1",),
                )
            degraded_status = repo.database.schema_status()
            self.assertFalse(degraded_status["schema_ready"])
            self.assertEqual(degraded_status["pending_migration_count"], 1)
            migrated_status = repo.database.migrate_schema()
            self.assertTrue(migrated_status["schema_ready"])
            self.assertEqual(migrated_status["schema_version"], 1)
            self.assertEqual(migrated_status["pending_migration_count"], 0)
            maintenance_status = repo.database.maintenance_mode_status()
            self.assertFalse(maintenance_status["active"])
            enabled_maintenance = repo.database.set_maintenance_mode(
                active=True,
                changed_by="operator-a",
                reason="backup window",
            )
            self.assertTrue(enabled_maintenance["active"])
            self.assertEqual(enabled_maintenance["changed_by"], "operator-a")
            self.assertEqual(enabled_maintenance["reason"], "backup window")

    def test_audit_repository_persists_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = AuditRepository(settings)
            record = AuditRecord(
                audit_id="audit-test",
                created_at="2026-01-01T00:00:00+00:00",
                snapshot_id="snap-test",
                snapshot_path="/tmp/snap.json",
                alert_count=1,
                report_paths=["/tmp/report.md"],
                alerts=[{"function": "f"}],
                events=[{"function": "f"}],
                sessions=[{"session_key": "request_id:req-123"}],
                explanation={"status": "clean", "summary": "No drift alerts detected."},
            )
            repo.save(record)

            fetched = repo.get("audit-test")
            self.assertEqual(fetched.audit_id, "audit-test")
            self.assertEqual(fetched.explanation["status"], "clean")
            self.assertEqual(len(repo.list()), 1)
            with sqlite3.connect(settings.database_path) as connection:
                row = connection.execute(
                    "SELECT audit_id, alert_count FROM audits WHERE audit_id = ?",
                    ("audit-test",),
                ).fetchone()
            assert row is not None
            self.assertEqual(row[0], "audit-test")
            self.assertEqual(row[1], 1)

    def test_job_repository_persists_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            record = repo.create(
                job_type="collect-audit",
                request_payload={"snapshot_id": "snap-test", "pid": 1234},
                job_id="job-test",
            )

            fetched = repo.get("job-test")
            self.assertEqual(fetched.job_id, "job-test")
            self.assertEqual(fetched.status, "queued")
            self.assertEqual(fetched.request_payload["pid"], 1234)
            self.assertEqual(len(repo.list()), 1)
            with sqlite3.connect(settings.database_path) as connection:
                row = connection.execute(
                    "SELECT job_id, job_type, status FROM jobs WHERE job_id = ?",
                    ("job-test",),
                ).fetchone()
            assert row is not None
            self.assertEqual(row[0], "job-test")
            self.assertEqual(row[1], "collect-audit")
            self.assertEqual(row[2], "queued")

    def test_job_repository_persists_worker_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            record = WorkerRecord(
                worker_id="worker-test",
                mode="standalone",
                status="running",
                started_at="2026-05-04T00:00:00+00:00",
                last_heartbeat_at="2026-05-04T00:00:01+00:00",
                host_name="localhost",
                process_id=4242,
                current_job_id="job-test",
            )
            repo.save_worker(record)

            fetched = repo.get_worker("worker-test")
            self.assertEqual(fetched.worker_id, "worker-test")
            self.assertEqual(fetched.current_job_id, "job-test")
            self.assertEqual(len(repo.list_workers()), 1)
            self.assertEqual(repo.count_workers_seen_since("2026-05-04T00:00:00+00:00"), 1)

    def test_postgres_control_plane_database_supports_live_job_queue_semantics(self) -> None:
        database = _StubPostgresControlPlaneDatabase(
            jobs={
                "job-a": {
                    "job_id": "job-a",
                    "created_at": "2026-05-06T00:00:00+00:00",
                    "job_type": "audit-trace",
                    "status": "queued",
                    "request_payload": {"snapshot_id": "snap-a"},
                    "result_payload": {},
                    "error": None,
                    "started_at": None,
                    "completed_at": None,
                    "claimed_by_worker_id": None,
                    "lease_expires_at": None,
                },
                "job-b": {
                    "job_id": "job-b",
                    "created_at": "2026-05-06T00:00:01+00:00",
                    "job_type": "collect-audit",
                    "status": "running",
                    "request_payload": {"snapshot_id": "snap-b"},
                    "result_payload": {},
                    "error": None,
                    "started_at": "2026-05-06T00:00:02+00:00",
                    "completed_at": None,
                    "claimed_by_worker_id": "worker-a",
                    "lease_expires_at": "2026-05-06T00:04:00+00:00",
                },
                "job-c": {
                    "job_id": "job-c",
                    "created_at": "2026-05-06T00:00:02+00:00",
                    "job_type": "audit-trace",
                    "status": "running",
                    "request_payload": {"snapshot_id": "snap-c"},
                    "result_payload": {},
                    "error": "stale worker",
                    "started_at": "2026-05-06T00:00:03+00:00",
                    "completed_at": None,
                    "claimed_by_worker_id": "worker-b",
                    "lease_expires_at": "2026-05-06T00:01:00+00:00",
                },
            },
            workers={
                "worker-a": {
                    "worker_id": "worker-a",
                    "status": "running",
                    "last_heartbeat_at": "2026-05-06T00:00:10+00:00",
                },
                "worker-b": {
                    "worker_id": "worker-b",
                    "status": "stopped",
                    "last_heartbeat_at": "2026-05-06T00:00:09+00:00",
                },
            },
        )

        claimed = database.claim_next_queued_job(
            started_at="2026-05-06T00:00:05+00:00",
            worker_id="worker-a",
            lease_expires_at="2026-05-06T00:05:00+00:00",
        )
        assert claimed is not None
        self.assertEqual(claimed.job_id, "job-a")
        self.assertEqual(claimed.status, "running")
        self.assertEqual(claimed.claimed_by_worker_id, "worker-a")
        self.assertEqual(database.count_jobs_with_status("queued"), 0)

        self.assertTrue(
            database.renew_job_lease(
                job_id="job-a",
                worker_id="worker-a",
                lease_expires_at="2026-05-06T00:06:00+00:00",
            )
        )
        self.assertFalse(
            database.renew_job_lease(
                job_id="job-a",
                worker_id="worker-z",
                lease_expires_at="2026-05-06T00:07:00+00:00",
            )
        )

        expired = database.requeue_expired_leases("2026-05-06T00:03:00+00:00")
        self.assertEqual([record.job_id for record in expired], ["job-c"])
        self.assertEqual(database.count_jobs_with_status("queued"), 1)

        self.assertEqual(database.requeue_jobs_with_status(("running",)), 2)
        self.assertEqual(database.count_jobs_with_status("queued"), 3)
        self.assertEqual(database.count_workers_seen_since("2026-05-06T00:00:00+00:00"), 1)

    def test_postgres_control_plane_database_supports_alert_and_oncall_lifecycle(self) -> None:
        database = _StubPostgresControlPlaneDatabase(
            jobs={},
            workers={},
        )

        database.insert_control_plane_alert(
            ControlPlaneAlertRecord(
                alert_id="alert-test",
                created_at="2026-05-06T00:00:00+00:00",
                alert_key="control-plane:critical:queue_backlog",
                status="critical",
                severity="critical",
                summary="Queued job backlog is above the configured critical threshold.",
                finding_codes=["queue_backlog"],
                delivery_state="delivered",
                payload={"report": {"evaluation": {"status": "critical"}}},
                error=None,
            )
        )
        self.assertEqual(database.list_control_plane_alerts()[0].alert_id, "alert-test")
        self.assertEqual(database.fetch_latest_control_plane_alert().alert_id, "alert-test")  # type: ignore[union-attr]
        self.assertEqual(
            database.fetch_latest_control_plane_alert_by_key("control-plane:critical:queue_backlog").alert_id,  # type: ignore[union-attr]
            "alert-test",
        )
        self.assertTrue(
            database.acknowledge_control_plane_alert(
                alert_id="alert-test",
                acknowledged_at="2026-05-06T00:10:00+00:00",
                acknowledged_by="operator-a",
                acknowledgement_note="Investigating",
            )
        )
        self.assertEqual(database.fetch_control_plane_alert("alert-test").acknowledged_by, "operator-a")  # type: ignore[union-attr]

        database.insert_control_plane_alert_silence(
            ControlPlaneAlertSilenceRecord(
                silence_id="silence-test",
                created_at="2026-05-06T00:00:00+00:00",
                created_by="operator-a",
                reason="Deployment",
                match_finding_code="queue_backlog",
                starts_at="2026-05-06T00:00:00+00:00",
                expires_at="2026-05-06T01:00:00+00:00",
            )
        )
        self.assertEqual(database.list_control_plane_alert_silences()[0].silence_id, "silence-test")
        self.assertTrue(
            database.cancel_control_plane_alert_silence(
                silence_id="silence-test",
                cancelled_at="2026-05-06T00:30:00+00:00",
                cancelled_by="operator-a",
            )
        )
        self.assertEqual(database.fetch_control_plane_alert_silence("silence-test").cancelled_by, "operator-a")  # type: ignore[union-attr]

        database.insert_control_plane_oncall_schedule(
            ControlPlaneOnCallScheduleRecord(
                schedule_id="schedule-test",
                created_at="2026-05-06T00:00:00+00:00",
                created_by="operator-a",
                environment_name="prod",
                created_by_team="platform",
                created_by_role="engineer",
                change_reason="Primary rotation",
                approved_by="director-a",
                approved_by_team="platform",
                approved_by_role="director",
                approved_at="2026-05-05T12:00:00+00:00",
                approval_note="Approved",
                team_name="platform",
                timezone_name="UTC",
                weekdays=[0, 1, 2],
                start_time="09:00",
                end_time="17:00",
                priority=150,
                rotation_name="primary",
                effective_start_date="2026-05-01",
                effective_end_date="2026-05-31",
                webhook_url="https://example.com/team",
                escalation_webhook_url="https://example.com/escalate",
            )
        )
        self.assertEqual(database.list_control_plane_oncall_schedules()[0].schedule_id, "schedule-test")
        self.assertTrue(
            database.cancel_control_plane_oncall_schedule(
                schedule_id="schedule-test",
                cancelled_at="2026-05-06T12:00:00+00:00",
                cancelled_by="operator-a",
            )
        )
        self.assertEqual(database.fetch_control_plane_oncall_schedule("schedule-test").cancelled_by, "operator-a")  # type: ignore[union-attr]

        database.insert_control_plane_oncall_change_request(
            ControlPlaneOnCallChangeRequestRecord(
                request_id="request-test",
                created_at="2026-05-06T00:00:00+00:00",
                created_by="operator-a",
                environment_name="prod",
                created_by_team="platform",
                created_by_role="engineer",
                change_reason="Temporary dual coverage during cutover.",
                status="pending_review",
                review_required=True,
                review_reasons=["ambiguous_overlap"],
                team_name="platform",
                timezone_name="UTC",
                weekdays=[0, 1, 2, 3, 4],
                start_time="09:00",
                end_time="17:00",
                priority=200,
                rotation_name="holiday",
                effective_start_date="2026-05-06",
                effective_end_date="2026-05-06",
                webhook_url="https://example.com/team",
                escalation_webhook_url="https://example.com/escalate",
            )
        )
        self.assertEqual(
            database.list_control_plane_oncall_change_requests(status="pending_review")[0].request_id,
            "request-test",
        )
        self.assertTrue(
            database.update_control_plane_oncall_change_request_assignment(
                request_id="request-test",
                assigned_to="reviewer-a",
                assigned_to_team="platform",
                assigned_at="2026-05-06T00:02:00+00:00",
                assigned_by="lead-a",
                assignment_note="Taking first review pass.",
            )
        )
        self.assertEqual(
            database.fetch_control_plane_oncall_change_request("request-test").assigned_to,  # type: ignore[union-attr]
            "reviewer-a",
        )
        self.assertTrue(
            database.update_control_plane_oncall_change_request_decision(
                request_id="request-test",
                status="applied",
                decision_at="2026-05-06T00:05:00+00:00",
                decided_by="director-a",
                decided_by_team="platform",
                decided_by_role="director",
                decision_note="Approved for cutover.",
                applied_schedule_id="schedule-test",
            )
        )
        decided = database.fetch_control_plane_oncall_change_request("request-test")
        self.assertEqual(decided.decided_by, "director-a")  # type: ignore[union-attr]
        self.assertEqual(decided.applied_schedule_id, "schedule-test")  # type: ignore[union-attr]

    def test_job_repository_persists_heartbeat_and_lease_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            heartbeat = WorkerHeartbeatRecord(
                heartbeat_id="heartbeat-test",
                worker_id="worker-test",
                recorded_at="2026-05-04T00:00:02+00:00",
                status="running",
                current_job_id="job-test",
            )
            lease_event = JobLeaseEventRecord(
                event_id="lease-event-test",
                job_id="job-test",
                worker_id="worker-test",
                event_type="lease_claimed",
                recorded_at="2026-05-04T00:00:03+00:00",
                details={"lease_expires_at": "2026-05-04T00:00:08+00:00"},
            )

            repo.append_worker_heartbeat(heartbeat)
            repo.append_job_lease_event(lease_event)

            heartbeats = repo.list_worker_heartbeats("worker-test")
            lease_events = repo.list_job_lease_events("job-test")
            self.assertEqual(len(heartbeats), 1)
            self.assertEqual(heartbeats[0].heartbeat_id, "heartbeat-test")
            self.assertEqual(len(lease_events), 1)
            self.assertEqual(lease_events[0].event_id, "lease-event-test")

    def test_job_repository_prunes_old_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            repo.append_worker_heartbeat(
                WorkerHeartbeatRecord(
                    heartbeat_id="heartbeat-old",
                    worker_id="worker-test",
                    recorded_at="2020-01-01T00:00:00+00:00",
                    status="running",
                    current_job_id=None,
                )
            )
            repo.append_job_lease_event(
                JobLeaseEventRecord(
                    event_id="lease-event-old",
                    job_id="job-test",
                    worker_id="worker-test",
                    event_type="lease_claimed",
                    recorded_at="2020-01-01T00:00:00+00:00",
                    details={},
                )
            )

            self.assertEqual(repo.prune_worker_heartbeats_before("2021-01-01T00:00:00+00:00"), 1)
            self.assertEqual(repo.prune_job_lease_events_before("2021-01-01T00:00:00+00:00"), 1)
            self.assertEqual(len(repo.list_worker_heartbeats("worker-test")), 0)
            self.assertEqual(len(repo.list_job_lease_events("job-test")), 0)

    def test_job_repository_compacts_old_history_into_rollups(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            repo.append_worker_heartbeat(
                WorkerHeartbeatRecord(
                    heartbeat_id="heartbeat-old-1",
                    worker_id="worker-test",
                    recorded_at="2020-01-01T00:00:00+00:00",
                    status="running",
                    current_job_id=None,
                )
            )
            repo.append_worker_heartbeat(
                WorkerHeartbeatRecord(
                    heartbeat_id="heartbeat-old-2",
                    worker_id="worker-test",
                    recorded_at="2020-01-01T01:00:00+00:00",
                    status="running",
                    current_job_id=None,
                )
            )
            repo.append_job_lease_event(
                JobLeaseEventRecord(
                    event_id="lease-event-old-1",
                    job_id="job-test",
                    worker_id="worker-test",
                    event_type="lease_claimed",
                    recorded_at="2020-01-01T00:00:00+00:00",
                    details={},
                )
            )
            repo.append_job_lease_event(
                JobLeaseEventRecord(
                    event_id="lease-event-old-2",
                    job_id="job-test",
                    worker_id="worker-test",
                    event_type="lease_claimed",
                    recorded_at="2020-01-01T02:00:00+00:00",
                    details={},
                )
            )

            self.assertEqual(repo.compact_worker_heartbeats_before("2021-01-01T00:00:00+00:00"), 2)
            self.assertEqual(repo.compact_job_lease_events_before("2021-01-01T00:00:00+00:00"), 2)
            worker_rollups = repo.list_worker_heartbeat_rollups("worker-test")
            lease_rollups = repo.list_job_lease_event_rollups("job-test")
            self.assertEqual(len(repo.list_worker_heartbeats("worker-test")), 0)
            self.assertEqual(len(repo.list_job_lease_events("job-test")), 0)
            self.assertEqual(len(worker_rollups), 1)
            self.assertEqual(worker_rollups[0].event_count, 2)
            self.assertEqual(len(lease_rollups), 1)
            self.assertEqual(lease_rollups[0].event_count, 2)

    def test_job_repository_persists_control_plane_alerts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            alert = ControlPlaneAlertRecord(
                alert_id="alert-test",
                created_at="2026-05-04T00:00:00+00:00",
                alert_key="control-plane:critical:queue_backlog",
                status="critical",
                severity="critical",
                summary="Queued job backlog is above the configured critical threshold.",
                finding_codes=["queue_backlog"],
                delivery_state="delivered",
                payload={"report": {"evaluation": {"status": "critical"}}},
                error=None,
            )
            repo.append_control_plane_alert(alert)

            listed = repo.list_control_plane_alerts()
            self.assertEqual(len(listed), 1)
            self.assertEqual(listed[0].alert_id, "alert-test")
            self.assertEqual(repo.latest_control_plane_alert_by_key(alert.alert_key).alert_id, "alert-test")  # type: ignore[union-attr]
            acknowledged = repo.acknowledge_control_plane_alert(
                alert_id="alert-test",
                acknowledged_at="2026-05-04T00:05:00+00:00",
                acknowledged_by="operator-a",
                acknowledgement_note="Acked for review",
            )
            self.assertEqual(acknowledged.acknowledged_by, "operator-a")

    def test_job_repository_persists_control_plane_alert_silences(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            silence = ControlPlaneAlertSilenceRecord(
                silence_id="silence-test",
                created_at="2026-05-04T00:00:00+00:00",
                created_by="operator-a",
                reason="Deployment",
                match_finding_code="queue_backlog",
                starts_at="2026-05-04T00:00:00+00:00",
                expires_at="2026-05-04T01:00:00+00:00",
            )
            repo.append_control_plane_alert_silence(silence)
            self.assertEqual(len(repo.list_control_plane_alert_silences()), 1)
            cancelled = repo.cancel_control_plane_alert_silence(
                silence_id="silence-test",
                cancelled_at="2026-05-04T00:30:00+00:00",
                cancelled_by="operator-a",
            )
            self.assertEqual(cancelled.cancelled_by, "operator-a")

    def test_job_repository_persists_control_plane_oncall_schedules(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            schedule = ControlPlaneOnCallScheduleRecord(
                schedule_id="schedule-test",
                created_at="2026-05-04T00:00:00+00:00",
                created_by="operator-a",
                environment_name="prod",
                created_by_team="platform",
                created_by_role="engineer",
                change_reason="Primary daytime rotation",
                approved_by="director-a",
                approved_by_team="platform",
                approved_by_role="director",
                approved_at="2026-05-03T12:00:00+00:00",
                approval_note="Approved during weekly ops review",
                team_name="platform",
                timezone_name="UTC",
                weekdays=[0, 1, 2],
                start_time="09:00",
                end_time="17:00",
                priority=150,
                rotation_name="primary",
                effective_start_date="2026-05-01",
                effective_end_date="2026-05-31",
                webhook_url="https://example.com/team",
                escalation_webhook_url="https://example.com/escalate",
            )
            repo.append_control_plane_oncall_schedule(schedule)
            stored = repo.list_control_plane_oncall_schedules()
            self.assertEqual(len(stored), 1)
            self.assertEqual(stored[0].priority, 150)
            self.assertEqual(stored[0].rotation_name, "primary")
            self.assertEqual(stored[0].effective_start_date, "2026-05-01")
            self.assertEqual(stored[0].approved_by, "director-a")
            self.assertEqual(stored[0].environment_name, "prod")
            self.assertEqual(stored[0].created_by_team, "platform")
            self.assertEqual(stored[0].approved_by_role, "director")
            cancelled = repo.cancel_control_plane_oncall_schedule(
                schedule_id="schedule-test",
                cancelled_at="2026-05-04T12:00:00+00:00",
                cancelled_by="operator-a",
            )
            self.assertEqual(cancelled.cancelled_by, "operator-a")

    def test_job_repository_persists_control_plane_oncall_change_requests(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            request = ControlPlaneOnCallChangeRequestRecord(
                request_id="request-test",
                created_at="2026-05-04T00:00:00+00:00",
                created_by="operator-a",
                environment_name="prod",
                created_by_team="platform",
                created_by_role="engineer",
                change_reason="Temporary dual coverage during cutover.",
                status="pending_review",
                review_required=True,
                review_reasons=["ambiguous_overlap"],
                team_name="platform",
                timezone_name="UTC",
                weekdays=[0, 1, 2, 3, 4],
                start_time="09:00",
                end_time="17:00",
                priority=200,
                rotation_name="holiday",
                effective_start_date="2026-05-04",
                effective_end_date="2026-05-04",
                webhook_url="https://example.com/team",
                escalation_webhook_url="https://example.com/escalate",
            )
            repo.append_control_plane_oncall_change_request(request)
            stored = repo.list_control_plane_oncall_change_requests()
            self.assertEqual(len(stored), 1)
            self.assertEqual(stored[0].status, "pending_review")
            self.assertEqual(stored[0].environment_name, "prod")
            self.assertEqual(stored[0].review_reasons, ["ambiguous_overlap"])
            assigned = repo.assign_control_plane_oncall_change_request(
                request_id="request-test",
                assigned_to="reviewer-a",
                assigned_to_team="platform",
                assigned_at="2026-05-04T00:02:00+00:00",
                assigned_by="lead-a",
                assignment_note="Taking first review pass.",
            )
            self.assertEqual(assigned.assigned_to, "reviewer-a")
            self.assertEqual(assigned.assignment_note, "Taking first review pass.")
            decided = repo.decide_control_plane_oncall_change_request(
                request_id="request-test",
                status="applied",
                decision_at="2026-05-04T00:05:00+00:00",
                decided_by="director-a",
                decided_by_team="platform",
                decided_by_role="director",
                decision_note="Approved for cutover.",
                applied_schedule_id="schedule-test",
            )
            self.assertEqual(decided.decided_by, "director-a")
            self.assertEqual(decided.applied_schedule_id, "schedule-test")

    def test_snapshot_repository_imports_legacy_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            settings.snapshots_dir.mkdir(parents=True, exist_ok=True)
            legacy_payload = {
                "snapshot_id": "legacy-snap",
                "created_at": "2026-01-02T00:00:00+00:00",
                "repo_path": "/tmp/legacy-service",
                "node_count": 3,
                "edge_count": 2,
                "snapshot_path": "/tmp/legacy-service/snapshot.json",
            }
            legacy_path = settings.snapshots_dir / "legacy-snap.meta.json"
            legacy_path.write_text(json.dumps(legacy_payload), encoding="utf-8")

            repo = SnapshotRepository(settings, graph=IntentGraph())

            fetched = repo.get("legacy-snap")
            self.assertEqual(fetched.snapshot_id, "legacy-snap")
            self.assertEqual(repo.list()[0].repo_path, "/tmp/legacy-service")

    def test_audit_repository_imports_legacy_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            settings.audits_dir.mkdir(parents=True, exist_ok=True)
            legacy_payload = {
                "audit_id": "legacy-audit",
                "created_at": "2026-01-03T00:00:00+00:00",
                "snapshot_id": "legacy-snap",
                "snapshot_path": "/tmp/legacy-service/snapshot.json",
                "alert_count": 1,
                "report_paths": ["/tmp/report.md"],
                "alerts": [{"function": "charge_customer"}],
                "events": [{"function": "charge_customer"}],
                "sessions": [{"session_key": "request_id:req-123"}],
                "explanation": {"status": "drift_detected", "summary": "Unexpected target observed."},
            }
            legacy_path = settings.audits_dir / "legacy-audit.json"
            legacy_path.write_text(json.dumps(legacy_payload), encoding="utf-8")

            repo = AuditRepository(settings)

            fetched = repo.get("legacy-audit")
            self.assertEqual(fetched.audit_id, "legacy-audit")
            self.assertEqual(fetched.explanation["status"], "drift_detected")
            self.assertEqual(repo.list()[0].audit_id, "legacy-audit")
