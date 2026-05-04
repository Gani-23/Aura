import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from lsa.core.intent_graph import IntentGraph
from lsa.ingest.graph_builder import GraphBuilder
from lsa.settings import resolve_workspace_settings
from lsa.storage.files import AuditRepository, JobRepository, SnapshotRepository
from lsa.storage.models import WorkerRecord
from lsa.storage.models import AuditRecord


class StorageTests(unittest.TestCase):
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
