import tempfile
import unittest
from pathlib import Path

from lsa.core.intent_graph import IntentGraph
from lsa.core.models import IntentGraphSnapshot
from lsa.services.control_plane_backup_service import ControlPlaneBackupService
from lsa.settings import resolve_workspace_settings
from lsa.storage.files import AuditRepository, JobRepository, SnapshotRepository
from lsa.storage.models import (
    AuditRecord,
    ControlPlaneOnCallScheduleRecord,
    JobLeaseEventRollupRecord,
    JobRecord,
    WorkerHeartbeatRollupRecord,
    WorkerRecord,
)


class ControlPlaneBackupServiceTests(unittest.TestCase):
    def test_export_and_import_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            snapshots = SnapshotRepository(settings, graph=IntentGraph())
            audits = AuditRepository(settings)
            jobs = JobRepository(settings)
            service = ControlPlaneBackupService(
                settings=settings,
                snapshot_repository=snapshots,
                audit_repository=audits,
                job_repository=jobs,
            )

            snapshot = IntentGraphSnapshot(root_path="/tmp/service", functions={}, edges=[])
            snapshots.save(snapshot, repo_path="/tmp/service", snapshot_id="snap-backup")
            report_path = Path(tmpdir) / "reports" / "audit-backup.md"
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text("# report\n", encoding="utf-8")
            audits.save(
                AuditRecord(
                    audit_id="audit-backup",
                    created_at="2026-01-01T00:00:00+00:00",
                    snapshot_id="snap-backup",
                    snapshot_path="/tmp/snap.json",
                    alert_count=1,
                    report_paths=[str(report_path)],
                    alerts=[{"function": "charge_customer"}],
                    events=[{"function": "charge_customer"}],
                    sessions=[{"session_key": "request_id:req-1"}],
                    explanation={"status": "drift_detected", "summary": "drift"},
                )
            )
            jobs.save(
                JobRecord(
                    job_id="job-backup",
                    created_at="2026-01-01T00:00:01+00:00",
                    job_type="audit-trace",
                    status="completed",
                    request_payload={"snapshot_id": "snap-backup"},
                    result_payload={"audit_id": "audit-backup"},
                    completed_at="2026-01-01T00:00:05+00:00",
                )
            )
            jobs.save_worker(
                WorkerRecord(
                    worker_id="worker-backup",
                    mode="standalone",
                    status="stopped",
                    started_at="2026-01-01T00:00:00+00:00",
                    last_heartbeat_at="2026-01-01T00:00:05+00:00",
                    host_name="localhost",
                    process_id=1234,
                )
            )
            jobs.save_worker_heartbeat_rollup(
                WorkerHeartbeatRollupRecord(
                    day_bucket="2026-01-01",
                    worker_id="worker-backup",
                    status="running",
                    current_job_id=None,
                    event_count=3,
                )
            )
            jobs.save_job_lease_event_rollup(
                JobLeaseEventRollupRecord(
                    day_bucket="2026-01-01",
                    job_id="job-backup",
                    worker_id="worker-backup",
                    event_type="lease_claimed",
                    event_count=2,
                )
            )
            jobs.append_control_plane_oncall_schedule(
                ControlPlaneOnCallScheduleRecord(
                    schedule_id="schedule-backup",
                    created_at="2026-01-01T00:00:00+00:00",
                    created_by="operator",
                    team_name="platform",
                    timezone_name="UTC",
                    weekdays=[0, 1],
                    start_time="09:00",
                    end_time="17:00",
                )
            )

            backup_path = Path(tmpdir) / "backup" / "control-plane.json"
            summary = service.export_bundle(str(backup_path))
            self.assertTrue(backup_path.exists())
            self.assertEqual(summary.counts["snapshots"], 1)
            self.assertEqual(summary.counts["worker_heartbeat_rollups"], 1)
            self.assertEqual(summary.artifact_counts["snapshots"], 1)
            self.assertEqual(summary.artifact_counts["reports"], 1)

            jobs.reset_control_plane()
            imported = service.import_bundle(str(backup_path), replace_existing=False)
            self.assertEqual(imported.counts["jobs"], 1)
            self.assertEqual(len(snapshots.list()), 1)
            self.assertEqual(len(audits.list()), 1)
            self.assertEqual(len(jobs.list()), 1)
            self.assertEqual(len(jobs.list_worker_heartbeat_rollups()), 1)
            self.assertEqual(len(jobs.list_job_lease_event_rollups()), 1)
            self.assertEqual(len(jobs.list_control_plane_oncall_schedules()), 1)
            self.assertTrue(Path(snapshots.get("snap-backup").snapshot_path).exists())
            self.assertTrue(Path(audits.get("audit-backup").report_paths[0]).exists())

    def test_import_requires_empty_target_without_replace(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            snapshots = SnapshotRepository(settings, graph=IntentGraph())
            audits = AuditRepository(settings)
            jobs = JobRepository(settings)
            service = ControlPlaneBackupService(
                settings=settings,
                snapshot_repository=snapshots,
                audit_repository=audits,
                job_repository=jobs,
            )
            snapshots.save(
                IntentGraphSnapshot(root_path="/tmp/service", functions={}, edges=[]),
                repo_path="/tmp/service",
                snapshot_id="snap-one",
            )
            backup_path = Path(tmpdir) / "control-plane.json"
            service.export_bundle(str(backup_path))
            snapshots.save(
                IntentGraphSnapshot(root_path="/tmp/service", functions={}, edges=[]),
                repo_path="/tmp/service",
                snapshot_id="snap-two",
            )

            with self.assertRaisesRegex(ValueError, "not empty"):
                service.import_bundle(str(backup_path), replace_existing=False)
