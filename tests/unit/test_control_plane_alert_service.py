from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import tempfile
import unittest

from lsa.services.analytics_service import AnalyticsService, ControlPlaneAlertThresholds
from lsa.services.control_plane_alert_service import ControlPlaneAlertService
from lsa.settings import resolve_workspace_settings
from lsa.storage.files import JobRepository
from lsa.storage.models import ControlPlaneAlertRecord, JobLeaseEventRecord, JobRecord, WorkerRecord


class ControlPlaneAlertServiceTests(unittest.TestCase):
    def test_emit_alerts_dedups_and_emits_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            analytics_service = AnalyticsService(
                job_repository=repo,
                heartbeat_timeout_seconds=5,
                default_thresholds=ControlPlaneAlertThresholds(
                    queue_warning_threshold=1,
                    queue_critical_threshold=2,
                    stale_worker_warning_threshold=1,
                    stale_worker_critical_threshold=2,
                    expired_lease_warning_threshold=2,
                    expired_lease_critical_threshold=3,
                    job_failure_rate_warning_threshold=0.2,
                    job_failure_rate_critical_threshold=0.5,
                    job_failure_rate_min_samples=1,
                ),
            )
            sink_path = Path(tmpdir) / "alerts.jsonl"
            service = ControlPlaneAlertService(
                job_repository=repo,
                analytics_service=analytics_service,
                window_days=7,
                dedup_window_seconds=3600,
                sink_path=str(sink_path),
            )

            now = datetime.now(UTC).isoformat()
            repo.save_worker(
                WorkerRecord(
                    worker_id="worker-stale",
                    mode="standalone",
                    status="stopped",
                    started_at=now,
                    last_heartbeat_at=(datetime.now(UTC) - timedelta(minutes=10)).isoformat(),
                    host_name="host-a",
                    process_id=101,
                    current_job_id=None,
                )
            )
            repo.save(
                JobRecord(
                    job_id="job-queued",
                    created_at=now,
                    job_type="audit-trace",
                    status="queued",
                )
            )
            repo.append_job_lease_event(
                JobLeaseEventRecord(
                    event_id="lease-expired",
                    job_id="job-queued",
                    worker_id="worker-stale",
                    event_type="lease_expired_requeued",
                    recorded_at=now,
                    details={},
                )
            )

            first = service.emit_alerts(force=False)
            self.assertEqual(len(first), 1)
            self.assertEqual(first[0].status, "critical")
            self.assertEqual(first[0].delivery_state, "delivered")
            self.assertTrue(sink_path.exists())
            acknowledged = service.acknowledge_alert(
                alert_id=first[0].alert_id,
                acknowledged_by="operator-a",
                acknowledgement_note="Investigating queue outage.",
            )
            self.assertEqual(acknowledged.acknowledged_by, "operator-a")

            second = service.emit_alerts(force=False)
            self.assertEqual(second, [])
            self.assertEqual(len(repo.list_control_plane_alerts()), 1)

            silence = service.create_silence(
                created_by="operator-a",
                reason="Maintenance window",
                duration_minutes=30,
                match_finding_code="queue_without_active_workers",
            )
            self.assertEqual(silence.created_by, "operator-a")
            self.assertEqual(len(service.list_silences(active_only=True)), 1)

            job = repo.get("job-queued")
            job.status = "queued"
            repo.save(job)
            suppressed = service.emit_alerts(force=True)
            self.assertEqual(len(suppressed), 1)
            self.assertEqual(suppressed[0].delivery_state, "suppressed")

            cancelled = service.cancel_silence(
                silence_id=silence.silence_id,
                cancelled_by="operator-a",
            )
            self.assertEqual(cancelled.cancelled_by, "operator-a")

            worker = repo.get_worker("worker-stale")
            worker.status = "running"
            worker.last_heartbeat_at = now
            repo.save_worker(worker)
            job = repo.get("job-queued")
            job.status = "completed"
            job.started_at = now
            job.completed_at = now
            repo.save(job)

            recovery = service.emit_alerts(force=False)
            self.assertEqual(len(recovery), 1)
            self.assertEqual(recovery[0].status, "healthy")
            self.assertEqual(recovery[0].severity, "info")

            listed = repo.list_control_plane_alerts()
            self.assertEqual(len(listed), 3)
            lines = sink_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 2)
            payload = json.loads(lines[0])
            self.assertIn("alert_key", payload)

    def test_follow_ups_emit_reminder_and_acknowledgement_stops_escalation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            analytics_service = AnalyticsService(
                job_repository=repo,
                heartbeat_timeout_seconds=5,
                default_thresholds=ControlPlaneAlertThresholds(),
            )
            service = ControlPlaneAlertService(
                job_repository=repo,
                analytics_service=analytics_service,
                window_days=7,
                dedup_window_seconds=10,
                reminder_interval_seconds=60,
                escalation_interval_seconds=120,
                sink_path=str(Path(tmpdir) / "followups.jsonl"),
            )

            incident = ControlPlaneAlertRecord(
                alert_id="incident-root",
                created_at=(datetime.now(UTC) - timedelta(seconds=90)).isoformat(),
                alert_key="control-plane:critical:queue_without_active_workers",
                status="critical",
                severity="critical",
                summary="No workers available for queued jobs.",
                finding_codes=["queue_without_active_workers"],
                delivery_state="delivered",
                payload={"report": {}, "lifecycle_event": "incident", "source_alert_id": None},
                error=None,
            )
            repo.append_control_plane_alert(incident)

            reminder = service.process_follow_ups(force=False)
            self.assertEqual(len(reminder), 1)
            self.assertEqual(reminder[0].payload["lifecycle_event"], "reminder")
            self.assertEqual(reminder[0].payload["source_alert_id"], "incident-root")

            acknowledged = service.acknowledge_alert(
                alert_id=reminder[0].alert_id,
                acknowledged_by="operator-b",
                acknowledgement_note="Owner engaged.",
            )
            self.assertEqual(acknowledged.acknowledged_by, "operator-b")
            self.assertEqual(repo.get_control_plane_alert("incident-root").acknowledged_by, "operator-b")

            no_escalation = service.process_follow_ups(force=True)
            self.assertEqual(no_escalation, [])

    def test_emit_alert_uses_active_oncall_route(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            analytics_service = AnalyticsService(
                job_repository=repo,
                heartbeat_timeout_seconds=5,
                default_thresholds=ControlPlaneAlertThresholds(
                    queue_warning_threshold=1,
                    queue_critical_threshold=2,
                    stale_worker_warning_threshold=10,
                    stale_worker_critical_threshold=20,
                    expired_lease_warning_threshold=10,
                    expired_lease_critical_threshold=20,
                    job_failure_rate_warning_threshold=1.0,
                    job_failure_rate_critical_threshold=1.0,
                    job_failure_rate_min_samples=99,
                ),
            )
            service = ControlPlaneAlertService(
                job_repository=repo,
                analytics_service=analytics_service,
                window_days=7,
                sink_path=str(Path(tmpdir) / "routed.jsonl"),
            )
            now_utc = datetime.now(UTC)
            current_weekday = now_utc.weekday()
            service.create_oncall_schedule(
                created_by="operator-a",
                team_name="platform-primary",
                timezone_name="UTC",
                weekdays=[current_weekday],
                start_time="00:00",
                end_time="23:59",
            )
            repo.save(
                JobRecord(
                    job_id="job-routed",
                    created_at=now_utc.isoformat(),
                    job_type="audit-trace",
                    status="queued",
                )
            )
            emitted = service.emit_alerts(force=True)
            self.assertEqual(len(emitted), 1)
            self.assertEqual(emitted[0].payload["route"]["team_name"], "platform-primary")


if __name__ == "__main__":
    unittest.main()
