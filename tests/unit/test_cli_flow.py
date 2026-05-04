from contextlib import redirect_stdout
from io import StringIO
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
import tempfile
import unittest

from lsa.cli import main as cli_main
from lsa.services.analytics_service import AnalyticsService, ControlPlaneAlertThresholds
from lsa.services.control_plane_alert_service import ControlPlaneAlertService
from lsa.settings import resolve_workspace_settings
from lsa.storage.models import JobLeaseEventRecord, JobRecord, WorkerHeartbeatRecord, WorkerRecord


class CliFlowTests(unittest.TestCase):
    def test_ingest_and_audit_create_reports(self) -> None:
        root = Path("tests/fixtures/sample_service").resolve()
        events = Path("tests/fixtures/sample_events.json").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.snapshot_repository = cli_main.SnapshotRepository(cli_main.settings, graph=cli_main.graph)
            cli_main.audit_repository = cli_main.AuditRepository(cli_main.settings)
            cli_main.ingest_service = cli_main.IngestService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
            )
            cli_main.audit_service = cli_main.AuditService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
                audit_repository=cli_main.audit_repository,
                drift_comparator=cli_main.DriftComparator(),
                remediation_client=cli_main.RuleBasedLLMClient(),
                settings=cli_main.settings,
            )
            cli_main.analytics_service = AnalyticsService(
                job_repository=cli_main.job_repository,
                heartbeat_timeout_seconds=cli_main.settings.worker_heartbeat_timeout_seconds,
                default_thresholds=ControlPlaneAlertThresholds(
                    queue_warning_threshold=cli_main.settings.analytics_queue_warning_threshold,
                    queue_critical_threshold=cli_main.settings.analytics_queue_critical_threshold,
                    stale_worker_warning_threshold=cli_main.settings.analytics_stale_worker_warning_threshold,
                    stale_worker_critical_threshold=cli_main.settings.analytics_stale_worker_critical_threshold,
                    expired_lease_warning_threshold=cli_main.settings.analytics_expired_lease_warning_threshold,
                    expired_lease_critical_threshold=cli_main.settings.analytics_expired_lease_critical_threshold,
                    job_failure_rate_warning_threshold=cli_main.settings.analytics_job_failure_rate_warning_threshold,
                    job_failure_rate_critical_threshold=cli_main.settings.analytics_job_failure_rate_critical_threshold,
                    job_failure_rate_min_samples=cli_main.settings.analytics_job_failure_rate_min_samples,
                ),
            )
            cli_main.control_plane_alert_service = ControlPlaneAlertService(
                job_repository=cli_main.job_repository,
                analytics_service=cli_main.analytics_service,
                window_days=cli_main.settings.control_plane_alert_window_days,
                dedup_window_seconds=cli_main.settings.control_plane_alert_dedup_window_seconds,
                sink_path=str(cli_main.settings.control_plane_alert_sink_path),
                webhook_url=cli_main.settings.control_plane_alert_webhook_url,
            )
            snapshot_path = Path(tmpdir) / "snapshot.json"
            report_dir = Path(tmpdir) / "reports"

            ingest_sink = StringIO()
            with redirect_stdout(ingest_sink):
                self.assertEqual(
                    cli_main.run_ingest(
                        str(root),
                        str(snapshot_path),
                        persist=False,
                        snapshot_id=None,
                    ),
                    0,
                )
            self.assertTrue(snapshot_path.exists(), ingest_sink.getvalue())

            audit_sink = StringIO()
            with redirect_stdout(audit_sink):
                self.assertEqual(
                    cli_main.run_audit(
                        str(snapshot_path),
                        str(events),
                        snapshot_is_id=False,
                        out_dir=str(report_dir),
                        persist=False,
                        audit_id=None,
                    ),
                    0,
                )
            reports = list(report_dir.glob("*.md"))
            self.assertEqual(len(reports), 1)
            payload = json.loads(audit_sink.getvalue())
            self.assertIn("explanation", payload)
            self.assertEqual(payload["explanation"]["status"], "drift_detected")

    def test_standalone_worker_processes_queued_job(self) -> None:
        fixture_root = Path("tests/fixtures/sample_service").resolve()
        trace_path = Path("tests/fixtures/sample_trace.log").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.snapshot_repository = cli_main.SnapshotRepository(cli_main.settings, graph=cli_main.graph)
            cli_main.audit_repository = cli_main.AuditRepository(cli_main.settings)
            cli_main.job_repository = cli_main.JobRepository(cli_main.settings)
            cli_main.ingest_service = cli_main.IngestService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
            )
            cli_main.audit_service = cli_main.AuditService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
                audit_repository=cli_main.audit_repository,
                drift_comparator=cli_main.DriftComparator(),
                remediation_client=cli_main.RuleBasedLLMClient(),
                settings=cli_main.settings,
            )
            cli_main.trace_collection_service = cli_main.TraceCollectionService(settings=cli_main.settings)
            cli_main.analytics_service = AnalyticsService(
                job_repository=cli_main.job_repository,
                heartbeat_timeout_seconds=cli_main.settings.worker_heartbeat_timeout_seconds,
                default_thresholds=ControlPlaneAlertThresholds(
                    queue_warning_threshold=cli_main.settings.analytics_queue_warning_threshold,
                    queue_critical_threshold=cli_main.settings.analytics_queue_critical_threshold,
                    stale_worker_warning_threshold=cli_main.settings.analytics_stale_worker_warning_threshold,
                    stale_worker_critical_threshold=cli_main.settings.analytics_stale_worker_critical_threshold,
                    expired_lease_warning_threshold=cli_main.settings.analytics_expired_lease_warning_threshold,
                    expired_lease_critical_threshold=cli_main.settings.analytics_expired_lease_critical_threshold,
                    job_failure_rate_warning_threshold=cli_main.settings.analytics_job_failure_rate_warning_threshold,
                    job_failure_rate_critical_threshold=cli_main.settings.analytics_job_failure_rate_critical_threshold,
                    job_failure_rate_min_samples=cli_main.settings.analytics_job_failure_rate_min_samples,
                ),
            )
            cli_main.control_plane_alert_service = ControlPlaneAlertService(
                job_repository=cli_main.job_repository,
                analytics_service=cli_main.analytics_service,
                window_days=cli_main.settings.control_plane_alert_window_days,
                dedup_window_seconds=cli_main.settings.control_plane_alert_dedup_window_seconds,
                sink_path=str(cli_main.settings.control_plane_alert_sink_path),
                webhook_url=cli_main.settings.control_plane_alert_webhook_url,
            )
            cli_main.job_service = cli_main.JobService(
                job_repository=cli_main.job_repository,
                audit_service=cli_main.audit_service,
                trace_collection_service=cli_main.trace_collection_service,
                worker_mode="standalone",
                poll_interval_seconds=0.01,
                heartbeat_timeout_seconds=cli_main.settings.worker_heartbeat_timeout_seconds,
                worker_history_retention_days=cli_main.settings.worker_history_retention_days,
                job_lease_history_retention_days=cli_main.settings.job_lease_history_retention_days,
                history_prune_interval_seconds=cli_main.settings.history_prune_interval_seconds,
                control_plane_alert_service=cli_main.control_plane_alert_service,
                control_plane_alert_interval_seconds=cli_main.settings.control_plane_alert_interval_seconds,
                control_plane_alerts_enabled=cli_main.settings.control_plane_alerts_enabled,
            )

            cli_main.ingest_service.ingest(str(fixture_root), persist=True, snapshot_id="snap-worker")
            cli_main.job_repository.create(
                job_type="audit-trace",
                request_payload={
                    "snapshot_id": "snap-worker",
                    "trace_path": str(trace_path),
                    "trace_format": "auto",
                    "persist": True,
                    "audit_id": "audit-worker",
                },
                job_id="job-worker",
            )

            worker_sink = StringIO()
            with redirect_stdout(worker_sink):
                self.assertEqual(
                    cli_main.run_worker(
                        poll_interval=0.01,
                        idle_timeout=0.2,
                        max_jobs=None,
                        once=False,
                    ),
                    0,
                )

            payload = json.loads(worker_sink.getvalue())
            self.assertEqual(payload["worker_mode"], "standalone")
            self.assertIsNotNone(payload["worker_id"])
            self.assertEqual(payload["processed_jobs"], 1)
            self.assertEqual(payload["active_workers"], 0)
            self.assertEqual(payload["queued_jobs"], 0)
            self.assertEqual(payload["completed_jobs"], 1)
            self.assertEqual(cli_main.job_repository.get("job-worker").status, "completed")
            self.assertIsNotNone(cli_main.job_repository.get("job-worker").claimed_by_worker_id)
            self.assertEqual(cli_main.audit_repository.get("audit-worker").audit_id, "audit-worker")
            worker_records = cli_main.job_repository.list_workers()
            self.assertEqual(len(worker_records), 1)
            self.assertEqual(worker_records[0].mode, "standalone")
            self.assertEqual(worker_records[0].status, "stopped")
            self.assertGreaterEqual(len(cli_main.job_repository.list_worker_heartbeats(worker_records[0].worker_id)), 1)
            self.assertGreaterEqual(len(cli_main.job_repository.list_job_lease_events("job-worker")), 1)

    def test_prune_history_removes_old_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.settings.worker_history_retention_days = 1
            cli_main.settings.job_lease_history_retention_days = 1
            cli_main.job_repository = cli_main.JobRepository(cli_main.settings)
            cli_main.analytics_service = AnalyticsService(
                job_repository=cli_main.job_repository,
                heartbeat_timeout_seconds=cli_main.settings.worker_heartbeat_timeout_seconds,
                default_thresholds=ControlPlaneAlertThresholds(
                    queue_warning_threshold=cli_main.settings.analytics_queue_warning_threshold,
                    queue_critical_threshold=cli_main.settings.analytics_queue_critical_threshold,
                    stale_worker_warning_threshold=cli_main.settings.analytics_stale_worker_warning_threshold,
                    stale_worker_critical_threshold=cli_main.settings.analytics_stale_worker_critical_threshold,
                    expired_lease_warning_threshold=cli_main.settings.analytics_expired_lease_warning_threshold,
                    expired_lease_critical_threshold=cli_main.settings.analytics_expired_lease_critical_threshold,
                    job_failure_rate_warning_threshold=cli_main.settings.analytics_job_failure_rate_warning_threshold,
                    job_failure_rate_critical_threshold=cli_main.settings.analytics_job_failure_rate_critical_threshold,
                    job_failure_rate_min_samples=cli_main.settings.analytics_job_failure_rate_min_samples,
                ),
            )
            cli_main.control_plane_alert_service = ControlPlaneAlertService(
                job_repository=cli_main.job_repository,
                analytics_service=cli_main.analytics_service,
                window_days=cli_main.settings.control_plane_alert_window_days,
                dedup_window_seconds=cli_main.settings.control_plane_alert_dedup_window_seconds,
                sink_path=str(cli_main.settings.control_plane_alert_sink_path),
                webhook_url=cli_main.settings.control_plane_alert_webhook_url,
            )
            cli_main.job_service = cli_main.JobService(
                job_repository=cli_main.job_repository,
                audit_service=cli_main.audit_service,
                trace_collection_service=cli_main.trace_collection_service,
                worker_mode="standalone",
                heartbeat_timeout_seconds=cli_main.settings.worker_heartbeat_timeout_seconds,
                worker_history_retention_days=cli_main.settings.worker_history_retention_days,
                job_lease_history_retention_days=cli_main.settings.job_lease_history_retention_days,
                history_prune_interval_seconds=cli_main.settings.history_prune_interval_seconds,
                control_plane_alert_service=cli_main.control_plane_alert_service,
                control_plane_alert_interval_seconds=cli_main.settings.control_plane_alert_interval_seconds,
                control_plane_alerts_enabled=cli_main.settings.control_plane_alerts_enabled,
            )
            cli_main.job_repository.append_worker_heartbeat(
                WorkerHeartbeatRecord(
                    heartbeat_id="heartbeat-old",
                    worker_id="worker-test",
                    recorded_at="2020-01-01T00:00:00+00:00",
                    status="running",
                    current_job_id=None,
                )
            )
            cli_main.job_repository.append_job_lease_event(
                JobLeaseEventRecord(
                    event_id="lease-event-old",
                    job_id="job-test",
                    worker_id="worker-test",
                    event_type="lease_claimed",
                    recorded_at="2020-01-01T00:00:00+00:00",
                    details={},
                )
            )

            prune_sink = StringIO()
            with redirect_stdout(prune_sink):
                self.assertEqual(cli_main.run_prune_history(), 0)
            payload = json.loads(prune_sink.getvalue())
            self.assertEqual(payload["worker_heartbeats_compacted"], 1)
            self.assertEqual(payload["job_lease_events_compacted"], 1)
            self.assertEqual(payload["worker_heartbeats_pruned"], 1)
            self.assertEqual(payload["job_lease_events_pruned"], 1)
            self.assertEqual(len(cli_main.job_repository.list_worker_heartbeat_rollups("worker-test")), 1)
            self.assertEqual(len(cli_main.job_repository.list_job_lease_event_rollups("job-test")), 1)

    def test_control_plane_analytics_reports_queue_and_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.job_repository = cli_main.JobRepository(cli_main.settings)
            cli_main.analytics_service = AnalyticsService(
                job_repository=cli_main.job_repository,
                heartbeat_timeout_seconds=60,
                default_thresholds=ControlPlaneAlertThresholds(
                    queue_warning_threshold=1,
                    queue_critical_threshold=5,
                    stale_worker_warning_threshold=1,
                    stale_worker_critical_threshold=3,
                    expired_lease_warning_threshold=1,
                    expired_lease_critical_threshold=2,
                    job_failure_rate_warning_threshold=0.2,
                    job_failure_rate_critical_threshold=0.5,
                    job_failure_rate_min_samples=1,
                ),
            )
            cli_main.control_plane_alert_service = ControlPlaneAlertService(
                job_repository=cli_main.job_repository,
                analytics_service=cli_main.analytics_service,
                window_days=cli_main.settings.control_plane_alert_window_days,
                dedup_window_seconds=cli_main.settings.control_plane_alert_dedup_window_seconds,
                sink_path=str(cli_main.settings.control_plane_alert_sink_path),
                webhook_url=cli_main.settings.control_plane_alert_webhook_url,
            )

            now = datetime.now(UTC)
            today = now.date()
            old_day = today - timedelta(days=2)
            old_timestamp = datetime(old_day.year, old_day.month, old_day.day, 12, 0, tzinfo=UTC).isoformat()
            current_timestamp = (now - timedelta(seconds=5)).isoformat()
            cutoff_timestamp = datetime(
                (today - timedelta(days=1)).year,
                (today - timedelta(days=1)).month,
                (today - timedelta(days=1)).day,
                0,
                0,
                tzinfo=UTC,
            ).isoformat()

            cli_main.job_repository.save_worker(
                WorkerRecord(
                    worker_id="worker-cli",
                    mode="standalone",
                    status="running",
                    started_at=current_timestamp,
                    last_heartbeat_at=current_timestamp,
                    host_name="host-cli",
                    process_id=303,
                    current_job_id="job-cli-running",
                )
            )
            cli_main.job_repository.append_worker_heartbeat(
                WorkerHeartbeatRecord(
                    heartbeat_id="heartbeat-cli-old",
                    worker_id="worker-cli",
                    recorded_at=old_timestamp,
                    status="running",
                    current_job_id="job-cli-old",
                )
            )
            cli_main.job_repository.append_job_lease_event(
                JobLeaseEventRecord(
                    event_id="lease-cli-old",
                    job_id="job-cli-old",
                    worker_id="worker-cli",
                    event_type="lease_claimed",
                    recorded_at=old_timestamp,
                    details={},
                )
            )
            cli_main.job_repository.compact_worker_heartbeats_before(cutoff_timestamp)
            cli_main.job_repository.compact_job_lease_events_before(cutoff_timestamp)

            cli_main.job_repository.save(
                JobRecord(
                    job_id="job-cli-running",
                    created_at=current_timestamp,
                    job_type="audit-trace",
                    status="running",
                    started_at=current_timestamp,
                    claimed_by_worker_id="worker-cli",
                    lease_expires_at=(now + timedelta(minutes=5)).isoformat(),
                )
            )

            analytics_sink = StringIO()
            with redirect_stdout(analytics_sink):
                self.assertEqual(cli_main.run_control_plane_analytics(days=7), 0)
            payload = json.loads(analytics_sink.getvalue())
            self.assertEqual(payload["window_days"], 7)
            self.assertEqual(payload["queue"]["running_jobs"], 1)
            self.assertEqual(payload["workers"]["active_workers"], 1)
            self.assertGreaterEqual(payload["leases"]["claimed_count"], 1)
            self.assertEqual(len(payload["workers"]["days"]), 7)
            self.assertEqual(payload["evaluation"]["status"], "healthy")
            self.assertEqual(payload["evaluation"]["findings"], [])

    def test_emit_control_plane_alerts_persists_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.job_repository = cli_main.JobRepository(cli_main.settings)
            cli_main.analytics_service = AnalyticsService(
                job_repository=cli_main.job_repository,
                heartbeat_timeout_seconds=5,
                default_thresholds=ControlPlaneAlertThresholds(
                    queue_warning_threshold=1,
                    queue_critical_threshold=2,
                    stale_worker_warning_threshold=1,
                    stale_worker_critical_threshold=2,
                    expired_lease_warning_threshold=1,
                    expired_lease_critical_threshold=2,
                    job_failure_rate_warning_threshold=0.2,
                    job_failure_rate_critical_threshold=0.5,
                    job_failure_rate_min_samples=1,
                ),
            )
            cli_main.control_plane_alert_service = ControlPlaneAlertService(
                job_repository=cli_main.job_repository,
                analytics_service=cli_main.analytics_service,
                window_days=7,
                dedup_window_seconds=3600,
                sink_path=str(cli_main.settings.control_plane_alert_sink_path),
                webhook_url=cli_main.settings.control_plane_alert_webhook_url,
            )
            cli_main.job_service = cli_main.JobService(
                job_repository=cli_main.job_repository,
                audit_service=cli_main.audit_service,
                trace_collection_service=cli_main.trace_collection_service,
                worker_mode="standalone",
                control_plane_alert_service=cli_main.control_plane_alert_service,
                control_plane_alerts_enabled=True,
            )

            now = datetime.now(UTC).isoformat()
            cli_main.job_repository.save_worker(
                WorkerRecord(
                    worker_id="worker-alert",
                    mode="standalone",
                    status="stopped",
                    started_at=now,
                    last_heartbeat_at=(datetime.now(UTC) - timedelta(minutes=10)).isoformat(),
                    host_name="host-alert",
                    process_id=404,
                    current_job_id=None,
                )
            )
            cli_main.job_repository.save(
                JobRecord(
                    job_id="job-alert",
                    created_at=now,
                    job_type="audit-trace",
                    status="queued",
                )
            )

            alert_sink = StringIO()
            with redirect_stdout(alert_sink):
                self.assertEqual(cli_main.run_emit_control_plane_alerts(force=True), 0)
            payload = json.loads(alert_sink.getvalue())
            self.assertEqual(payload["emitted_count"], 1)
            self.assertEqual(len(cli_main.job_repository.list_control_plane_alerts()), 1)
            alert_id = payload["alerts"][0]["alert_id"]

            followup_sink = StringIO()
            with redirect_stdout(followup_sink):
                self.assertEqual(cli_main.run_process_control_plane_alert_followups(force=True), 0)
            followups = json.loads(followup_sink.getvalue())
            self.assertGreaterEqual(followups["emitted_count"], 1)

            ack_sink = StringIO()
            with redirect_stdout(ack_sink):
                self.assertEqual(
                    cli_main.run_acknowledge_control_plane_alert(
                        alert_id=alert_id,
                        acknowledged_by="operator-cli",
                        acknowledgement_note="Investigating",
                    ),
                    0,
                )
            acknowledged = json.loads(ack_sink.getvalue())
            self.assertEqual(acknowledged["acknowledged_by"], "operator-cli")

            silence_sink = StringIO()
            with redirect_stdout(silence_sink):
                self.assertEqual(
                    cli_main.run_create_control_plane_alert_silence(
                        created_by="operator-cli",
                        reason="maintenance",
                        duration_minutes=15,
                        match_alert_key=None,
                        match_finding_code="queue_without_active_workers",
                    ),
                    0,
                )
            silence = json.loads(silence_sink.getvalue())
            self.assertEqual(silence["created_by"], "operator-cli")

            silences_sink = StringIO()
            with redirect_stdout(silences_sink):
                self.assertEqual(cli_main.run_list_control_plane_alert_silences(active_only=True), 0)
            silences = json.loads(silences_sink.getvalue())
            self.assertGreaterEqual(len(silences), 1)

            cancel_sink = StringIO()
            with redirect_stdout(cancel_sink):
                self.assertEqual(
                    cli_main.run_cancel_control_plane_alert_silence(
                        silence_id=silence["silence_id"],
                        cancelled_by="operator-cli",
                    ),
                    0,
                )
            cancelled = json.loads(cancel_sink.getvalue())
            self.assertEqual(cancelled["cancelled_by"], "operator-cli")

            schedule_sink = StringIO()
            with redirect_stdout(schedule_sink):
                self.assertEqual(
                    cli_main.run_create_control_plane_oncall_schedule(
                        created_by="operator-cli",
                        team_name="platform-cli",
                        timezone_name="UTC",
                        weekdays=[0, 1, 2, 3, 4, 5, 6],
                        start_time="00:00",
                        end_time="23:59",
                        webhook_url=None,
                        escalation_webhook_url=None,
                    ),
                    0,
                )
            schedule = json.loads(schedule_sink.getvalue())
            self.assertEqual(schedule["team_name"], "platform-cli")

            schedules_sink = StringIO()
            with redirect_stdout(schedules_sink):
                self.assertEqual(cli_main.run_list_control_plane_oncall_schedules(active_only=True), 0)
            schedules = json.loads(schedules_sink.getvalue())
            self.assertGreaterEqual(len(schedules), 1)

            cancel_schedule_sink = StringIO()
            with redirect_stdout(cancel_schedule_sink):
                self.assertEqual(
                    cli_main.run_cancel_control_plane_oncall_schedule(
                        schedule_id=schedule["schedule_id"],
                        cancelled_by="operator-cli",
                    ),
                    0,
                )
            cancelled_schedule = json.loads(cancel_schedule_sink.getvalue())
            self.assertEqual(cancelled_schedule["cancelled_by"], "operator-cli")

            list_sink = StringIO()
            with redirect_stdout(list_sink):
                self.assertEqual(cli_main.run_list_control_plane_alerts(limit=10), 0)
            listed = json.loads(list_sink.getvalue())
            self.assertEqual(len(listed), 2)


if __name__ == "__main__":
    unittest.main()
