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
from lsa.services.control_plane_runtime_validation_review_service import (
    ControlPlaneRuntimeValidationReviewService,
)
from lsa.services.metrics_service import ControlPlaneMetricsService
from lsa.settings import resolve_workspace_settings
from lsa.storage.models import JobLeaseEventRecord, JobRecord, WorkerHeartbeatRecord, WorkerRecord
from lsa.storage.models import ControlPlaneMaintenanceEventRecord


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
            cli_main.control_plane_backup_service = cli_main.ControlPlaneBackupService(
                settings=cli_main.settings,
                snapshot_repository=cli_main.snapshot_repository,
                audit_repository=cli_main.audit_repository,
                job_repository=cli_main.job_repository,
            )
            cli_main.metrics_service = ControlPlaneMetricsService(
                job_repository=cli_main.job_repository,
                job_service=cli_main.job_service,
                analytics_service=cli_main.analytics_service,
                environment_name=cli_main.settings.environment_name,
                worker_mode="standalone",
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

    def test_export_and_import_control_plane_backup(self) -> None:
        fixture_root = Path("tests/fixtures/sample_service").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.snapshot_repository = cli_main.SnapshotRepository(cli_main.settings, graph=cli_main.graph)
            cli_main.audit_repository = cli_main.AuditRepository(cli_main.settings)
            cli_main.job_repository = cli_main.JobRepository(cli_main.settings)
            cli_main.ingest_service = cli_main.IngestService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
            )
            cli_main.control_plane_backup_service = cli_main.ControlPlaneBackupService(
                settings=cli_main.settings,
                snapshot_repository=cli_main.snapshot_repository,
                audit_repository=cli_main.audit_repository,
                job_repository=cli_main.job_repository,
            )

            cli_main.ingest_service.ingest(str(fixture_root), persist=True, snapshot_id="snap-backup-cli")
            backup_path = Path(tmpdir) / "control-plane-backup.json"

            export_sink = StringIO()
            with redirect_stdout(export_sink):
                self.assertEqual(
                    cli_main.run_export_control_plane_backup(output_path=str(backup_path)),
                    0,
                )
            self.assertTrue(backup_path.exists())
            export_payload = json.loads(export_sink.getvalue())
            self.assertEqual(export_payload["counts"]["snapshots"], 1)
            self.assertEqual(export_payload["artifact_counts"]["snapshots"], 1)

            cli_main.job_repository.reset_control_plane()
            import_sink = StringIO()
            with redirect_stdout(import_sink):
                self.assertEqual(
                    cli_main.run_import_control_plane_backup(
                        input_path=str(backup_path),
                        replace_existing=False,
                    ),
                    0,
                )
            import_payload = json.loads(import_sink.getvalue())
            self.assertFalse(import_payload["replace_existing"])
            self.assertEqual(len(cli_main.snapshot_repository.list()), 1)

    def test_control_plane_schema_reports_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.job_repository = cli_main.JobRepository(cli_main.settings)

            sink = StringIO()
            with redirect_stdout(sink):
                self.assertEqual(cli_main.run_control_plane_schema(), 0)
            payload = json.loads(sink.getvalue())
            self.assertEqual(payload["schema_version"], 1)
            self.assertEqual(payload["expected_schema_version"], 1)
            self.assertTrue(payload["schema_ready"])
            self.assertEqual(payload["pending_migration_count"], 0)
            self.assertEqual(len(payload["migrations"]), 1)

            contract_sink = StringIO()
            with redirect_stdout(contract_sink):
                self.assertEqual(cli_main.run_control_plane_schema_contract(), 0)
            contract_payload = json.loads(contract_sink.getvalue())
            self.assertEqual(contract_payload["schema_version"], 1)
            self.assertIn("sqlite", contract_payload["runtime_supported_backends"])
            self.assertIn("postgres", contract_payload["bootstrap_supported_backends"])
            self.assertIn("control_plane_oncall_change_requests", contract_payload["table_names"])

            runtime_backend_sink = StringIO()
            with redirect_stdout(runtime_backend_sink):
                self.assertEqual(cli_main.run_control_plane_runtime_backend(), 0)
            runtime_backend_payload = json.loads(runtime_backend_sink.getvalue())
            self.assertEqual(runtime_backend_payload["backend"], "sqlite")
            self.assertTrue(runtime_backend_payload["runtime_available"])

            runtime_smoke_sink = StringIO()
            cli_main.snapshot_repository = cli_main.SnapshotRepository(cli_main.settings, graph=cli_main.graph)
            cli_main.audit_repository = cli_main.AuditRepository(cli_main.settings)
            cli_main.job_repository = cli_main.JobRepository(cli_main.settings)
            cli_main.audit_service = cli_main.AuditService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
                audit_repository=cli_main.audit_repository,
                drift_comparator=cli_main.DriftComparator(),
                remediation_client=cli_main.RuleBasedLLMClient(),
                settings=cli_main.settings,
            )
            cli_main.trace_collection_service = cli_main.TraceCollectionService(settings=cli_main.settings)
            cli_main.job_service = cli_main.JobService(
                job_repository=cli_main.job_repository,
                audit_service=cli_main.audit_service,
                trace_collection_service=cli_main.trace_collection_service,
                worker_mode="standalone",
                heartbeat_timeout_seconds=cli_main.settings.worker_heartbeat_timeout_seconds,
                worker_history_retention_days=cli_main.settings.worker_history_retention_days,
                job_lease_history_retention_days=cli_main.settings.job_lease_history_retention_days,
                history_prune_interval_seconds=cli_main.settings.history_prune_interval_seconds,
                control_plane_alert_service=None,
                control_plane_alerts_enabled=False,
            )
            with redirect_stdout(runtime_smoke_sink):
                self.assertEqual(
                    cli_main.run_control_plane_runtime_smoke(
                        changed_by="operator-a",
                        reason="cli smoke",
                        cleanup=True,
                    ),
                    0,
                )
            runtime_smoke_payload = json.loads(runtime_smoke_sink.getvalue())
            self.assertEqual(runtime_smoke_payload["repository_layout"], "shared")
            self.assertTrue(runtime_smoke_payload["cleanup_completed"])
            self.assertEqual(cli_main.snapshot_repository.list(), [])
            self.assertEqual(cli_main.audit_repository.list(), [])
            self.assertEqual(cli_main.job_repository.list(), [])

            runtime_rehearsal_sink = StringIO()
            with redirect_stdout(runtime_rehearsal_sink):
                self.assertEqual(
                    cli_main.run_control_plane_runtime_rehearsal(
                        changed_by="operator-a",
                        expected_backend="sqlite",
                        expected_repository_layout="shared",
                        reason="cli rehearsal",
                        cleanup=True,
                    ),
                    0,
                )
            runtime_rehearsal_payload = json.loads(runtime_rehearsal_sink.getvalue())
            self.assertEqual(runtime_rehearsal_payload["status"], "passed")
            self.assertEqual(runtime_rehearsal_payload["database_backend"], "sqlite")
            self.assertFalse(runtime_rehearsal_payload["snapshots_audits_repository_runtime_active"])
            self.assertFalse(runtime_rehearsal_payload["job_repository_runtime_active"])
            self.assertTrue(all(runtime_rehearsal_payload["checks"].values()))
            self.assertTrue(runtime_rehearsal_payload["smoke"]["cleanup_completed"])

            runtime_validation_sink = StringIO()
            with redirect_stdout(runtime_validation_sink):
                self.assertEqual(cli_main.run_control_plane_runtime_validation(), 0)
            runtime_validation_payload = json.loads(runtime_validation_sink.getvalue())
            self.assertEqual(runtime_validation_payload["status"], "passed")
            self.assertEqual(runtime_validation_payload["latest_rehearsal_status"], "passed")
            self.assertEqual(runtime_validation_payload["latest_expected_backend"], "sqlite")

            inspect_runtime_backend_sink = StringIO()
            with redirect_stdout(inspect_runtime_backend_sink):
                self.assertEqual(
                    cli_main.run_inspect_control_plane_runtime_backend(
                        database_url="postgresql://lsa:secret@db.example.com:5432/lsa_prod"
                    ),
                    0,
                )
            inspect_runtime_backend_payload = json.loads(inspect_runtime_backend_sink.getvalue())
            self.assertEqual(inspect_runtime_backend_payload["backend"], "postgres")
            self.assertFalse(inspect_runtime_backend_payload["runtime_available"])
            self.assertIn("unsupported_runtime_backend:postgres", inspect_runtime_backend_payload["runtime_blockers"])

            with cli_main.job_repository.database._connect() as connection:
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

            migrate_sink = StringIO()
            with redirect_stdout(migrate_sink):
                self.assertEqual(cli_main.run_migrate_control_plane_schema(), 0)
            migrated_payload = json.loads(migrate_sink.getvalue())
            self.assertEqual(migrated_payload["schema_version"], 1)
            self.assertTrue(migrated_payload["schema_ready"])
            self.assertEqual(migrated_payload["pending_migration_count"], 0)
            self.assertEqual(len(migrated_payload["migrations"]), 1)

    def test_control_plane_metrics_renders_prometheus_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
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
            cli_main.job_service = cli_main.JobService(
                job_repository=cli_main.job_repository,
                audit_service=cli_main.audit_service,
                trace_collection_service=cli_main.trace_collection_service,
                worker_mode="standalone",
                heartbeat_timeout_seconds=cli_main.settings.worker_heartbeat_timeout_seconds,
            )
            cli_main.metrics_service = ControlPlaneMetricsService(
                job_repository=cli_main.job_repository,
                job_service=cli_main.job_service,
                analytics_service=cli_main.analytics_service,
                environment_name=cli_main.settings.environment_name,
                worker_mode="standalone",
            )

            sink = StringIO()
            with redirect_stdout(sink):
                self.assertEqual(cli_main.run_control_plane_metrics(days=1), 0)
            payload = sink.getvalue()
            self.assertIn('lsa_control_plane_info{database_backend="sqlite",environment="default",worker_mode="standalone"} 1', payload)
            self.assertIn("lsa_control_plane_database_schema_ready 1", payload)
            self.assertIn("lsa_control_plane_maintenance_mode_active 0", payload)

    def test_control_plane_maintenance_mode_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.job_repository = cli_main.JobRepository(cli_main.settings)
            cli_main.job_service = cli_main.JobService(
                job_repository=cli_main.job_repository,
                audit_service=cli_main.audit_service,
                trace_collection_service=cli_main.trace_collection_service,
                worker_mode="standalone",
                heartbeat_timeout_seconds=cli_main.settings.worker_heartbeat_timeout_seconds,
            )
            cli_main.control_plane_backup_service = cli_main.ControlPlaneBackupService(
                settings=cli_main.settings,
                snapshot_repository=cli_main.snapshot_repository,
                audit_repository=cli_main.audit_repository,
                job_repository=cli_main.job_repository,
            )
            cli_main.control_plane_maintenance_service = cli_main.ControlPlaneMaintenanceService(
                settings=cli_main.settings,
                job_repository=cli_main.job_repository,
                job_service=cli_main.job_service,
                backup_service=cli_main.control_plane_backup_service,
                worker_mode="standalone",
            )
            cli_main.control_plane_cutover_service = cli_main.ControlPlaneCutoverService(
                settings=cli_main.settings,
                maintenance_service=cli_main.control_plane_maintenance_service,
            )

            status_sink = StringIO()
            with redirect_stdout(status_sink):
                self.assertEqual(cli_main.run_control_plane_maintenance_mode(), 0)
            self.assertFalse(json.loads(status_sink.getvalue())["active"])

            enable_sink = StringIO()
            with redirect_stdout(enable_sink):
                self.assertEqual(
                    cli_main.run_enable_control_plane_maintenance_mode(
                        changed_by="operator-a",
                        reason="backup",
                    ),
                    0,
                )
            self.assertTrue(json.loads(enable_sink.getvalue())["active"])

            disable_sink = StringIO()
            with redirect_stdout(disable_sink):
                self.assertEqual(
                    cli_main.run_disable_control_plane_maintenance_mode(
                        changed_by="operator-a",
                        reason="done",
                    ),
                    0,
                )
            self.assertFalse(json.loads(disable_sink.getvalue())["active"])

    def test_control_plane_preflight_and_runbook_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.snapshot_repository = cli_main.SnapshotRepository(cli_main.settings, graph=cli_main.graph)
            cli_main.audit_repository = cli_main.AuditRepository(cli_main.settings)
            cli_main.job_repository = cli_main.JobRepository(cli_main.settings)
            cli_main.control_plane_backup_service = cli_main.ControlPlaneBackupService(
                settings=cli_main.settings,
                snapshot_repository=cli_main.snapshot_repository,
                audit_repository=cli_main.audit_repository,
                job_repository=cli_main.job_repository,
            )
            cli_main.job_service = cli_main.JobService(
                job_repository=cli_main.job_repository,
                audit_service=cli_main.audit_service,
                trace_collection_service=cli_main.trace_collection_service,
                worker_mode="standalone",
                heartbeat_timeout_seconds=cli_main.settings.worker_heartbeat_timeout_seconds,
            )
            cli_main.control_plane_maintenance_service = cli_main.ControlPlaneMaintenanceService(
                settings=cli_main.settings,
                job_repository=cli_main.job_repository,
                job_service=cli_main.job_service,
                backup_service=cli_main.control_plane_backup_service,
                worker_mode="standalone",
            )
            cli_main.control_plane_cutover_service = cli_main.ControlPlaneCutoverService(
                settings=cli_main.settings,
                maintenance_service=cli_main.control_plane_maintenance_service,
            )

            preflight_sink = StringIO()
            with redirect_stdout(preflight_sink):
                self.assertEqual(cli_main.run_control_plane_preflight(), 0)
            self.assertTrue(json.loads(preflight_sink.getvalue())["can_execute"])

            cutover_preflight_sink = StringIO()
            with redirect_stdout(cutover_preflight_sink):
                self.assertEqual(
                    cli_main.run_control_plane_cutover_preflight(
                        target_database_url="postgresql://lsa:secret@db.example.com:5432/lsa_prod"
                    ),
                    0,
                )
            self.assertEqual(json.loads(cutover_preflight_sink.getvalue())["target"]["backend"], "postgres")

            with cli_main.job_repository.database._connect() as connection:
                connection.execute(
                    """
                    UPDATE control_plane_schema_metadata
                    SET metadata_value = '0'
                    WHERE metadata_key = 'schema_version'
                    """
                )

            runbook_path = Path(tmpdir) / "data" / "backups" / "cli-runbook.json"
            runbook_sink = StringIO()
            with redirect_stdout(runbook_sink):
                self.assertEqual(
                    cli_main.run_control_plane_maintenance_workflow(
                        output_path=str(runbook_path),
                        changed_by="operator-a",
                        reason="cli runbook",
                        allow_running_jobs=False,
                        keep_maintenance_enabled=False,
                    ),
                    0,
                )
            runbook_payload = json.loads(runbook_sink.getvalue())
            self.assertTrue(runbook_payload["schema_status"]["schema_ready"])
            self.assertFalse(runbook_payload["maintenance_final"]["active"])
            self.assertTrue(runbook_path.exists())

            runtime_rehearsal_sink = StringIO()
            with redirect_stdout(runtime_rehearsal_sink):
                self.assertEqual(
                    cli_main.run_control_plane_runtime_rehearsal(
                        changed_by="operator-a",
                        expected_backend="sqlite",
                        expected_repository_layout="shared",
                        reason="cli runtime proof",
                        cleanup=True,
                    ),
                    0,
                )
            self.assertEqual(json.loads(runtime_rehearsal_sink.getvalue())["status"], "passed")

            cutover_bundle_path = Path(tmpdir) / "data" / "backups" / "cutover-bundle.json"
            cutover_bundle_sink = StringIO()
            with redirect_stdout(cutover_bundle_sink):
                self.assertEqual(
                    cli_main.run_prepare_control_plane_cutover_bundle(
                        output_path=str(cutover_bundle_path),
                        target_database_url="postgres://lsa:secret@db.example.com/lsa_prod",
                        changed_by="operator-a",
                        reason="cli cutover",
                        allow_running_jobs=False,
                        keep_maintenance_enabled=False,
                    ),
                    0,
                )
            cutover_bundle_payload = json.loads(cutover_bundle_sink.getvalue())
            self.assertEqual(cutover_bundle_payload["target"]["backend"], "postgres")
            self.assertIsNotNone(cutover_bundle_payload["postgres_bootstrap_package"])
            self.assertTrue(cutover_bundle_path.exists())

            inspect_sink = StringIO()
            with redirect_stdout(inspect_sink):
                self.assertEqual(
                    cli_main.run_inspect_postgres_bootstrap_package(
                        package_dir=cutover_bundle_payload["postgres_bootstrap_package"]["output_dir"]
                    ),
                    0,
                )
            self.assertTrue(json.loads(inspect_sink.getvalue())["valid"])

            bootstrap_manifest = json.loads(
                Path(cutover_bundle_payload["postgres_bootstrap_package"]["manifest_path"]).read_text(
                    encoding="utf-8"
                )
            )
            payload_path = Path(tmpdir) / "pg-payload.json"
            payload_path.write_text(
                json.dumps(
                    {
                        "schema_version": str(bootstrap_manifest["schema_status"]["schema_version"]),
                        "maintenance_mode_active": "0",
                        "table_presence": {
                            name: True for name in bootstrap_manifest["schema_contract"]["table_names"]
                        },
                        "row_counts": dict(bootstrap_manifest["table_counts"]),
                    }
                ),
                encoding="utf-8",
            )
            fake_psql = Path(tmpdir) / "fake-psql.sh"
            fake_psql.write_text(
                "#!/usr/bin/env sh\n"
                "set -eu\n"
                f"cat {payload_path}\n",
                encoding="utf-8",
            )
            fake_psql.chmod(0o755)

            inspect_target_sink = StringIO()
            with redirect_stdout(inspect_target_sink):
                self.assertEqual(
                    cli_main.run_inspect_postgres_target(
                        target_database_url="postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                        psql_executable=str(fake_psql),
                    ),
                    0,
                )
            self.assertTrue(json.loads(inspect_target_sink.getvalue())["reachable"])

            plan_sink = StringIO()
            with redirect_stdout(plan_sink):
                self.assertEqual(
                    cli_main.run_plan_postgres_bootstrap_execution(
                        package_dir=cutover_bundle_payload["postgres_bootstrap_package"]["output_dir"],
                        target_database_url="postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                        artifact_target_root=None,
                        psql_executable="/definitely/missing/psql",
                    ),
                    0,
                )
            self.assertIn("psql_not_found", json.loads(plan_sink.getvalue())["blockers"])

            execute_sink = StringIO()
            with redirect_stdout(execute_sink):
                self.assertEqual(
                    cli_main.run_execute_postgres_bootstrap_package(
                        package_dir=cutover_bundle_payload["postgres_bootstrap_package"]["output_dir"],
                        target_database_url="postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                        artifact_target_root=None,
                        psql_executable="/definitely/missing/psql",
                        dry_run=True,
                    ),
                    0,
                )
            self.assertTrue(json.loads(execute_sink.getvalue())["dry_run"])

            verify_sink = StringIO()
            with redirect_stdout(verify_sink):
                self.assertEqual(
                    cli_main.run_verify_postgres_bootstrap_package(
                        package_dir=cutover_bundle_payload["postgres_bootstrap_package"]["output_dir"],
                        target_database_url="postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                        psql_executable=str(fake_psql),
                    ),
                    0,
                )
            verify_payload = json.loads(verify_sink.getvalue())
            self.assertTrue(verify_payload["valid"])
            self.assertTrue(verify_payload["schema_contract_match"])

            rehearsal_sink = StringIO()
            with redirect_stdout(rehearsal_sink):
                self.assertEqual(
                    cli_main.run_postgres_cutover_rehearsal(
                        package_dir=cutover_bundle_payload["postgres_bootstrap_package"]["output_dir"],
                        target_database_url="postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                        changed_by="operator-a",
                        reason="cli rehearsal",
                        psql_executable=str(fake_psql),
                        artifact_target_root=None,
                        apply_to_target=False,
                    ),
                    0,
                )
            rehearsal_payload = json.loads(rehearsal_sink.getvalue())
            self.assertTrue(rehearsal_payload["valid"])
            self.assertFalse(rehearsal_payload["apply_to_target"])

            readiness_sink = StringIO()
            with redirect_stdout(readiness_sink):
                self.assertEqual(
                    cli_main.run_evaluate_control_plane_cutover_readiness(
                        package_dir=cutover_bundle_payload["postgres_bootstrap_package"]["output_dir"],
                        target_database_url="postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                        rehearsal_max_age_hours=24.0,
                        require_apply_rehearsal=False,
                    ),
                    0,
                )
            readiness_payload = json.loads(readiness_sink.getvalue())
            self.assertTrue(readiness_payload["ready"])

            decision_sink = StringIO()
            with redirect_stdout(decision_sink):
                self.assertEqual(
                    cli_main.run_decide_control_plane_cutover(
                        package_dir=cutover_bundle_payload["postgres_bootstrap_package"]["output_dir"],
                        target_database_url="postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                        changed_by="operator-a",
                        requested_decision="approve",
                        reason="cli approval",
                        decision_note=None,
                        rehearsal_max_age_hours=24.0,
                        require_apply_rehearsal=False,
                        allow_override=False,
                    ),
                    0,
                )
            decision_payload = json.loads(decision_sink.getvalue())
            self.assertTrue(decision_payload["approved"])
            self.assertEqual(decision_payload["final_decision"], "approved")
            self.assertEqual(decision_payload["maintenance_event"]["event_type"], "postgres_cutover_promoted")

            shadow_target_settings = resolve_workspace_settings(str(Path(tmpdir) / "shadow-target"))
            shadow_target_repo = cli_main.JobRepository(shadow_target_settings)
            cli_main._postgres_runtime_shadow_service = lambda: cli_main.PostgresRuntimeShadowService(  # type: ignore[assignment]
                settings=cli_main.settings,
                source_job_repository=cli_main.job_repository,
                target_repository_factory=lambda _: shadow_target_repo,
                runtime_support_inspector=lambda **_: type(
                    "Support",
                    (),
                    {
                        "backend": "postgres",
                        "url": "postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                        "redacted_url": "postgresql://lsa:***@db.example.com:5432/lsa_prod",
                        "runtime_supported": True,
                        "runtime_driver": "psycopg",
                        "runtime_dependency_installed": True,
                        "runtime_available": True,
                        "blockers": [],
                    },
                )(),
            )
            shadow_sink = StringIO()
            with redirect_stdout(shadow_sink):
                self.assertEqual(
                    cli_main.run_sync_postgres_runtime_shadow(
                        target_database_url="postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                        changed_by="operator-a",
                        reason="cli shadow sync",
                    ),
                    0,
                )
            shadow_payload = json.loads(shadow_sink.getvalue())
            self.assertGreaterEqual(shadow_payload["target_event_count"], 1)
            self.assertGreaterEqual(shadow_payload["synced_event_count"], 1)
            self.assertEqual(shadow_payload["target_job_count"], shadow_payload["source_job_count"])
            self.assertFalse(shadow_payload["maintenance_mode"]["active"])

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
            cli_main.settings.environment_name = "prod"
            cli_main.job_repository = cli_main.JobRepository(cli_main.settings)
            cli_main.analytics_service = AnalyticsService(
                job_repository=cli_main.job_repository,
                default_environment_name=cli_main.settings.environment_name,
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
            cli_main.job_repository.append_control_plane_maintenance_event(
                ControlPlaneMaintenanceEventRecord(
                    event_id="runtime-rehearsal-cli",
                    recorded_at=current_timestamp,
                    event_type="control_plane_runtime_rehearsal_executed",
                    changed_by="operator-a",
                    details={
                        "environment_name": "prod",
                        "status": "passed",
                        "expected_backend": "sqlite",
                        "expected_repository_layout": "shared",
                        "database_backend": "sqlite",
                        "repository_layout": "shared",
                        "mixed_backends": False,
                        "checks": {"smoke_job_round_trip_ok": True},
                    },
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
            self.assertIn("oncall", payload)
            self.assertEqual(len(payload["workers"]["days"]), 7)
            self.assertEqual(payload["evaluation"]["status"], "healthy")
            self.assertEqual(payload["evaluation"]["findings"], [])

    def test_emit_control_plane_alerts_persists_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.settings.environment_name = "prod"
            cli_main.job_repository = cli_main.JobRepository(cli_main.settings)
            cli_main.analytics_service = AnalyticsService(
                job_repository=cli_main.job_repository,
                default_environment_name=cli_main.settings.environment_name,
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
                default_environment_name=cli_main.settings.environment_name,
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
            cli_main.job_repository.append_control_plane_maintenance_event(
                ControlPlaneMaintenanceEventRecord(
                    event_id="runtime-rehearsal-cli-alert",
                    recorded_at=now,
                    event_type="control_plane_runtime_rehearsal_executed",
                    changed_by="operator-a",
                    details={
                        "environment_name": cli_main.settings.environment_name,
                        "status": "passed",
                        "expected_backend": "sqlite",
                        "expected_repository_layout": "shared",
                        "database_backend": "sqlite",
                        "repository_layout": "shared",
                        "mixed_backends": False,
                        "checks": {"smoke_job_round_trip_ok": True},
                    },
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

    def test_runtime_validation_review_cli_flow(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.settings.environment_name = "prod"
            cli_main.job_repository = cli_main.JobRepository(cli_main.settings)
            cli_main.analytics_service = AnalyticsService(
                job_repository=cli_main.job_repository,
                default_environment_name=cli_main.settings.environment_name,
                heartbeat_timeout_seconds=5,
                default_thresholds=ControlPlaneAlertThresholds(),
            )
            cli_main.control_plane_alert_service = ControlPlaneAlertService(
                job_repository=cli_main.job_repository,
                analytics_service=cli_main.analytics_service,
                default_environment_name=cli_main.settings.environment_name,
                window_days=7,
            )
            cli_main.job_service = cli_main.JobService(
                job_repository=cli_main.job_repository,
                audit_service=cli_main.audit_service,
                trace_collection_service=cli_main.trace_collection_service,
                worker_mode="standalone",
                control_plane_alert_service=cli_main.control_plane_alert_service,
                control_plane_alerts_enabled=True,
            )
            cli_main.runtime_validation_review_service = ControlPlaneRuntimeValidationReviewService(
                settings=cli_main.settings,
                job_service=cli_main.job_service,
                job_repository=cli_main.job_repository,
            )
            cli_main.job_service.runtime_validation_review_service = cli_main.runtime_validation_review_service
            cli_main.control_plane_alert_service.runtime_validation_review_service = (
                cli_main.runtime_validation_review_service
            )

            cli_main.job_repository.append_control_plane_maintenance_event(
                ControlPlaneMaintenanceEventRecord(
                    event_id="runtime-cli-review-due-soon",
                    recorded_at=(datetime.now(UTC) - timedelta(hours=20)).isoformat(),
                    event_type="control_plane_runtime_rehearsal_executed",
                    changed_by="operator-a",
                    details={
                        "environment_name": cli_main.settings.environment_name,
                        "status": "passed",
                        "expected_backend": "sqlite",
                        "expected_repository_layout": "shared",
                        "database_backend": "sqlite",
                        "repository_layout": "shared",
                        "mixed_backends": False,
                        "checks": {"smoke_job_round_trip_ok": True},
                    },
                )
            )

            process_sink = StringIO()
            with redirect_stdout(process_sink):
                self.assertEqual(
                    cli_main.run_process_control_plane_runtime_validation_reviews(
                        changed_by="system",
                        reason="review sweep",
                        force=False,
                    ),
                    0,
                )
            opened = json.loads(process_sink.getvalue())
            self.assertEqual(len(opened), 1)
            review_id = opened[0]["review_id"]

            assign_sink = StringIO()
            with redirect_stdout(assign_sink):
                self.assertEqual(
                    cli_main.run_assign_control_plane_runtime_validation_review(
                        review_id=review_id,
                        assigned_to="reviewer-prod",
                        assigned_to_team="platform",
                        assigned_by="system",
                        assignment_note="Own the refresh",
                    ),
                    0,
                )
            assigned = json.loads(assign_sink.getvalue())
            self.assertEqual(assigned["assigned_to"], "reviewer-prod")
            cli_main.settings.control_plane_alert_reminder_interval_seconds = 0.0
            cli_main.settings.control_plane_alert_escalation_interval_seconds = 3600.0

            alert_sink = StringIO()
            with redirect_stdout(alert_sink):
                self.assertEqual(cli_main.run_emit_control_plane_alerts(force=False), 0)
            alert_payload = json.loads(alert_sink.getvalue())
            self.assertGreaterEqual(alert_payload["emitted_count"], 1)
            runtime_review_alerts = [
                record
                for record in alert_payload["alerts"]
                if record["payload"].get("alert_family") == "runtime_validation_review"
            ]
            self.assertEqual(len(runtime_review_alerts), 1)
            self.assertEqual(runtime_review_alerts[0]["status"], "degraded")


if __name__ == "__main__":
    unittest.main()
