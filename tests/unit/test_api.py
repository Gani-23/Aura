from datetime import UTC, datetime, timedelta
from pathlib import Path
import json
import tempfile
import time
import unittest

from fastapi.testclient import TestClient

from lsa.api import main as api_main
from lsa.services.analytics_service import AnalyticsService, ControlPlaneAlertThresholds
from lsa.services.control_plane_alert_service import ControlPlaneAlertService
from lsa.services.metrics_service import ControlPlaneMetricsService
from lsa.services.control_plane_cutover_service import ControlPlaneCutoverService
from lsa.services.control_plane_maintenance_service import ControlPlaneMaintenanceService
from lsa.services.control_plane_runtime_validation_review_service import (
    ControlPlaneRuntimeValidationReviewService,
)
from lsa.storage.models import ControlPlaneMaintenanceEventRecord, JobLeaseEventRecord, WorkerHeartbeatRecord


class ApiTests(unittest.TestCase):
    def test_ingest_and_audit_round_trip(self) -> None:
        fixture_root = Path("tests/fixtures/sample_service").resolve()
        trace_path = Path("tests/fixtures/sample_trace.log").resolve()
        alias_trace_path = Path("tests/fixtures/alias_smoke_trace.log").resolve()
        symbolized_script = Path("tests/fixtures/scripts/emit_inline_symbolized_trace.sh").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            api_main.settings = api_main.resolve_workspace_settings(tmpdir)
            api_main.settings.environment_name = "prod"
            api_main.settings.api_key = "test-key"
            api_main.settings.run_embedded_worker = True
            api_main.settings.worker_history_retention_days = 1
            api_main.settings.job_lease_history_retention_days = 1
            api_main.settings.data_dir.mkdir(parents=True, exist_ok=True)
            api_main.settings.destination_aliases_path.write_text(
                json.dumps({"93.184.216.34": "api.stripe.com"}),
                encoding="utf-8",
            )
            api_main.settings.oncall_policy_path.write_text(
                json.dumps(
                    {
                        "default": {
                            "required_approver_roles": ["director", "admin"],
                            "allow_self_approval": False,
                        },
                        "rotations": {
                            "holiday": {
                                "allowed_requester_teams": ["platform"],
                                "allowed_approver_teams": ["platform"],
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            api_main.snapshot_repository = api_main.SnapshotRepository(api_main.settings, graph=api_main.graph)
            api_main.audit_repository = api_main.AuditRepository(api_main.settings)
            api_main.job_repository = api_main.JobRepository(api_main.settings)
            api_main.ingest_service = api_main.IngestService(
                graph=api_main.graph,
                snapshot_repository=api_main.snapshot_repository,
            )
            api_main.audit_service = api_main.AuditService(
                graph=api_main.graph,
                snapshot_repository=api_main.snapshot_repository,
                audit_repository=api_main.audit_repository,
                drift_comparator=api_main.DriftComparator(),
                remediation_client=api_main.RuleBasedLLMClient(),
                settings=api_main.settings,
            )
            api_main.trace_collection_service = api_main.TraceCollectionService(settings=api_main.settings)
            api_main.analytics_service = AnalyticsService(
                job_repository=api_main.job_repository,
                default_environment_name=api_main.settings.environment_name,
                heartbeat_timeout_seconds=api_main.settings.worker_heartbeat_timeout_seconds,
                default_thresholds=ControlPlaneAlertThresholds(
                    queue_warning_threshold=api_main.settings.analytics_queue_warning_threshold,
                    queue_critical_threshold=api_main.settings.analytics_queue_critical_threshold,
                    stale_worker_warning_threshold=api_main.settings.analytics_stale_worker_warning_threshold,
                    stale_worker_critical_threshold=api_main.settings.analytics_stale_worker_critical_threshold,
                    expired_lease_warning_threshold=api_main.settings.analytics_expired_lease_warning_threshold,
                    expired_lease_critical_threshold=api_main.settings.analytics_expired_lease_critical_threshold,
                    job_failure_rate_warning_threshold=api_main.settings.analytics_job_failure_rate_warning_threshold,
                    job_failure_rate_critical_threshold=api_main.settings.analytics_job_failure_rate_critical_threshold,
                    job_failure_rate_min_samples=api_main.settings.analytics_job_failure_rate_min_samples,
                    oncall_conflict_warning_threshold=api_main.settings.analytics_oncall_conflict_warning_threshold,
                    oncall_conflict_critical_threshold=api_main.settings.analytics_oncall_conflict_critical_threshold,
                    oncall_pending_review_warning_threshold=api_main.settings.analytics_oncall_pending_review_warning_threshold,
                    oncall_pending_review_critical_threshold=api_main.settings.analytics_oncall_pending_review_critical_threshold,
                    oncall_pending_review_sla_hours=api_main.settings.analytics_oncall_pending_review_sla_hours,
                ),
            )
            api_main.control_plane_alert_service = ControlPlaneAlertService(
                job_repository=api_main.job_repository,
                analytics_service=api_main.analytics_service,
                default_environment_name=api_main.settings.environment_name,
                window_days=api_main.settings.control_plane_alert_window_days,
                dedup_window_seconds=api_main.settings.control_plane_alert_dedup_window_seconds,
                policy_path=str(api_main.settings.oncall_policy_path),
                sink_path=str(api_main.settings.control_plane_alert_sink_path),
                webhook_url=api_main.settings.control_plane_alert_webhook_url,
            )
            api_main.control_plane_backup_service = api_main.ControlPlaneBackupService(
                settings=api_main.settings,
                snapshot_repository=api_main.snapshot_repository,
                audit_repository=api_main.audit_repository,
                job_repository=api_main.job_repository,
            )
            api_main.job_service = api_main.JobService(
                job_repository=api_main.job_repository,
                audit_service=api_main.audit_service,
                trace_collection_service=api_main.trace_collection_service,
                worker_mode="embedded",
                heartbeat_timeout_seconds=api_main.settings.worker_heartbeat_timeout_seconds,
                worker_history_retention_days=api_main.settings.worker_history_retention_days,
                job_lease_history_retention_days=api_main.settings.job_lease_history_retention_days,
                history_prune_interval_seconds=api_main.settings.history_prune_interval_seconds,
                control_plane_alert_service=api_main.control_plane_alert_service,
                control_plane_alert_interval_seconds=api_main.settings.control_plane_alert_interval_seconds,
                control_plane_alerts_enabled=api_main.settings.control_plane_alerts_enabled,
            )
            api_main.runtime_validation_review_service = ControlPlaneRuntimeValidationReviewService(
                settings=api_main.settings,
                job_service=api_main.job_service,
                job_repository=api_main.job_repository,
            )
            api_main.job_service.runtime_validation_review_service = api_main.runtime_validation_review_service
            api_main.control_plane_alert_service.runtime_validation_review_service = (
                api_main.runtime_validation_review_service
            )
            api_main.metrics_service = ControlPlaneMetricsService(
                job_repository=api_main.job_repository,
                job_service=api_main.job_service,
                analytics_service=api_main.analytics_service,
                environment_name=api_main.settings.environment_name,
                worker_mode="embedded",
            )
            api_main.control_plane_maintenance_service = ControlPlaneMaintenanceService(
                settings=api_main.settings,
                job_repository=api_main.job_repository,
                job_service=api_main.job_service,
                backup_service=api_main.control_plane_backup_service,
                worker_mode="embedded",
            )
            api_main.control_plane_cutover_service = ControlPlaneCutoverService(
                settings=api_main.settings,
                maintenance_service=api_main.control_plane_maintenance_service,
            )
            auth_headers = {"X-API-Key": "test-key"}
            with TestClient(api_main.app) as client:
                health_response = client.get("/health")
                self.assertEqual(health_response.status_code, 200)
                health_payload = health_response.json()
                self.assertEqual(health_payload["status"], "ok")
                self.assertEqual(health_payload["environment_name"], "prod")
                self.assertTrue(health_payload["auth_enabled"])
                self.assertEqual(health_payload["worker_mode"], "embedded")
                self.assertEqual(health_payload["database_backend"], "sqlite")
                self.assertEqual(health_payload["database_url"], api_main.settings.database_url)
                self.assertEqual(health_payload["snapshot_repository_backend"], "sqlite")
                self.assertEqual(health_payload["audit_repository_backend"], "sqlite")
                self.assertEqual(health_payload["job_repository_backend"], "sqlite")
                self.assertEqual(health_payload["control_plane_repository_layout"], "shared")
                self.assertFalse(health_payload["control_plane_mixed_backends"])
                self.assertFalse(health_payload["snapshots_audits_repository_runtime_enabled"])
                self.assertFalse(health_payload["snapshots_audits_repository_runtime_active"])
                self.assertFalse(health_payload["job_repository_runtime_enabled"])
                self.assertFalse(health_payload["job_repository_runtime_active"])
                self.assertTrue(health_payload["database_runtime_supported"])
                self.assertEqual(health_payload["database_runtime_driver"], "sqlite3")
                self.assertTrue(health_payload["database_runtime_dependency_installed"])
                self.assertTrue(health_payload["database_runtime_available"])
                self.assertEqual(health_payload["database_runtime_blockers"], [])
                self.assertTrue(health_payload["database_ready"])
                self.assertTrue(health_payload["database_writable"])
                self.assertEqual(health_payload["database_schema_version"], 1)
                self.assertEqual(health_payload["database_expected_schema_version"], 1)
                self.assertTrue(health_payload["database_schema_ready"])
                self.assertEqual(health_payload["database_pending_migration_count"], 0)
                self.assertTrue(health_payload["worker_running"])
                self.assertEqual(health_payload["active_workers"], 1)
                self.assertEqual(health_payload["queued_jobs"], 0)
                self.assertEqual(health_payload["running_jobs"], 0)
                self.assertEqual(health_payload["database_path"], str(api_main.settings.database_path))

                unauthorized_ingest = client.post(
                    "/ingest",
                    json={"repo_path": str(fixture_root), "persist": True, "snapshot_id": "snap-api"},
                )
                self.assertEqual(unauthorized_ingest.status_code, 401)

                unauthorized_metrics = client.get("/metrics")
                self.assertEqual(unauthorized_metrics.status_code, 401)

                metrics_response = client.get("/metrics?days=1", headers=auth_headers)
                self.assertEqual(metrics_response.status_code, 200)
                self.assertIn("lsa_control_plane_database_ready 1", metrics_response.text)
                self.assertIn('lsa_control_plane_info{database_backend="sqlite",environment="prod",worker_mode="embedded"} 1', metrics_response.text)
                self.assertIn("lsa_control_plane_maintenance_mode_active 0", metrics_response.text)

                maintenance_status_response = client.get("/maintenance/mode", headers=auth_headers)
                self.assertEqual(maintenance_status_response.status_code, 200)
                self.assertFalse(maintenance_status_response.json()["active"])

                preflight_response = client.get("/maintenance/control-plane-preflight", headers=auth_headers)
                self.assertEqual(preflight_response.status_code, 200)
                self.assertTrue(preflight_response.json()["can_execute"])
                self.assertEqual(preflight_response.json()["database_backend"], "sqlite")

                runtime_smoke_response = client.post(
                    "/maintenance/control-plane-runtime-smoke",
                    json={"changed_by": "operator-a", "reason": "api smoke", "cleanup": True},
                    headers=auth_headers,
                )
                self.assertEqual(runtime_smoke_response.status_code, 200)
                runtime_smoke_payload = runtime_smoke_response.json()
                self.assertEqual(runtime_smoke_payload["repository_layout"], "shared")
                self.assertTrue(runtime_smoke_payload["snapshot_round_trip_ok"])
                self.assertTrue(runtime_smoke_payload["audit_round_trip_ok"])
                self.assertTrue(runtime_smoke_payload["job_round_trip_ok"])
                self.assertTrue(runtime_smoke_payload["cleanup_completed"])

                runtime_rehearsal_response = client.post(
                    "/maintenance/control-plane-runtime-rehearsal",
                    json={
                        "changed_by": "operator-a",
                        "expected_backend": "sqlite",
                        "expected_repository_layout": "shared",
                        "reason": "api rehearsal",
                        "cleanup": True,
                    },
                    headers=auth_headers,
                )
                self.assertEqual(runtime_rehearsal_response.status_code, 200)
                runtime_rehearsal_payload = runtime_rehearsal_response.json()
                self.assertEqual(runtime_rehearsal_payload["status"], "passed")
                self.assertEqual(runtime_rehearsal_payload["database_backend"], "sqlite")
                self.assertEqual(runtime_rehearsal_payload["repository_layout"], "shared")
                self.assertFalse(runtime_rehearsal_payload["snapshots_audits_repository_runtime_active"])
                self.assertFalse(runtime_rehearsal_payload["job_repository_runtime_active"])
                self.assertTrue(all(runtime_rehearsal_payload["checks"].values()))
                self.assertTrue(runtime_rehearsal_payload["smoke"]["cleanup_completed"])

                runtime_validation_response = client.get(
                    "/maintenance/control-plane-runtime-validation",
                    headers=auth_headers,
                )
                self.assertEqual(runtime_validation_response.status_code, 200)
                runtime_validation_payload = runtime_validation_response.json()
                self.assertEqual(runtime_validation_payload["status"], "passed")
                self.assertEqual(runtime_validation_payload["latest_rehearsal_status"], "passed")
                self.assertEqual(runtime_validation_payload["latest_expected_backend"], "sqlite")
                self.assertIsNotNone(runtime_validation_payload["latest_rehearsal_event_id"])

                runtime_review_process_response = client.post(
                    "/maintenance/control-plane-runtime-validation-reviews/process",
                    json={"changed_by": "system", "reason": "review sweep", "force": False},
                    headers=auth_headers,
                )
                self.assertEqual(runtime_review_process_response.status_code, 200)
                initial_review_payload = runtime_review_process_response.json()
                self.assertEqual(len(initial_review_payload), 1)
                self.assertEqual(initial_review_payload[0]["status"], "resolved")
                self.assertEqual(initial_review_payload[0]["trigger_status"], "missing")
                self.assertEqual(
                    initial_review_payload[0]["resolution_reason"],
                    "runtime_proof_restored",
                )

                api_main.settings.analytics_runtime_rehearsal_due_soon_age_hours = 0
                api_main.job_repository.append_control_plane_maintenance_event(
                    ControlPlaneMaintenanceEventRecord(
                        event_id="runtime-review-due-soon",
                        recorded_at=datetime.now(UTC).isoformat(),
                        event_type="control_plane_runtime_rehearsal_executed",
                        changed_by="operator-a",
                        details={
                            "environment_name": api_main.settings.environment_name,
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
                runtime_review_process_response = client.post(
                    "/maintenance/control-plane-runtime-validation-reviews/process",
                    json={"changed_by": "system", "reason": "review sweep", "force": False},
                    headers=auth_headers,
                )
                self.assertEqual(runtime_review_process_response.status_code, 200)
                review_payload = runtime_review_process_response.json()
                self.assertEqual(len(review_payload), 1)
                self.assertEqual(review_payload[0]["trigger_cadence_status"], "due_soon")
                review_id = review_payload[0]["review_id"]

                runtime_review_assign_response = client.post(
                    f"/maintenance/control-plane-runtime-validation-reviews/{review_id}/assign",
                    json={
                        "assigned_to": "reviewer-prod",
                        "assigned_to_team": "platform",
                        "assigned_by": "system",
                        "assignment_note": "Own the refresh",
                    },
                    headers=auth_headers,
                )
                self.assertEqual(runtime_review_assign_response.status_code, 200)
                self.assertEqual(runtime_review_assign_response.json()["assigned_to"], "reviewer-prod")
                api_main.settings.control_plane_alert_reminder_interval_seconds = 0.0
                api_main.settings.control_plane_alert_escalation_interval_seconds = 3600.0
                runtime_review_alert_emit = client.post(
                    "/maintenance/emit-control-plane-alerts",
                    headers=auth_headers,
                )
                self.assertEqual(runtime_review_alert_emit.status_code, 200)
                self.assertGreaterEqual(runtime_review_alert_emit.json()["emitted_count"], 1)
                runtime_review_alerts = [
                    record
                    for record in runtime_review_alert_emit.json()["alerts"]
                    if record["payload"].get("alert_family") == "runtime_validation_review"
                ]
                self.assertEqual(len(runtime_review_alerts), 1)
                self.assertEqual(runtime_review_alerts[0]["status"], "degraded")

                cutover_preflight_response = client.get(
                    "/maintenance/control-plane-cutover-preflight",
                    params={"target_database_url": "postgresql://lsa:secret@db.example.com:5432/lsa_prod"},
                    headers=auth_headers,
                )
                self.assertEqual(cutover_preflight_response.status_code, 200)
                self.assertTrue(cutover_preflight_response.json()["can_prepare"])
                self.assertEqual(cutover_preflight_response.json()["target"]["backend"], "postgres")

                runtime_backend_response = client.get(
                    "/maintenance/control-plane-runtime-backend",
                    headers=auth_headers,
                )
                self.assertEqual(runtime_backend_response.status_code, 200)
                self.assertEqual(runtime_backend_response.json()["backend"], "sqlite")
                self.assertTrue(runtime_backend_response.json()["runtime_available"])

                inspect_runtime_backend_response = client.post(
                    "/maintenance/control-plane-runtime-backend/inspect",
                    json={"database_url": "postgresql://lsa:secret@db.example.com:5432/lsa_prod"},
                    headers=auth_headers,
                )
                self.assertEqual(inspect_runtime_backend_response.status_code, 200)
                inspect_runtime_payload = inspect_runtime_backend_response.json()
                self.assertEqual(inspect_runtime_payload["backend"], "postgres")
                self.assertFalse(inspect_runtime_payload["runtime_available"])
                self.assertIn("unsupported_runtime_backend:postgres", inspect_runtime_payload["runtime_blockers"])

                enable_maintenance_response = client.post(
                    "/maintenance/mode/enable",
                    json={"changed_by": "operator-a", "reason": "backup"},
                    headers=auth_headers,
                )
                self.assertEqual(enable_maintenance_response.status_code, 200)
                self.assertTrue(enable_maintenance_response.json()["active"])
                self.assertEqual(enable_maintenance_response.json()["changed_by"], "operator-a")

                maintenance_health_response = client.get("/health")
                self.assertEqual(maintenance_health_response.status_code, 200)
                self.assertTrue(maintenance_health_response.json()["maintenance_mode_active"])

                blocked_ingest_response = client.post(
                    "/ingest",
                    json={"repo_path": str(fixture_root), "persist": True, "snapshot_id": "snap-api-blocked"},
                    headers=auth_headers,
                )
                self.assertEqual(blocked_ingest_response.status_code, 503)

                disable_maintenance_response = client.post(
                    "/maintenance/mode/disable",
                    json={"changed_by": "operator-a", "reason": "done"},
                    headers=auth_headers,
                )
                self.assertEqual(disable_maintenance_response.status_code, 200)
                self.assertFalse(disable_maintenance_response.json()["active"])

                with api_main.job_repository.database._connect() as connection:  # noqa: SLF001
                    connection.execute(
                        """
                        UPDATE control_plane_schema_metadata
                        SET metadata_value = '0'
                        WHERE metadata_key = 'schema_version'
                        """
                    )

                runbook_response = client.post(
                    "/maintenance/control-plane-runbook",
                    json={
                        "output_path": str(Path(tmpdir) / "data" / "backups" / "api-runbook.json"),
                        "changed_by": "operator-a",
                        "reason": "api runbook",
                    },
                    headers=auth_headers,
                )
                self.assertEqual(runbook_response.status_code, 200)
                runbook_payload = runbook_response.json()
                self.assertTrue(runbook_payload["schema_status"]["schema_ready"])
                self.assertFalse(runbook_payload["maintenance_final"]["active"])
                self.assertIn("backup_exported", runbook_payload["steps"])

                cutover_bundle_response = client.post(
                    "/maintenance/control-plane-cutover-bundle",
                    json={
                        "output_path": str(Path(tmpdir) / "data" / "backups" / "cutover-bundle.json"),
                        "target_database_url": "postgres://lsa:secret@db.example.com/lsa_prod",
                        "changed_by": "operator-a",
                        "reason": "api cutover",
                    },
                    headers=auth_headers,
                )
                self.assertEqual(cutover_bundle_response.status_code, 200)
                cutover_bundle_payload = cutover_bundle_response.json()
                self.assertEqual(cutover_bundle_payload["target"]["backend"], "postgres")
                self.assertTrue(cutover_bundle_payload["maintenance_workflow"]["schema_status"]["schema_ready"])
                self.assertIsNotNone(cutover_bundle_payload["postgres_bootstrap_package"])

                bootstrap_inspection_response = client.post(
                    "/maintenance/postgres-bootstrap-package/inspect",
                    json={
                        "package_dir": cutover_bundle_payload["postgres_bootstrap_package"]["output_dir"],
                    },
                    headers=auth_headers,
                )
                self.assertEqual(bootstrap_inspection_response.status_code, 200)
                self.assertTrue(bootstrap_inspection_response.json()["valid"])

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

                target_inspection_response = client.post(
                    "/maintenance/postgres-target/inspect",
                    json={
                        "target_database_url": "postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                        "psql_executable": str(fake_psql),
                    },
                    headers=auth_headers,
                )
                self.assertEqual(target_inspection_response.status_code, 200)
                self.assertTrue(target_inspection_response.json()["reachable"])
                self.assertTrue(target_inspection_response.json()["schema_ready"])

                bootstrap_plan_response = client.post(
                    "/maintenance/postgres-bootstrap-package/plan",
                    json={
                        "package_dir": cutover_bundle_payload["postgres_bootstrap_package"]["output_dir"],
                        "target_database_url": "postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                        "psql_executable": "/definitely/missing/psql",
                    },
                    headers=auth_headers,
                )
                self.assertEqual(bootstrap_plan_response.status_code, 200)
                self.assertIn("psql_not_found", bootstrap_plan_response.json()["blockers"])

                bootstrap_execute_response = client.post(
                    "/maintenance/postgres-bootstrap-package/execute",
                    json={
                        "package_dir": cutover_bundle_payload["postgres_bootstrap_package"]["output_dir"],
                        "target_database_url": "postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                        "psql_executable": "/definitely/missing/psql",
                        "dry_run": True,
                    },
                    headers=auth_headers,
                )
                self.assertEqual(bootstrap_execute_response.status_code, 200)
                self.assertTrue(bootstrap_execute_response.json()["dry_run"])

                bootstrap_verify_target_response = client.post(
                    "/maintenance/postgres-bootstrap-package/verify-target",
                    json={
                        "package_dir": cutover_bundle_payload["postgres_bootstrap_package"]["output_dir"],
                        "target_database_url": "postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                        "psql_executable": str(fake_psql),
                    },
                    headers=auth_headers,
                )
                self.assertEqual(bootstrap_verify_target_response.status_code, 200)
                self.assertTrue(bootstrap_verify_target_response.json()["valid"])
                self.assertTrue(bootstrap_verify_target_response.json()["schema_contract_match"])

                rehearsal_response = client.post(
                    "/maintenance/postgres-cutover-rehearsal",
                    json={
                        "package_dir": cutover_bundle_payload["postgres_bootstrap_package"]["output_dir"],
                        "target_database_url": "postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                        "changed_by": "operator-a",
                        "reason": "api rehearsal",
                        "psql_executable": str(fake_psql),
                        "apply_to_target": False,
                    },
                    headers=auth_headers,
                )
                self.assertEqual(rehearsal_response.status_code, 200)
                self.assertTrue(rehearsal_response.json()["valid"])
                self.assertFalse(rehearsal_response.json()["apply_to_target"])

                readiness_response = client.post(
                    "/maintenance/control-plane-cutover-readiness",
                    json={
                        "package_dir": cutover_bundle_payload["postgres_bootstrap_package"]["output_dir"],
                        "target_database_url": "postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                        "rehearsal_max_age_hours": 24.0,
                        "require_apply_rehearsal": False,
                    },
                    headers=auth_headers,
                )
                self.assertEqual(readiness_response.status_code, 200)
                self.assertTrue(readiness_response.json()["ready"])

                cutover_decision_response = client.post(
                    "/maintenance/control-plane-cutover-decision",
                    json={
                        "package_dir": cutover_bundle_payload["postgres_bootstrap_package"]["output_dir"],
                        "target_database_url": "postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                        "changed_by": "operator-a",
                        "requested_decision": "approve",
                        "reason": "api approval",
                    },
                    headers=auth_headers,
                )
                self.assertEqual(cutover_decision_response.status_code, 200)
                cutover_decision_payload = cutover_decision_response.json()
                self.assertTrue(cutover_decision_payload["approved"])
                self.assertEqual(cutover_decision_payload["final_decision"], "approved")
                self.assertEqual(cutover_decision_payload["maintenance_event"]["event_type"], "postgres_cutover_promoted")

                shadow_target_settings = api_main.resolve_workspace_settings(str(Path(tmpdir) / "shadow-target"))
                shadow_target_repo = api_main.JobRepository(shadow_target_settings)
                api_main._postgres_runtime_shadow_service = lambda: api_main.PostgresRuntimeShadowService(  # type: ignore[assignment]
                    settings=api_main.settings,
                    source_job_repository=api_main.job_repository,
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
                runtime_shadow_response = client.post(
                    "/maintenance/postgres-runtime-shadow-sync",
                    json={
                        "target_database_url": "postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                        "changed_by": "operator-a",
                        "reason": "api shadow sync",
                    },
                    headers=auth_headers,
                )
                self.assertEqual(runtime_shadow_response.status_code, 200)
                runtime_shadow_payload = runtime_shadow_response.json()
                self.assertGreaterEqual(runtime_shadow_payload["target_event_count"], 1)
                self.assertGreaterEqual(runtime_shadow_payload["synced_event_count"], 1)
                self.assertGreaterEqual(runtime_shadow_payload["target_worker_count"], 1)
                self.assertFalse(runtime_shadow_payload["maintenance_mode"]["active"])

                ingest_response = client.post(
                    "/ingest",
                    json={"repo_path": str(fixture_root), "persist": True, "snapshot_id": "snap-api"},
                    headers=auth_headers,
                )
                self.assertEqual(ingest_response.status_code, 200)
                ingest_payload = ingest_response.json()
                self.assertEqual(ingest_payload["snapshot_id"], "snap-api")

                list_response = client.get("/snapshots", headers=auth_headers)
                self.assertEqual(list_response.status_code, 200)
                self.assertEqual(len(list_response.json()), 1)

                audit_response = client.post(
                    "/audit",
                    json={
                        "snapshot_id": "snap-api",
                        "persist": True,
                        "audit_id": "audit-api",
                        "events": [
                            {
                                "function": "charge_customer",
                                "event_type": "network",
                                "target": "https://malicious.example.com/exfil",
                            }
                        ],
                    },
                    headers=auth_headers,
                )
                self.assertEqual(audit_response.status_code, 200)
                audit_payload = audit_response.json()
                self.assertEqual(audit_payload["audit_id"], "audit-api")
                self.assertEqual(audit_payload["alert_count"], 1)
                self.assertEqual(len(audit_payload["sessions"]), 1)
                self.assertEqual(audit_payload["explanation"]["status"], "drift_detected")
                self.assertEqual(audit_payload["explanation"]["primary_function"], "charge_customer")

                trace_audit_response = client.post(
                    "/audit-trace",
                    json={
                        "snapshot_id": "snap-api",
                        "persist": True,
                        "audit_id": "audit-trace-api",
                        "trace_path": str(trace_path),
                        "trace_format": "auto",
                    },
                    headers=auth_headers,
                )
                self.assertEqual(trace_audit_response.status_code, 200)
                self.assertEqual(trace_audit_response.json()["audit_id"], "audit-trace-api")
                self.assertGreaterEqual(len(trace_audit_response.json()["sessions"]), 1)
                self.assertIn("status", trace_audit_response.json()["explanation"])

                alias_audit_response = client.post(
                    "/audit-trace",
                    json={
                        "snapshot_id": "snap-api",
                        "persist": True,
                        "audit_id": "audit-alias-api",
                        "trace_path": str(alias_trace_path),
                        "trace_format": "auto",
                    },
                    headers=auth_headers,
                )
                self.assertEqual(alias_audit_response.status_code, 200)
                self.assertEqual(alias_audit_response.json()["alert_count"], 0)
                self.assertEqual(alias_audit_response.json()["explanation"]["status"], "clean")

                collect_trace_response = client.post(
                    "/collect-trace",
                    json={
                        "pid": 1234,
                        "program": str(symbolized_script),
                        "output_path": str(Path(tmpdir) / "api-collected.log"),
                    },
                    headers=auth_headers,
                )
                self.assertEqual(collect_trace_response.status_code, 200)
                collect_trace_payload = collect_trace_response.json()
                self.assertEqual(collect_trace_payload["line_count"], 1)
                self.assertIn("trace_symbol_map_path", collect_trace_payload)
                self.assertIn("trace_context_map_path", collect_trace_payload)

                backup_path = Path(tmpdir) / "control-plane-backup.json"
                export_backup_response = client.post(
                    "/maintenance/export-control-plane-backup",
                    json={"output_path": str(backup_path)},
                    headers=auth_headers,
                )
                self.assertEqual(export_backup_response.status_code, 200)
                self.assertTrue(backup_path.exists())
                self.assertGreaterEqual(export_backup_response.json()["counts"]["snapshots"], 1)
                self.assertGreaterEqual(export_backup_response.json()["artifact_counts"]["snapshots"], 1)

                api_main.job_repository.reset_control_plane()
                import_backup_response = client.post(
                    "/maintenance/import-control-plane-backup",
                    json={"input_path": str(backup_path), "replace_existing": True},
                    headers=auth_headers,
                )
                self.assertEqual(import_backup_response.status_code, 200)
                restored_snapshots = client.get("/snapshots", headers=auth_headers)
                self.assertEqual(restored_snapshots.status_code, 200)
                self.assertGreaterEqual(len(restored_snapshots.json()), 1)

                schema_response = client.get("/maintenance/control-plane-schema", headers=auth_headers)
                self.assertEqual(schema_response.status_code, 200)
                self.assertEqual(schema_response.json()["schema_version"], 1)
                self.assertEqual(schema_response.json()["expected_schema_version"], 1)
                self.assertTrue(schema_response.json()["schema_ready"])
                self.assertEqual(schema_response.json()["pending_migration_count"], 0)
                self.assertEqual(len(schema_response.json()["migrations"]), 1)

                schema_contract_response = client.get(
                    "/maintenance/control-plane-schema/contract",
                    headers=auth_headers,
                )
                self.assertEqual(schema_contract_response.status_code, 200)
                self.assertEqual(schema_contract_response.json()["schema_version"], 1)
                self.assertIn("sqlite", schema_contract_response.json()["runtime_supported_backends"])
                self.assertIn("postgres", schema_contract_response.json()["bootstrap_supported_backends"])
                self.assertIn(
                    "control_plane_oncall_change_requests",
                    schema_contract_response.json()["table_names"],
                )

                with api_main.job_repository.database._connect() as connection:
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

                degraded_health_response = client.get("/health")
                self.assertEqual(degraded_health_response.status_code, 200)
                self.assertFalse(degraded_health_response.json()["database_schema_ready"])
                self.assertEqual(degraded_health_response.json()["database_pending_migration_count"], 1)

                migrate_schema_response = client.post(
                    "/maintenance/control-plane-schema/migrate",
                    headers=auth_headers,
                )
                self.assertEqual(migrate_schema_response.status_code, 200)
                self.assertTrue(migrate_schema_response.json()["schema_ready"])
                self.assertEqual(migrate_schema_response.json()["schema_version"], 1)
                self.assertEqual(migrate_schema_response.json()["pending_migration_count"], 0)

                explicit_context_script = Path(tmpdir) / "emit_context_trace.sh"
                explicit_context_script.write_text(
                    "#!/bin/sh\n"
                    "printf '%s\\n' 'event=network function=charge_customer process=python conn_id=conn-1 "
                    "target=https://malicious.example.com/exfil'\n",
                    encoding="utf-8",
                )
                explicit_context_script.chmod(0o755)
                explicit_context_map_path = Path(tmpdir) / "explicit.contexts.json"
                explicit_context_map_path.write_text(
                    json.dumps(
                        {
                            "contexts": {
                                "conn-1": {
                                    "request_id": "req-explicit",
                                    "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                                }
                            }
                        }
                    ),
                    encoding="utf-8",
                )
                explicit_collect_trace_response = client.post(
                    "/collect-trace",
                    json={
                        "pid": 1234,
                        "program": str(explicit_context_script),
                        "output_path": str(Path(tmpdir) / "api-explicit-context.log"),
                        "context_map_path": str(explicit_context_map_path),
                    },
                    headers=auth_headers,
                )
                self.assertEqual(explicit_collect_trace_response.status_code, 200)
                explicit_collect_payload = explicit_collect_trace_response.json()
                self.assertTrue(explicit_collect_payload["trace_context_map_path"].endswith(".contexts.json"))
                self.assertTrue(Path(explicit_collect_payload["trace_context_map_path"]).exists())

                collect_audit_response = client.post(
                    "/collect-audit",
                    json={
                        "snapshot_id": "snap-api",
                        "pid": 1234,
                        "program": str(symbolized_script),
                        "trace_format": "auto",
                        "output_path": str(Path(tmpdir) / "api-collected-audit.log"),
                        "persist": True,
                        "audit_id": "collect-audit-api",
                    },
                    headers=auth_headers,
                )
                self.assertEqual(collect_audit_response.status_code, 200)
                collect_audit_payload = collect_audit_response.json()
                self.assertEqual(collect_audit_payload["audit_id"], "collect-audit-api")
                self.assertEqual(collect_audit_payload["alert_count"], 1)
                self.assertEqual(collect_audit_payload["alerts"][0]["function"], "charge_customer")
                self.assertIn("trace_symbol_map_path", collect_audit_payload)
                self.assertIn("trace_context_map_path", collect_audit_payload)

                audit_job_response = client.post(
                    "/jobs/audit-trace",
                    json={
                        "snapshot_id": "snap-api",
                        "persist": True,
                        "audit_id": "audit-trace-job-api",
                        "trace_path": str(trace_path),
                        "trace_format": "auto",
                    },
                    headers=auth_headers,
                )
                self.assertEqual(audit_job_response.status_code, 202)
                audit_job_payload = audit_job_response.json()
                self.assertEqual(audit_job_payload["job_type"], "audit-trace")

                audit_job_detail = None
                for _ in range(40):
                    audit_job_detail = client.get(f"/jobs/{audit_job_payload['job_id']}", headers=auth_headers)
                    self.assertEqual(audit_job_detail.status_code, 200)
                    if audit_job_detail.json()["status"] in {"completed", "failed"}:
                        break
                    time.sleep(0.05)
                assert audit_job_detail is not None
                self.assertEqual(audit_job_detail.json()["status"], "completed")
                self.assertEqual(audit_job_detail.json()["result_payload"]["audit_id"], "audit-trace-job-api")
                self.assertIsNotNone(audit_job_detail.json()["claimed_by_worker_id"])

                collect_job_response = client.post(
                    "/jobs/collect-audit",
                    json={
                        "snapshot_id": "snap-api",
                        "pid": 1234,
                        "program": str(symbolized_script),
                        "trace_format": "auto",
                        "output_path": str(Path(tmpdir) / "api-collected-job.log"),
                        "persist": True,
                        "audit_id": "collect-audit-job-api",
                    },
                    headers=auth_headers,
                )
                self.assertEqual(collect_job_response.status_code, 202)
                collect_job_payload = collect_job_response.json()
                self.assertEqual(collect_job_payload["job_type"], "collect-audit")

                collect_job_detail = None
                for _ in range(40):
                    collect_job_detail = client.get(f"/jobs/{collect_job_payload['job_id']}", headers=auth_headers)
                    self.assertEqual(collect_job_detail.status_code, 200)
                    if collect_job_detail.json()["status"] in {"completed", "failed"}:
                        break
                    time.sleep(0.05)
                assert collect_job_detail is not None
                self.assertEqual(collect_job_detail.json()["status"], "completed")
                self.assertEqual(collect_job_detail.json()["result_payload"]["audit_id"], "collect-audit-job-api")
                self.assertIn("trace_path", collect_job_detail.json()["result_payload"])
                self.assertIsNotNone(collect_job_detail.json()["claimed_by_worker_id"])

                stored_jobs = client.get("/jobs", headers=auth_headers)
                self.assertEqual(stored_jobs.status_code, 200)
                self.assertGreaterEqual(len(stored_jobs.json()), 2)

                stored_workers = client.get("/workers", headers=auth_headers)
                self.assertEqual(stored_workers.status_code, 200)
                self.assertGreaterEqual(len(stored_workers.json()), 1)
                worker_id = stored_workers.json()[0]["worker_id"]
                worker_detail = client.get(f"/workers/{worker_id}", headers=auth_headers)
                self.assertEqual(worker_detail.status_code, 200)
                self.assertEqual(worker_detail.json()["mode"], "embedded")
                worker_heartbeats = client.get(f"/workers/{worker_id}/heartbeats", headers=auth_headers)
                self.assertEqual(worker_heartbeats.status_code, 200)
                self.assertGreaterEqual(len(worker_heartbeats.json()), 1)
                lease_events = client.get(
                    f"/jobs/{collect_job_payload['job_id']}/lease-events",
                    headers=auth_headers,
                )
                self.assertEqual(lease_events.status_code, 200)
                self.assertTrue(any(item["event_type"] == "lease_claimed" for item in lease_events.json()))

                api_main.job_repository.append_worker_heartbeat(
                    WorkerHeartbeatRecord(
                        heartbeat_id="heartbeat-old",
                        worker_id=worker_id,
                        recorded_at="2020-01-01T00:00:00+00:00",
                        status="running",
                        current_job_id=None,
                    )
                )
                api_main.job_repository.append_job_lease_event(
                    JobLeaseEventRecord(
                        event_id="lease-event-old",
                        job_id=collect_job_payload["job_id"],
                        worker_id=worker_id,
                        event_type="lease_claimed",
                        recorded_at="2020-01-01T00:00:00+00:00",
                        details={},
                    )
                )
                prune_response = client.post("/maintenance/prune-history", headers=auth_headers)
                self.assertEqual(prune_response.status_code, 200)
                self.assertGreaterEqual(prune_response.json()["worker_heartbeats_compacted"], 1)
                self.assertGreaterEqual(prune_response.json()["job_lease_events_compacted"], 1)
                self.assertGreaterEqual(prune_response.json()["worker_heartbeats_pruned"], 1)
                self.assertGreaterEqual(prune_response.json()["job_lease_events_pruned"], 1)
                heartbeat_rollups = client.get(f"/workers/{worker_id}/heartbeat-rollups", headers=auth_headers)
                self.assertEqual(heartbeat_rollups.status_code, 200)
                self.assertGreaterEqual(len(heartbeat_rollups.json()), 1)
                lease_rollups = client.get(
                    f"/jobs/{collect_job_payload['job_id']}/lease-event-rollups",
                    headers=auth_headers,
                )
                self.assertEqual(lease_rollups.status_code, 200)
                self.assertGreaterEqual(len(lease_rollups.json()), 1)
                analytics = client.get("/analytics/control-plane?days=30", headers=auth_headers)
                self.assertEqual(analytics.status_code, 200)
                analytics_payload = analytics.json()
                self.assertEqual(analytics_payload["window_days"], 30)
                self.assertGreaterEqual(analytics_payload["queue"]["completed_jobs"], 2)
                self.assertGreaterEqual(analytics_payload["workers"]["total_workers_seen"], 1)
                self.assertGreaterEqual(analytics_payload["leases"]["total_events"], 1)
                self.assertEqual(len(analytics_payload["jobs"]["days"]), 30)
                self.assertIn("oncall", analytics_payload)
                self.assertIn("evaluation", analytics_payload)
                self.assertIn("status", analytics_payload["evaluation"])
                self.assertIn("thresholds", analytics_payload["evaluation"])
                alert_emit = client.post("/maintenance/emit-control-plane-alerts", headers=auth_headers)
                self.assertEqual(alert_emit.status_code, 200)
                alert_payload = alert_emit.json()
                self.assertIn("emitted_count", alert_payload)
                followup_emit = client.post("/maintenance/process-control-plane-alert-followups", headers=auth_headers)
                self.assertEqual(followup_emit.status_code, 200)
                self.assertIn("emitted_count", followup_emit.json())
                alert_list = client.get("/control-plane-alerts", headers=auth_headers)
                self.assertEqual(alert_list.status_code, 200)
                self.assertGreaterEqual(len(alert_list.json()), alert_payload["emitted_count"])
                if alert_list.json():
                    alert_id = alert_list.json()[0]["alert_id"]
                    ack_response = client.post(
                        f"/control-plane-alerts/{alert_id}/acknowledge",
                        json={"acknowledged_by": "operator-api", "acknowledgement_note": "Watching"},
                        headers=auth_headers,
                    )
                    self.assertEqual(ack_response.status_code, 200)
                    self.assertEqual(ack_response.json()["acknowledged_by"], "operator-api")
                silence_response = client.post(
                    "/control-plane-alert-silences",
                    json={
                        "created_by": "operator-api",
                        "reason": "maintenance",
                        "duration_minutes": 15,
                        "match_finding_code": "queue_without_active_workers",
                    },
                    headers=auth_headers,
                )
                self.assertEqual(silence_response.status_code, 200)
                silence_id = silence_response.json()["silence_id"]
                silence_list = client.get("/control-plane-alert-silences?active_only=true", headers=auth_headers)
                self.assertEqual(silence_list.status_code, 200)
                self.assertGreaterEqual(len(silence_list.json()), 1)
                cancel_silence = client.post(
                    f"/control-plane-alert-silences/{silence_id}/cancel",
                    json={"cancelled_by": "operator-api"},
                    headers=auth_headers,
                )
                self.assertEqual(cancel_silence.status_code, 200)
                self.assertEqual(cancel_silence.json()["cancelled_by"], "operator-api")
                today = datetime.now(UTC).date().isoformat()
                schedule_response = client.post(
                    "/control-plane-oncall-schedules",
                    json={
                        "created_by": "operator-api",
                        "created_by_team": "platform",
                        "team_name": "platform-api",
                        "timezone_name": "UTC",
                        "weekdays": [0, 1, 2, 3, 4, 5, 6],
                        "start_time": "00:00",
                        "end_time": "23:59",
                        "priority": 200,
                        "rotation_name": "holiday",
                        "effective_start_date": today,
                        "effective_end_date": today,
                    },
                    headers=auth_headers,
                )
                self.assertEqual(schedule_response.status_code, 200)
                self.assertEqual(schedule_response.json()["priority"], 200)
                self.assertEqual(schedule_response.json()["environment_name"], "prod")
                schedule_id = schedule_response.json()["schedule_id"]
                conflicting_schedule = client.post(
                    "/control-plane-oncall-schedules",
                    json={
                        "created_by": "operator-api-2",
                        "created_by_team": "platform",
                        "team_name": "platform-api-2",
                        "timezone_name": "UTC",
                        "weekdays": [0, 1, 2, 3, 4, 5, 6],
                        "start_time": "00:00",
                        "end_time": "23:59",
                        "priority": 200,
                        "rotation_name": "holiday-backup",
                        "effective_start_date": today,
                        "effective_end_date": today,
                    },
                    headers=auth_headers,
                )
                self.assertEqual(conflicting_schedule.status_code, 400)
                approved_conflicting_schedule = client.post(
                    "/control-plane-oncall-schedules",
                    json={
                        "created_by": "operator-api-2",
                        "created_by_role": "engineer",
                        "created_by_team": "platform",
                        "change_reason": "Dual coverage during cutover rehearsal.",
                        "approved_by": "director-api",
                        "approved_by_team": "platform",
                        "approved_by_role": "director",
                        "approval_note": "Accepted for one-day overlap.",
                        "team_name": "platform-api-2",
                        "timezone_name": "UTC",
                        "weekdays": [0, 1, 2, 3, 4, 5, 6],
                        "start_time": "00:00",
                        "end_time": "23:59",
                        "priority": 200,
                        "rotation_name": "holiday-backup",
                        "effective_start_date": today,
                        "effective_end_date": today,
                    },
                    headers=auth_headers,
                )
                self.assertEqual(approved_conflicting_schedule.status_code, 200)
                self.assertEqual(approved_conflicting_schedule.json()["approved_by"], "director-api")
                self.assertEqual(approved_conflicting_schedule.json()["approved_by_role"], "director")
                invalid_role_schedule = client.post(
                    "/control-plane-oncall-schedules",
                    json={
                        "created_by": "operator-api-3",
                        "created_by_role": "engineer",
                        "created_by_team": "platform",
                        "change_reason": "Bad approval role test.",
                        "approved_by": "lead-api",
                        "approved_by_team": "platform",
                        "approved_by_role": "engineer",
                        "team_name": "platform-api-3",
                        "timezone_name": "UTC",
                        "weekdays": [0, 1, 2, 3, 4, 5, 6],
                        "start_time": "00:00",
                        "end_time": "23:59",
                        "priority": 200,
                        "rotation_name": "holiday-third",
                        "effective_start_date": today,
                        "effective_end_date": today,
                    },
                    headers=auth_headers,
                )
                self.assertEqual(invalid_role_schedule.status_code, 400)
                change_request = client.post(
                    "/control-plane-oncall-change-requests",
                    json={
                        "created_by": "operator-api-4",
                        "created_by_team": "platform",
                        "created_by_role": "engineer",
                        "change_reason": "Need staged overlap with formal review.",
                        "team_name": "platform-api-review",
                        "timezone_name": "UTC",
                        "weekdays": [0, 1, 2, 3, 4, 5, 6],
                        "start_time": "00:00",
                        "end_time": "23:59",
                        "priority": 200,
                        "rotation_name": "holiday-review",
                        "effective_start_date": today,
                        "effective_end_date": today,
                    },
                    headers=auth_headers,
                )
                self.assertEqual(change_request.status_code, 200)
                change_request_payload = change_request.json()
                self.assertEqual(change_request_payload["environment_name"], "prod")
                self.assertEqual(change_request_payload["status"], "pending_review")
                self.assertTrue(change_request_payload["review_required"])
                request_id = change_request_payload["request_id"]
                listed_requests = client.get(
                    "/control-plane-oncall-change-requests?status=pending_review",
                    headers=auth_headers,
                )
                self.assertEqual(listed_requests.status_code, 200)
                self.assertGreaterEqual(len(listed_requests.json()), 1)
                fetched_request = client.get(
                    f"/control-plane-oncall-change-requests/{request_id}",
                    headers=auth_headers,
                )
                self.assertEqual(fetched_request.status_code, 200)
                assigned_request = client.post(
                    f"/control-plane-oncall-change-requests/{request_id}/assign",
                    json={
                        "assigned_to": "reviewer-api",
                        "assigned_to_team": "platform",
                        "assigned_by": "lead-api",
                        "assignment_note": "Handle this before the prod cutover.",
                    },
                    headers=auth_headers,
                )
                self.assertEqual(assigned_request.status_code, 200)
                self.assertEqual(assigned_request.json()["assigned_to"], "reviewer-api")
                reviewed_request = client.post(
                    f"/control-plane-oncall-change-requests/{request_id}/review",
                    json={
                        "decision": "approve",
                        "reviewed_by": "director-api",
                        "reviewed_by_team": "platform",
                        "reviewed_by_role": "director",
                        "review_note": "Approved through review workflow.",
                    },
                    headers=auth_headers,
                )
                self.assertEqual(reviewed_request.status_code, 200)
                self.assertEqual(reviewed_request.json()["status"], "applied")
                self.assertIsNotNone(reviewed_request.json()["applied_schedule_id"])
                rejected_request = client.post(
                    "/control-plane-oncall-change-requests",
                    json={
                        "created_by": "operator-api-5",
                        "created_by_team": "platform",
                        "created_by_role": "engineer",
                        "change_reason": "Trying another overlap.",
                        "team_name": "platform-api-review-2",
                        "timezone_name": "UTC",
                        "weekdays": [0, 1, 2, 3, 4, 5, 6],
                        "start_time": "00:00",
                        "end_time": "23:59",
                        "priority": 200,
                        "rotation_name": "holiday-review-2",
                        "effective_start_date": today,
                        "effective_end_date": today,
                    },
                    headers=auth_headers,
                )
                self.assertEqual(rejected_request.status_code, 200)
                rejected_request_id = rejected_request.json()["request_id"]
                rejected_review = client.post(
                    f"/control-plane-oncall-change-requests/{rejected_request_id}/review",
                    json={
                        "decision": "reject",
                        "reviewed_by": "director-api",
                        "reviewed_by_team": "platform",
                        "reviewed_by_role": "director",
                        "review_note": "Rejecting until coverage plan is tightened.",
                    },
                    headers=auth_headers,
                )
                self.assertEqual(rejected_review.status_code, 200)
                self.assertEqual(rejected_review.json()["status"], "rejected")
                schedule_list = client.get("/control-plane-oncall-schedules?active_only=true", headers=auth_headers)
                self.assertEqual(schedule_list.status_code, 200)
                self.assertGreaterEqual(len(schedule_list.json()), 1)
                schedule_preview = client.get(
                    f"/control-plane-oncall-schedules/resolve?at={today}T12:00:00Z",
                    headers=auth_headers,
                )
                self.assertEqual(schedule_preview.status_code, 200)
                self.assertEqual(schedule_preview.json()["resolved_route"]["team_name"], "platform-api-review")
                self.assertGreaterEqual(schedule_preview.json()["active_candidate_count"], 1)
                schedule_cancel = client.post(
                    f"/control-plane-oncall-schedules/{schedule_id}/cancel",
                    json={"cancelled_by": "operator-api"},
                    headers=auth_headers,
                )
                self.assertEqual(schedule_cancel.status_code, 200)
                self.assertEqual(schedule_cancel.json()["cancelled_by"], "operator-api")

                stored_audits = client.get("/audits", headers=auth_headers)
                self.assertEqual(stored_audits.status_code, 200)
                self.assertEqual(len(stored_audits.json()), 6)
                self.assertIn("explanation", stored_audits.json()[0])
