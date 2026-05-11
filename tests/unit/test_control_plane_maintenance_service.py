from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
import tempfile
import unittest

from lsa.core.intent_graph import IntentGraph
from lsa.drift.comparator import DriftComparator
from lsa.remediation.llm_client import RuleBasedLLMClient
from lsa.services.audit_service import AuditService
from lsa.services.control_plane_backup_service import ControlPlaneBackupService
from lsa.services.control_plane_maintenance_service import ControlPlaneMaintenanceService
from lsa.services.job_service import JobService
from lsa.services.trace_collection_service import TraceCollectionService
from lsa.settings import resolve_workspace_settings
from lsa.storage.files import AuditRepository, JobRepository, SnapshotRepository
from lsa.storage.models import ControlPlaneMaintenanceEventRecord, JobRecord


class ControlPlaneMaintenanceServiceTests(unittest.TestCase):
    def _build_subject(self, tmpdir: str) -> tuple[JobRepository, ControlPlaneMaintenanceService]:
        settings = resolve_workspace_settings(tmpdir)
        graph = IntentGraph()
        snapshot_repository = SnapshotRepository(settings, graph=graph)
        audit_repository = AuditRepository(settings)
        job_repository = JobRepository(settings)
        audit_service = AuditService(
            graph=graph,
            snapshot_repository=snapshot_repository,
            audit_repository=audit_repository,
            drift_comparator=DriftComparator(),
            remediation_client=RuleBasedLLMClient(),
            settings=settings,
        )
        trace_collection_service = TraceCollectionService(settings=settings)
        backup_service = ControlPlaneBackupService(
            settings=settings,
            snapshot_repository=snapshot_repository,
            audit_repository=audit_repository,
            job_repository=job_repository,
        )
        job_service = JobService(
            job_repository=job_repository,
            audit_service=audit_service,
            trace_collection_service=trace_collection_service,
            worker_mode="standalone",
            heartbeat_timeout_seconds=settings.worker_heartbeat_timeout_seconds,
        )
        job_repository.append_control_plane_maintenance_event(
            ControlPlaneMaintenanceEventRecord(
                event_id="runtime-rehearsal-current",
                recorded_at=datetime.now(UTC).isoformat(),
                event_type="control_plane_runtime_rehearsal_executed",
                changed_by="operator-a",
                details={
                    "environment_name": settings.environment_name,
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
        return job_repository, ControlPlaneMaintenanceService(
            settings=settings,
            job_repository=job_repository,
            job_service=job_service,
            backup_service=backup_service,
            worker_mode="standalone",
        )

    def test_build_preflight_reports_running_job_and_pending_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            job_repository, service = self._build_subject(tmpdir)
            job_repository.save(
                JobRecord(
                    job_id="job-running",
                    created_at=datetime.now(UTC).isoformat(),
                    job_type="audit-trace",
                    status="running",
                    request_payload={},
                    claimed_by_worker_id="worker-a",
                    lease_expires_at=datetime.now(UTC).isoformat(),
                )
            )
            with job_repository.database._connect() as connection:  # noqa: SLF001
                connection.execute(
                    """
                    UPDATE control_plane_schema_metadata
                    SET metadata_value = '0'
                    WHERE metadata_key = 'schema_version'
                    """
                )

            report = service.build_preflight()
            self.assertIn("running_jobs_present", report.blockers)
            self.assertIn("schema_migration_pending", report.warnings)
            self.assertFalse(report.can_execute)
            self.assertEqual(report.running_jobs, 1)

    def test_execute_workflow_exports_backup_and_reconciles_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            job_repository, service = self._build_subject(tmpdir)
            with job_repository.database._connect() as connection:  # noqa: SLF001
                connection.execute(
                    """
                    UPDATE control_plane_schema_metadata
                    SET metadata_value = '0'
                    WHERE metadata_key = 'schema_version'
                    """
                )
            output_path = str(Path(tmpdir) / "data" / "backups" / "runbook.json")

            summary = service.execute_workflow(
                output_path=output_path,
                changed_by="operator-a",
                reason="cutover rehearsal",
            )

            self.assertTrue(Path(summary.backup_path).exists())
            self.assertTrue(summary.schema_status["schema_ready"])
            self.assertTrue(summary.maintenance_enabled_by_workflow)
            self.assertIn("backup_exported", summary.steps)
            self.assertIn("schema_migrated", summary.steps)
            self.assertIn("maintenance_mode_disabled", summary.steps)
            self.assertFalse(job_repository.maintenance_mode_status()["active"])

            event_types = [record.event_type for record in job_repository.list_control_plane_maintenance_events()]
            self.assertIn("maintenance_workflow_started", event_types)
            self.assertIn("maintenance_workflow_completed", event_types)

    def test_build_preflight_blocks_when_runtime_validation_required_and_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            job_repository, service = self._build_subject(tmpdir)
            service.settings.maintenance_runtime_validation_required = True
            job_repository.reset_control_plane()

            report = service.build_preflight()

            self.assertIn("runtime_validation_missing", report.blockers)
            self.assertFalse(report.can_execute)
