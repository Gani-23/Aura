from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lsa.core.intent_graph import IntentGraph
from lsa.drift.comparator import DriftComparator
from lsa.remediation.llm_client import RuleBasedLLMClient
from lsa.services.audit_service import AuditService
from lsa.services.control_plane_backup_service import ControlPlaneBackupService
from lsa.services.control_plane_cutover_service import ControlPlaneCutoverService
from lsa.services.control_plane_maintenance_service import ControlPlaneMaintenanceService
from lsa.services.job_service import JobService
from lsa.services.trace_collection_service import TraceCollectionService
from lsa.settings import resolve_workspace_settings
from lsa.storage.files import AuditRepository, JobRepository, SnapshotRepository
from lsa.storage.models import JobRecord


class ControlPlaneCutoverServiceTests(unittest.TestCase):
    def _build_subject(self, tmpdir: str) -> tuple[JobRepository, ControlPlaneCutoverService]:
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
        maintenance_service = ControlPlaneMaintenanceService(
            settings=settings,
            job_repository=job_repository,
            job_service=job_service,
            backup_service=backup_service,
            worker_mode="standalone",
        )
        return job_repository, ControlPlaneCutoverService(
            settings=settings,
            maintenance_service=maintenance_service,
        )

    def test_preflight_accepts_postgres_target_and_marks_runtime_gap(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            _, service = self._build_subject(tmpdir)
            report = service.build_preflight(
                target_database_url="postgresql://lsa:secret@db.example.com:5432/lsa_prod?sslmode=require"
            )

            self.assertTrue(report.can_prepare)
            self.assertEqual(report.target.backend, "postgres")
            self.assertEqual(report.target.host, "db.example.com")
            self.assertEqual(report.target.port, 5432)
            self.assertEqual(report.target.database_name, "lsa_prod")
            self.assertFalse(report.target.runtime_supported)
            self.assertIn("target_backend_not_supported_by_current_runtime", report.warnings)
            self.assertIn("postgresql://lsa:***@db.example.com:5432/lsa_prod?sslmode=require", report.target.redacted_url)

    def test_preflight_blocks_when_target_matches_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            _, service = self._build_subject(tmpdir)
            report = service.build_preflight(target_database_url=service.settings.database_url)
            self.assertFalse(report.can_prepare)
            self.assertIn("target_matches_source_database", report.blockers)

    def test_prepare_cutover_bundle_runs_maintenance_bridge(self) -> None:
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
            output_path = Path(tmpdir) / "data" / "backups" / "cutover-bundle.json"

            summary = service.prepare_cutover_bundle(
                output_path=str(output_path),
                target_database_url="postgres://lsa:secret@db.example.com/lsa_prod",
                changed_by="operator-a",
                reason="prepare postgres cutover",
            )

            self.assertTrue(output_path.exists())
            self.assertEqual(summary.target.backend, "postgres")
            self.assertTrue(Path(summary.maintenance_workflow.backup_path).exists())
            self.assertTrue(summary.maintenance_workflow.schema_status["schema_ready"])
            self.assertIsNotNone(summary.postgres_bootstrap_package)
            assert summary.postgres_bootstrap_package is not None
            self.assertTrue(Path(summary.postgres_bootstrap_package.output_dir).exists())
            self.assertTrue(Path(summary.postgres_bootstrap_package.schema_sql_path).exists())
            self.assertTrue(Path(summary.postgres_bootstrap_package.data_sql_path).exists())
            event_types = [record.event_type for record in job_repository.list_control_plane_maintenance_events()]
            self.assertIn("database_cutover_bundle_prepared", event_types)
