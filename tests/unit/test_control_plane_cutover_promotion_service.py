from __future__ import annotations

import json
from datetime import UTC, datetime
import tempfile
import unittest
from pathlib import Path

from lsa.core.intent_graph import IntentGraph
from lsa.core.models import IntentGraphSnapshot
from lsa.drift.comparator import DriftComparator
from lsa.remediation.llm_client import RuleBasedLLMClient
from lsa.services.audit_service import AuditService
from lsa.services.control_plane_backup_service import ControlPlaneBackupService
from lsa.services.control_plane_cutover_promotion_service import ControlPlaneCutoverPromotionService
from lsa.services.control_plane_cutover_readiness_service import ControlPlaneCutoverReadinessService
from lsa.services.control_plane_cutover_service import ControlPlaneCutoverService
from lsa.services.control_plane_maintenance_service import ControlPlaneMaintenanceService
from lsa.services.job_service import JobService
from lsa.services.postgres_bootstrap_service import PostgresBootstrapService
from lsa.services.postgres_cutover_rehearsal_service import PostgresCutoverRehearsalService
from lsa.services.postgres_target_service import PostgresTargetService
from lsa.services.trace_collection_service import TraceCollectionService
from lsa.settings import resolve_workspace_settings
from lsa.storage.files import AuditRepository, JobRepository, SnapshotRepository
from lsa.storage.models import ControlPlaneMaintenanceEventRecord


class ControlPlaneCutoverPromotionServiceTests(unittest.TestCase):
    def test_decision_approves_ready_cutover(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            service, package_dir, job_repository = self._build_subject(Path(tmpdir), apply_rehearsal=False)
            summary = service.decide(
                package_dir=str(package_dir),
                target_database_url="postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                changed_by="operator-a",
                requested_decision="approve",
                reason="ship it",
            )
            self.assertTrue(summary.approved)
            self.assertEqual(summary.final_decision, "approved")
            self.assertEqual(summary.maintenance_event["event_type"], "postgres_cutover_promoted")
            self.assertEqual(job_repository.list_control_plane_maintenance_events(limit=1)[0].event_type, "postgres_cutover_promoted")

    def test_decision_blocks_when_requirements_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            service, package_dir, _ = self._build_subject(Path(tmpdir), apply_rehearsal=False)
            summary = service.decide(
                package_dir=str(package_dir),
                target_database_url="postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                changed_by="operator-a",
                requested_decision="approve",
                reason="needs apply rehearsal",
                require_apply_rehearsal=True,
            )
            self.assertFalse(summary.approved)
            self.assertEqual(summary.final_decision, "blocked")
            self.assertIn("apply_rehearsal_required", summary.blockers)
            self.assertEqual(summary.maintenance_event["event_type"], "postgres_cutover_promotion_blocked")

    def test_decision_allows_governed_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            service, package_dir, _ = self._build_subject(Path(tmpdir), apply_rehearsal=False)
            summary = service.decide(
                package_dir=str(package_dir),
                target_database_url="postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                changed_by="operator-a",
                requested_decision="approve",
                reason="emergency override",
                decision_note="approved under incident window",
                require_apply_rehearsal=True,
                allow_override=True,
            )
            self.assertTrue(summary.approved)
            self.assertTrue(summary.override_applied)
            self.assertEqual(summary.final_decision, "approved_with_override")
            self.assertIn("override_applied_to_unready_cutover", summary.warnings)
            self.assertEqual(summary.maintenance_event["event_type"], "postgres_cutover_promoted_with_override")

    def test_decision_records_manual_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            service, package_dir, _ = self._build_subject(Path(tmpdir), apply_rehearsal=False)
            summary = service.decide(
                package_dir=str(package_dir),
                target_database_url="postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                changed_by="operator-a",
                requested_decision="reject",
                reason="change freeze",
                decision_note="hold until next window",
            )
            self.assertFalse(summary.approved)
            self.assertEqual(summary.final_decision, "rejected")
            self.assertEqual(summary.maintenance_event["event_type"], "postgres_cutover_rejected")

    def _build_subject(
        self,
        root: Path,
        *,
        apply_rehearsal: bool,
    ) -> tuple[ControlPlaneCutoverPromotionService, Path, JobRepository]:
        settings = resolve_workspace_settings(str(root))
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
        maintenance_service = ControlPlaneMaintenanceService(
            settings=settings,
            job_repository=job_repository,
            job_service=job_service,
            backup_service=backup_service,
            worker_mode="standalone",
        )
        cutover_service = ControlPlaneCutoverService(
            settings=settings,
            maintenance_service=maintenance_service,
        )

        snapshot_repository.save(
            IntentGraphSnapshot(root_path="/tmp/service", functions={}, edges=[]),
            repo_path="/tmp/service",
            snapshot_id="snap-promotion",
        )
        cutover_bundle_path = root / "data" / "backups" / "cutover-bundle.json"
        cutover_summary = cutover_service.prepare_cutover_bundle(
            output_path=str(cutover_bundle_path),
            target_database_url="postgresql://lsa:secret@db.example.com:5432/lsa_prod",
            changed_by="operator-a",
            reason="prepare cutover",
        )
        assert cutover_summary.postgres_bootstrap_package is not None
        package_dir = Path(cutover_summary.postgres_bootstrap_package.output_dir)
        manifest = json.loads((package_dir / "manifest.json").read_text(encoding="utf-8"))

        pre_payload_path = root / "pg-pre.json"
        post_payload_path = root / "pg-post.json"
        state_path = root / "pg-applied.state"
        pre_payload_path.write_text(
            json.dumps(
                {
                    "schema_version": "0",
                    "maintenance_mode_active": "0",
                    "table_presence": {
                        name: True for name in manifest["schema_contract"]["table_names"]
                    },
                    "row_counts": {name: 0 for name in manifest["schema_contract"]["table_names"]},
                }
            ),
            encoding="utf-8",
        )
        post_payload_path.write_text(
            json.dumps(
                {
                    "schema_version": str(manifest["schema_status"]["schema_version"]),
                    "maintenance_mode_active": "0",
                    "table_presence": {
                        name: True for name in manifest["schema_contract"]["table_names"]
                    },
                    "row_counts": dict(manifest["table_counts"]),
                }
            ),
            encoding="utf-8",
        )
        fake_psql = root / "fake-psql.sh"
        fake_psql.write_text(
            "\n".join(
                [
                    "#!/usr/bin/env sh",
                    "set -eu",
                    'mode=""',
                    'file_arg=""',
                    'while [ "$#" -gt 0 ]; do',
                    '  if [ "$1" = "-c" ]; then',
                    '    mode="query"',
                    '    shift 2',
                    '    continue',
                    '  fi',
                    '  if [ "$1" = "-f" ]; then',
                    '    mode="file"',
                    '    file_arg="$2"',
                    '    shift 2',
                    '    continue',
                    '  fi',
                    '  shift',
                    'done',
                    'if [ "$mode" = "query" ]; then',
                    f'  if [ -f "{state_path}" ]; then cat "{post_payload_path}"; else cat "{pre_payload_path}"; fi',
                    "  exit 0",
                    "fi",
                    'if [ "$mode" = "file" ]; then',
                    f'  case "$file_arg" in *data.sql) touch "{state_path}" ;; esac',
                    "  exit 0",
                    "fi",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        fake_psql.chmod(0o755)

        bootstrap_service = PostgresBootstrapService()
        target_service = PostgresTargetService(bootstrap_service=bootstrap_service)
        rehearsal_service = PostgresCutoverRehearsalService(
            job_service=job_service,
            bootstrap_service=bootstrap_service,
            target_service=target_service,
        )
        rehearsal_service.execute_rehearsal(
            package_dir=str(package_dir),
            target_database_url="postgresql://lsa:secret@db.example.com:5432/lsa_prod",
            changed_by="operator-a",
            reason="rehearsal",
            psql_executable=str(fake_psql),
            apply_to_target=apply_rehearsal,
        )
        readiness_service = ControlPlaneCutoverReadinessService(
            settings=settings,
            job_repository=job_repository,
            bootstrap_service=bootstrap_service,
        )
        service = ControlPlaneCutoverPromotionService(
            settings=settings,
            job_service=job_service,
            readiness_service=readiness_service,
        )
        return service, package_dir, job_repository
