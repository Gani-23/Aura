from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from lsa.core.intent_graph import IntentGraph
from lsa.core.models import IntentGraphSnapshot
from lsa.services.control_plane_backup_service import ControlPlaneBackupService
from lsa.services.postgres_bootstrap_service import PostgresBootstrapService
from lsa.settings import resolve_workspace_settings
from lsa.storage.files import AuditRepository, JobRepository, SnapshotRepository
from lsa.storage.models import AuditRecord, ControlPlaneOnCallChangeRequestRecord


class PostgresBootstrapServiceTests(unittest.TestCase):
    def test_generate_from_cutover_bundle_writes_sql_and_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            snapshots = SnapshotRepository(settings, graph=IntentGraph())
            audits = AuditRepository(settings)
            jobs = JobRepository(settings)
            backup_service = ControlPlaneBackupService(
                settings=settings,
                snapshot_repository=snapshots,
                audit_repository=audits,
                job_repository=jobs,
            )

            snapshots.save(
                IntentGraphSnapshot(root_path="/tmp/service", functions={}, edges=[]),
                repo_path="/tmp/service",
                snapshot_id="snap-bootstrap",
            )
            report_path = Path(tmpdir) / "reports" / "audit-bootstrap.md"
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text("# bootstrap\n", encoding="utf-8")
            audits.save(
                AuditRecord(
                    audit_id="audit-bootstrap",
                    created_at="2026-01-01T00:00:00+00:00",
                    snapshot_id="snap-bootstrap",
                    snapshot_path="/tmp/snap.json",
                    alert_count=1,
                    report_paths=[str(report_path)],
                    alerts=[{"function": "charge_customer"}],
                    events=[{"function": "charge_customer"}],
                    sessions=[{"session_key": "request_id:req-1"}],
                    explanation={"status": "drift_detected", "summary": "drift"},
                )
            )
            jobs.append_control_plane_oncall_change_request(
                ControlPlaneOnCallChangeRequestRecord(
                    request_id="change-bootstrap",
                    created_at="2026-01-01T00:10:00+00:00",
                    created_by="operator-a",
                    created_by_team="platform",
                    created_by_role="engineer",
                    change_reason="Temporary cutover coverage.",
                    status="applied",
                    review_required=True,
                    review_reasons=["overlap"],
                    team_name="platform",
                    timezone_name="UTC",
                    weekdays=[1, 2, 3],
                    start_time="09:00",
                    end_time="17:00",
                    priority=150,
                    rotation_name="cutover-shadow",
                    assigned_to="owner-a",
                    assigned_to_team="platform",
                    assigned_at="2026-01-01T00:20:00+00:00",
                    assigned_by="lead-a",
                    assignment_note="Own the review.",
                    decision_at="2026-01-01T00:30:00+00:00",
                    decided_by="director-a",
                    decided_by_team="platform",
                    decided_by_role="director",
                    decision_note="Approved for rehearsal.",
                    applied_schedule_id="schedule-bootstrap",
                )
            )
            backup_path = Path(tmpdir) / "backup" / "control-plane.json"
            backup_summary = backup_service.export_bundle(str(backup_path))

            cutover_bundle_path = Path(tmpdir) / "backup" / "cutover-bundle.json"
            cutover_bundle_path.write_text(
                json.dumps(
                    {
                        "target": {
                            "backend": "postgres",
                            "url": "postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                            "redacted_url": "postgresql://lsa:***@db.example.com:5432/lsa_prod",
                            "runtime_supported": False,
                            "host": "db.example.com",
                            "port": 5432,
                            "database_name": "lsa_prod",
                            "username": "lsa",
                        },
                        "maintenance_workflow": {
                            "backup_path": backup_summary.path,
                            "schema_status": {
                                "schema_version": 1,
                                "expected_schema_version": 1,
                                "schema_ready": True,
                                "pending_migration_count": 0,
                                "migrations": [
                                    {
                                        "migration_id": "2026-05-05-control-plane-schema-v1",
                                        "schema_version": 1,
                                        "applied_at": "2026-05-05T00:00:00+00:00",
                                        "description": "Bootstrap schema version tracking for the control-plane database.",
                                    }
                                ],
                            },
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            summary = PostgresBootstrapService().generate_from_cutover_bundle(
                cutover_bundle_path=str(cutover_bundle_path),
                output_dir=str(Path(tmpdir) / "bootstrap"),
            )

            self.assertTrue(Path(summary.schema_sql_path).exists())
            self.assertTrue(Path(summary.data_sql_path).exists())
            self.assertTrue(Path(summary.manifest_path).exists())
            self.assertTrue((Path(summary.output_dir) / "apply.sh").exists())
            self.assertTrue((Path(summary.output_dir) / "verify.sql").exists())
            self.assertTrue((Path(summary.output_dir) / "artifacts" / "snapshots" / "snap-bootstrap.json").exists())
            self.assertTrue(
                (Path(summary.output_dir) / "artifacts" / "reports" / "audit-bootstrap" / "audit-bootstrap.md").exists()
            )
            data_sql = Path(summary.data_sql_path).read_text(encoding="utf-8")
            self.assertIn("INSERT INTO snapshots", data_sql)
            self.assertIn("artifacts/snapshots/snap-bootstrap.json", data_sql)
            self.assertIn("INSERT INTO audits", data_sql)
            self.assertIn("artifacts/reports/audit-bootstrap/audit-bootstrap.md", data_sql)
            self.assertIn("decided_by", data_sql)
            self.assertNotIn("decision_by", data_sql)
            self.assertIn("schema.sql", summary.file_checksums)
            self.assertIn("data.sql", summary.file_checksums)
            self.assertIn("apply.sh", summary.file_checksums)
            self.assertIn("verify.sql", summary.file_checksums)
            apply_script = (Path(summary.output_dir) / "apply.sh").read_text(encoding="utf-8")
            self.assertIn('psql "$TARGET_DATABASE_URL" -v ON_ERROR_STOP=1 -f "$PACKAGE_DIR/schema.sql"', apply_script)
            self.assertIn('psql "$TARGET_DATABASE_URL" -v ON_ERROR_STOP=1 -f "$PACKAGE_DIR/verify.sql"', apply_script)
            verify_sql = (Path(summary.output_dir) / "verify.sql").read_text(encoding="utf-8")
            self.assertIn("Expected 1 rows in snapshots", verify_sql)
            self.assertIn("Expected schema_version 1", verify_sql)

            inspection = PostgresBootstrapService().inspect_package(package_dir=summary.output_dir)
            self.assertTrue(inspection.valid)
            self.assertEqual(inspection.target_backend, "postgres")
            self.assertIn("schema.sql", inspection.files_present)
            self.assertIn("apply.sh", inspection.files_present)

    def test_inspect_package_detects_checksum_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            package_dir = Path(tmpdir) / "package"
            package_dir.mkdir(parents=True, exist_ok=True)
            (package_dir / "schema.sql").write_text("SELECT 1;\n", encoding="utf-8")
            (package_dir / "data.sql").write_text("SELECT 2;\n", encoding="utf-8")
            artifacts_dir = package_dir / "artifacts"
            artifacts_dir.mkdir(parents=True, exist_ok=True)
            manifest = {
                "package_version": 1,
                "target_database": {"backend": "postgres"},
                "table_counts": {},
                "artifact_counts": {},
                "file_checksums": {
                    "schema.sql": "deadbeef",
                    "data.sql": PostgresBootstrapService()._sha256_file(package_dir / "data.sql"),  # noqa: SLF001
                },
            }
            (package_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

            inspection = PostgresBootstrapService().inspect_package(package_dir=str(package_dir))
            self.assertFalse(inspection.valid)
            self.assertIn("schema.sql", inspection.checksum_mismatches)

    def test_build_execution_plan_and_execute_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            snapshots = SnapshotRepository(settings, graph=IntentGraph())
            audits = AuditRepository(settings)
            jobs = JobRepository(settings)
            backup_service = ControlPlaneBackupService(
                settings=settings,
                snapshot_repository=snapshots,
                audit_repository=audits,
                job_repository=jobs,
            )

            snapshots.save(
                IntentGraphSnapshot(root_path="/tmp/service", functions={}, edges=[]),
                repo_path="/tmp/service",
                snapshot_id="snap-bootstrap",
            )
            backup_path = Path(tmpdir) / "backup" / "control-plane.json"
            backup_summary = backup_service.export_bundle(str(backup_path))
            cutover_bundle_path = Path(tmpdir) / "backup" / "cutover-bundle.json"
            cutover_bundle_path.write_text(
                json.dumps(
                    {
                        "target": {
                            "backend": "postgres",
                            "url": "postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                            "redacted_url": "postgresql://lsa:***@db.example.com:5432/lsa_prod",
                            "runtime_supported": False,
                            "host": "db.example.com",
                            "port": 5432,
                            "database_name": "lsa_prod",
                            "username": "lsa",
                        },
                        "maintenance_workflow": {
                            "backup_path": backup_summary.path,
                            "schema_status": {
                                "schema_version": 1,
                                "expected_schema_version": 1,
                                "schema_ready": True,
                                "pending_migration_count": 0,
                                "migrations": [],
                            },
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            service = PostgresBootstrapService()
            summary = service.generate_from_cutover_bundle(
                cutover_bundle_path=str(cutover_bundle_path),
                output_dir=str(Path(tmpdir) / "bootstrap"),
            )

            fake_psql = Path(tmpdir) / "fake-psql.sh"
            psql_log = Path(tmpdir) / "psql.log"
            fake_psql.write_text(
                "\n".join(
                    [
                        "#!/usr/bin/env sh",
                        "set -eu",
                        f'echo \"$@\" >> "{psql_log}"',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            fake_psql.chmod(0o755)

            plan = service.build_execution_plan(
                package_dir=summary.output_dir,
                target_database_url="postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                artifact_target_root=str(Path(tmpdir) / "restored-artifacts"),
                psql_executable=str(fake_psql),
            )
            self.assertTrue(plan.executable)
            self.assertEqual(len(plan.commands), 3)
            self.assertTrue(plan.copy_artifacts)

            dry_run = service.execute_package(
                package_dir=summary.output_dir,
                target_database_url="postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                artifact_target_root=str(Path(tmpdir) / "restored-artifacts"),
                psql_executable=str(fake_psql),
                dry_run=True,
            )
            self.assertTrue(dry_run.dry_run)
            self.assertEqual(len(dry_run.executed_commands), 3)
            self.assertFalse(dry_run.verification_passed)

            result = service.execute_package(
                package_dir=summary.output_dir,
                target_database_url="postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                artifact_target_root=str(Path(tmpdir) / "restored-artifacts"),
                psql_executable=str(fake_psql),
                dry_run=False,
            )
            self.assertFalse(result.dry_run)
            self.assertEqual(len(result.executed_commands), 3)
            self.assertTrue(result.copied_artifacts)
            self.assertTrue(result.verification_passed)
            self.assertTrue((Path(tmpdir) / "restored-artifacts" / "snapshots" / "snap-bootstrap.json").exists())
            self.assertEqual(len(psql_log.read_text(encoding="utf-8").strip().splitlines()), 3)
