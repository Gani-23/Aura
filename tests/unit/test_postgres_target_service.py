from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from lsa.core.intent_graph import IntentGraph
from lsa.core.models import IntentGraphSnapshot
from lsa.services.control_plane_backup_service import ControlPlaneBackupService
from lsa.services.postgres_bootstrap_service import PostgresBootstrapService
from lsa.services.postgres_target_service import PostgresTargetService
from lsa.settings import resolve_workspace_settings
from lsa.storage.files import AuditRepository, JobRepository, SnapshotRepository


class PostgresTargetServiceTests(unittest.TestCase):
    def test_inspect_target_reports_schema_and_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            service = PostgresTargetService()
            payload = {
                "schema_version": "1",
                "maintenance_mode_active": "0",
                "table_presence": {
                    "control_plane_schema_metadata": True,
                    "control_plane_schema_migrations": True,
                    "snapshots": True,
                },
                "row_counts": {
                    "control_plane_schema_metadata": 1,
                    "control_plane_schema_migrations": 1,
                    "snapshots": 2,
                },
            }
            fake_psql = self._write_fake_psql(Path(tmpdir), payload)

            inspection = service.inspect_target(
                target_database_url="postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                psql_executable=str(fake_psql),
            )

            self.assertTrue(inspection.reachable)
            self.assertEqual(inspection.schema_version, 1)
            self.assertTrue(inspection.schema_ready)
            self.assertFalse(inspection.maintenance_mode_active)
            self.assertEqual(inspection.row_counts["snapshots"], 2)
            self.assertEqual(inspection.target["redacted_url"], "postgresql://lsa:***@db.example.com:5432/lsa_prod")

    def test_verify_bootstrap_package_against_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            package_dir = self._generate_bootstrap_package(Path(tmpdir))
            manifest = json.loads((package_dir / "manifest.json").read_text(encoding="utf-8"))
            payload = {
                "schema_version": str(manifest["schema_status"]["schema_version"]),
                "maintenance_mode_active": "0",
                "table_presence": {
                    name: True for name in manifest["schema_contract"]["table_names"]
                },
                "row_counts": dict(manifest["table_counts"]),
            }
            fake_psql = self._write_fake_psql(Path(tmpdir), payload)

            verification = PostgresTargetService().verify_bootstrap_package_against_target(
                package_dir=str(package_dir),
                target_database_url="postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                psql_executable=str(fake_psql),
            )

            self.assertTrue(verification.valid)
            self.assertTrue(verification.schema_contract_match)
            self.assertTrue(verification.schema_version_match)
            self.assertTrue(verification.row_counts_match)
            self.assertFalse(verification.blockers)

    def _write_fake_psql(self, root: Path, payload: dict) -> Path:
        script_path = root / "fake-psql.sh"
        payload_path = root / "psql-payload.json"
        payload_path.write_text(json.dumps(payload), encoding="utf-8")
        script_path.write_text(
            "\n".join(
                [
                    "#!/usr/bin/env sh",
                    "set -eu",
                    f"cat {payload_path}",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        script_path.chmod(0o755)
        return script_path

    def _generate_bootstrap_package(self, root: Path) -> Path:
        settings = resolve_workspace_settings(str(root))
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
            snapshot_id="snap-target",
        )
        backup_path = root / "backup" / "control-plane.json"
        backup_summary = backup_service.export_bundle(str(backup_path))
        cutover_bundle_path = root / "backup" / "cutover-bundle.json"
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
            output_dir=str(root / "bootstrap"),
        )
        return Path(summary.output_dir)
