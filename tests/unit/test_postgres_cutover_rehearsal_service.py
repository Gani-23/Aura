from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from lsa.core.intent_graph import IntentGraph
from lsa.core.models import IntentGraphSnapshot
from lsa.drift.comparator import DriftComparator
from lsa.remediation.llm_client import RuleBasedLLMClient
from lsa.services.audit_service import AuditService
from lsa.services.control_plane_backup_service import ControlPlaneBackupService
from lsa.services.job_service import JobService
from lsa.services.postgres_bootstrap_service import PostgresBootstrapService
from lsa.services.postgres_cutover_rehearsal_service import PostgresCutoverRehearsalService
from lsa.services.postgres_target_service import PostgresTargetService
from lsa.services.trace_collection_service import TraceCollectionService
from lsa.settings import resolve_workspace_settings
from lsa.storage.files import AuditRepository, JobRepository, SnapshotRepository


class PostgresCutoverRehearsalServiceTests(unittest.TestCase):
    def test_execute_rehearsal_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            service, package_dir, fake_psql = self._build_subject(Path(tmpdir))

            summary = service.execute_rehearsal(
                package_dir=str(package_dir),
                target_database_url="postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                changed_by="operator-a",
                reason="dry rehearsal",
                psql_executable=str(fake_psql),
                apply_to_target=False,
            )

            self.assertTrue(summary.valid)
            self.assertFalse(summary.apply_to_target)
            self.assertIn("package_dry_run_planned", summary.steps)
            self.assertIsNone(summary.target_after)
            self.assertIsNone(summary.verification)

    def test_execute_rehearsal_apply_and_verify(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            service, package_dir, fake_psql = self._build_subject(Path(tmpdir))

            summary = service.execute_rehearsal(
                package_dir=str(package_dir),
                target_database_url="postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                changed_by="operator-a",
                reason="apply rehearsal",
                psql_executable=str(fake_psql),
                apply_to_target=True,
            )

            self.assertTrue(summary.valid)
            self.assertTrue(summary.apply_to_target)
            self.assertIn("package_applied", summary.steps)
            self.assertIn("package_verified_against_target", summary.steps)
            assert summary.verification is not None
            self.assertTrue(summary.verification["valid"])
            assert summary.target_after is not None
            self.assertTrue(summary.target_after["schema_ready"])

    def _build_subject(self, root: Path) -> tuple[PostgresCutoverRehearsalService, Path, Path]:
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
        snapshot_repository.save(
            IntentGraphSnapshot(root_path="/tmp/service", functions={}, edges=[]),
            repo_path="/tmp/service",
            snapshot_id="snap-rehearsal",
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
        bootstrap_service = PostgresBootstrapService()
        package_summary = bootstrap_service.generate_from_cutover_bundle(
            cutover_bundle_path=str(cutover_bundle_path),
            output_dir=str(root / "bootstrap"),
        )
        package_dir = Path(package_summary.output_dir)

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
        target_service = PostgresTargetService(bootstrap_service=bootstrap_service)
        service = PostgresCutoverRehearsalService(
            job_service=job_service,
            bootstrap_service=bootstrap_service,
            target_service=target_service,
        )
        return service, package_dir, fake_psql
