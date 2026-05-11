from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lsa.core.intent_graph import IntentGraph
from lsa.remediation.llm_client import RuleBasedLLMClient
from lsa.drift.comparator import DriftComparator
from lsa.services.audit_service import AuditService
from lsa.services.job_service import JobService
from lsa.services.postgres_runtime_shadow_service import PostgresRuntimeShadowService
from lsa.services.trace_collection_service import TraceCollectionService
from lsa.settings import resolve_workspace_settings
from lsa.storage.files import AuditRepository, JobRepository, SnapshotRepository
from lsa.storage.models import JobLeaseEventRecord, WorkerHeartbeatRecord, WorkerRecord


class _RuntimeSupport:
    def __init__(self, url: str, redacted_url: str) -> None:
        self.backend = "postgres"
        self.url = url
        self.redacted_url = redacted_url
        self.runtime_supported = True
        self.runtime_driver = "psycopg"
        self.runtime_dependency_installed = True
        self.runtime_available = True
        self.blockers: list[str] = []


class PostgresRuntimeShadowServiceTests(unittest.TestCase):
    def test_sync_control_plane_slice_copies_maintenance_state_and_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source_settings = resolve_workspace_settings(root / "source")
            target_settings = resolve_workspace_settings(root / "target")

            source_repo = JobRepository(source_settings)
            source_audit_service = AuditService(
                graph=IntentGraph(),
                snapshot_repository=SnapshotRepository(source_settings, graph=IntentGraph()),
                audit_repository=AuditRepository(source_settings),
                drift_comparator=DriftComparator(),
                remediation_client=RuleBasedLLMClient(),
                settings=source_settings,
            )
            source_job_service = JobService(
                job_repository=source_repo,
                audit_service=source_audit_service,
                trace_collection_service=TraceCollectionService(settings=source_settings),
                worker_mode="standalone",
                heartbeat_timeout_seconds=source_settings.worker_heartbeat_timeout_seconds,
            )
            source_job_service.record_maintenance_event(
                event_type="postgres_cutover_promoted",
                changed_by="operator-a",
                reason="cutover approved",
                details={"package_dir": "/tmp/pkg"},
            )
            source_job_service.enable_maintenance_mode(changed_by="operator-a", reason="shadow sync test")
            source_repo.create("audit-trace", {"snapshot_id": "snap-a"}, job_id="job-a")
            source_repo.save_worker(
                WorkerRecord(
                    worker_id="worker-a",
                    mode="standalone",
                    status="running",
                    started_at="2026-05-06T00:00:00+00:00",
                    last_heartbeat_at="2026-05-06T00:00:01+00:00",
                    host_name="host-a",
                    process_id=123,
                    current_job_id="job-a",
                )
            )
            source_repo.append_worker_heartbeat(
                WorkerHeartbeatRecord(
                    heartbeat_id="hb-a",
                    worker_id="worker-a",
                    recorded_at="2026-05-06T00:00:01+00:00",
                    status="running",
                    current_job_id="job-a",
                )
            )
            source_repo.append_job_lease_event(
                JobLeaseEventRecord(
                    event_id="lease-a",
                    job_id="job-a",
                    worker_id="worker-a",
                    event_type="lease_claimed",
                    recorded_at="2026-05-06T00:00:02+00:00",
                    details={"lease_expires_at": "2026-05-06T00:05:00+00:00"},
                )
            )

            target_repo = JobRepository(target_settings)
            service = PostgresRuntimeShadowService(
                settings=source_settings,
                source_job_repository=source_repo,
                target_repository_factory=lambda _: target_repo,
                runtime_support_inspector=lambda **_: _RuntimeSupport(
                    "postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                    "postgresql://lsa:***@db.example.com:5432/lsa_prod",
                ),
                now_factory=lambda: "2026-05-06T00:00:00+00:00",
            )

            summary = service.sync_control_plane_slice(
                target_database_url="postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                changed_by="operator-a",
                reason="shadow sync",
            )

            self.assertGreaterEqual(summary.synced_event_count, 2)
            self.assertEqual(summary.target_event_count, summary.source_event_count)
            self.assertEqual(summary.synced_job_count, 1)
            self.assertEqual(summary.synced_worker_count, 1)
            self.assertEqual(summary.synced_worker_heartbeat_count, 1)
            self.assertEqual(summary.synced_job_lease_event_count, 1)
            self.assertTrue(summary.maintenance_mode["active"])
            self.assertIn(
                "postgres_cutover_promoted",
                {record.event_type for record in target_repo.list_control_plane_maintenance_events(limit=None)},
            )
            self.assertEqual(len(target_repo.list()), 1)
            self.assertEqual(len(target_repo.list_workers()), 1)
            self.assertEqual(len(target_repo.list_worker_heartbeats()), 1)
            self.assertEqual(len(target_repo.list_job_lease_events()), 1)

    def test_sync_control_plane_slice_raises_when_runtime_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(Path(tmpdir) / "source")
            source_repo = JobRepository(settings)
            service = PostgresRuntimeShadowService(
                settings=settings,
                source_job_repository=source_repo,
                runtime_support_inspector=lambda **_: type(
                    "UnavailableSupport",
                    (),
                    {
                        "backend": "postgres",
                        "url": "postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                        "redacted_url": "postgresql://lsa:***@db.example.com:5432/lsa_prod",
                        "runtime_supported": False,
                        "runtime_driver": "psycopg",
                        "runtime_dependency_installed": False,
                        "runtime_available": False,
                        "blockers": ["unsupported_runtime_backend:postgres", "missing_runtime_dependency:psycopg"],
                    },
                )(),
            )
            with self.assertRaisesRegex(ValueError, "unsupported_runtime_backend:postgres"):
                service.sync_control_plane_slice(
                    target_database_url="postgresql://lsa:secret@db.example.com:5432/lsa_prod",
                    changed_by="operator-a",
                )
