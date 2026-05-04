from pathlib import Path
import tempfile
import unittest

from lsa.core.intent_graph import IntentGraph
from lsa.drift.comparator import DriftComparator
from lsa.remediation.llm_client import RuleBasedLLMClient
from lsa.services.audit_service import AuditService
from lsa.services.job_service import JobService
from lsa.services.trace_collection_service import TraceCollectionService
from lsa.settings import resolve_workspace_settings
from lsa.storage.files import AuditRepository, JobRepository, SnapshotRepository


class JobServiceTests(unittest.TestCase):
    def test_worker_recovers_stale_running_job(self) -> None:
        fixture_root = Path("tests/fixtures/sample_service").resolve()
        trace_path = Path("tests/fixtures/sample_trace.log").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
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

            snapshot = graph.build_from_path(str(fixture_root))
            snapshot_repository.save(snapshot, repo_path=str(fixture_root), snapshot_id="snap-recovery")

            job = job_repository.create(
                job_type="audit-trace",
                request_payload={
                    "snapshot_id": "snap-recovery",
                    "trace_path": str(trace_path),
                    "trace_format": "auto",
                    "persist": True,
                    "audit_id": "audit-recovery",
                },
                job_id="job-recovery",
            )
            job.status = "running"
            job.started_at = "2026-05-03T00:00:00+00:00"
            job_repository.save(job)

            service = JobService(
                job_repository=job_repository,
                audit_service=audit_service,
                trace_collection_service=trace_collection_service,
                worker_mode="standalone",
                poll_interval_seconds=0.01,
                heartbeat_timeout_seconds=settings.worker_heartbeat_timeout_seconds,
            )
            service.start()
            try:
                completed = service.wait_for_job("job-recovery", timeout_seconds=2)
            finally:
                service.stop()

            self.assertEqual(completed.status, "completed")
            self.assertEqual(completed.result_payload["audit_id"], "audit-recovery")
            self.assertEqual(completed.result_payload["alert_count"], 1)
            self.assertEqual(completed.claimed_by_worker_id, service.worker_id())
            worker = job_repository.get_worker(service.worker_id())
            self.assertEqual(worker.status, "stopped")


if __name__ == "__main__":
    unittest.main()
