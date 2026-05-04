from pathlib import Path
import tempfile
import time
import unittest

from lsa.core.intent_graph import IntentGraph
from lsa.drift.comparator import DriftComparator
from lsa.remediation.llm_client import RuleBasedLLMClient
from lsa.services.audit_service import AuditService
from lsa.services.job_service import JobService
from lsa.services.trace_collection_service import TraceCollectionService
from lsa.settings import resolve_workspace_settings
from lsa.storage.files import AuditRepository, JobRepository, SnapshotRepository


class SlowJobService(JobService):
    def _run_job(self, record) -> dict:  # type: ignore[override]
        time.sleep(0.35)
        return {"job_id": record.job_id, "status": "simulated"}


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
            lease_events = job_repository.list_job_lease_events("job-recovery")
            self.assertTrue(any(event.event_type == "lease_claimed" for event in lease_events))
            self.assertTrue(any(event.event_type == "job_completed" for event in lease_events))
            heartbeats = job_repository.list_worker_heartbeats(service.worker_id())
            self.assertGreaterEqual(len(heartbeats), 2)

    def test_worker_takes_over_expired_lease(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            job_repository = JobRepository(settings)
            service = JobService(
                job_repository=job_repository,
                audit_service=AuditService(
                    graph=IntentGraph(),
                    snapshot_repository=SnapshotRepository(settings, graph=IntentGraph()),
                    audit_repository=AuditRepository(settings),
                    drift_comparator=DriftComparator(),
                    remediation_client=RuleBasedLLMClient(),
                    settings=settings,
                ),
                trace_collection_service=TraceCollectionService(settings=settings),
                worker_mode="standalone",
                poll_interval_seconds=0.01,
                heartbeat_timeout_seconds=0.2,
            )

            job = job_repository.create(
                job_type="audit-trace",
                request_payload={},
                job_id="job-stale-lease",
            )
            job.status = "running"
            job.started_at = "2026-05-04T00:00:00+00:00"
            job.claimed_by_worker_id = "dead-worker"
            job.lease_expires_at = "2026-05-04T00:00:01+00:00"
            job_repository.save(job)

            service._mark_worker_running(current_job_id=None)
            processed = service.process_next_job()
            self.assertTrue(processed)
            service._mark_worker_stopped()
            claimed = job_repository.get("job-stale-lease")
            self.assertEqual(claimed.status, "failed")
            self.assertEqual(claimed.claimed_by_worker_id, service.worker_id())
            lease_events = job_repository.list_job_lease_events("job-stale-lease")
            self.assertTrue(any(event.event_type == "lease_expired_requeued" for event in lease_events))

    def test_worker_renews_lease_for_long_running_job(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            job_repository = JobRepository(settings)
            service = SlowJobService(
                job_repository=job_repository,
                audit_service=AuditService(
                    graph=IntentGraph(),
                    snapshot_repository=SnapshotRepository(settings, graph=IntentGraph()),
                    audit_repository=AuditRepository(settings),
                    drift_comparator=DriftComparator(),
                    remediation_client=RuleBasedLLMClient(),
                    settings=settings,
                ),
                trace_collection_service=TraceCollectionService(settings=settings),
                worker_mode="standalone",
                poll_interval_seconds=0.01,
                heartbeat_timeout_seconds=0.2,
            )
            job_repository.create(
                job_type="audit-trace",
                request_payload={},
                job_id="job-renew",
            )

            service.start()
            try:
                for _ in range(30):
                    running = job_repository.get("job-renew")
                    if running.status == "running":
                        break
                    time.sleep(0.02)
                first_seen = job_repository.get("job-renew")
                self.assertEqual(first_seen.status, "running")
                first_lease = first_seen.lease_expires_at
                self.assertIsNotNone(first_lease)

                time.sleep(0.15)
                renewed = job_repository.get("job-renew")
                self.assertEqual(renewed.status, "running")
                self.assertIsNotNone(renewed.lease_expires_at)
                self.assertGreater(str(renewed.lease_expires_at), str(first_lease))

                completed = service.wait_for_job("job-renew", timeout_seconds=2)
            finally:
                service.stop()

            self.assertEqual(completed.status, "completed")
            self.assertEqual(completed.claimed_by_worker_id, service.worker_id())
            lease_events = job_repository.list_job_lease_events("job-renew")
            self.assertTrue(any(event.event_type == "lease_renewed" for event in lease_events))


if __name__ == "__main__":
    unittest.main()
