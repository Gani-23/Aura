from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest

from lsa.cli import main as cli_main
from lsa.settings import resolve_workspace_settings


class CliFlowTests(unittest.TestCase):
    def test_ingest_and_audit_create_reports(self) -> None:
        root = Path("tests/fixtures/sample_service").resolve()
        events = Path("tests/fixtures/sample_events.json").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.snapshot_repository = cli_main.SnapshotRepository(cli_main.settings, graph=cli_main.graph)
            cli_main.audit_repository = cli_main.AuditRepository(cli_main.settings)
            cli_main.ingest_service = cli_main.IngestService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
            )
            cli_main.audit_service = cli_main.AuditService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
                audit_repository=cli_main.audit_repository,
                drift_comparator=cli_main.DriftComparator(),
                remediation_client=cli_main.RuleBasedLLMClient(),
                settings=cli_main.settings,
            )
            snapshot_path = Path(tmpdir) / "snapshot.json"
            report_dir = Path(tmpdir) / "reports"

            ingest_sink = StringIO()
            with redirect_stdout(ingest_sink):
                self.assertEqual(
                    cli_main.run_ingest(
                        str(root),
                        str(snapshot_path),
                        persist=False,
                        snapshot_id=None,
                    ),
                    0,
                )
            self.assertTrue(snapshot_path.exists(), ingest_sink.getvalue())

            audit_sink = StringIO()
            with redirect_stdout(audit_sink):
                self.assertEqual(
                    cli_main.run_audit(
                        str(snapshot_path),
                        str(events),
                        snapshot_is_id=False,
                        out_dir=str(report_dir),
                        persist=False,
                        audit_id=None,
                    ),
                    0,
                )
            reports = list(report_dir.glob("*.md"))
            self.assertEqual(len(reports), 1)
            payload = json.loads(audit_sink.getvalue())
            self.assertIn("explanation", payload)
            self.assertEqual(payload["explanation"]["status"], "drift_detected")

    def test_standalone_worker_processes_queued_job(self) -> None:
        fixture_root = Path("tests/fixtures/sample_service").resolve()
        trace_path = Path("tests/fixtures/sample_trace.log").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.snapshot_repository = cli_main.SnapshotRepository(cli_main.settings, graph=cli_main.graph)
            cli_main.audit_repository = cli_main.AuditRepository(cli_main.settings)
            cli_main.job_repository = cli_main.JobRepository(cli_main.settings)
            cli_main.ingest_service = cli_main.IngestService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
            )
            cli_main.audit_service = cli_main.AuditService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
                audit_repository=cli_main.audit_repository,
                drift_comparator=cli_main.DriftComparator(),
                remediation_client=cli_main.RuleBasedLLMClient(),
                settings=cli_main.settings,
            )
            cli_main.trace_collection_service = cli_main.TraceCollectionService(settings=cli_main.settings)
            cli_main.job_service = cli_main.JobService(
                job_repository=cli_main.job_repository,
                audit_service=cli_main.audit_service,
                trace_collection_service=cli_main.trace_collection_service,
                worker_mode="standalone",
                poll_interval_seconds=0.01,
                heartbeat_timeout_seconds=cli_main.settings.worker_heartbeat_timeout_seconds,
            )

            cli_main.ingest_service.ingest(str(fixture_root), persist=True, snapshot_id="snap-worker")
            cli_main.job_repository.create(
                job_type="audit-trace",
                request_payload={
                    "snapshot_id": "snap-worker",
                    "trace_path": str(trace_path),
                    "trace_format": "auto",
                    "persist": True,
                    "audit_id": "audit-worker",
                },
                job_id="job-worker",
            )

            worker_sink = StringIO()
            with redirect_stdout(worker_sink):
                self.assertEqual(
                    cli_main.run_worker(
                        poll_interval=0.01,
                        idle_timeout=0.2,
                        max_jobs=None,
                        once=False,
                    ),
                    0,
                )

            payload = json.loads(worker_sink.getvalue())
            self.assertEqual(payload["worker_mode"], "standalone")
            self.assertIsNotNone(payload["worker_id"])
            self.assertEqual(payload["processed_jobs"], 1)
            self.assertEqual(payload["active_workers"], 0)
            self.assertEqual(payload["queued_jobs"], 0)
            self.assertEqual(payload["completed_jobs"], 1)
            self.assertEqual(cli_main.job_repository.get("job-worker").status, "completed")
            self.assertIsNotNone(cli_main.job_repository.get("job-worker").claimed_by_worker_id)
            self.assertEqual(cli_main.audit_repository.get("audit-worker").audit_id, "audit-worker")
            worker_records = cli_main.job_repository.list_workers()
            self.assertEqual(len(worker_records), 1)
            self.assertEqual(worker_records[0].mode, "standalone")
            self.assertEqual(worker_records[0].status, "stopped")


if __name__ == "__main__":
    unittest.main()
