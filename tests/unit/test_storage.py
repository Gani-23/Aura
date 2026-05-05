import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from lsa.core.intent_graph import IntentGraph
from lsa.ingest.graph_builder import GraphBuilder
from lsa.settings import resolve_workspace_settings
from lsa.storage.files import AuditRepository, JobRepository, SnapshotRepository
from lsa.storage.models import (
    ControlPlaneAlertRecord,
    ControlPlaneAlertSilenceRecord,
    ControlPlaneOnCallChangeRequestRecord,
    ControlPlaneOnCallScheduleRecord,
    JobLeaseEventRecord,
    WorkerHeartbeatRecord,
    WorkerRecord,
)
from lsa.storage.models import AuditRecord


class StorageTests(unittest.TestCase):
    def test_snapshot_repository_persists_and_lists_records(self) -> None:
        root = Path("tests/fixtures/sample_service").resolve()
        snapshot = GraphBuilder().build(root)

        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = SnapshotRepository(settings, graph=IntentGraph())
            record = repo.save(snapshot, repo_path=str(root), snapshot_id="snap-test")

            self.assertEqual(record.snapshot_id, "snap-test")
            self.assertTrue(settings.database_path.exists())
            listed = repo.list()
            self.assertEqual(len(listed), 1)
            self.assertEqual(listed[0].snapshot_id, "snap-test")
            with sqlite3.connect(settings.database_path) as connection:
                row = connection.execute(
                    "SELECT snapshot_id, repo_path FROM snapshots WHERE snapshot_id = ?",
                    ("snap-test",),
                ).fetchone()
            assert row is not None
            self.assertEqual(row[0], "snap-test")
            self.assertEqual(row[1], str(root))

    def test_audit_repository_persists_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = AuditRepository(settings)
            record = AuditRecord(
                audit_id="audit-test",
                created_at="2026-01-01T00:00:00+00:00",
                snapshot_id="snap-test",
                snapshot_path="/tmp/snap.json",
                alert_count=1,
                report_paths=["/tmp/report.md"],
                alerts=[{"function": "f"}],
                events=[{"function": "f"}],
                sessions=[{"session_key": "request_id:req-123"}],
                explanation={"status": "clean", "summary": "No drift alerts detected."},
            )
            repo.save(record)

            fetched = repo.get("audit-test")
            self.assertEqual(fetched.audit_id, "audit-test")
            self.assertEqual(fetched.explanation["status"], "clean")
            self.assertEqual(len(repo.list()), 1)
            with sqlite3.connect(settings.database_path) as connection:
                row = connection.execute(
                    "SELECT audit_id, alert_count FROM audits WHERE audit_id = ?",
                    ("audit-test",),
                ).fetchone()
            assert row is not None
            self.assertEqual(row[0], "audit-test")
            self.assertEqual(row[1], 1)

    def test_job_repository_persists_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            record = repo.create(
                job_type="collect-audit",
                request_payload={"snapshot_id": "snap-test", "pid": 1234},
                job_id="job-test",
            )

            fetched = repo.get("job-test")
            self.assertEqual(fetched.job_id, "job-test")
            self.assertEqual(fetched.status, "queued")
            self.assertEqual(fetched.request_payload["pid"], 1234)
            self.assertEqual(len(repo.list()), 1)
            with sqlite3.connect(settings.database_path) as connection:
                row = connection.execute(
                    "SELECT job_id, job_type, status FROM jobs WHERE job_id = ?",
                    ("job-test",),
                ).fetchone()
            assert row is not None
            self.assertEqual(row[0], "job-test")
            self.assertEqual(row[1], "collect-audit")
            self.assertEqual(row[2], "queued")

    def test_job_repository_persists_worker_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            record = WorkerRecord(
                worker_id="worker-test",
                mode="standalone",
                status="running",
                started_at="2026-05-04T00:00:00+00:00",
                last_heartbeat_at="2026-05-04T00:00:01+00:00",
                host_name="localhost",
                process_id=4242,
                current_job_id="job-test",
            )
            repo.save_worker(record)

            fetched = repo.get_worker("worker-test")
            self.assertEqual(fetched.worker_id, "worker-test")
            self.assertEqual(fetched.current_job_id, "job-test")
            self.assertEqual(len(repo.list_workers()), 1)
            self.assertEqual(repo.count_workers_seen_since("2026-05-04T00:00:00+00:00"), 1)

    def test_job_repository_persists_heartbeat_and_lease_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            heartbeat = WorkerHeartbeatRecord(
                heartbeat_id="heartbeat-test",
                worker_id="worker-test",
                recorded_at="2026-05-04T00:00:02+00:00",
                status="running",
                current_job_id="job-test",
            )
            lease_event = JobLeaseEventRecord(
                event_id="lease-event-test",
                job_id="job-test",
                worker_id="worker-test",
                event_type="lease_claimed",
                recorded_at="2026-05-04T00:00:03+00:00",
                details={"lease_expires_at": "2026-05-04T00:00:08+00:00"},
            )

            repo.append_worker_heartbeat(heartbeat)
            repo.append_job_lease_event(lease_event)

            heartbeats = repo.list_worker_heartbeats("worker-test")
            lease_events = repo.list_job_lease_events("job-test")
            self.assertEqual(len(heartbeats), 1)
            self.assertEqual(heartbeats[0].heartbeat_id, "heartbeat-test")
            self.assertEqual(len(lease_events), 1)
            self.assertEqual(lease_events[0].event_id, "lease-event-test")

    def test_job_repository_prunes_old_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            repo.append_worker_heartbeat(
                WorkerHeartbeatRecord(
                    heartbeat_id="heartbeat-old",
                    worker_id="worker-test",
                    recorded_at="2020-01-01T00:00:00+00:00",
                    status="running",
                    current_job_id=None,
                )
            )
            repo.append_job_lease_event(
                JobLeaseEventRecord(
                    event_id="lease-event-old",
                    job_id="job-test",
                    worker_id="worker-test",
                    event_type="lease_claimed",
                    recorded_at="2020-01-01T00:00:00+00:00",
                    details={},
                )
            )

            self.assertEqual(repo.prune_worker_heartbeats_before("2021-01-01T00:00:00+00:00"), 1)
            self.assertEqual(repo.prune_job_lease_events_before("2021-01-01T00:00:00+00:00"), 1)
            self.assertEqual(len(repo.list_worker_heartbeats("worker-test")), 0)
            self.assertEqual(len(repo.list_job_lease_events("job-test")), 0)

    def test_job_repository_compacts_old_history_into_rollups(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            repo.append_worker_heartbeat(
                WorkerHeartbeatRecord(
                    heartbeat_id="heartbeat-old-1",
                    worker_id="worker-test",
                    recorded_at="2020-01-01T00:00:00+00:00",
                    status="running",
                    current_job_id=None,
                )
            )
            repo.append_worker_heartbeat(
                WorkerHeartbeatRecord(
                    heartbeat_id="heartbeat-old-2",
                    worker_id="worker-test",
                    recorded_at="2020-01-01T01:00:00+00:00",
                    status="running",
                    current_job_id=None,
                )
            )
            repo.append_job_lease_event(
                JobLeaseEventRecord(
                    event_id="lease-event-old-1",
                    job_id="job-test",
                    worker_id="worker-test",
                    event_type="lease_claimed",
                    recorded_at="2020-01-01T00:00:00+00:00",
                    details={},
                )
            )
            repo.append_job_lease_event(
                JobLeaseEventRecord(
                    event_id="lease-event-old-2",
                    job_id="job-test",
                    worker_id="worker-test",
                    event_type="lease_claimed",
                    recorded_at="2020-01-01T02:00:00+00:00",
                    details={},
                )
            )

            self.assertEqual(repo.compact_worker_heartbeats_before("2021-01-01T00:00:00+00:00"), 2)
            self.assertEqual(repo.compact_job_lease_events_before("2021-01-01T00:00:00+00:00"), 2)
            worker_rollups = repo.list_worker_heartbeat_rollups("worker-test")
            lease_rollups = repo.list_job_lease_event_rollups("job-test")
            self.assertEqual(len(repo.list_worker_heartbeats("worker-test")), 0)
            self.assertEqual(len(repo.list_job_lease_events("job-test")), 0)
            self.assertEqual(len(worker_rollups), 1)
            self.assertEqual(worker_rollups[0].event_count, 2)
            self.assertEqual(len(lease_rollups), 1)
            self.assertEqual(lease_rollups[0].event_count, 2)

    def test_job_repository_persists_control_plane_alerts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            alert = ControlPlaneAlertRecord(
                alert_id="alert-test",
                created_at="2026-05-04T00:00:00+00:00",
                alert_key="control-plane:critical:queue_backlog",
                status="critical",
                severity="critical",
                summary="Queued job backlog is above the configured critical threshold.",
                finding_codes=["queue_backlog"],
                delivery_state="delivered",
                payload={"report": {"evaluation": {"status": "critical"}}},
                error=None,
            )
            repo.append_control_plane_alert(alert)

            listed = repo.list_control_plane_alerts()
            self.assertEqual(len(listed), 1)
            self.assertEqual(listed[0].alert_id, "alert-test")
            self.assertEqual(repo.latest_control_plane_alert_by_key(alert.alert_key).alert_id, "alert-test")  # type: ignore[union-attr]
            acknowledged = repo.acknowledge_control_plane_alert(
                alert_id="alert-test",
                acknowledged_at="2026-05-04T00:05:00+00:00",
                acknowledged_by="operator-a",
                acknowledgement_note="Acked for review",
            )
            self.assertEqual(acknowledged.acknowledged_by, "operator-a")

    def test_job_repository_persists_control_plane_alert_silences(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            silence = ControlPlaneAlertSilenceRecord(
                silence_id="silence-test",
                created_at="2026-05-04T00:00:00+00:00",
                created_by="operator-a",
                reason="Deployment",
                match_finding_code="queue_backlog",
                starts_at="2026-05-04T00:00:00+00:00",
                expires_at="2026-05-04T01:00:00+00:00",
            )
            repo.append_control_plane_alert_silence(silence)
            self.assertEqual(len(repo.list_control_plane_alert_silences()), 1)
            cancelled = repo.cancel_control_plane_alert_silence(
                silence_id="silence-test",
                cancelled_at="2026-05-04T00:30:00+00:00",
                cancelled_by="operator-a",
            )
            self.assertEqual(cancelled.cancelled_by, "operator-a")

    def test_job_repository_persists_control_plane_oncall_schedules(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            schedule = ControlPlaneOnCallScheduleRecord(
                schedule_id="schedule-test",
                created_at="2026-05-04T00:00:00+00:00",
                created_by="operator-a",
                environment_name="prod",
                created_by_team="platform",
                created_by_role="engineer",
                change_reason="Primary daytime rotation",
                approved_by="director-a",
                approved_by_team="platform",
                approved_by_role="director",
                approved_at="2026-05-03T12:00:00+00:00",
                approval_note="Approved during weekly ops review",
                team_name="platform",
                timezone_name="UTC",
                weekdays=[0, 1, 2],
                start_time="09:00",
                end_time="17:00",
                priority=150,
                rotation_name="primary",
                effective_start_date="2026-05-01",
                effective_end_date="2026-05-31",
                webhook_url="https://example.com/team",
                escalation_webhook_url="https://example.com/escalate",
            )
            repo.append_control_plane_oncall_schedule(schedule)
            stored = repo.list_control_plane_oncall_schedules()
            self.assertEqual(len(stored), 1)
            self.assertEqual(stored[0].priority, 150)
            self.assertEqual(stored[0].rotation_name, "primary")
            self.assertEqual(stored[0].effective_start_date, "2026-05-01")
            self.assertEqual(stored[0].approved_by, "director-a")
            self.assertEqual(stored[0].environment_name, "prod")
            self.assertEqual(stored[0].created_by_team, "platform")
            self.assertEqual(stored[0].approved_by_role, "director")
            cancelled = repo.cancel_control_plane_oncall_schedule(
                schedule_id="schedule-test",
                cancelled_at="2026-05-04T12:00:00+00:00",
                cancelled_by="operator-a",
            )
            self.assertEqual(cancelled.cancelled_by, "operator-a")

    def test_job_repository_persists_control_plane_oncall_change_requests(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            request = ControlPlaneOnCallChangeRequestRecord(
                request_id="request-test",
                created_at="2026-05-04T00:00:00+00:00",
                created_by="operator-a",
                environment_name="prod",
                created_by_team="platform",
                created_by_role="engineer",
                change_reason="Temporary dual coverage during cutover.",
                status="pending_review",
                review_required=True,
                review_reasons=["ambiguous_overlap"],
                team_name="platform",
                timezone_name="UTC",
                weekdays=[0, 1, 2, 3, 4],
                start_time="09:00",
                end_time="17:00",
                priority=200,
                rotation_name="holiday",
                effective_start_date="2026-05-04",
                effective_end_date="2026-05-04",
                webhook_url="https://example.com/team",
                escalation_webhook_url="https://example.com/escalate",
            )
            repo.append_control_plane_oncall_change_request(request)
            stored = repo.list_control_plane_oncall_change_requests()
            self.assertEqual(len(stored), 1)
            self.assertEqual(stored[0].status, "pending_review")
            self.assertEqual(stored[0].environment_name, "prod")
            self.assertEqual(stored[0].review_reasons, ["ambiguous_overlap"])
            decided = repo.decide_control_plane_oncall_change_request(
                request_id="request-test",
                status="applied",
                decision_at="2026-05-04T00:05:00+00:00",
                decided_by="director-a",
                decided_by_team="platform",
                decided_by_role="director",
                decision_note="Approved for cutover.",
                applied_schedule_id="schedule-test",
            )
            self.assertEqual(decided.decided_by, "director-a")
            self.assertEqual(decided.applied_schedule_id, "schedule-test")

    def test_snapshot_repository_imports_legacy_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            settings.snapshots_dir.mkdir(parents=True, exist_ok=True)
            legacy_payload = {
                "snapshot_id": "legacy-snap",
                "created_at": "2026-01-02T00:00:00+00:00",
                "repo_path": "/tmp/legacy-service",
                "node_count": 3,
                "edge_count": 2,
                "snapshot_path": "/tmp/legacy-service/snapshot.json",
            }
            legacy_path = settings.snapshots_dir / "legacy-snap.meta.json"
            legacy_path.write_text(json.dumps(legacy_payload), encoding="utf-8")

            repo = SnapshotRepository(settings, graph=IntentGraph())

            fetched = repo.get("legacy-snap")
            self.assertEqual(fetched.snapshot_id, "legacy-snap")
            self.assertEqual(repo.list()[0].repo_path, "/tmp/legacy-service")

    def test_audit_repository_imports_legacy_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            settings.audits_dir.mkdir(parents=True, exist_ok=True)
            legacy_payload = {
                "audit_id": "legacy-audit",
                "created_at": "2026-01-03T00:00:00+00:00",
                "snapshot_id": "legacy-snap",
                "snapshot_path": "/tmp/legacy-service/snapshot.json",
                "alert_count": 1,
                "report_paths": ["/tmp/report.md"],
                "alerts": [{"function": "charge_customer"}],
                "events": [{"function": "charge_customer"}],
                "sessions": [{"session_key": "request_id:req-123"}],
                "explanation": {"status": "drift_detected", "summary": "Unexpected target observed."},
            }
            legacy_path = settings.audits_dir / "legacy-audit.json"
            legacy_path.write_text(json.dumps(legacy_payload), encoding="utf-8")

            repo = AuditRepository(settings)

            fetched = repo.get("legacy-audit")
            self.assertEqual(fetched.audit_id, "legacy-audit")
            self.assertEqual(fetched.explanation["status"], "drift_detected")
            self.assertEqual(repo.list()[0].audit_id, "legacy-audit")
