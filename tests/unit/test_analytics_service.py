from datetime import UTC, datetime, timedelta
import tempfile
import unittest

from lsa.services.analytics_service import AnalyticsService, ControlPlaneAlertThresholds
from lsa.settings import resolve_workspace_settings
from lsa.storage.files import JobRepository
from lsa.storage.models import (
    ControlPlaneOnCallChangeRequestRecord,
    ControlPlaneOnCallScheduleRecord,
    JobLeaseEventRecord,
    JobRecord,
    WorkerHeartbeatRecord,
    WorkerRecord,
)


class AnalyticsServiceTests(unittest.TestCase):
    def test_build_control_plane_analytics_merges_raw_and_rollups(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            service = AnalyticsService(job_repository=repo, heartbeat_timeout_seconds=60)

            now = datetime.now(UTC)
            today = now.date()
            old_day = today - timedelta(days=2)

            old_timestamp = datetime(old_day.year, old_day.month, old_day.day, 12, 0, tzinfo=UTC).isoformat()
            current_timestamp = (now - timedelta(seconds=10)).isoformat()
            stale_timestamp = (now - timedelta(days=3)).isoformat()
            cutoff_timestamp = datetime(
                (today - timedelta(days=1)).year,
                (today - timedelta(days=1)).month,
                (today - timedelta(days=1)).day,
                0,
                0,
                tzinfo=UTC,
            ).isoformat()

            repo.save_worker(
                WorkerRecord(
                    worker_id="worker-active",
                    mode="standalone",
                    status="running",
                    started_at=current_timestamp,
                    last_heartbeat_at=current_timestamp,
                    host_name="host-a",
                    process_id=101,
                    current_job_id="job-running",
                )
            )
            repo.save_worker(
                WorkerRecord(
                    worker_id="worker-stale",
                    mode="standalone",
                    status="stopped",
                    started_at=stale_timestamp,
                    last_heartbeat_at=stale_timestamp,
                    host_name="host-b",
                    process_id=202,
                    current_job_id=None,
                )
            )

            repo.append_worker_heartbeat(
                WorkerHeartbeatRecord(
                    heartbeat_id="heartbeat-old",
                    worker_id="worker-stale",
                    recorded_at=old_timestamp,
                    status="running",
                    current_job_id="job-completed",
                )
            )
            repo.append_worker_heartbeat(
                WorkerHeartbeatRecord(
                    heartbeat_id="heartbeat-current",
                    worker_id="worker-active",
                    recorded_at=current_timestamp,
                    status="running",
                    current_job_id="job-running",
                )
            )
            repo.append_job_lease_event(
                JobLeaseEventRecord(
                    event_id="lease-old",
                    job_id="job-completed",
                    worker_id="worker-stale",
                    event_type="lease_claimed",
                    recorded_at=old_timestamp,
                    details={},
                )
            )
            repo.append_job_lease_event(
                JobLeaseEventRecord(
                    event_id="lease-current-claim",
                    job_id="job-running",
                    worker_id="worker-active",
                    event_type="lease_claimed",
                    recorded_at=current_timestamp,
                    details={},
                )
            )
            repo.append_job_lease_event(
                JobLeaseEventRecord(
                    event_id="lease-current-complete",
                    job_id="job-completed",
                    worker_id="worker-active",
                    event_type="job_completed",
                    recorded_at=current_timestamp,
                    details={},
                )
            )

            repo.compact_worker_heartbeats_before(cutoff_timestamp)
            repo.compact_job_lease_events_before(cutoff_timestamp)

            repo.save(
                JobRecord(
                    job_id="job-queued",
                    created_at=current_timestamp,
                    job_type="audit-trace",
                    status="queued",
                )
            )
            repo.save(
                JobRecord(
                    job_id="job-running",
                    created_at=current_timestamp,
                    job_type="audit-trace",
                    status="running",
                    started_at=current_timestamp,
                    claimed_by_worker_id="worker-active",
                    lease_expires_at=(now + timedelta(minutes=5)).isoformat(),
                )
            )
            repo.save(
                JobRecord(
                    job_id="job-completed",
                    created_at=old_timestamp,
                    job_type="collect-audit",
                    status="completed",
                    started_at=old_timestamp,
                    completed_at=current_timestamp,
                    claimed_by_worker_id="worker-active",
                )
            )
            repo.save(
                JobRecord(
                    job_id="job-failed",
                    created_at=current_timestamp,
                    job_type="collect-audit",
                    status="failed",
                    started_at=current_timestamp,
                    completed_at=current_timestamp,
                    error="boom",
                )
            )

            report = service.build_control_plane_analytics(days=7)
            payload = report.to_dict()

            self.assertEqual(payload["queue"]["total_jobs"], 4)
            self.assertEqual(payload["queue"]["queued_jobs"], 1)
            self.assertEqual(payload["queue"]["running_jobs"], 1)
            self.assertEqual(payload["queue"]["completed_jobs"], 1)
            self.assertEqual(payload["queue"]["failed_jobs"], 1)

            self.assertEqual(payload["workers"]["active_workers"], 1)
            self.assertEqual(payload["workers"]["busy_workers"], 1)
            self.assertEqual(payload["workers"]["idle_workers"], 0)
            self.assertEqual(payload["workers"]["stale_workers"], 1)
            self.assertEqual(payload["workers"]["total_workers_seen"], 2)

            worker_days = {item["day_bucket"]: item for item in payload["workers"]["days"]}
            self.assertEqual(worker_days[old_day.isoformat()]["total_heartbeats"], 1)
            self.assertEqual(worker_days[old_day.isoformat()]["active_worker_count"], 1)
            self.assertEqual(worker_days[old_day.isoformat()]["busy_worker_count"], 1)
            self.assertEqual(worker_days[today.isoformat()]["total_heartbeats"], 1)
            self.assertEqual(worker_days[today.isoformat()]["busy_worker_count"], 1)

            self.assertEqual(payload["leases"]["total_events"], 3)
            self.assertEqual(payload["leases"]["claimed_count"], 2)
            self.assertEqual(payload["leases"]["completed_count"], 1)
            lease_days = {item["day_bucket"]: item for item in payload["leases"]["days"]}
            self.assertEqual(lease_days[old_day.isoformat()]["claimed_count"], 1)
            self.assertEqual(lease_days[today.isoformat()]["claimed_count"], 1)
            self.assertEqual(lease_days[today.isoformat()]["completed_count"], 1)

            self.assertEqual(payload["jobs"]["submitted_count"], 4)
            self.assertEqual(payload["jobs"]["started_count"], 3)
            self.assertEqual(payload["jobs"]["completed_count"], 1)
            self.assertEqual(payload["jobs"]["failed_count"], 1)
            self.assertEqual(payload["jobs"]["success_rate"], 0.5)
            self.assertEqual(payload["evaluation"]["status"], "degraded")
            finding_codes = {item["code"] for item in payload["evaluation"]["findings"]}
            self.assertIn("stale_workers", finding_codes)

    def test_control_plane_analytics_flags_critical_conditions(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            service = AnalyticsService(
                job_repository=repo,
                heartbeat_timeout_seconds=5,
                default_thresholds=ControlPlaneAlertThresholds(
                    queue_warning_threshold=1,
                    queue_critical_threshold=2,
                    stale_worker_warning_threshold=1,
                    stale_worker_critical_threshold=1,
                    expired_lease_warning_threshold=1,
                    expired_lease_critical_threshold=1,
                    job_failure_rate_warning_threshold=0.2,
                    job_failure_rate_critical_threshold=0.4,
                    job_failure_rate_min_samples=2,
                ),
            )

            now = datetime.now(UTC)
            current_timestamp = now.isoformat()
            stale_timestamp = (now - timedelta(minutes=10)).isoformat()

            repo.save_worker(
                WorkerRecord(
                    worker_id="worker-stale",
                    mode="standalone",
                    status="stopped",
                    started_at=stale_timestamp,
                    last_heartbeat_at=stale_timestamp,
                    host_name="host-critical",
                    process_id=404,
                    current_job_id=None,
                )
            )
            repo.append_job_lease_event(
                JobLeaseEventRecord(
                    event_id="lease-expired",
                    job_id="job-a",
                    worker_id="worker-stale",
                    event_type="lease_expired_requeued",
                    recorded_at=current_timestamp,
                    details={},
                )
            )
            repo.save(
                JobRecord(
                    job_id="job-a",
                    created_at=current_timestamp,
                    job_type="audit-trace",
                    status="queued",
                )
            )
            repo.save(
                JobRecord(
                    job_id="job-b",
                    created_at=current_timestamp,
                    job_type="audit-trace",
                    status="queued",
                )
            )
            repo.save(
                JobRecord(
                    job_id="job-c",
                    created_at=current_timestamp,
                    job_type="audit-trace",
                    status="failed",
                    started_at=current_timestamp,
                    completed_at=current_timestamp,
                    error="boom",
                )
            )
            repo.save(
                JobRecord(
                    job_id="job-d",
                    created_at=current_timestamp,
                    job_type="audit-trace",
                    status="failed",
                    started_at=current_timestamp,
                    completed_at=current_timestamp,
                    error="boom",
                )
            )
            repo.save(
                JobRecord(
                    job_id="job-e",
                    created_at=current_timestamp,
                    job_type="audit-trace",
                    status="completed",
                    started_at=current_timestamp,
                    completed_at=current_timestamp,
                )
            )

            payload = service.build_control_plane_analytics(days=7).to_dict()
            self.assertEqual(payload["evaluation"]["status"], "critical")
            finding_codes = {item["code"] for item in payload["evaluation"]["findings"]}
            self.assertIn("queue_backlog", finding_codes)
            self.assertIn("stale_workers", finding_codes)
            self.assertIn("expired_leases", finding_codes)
            self.assertIn("job_failure_rate", finding_codes)
            self.assertIn("queue_without_active_workers", finding_codes)

    def test_control_plane_analytics_flags_ambiguous_oncall_conflicts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            service = AnalyticsService(
                job_repository=repo,
                heartbeat_timeout_seconds=5,
                default_thresholds=ControlPlaneAlertThresholds(
                    oncall_conflict_warning_threshold=1,
                    oncall_conflict_critical_threshold=2,
                ),
            )

            repo.append_control_plane_oncall_schedule(
                ControlPlaneOnCallScheduleRecord(
                    schedule_id="schedule-a",
                    created_at="2026-05-05T00:00:00+00:00",
                    created_by="operator-a",
                    team_name="platform-a",
                    timezone_name="UTC",
                    weekdays=[0, 1, 2, 3, 4, 5, 6],
                    start_time="00:00",
                    end_time="23:59",
                    priority=100,
                    rotation_name="primary-a",
                )
            )
            repo.append_control_plane_oncall_schedule(
                ControlPlaneOnCallScheduleRecord(
                    schedule_id="schedule-b",
                    created_at="2026-05-06T00:00:00+00:00",
                    created_by="operator-b",
                    team_name="platform-b",
                    timezone_name="UTC",
                    weekdays=[0, 1, 2, 3, 4, 5, 6],
                    start_time="00:00",
                    end_time="23:59",
                    priority=100,
                    rotation_name="primary-b",
                )
            )

            payload = service.build_control_plane_analytics(days=7).to_dict()
            self.assertEqual(payload["evaluation"]["status"], "degraded")
            self.assertEqual(payload["oncall"]["conflict_count"], 1)
            self.assertGreaterEqual(payload["oncall"]["active_schedules"], 2)
            finding_codes = {item["code"] for item in payload["evaluation"]["findings"]}
            self.assertIn("oncall_route_conflicts", finding_codes)

    def test_control_plane_analytics_scopes_oncall_to_environment_and_flags_stale_reviews(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            service = AnalyticsService(
                job_repository=repo,
                default_environment_name="prod",
                heartbeat_timeout_seconds=5,
                default_thresholds=ControlPlaneAlertThresholds(
                    oncall_conflict_warning_threshold=1,
                    oncall_conflict_critical_threshold=2,
                    oncall_pending_review_warning_threshold=1,
                    oncall_pending_review_critical_threshold=2,
                    oncall_pending_review_sla_hours=1.0,
                ),
            )

            repo.append_control_plane_oncall_schedule(
                ControlPlaneOnCallScheduleRecord(
                    schedule_id="schedule-prod-a",
                    created_at="2026-05-05T00:00:00+00:00",
                    created_by="operator-a",
                    environment_name="prod",
                    team_name="platform-a",
                    timezone_name="UTC",
                    weekdays=[0, 1, 2, 3, 4, 5, 6],
                    start_time="00:00",
                    end_time="23:59",
                    priority=100,
                    rotation_name="primary-a",
                )
            )
            repo.append_control_plane_oncall_schedule(
                ControlPlaneOnCallScheduleRecord(
                    schedule_id="schedule-staging-b",
                    created_at="2026-05-06T00:00:00+00:00",
                    created_by="operator-b",
                    environment_name="staging",
                    team_name="platform-b",
                    timezone_name="UTC",
                    weekdays=[0, 1, 2, 3, 4, 5, 6],
                    start_time="00:00",
                    end_time="23:59",
                    priority=100,
                    rotation_name="primary-b",
                )
            )
            repo.append_control_plane_oncall_change_request(
                ControlPlaneOnCallChangeRequestRecord(
                    request_id="request-prod-stale",
                    created_at=(datetime.now(UTC) - timedelta(hours=3)).isoformat(),
                    created_by="operator-c",
                    environment_name="prod",
                    team_name="platform-a",
                    timezone_name="UTC",
                    status="pending_review",
                    change_reason="Prod overlap waiting on approval.",
                    review_required=True,
                    review_reasons=["ambiguous_overlap"],
                    assigned_to="reviewer-prod",
                    assigned_to_team="platform",
                    weekdays=[0, 1, 2, 3, 4, 5, 6],
                    start_time="00:00",
                    end_time="23:59",
                    priority=100,
                    rotation_name="primary-c",
                )
            )
            repo.append_control_plane_oncall_change_request(
                ControlPlaneOnCallChangeRequestRecord(
                    request_id="request-staging-stale",
                    created_at=(datetime.now(UTC) - timedelta(hours=5)).isoformat(),
                    created_by="operator-d",
                    environment_name="staging",
                    team_name="platform-b",
                    timezone_name="UTC",
                    status="pending_review",
                    change_reason="Staging overlap waiting on approval.",
                    review_required=True,
                    review_reasons=["ambiguous_overlap"],
                    weekdays=[0, 1, 2, 3, 4, 5, 6],
                    start_time="00:00",
                    end_time="23:59",
                    priority=100,
                    rotation_name="primary-d",
                )
            )

            payload = service.build_control_plane_analytics(days=7).to_dict()
            self.assertEqual(payload["oncall"]["total_schedules"], 1)
            self.assertEqual(payload["oncall"]["conflict_count"], 0)
            self.assertEqual(payload["oncall"]["pending_review_count"], 1)
            self.assertEqual(payload["oncall"]["stale_pending_review_count"], 1)
            self.assertGreaterEqual(payload["oncall"]["oldest_pending_review_age_hours"], 3.0)
            self.assertEqual(payload["oncall"]["pending_review_samples"][0]["assigned_to"], "reviewer-prod")
            finding_codes = {item["code"] for item in payload["evaluation"]["findings"]}
            self.assertIn("oncall_pending_reviews_stale", finding_codes)


if __name__ == "__main__":
    unittest.main()
