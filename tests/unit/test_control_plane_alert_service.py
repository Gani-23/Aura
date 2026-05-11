from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import tempfile
import unittest

from lsa.services.analytics_service import AnalyticsService, ControlPlaneAlertThresholds
from lsa.services.control_plane_alert_service import ControlPlaneAlertService
from lsa.services.control_plane_runtime_validation_review_service import (
    RuntimeValidationReviewAlertState,
    RuntimeValidationReviewRequest,
)
from lsa.settings import resolve_workspace_settings
from lsa.storage.files import JobRepository
from lsa.storage.models import (
    ControlPlaneAlertRecord,
    ControlPlaneMaintenanceEventRecord,
    ControlPlaneOnCallChangeRequestRecord,
    JobLeaseEventRecord,
    JobRecord,
    WorkerRecord,
)


class ControlPlaneAlertServiceTests(unittest.TestCase):
    def test_emit_alerts_emits_runtime_validation_review_chain_and_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            analytics_service = AnalyticsService(
                job_repository=repo,
                heartbeat_timeout_seconds=5,
                default_thresholds=ControlPlaneAlertThresholds(),
            )
            repo.append_control_plane_maintenance_event(
                ControlPlaneMaintenanceEventRecord(
                    event_id="runtime-rehearsal-current-review-alert",
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

            class FakeRuntimeValidationReviewService:
                def __init__(self, state):
                    self.state = state

                def build_alert_state(self, *, force: bool = False):
                    return self.state

            review = RuntimeValidationReviewRequest(
                review_id="review-prod-1",
                opened_at=(datetime.now(UTC) - timedelta(minutes=5)).isoformat(),
                opened_by="system",
                environment_name=settings.environment_name,
                status="pending_review",
                evidence_key="prod:evidence-1:due_soon",
                trigger_status="passed",
                trigger_cadence_status="due_soon",
                summary="Runtime proof is approaching its warning threshold and should be refreshed.",
            )
            review_state = RuntimeValidationReviewAlertState(
                review=review,
                policy_source="defaults",
                reminder_interval_seconds=60.0,
                escalation_interval_seconds=120.0,
                age_seconds=300.0,
                status="critical",
                severity="critical",
                finding_codes=["runtime_validation_review_unassigned_overdue"],
                summary="Runtime-proof review has been unassigned for 5 minutes and now requires escalation.",
            )
            review_service = FakeRuntimeValidationReviewService(review_state)
            service = ControlPlaneAlertService(
                job_repository=repo,
                analytics_service=analytics_service,
                window_days=7,
                sink_path=str(Path(tmpdir) / "runtime-review-alerts.jsonl"),
                runtime_validation_review_service=review_service,
            )

            emitted = service.emit_alerts(force=False)

            self.assertEqual(len(emitted), 1)
            self.assertEqual(emitted[0].payload["alert_family"], "runtime_validation_review")
            self.assertEqual(emitted[0].status, "critical")
            self.assertEqual(
                emitted[0].finding_codes,
                ["runtime_validation_review_unassigned_overdue"],
            )

            follow_ups = service.process_follow_ups(force=True)

            self.assertEqual(len(follow_ups), 1)
            self.assertEqual(follow_ups[0].payload["alert_family"], "runtime_validation_review")
            self.assertEqual(follow_ups[0].payload["source_alert_id"], emitted[0].alert_id)

            service.acknowledge_alert(
                alert_id=emitted[0].alert_id,
                acknowledged_by="operator-a",
                acknowledgement_note="Owner found.",
            )
            self.assertEqual(service.process_follow_ups(force=True), [])

            review_service.state = None
            recovery = service.emit_alerts(force=True)

            runtime_review_recovery = [
                record
                for record in recovery
                if record.payload.get("alert_family") == "runtime_validation_review"
            ]
            self.assertEqual(len(runtime_review_recovery), 1)
            self.assertEqual(runtime_review_recovery[0].status, "healthy")
            self.assertEqual(runtime_review_recovery[0].payload["lifecycle_event"], "recovery")

    def test_emit_alerts_emits_runtime_validation_chain_and_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            analytics_service = AnalyticsService(
                job_repository=repo,
                heartbeat_timeout_seconds=5,
                default_thresholds=ControlPlaneAlertThresholds(
                    runtime_rehearsal_due_soon_age_hours=1.0,
                    runtime_rehearsal_warning_age_hours=2.0,
                    runtime_rehearsal_critical_age_hours=6.0,
                ),
            )
            service = ControlPlaneAlertService(
                job_repository=repo,
                analytics_service=analytics_service,
                window_days=7,
                sink_path=str(Path(tmpdir) / "runtime-validation.jsonl"),
            )

            stale_rehearsal_at = (datetime.now(UTC) - timedelta(minutes=90)).isoformat()
            repo.append_control_plane_maintenance_event(
                ControlPlaneMaintenanceEventRecord(
                    event_id="runtime-rehearsal-aging",
                    recorded_at=stale_rehearsal_at,
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

            emitted = service.emit_alerts(force=True)

            self.assertEqual(len(emitted), 2)
            runtime_alert = next(
                alert for alert in emitted if alert.alert_key.startswith("control-plane-runtime-validation:")
            )
            aggregate_alert = next(
                alert for alert in emitted if not alert.alert_key.startswith("control-plane-runtime-validation:")
            )
            self.assertEqual(runtime_alert.status, "degraded")
            self.assertEqual(runtime_alert.finding_codes, ["runtime_rehearsal_due_soon"])
            self.assertEqual(runtime_alert.payload["alert_family"], "runtime_validation")
            self.assertEqual(aggregate_alert.status, "degraded")
            self.assertIn("runtime_rehearsal_due_soon", aggregate_alert.finding_codes)

            repo.append_control_plane_maintenance_event(
                ControlPlaneMaintenanceEventRecord(
                    event_id="runtime-rehearsal-fresh",
                    recorded_at=datetime.now(UTC).isoformat(),
                    event_type="control_plane_runtime_rehearsal_executed",
                    changed_by="operator-b",
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

            recovered = service.emit_alerts(force=True)

            self.assertEqual(len(recovered), 2)
            runtime_recovery = next(
                alert for alert in recovered if alert.alert_key.startswith("control-plane-runtime-validation:")
            )
            aggregate_recovery = next(
                alert for alert in recovered if not alert.alert_key.startswith("control-plane-runtime-validation:")
            )
            self.assertEqual(runtime_recovery.status, "healthy")
            self.assertEqual(runtime_recovery.payload["lifecycle_event"], "recovery")
            self.assertEqual(aggregate_recovery.status, "healthy")
            self.assertEqual(aggregate_recovery.payload["lifecycle_event"], "recovery")

    def test_emit_alerts_dedups_and_emits_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            analytics_service = AnalyticsService(
                job_repository=repo,
                heartbeat_timeout_seconds=5,
                default_thresholds=ControlPlaneAlertThresholds(
                    queue_warning_threshold=1,
                    queue_critical_threshold=2,
                    stale_worker_warning_threshold=1,
                    stale_worker_critical_threshold=2,
                    expired_lease_warning_threshold=2,
                    expired_lease_critical_threshold=3,
                    job_failure_rate_warning_threshold=0.2,
                    job_failure_rate_critical_threshold=0.5,
                    job_failure_rate_min_samples=1,
                ),
            )
            sink_path = Path(tmpdir) / "alerts.jsonl"
            service = ControlPlaneAlertService(
                job_repository=repo,
                analytics_service=analytics_service,
                window_days=7,
                dedup_window_seconds=3600,
                sink_path=str(sink_path),
            )

            now = datetime.now(UTC).isoformat()
            repo.append_control_plane_maintenance_event(
                ControlPlaneMaintenanceEventRecord(
                    event_id="runtime-rehearsal-current",
                    recorded_at=now,
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
            repo.save_worker(
                WorkerRecord(
                    worker_id="worker-stale",
                    mode="standalone",
                    status="stopped",
                    started_at=now,
                    last_heartbeat_at=(datetime.now(UTC) - timedelta(minutes=10)).isoformat(),
                    host_name="host-a",
                    process_id=101,
                    current_job_id=None,
                )
            )
            repo.save(
                JobRecord(
                    job_id="job-queued",
                    created_at=now,
                    job_type="audit-trace",
                    status="queued",
                )
            )
            repo.append_job_lease_event(
                JobLeaseEventRecord(
                    event_id="lease-expired",
                    job_id="job-queued",
                    worker_id="worker-stale",
                    event_type="lease_expired_requeued",
                    recorded_at=now,
                    details={},
                )
            )

            first = service.emit_alerts(force=False)
            self.assertEqual(len(first), 1)
            self.assertEqual(first[0].status, "critical")
            self.assertEqual(first[0].delivery_state, "delivered")
            self.assertTrue(sink_path.exists())
            acknowledged = service.acknowledge_alert(
                alert_id=first[0].alert_id,
                acknowledged_by="operator-a",
                acknowledgement_note="Investigating queue outage.",
            )
            self.assertEqual(acknowledged.acknowledged_by, "operator-a")

            second = service.emit_alerts(force=False)
            self.assertEqual(second, [])
            self.assertEqual(len(repo.list_control_plane_alerts()), 1)

            silence = service.create_silence(
                created_by="operator-a",
                reason="Maintenance window",
                duration_minutes=30,
                match_finding_code="queue_without_active_workers",
            )
            self.assertEqual(silence.created_by, "operator-a")
            self.assertEqual(len(service.list_silences(active_only=True)), 1)

            job = repo.get("job-queued")
            job.status = "queued"
            repo.save(job)
            suppressed = service.emit_alerts(force=True)
            self.assertEqual(len(suppressed), 1)
            self.assertEqual(suppressed[0].delivery_state, "suppressed")

            cancelled = service.cancel_silence(
                silence_id=silence.silence_id,
                cancelled_by="operator-a",
            )
            self.assertEqual(cancelled.cancelled_by, "operator-a")

            worker = repo.get_worker("worker-stale")
            worker.status = "running"
            worker.last_heartbeat_at = now
            repo.save_worker(worker)
            job = repo.get("job-queued")
            job.status = "completed"
            job.started_at = now
            job.completed_at = now
            repo.save(job)

            recovery = service.emit_alerts(force=False)
            self.assertEqual(len(recovery), 1)
            self.assertEqual(recovery[0].status, "healthy")
            self.assertEqual(recovery[0].severity, "info")

            listed = repo.list_control_plane_alerts()
            self.assertEqual(len(listed), 3)
            lines = sink_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 2)
            payload = json.loads(lines[0])
            self.assertIn("alert_key", payload)

    def test_follow_ups_emit_reminder_and_acknowledgement_stops_escalation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            analytics_service = AnalyticsService(
                job_repository=repo,
                heartbeat_timeout_seconds=5,
                default_thresholds=ControlPlaneAlertThresholds(),
            )
            service = ControlPlaneAlertService(
                job_repository=repo,
                analytics_service=analytics_service,
                window_days=7,
                dedup_window_seconds=10,
                reminder_interval_seconds=60,
                escalation_interval_seconds=120,
                sink_path=str(Path(tmpdir) / "followups.jsonl"),
            )

            incident = ControlPlaneAlertRecord(
                alert_id="incident-root",
                created_at=(datetime.now(UTC) - timedelta(seconds=90)).isoformat(),
                alert_key="control-plane:critical:queue_without_active_workers",
                status="critical",
                severity="critical",
                summary="No workers available for queued jobs.",
                finding_codes=["queue_without_active_workers"],
                delivery_state="delivered",
                payload={"report": {}, "lifecycle_event": "incident", "source_alert_id": None},
                error=None,
            )
            repo.append_control_plane_alert(incident)

            reminder = service.process_follow_ups(force=False)
            self.assertEqual(len(reminder), 1)
            self.assertEqual(reminder[0].payload["lifecycle_event"], "reminder")
            self.assertEqual(reminder[0].payload["source_alert_id"], "incident-root")

            acknowledged = service.acknowledge_alert(
                alert_id=reminder[0].alert_id,
                acknowledged_by="operator-b",
                acknowledgement_note="Owner engaged.",
            )
            self.assertEqual(acknowledged.acknowledged_by, "operator-b")
            self.assertEqual(repo.get_control_plane_alert("incident-root").acknowledged_by, "operator-b")

            no_escalation = service.process_follow_ups(force=True)
            self.assertEqual(no_escalation, [])

    def test_follow_ups_emit_runtime_validation_reminder_alongside_aggregate_incident(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            analytics_service = AnalyticsService(
                job_repository=repo,
                heartbeat_timeout_seconds=5,
                default_thresholds=ControlPlaneAlertThresholds(),
            )
            service = ControlPlaneAlertService(
                job_repository=repo,
                analytics_service=analytics_service,
                window_days=7,
                dedup_window_seconds=10,
                reminder_interval_seconds=60,
                escalation_interval_seconds=120,
                sink_path=str(Path(tmpdir) / "runtime-followups.jsonl"),
            )
            now = datetime.now(UTC)
            runtime_incident = ControlPlaneAlertRecord(
                alert_id="runtime-incident-root",
                created_at=(now - timedelta(seconds=91)).isoformat(),
                alert_key="control-plane-runtime-validation:degraded:runtime_rehearsal_due_soon",
                status="degraded",
                severity="warning",
                summary="Control-plane runtime proof is approaching its warning threshold.",
                finding_codes=["runtime_rehearsal_due_soon"],
                delivery_state="delivered",
                payload={
                    "report": {},
                    "runtime_validation": {},
                    "alert_family": "runtime_validation",
                    "lifecycle_event": "incident",
                    "source_alert_id": None,
                },
                error=None,
            )
            aggregate_incident = ControlPlaneAlertRecord(
                alert_id="aggregate-incident-root",
                created_at=(now - timedelta(seconds=90)).isoformat(),
                alert_key="control-plane:degraded:oncall_pending_reviews_stale",
                status="degraded",
                severity="warning",
                summary="Pending on-call change reviews are older than the configured SLA.",
                finding_codes=["oncall_pending_reviews_stale"],
                delivery_state="delivered",
                payload={"report": {}, "lifecycle_event": "incident", "source_alert_id": None},
                error=None,
            )
            repo.append_control_plane_alert(runtime_incident)
            repo.append_control_plane_alert(aggregate_incident)

            reminders = service.process_follow_ups(force=False)

            self.assertEqual(len(reminders), 2)
            source_alert_ids = {alert.payload["source_alert_id"] for alert in reminders}
            self.assertEqual(source_alert_ids, {"runtime-incident-root", "aggregate-incident-root"})
            self.assertTrue(
                any(alert.alert_key.startswith("control-plane-runtime-validation:") for alert in reminders)
            )

    def test_runtime_validation_follow_ups_use_environment_policy_intervals(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            settings.environment_name = "prod"
            settings.runtime_validation_policy_path.parent.mkdir(parents=True, exist_ok=True)
            settings.runtime_validation_policy_path.write_text(
                json.dumps(
                    {
                        "environments": {
                            "prod": {
                                "reminder_interval_seconds": 30.0,
                                "escalation_interval_seconds": 60.0,
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            repo = JobRepository(settings)
            analytics_service = AnalyticsService(
                job_repository=repo,
                default_environment_name="prod",
                heartbeat_timeout_seconds=5,
                default_thresholds=ControlPlaneAlertThresholds(),
                runtime_validation_policy_path=str(settings.runtime_validation_policy_path),
                runtime_validation_reminder_interval_seconds=900.0,
                runtime_validation_escalation_interval_seconds=1800.0,
            )
            service = ControlPlaneAlertService(
                job_repository=repo,
                analytics_service=analytics_service,
                default_environment_name="prod",
                window_days=7,
                reminder_interval_seconds=900.0,
                escalation_interval_seconds=1800.0,
                runtime_validation_policy_path=str(settings.runtime_validation_policy_path),
                sink_path=str(Path(tmpdir) / "runtime-policy-followups.jsonl"),
            )
            now = datetime.now(UTC)
            runtime_incident = ControlPlaneAlertRecord(
                alert_id="runtime-policy-root",
                created_at=(now - timedelta(seconds=40)).isoformat(),
                alert_key="control-plane-runtime-validation:degraded:runtime_rehearsal_due_soon",
                status="degraded",
                severity="warning",
                summary="Control-plane runtime proof is approaching its warning threshold.",
                finding_codes=["runtime_rehearsal_due_soon"],
                delivery_state="delivered",
                payload={
                    "report": {},
                    "runtime_validation": {"environment_name": "prod"},
                    "alert_family": "runtime_validation",
                    "lifecycle_event": "incident",
                    "source_alert_id": None,
                },
                error=None,
            )
            aggregate_incident = ControlPlaneAlertRecord(
                alert_id="aggregate-policy-root",
                created_at=(now - timedelta(seconds=40)).isoformat(),
                alert_key="control-plane:degraded:oncall_pending_reviews_stale",
                status="degraded",
                severity="warning",
                summary="Pending on-call change reviews are older than the configured SLA.",
                finding_codes=["oncall_pending_reviews_stale"],
                delivery_state="delivered",
                payload={"report": {}, "lifecycle_event": "incident", "source_alert_id": None},
                error=None,
            )
            repo.append_control_plane_alert(runtime_incident)
            repo.append_control_plane_alert(aggregate_incident)

            reminders = service.process_follow_ups(force=False)

            self.assertEqual(len(reminders), 1)
            self.assertEqual(reminders[0].payload["source_alert_id"], "runtime-policy-root")
            self.assertTrue(reminders[0].alert_key.startswith("control-plane-runtime-validation:"))

    def test_emit_alert_uses_active_oncall_route(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            analytics_service = AnalyticsService(
                job_repository=repo,
                heartbeat_timeout_seconds=5,
                default_thresholds=ControlPlaneAlertThresholds(
                    queue_warning_threshold=1,
                    queue_critical_threshold=2,
                    stale_worker_warning_threshold=10,
                    stale_worker_critical_threshold=20,
                    expired_lease_warning_threshold=10,
                    expired_lease_critical_threshold=20,
                    job_failure_rate_warning_threshold=1.0,
                    job_failure_rate_critical_threshold=1.0,
                    job_failure_rate_min_samples=99,
                ),
            )
            service = ControlPlaneAlertService(
                job_repository=repo,
                analytics_service=analytics_service,
                window_days=7,
                sink_path=str(Path(tmpdir) / "routed.jsonl"),
            )
            now_utc = datetime.now(UTC)
            current_weekday = now_utc.weekday()
            service.create_oncall_schedule(
                created_by="operator-a",
                team_name="platform-primary",
                timezone_name="UTC",
                weekdays=[current_weekday],
                start_time="00:00",
                end_time="23:59",
                rotation_name="primary",
            )
            repo.save(
                JobRecord(
                    job_id="job-routed",
                    created_at=now_utc.isoformat(),
                    job_type="audit-trace",
                    status="queued",
                )
            )
            repo.append_control_plane_maintenance_event(
                ControlPlaneMaintenanceEventRecord(
                    event_id="runtime-rehearsal-routed",
                    recorded_at=now_utc.isoformat(),
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
            emitted = service.emit_alerts(force=True)
            self.assertEqual(len(emitted), 1)
            self.assertEqual(emitted[0].payload["route"]["team_name"], "platform-primary")
            self.assertEqual(emitted[0].payload["route"]["rotation_name"], "primary")

    def test_active_route_prefers_higher_priority_date_bounded_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            analytics_service = AnalyticsService(
                job_repository=repo,
                heartbeat_timeout_seconds=5,
                default_thresholds=ControlPlaneAlertThresholds(),
            )
            service = ControlPlaneAlertService(
                job_repository=repo,
                analytics_service=analytics_service,
                window_days=7,
            )
            reference_timestamp = datetime(2026, 12, 25, 10, 30, tzinfo=UTC)
            service.create_oncall_schedule(
                created_by="operator-a",
                team_name="platform-primary",
                timezone_name="UTC",
                weekdays=[0, 1, 2, 3, 4, 5, 6],
                start_time="00:00",
                end_time="23:59",
                priority=100,
                rotation_name="primary",
            )
            service.create_oncall_schedule(
                created_by="operator-b",
                team_name="holiday-override",
                timezone_name="UTC",
                weekdays=[0, 1, 2, 3, 4, 5, 6],
                start_time="00:00",
                end_time="23:59",
                priority=250,
                rotation_name="holiday",
                effective_start_date="2026-12-25",
                effective_end_date="2026-12-25",
            )

            active = service.resolve_active_oncall_route(reference_timestamp=reference_timestamp)

            self.assertIsNotNone(active)
            assert active is not None
            self.assertEqual(active.team_name, "holiday-override")
            self.assertEqual(active.priority, 250)
            self.assertEqual(active.effective_start_date, "2026-12-25")

            preview = service.preview_oncall_route(reference_timestamp=reference_timestamp)
            self.assertEqual(preview["active_candidate_count"], 2)
            self.assertEqual(preview["resolved_route"]["team_name"], "holiday-override")
            self.assertTrue(preview["active_candidates"][0]["selected"])
            self.assertEqual(preview["active_candidates"][0]["route"]["team_name"], "holiday-override")
            self.assertIn("priority=250", preview["active_candidates"][0]["reasons"])
            self.assertEqual(preview["active_candidates"][1]["route"]["team_name"], "platform-primary")

    def test_emit_alert_flags_oncall_route_conflicts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            analytics_service = AnalyticsService(
                job_repository=repo,
                heartbeat_timeout_seconds=5,
                default_thresholds=ControlPlaneAlertThresholds(
                    oncall_conflict_warning_threshold=1,
                    oncall_conflict_critical_threshold=2,
                ),
            )
            service = ControlPlaneAlertService(
                job_repository=repo,
                analytics_service=analytics_service,
                window_days=7,
                sink_path=str(Path(tmpdir) / "oncall-conflicts.jsonl"),
            )
            service.create_oncall_schedule(
                created_by="operator-a",
                team_name="platform-a",
                timezone_name="UTC",
                weekdays=[0, 1, 2, 3, 4, 5, 6],
                start_time="00:00",
                end_time="23:59",
                priority=100,
                rotation_name="primary-a",
            )
            service.create_oncall_schedule(
                created_by="operator-b",
                change_reason="Shared ownership rehearsal.",
                approved_by="director-b",
                approved_by_role="director",
                team_name="platform-b",
                timezone_name="UTC",
                weekdays=[0, 1, 2, 3, 4, 5, 6],
                start_time="00:00",
                end_time="23:59",
                priority=100,
                rotation_name="primary-b",
            )
            repo.append_control_plane_maintenance_event(
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

            emitted = service.emit_alerts(force=True)

            self.assertEqual(len(emitted), 1)
            self.assertEqual(emitted[0].status, "degraded")
            self.assertIn("oncall_route_conflicts", emitted[0].finding_codes)

    def test_emit_alert_flags_stale_pending_oncall_reviews(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            analytics_service = AnalyticsService(
                job_repository=repo,
                default_environment_name="prod",
                heartbeat_timeout_seconds=5,
                default_thresholds=ControlPlaneAlertThresholds(
                    oncall_pending_review_warning_threshold=1,
                    oncall_pending_review_critical_threshold=2,
                    oncall_pending_review_sla_hours=1.0,
                ),
            )
            service = ControlPlaneAlertService(
                job_repository=repo,
                analytics_service=analytics_service,
                default_environment_name="prod",
                window_days=7,
                sink_path=str(Path(tmpdir) / "oncall-reviews.jsonl"),
            )
            repo.append_control_plane_oncall_change_request(
                ControlPlaneOnCallChangeRequestRecord(
                    request_id="request-prod-stale",
                    created_at=(datetime.now(UTC) - timedelta(hours=3)).isoformat(),
                    created_by="operator-a",
                    environment_name="prod",
                    team_name="platform-a",
                    timezone_name="UTC",
                    status="pending_review",
                    change_reason="Prod overlap waiting on approval.",
                    review_required=True,
                    review_reasons=["ambiguous_overlap"],
                    weekdays=[0, 1, 2, 3, 4, 5, 6],
                    start_time="00:00",
                    end_time="23:59",
                    priority=100,
                    rotation_name="primary-a",
                )
            )
            repo.append_control_plane_maintenance_event(
                ControlPlaneMaintenanceEventRecord(
                    event_id="runtime-rehearsal-current",
                    recorded_at=datetime.now(UTC).isoformat(),
                    event_type="control_plane_runtime_rehearsal_executed",
                    changed_by="operator-a",
                    details={
                        "environment_name": "prod",
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

            emitted = service.emit_alerts(force=True)

            self.assertEqual(len(emitted), 1)
            self.assertEqual(emitted[0].status, "degraded")
            self.assertIn("oncall_pending_reviews_stale", emitted[0].finding_codes)

    def test_ambiguous_oncall_overlap_requires_approval_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            analytics_service = AnalyticsService(
                job_repository=repo,
                heartbeat_timeout_seconds=5,
                default_thresholds=ControlPlaneAlertThresholds(),
            )
            service = ControlPlaneAlertService(
                job_repository=repo,
                analytics_service=analytics_service,
                window_days=7,
            )
            service.create_oncall_schedule(
                created_by="operator-a",
                team_name="platform-a",
                timezone_name="UTC",
                weekdays=[0, 1, 2, 3, 4, 5, 6],
                start_time="00:00",
                end_time="23:59",
                priority=100,
                rotation_name="primary-a",
            )

            with self.assertRaisesRegex(
                ValueError,
                "Ambiguous on-call overlaps require change_reason, approved_by, and approved_by_role.",
            ):
                service.create_oncall_schedule(
                    created_by="operator-b",
                    team_name="platform-b",
                    timezone_name="UTC",
                    weekdays=[0, 1, 2, 3, 4, 5, 6],
                    start_time="00:00",
                    end_time="23:59",
                    priority=100,
                    rotation_name="primary-b",
                )

            approved = service.create_oncall_schedule(
                created_by="operator-b",
                created_by_role="engineer",
                change_reason="Temporary split coverage during migration week.",
                approved_by="director-b",
                approved_by_role="director",
                approval_note="Approved despite overlap because both teams are shadowing.",
                team_name="platform-b",
                timezone_name="UTC",
                weekdays=[0, 1, 2, 3, 4, 5, 6],
                start_time="00:00",
                end_time="23:59",
                priority=100,
                rotation_name="primary-b",
            )

            self.assertEqual(approved.approved_by, "director-b")
            self.assertIsNotNone(approved.approved_at)

    def test_oncall_policy_enforces_team_boundaries_and_approver_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            settings.oncall_policy_path.parent.mkdir(parents=True, exist_ok=True)
            settings.oncall_policy_path.write_text(
                json.dumps(
                    {
                        "default": {
                            "required_approver_roles": ["director"],
                            "allow_self_approval": False,
                        },
                        "teams": {
                            "platform-owned": {
                                "owner_team": "platform",
                                "allowed_requester_teams": ["platform"],
                                "allowed_approver_teams": ["platform"],
                                "allowed_approver_ids": ["director-platform"],
                            }
                        },
                        "rotations": {
                            "holiday": {
                                "required_approver_roles": ["admin"],
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            repo = JobRepository(settings)
            analytics_service = AnalyticsService(
                job_repository=repo,
                heartbeat_timeout_seconds=5,
                default_thresholds=ControlPlaneAlertThresholds(),
            )
            service = ControlPlaneAlertService(
                job_repository=repo,
                analytics_service=analytics_service,
                window_days=7,
                policy_path=str(settings.oncall_policy_path),
            )

            with self.assertRaisesRegex(
                ValueError,
                "created_by_team is not allowed by the on-call governance policy.",
            ):
                service.create_oncall_schedule(
                    created_by="operator-a",
                    created_by_team="security",
                    created_by_role="engineer",
                    team_name="platform-owned",
                    timezone_name="UTC",
                    weekdays=[0, 1, 2, 3, 4, 5, 6],
                    start_time="00:00",
                    end_time="23:59",
                    priority=100,
                    rotation_name="primary",
                )

            service.create_oncall_schedule(
                created_by="operator-a",
                created_by_team="platform",
                created_by_role="engineer",
                team_name="platform-owned",
                timezone_name="UTC",
                weekdays=[0, 1, 2, 3, 4, 5, 6],
                start_time="00:00",
                end_time="23:59",
                priority=100,
                rotation_name="primary",
            )

            with self.assertRaisesRegex(
                ValueError,
                "approved_by must be one of: director-platform.",
            ):
                service.create_oncall_schedule(
                    created_by="operator-b",
                    created_by_team="platform",
                    created_by_role="engineer",
                    change_reason="Need overlap during maintenance.",
                    approved_by="director-other",
                    approved_by_team="platform",
                    approved_by_role="director",
                    team_name="platform-owned",
                    timezone_name="UTC",
                    weekdays=[0, 1, 2, 3, 4, 5, 6],
                    start_time="00:00",
                    end_time="23:59",
                    priority=100,
                    rotation_name="primary",
                )

            with self.assertRaisesRegex(
                ValueError,
                "approved_by_role must be one of: admin.",
            ):
                service.create_oncall_schedule(
                    created_by="operator-c",
                    created_by_team="platform",
                    created_by_role="engineer",
                    change_reason="Holiday overlap request.",
                    approved_by="director-platform",
                    approved_by_team="platform",
                    approved_by_role="director",
                    team_name="platform-owned",
                    timezone_name="UTC",
                    weekdays=[0, 1, 2, 3, 4, 5, 6],
                    start_time="00:00",
                    end_time="23:59",
                    priority=100,
                    rotation_name="holiday",
                )

    def test_ambiguous_oncall_overlap_rejects_invalid_approver_role_and_self_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            analytics_service = AnalyticsService(
                job_repository=repo,
                heartbeat_timeout_seconds=5,
                default_thresholds=ControlPlaneAlertThresholds(),
            )
            service = ControlPlaneAlertService(
                job_repository=repo,
                analytics_service=analytics_service,
                window_days=7,
                required_approver_roles=("director", "admin"),
                allow_self_approval=False,
            )
            service.create_oncall_schedule(
                created_by="operator-a",
                created_by_role="engineer",
                team_name="platform-a",
                timezone_name="UTC",
                weekdays=[0, 1, 2, 3, 4, 5, 6],
                start_time="00:00",
                end_time="23:59",
                priority=100,
                rotation_name="primary-a",
            )

            with self.assertRaisesRegex(ValueError, "approved_by_role must be one of: director, admin."):
                service.create_oncall_schedule(
                    created_by="operator-b",
                    created_by_role="engineer",
                    change_reason="Temporary overlap for load test.",
                    approved_by="lead-b",
                    approved_by_role="manager",
                    team_name="platform-b",
                    timezone_name="UTC",
                    weekdays=[0, 1, 2, 3, 4, 5, 6],
                    start_time="00:00",
                    end_time="23:59",
                    priority=100,
                    rotation_name="primary-b",
                )

            with self.assertRaisesRegex(ValueError, "Self-approval is not allowed for ambiguous on-call overlaps."):
                service.create_oncall_schedule(
                    created_by="operator-b",
                    created_by_role="director",
                    change_reason="Trying to self-approve.",
                    approved_by="operator-b",
                    approved_by_role="director",
                    team_name="platform-b",
                    timezone_name="UTC",
                    weekdays=[0, 1, 2, 3, 4, 5, 6],
                    start_time="00:00",
                    end_time="23:59",
                    priority=100,
                    rotation_name="primary-b",
                )

    def test_oncall_change_request_auto_applies_when_review_not_required(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            analytics_service = AnalyticsService(
                job_repository=repo,
                heartbeat_timeout_seconds=5,
                default_thresholds=ControlPlaneAlertThresholds(),
            )
            service = ControlPlaneAlertService(
                job_repository=repo,
                analytics_service=analytics_service,
                window_days=7,
            )

            request = service.submit_oncall_change_request(
                created_by="operator-a",
                created_by_team="platform",
                created_by_role="engineer",
                change_reason="Create baseline primary coverage.",
                team_name="platform-a",
                timezone_name="UTC",
                weekdays=[0, 1, 2, 3, 4, 5, 6],
                start_time="00:00",
                end_time="23:59",
                priority=200,
                rotation_name="primary",
            )

            self.assertEqual(request.status, "applied")
            self.assertFalse(request.review_required)
            self.assertIsNotNone(request.applied_schedule_id)
            schedules = service.list_oncall_schedules(active_only=False)
            self.assertEqual(len(schedules), 1)

    def test_oncall_change_request_moves_through_pending_review_and_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            repo = JobRepository(settings)
            analytics_service = AnalyticsService(
                job_repository=repo,
                heartbeat_timeout_seconds=5,
                default_thresholds=ControlPlaneAlertThresholds(),
            )
            service = ControlPlaneAlertService(
                job_repository=repo,
                analytics_service=analytics_service,
                window_days=7,
                required_approver_roles=("director",),
            )
            service.create_oncall_schedule(
                created_by="operator-a",
                created_by_team="platform",
                created_by_role="engineer",
                team_name="platform-a",
                timezone_name="UTC",
                weekdays=[0, 1, 2, 3, 4, 5, 6],
                start_time="00:00",
                end_time="23:59",
                priority=100,
                rotation_name="primary",
            )

            request = service.submit_oncall_change_request(
                created_by="operator-b",
                created_by_team="platform",
                created_by_role="engineer",
                change_reason="Need temporary overlap for migration.",
                team_name="platform-b",
                timezone_name="UTC",
                weekdays=[0, 1, 2, 3, 4, 5, 6],
                start_time="00:00",
                end_time="23:59",
                priority=100,
                rotation_name="primary-b",
            )
            self.assertEqual(request.status, "pending_review")
            self.assertTrue(request.review_required)
            assigned = service.assign_oncall_change_request(
                request_id=request.request_id,
                assigned_to="reviewer-a",
                assigned_to_team="platform",
                assigned_by="lead-a",
                assignment_note="Please handle migration review.",
            )
            self.assertEqual(assigned.assigned_to, "reviewer-a")
            self.assertEqual(assigned.assignment_note, "Please handle migration review.")

            rejected = service.review_oncall_change_request(
                request_id=request.request_id,
                decision="reject",
                reviewed_by="director-a",
                reviewed_by_team="platform",
                reviewed_by_role="director",
                review_note="Overlap is not justified yet.",
            )
            self.assertEqual(rejected.status, "rejected")
            self.assertIsNone(rejected.applied_schedule_id)

    def test_oncall_change_request_review_applies_schedule(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            settings.oncall_policy_path.parent.mkdir(parents=True, exist_ok=True)
            settings.oncall_policy_path.write_text(
                json.dumps(
                    {
                        "default": {
                            "required_approver_roles": ["director"],
                            "allow_self_approval": False,
                        },
                        "teams": {
                            "platform-owned": {
                                "owner_team": "platform",
                                "allowed_requester_teams": ["platform"],
                                "allowed_approver_teams": ["platform"],
                                "allowed_approver_ids": ["director-platform"],
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            repo = JobRepository(settings)
            analytics_service = AnalyticsService(
                job_repository=repo,
                heartbeat_timeout_seconds=5,
                default_thresholds=ControlPlaneAlertThresholds(),
            )
            service = ControlPlaneAlertService(
                job_repository=repo,
                analytics_service=analytics_service,
                window_days=7,
                policy_path=str(settings.oncall_policy_path),
            )
            service.create_oncall_schedule(
                created_by="operator-a",
                created_by_team="platform",
                created_by_role="engineer",
                team_name="platform-owned",
                timezone_name="UTC",
                weekdays=[0, 1, 2, 3, 4, 5, 6],
                start_time="00:00",
                end_time="23:59",
                priority=100,
                rotation_name="primary",
            )

            request = service.submit_oncall_change_request(
                created_by="operator-b",
                created_by_team="platform",
                created_by_role="engineer",
                change_reason="Need controlled overlap during migration.",
                team_name="platform-owned",
                timezone_name="UTC",
                weekdays=[0, 1, 2, 3, 4, 5, 6],
                start_time="00:00",
                end_time="23:59",
                priority=100,
                rotation_name="backup",
            )

            applied = service.review_oncall_change_request(
                request_id=request.request_id,
                decision="approve",
                reviewed_by="director-platform",
                reviewed_by_team="platform",
                reviewed_by_role="director",
                review_note="Approved for a time-boxed migration window.",
            )
            self.assertEqual(applied.status, "applied")
            self.assertIsNotNone(applied.applied_schedule_id)
            self.assertEqual(len(service.list_oncall_schedules(active_only=False)), 2)

    def test_oncall_policy_can_override_by_environment(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            settings.oncall_policy_path.parent.mkdir(parents=True, exist_ok=True)
            settings.oncall_policy_path.write_text(
                json.dumps(
                    {
                        "default": {
                            "required_approver_roles": ["director"],
                        },
                        "teams": {
                            "payments-owned": {
                                "owner_team": "platform",
                                "allowed_requester_teams": ["platform"],
                                "allowed_approver_teams": ["platform"],
                            }
                        },
                        "environments": {
                            "prod": {
                                "default": {
                                    "required_approver_roles": ["admin"],
                                }
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            repo = JobRepository(settings)
            analytics_service = AnalyticsService(
                job_repository=repo,
                heartbeat_timeout_seconds=5,
                default_thresholds=ControlPlaneAlertThresholds(),
            )
            service = ControlPlaneAlertService(
                job_repository=repo,
                analytics_service=analytics_service,
                default_environment_name="staging",
                window_days=7,
                policy_path=str(settings.oncall_policy_path),
            )
            service.create_oncall_schedule(
                created_by="operator-a",
                environment_name="prod",
                created_by_team="platform",
                created_by_role="engineer",
                team_name="payments-owned",
                timezone_name="UTC",
                weekdays=[0, 1, 2, 3, 4, 5, 6],
                start_time="00:00",
                end_time="23:59",
                priority=100,
                rotation_name="primary",
            )

            with self.assertRaisesRegex(ValueError, "approved_by_role must be one of: admin."):
                service.create_oncall_schedule(
                    created_by="operator-b",
                    environment_name="prod",
                    created_by_team="platform",
                    created_by_role="engineer",
                    change_reason="Need prod overlap.",
                    approved_by="director-b",
                    approved_by_team="platform",
                    approved_by_role="director",
                    team_name="payments-owned",
                    timezone_name="UTC",
                    weekdays=[0, 1, 2, 3, 4, 5, 6],
                    start_time="00:00",
                    end_time="23:59",
                    priority=100,
                    rotation_name="backup",
                )

            service.create_oncall_schedule(
                created_by="operator-c",
                environment_name="staging",
                created_by_team="platform",
                created_by_role="engineer",
                team_name="payments-owned",
                timezone_name="UTC",
                weekdays=[0, 1, 2, 3, 4, 5, 6],
                start_time="00:00",
                end_time="23:59",
                priority=100,
                rotation_name="staging-primary",
            )
            staging = service.create_oncall_schedule(
                created_by="operator-d",
                environment_name="staging",
                created_by_team="platform",
                created_by_role="engineer",
                change_reason="Need staging overlap.",
                approved_by="director-d",
                approved_by_team="platform",
                approved_by_role="director",
                team_name="payments-owned",
                timezone_name="UTC",
                weekdays=[0, 1, 2, 3, 4, 5, 6],
                start_time="00:00",
                end_time="23:59",
                priority=100,
                rotation_name="staging-backup",
            )
            self.assertEqual(staging.environment_name, "staging")


if __name__ == "__main__":
    unittest.main()
