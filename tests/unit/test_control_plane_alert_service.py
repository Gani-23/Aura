from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import tempfile
import unittest

from lsa.services.analytics_service import AnalyticsService, ControlPlaneAlertThresholds
from lsa.services.control_plane_alert_service import ControlPlaneAlertService
from lsa.settings import resolve_workspace_settings
from lsa.storage.files import JobRepository
from lsa.storage.models import ControlPlaneAlertRecord, JobLeaseEventRecord, JobRecord, WorkerRecord


class ControlPlaneAlertServiceTests(unittest.TestCase):
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

            emitted = service.emit_alerts(force=True)

            self.assertEqual(len(emitted), 1)
            self.assertEqual(emitted[0].status, "degraded")
            self.assertIn("oncall_route_conflicts", emitted[0].finding_codes)

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
