from __future__ import annotations

from datetime import datetime
import json
import tempfile
import unittest
from pathlib import Path

from lsa.core.intent_graph import IntentGraph
from lsa.remediation.llm_client import RuleBasedLLMClient
from lsa.drift.comparator import DriftComparator
from lsa.services.audit_service import AuditService
from lsa.services.control_plane_runtime_rehearsal_service import ControlPlaneRuntimeRehearsalService
from lsa.services.control_plane_runtime_smoke_service import ControlPlaneRuntimeSmokeService
from lsa.services.control_plane_runtime_validation_service import ControlPlaneRuntimeValidationService
from lsa.services.job_service import JobService
from lsa.services.trace_collection_service import TraceCollectionService
from lsa.settings import resolve_workspace_settings
from lsa.storage.files import AuditRepository, JobRepository, SnapshotRepository
from lsa.storage.models import ControlPlaneMaintenanceEventRecord


class ControlPlaneRuntimeSmokeServiceTests(unittest.TestCase):
    def test_runtime_smoke_round_trips_and_cleans_up(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(Path(tmpdir))
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
            job_service = JobService(
                job_repository=job_repository,
                audit_service=audit_service,
                trace_collection_service=TraceCollectionService(settings=settings),
                worker_mode="standalone",
                heartbeat_timeout_seconds=settings.worker_heartbeat_timeout_seconds,
            )
            service = ControlPlaneRuntimeSmokeService(
                settings=settings,
                snapshot_repository=snapshot_repository,
                audit_repository=audit_repository,
                job_repository=job_repository,
                job_service=job_service,
                repository_layout="shared",
                mixed_backends=False,
                now_factory=lambda: "2026-05-06T00:00:00+00:00",
            )

            summary = service.run(changed_by="operator-a", reason="runtime smoke", cleanup=True)

            self.assertEqual(summary.snapshot_repository_backend, "sqlite")
            self.assertEqual(summary.audit_repository_backend, "sqlite")
            self.assertEqual(summary.job_repository_backend, "sqlite")
            self.assertEqual(summary.repository_layout, "shared")
            self.assertTrue(summary.snapshot_round_trip_ok)
            self.assertTrue(summary.audit_round_trip_ok)
            self.assertTrue(summary.job_round_trip_ok)
            self.assertTrue(summary.cleanup_requested)
            self.assertTrue(summary.cleanup_completed)
            self.assertIsNotNone(summary.maintenance_event_id)
            self.assertEqual(snapshot_repository.list(), [])
            self.assertEqual(audit_repository.list(), [])
            self.assertEqual(job_repository.list(), [])
            self.assertFalse(Path(summary.snapshot_path).exists())
            self.assertFalse(Path(summary.report_path).exists())

    def test_runtime_rehearsal_evaluates_expected_backend_and_layout(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(Path(tmpdir))
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
            job_service = JobService(
                job_repository=job_repository,
                audit_service=audit_service,
                trace_collection_service=TraceCollectionService(settings=settings),
                worker_mode="standalone",
                heartbeat_timeout_seconds=settings.worker_heartbeat_timeout_seconds,
            )
            smoke_service = ControlPlaneRuntimeSmokeService(
                settings=settings,
                snapshot_repository=snapshot_repository,
                audit_repository=audit_repository,
                job_repository=job_repository,
                job_service=job_service,
                repository_layout="shared",
                mixed_backends=False,
                now_factory=lambda: "2026-05-06T00:00:00+00:00",
            )
            rehearsal_service = ControlPlaneRuntimeRehearsalService(
                settings=settings,
                job_repository=job_repository,
                job_service=job_service,
                runtime_smoke_service=smoke_service,
                now_factory=lambda: "2026-05-06T00:00:01+00:00",
            )

            summary = rehearsal_service.run(
                changed_by="operator-a",
                expected_backend="sqlite",
                expected_repository_layout="shared",
                reason="runtime rehearsal",
                cleanup=True,
            )

            self.assertEqual(summary.status, "passed")
            self.assertEqual(summary.database_backend, "sqlite")
            self.assertFalse(summary.snapshots_audits_repository_runtime_enabled)
            self.assertFalse(summary.snapshots_audits_repository_runtime_active)
            self.assertFalse(summary.job_repository_runtime_enabled)
            self.assertFalse(summary.job_repository_runtime_active)
            self.assertTrue(all(summary.checks.values()))
            self.assertTrue(summary.smoke["cleanup_completed"])
            self.assertIsNotNone(summary.maintenance_event_id)

            validation_service = ControlPlaneRuntimeValidationService(
                job_repository=job_repository,
                environment_name=settings.environment_name,
                due_soon_age_hours=18.0,
                warning_age_hours=24.0,
                critical_age_hours=72.0,
                now_factory=lambda: datetime.fromisoformat("2026-05-06T01:00:00+00:00"),
            )
            validation_summary = validation_service.build_summary()
            self.assertEqual(validation_summary.status, "passed")
            self.assertEqual(validation_summary.cadence_status, "fresh")
            self.assertEqual(validation_summary.latest_rehearsal_status, "passed")
            self.assertIsNotNone(validation_summary.latest_rehearsal_event_id)
            self.assertLess(validation_summary.age_hours, 24.0)

    def test_runtime_validation_reports_missing_rehearsal(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(Path(tmpdir))
            repo = JobRepository(settings)
            summary = ControlPlaneRuntimeValidationService(
                job_repository=repo,
                environment_name=settings.environment_name,
                due_soon_age_hours=18.0,
                warning_age_hours=24.0,
                critical_age_hours=72.0,
                now_factory=lambda: datetime.fromisoformat("2026-05-06T01:00:00+00:00"),
            ).build_summary()
            self.assertEqual(summary.status, "missing")
            self.assertEqual(summary.cadence_status, "missing")
            self.assertEqual(summary.severity, "critical")
            self.assertIn("missing_runtime_rehearsal", summary.blockers)

    def test_runtime_validation_reports_due_soon_before_warning_age(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(Path(tmpdir))
            repo = JobRepository(settings)
            repo.append_control_plane_maintenance_event(
                ControlPlaneMaintenanceEventRecord(
                    event_id="runtime-rehearsal-due-soon",
                    recorded_at="2026-05-05T05:00:00+00:00",
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
            summary = ControlPlaneRuntimeValidationService(
                job_repository=repo,
                environment_name=settings.environment_name,
                due_soon_age_hours=18.0,
                warning_age_hours=24.0,
                critical_age_hours=72.0,
                now_factory=lambda: datetime.fromisoformat("2026-05-06T00:00:00+00:00"),
            ).build_summary()
            self.assertEqual(summary.status, "passed")
            self.assertEqual(summary.cadence_status, "due_soon")
            self.assertEqual(summary.severity, "none")
            self.assertGreater(summary.due_in_hours, 0.0)

    def test_runtime_validation_uses_environment_policy_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(Path(tmpdir))
            settings.environment_name = "prod"
            settings.runtime_validation_policy_path.parent.mkdir(parents=True, exist_ok=True)
            settings.runtime_validation_policy_path.write_text(
                json.dumps(
                    {
                        "default": {
                            "due_soon_age_hours": 18.0,
                            "warning_age_hours": 24.0,
                            "critical_age_hours": 72.0,
                        },
                        "environments": {
                            "prod": {
                                "due_soon_age_hours": 8.0,
                                "warning_age_hours": 12.0,
                                "critical_age_hours": 18.0,
                                "reminder_interval_seconds": 30.0,
                                "escalation_interval_seconds": 60.0,
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            repo = JobRepository(settings)
            repo.append_control_plane_maintenance_event(
                ControlPlaneMaintenanceEventRecord(
                    event_id="runtime-rehearsal-policy-prod",
                    recorded_at="2026-05-05T14:00:00+00:00",
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
            from lsa.services.runtime_validation_policy import (
                RuntimeValidationPolicy,
                load_runtime_validation_policy_bundle,
            )

            bundle = load_runtime_validation_policy_bundle(settings.runtime_validation_policy_path)
            policy = bundle.resolve(
                environment_name=settings.environment_name,
                fallback=RuntimeValidationPolicy(
                    due_soon_age_hours=18.0,
                    warning_age_hours=24.0,
                    critical_age_hours=72.0,
                    reminder_interval_seconds=900.0,
                    escalation_interval_seconds=1800.0,
                ),
            )
            summary = ControlPlaneRuntimeValidationService(
                job_repository=repo,
                environment_name=settings.environment_name,
                due_soon_age_hours=policy.due_soon_age_hours or 18.0,
                warning_age_hours=policy.warning_age_hours or 24.0,
                critical_age_hours=policy.critical_age_hours or 72.0,
                policy_source=bundle.source_for(environment_name=settings.environment_name),
                reminder_interval_seconds=policy.reminder_interval_seconds,
                escalation_interval_seconds=policy.escalation_interval_seconds,
                now_factory=lambda: datetime.fromisoformat("2026-05-06T00:00:00+00:00"),
            ).build_summary()
            self.assertEqual(summary.policy_source, "policy:prod")
            self.assertEqual(summary.due_soon_age_hours, 8.0)
            self.assertEqual(summary.warning_age_hours, 12.0)
            self.assertEqual(summary.critical_age_hours, 18.0)
            self.assertEqual(summary.cadence_status, "due_soon")
            self.assertEqual(summary.reminder_interval_seconds, 30.0)
            self.assertEqual(summary.escalation_interval_seconds, 60.0)
