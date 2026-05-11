from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
import tempfile
import unittest

from lsa.core.intent_graph import IntentGraph
from lsa.drift.comparator import DriftComparator
from lsa.remediation.llm_client import RuleBasedLLMClient
from lsa.services.audit_service import AuditService
from lsa.services.control_plane_runtime_validation_review_service import (
    ControlPlaneRuntimeValidationReviewService,
)
from lsa.services.job_service import JobService
from lsa.services.trace_collection_service import TraceCollectionService
from lsa.settings import resolve_workspace_settings
from lsa.storage.files import AuditRepository, JobRepository, SnapshotRepository
from lsa.storage.models import ControlPlaneMaintenanceEventRecord


class ControlPlaneRuntimeValidationReviewServiceTests(unittest.TestCase):
    def test_process_assign_and_auto_resolve_review(self) -> None:
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
            review_service = ControlPlaneRuntimeValidationReviewService(
                settings=settings,
                job_service=job_service,
                job_repository=job_repository,
            )
            job_service.runtime_validation_review_service = review_service

            job_repository.append_control_plane_maintenance_event(
                ControlPlaneMaintenanceEventRecord(
                    event_id="runtime-rehearsal-due-soon-review",
                    recorded_at=(datetime.now(UTC) - timedelta(hours=20)).isoformat(),
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

            opened = review_service.process_reviews(
                changed_by="system",
                reason="scheduled review sweep",
            )

            self.assertEqual(len(opened), 1)
            self.assertEqual(opened[0].status, "pending_review")
            self.assertEqual(opened[0].trigger_cadence_status, "due_soon")

            assigned = review_service.assign_review(
                review_id=opened[0].review_id,
                assigned_to="reviewer-prod",
                assigned_to_team="platform",
                assigned_by="system",
                assignment_note="Own the next runtime proof refresh.",
            )
            self.assertEqual(assigned.status, "assigned")
            self.assertEqual(assigned.assigned_to, "reviewer-prod")

            job_repository.append_control_plane_maintenance_event(
                ControlPlaneMaintenanceEventRecord(
                    event_id="runtime-rehearsal-fresh-review",
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

            resolved = review_service.process_reviews(
                changed_by="system",
                reason="runtime proof refreshed",
            )

            self.assertEqual(len(resolved), 1)
            self.assertEqual(resolved[0].status, "resolved")
            self.assertEqual(resolved[0].resolution_reason, "runtime_proof_restored")

    def test_process_reviews_uses_environment_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(Path(tmpdir))
            settings.environment_name = "prod"
            settings.runtime_validation_policy_path.parent.mkdir(parents=True, exist_ok=True)
            settings.runtime_validation_policy_path.write_text(
                json.dumps(
                    {
                        "environments": {
                            "prod": {
                                "due_soon_age_hours": 8.0,
                                "warning_age_hours": 12.0,
                                "critical_age_hours": 18.0,
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
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
            review_service = ControlPlaneRuntimeValidationReviewService(
                settings=settings,
                job_service=job_service,
                job_repository=job_repository,
            )
            job_service.runtime_validation_review_service = review_service

            job_repository.append_control_plane_maintenance_event(
                ControlPlaneMaintenanceEventRecord(
                    event_id="runtime-rehearsal-prod-policy-review",
                    recorded_at=(datetime.now(UTC) - timedelta(hours=10)).isoformat(),
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

            opened = review_service.process_reviews(changed_by="system")

            self.assertEqual(len(opened), 1)
            self.assertEqual(opened[0].policy_source, "policy:prod")
            self.assertEqual(opened[0].trigger_cadence_status, "due_soon")


if __name__ == "__main__":
    unittest.main()
