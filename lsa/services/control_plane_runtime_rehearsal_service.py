from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from lsa.services.control_plane_runtime_smoke_service import ControlPlaneRuntimeSmokeService


@dataclass(slots=True)
class ControlPlaneRuntimeRehearsalSummary:
    rehearsal_id: str
    executed_at: str
    changed_by: str
    reason: str | None
    environment_name: str
    expected_backend: str
    expected_repository_layout: str
    database_backend: str
    snapshot_repository_backend: str
    audit_repository_backend: str
    job_repository_backend: str
    repository_layout: str
    mixed_backends: bool
    snapshots_audits_repository_runtime_enabled: bool
    snapshots_audits_repository_runtime_active: bool
    job_repository_runtime_enabled: bool
    job_repository_runtime_active: bool
    database_runtime_available: bool
    database_runtime_blockers: list[str]
    checks: dict[str, bool]
    status: str
    smoke: dict[str, Any]
    maintenance_event_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rehearsal_id": self.rehearsal_id,
            "executed_at": self.executed_at,
            "changed_by": self.changed_by,
            "reason": self.reason,
            "environment_name": self.environment_name,
            "expected_backend": self.expected_backend,
            "expected_repository_layout": self.expected_repository_layout,
            "database_backend": self.database_backend,
            "snapshot_repository_backend": self.snapshot_repository_backend,
            "audit_repository_backend": self.audit_repository_backend,
            "job_repository_backend": self.job_repository_backend,
            "repository_layout": self.repository_layout,
            "mixed_backends": self.mixed_backends,
            "snapshots_audits_repository_runtime_enabled": self.snapshots_audits_repository_runtime_enabled,
            "snapshots_audits_repository_runtime_active": self.snapshots_audits_repository_runtime_active,
            "job_repository_runtime_enabled": self.job_repository_runtime_enabled,
            "job_repository_runtime_active": self.job_repository_runtime_active,
            "database_runtime_available": self.database_runtime_available,
            "database_runtime_blockers": list(self.database_runtime_blockers),
            "checks": dict(self.checks),
            "status": self.status,
            "smoke": dict(self.smoke),
            "maintenance_event_id": self.maintenance_event_id,
        }


@dataclass(slots=True)
class ControlPlaneRuntimeRehearsalService:
    settings: Any
    job_repository: Any
    job_service: Any
    runtime_smoke_service: ControlPlaneRuntimeSmokeService
    now_factory: Any

    def run(
        self,
        *,
        changed_by: str,
        expected_backend: str,
        expected_repository_layout: str,
        reason: str | None = None,
        cleanup: bool = True,
    ) -> ControlPlaneRuntimeRehearsalSummary:
        rehearsal_id = uuid4().hex[:12]
        executed_at = self.now_factory()
        database_status = self.job_repository.database_status()
        smoke_summary = self.runtime_smoke_service.run(
            changed_by=changed_by,
            reason=reason,
            cleanup=cleanup,
        )
        smoke_payload = smoke_summary.to_dict()

        snapshots_audits_runtime_active = (
            smoke_summary.snapshot_repository_backend == "postgres"
            and smoke_summary.audit_repository_backend == "postgres"
        )
        checks = {
            "database_backend_matches_expected": str(database_status["backend"]) == expected_backend,
            "snapshot_repository_backend_matches_expected": smoke_summary.snapshot_repository_backend == expected_backend,
            "audit_repository_backend_matches_expected": smoke_summary.audit_repository_backend == expected_backend,
            "job_repository_backend_matches_expected": smoke_summary.job_repository_backend == expected_backend,
            "repository_layout_matches_expected": smoke_summary.repository_layout == expected_repository_layout,
            "database_runtime_available": bool(database_status["runtime_available"]),
            "snapshots_audits_repository_runtime_active_matches_expected": (
                snapshots_audits_runtime_active if expected_backend == "postgres" else not snapshots_audits_runtime_active
            ),
            "job_repository_runtime_active_matches_expected": (
                smoke_summary.job_repository_backend == "postgres"
                if expected_backend == "postgres"
                else smoke_summary.job_repository_backend != "postgres"
            ),
            "smoke_snapshot_round_trip_ok": smoke_summary.snapshot_round_trip_ok,
            "smoke_audit_round_trip_ok": smoke_summary.audit_round_trip_ok,
            "smoke_job_round_trip_ok": smoke_summary.job_round_trip_ok,
            "smoke_cleanup_satisfied": (not cleanup) or smoke_summary.cleanup_completed,
        }
        status = "passed" if all(checks.values()) else "failed"

        summary = ControlPlaneRuntimeRehearsalSummary(
            rehearsal_id=rehearsal_id,
            executed_at=executed_at,
            changed_by=changed_by,
            reason=reason,
            environment_name=self.settings.environment_name,
            expected_backend=expected_backend,
            expected_repository_layout=expected_repository_layout,
            database_backend=str(database_status["backend"]),
            snapshot_repository_backend=smoke_summary.snapshot_repository_backend,
            audit_repository_backend=smoke_summary.audit_repository_backend,
            job_repository_backend=smoke_summary.job_repository_backend,
            repository_layout=smoke_summary.repository_layout,
            mixed_backends=smoke_summary.mixed_backends,
            snapshots_audits_repository_runtime_enabled=self.settings.enable_postgres_runtime_snapshots_audits,
            snapshots_audits_repository_runtime_active=snapshots_audits_runtime_active,
            job_repository_runtime_enabled=self.settings.enable_postgres_runtime_jobs,
            job_repository_runtime_active=smoke_summary.job_repository_backend == "postgres",
            database_runtime_available=bool(database_status["runtime_available"]),
            database_runtime_blockers=[str(item) for item in database_status["runtime_blockers"]],
            checks=checks,
            status=status,
            smoke=smoke_payload,
        )
        event = self.job_service.record_maintenance_event(
            event_type="control_plane_runtime_rehearsal_executed",
            changed_by=changed_by,
            reason=reason,
            details=summary.to_dict(),
        )
        summary.maintenance_event_id = event.event_id
        return summary
