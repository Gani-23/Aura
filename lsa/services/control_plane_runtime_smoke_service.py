from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from lsa.core.models import IntentGraphSnapshot
from lsa.storage.files import AuditRepository, JobRepository, SnapshotRepository


@dataclass(slots=True)
class ControlPlaneRuntimeSmokeSummary:
    smoke_id: str
    executed_at: str
    changed_by: str
    reason: str | None
    snapshot_repository_backend: str
    audit_repository_backend: str
    job_repository_backend: str
    repository_layout: str
    mixed_backends: bool
    snapshot_id: str
    audit_id: str
    job_id: str
    snapshot_path: str
    report_path: str
    snapshot_round_trip_ok: bool
    audit_round_trip_ok: bool
    job_round_trip_ok: bool
    cleanup_requested: bool
    cleanup_completed: bool
    maintenance_event_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "smoke_id": self.smoke_id,
            "executed_at": self.executed_at,
            "changed_by": self.changed_by,
            "reason": self.reason,
            "snapshot_repository_backend": self.snapshot_repository_backend,
            "audit_repository_backend": self.audit_repository_backend,
            "job_repository_backend": self.job_repository_backend,
            "repository_layout": self.repository_layout,
            "mixed_backends": self.mixed_backends,
            "snapshot_id": self.snapshot_id,
            "audit_id": self.audit_id,
            "job_id": self.job_id,
            "snapshot_path": self.snapshot_path,
            "report_path": self.report_path,
            "snapshot_round_trip_ok": self.snapshot_round_trip_ok,
            "audit_round_trip_ok": self.audit_round_trip_ok,
            "job_round_trip_ok": self.job_round_trip_ok,
            "cleanup_requested": self.cleanup_requested,
            "cleanup_completed": self.cleanup_completed,
            "maintenance_event_id": self.maintenance_event_id,
        }


@dataclass(slots=True)
class ControlPlaneRuntimeSmokeService:
    settings: Any
    snapshot_repository: SnapshotRepository
    audit_repository: AuditRepository
    job_repository: JobRepository
    job_service: Any
    repository_layout: str
    mixed_backends: bool
    now_factory: Any

    def run(
        self,
        *,
        changed_by: str,
        reason: str | None = None,
        cleanup: bool = True,
    ) -> ControlPlaneRuntimeSmokeSummary:
        smoke_id = uuid4().hex[:12]
        snapshot_id = f"smoke-snapshot-{smoke_id}"
        audit_id = f"smoke-audit-{smoke_id}"
        job_id = f"smoke-job-{smoke_id}"
        executed_at = self.now_factory()
        report_path = self.settings.reports_dir / f"{smoke_id}.md"

        snapshot = IntentGraphSnapshot(root_path="control-plane-runtime-smoke", functions={}, edges=[])
        self.settings.reports_dir.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            "# Control-Plane Runtime Smoke\n\nThis is a synthetic runtime smoke report.\n",
            encoding="utf-8",
        )

        snapshot_record = self.snapshot_repository.save(
            snapshot,
            repo_path="control-plane-runtime-smoke",
            snapshot_id=snapshot_id,
        )
        fetched_snapshot = self.snapshot_repository.get(snapshot_id)

        audit_record = self.audit_repository.create(
            snapshot_id=snapshot_record.snapshot_id,
            snapshot_path=snapshot_record.snapshot_path,
            alerts=[],
            events=[],
            sessions=[],
            explanation={
                "status": "clean",
                "summary": "Control-plane runtime smoke completed successfully.",
                "alert_count": 0,
                "session_count": 0,
                "impacted_functions": [],
                "unexpected_targets": [],
                "expected_targets": [],
                "evidence": [],
            },
            report_paths=[str(report_path)],
            audit_id=audit_id,
        )
        fetched_audit = self.audit_repository.get(audit_id)

        job_record = self.job_repository.create(
            job_type="runtime-smoke",
            request_payload={"smoke_id": smoke_id},
            job_id=job_id,
        )
        fetched_job = self.job_repository.get(job_id)

        summary = ControlPlaneRuntimeSmokeSummary(
            smoke_id=smoke_id,
            executed_at=executed_at,
            changed_by=changed_by,
            reason=reason,
            snapshot_repository_backend=str(self.snapshot_repository.database.config.backend),
            audit_repository_backend=str(self.audit_repository.database.config.backend),
            job_repository_backend=str(self.job_repository.database.config.backend),
            repository_layout=self.repository_layout,
            mixed_backends=self.mixed_backends,
            snapshot_id=snapshot_id,
            audit_id=audit_id,
            job_id=job_id,
            snapshot_path=snapshot_record.snapshot_path,
            report_path=str(report_path),
            snapshot_round_trip_ok=fetched_snapshot.snapshot_id == snapshot_id,
            audit_round_trip_ok=fetched_audit.audit_id == audit_id and fetched_audit.snapshot_id == snapshot_id,
            job_round_trip_ok=fetched_job.job_id == job_id and fetched_job.request_payload.get("smoke_id") == smoke_id,
            cleanup_requested=cleanup,
            cleanup_completed=False,
        )

        if cleanup:
            cleanup_completed = self._cleanup(snapshot_id=snapshot_id, audit_id=audit_id, job_id=job_id, report_path=report_path)
            summary.cleanup_completed = cleanup_completed

        event = self.job_service.record_maintenance_event(
            event_type="control_plane_runtime_smoke_executed",
            changed_by=changed_by,
            reason=reason,
            details=summary.to_dict(),
        )
        summary.maintenance_event_id = event.event_id

        return summary

    def _cleanup(self, *, snapshot_id: str, audit_id: str, job_id: str, report_path: Path) -> bool:
        job_deleted = self.job_repository.delete(job_id)
        audit_deleted = self.audit_repository.delete(audit_id)
        snapshot_deleted = self.snapshot_repository.delete(snapshot_id)
        snapshot_path = Path(self.settings.snapshots_dir) / f"{snapshot_id}.json"
        if snapshot_path.exists():
            snapshot_path.unlink()
        if report_path.exists():
            report_path.unlink()
        return job_deleted and audit_deleted and snapshot_deleted
