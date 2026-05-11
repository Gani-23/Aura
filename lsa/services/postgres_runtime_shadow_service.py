from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from lsa.settings import WorkspaceSettings
from lsa.storage.database import inspect_database_runtime_support
from lsa.storage.files import JobRepository, build_control_plane_database_for_url


@dataclass(slots=True)
class PostgresRuntimeShadowSyncSummary:
    synced_at: str
    environment_name: str
    changed_by: str
    reason: str | None
    target_database_url: str
    target_database_redacted_url: str
    runtime_supported: bool
    runtime_driver: str
    runtime_dependency_installed: bool
    runtime_available: bool
    runtime_blockers: list[str]
    source_event_count: int
    target_event_count: int
    synced_event_count: int
    source_job_count: int
    target_job_count: int
    synced_job_count: int
    source_worker_count: int
    target_worker_count: int
    synced_worker_count: int
    source_worker_heartbeat_count: int
    target_worker_heartbeat_count: int
    synced_worker_heartbeat_count: int
    source_job_lease_event_count: int
    target_job_lease_event_count: int
    synced_job_lease_event_count: int
    maintenance_mode: dict[str, Any]
    latest_target_event_id: str | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "synced_at": self.synced_at,
            "environment_name": self.environment_name,
            "changed_by": self.changed_by,
            "reason": self.reason,
            "target_database_url": self.target_database_url,
            "target_database_redacted_url": self.target_database_redacted_url,
            "runtime_supported": self.runtime_supported,
            "runtime_driver": self.runtime_driver,
            "runtime_dependency_installed": self.runtime_dependency_installed,
            "runtime_available": self.runtime_available,
            "runtime_blockers": list(self.runtime_blockers),
            "source_event_count": self.source_event_count,
            "target_event_count": self.target_event_count,
            "synced_event_count": self.synced_event_count,
            "source_job_count": self.source_job_count,
            "target_job_count": self.target_job_count,
            "synced_job_count": self.synced_job_count,
            "source_worker_count": self.source_worker_count,
            "target_worker_count": self.target_worker_count,
            "synced_worker_count": self.synced_worker_count,
            "source_worker_heartbeat_count": self.source_worker_heartbeat_count,
            "target_worker_heartbeat_count": self.target_worker_heartbeat_count,
            "synced_worker_heartbeat_count": self.synced_worker_heartbeat_count,
            "source_job_lease_event_count": self.source_job_lease_event_count,
            "target_job_lease_event_count": self.target_job_lease_event_count,
            "synced_job_lease_event_count": self.synced_job_lease_event_count,
            "maintenance_mode": dict(self.maintenance_mode),
            "latest_target_event_id": self.latest_target_event_id,
            "warnings": list(self.warnings),
        }


@dataclass(slots=True)
class PostgresRuntimeShadowService:
    settings: WorkspaceSettings
    source_job_repository: JobRepository
    target_repository_factory: Callable[[str], JobRepository] | None = None
    runtime_support_inspector: Callable[..., Any] = inspect_database_runtime_support
    now_factory: Callable[[], str] | None = None

    def sync_control_plane_slice(
        self,
        *,
        target_database_url: str,
        changed_by: str,
        reason: str | None = None,
    ) -> PostgresRuntimeShadowSyncSummary:
        runtime_support = self.runtime_support_inspector(
            root_dir=self.settings.root_dir,
            default_path=self.settings.database_path,
            raw_url=target_database_url,
            supported_backends=("postgres",),
        )
        if not runtime_support.runtime_available:
            raise ValueError(
                "Postgres runtime backend is not activatable for this target: "
                + ", ".join(runtime_support.blockers)
            )

        target_repository = self._build_target_repository(target_database_url)
        maintenance_mode = self.source_job_repository.maintenance_mode_status()
        target_repository.set_maintenance_mode(
            active=bool(maintenance_mode["active"]),
            changed_by=str(maintenance_mode.get("changed_by") or changed_by),
            reason=maintenance_mode.get("reason") or reason,
        )

        source_events = self.source_job_repository.list_control_plane_maintenance_events(limit=None)
        target_event_ids = {
            record.event_id for record in target_repository.list_control_plane_maintenance_events(limit=None)
        }
        synced_event_count = 0
        for record in reversed(source_events):
            if record.event_id in target_event_ids:
                continue
            target_repository.append_control_plane_maintenance_event(record)
            synced_event_count += 1

        source_jobs = self.source_job_repository.list()
        target_jobs_before = {record.job_id: record for record in target_repository.list()}
        synced_job_count = 0
        for record in source_jobs:
            if record.job_id not in target_jobs_before or target_jobs_before[record.job_id].to_dict() != record.to_dict():
                target_repository.save(record)
                synced_job_count += 1

        source_workers = self.source_job_repository.list_workers()
        target_workers_before = {record.worker_id: record for record in target_repository.list_workers()}
        synced_worker_count = 0
        for record in source_workers:
            if (
                record.worker_id not in target_workers_before
                or target_workers_before[record.worker_id].to_dict() != record.to_dict()
            ):
                target_repository.save_worker(record)
                synced_worker_count += 1

        source_worker_heartbeats = self.source_job_repository.list_worker_heartbeats()
        target_worker_heartbeat_ids = {
            record.heartbeat_id for record in target_repository.list_worker_heartbeats()
        }
        synced_worker_heartbeat_count = 0
        for record in reversed(source_worker_heartbeats):
            if record.heartbeat_id in target_worker_heartbeat_ids:
                continue
            target_repository.append_worker_heartbeat(record)
            synced_worker_heartbeat_count += 1

        source_job_lease_events = self.source_job_repository.list_job_lease_events()
        target_job_lease_event_ids = {
            record.event_id for record in target_repository.list_job_lease_events()
        }
        synced_job_lease_event_count = 0
        for record in reversed(source_job_lease_events):
            if record.event_id in target_job_lease_event_ids:
                continue
            target_repository.append_job_lease_event(record)
            synced_job_lease_event_count += 1

        target_events = target_repository.list_control_plane_maintenance_events(limit=None)
        target_jobs = target_repository.list()
        target_workers = target_repository.list_workers()
        target_worker_heartbeats = target_repository.list_worker_heartbeats()
        target_job_lease_events = target_repository.list_job_lease_events()
        warnings: list[str] = []
        if (
            synced_event_count == 0
            and synced_job_count == 0
            and synced_worker_count == 0
            and synced_worker_heartbeat_count == 0
            and synced_job_lease_event_count == 0
        ):
            warnings.append("no_new_control_plane_records_to_sync")
        return PostgresRuntimeShadowSyncSummary(
            synced_at=self._utc_now(),
            environment_name=self.settings.environment_name,
            changed_by=changed_by,
            reason=reason,
            target_database_url=runtime_support.url,
            target_database_redacted_url=runtime_support.redacted_url,
            runtime_supported=runtime_support.runtime_supported,
            runtime_driver=runtime_support.runtime_driver,
            runtime_dependency_installed=runtime_support.runtime_dependency_installed,
            runtime_available=runtime_support.runtime_available,
            runtime_blockers=list(runtime_support.blockers),
            source_event_count=len(source_events),
            target_event_count=len(target_events),
            synced_event_count=synced_event_count,
            source_job_count=len(source_jobs),
            target_job_count=len(target_jobs),
            synced_job_count=synced_job_count,
            source_worker_count=len(source_workers),
            target_worker_count=len(target_workers),
            synced_worker_count=synced_worker_count,
            source_worker_heartbeat_count=len(source_worker_heartbeats),
            target_worker_heartbeat_count=len(target_worker_heartbeats),
            synced_worker_heartbeat_count=synced_worker_heartbeat_count,
            source_job_lease_event_count=len(source_job_lease_events),
            target_job_lease_event_count=len(target_job_lease_events),
            synced_job_lease_event_count=synced_job_lease_event_count,
            maintenance_mode=target_repository.maintenance_mode_status(),
            latest_target_event_id=target_events[0].event_id if target_events else None,
            warnings=warnings,
        )

    def _build_target_repository(self, target_database_url: str) -> JobRepository:
        if self.target_repository_factory is not None:
            return self.target_repository_factory(target_database_url)
        return JobRepository(
            self.settings,
            database=build_control_plane_database_for_url(self.settings, raw_url=target_database_url),
        )

    def _utc_now(self) -> str:
        if self.now_factory is not None:
            return self.now_factory()
        from datetime import UTC, datetime

        return datetime.now(UTC).isoformat()
