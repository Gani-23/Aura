from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from lsa.services.control_plane_maintenance_service import (
    ControlPlaneMaintenancePreflight,
    ControlPlaneMaintenanceService,
    ControlPlaneMaintenanceWorkflowSummary,
)
from lsa.services.postgres_bootstrap_service import PostgresBootstrapPackageSummary, PostgresBootstrapService
from lsa.storage.database import inspect_database_config


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class ControlPlaneCutoverTarget:
    backend: str
    url: str
    redacted_url: str
    runtime_supported: bool
    host: str | None
    port: int | None
    database_name: str | None
    username: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "url": self.url,
            "redacted_url": self.redacted_url,
            "runtime_supported": self.runtime_supported,
            "host": self.host,
            "port": self.port,
            "database_name": self.database_name,
            "username": self.username,
        }


@dataclass(slots=True)
class ControlPlaneCutoverPreflight:
    generated_at: str
    environment_name: str
    source_database_backend: str
    source_database_url: str
    source_database_redacted_url: str
    target: ControlPlaneCutoverTarget
    maintenance_preflight: ControlPlaneMaintenancePreflight
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def can_prepare(self) -> bool:
        return not self.blockers

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "environment_name": self.environment_name,
            "source_database_backend": self.source_database_backend,
            "source_database_url": self.source_database_url,
            "source_database_redacted_url": self.source_database_redacted_url,
            "target": self.target.to_dict(),
            "maintenance_preflight": self.maintenance_preflight.to_dict(),
            "blockers": list(self.blockers),
            "warnings": list(self.warnings),
            "can_prepare": self.can_prepare,
        }


@dataclass(slots=True)
class ControlPlaneCutoverBundleSummary:
    bundle_version: int
    generated_at: str
    environment_name: str
    source_database_backend: str
    source_database_url: str
    source_database_redacted_url: str
    target: ControlPlaneCutoverTarget
    path: str
    maintenance_workflow: ControlPlaneMaintenanceWorkflowSummary
    recommended_restore_order: list[str]
    postgres_bootstrap_package: PostgresBootstrapPackageSummary | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_version": self.bundle_version,
            "generated_at": self.generated_at,
            "environment_name": self.environment_name,
            "source_database_backend": self.source_database_backend,
            "source_database_url": self.source_database_url,
            "source_database_redacted_url": self.source_database_redacted_url,
            "target": self.target.to_dict(),
            "path": self.path,
            "maintenance_workflow": self.maintenance_workflow.to_dict(),
            "recommended_restore_order": list(self.recommended_restore_order),
            "postgres_bootstrap_package": None
            if self.postgres_bootstrap_package is None
            else self.postgres_bootstrap_package.to_dict(),
        }


class ControlPlaneCutoverService:
    def __init__(
        self,
        *,
        settings: Any,
        maintenance_service: ControlPlaneMaintenanceService,
        postgres_bootstrap_service: PostgresBootstrapService | None = None,
    ) -> None:
        self.settings = settings
        self.maintenance_service = maintenance_service
        self.postgres_bootstrap_service = postgres_bootstrap_service or PostgresBootstrapService()

    def build_preflight(self, *, target_database_url: str) -> ControlPlaneCutoverPreflight:
        source_config = inspect_database_config(
            root_dir=self.settings.root_dir,
            default_path=self.settings.database_path,
            raw_url=self.settings.database_url,
        )
        target_config = inspect_database_config(
            root_dir=self.settings.root_dir,
            default_path=self.settings.database_path,
            raw_url=target_database_url,
        )
        maintenance_preflight = self.maintenance_service.build_preflight()

        blockers: list[str] = list(maintenance_preflight.blockers)
        warnings: list[str] = list(maintenance_preflight.warnings)
        if source_config.redacted_url == target_config.redacted_url:
            blockers.append("target_matches_source_database")
        if target_config.backend == source_config.backend:
            warnings.append("target_backend_matches_source_backend")
        if not target_config.runtime_supported:
            warnings.append("target_backend_not_supported_by_current_runtime")

        return ControlPlaneCutoverPreflight(
            generated_at=_utc_now(),
            environment_name=self.settings.environment_name,
            source_database_backend=source_config.backend,
            source_database_url=source_config.url,
            source_database_redacted_url=source_config.redacted_url,
            target=ControlPlaneCutoverTarget(
                backend=target_config.backend,
                url=target_config.url,
                redacted_url=target_config.redacted_url,
                runtime_supported=target_config.runtime_supported,
                host=target_config.host,
                port=target_config.port,
                database_name=target_config.database_name,
                username=target_config.username,
            ),
            maintenance_preflight=maintenance_preflight,
            blockers=blockers,
            warnings=warnings,
        )

    def prepare_cutover_bundle(
        self,
        *,
        output_path: str,
        target_database_url: str,
        changed_by: str,
        reason: str | None = None,
        allow_running_jobs: bool = False,
        disable_maintenance_on_success: bool = True,
    ) -> ControlPlaneCutoverBundleSummary:
        preflight = self.build_preflight(target_database_url=target_database_url)
        effective_blockers = [
            blocker
            for blocker in preflight.blockers
            if not (allow_running_jobs and blocker == "running_jobs_present")
        ]
        if effective_blockers:
            raise ValueError(
                "Control-plane cutover preflight failed: " + ", ".join(sorted(effective_blockers))
            )

        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        maintenance_backup_path = target.with_suffix(".control-plane-backup.json")
        maintenance_summary = self.maintenance_service.execute_workflow(
            output_path=str(maintenance_backup_path),
            changed_by=changed_by,
            reason=reason or f"database cutover bundle for {preflight.target.redacted_url}",
            allow_running_jobs=allow_running_jobs,
            disable_maintenance_on_success=disable_maintenance_on_success,
        )
        postgres_bootstrap_package = None
        recommended_restore_order = [
            "provision_target_database",
            "restore_control_plane_backup_bundle",
            "verify_target_schema_state",
            "point_runtime_to_target_database_url",
            "run_post_cutover_health_checks",
        ]
        if preflight.target.backend == "postgres":
            recommended_restore_order.insert(2, "apply_postgres_bootstrap_package")

        summary = ControlPlaneCutoverBundleSummary(
            bundle_version=1,
            generated_at=_utc_now(),
            environment_name=self.settings.environment_name,
            source_database_backend=preflight.source_database_backend,
            source_database_url=preflight.source_database_url,
            source_database_redacted_url=preflight.source_database_redacted_url,
            target=preflight.target,
            path=str(target.resolve()),
            maintenance_workflow=maintenance_summary,
            recommended_restore_order=recommended_restore_order,
        )
        target.write_text(json.dumps(summary.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
        if preflight.target.backend == "postgres":
            bootstrap_output_dir = target.parent / f"{target.stem}.postgres-bootstrap"
            postgres_bootstrap_package = self.postgres_bootstrap_service.generate_from_cutover_bundle(
                cutover_bundle_path=str(target),
                output_dir=str(bootstrap_output_dir),
            )
            summary.postgres_bootstrap_package = postgres_bootstrap_package
            target.write_text(json.dumps(summary.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
        self.maintenance_service.job_service.record_maintenance_event(
            event_type="database_cutover_bundle_prepared",
            changed_by=changed_by,
            reason=reason,
            details=summary.to_dict(),
        )
        return summary
