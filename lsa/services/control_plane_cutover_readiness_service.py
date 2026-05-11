from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from lsa.services.control_plane_runtime_validation_service import ControlPlaneRuntimeValidationService
from lsa.services.control_plane_runtime_validation_review_service import ControlPlaneRuntimeValidationReviewService
from lsa.services.postgres_bootstrap_service import PostgresBootstrapService
from lsa.services.runtime_validation_policy import RuntimeValidationPolicy, load_runtime_validation_policy_bundle
from lsa.storage.database import inspect_database_config
from lsa.storage.files import JobRepository


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


@dataclass(slots=True)
class ControlPlaneCutoverReadinessSummary:
    evaluated_at: str
    environment_name: str
    target_database_url: str
    target_database_redacted_url: str
    package_dir: str
    rehearsal_max_age_hours: float
    require_apply_rehearsal: bool
    require_runtime_validation: bool
    latest_bundle_event: dict[str, Any] | None
    latest_rehearsal_event: dict[str, Any] | None
    runtime_validation: dict[str, Any]
    package_inspection: dict[str, Any] | None
    runtime_validation_change_control_requests: list[dict[str, Any]] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return not self.blockers

    def to_dict(self) -> dict[str, Any]:
        return {
            "evaluated_at": self.evaluated_at,
            "environment_name": self.environment_name,
            "target_database_url": self.target_database_url,
            "target_database_redacted_url": self.target_database_redacted_url,
            "package_dir": self.package_dir,
            "rehearsal_max_age_hours": self.rehearsal_max_age_hours,
            "require_apply_rehearsal": self.require_apply_rehearsal,
            "require_runtime_validation": self.require_runtime_validation,
            "latest_bundle_event": None if self.latest_bundle_event is None else dict(self.latest_bundle_event),
            "latest_rehearsal_event": None if self.latest_rehearsal_event is None else dict(self.latest_rehearsal_event),
            "runtime_validation": dict(self.runtime_validation),
            "runtime_validation_change_control_requests": [
                dict(item) for item in self.runtime_validation_change_control_requests
            ],
            "package_inspection": None if self.package_inspection is None else dict(self.package_inspection),
            "blockers": list(self.blockers),
            "warnings": list(self.warnings),
            "ready": self.ready,
        }


@dataclass(slots=True)
class ControlPlaneCutoverReadinessService:
    settings: Any
    job_repository: JobRepository
    bootstrap_service: PostgresBootstrapService

    def evaluate(
        self,
        *,
        target_database_url: str,
        package_dir: str,
        rehearsal_max_age_hours: float = 24.0,
        require_apply_rehearsal: bool = False,
        require_runtime_validation: bool | None = None,
    ) -> ControlPlaneCutoverReadinessSummary:
        target_config = inspect_database_config(
            root_dir=self.settings.root_dir,
            default_path=self.settings.database_path,
            raw_url=target_database_url,
        )
        package_path = str(Path(package_dir).resolve())
        blockers: list[str] = []
        warnings: list[str] = []
        effective_require_runtime_validation = (
            self.settings.cutover_runtime_validation_required
            if require_runtime_validation is None
            else require_runtime_validation
        )
        runtime_policy_bundle = load_runtime_validation_policy_bundle(
            self.settings.runtime_validation_policy_path
        )
        runtime_policy = runtime_policy_bundle.resolve(
            environment_name=self.settings.environment_name,
            fallback=RuntimeValidationPolicy(
                due_soon_age_hours=self.settings.analytics_runtime_rehearsal_due_soon_age_hours,
                warning_age_hours=self.settings.analytics_runtime_rehearsal_warning_age_hours,
                critical_age_hours=self.settings.analytics_runtime_rehearsal_critical_age_hours,
            ),
        )
        runtime_validation = ControlPlaneRuntimeValidationService(
            job_repository=self.job_repository,
            environment_name=self.settings.environment_name,
            due_soon_age_hours=runtime_policy.due_soon_age_hours
            or self.settings.analytics_runtime_rehearsal_due_soon_age_hours,
            warning_age_hours=runtime_policy.warning_age_hours
            or self.settings.analytics_runtime_rehearsal_warning_age_hours,
            critical_age_hours=runtime_policy.critical_age_hours
            or self.settings.analytics_runtime_rehearsal_critical_age_hours,
            policy_source=runtime_policy_bundle.source_for(environment_name=self.settings.environment_name),
        ).build_summary()
        review_service = ControlPlaneRuntimeValidationReviewService(
            settings=self.settings,
            job_service=None,
            job_repository=self.job_repository,
        )
        runtime_validation_change_control_requests = [
            request.to_dict()
            for request in review_service.list_change_control_requests(owner_team=None)
            if request.environment_name == self.settings.environment_name
            and request.status in {"pending_review", "rejected"}
        ]
        pending_change_control_requests = [
            request for request in runtime_validation_change_control_requests if request["status"] == "pending_review"
        ]
        rejected_change_control_requests = [
            request for request in runtime_validation_change_control_requests if request["status"] == "rejected"
        ]

        try:
            package_inspection = self.bootstrap_service.inspect_package(package_dir=package_dir).to_dict()
        except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError) as exc:
            blockers.append("package_inspection_failed")
            warnings.append(str(exc))
            package_inspection = None

        if package_inspection is not None and not bool(package_inspection.get("valid")):
            blockers.append("invalid_package")

        events = self.job_repository.list_control_plane_maintenance_events(limit=500)
        target_identity = {
            "backend": target_config.backend,
            "host": target_config.host,
            "port": target_config.port,
            "database_name": target_config.database_name,
            "username": target_config.username,
        }
        latest_bundle_event = self._find_latest_bundle_event(events, package_path, target_identity)
        latest_rehearsal_event = self._find_latest_rehearsal_event(events, package_path, target_database_url)

        if latest_bundle_event is None:
            blockers.append("missing_cutover_bundle_event")
        if latest_rehearsal_event is None:
            blockers.append("missing_rehearsal_event")
        else:
            if not bool(latest_rehearsal_event["details"].get("valid")):
                blockers.append("rehearsal_not_valid")
            if require_apply_rehearsal and not bool(latest_rehearsal_event["details"].get("apply_to_target")):
                blockers.append("apply_rehearsal_required")
            rehearsal_completed_at = _parse_ts(str(latest_rehearsal_event["details"].get("completed_at")))
            if rehearsal_completed_at is None:
                blockers.append("rehearsal_missing_completed_at")
            else:
                age = datetime.now(UTC) - rehearsal_completed_at.astimezone(UTC)
                if age > timedelta(hours=rehearsal_max_age_hours):
                    blockers.append("rehearsal_stale")
                    warnings.append(f"latest_rehearsal_age_hours={age.total_seconds() / 3600:.2f}")

            verification = latest_rehearsal_event["details"].get("verification")
            if verification is None:
                warnings.append("rehearsal_has_no_target_verification")
            elif not bool(verification.get("valid")):
                blockers.append("rehearsal_target_verification_failed")

        if latest_bundle_event and latest_rehearsal_event:
            bundle_generated_at = _parse_ts(str(latest_bundle_event["details"].get("generated_at")))
            rehearsal_started_at = _parse_ts(str(latest_rehearsal_event["details"].get("started_at")))
            if bundle_generated_at and rehearsal_started_at and rehearsal_started_at < bundle_generated_at:
                blockers.append("rehearsal_older_than_bundle")

        if runtime_validation.status != "passed":
            runtime_validation_code = f"runtime_validation_{runtime_validation.status}"
            if effective_require_runtime_validation:
                blockers.append(runtime_validation_code)
            else:
                warnings.append(runtime_validation_code)
        if pending_change_control_requests:
            blockers.append("runtime_validation_change_control_pending")
        if rejected_change_control_requests:
            blockers.append("runtime_validation_change_control_rejected")

        return ControlPlaneCutoverReadinessSummary(
            evaluated_at=_utc_now(),
            environment_name=self.settings.environment_name,
            target_database_url=target_config.url,
            target_database_redacted_url=target_config.redacted_url,
            package_dir=package_path,
            rehearsal_max_age_hours=rehearsal_max_age_hours,
            require_apply_rehearsal=require_apply_rehearsal,
            require_runtime_validation=effective_require_runtime_validation,
            latest_bundle_event=latest_bundle_event,
            latest_rehearsal_event=latest_rehearsal_event,
            runtime_validation=runtime_validation.to_dict(),
            runtime_validation_change_control_requests=runtime_validation_change_control_requests,
            package_inspection=package_inspection,
            blockers=blockers,
            warnings=warnings,
        )

    def _find_latest_bundle_event(
        self,
        events: list[Any],
        package_dir: str,
        target_identity: dict[str, Any],
    ) -> dict[str, Any] | None:
        for record in events:
            if record.event_type != "database_cutover_bundle_prepared":
                continue
            details = dict(record.details)
            bundle_package = details.get("postgres_bootstrap_package") or {}
            if str(bundle_package.get("output_dir", "")) != package_dir:
                continue
            target = details.get("target") or {}
            event_identity = {
                "backend": target.get("backend"),
                "host": target.get("host"),
                "port": target.get("port"),
                "database_name": target.get("database_name"),
                "username": target.get("username"),
            }
            if event_identity != target_identity:
                continue
            return record.to_dict()
        return None

    def _find_latest_rehearsal_event(
        self,
        events: list[Any],
        package_dir: str,
        target_database_url: str,
    ) -> dict[str, Any] | None:
        for record in events:
            if record.event_type != "postgres_cutover_rehearsed":
                continue
            details = dict(record.details)
            if str(details.get("package_dir", "")) != package_dir:
                continue
            if str(details.get("target_database_url", "")) != target_database_url:
                continue
            return record.to_dict()
        return None
