from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from lsa.services.control_plane_runtime_validation_review_service import ControlPlaneRuntimeValidationReviewService
from lsa.services.control_plane_runtime_validation_service import ControlPlaneRuntimeValidationService
from lsa.services.runtime_validation_policy import RuntimeValidationPolicy, load_runtime_validation_policy_bundle


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class ControlPlaneDeploymentReadinessOwnerTeamRollup:
    owner_team: str
    total_blocking_requests: int
    pending_review_count: int
    rejected_count: int
    assigned_count: int
    unassigned_count: int
    oldest_rejected_age_hours: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "owner_team": self.owner_team,
            "total_blocking_requests": self.total_blocking_requests,
            "pending_review_count": self.pending_review_count,
            "rejected_count": self.rejected_count,
            "assigned_count": self.assigned_count,
            "unassigned_count": self.unassigned_count,
            "oldest_rejected_age_hours": self.oldest_rejected_age_hours,
        }


@dataclass(slots=True)
class ControlPlaneDeploymentReadinessSummary:
    evaluated_at: str
    environment_name: str
    runtime_validation: dict[str, Any]
    runtime_validation_change_control_requests: list[dict[str, Any]] = field(default_factory=list)
    owner_team_rollups: list[ControlPlaneDeploymentReadinessOwnerTeamRollup] = field(default_factory=list)
    oldest_rejected_age_hours: float | None = None
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return not self.blockers

    def to_dict(self) -> dict[str, Any]:
        return {
            "evaluated_at": self.evaluated_at,
            "environment_name": self.environment_name,
            "runtime_validation": dict(self.runtime_validation),
            "runtime_validation_change_control_requests": [
                dict(item) for item in self.runtime_validation_change_control_requests
            ],
            "owner_team_rollups": [item.to_dict() for item in self.owner_team_rollups],
            "blocked_owner_team_count": len(self.owner_team_rollups),
            "oldest_rejected_age_hours": self.oldest_rejected_age_hours,
            "blockers": list(self.blockers),
            "warnings": list(self.warnings),
            "ready": self.ready,
        }


@dataclass(slots=True)
class ControlPlaneDeploymentReadinessService:
    settings: Any
    job_repository: Any
    job_service: Any

    def evaluate(self) -> ControlPlaneDeploymentReadinessSummary:
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
            job_service=self.job_service,
            job_repository=self.job_repository,
        )
        now = datetime.now(UTC)
        change_control_requests = [
            request.to_dict()
            for request in review_service.list_change_control_requests(owner_team=None)
            if request.environment_name == self.settings.environment_name
            and request.status in {"pending_review", "rejected"}
        ]
        owner_team_rollups_by_key: dict[str, dict[str, int]] = {}
        oldest_rejected_age_hours: float | None = None
        for request in change_control_requests:
            owner_key = str(request.get("owner_team") or "unowned")
            rollup = owner_team_rollups_by_key.setdefault(
                owner_key,
                {
                    "total_blocking_requests": 0,
                    "pending_review_count": 0,
                    "rejected_count": 0,
                    "assigned_count": 0,
                    "unassigned_count": 0,
                    "oldest_rejected_age_hours": None,
                },
            )
            rollup["total_blocking_requests"] += 1
            if request["status"] == "pending_review":
                rollup["pending_review_count"] += 1
            elif request["status"] == "rejected":
                rollup["rejected_count"] += 1
                age_hours = max(
                    (now - datetime.fromisoformat(str(request["opened_at"]))).total_seconds() / 3600.0,
                    0.0,
                )
                oldest_rejected_age_hours = (
                    age_hours
                    if oldest_rejected_age_hours is None
                    else max(oldest_rejected_age_hours, age_hours)
                )
                current_rollup_age = rollup["oldest_rejected_age_hours"]
                rollup["oldest_rejected_age_hours"] = (
                    age_hours
                    if current_rollup_age is None
                    else max(float(current_rollup_age), age_hours)
                )
            if request.get("assigned_to"):
                rollup["assigned_count"] += 1
            else:
                rollup["unassigned_count"] += 1
        blockers: list[str] = []
        warnings: list[str] = []
        if runtime_validation.status != "passed":
            blockers.append(f"runtime_validation_{runtime_validation.status}")
        if any(item["status"] == "pending_review" for item in change_control_requests):
            blockers.append("runtime_validation_change_control_pending")
        if any(item["status"] == "rejected" for item in change_control_requests):
            blockers.append("runtime_validation_change_control_rejected")
        if (
            oldest_rejected_age_hours is not None
            and oldest_rejected_age_hours >= self.settings.analytics_deployment_rejected_change_control_critical_age_hours
        ):
            blockers.append("runtime_validation_change_control_rejected_stale")
        if self.job_service.is_maintenance_mode_active():
            warnings.append("maintenance_mode_active")
        return ControlPlaneDeploymentReadinessSummary(
            evaluated_at=_utc_now(),
            environment_name=self.settings.environment_name,
            runtime_validation=runtime_validation.to_dict(),
            runtime_validation_change_control_requests=change_control_requests,
            owner_team_rollups=[
                ControlPlaneDeploymentReadinessOwnerTeamRollup(
                    owner_team=owner_team,
                    total_blocking_requests=values["total_blocking_requests"],
                    pending_review_count=values["pending_review_count"],
                    rejected_count=values["rejected_count"],
                    assigned_count=values["assigned_count"],
                    unassigned_count=values["unassigned_count"],
                    oldest_rejected_age_hours=(
                        None
                        if values["oldest_rejected_age_hours"] is None
                        else round(float(values["oldest_rejected_age_hours"]), 2)
                    ),
                )
                for owner_team, values in sorted(
                    owner_team_rollups_by_key.items(),
                    key=lambda item: (
                        -item[1]["rejected_count"],
                        -item[1]["total_blocking_requests"],
                        item[0],
                    ),
                )
            ],
            oldest_rejected_age_hours=(
                None if oldest_rejected_age_hours is None else round(oldest_rejected_age_hours, 2)
            ),
            blockers=blockers,
            warnings=warnings,
        )
