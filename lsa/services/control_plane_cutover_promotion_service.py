from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from lsa.services.control_plane_cutover_readiness_service import (
    ControlPlaneCutoverReadinessService,
)
from lsa.services.job_service import JobService


@dataclass(slots=True)
class ControlPlaneCutoverPromotionSummary:
    decided_at: str
    environment_name: str
    requested_decision: Literal["approve", "reject"]
    final_decision: Literal["approved", "approved_with_override", "blocked", "rejected"]
    changed_by: str
    reason: str | None
    decision_note: str | None
    package_dir: str
    target_database_url: str
    target_database_redacted_url: str
    rehearsal_max_age_hours: float
    require_apply_rehearsal: bool
    require_runtime_validation: bool
    allow_override: bool
    override_applied: bool
    readiness: dict[str, Any]
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    maintenance_event: dict[str, Any] | None = None

    @property
    def approved(self) -> bool:
        return self.final_decision in {"approved", "approved_with_override"}

    def to_event_details(self) -> dict[str, Any]:
        return {
            "decided_at": self.decided_at,
            "environment_name": self.environment_name,
            "requested_decision": self.requested_decision,
            "final_decision": self.final_decision,
            "changed_by": self.changed_by,
            "reason": self.reason,
            "decision_note": self.decision_note,
            "package_dir": self.package_dir,
            "target_database_url": self.target_database_url,
            "target_database_redacted_url": self.target_database_redacted_url,
            "rehearsal_max_age_hours": self.rehearsal_max_age_hours,
            "require_apply_rehearsal": self.require_apply_rehearsal,
            "require_runtime_validation": self.require_runtime_validation,
            "allow_override": self.allow_override,
            "override_applied": self.override_applied,
            "readiness": dict(self.readiness),
            "blockers": list(self.blockers),
            "warnings": list(self.warnings),
            "approved": self.approved,
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self.to_event_details()
        payload["maintenance_event"] = None if self.maintenance_event is None else dict(self.maintenance_event)
        return payload


@dataclass(slots=True)
class ControlPlaneCutoverPromotionService:
    settings: Any
    job_service: JobService
    readiness_service: ControlPlaneCutoverReadinessService

    def decide(
        self,
        *,
        target_database_url: str,
        package_dir: str,
        changed_by: str,
        requested_decision: Literal["approve", "reject"] = "approve",
        reason: str | None = None,
        decision_note: str | None = None,
        rehearsal_max_age_hours: float = 24.0,
        require_apply_rehearsal: bool = False,
        require_runtime_validation: bool | None = None,
        allow_override: bool = False,
    ) -> ControlPlaneCutoverPromotionSummary:
        if requested_decision != "approve" and allow_override:
            raise ValueError("allow_override is only supported when requested_decision='approve'.")
        if allow_override and not decision_note:
            raise ValueError("decision_note is required when allow_override is enabled.")

        readiness = self.readiness_service.evaluate(
            target_database_url=target_database_url,
            package_dir=package_dir,
            rehearsal_max_age_hours=rehearsal_max_age_hours,
            require_apply_rehearsal=require_apply_rehearsal,
            require_runtime_validation=require_runtime_validation,
        )
        blockers = list(readiness.blockers)
        warnings = list(readiness.warnings)
        override_applied = False

        if requested_decision == "reject":
            final_decision: Literal["approved", "approved_with_override", "blocked", "rejected"] = "rejected"
            event_type = "postgres_cutover_rejected"
        elif readiness.ready:
            final_decision = "approved"
            event_type = "postgres_cutover_promoted"
        elif allow_override:
            final_decision = "approved_with_override"
            event_type = "postgres_cutover_promoted_with_override"
            override_applied = True
            warnings.append("override_applied_to_unready_cutover")
        else:
            final_decision = "blocked"
            event_type = "postgres_cutover_promotion_blocked"

        summary = ControlPlaneCutoverPromotionSummary(
            decided_at=readiness.evaluated_at,
            environment_name=self.settings.environment_name,
            requested_decision=requested_decision,
            final_decision=final_decision,
            changed_by=changed_by,
            reason=reason,
            decision_note=decision_note,
            package_dir=str(Path(package_dir).resolve()),
            target_database_url=readiness.target_database_url,
            target_database_redacted_url=readiness.target_database_redacted_url,
            rehearsal_max_age_hours=rehearsal_max_age_hours,
            require_apply_rehearsal=require_apply_rehearsal,
            require_runtime_validation=readiness.require_runtime_validation,
            allow_override=allow_override,
            override_applied=override_applied,
            readiness=readiness.to_dict(),
            blockers=blockers,
            warnings=warnings,
        )
        event = self.job_service.record_maintenance_event(
            event_type=event_type,
            changed_by=changed_by,
            reason=reason,
            details=summary.to_event_details(),
        )
        summary.maintenance_event = event.to_dict()
        return summary
