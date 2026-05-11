from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from lsa.services.control_plane_runtime_validation_service import (
    ControlPlaneRuntimeValidationService,
    ControlPlaneRuntimeValidationSummary,
)
from lsa.services.runtime_validation_policy import RuntimeValidationPolicy, load_runtime_validation_policy_bundle
from lsa.storage.models import ControlPlaneMaintenanceEventRecord


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class RuntimeValidationReviewRequest:
    review_id: str
    opened_at: str
    opened_by: str
    environment_name: str
    status: str
    evidence_key: str
    trigger_status: str
    trigger_cadence_status: str
    summary: str
    latest_rehearsal_event_id: str | None = None
    latest_rehearsal_recorded_at: str | None = None
    due_in_hours: float | None = None
    next_due_at: str | None = None
    owner_team: str | None = None
    allowed_assignee_teams: tuple[str, ...] | None = None
    assigned_to: str | None = None
    assigned_to_team: str | None = None
    assigned_at: str | None = None
    assigned_by: str | None = None
    assignment_note: str | None = None
    resolved_at: str | None = None
    resolved_by: str | None = None
    resolution_note: str | None = None
    resolution_reason: str | None = None
    policy_source: str = "defaults"

    def to_dict(self) -> dict[str, Any]:
        return {
            "review_id": self.review_id,
            "opened_at": self.opened_at,
            "opened_by": self.opened_by,
            "environment_name": self.environment_name,
            "status": self.status,
            "evidence_key": self.evidence_key,
            "trigger_status": self.trigger_status,
            "trigger_cadence_status": self.trigger_cadence_status,
            "summary": self.summary,
            "latest_rehearsal_event_id": self.latest_rehearsal_event_id,
            "latest_rehearsal_recorded_at": self.latest_rehearsal_recorded_at,
            "due_in_hours": self.due_in_hours,
            "next_due_at": self.next_due_at,
            "owner_team": self.owner_team,
            "allowed_assignee_teams": None
            if self.allowed_assignee_teams is None
            else list(self.allowed_assignee_teams),
            "assigned_to": self.assigned_to,
            "assigned_to_team": self.assigned_to_team,
            "assigned_at": self.assigned_at,
            "assigned_by": self.assigned_by,
            "assignment_note": self.assignment_note,
            "resolved_at": self.resolved_at,
            "resolved_by": self.resolved_by,
            "resolution_note": self.resolution_note,
            "resolution_reason": self.resolution_reason,
            "policy_source": self.policy_source,
        }


@dataclass(slots=True)
class RuntimeValidationReviewAlertState:
    review: RuntimeValidationReviewRequest
    policy_source: str
    reminder_interval_seconds: float
    escalation_interval_seconds: float
    age_seconds: float
    status: str
    severity: str
    finding_codes: list[str]
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "review": self.review.to_dict(),
            "policy_source": self.policy_source,
            "reminder_interval_seconds": self.reminder_interval_seconds,
            "escalation_interval_seconds": self.escalation_interval_seconds,
            "age_seconds": self.age_seconds,
            "status": self.status,
            "severity": self.severity,
            "finding_codes": list(self.finding_codes),
            "summary": self.summary,
        }


@dataclass(slots=True)
class ControlPlaneRuntimeValidationReviewService:
    settings: Any
    job_service: Any
    job_repository: Any

    OPENED_EVENT_TYPE = "runtime_validation_review_opened"
    ASSIGNED_EVENT_TYPE = "runtime_validation_review_assigned"
    RESOLVED_EVENT_TYPE = "runtime_validation_review_resolved"

    def list_reviews(self, *, status: str | None = None) -> list[RuntimeValidationReviewRequest]:
        reviews = self._rebuild_reviews()
        if status is None:
            return reviews
        normalized = status.strip().lower()
        return [review for review in reviews if review.status == normalized]

    def get_review(self, review_id: str) -> RuntimeValidationReviewRequest:
        for review in self._rebuild_reviews():
            if review.review_id == review_id:
                return review
        raise FileNotFoundError(f"Runtime-validation review '{review_id}' was not found.")

    def active_review(
        self,
        *,
        environment_name: str | None = None,
    ) -> RuntimeValidationReviewRequest | None:
        effective_environment = environment_name or self.settings.environment_name
        for review in self._rebuild_reviews():
            if review.environment_name != effective_environment:
                continue
            if review.status == "resolved":
                continue
            return review
        return None

    def build_alert_state(self, *, force: bool = False) -> RuntimeValidationReviewAlertState | None:
        review = self.active_review()
        if review is None:
            return None
        policy, policy_source = self._effective_policy(review.environment_name)
        reminder_interval_seconds = (
            policy.reminder_interval_seconds or self.settings.control_plane_alert_reminder_interval_seconds
        )
        escalation_interval_seconds = (
            policy.escalation_interval_seconds or self.settings.control_plane_alert_escalation_interval_seconds
        )
        age_seconds = max(
            (datetime.now(UTC) - datetime.fromisoformat(review.opened_at)).total_seconds(),
            0.0,
        )
        if not force and age_seconds < reminder_interval_seconds:
            return None

        is_assigned = review.assigned_to is not None
        overdue = escalation_interval_seconds <= reminder_interval_seconds if force else age_seconds >= escalation_interval_seconds
        if overdue:
            if is_assigned:
                finding_codes = ["runtime_validation_review_overdue"]
                summary = (
                    f"Runtime-proof review is still unresolved after {int(age_seconds // 60)} minutes "
                    f"and remains assigned to {review.assigned_to}."
                )
            else:
                finding_codes = ["runtime_validation_review_unassigned_overdue"]
                summary = (
                    f"Runtime-proof review has been unassigned for {int(age_seconds // 60)} minutes "
                    "and now requires escalation."
                )
            return RuntimeValidationReviewAlertState(
                review=review,
                policy_source=policy_source,
                reminder_interval_seconds=reminder_interval_seconds,
                escalation_interval_seconds=escalation_interval_seconds,
                age_seconds=age_seconds,
                status="critical",
                severity="critical",
                finding_codes=finding_codes,
                summary=summary,
            )

        if is_assigned:
            finding_codes = ["runtime_validation_review_pending"]
            summary = (
                f"Runtime-proof review is still pending after {int(age_seconds // 60)} minutes "
                f"and is currently assigned to {review.assigned_to}."
            )
        else:
            finding_codes = ["runtime_validation_review_unassigned"]
            summary = (
                f"Runtime-proof review has been waiting unassigned for {int(age_seconds // 60)} minutes."
            )
        return RuntimeValidationReviewAlertState(
            review=review,
            policy_source=policy_source,
            reminder_interval_seconds=reminder_interval_seconds,
            escalation_interval_seconds=escalation_interval_seconds,
            age_seconds=age_seconds,
            status="degraded",
            severity="warning",
            finding_codes=finding_codes,
            summary=summary,
        )

    def process_reviews(
        self,
        *,
        changed_by: str,
        reason: str | None = None,
        force: bool = False,
    ) -> list[RuntimeValidationReviewRequest]:
        summary = self._build_runtime_validation_summary()
        reviews = self._rebuild_reviews()
        active = next(
            (
                review
                for review in reviews
                if review.environment_name == self.settings.environment_name and review.status != "resolved"
            ),
            None,
        )
        changed: list[RuntimeValidationReviewRequest] = []
        if not self._summary_requires_review(summary):
            if active is not None:
                changed.append(
                    self.resolve_review(
                        review_id=active.review_id,
                        resolved_by=changed_by,
                        resolution_note=reason or "Runtime proof returned to policy.",
                        resolution_reason="runtime_proof_restored",
                    )
                )
            return changed

        evidence_key = self._review_evidence_key(summary)
        if active is None:
            changed.append(
                self._open_review(
                    changed_by=changed_by,
                    reason=reason,
                    summary=summary,
                    evidence_key=evidence_key,
                )
            )
            return changed

        if force and active.evidence_key != evidence_key:
            changed.append(
                self.resolve_review(
                    review_id=active.review_id,
                    resolved_by=changed_by,
                    resolution_note="Superseded by newer runtime-validation evidence.",
                    resolution_reason="superseded",
                )
            )
            changed.append(
                self._open_review(
                    changed_by=changed_by,
                    reason=reason,
                    summary=summary,
                    evidence_key=evidence_key,
                )
            )
        return changed

    def assign_review(
        self,
        *,
        review_id: str,
        assigned_to: str,
        assigned_to_team: str | None,
        assigned_by: str,
        assignment_note: str | None = None,
    ) -> RuntimeValidationReviewRequest:
        review = self.get_review(review_id)
        if review.status == "resolved":
            raise ValueError(f"Runtime-validation review '{review_id}' is already resolved.")
        normalized_assigned_to = assigned_to.strip()
        if not normalized_assigned_to:
            raise ValueError("assigned_to must not be empty.")
        normalized_team = self._normalize_team(assigned_to_team)
        if review.owner_team is not None and normalized_team is None:
            raise ValueError("assigned_to_team is required for policy-governed runtime-validation reviews.")
        if review.owner_team is not None and normalized_team != review.owner_team:
            raise ValueError("assigned_to_team does not match the owner_team required by runtime-validation policy.")
        if review.allowed_assignee_teams is not None and normalized_team not in review.allowed_assignee_teams:
            raise ValueError("assigned_to_team is not allowed by runtime-validation policy.")
        self.job_service.record_maintenance_event(
            event_type=self.ASSIGNED_EVENT_TYPE,
            changed_by=assigned_by,
            reason=assignment_note,
            details={
                "review_id": review_id,
                "assigned_to": normalized_assigned_to,
                "assigned_to_team": normalized_team,
                "assigned_at": _utc_now(),
                "assigned_by": assigned_by,
                "assignment_note": assignment_note,
            },
        )
        return self.get_review(review_id)

    def resolve_review(
        self,
        *,
        review_id: str,
        resolved_by: str,
        resolution_note: str | None,
        resolution_reason: str,
    ) -> RuntimeValidationReviewRequest:
        review = self.get_review(review_id)
        if review.status == "resolved":
            return review
        self.job_service.record_maintenance_event(
            event_type=self.RESOLVED_EVENT_TYPE,
            changed_by=resolved_by,
            reason=resolution_note,
            details={
                "review_id": review_id,
                "resolved_at": _utc_now(),
                "resolved_by": resolved_by,
                "resolution_note": resolution_note,
                "resolution_reason": resolution_reason,
            },
        )
        return self.get_review(review_id)

    def _open_review(
        self,
        *,
        changed_by: str,
        reason: str | None,
        summary: ControlPlaneRuntimeValidationSummary,
        evidence_key: str,
    ) -> RuntimeValidationReviewRequest:
        review_id = uuid4().hex[:16]
        policy, policy_source = self._effective_policy(summary.environment_name)
        self.job_service.record_maintenance_event(
            event_type=self.OPENED_EVENT_TYPE,
            changed_by=changed_by,
            reason=reason,
            details={
                "review_id": review_id,
                "opened_at": _utc_now(),
                "opened_by": changed_by,
                "environment_name": summary.environment_name,
                "evidence_key": evidence_key,
                "trigger_status": summary.status,
                "trigger_cadence_status": summary.cadence_status,
                "summary": self._summary_text(summary),
                "latest_rehearsal_event_id": summary.latest_rehearsal_event_id,
                "latest_rehearsal_recorded_at": summary.latest_rehearsal_recorded_at,
                "due_in_hours": summary.due_in_hours,
                "next_due_at": summary.next_due_at,
                "owner_team": policy.owner_team,
                "allowed_assignee_teams": None
                if policy.allowed_assignee_teams is None
                else list(policy.allowed_assignee_teams),
                "policy_source": policy_source,
            },
        )
        if policy.auto_assign_to is not None:
            return self.assign_review(
                review_id=review_id,
                assigned_to=policy.auto_assign_to,
                assigned_to_team=policy.auto_assign_to_team,
                assigned_by=changed_by,
                assignment_note="Auto-assigned by runtime-validation policy.",
            )
        return self.get_review(review_id)

    def _rebuild_reviews(self) -> list[RuntimeValidationReviewRequest]:
        reviews: dict[str, RuntimeValidationReviewRequest] = {}
        events = list(reversed(self.job_repository.list_control_plane_maintenance_events(limit=2000)))
        for record in events:
            details = dict(record.details)
            if record.event_type == self.OPENED_EVENT_TYPE:
                review_id = str(details["review_id"])
                reviews[review_id] = RuntimeValidationReviewRequest(
                    review_id=review_id,
                    opened_at=str(details["opened_at"]),
                    opened_by=str(details["opened_by"]),
                    environment_name=str(details["environment_name"]),
                    status="pending_review",
                    evidence_key=str(details["evidence_key"]),
                    trigger_status=str(details["trigger_status"]),
                    trigger_cadence_status=str(details["trigger_cadence_status"]),
                    summary=str(details["summary"]),
                    latest_rehearsal_event_id=_optional_str(details.get("latest_rehearsal_event_id")),
                    latest_rehearsal_recorded_at=_optional_str(details.get("latest_rehearsal_recorded_at")),
                    due_in_hours=_optional_float(details.get("due_in_hours")),
                    next_due_at=_optional_str(details.get("next_due_at")),
                    owner_team=_optional_str(details.get("owner_team")),
                    allowed_assignee_teams=_optional_string_tuple(details.get("allowed_assignee_teams")),
                    policy_source=str(details.get("policy_source", "defaults")),
                )
            elif record.event_type == self.ASSIGNED_EVENT_TYPE:
                review_id = str(details.get("review_id", ""))
                if review_id not in reviews:
                    continue
                review = reviews[review_id]
                review.status = "assigned"
                review.assigned_to = _optional_str(details.get("assigned_to"))
                review.assigned_to_team = _optional_str(details.get("assigned_to_team"))
                review.assigned_at = _optional_str(details.get("assigned_at"))
                review.assigned_by = _optional_str(details.get("assigned_by"))
                review.assignment_note = _optional_str(details.get("assignment_note"))
            elif record.event_type == self.RESOLVED_EVENT_TYPE:
                review_id = str(details.get("review_id", ""))
                if review_id not in reviews:
                    continue
                review = reviews[review_id]
                review.status = "resolved"
                review.resolved_at = _optional_str(details.get("resolved_at"))
                review.resolved_by = _optional_str(details.get("resolved_by"))
                review.resolution_note = _optional_str(details.get("resolution_note"))
                review.resolution_reason = _optional_str(details.get("resolution_reason"))
        return sorted(reviews.values(), key=lambda item: item.opened_at, reverse=True)

    def _build_runtime_validation_summary(self) -> ControlPlaneRuntimeValidationSummary:
        policy, policy_source = self._effective_policy(self.settings.environment_name)
        return ControlPlaneRuntimeValidationService(
            job_repository=self.job_repository,
            environment_name=self.settings.environment_name,
            due_soon_age_hours=policy.due_soon_age_hours
            or self.settings.analytics_runtime_rehearsal_due_soon_age_hours,
            warning_age_hours=policy.warning_age_hours
            or self.settings.analytics_runtime_rehearsal_warning_age_hours,
            critical_age_hours=policy.critical_age_hours
            or self.settings.analytics_runtime_rehearsal_critical_age_hours,
            policy_source=policy_source,
            reminder_interval_seconds=policy.reminder_interval_seconds,
            escalation_interval_seconds=policy.escalation_interval_seconds,
        ).build_summary()

    def _effective_policy(self, environment_name: str) -> tuple[RuntimeValidationPolicy, str]:
        bundle = load_runtime_validation_policy_bundle(self.settings.runtime_validation_policy_path)
        policy = bundle.resolve(
            environment_name=environment_name,
            fallback=RuntimeValidationPolicy(
                due_soon_age_hours=self.settings.analytics_runtime_rehearsal_due_soon_age_hours,
                warning_age_hours=self.settings.analytics_runtime_rehearsal_warning_age_hours,
                critical_age_hours=self.settings.analytics_runtime_rehearsal_critical_age_hours,
                reminder_interval_seconds=self.settings.control_plane_alert_reminder_interval_seconds,
                escalation_interval_seconds=self.settings.control_plane_alert_escalation_interval_seconds,
            ),
        )
        return policy, bundle.source_for(environment_name=environment_name)

    def _summary_requires_review(self, summary: ControlPlaneRuntimeValidationSummary) -> bool:
        if summary.status in {"missing", "failed", "warning", "critical"}:
            return True
        return summary.cadence_status == "due_soon"

    def _review_evidence_key(self, summary: ControlPlaneRuntimeValidationSummary) -> str:
        if summary.latest_rehearsal_event_id:
            return f"{summary.environment_name}:{summary.latest_rehearsal_event_id}:{summary.cadence_status}"
        return f"{summary.environment_name}:{summary.status}:{summary.cadence_status}"

    def _summary_text(self, summary: ControlPlaneRuntimeValidationSummary) -> str:
        if summary.status == "missing":
            return "No runtime-proof evidence exists for this environment."
        if summary.status == "failed":
            return "The latest runtime rehearsal failed and needs review."
        if summary.cadence_status == "due_soon":
            return "Runtime proof is approaching its warning threshold and should be refreshed."
        if summary.cadence_status == "aging":
            return "Runtime proof is older than the warning threshold."
        if summary.cadence_status == "overdue":
            return "Runtime proof is older than the critical threshold."
        return "Runtime-proof review requested."

    def _normalize_team(self, raw_value: str | None) -> str | None:
        if raw_value is None:
            return None
        normalized = raw_value.strip().lower()
        return normalized or None


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text or None


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _optional_string_tuple(value: Any) -> tuple[str, ...] | None:
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        values = [str(item).strip().lower() for item in value if str(item).strip()]
        return tuple(values) or None
    return None
