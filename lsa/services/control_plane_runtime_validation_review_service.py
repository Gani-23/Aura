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
class RuntimeValidationReviewOwnerQueueRollup:
    owner_team: str
    total_reviews: int
    assigned_reviews: int
    unassigned_reviews: int
    stale_reviews: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "owner_team": self.owner_team,
            "total_reviews": self.total_reviews,
            "assigned_reviews": self.assigned_reviews,
            "unassigned_reviews": self.unassigned_reviews,
            "stale_reviews": self.stale_reviews,
        }


@dataclass(slots=True)
class RuntimeValidationReviewQueueSummary:
    environment_name: str
    total_reviews: int
    assigned_reviews: int
    unassigned_reviews: int
    stale_reviews: int
    stale_unassigned_reviews: int
    oldest_review_age_hours: float | None
    owner_team_rollups: list[RuntimeValidationReviewOwnerQueueRollup]
    reviews: list[RuntimeValidationReviewRequest]

    def to_dict(self) -> dict[str, Any]:
        return {
            "environment_name": self.environment_name,
            "total_reviews": self.total_reviews,
            "assigned_reviews": self.assigned_reviews,
            "unassigned_reviews": self.unassigned_reviews,
            "stale_reviews": self.stale_reviews,
            "stale_unassigned_reviews": self.stale_unassigned_reviews,
            "oldest_review_age_hours": self.oldest_review_age_hours,
            "owner_team_rollups": [item.to_dict() for item in self.owner_team_rollups],
            "reviews": [item.to_dict() for item in self.reviews],
        }


@dataclass(slots=True)
class RuntimeValidationReviewBulkActionResult:
    environment_name: str
    action: str
    matched_count: int
    changed_count: int
    reviews: list[RuntimeValidationReviewRequest]

    def to_dict(self) -> dict[str, Any]:
        return {
            "environment_name": self.environment_name,
            "action": self.action,
            "matched_count": self.matched_count,
            "changed_count": self.changed_count,
            "reviews": [item.to_dict() for item in self.reviews],
        }


@dataclass(slots=True)
class RuntimeValidationReviewSLA:
    warning_age_hours: float
    critical_age_hours: float


@dataclass(slots=True)
class RuntimeValidationGovernanceRequest:
    request_id: str
    opened_at: str
    opened_by: str
    environment_name: str
    review_id: str
    owner_team: str | None
    review_opened_at: str
    summary: str
    status: str
    trigger_code: str
    policy_source: str
    assigned_to: str | None = None
    assigned_to_team: str | None = None
    resolved_at: str | None = None
    resolved_by: str | None = None
    resolution_note: str | None = None
    resolution_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "opened_at": self.opened_at,
            "opened_by": self.opened_by,
            "environment_name": self.environment_name,
            "review_id": self.review_id,
            "owner_team": self.owner_team,
            "review_opened_at": self.review_opened_at,
            "summary": self.summary,
            "status": self.status,
            "trigger_code": self.trigger_code,
            "policy_source": self.policy_source,
            "assigned_to": self.assigned_to,
            "assigned_to_team": self.assigned_to_team,
            "resolved_at": self.resolved_at,
            "resolved_by": self.resolved_by,
            "resolution_note": self.resolution_note,
            "resolution_reason": self.resolution_reason,
        }


@dataclass(slots=True)
class RuntimeValidationChangeControlRequest:
    request_id: str
    opened_at: str
    opened_by: str
    environment_name: str
    governance_request_id: str
    review_id: str
    owner_team: str | None
    summary: str
    status: str
    trigger_code: str
    policy_source: str
    assigned_to: str | None = None
    assigned_to_team: str | None = None
    assigned_at: str | None = None
    assigned_by: str | None = None
    assignment_note: str | None = None
    resolved_at: str | None = None
    resolved_by: str | None = None
    resolution_note: str | None = None
    resolution_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "opened_at": self.opened_at,
            "opened_by": self.opened_by,
            "environment_name": self.environment_name,
            "governance_request_id": self.governance_request_id,
            "review_id": self.review_id,
            "owner_team": self.owner_team,
            "summary": self.summary,
            "status": self.status,
            "trigger_code": self.trigger_code,
            "policy_source": self.policy_source,
            "assigned_to": self.assigned_to,
            "assigned_to_team": self.assigned_to_team,
            "assigned_at": self.assigned_at,
            "assigned_by": self.assigned_by,
            "assignment_note": self.assignment_note,
            "resolved_at": self.resolved_at,
            "resolved_by": self.resolved_by,
            "resolution_note": self.resolution_note,
            "resolution_reason": self.resolution_reason,
        }


@dataclass(slots=True)
class RuntimeValidationChangeControlQueueSummary:
    environment_name: str
    total_requests: int
    assigned_requests: int
    unassigned_requests: int
    pending_review_count: int
    rejected_count: int
    owner_team_rollups: list[dict[str, Any]]
    requests: list[RuntimeValidationChangeControlRequest]

    def to_dict(self) -> dict[str, Any]:
        return {
            "environment_name": self.environment_name,
            "total_requests": self.total_requests,
            "assigned_requests": self.assigned_requests,
            "unassigned_requests": self.unassigned_requests,
            "pending_review_count": self.pending_review_count,
            "rejected_count": self.rejected_count,
            "owner_team_rollups": [dict(item) for item in self.owner_team_rollups],
            "requests": [item.to_dict() for item in self.requests],
        }


@dataclass(slots=True)
class RuntimeValidationChangeControlBulkActionResult:
    environment_name: str
    action: str
    matched_count: int
    changed_count: int
    requests: list[RuntimeValidationChangeControlRequest]

    def to_dict(self) -> dict[str, Any]:
        return {
            "environment_name": self.environment_name,
            "action": self.action,
            "matched_count": self.matched_count,
            "changed_count": self.changed_count,
            "requests": [item.to_dict() for item in self.requests],
        }


@dataclass(slots=True)
class ControlPlaneRuntimeValidationReviewService:
    settings: Any
    job_service: Any
    job_repository: Any

    OPENED_EVENT_TYPE = "runtime_validation_review_opened"
    ASSIGNED_EVENT_TYPE = "runtime_validation_review_assigned"
    RESOLVED_EVENT_TYPE = "runtime_validation_review_resolved"
    GOVERNANCE_OPENED_EVENT_TYPE = "runtime_validation_governance_opened"
    GOVERNANCE_RESOLVED_EVENT_TYPE = "runtime_validation_governance_resolved"
    CHANGE_CONTROL_OPENED_EVENT_TYPE = "runtime_validation_change_control_opened"
    CHANGE_CONTROL_ASSIGNED_EVENT_TYPE = "runtime_validation_change_control_assigned"
    CHANGE_CONTROL_DECIDED_EVENT_TYPE = "runtime_validation_change_control_decided"
    CHANGE_CONTROL_RESOLVED_EVENT_TYPE = "runtime_validation_change_control_resolved"

    def list_reviews(
        self,
        *,
        status: str | None = None,
        owner_team: str | None = None,
        assignment_state: str | None = None,
    ) -> list[RuntimeValidationReviewRequest]:
        reviews = self._rebuild_reviews()
        if status is not None:
            normalized = status.strip().lower()
            reviews = [review for review in reviews if review.status == normalized]
        if owner_team is not None:
            normalized_owner_team = owner_team.strip().lower()
            reviews = [review for review in reviews if review.owner_team == normalized_owner_team]
        if assignment_state is not None:
            normalized_assignment_state = assignment_state.strip().lower()
            if normalized_assignment_state == "assigned":
                reviews = [review for review in reviews if review.assigned_to is not None]
            elif normalized_assignment_state == "unassigned":
                reviews = [review for review in reviews if review.assigned_to is None]
            elif normalized_assignment_state != "any":
                raise ValueError("assignment_state must be one of: assigned, unassigned, any.")
        return reviews

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

    def queue_summary(
        self,
        *,
        status: str | None = None,
        owner_team: str | None = None,
        assignment_state: str | None = None,
    ) -> RuntimeValidationReviewQueueSummary:
        reviews = self.list_reviews(
            status=status,
            owner_team=owner_team,
            assignment_state=assignment_state,
        )
        fallback_policy = self._fallback_policy()
        assigned_reviews = 0
        unassigned_reviews = 0
        stale_reviews = 0
        stale_unassigned_reviews = 0
        oldest_review_age_hours: float | None = None
        owner_team_rollups: dict[str, dict[str, int]] = {}
        now = datetime.now(UTC)

        for review in reviews:
            if review.assigned_to is not None:
                assigned_reviews += 1
            else:
                unassigned_reviews += 1
            age_hours = max((now - datetime.fromisoformat(review.opened_at)).total_seconds() / 3600.0, 0.0)
            if oldest_review_age_hours is None or age_hours > oldest_review_age_hours:
                oldest_review_age_hours = age_hours
            sla = self._review_sla(review, fallback_policy=fallback_policy)
            is_stale = age_hours >= sla.critical_age_hours
            owner_key = review.owner_team or "unowned"
            rollup = owner_team_rollups.setdefault(
                owner_key,
                {
                    "total_reviews": 0,
                    "assigned_reviews": 0,
                    "unassigned_reviews": 0,
                    "stale_reviews": 0,
                },
            )
            rollup["total_reviews"] += 1
            if review.assigned_to is not None:
                rollup["assigned_reviews"] += 1
            else:
                rollup["unassigned_reviews"] += 1
            if is_stale:
                stale_reviews += 1
                rollup["stale_reviews"] += 1
                if review.assigned_to is None:
                    stale_unassigned_reviews += 1

        rollups = [
            RuntimeValidationReviewOwnerQueueRollup(
                owner_team=owner_team_key,
                total_reviews=values["total_reviews"],
                assigned_reviews=values["assigned_reviews"],
                unassigned_reviews=values["unassigned_reviews"],
                stale_reviews=values["stale_reviews"],
            )
            for owner_team_key, values in sorted(
                owner_team_rollups.items(),
                key=lambda item: (-item[1]["stale_reviews"], -item[1]["total_reviews"], item[0]),
            )
        ]
        return RuntimeValidationReviewQueueSummary(
            environment_name=self.settings.environment_name,
            total_reviews=len(reviews),
            assigned_reviews=assigned_reviews,
            unassigned_reviews=unassigned_reviews,
            stale_reviews=stale_reviews,
            stale_unassigned_reviews=stale_unassigned_reviews,
            oldest_review_age_hours=None if oldest_review_age_hours is None else round(oldest_review_age_hours, 2),
            owner_team_rollups=rollups,
            reviews=reviews,
        )

    def bulk_assign_reviews(
        self,
        *,
        assigned_to: str,
        assigned_to_team: str | None,
        assigned_by: str,
        assignment_note: str | None = None,
        status: str | None = None,
        owner_team: str | None = None,
        assignment_state: str | None = None,
    ) -> RuntimeValidationReviewBulkActionResult:
        reviews = self.list_reviews(
            status=status,
            owner_team=owner_team,
            assignment_state=assignment_state,
        )
        changed: list[RuntimeValidationReviewRequest] = []
        for review in reviews:
            updated = self.assign_review(
                review_id=review.review_id,
                assigned_to=assigned_to,
                assigned_to_team=assigned_to_team,
                assigned_by=assigned_by,
                assignment_note=assignment_note,
            )
            changed.append(updated)
        return RuntimeValidationReviewBulkActionResult(
            environment_name=self.settings.environment_name,
            action="bulk_assign",
            matched_count=len(reviews),
            changed_count=len(changed),
            reviews=changed,
        )

    def bulk_resolve_reviews(
        self,
        *,
        resolved_by: str,
        resolution_reason: str,
        resolution_note: str | None = None,
        status: str | None = None,
        owner_team: str | None = None,
        assignment_state: str | None = None,
    ) -> RuntimeValidationReviewBulkActionResult:
        reviews = self.list_reviews(
            status=status,
            owner_team=owner_team,
            assignment_state=assignment_state,
        )
        changed: list[RuntimeValidationReviewRequest] = []
        for review in reviews:
            updated = self.resolve_review(
                review_id=review.review_id,
                resolved_by=resolved_by,
                resolution_note=resolution_note,
                resolution_reason=resolution_reason,
            )
            changed.append(updated)
        return RuntimeValidationReviewBulkActionResult(
            environment_name=self.settings.environment_name,
            action="bulk_resolve",
            matched_count=len(reviews),
            changed_count=len(changed),
            reviews=changed,
        )

    def build_alert_state(self, *, force: bool = False) -> RuntimeValidationReviewAlertState | None:
        review = self.active_review()
        if review is None:
            return None
        fallback_policy = self._fallback_policy()
        policy, policy_source = self._effective_policy(review.environment_name)
        effective_policy = policy.finalized(fallback_policy)
        reminder_interval_seconds = (
            effective_policy.reminder_interval_seconds or self.settings.control_plane_alert_reminder_interval_seconds
        )
        escalation_interval_seconds = (
            effective_policy.escalation_interval_seconds or self.settings.control_plane_alert_escalation_interval_seconds
        )
        age_seconds = max(
            (datetime.now(UTC) - datetime.fromisoformat(review.opened_at)).total_seconds(),
            0.0,
        )
        sla = self._review_sla(review, fallback_policy=fallback_policy)
        warning_age_seconds = sla.warning_age_hours * 3600.0
        critical_age_seconds = sla.critical_age_hours * 3600.0
        if not force and age_seconds < warning_age_seconds:
            return None

        is_assigned = review.assigned_to is not None
        overdue = critical_age_seconds <= warning_age_seconds if force else age_seconds >= critical_age_seconds
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

    def list_governance_requests(
        self,
        *,
        status: str | None = None,
        owner_team: str | None = None,
    ) -> list[RuntimeValidationGovernanceRequest]:
        requests = self._rebuild_governance_requests()
        if status is not None:
            normalized = status.strip().lower()
            requests = [request for request in requests if request.status == normalized]
        if owner_team is not None:
            normalized_owner_team = owner_team.strip().lower()
            requests = [request for request in requests if request.owner_team == normalized_owner_team]
        return requests

    def process_governance_requests(
        self,
        *,
        changed_by: str,
        reason: str | None = None,
        force: bool = False,
    ) -> list[RuntimeValidationGovernanceRequest]:
        fallback_policy = self._fallback_policy()
        review = self.active_review()
        active_requests = [
            request
            for request in self._rebuild_governance_requests()
            if request.environment_name == self.settings.environment_name and request.status != "resolved"
        ]
        changed: list[RuntimeValidationGovernanceRequest] = []
        governance_required = (
            review is not None
            and self._governance_required(review, fallback_policy=fallback_policy)
        )
        if not governance_required:
            for request in active_requests:
                changed.append(
                    self._resolve_governance_request(
                        request_id=request.request_id,
                        resolved_by=changed_by,
                        resolution_note=reason or "Governance condition cleared.",
                        resolution_reason="review_recovered",
                    )
                )
            return changed

        assert review is not None
        existing = next((request for request in active_requests if request.review_id == review.review_id), None)
        if existing is None:
            changed.append(
                self._open_governance_request(
                    review=review,
                    changed_by=changed_by,
                    reason=reason,
                )
            )
            return changed
        if force and len(active_requests) > 1:
            for request in active_requests:
                if request.request_id == existing.request_id:
                    continue
                changed.append(
                    self._resolve_governance_request(
                        request_id=request.request_id,
                        resolved_by=changed_by,
                        resolution_note="Superseded by current governance request.",
                        resolution_reason="superseded",
                    )
                )
        return changed

    def list_change_control_requests(
        self,
        *,
        status: str | None = None,
        owner_team: str | None = None,
        assignment_state: str | None = None,
    ) -> list[RuntimeValidationChangeControlRequest]:
        requests = self._rebuild_change_control_requests()
        if status is not None:
            normalized = status.strip().lower()
            requests = [request for request in requests if request.status == normalized]
        if owner_team is not None:
            normalized_owner_team = owner_team.strip().lower()
            requests = [request for request in requests if request.owner_team == normalized_owner_team]
        if assignment_state is not None:
            normalized_assignment_state = assignment_state.strip().lower()
            if normalized_assignment_state == "assigned":
                requests = [request for request in requests if request.assigned_to is not None]
            elif normalized_assignment_state == "unassigned":
                requests = [request for request in requests if request.assigned_to is None]
            elif normalized_assignment_state != "any":
                raise ValueError("assignment_state must be one of: assigned, unassigned, any.")
        return requests

    def change_control_queue_summary(
        self,
        *,
        status: str | None = None,
        owner_team: str | None = None,
        assignment_state: str | None = None,
    ) -> RuntimeValidationChangeControlQueueSummary:
        requests = self.list_change_control_requests(
            status=status,
            owner_team=owner_team,
            assignment_state=assignment_state,
        )
        assigned_requests = 0
        unassigned_requests = 0
        pending_review_count = 0
        rejected_count = 0
        owner_team_rollups: dict[str, dict[str, int | str]] = {}

        for request in requests:
            if request.assigned_to is not None:
                assigned_requests += 1
            else:
                unassigned_requests += 1
            if request.status == "pending_review":
                pending_review_count += 1
            elif request.status == "rejected":
                rejected_count += 1
            owner_key = request.owner_team or "unowned"
            rollup = owner_team_rollups.setdefault(
                owner_key,
                {
                    "owner_team": owner_key,
                    "total_requests": 0,
                    "assigned_requests": 0,
                    "unassigned_requests": 0,
                    "pending_review_count": 0,
                    "rejected_count": 0,
                },
            )
            rollup["total_requests"] += 1
            if request.assigned_to is not None:
                rollup["assigned_requests"] += 1
            else:
                rollup["unassigned_requests"] += 1
            if request.status == "pending_review":
                rollup["pending_review_count"] += 1
            elif request.status == "rejected":
                rollup["rejected_count"] += 1

        return RuntimeValidationChangeControlQueueSummary(
            environment_name=self.settings.environment_name,
            total_requests=len(requests),
            assigned_requests=assigned_requests,
            unassigned_requests=unassigned_requests,
            pending_review_count=pending_review_count,
            rejected_count=rejected_count,
            owner_team_rollups=[
                dict(item)
                for item in sorted(
                    owner_team_rollups.values(),
                    key=lambda item: (-int(item["rejected_count"]), -int(item["total_requests"]), str(item["owner_team"])),
                )
            ],
            requests=requests,
        )

    def assign_change_control_request(
        self,
        *,
        request_id: str,
        assigned_to: str,
        assigned_to_team: str | None,
        assigned_by: str,
        assignment_note: str | None = None,
    ) -> RuntimeValidationChangeControlRequest:
        request = self.get_change_control_request(request_id)
        if request.status != "pending_review":
            raise ValueError(f"Change-control request '{request_id}' is not pending review.")
        normalized_assigned_to = assigned_to.strip()
        if not normalized_assigned_to:
            raise ValueError("assigned_to must not be empty.")
        self.job_service.record_maintenance_event(
            event_type=self.CHANGE_CONTROL_ASSIGNED_EVENT_TYPE,
            changed_by=assigned_by,
            reason=assignment_note,
            details={
                "request_id": request_id,
                "assigned_to": normalized_assigned_to,
                "assigned_to_team": self._normalize_team(assigned_to_team),
                "assigned_at": _utc_now(),
                "assigned_by": assigned_by,
                "assignment_note": assignment_note,
            },
        )
        return self.get_change_control_request(request_id)

    def decide_change_control_request(
        self,
        *,
        request_id: str,
        decision: str,
        decided_by: str,
        decision_note: str | None = None,
    ) -> RuntimeValidationChangeControlRequest:
        request = self.get_change_control_request(request_id)
        if request.status != "pending_review":
            raise ValueError(f"Change-control request '{request_id}' is not pending review.")
        normalized_decision = decision.strip().lower()
        if normalized_decision not in {"approve", "reject"}:
            raise ValueError("decision must be either 'approve' or 'reject'.")
        if normalized_decision == "reject" and (decision_note is None or not decision_note.strip()):
            raise ValueError("decision_note is required when rejecting a change-control request.")
        self.job_service.record_maintenance_event(
            event_type=self.CHANGE_CONTROL_DECIDED_EVENT_TYPE,
            changed_by=decided_by,
            reason=decision_note,
            details={
                "request_id": request_id,
                "decision": normalized_decision,
                "decided_at": _utc_now(),
                "decided_by": decided_by,
                "decision_note": decision_note,
            },
        )
        return self.get_change_control_request(request_id)

    def bulk_assign_change_control_requests(
        self,
        *,
        assigned_to: str,
        assigned_to_team: str | None,
        assigned_by: str,
        assignment_note: str | None = None,
        status: str | None = None,
        owner_team: str | None = None,
        assignment_state: str | None = None,
    ) -> RuntimeValidationChangeControlBulkActionResult:
        requests = self.list_change_control_requests(
            status=status,
            owner_team=owner_team,
            assignment_state=assignment_state,
        )
        changed: list[RuntimeValidationChangeControlRequest] = []
        for request in requests:
            if request.status != "pending_review":
                continue
            changed.append(
                self.assign_change_control_request(
                    request_id=request.request_id,
                    assigned_to=assigned_to,
                    assigned_to_team=assigned_to_team,
                    assigned_by=assigned_by,
                    assignment_note=assignment_note,
                )
            )
        return RuntimeValidationChangeControlBulkActionResult(
            environment_name=self.settings.environment_name,
            action="bulk_assign",
            matched_count=len(requests),
            changed_count=len(changed),
            requests=changed,
        )

    def bulk_decide_change_control_requests(
        self,
        *,
        decision: str,
        decided_by: str,
        decision_note: str | None = None,
        status: str | None = None,
        owner_team: str | None = None,
        assignment_state: str | None = None,
    ) -> RuntimeValidationChangeControlBulkActionResult:
        requests = self.list_change_control_requests(
            status=status,
            owner_team=owner_team,
            assignment_state=assignment_state,
        )
        changed: list[RuntimeValidationChangeControlRequest] = []
        for request in requests:
            if request.status != "pending_review":
                continue
            changed.append(
                self.decide_change_control_request(
                    request_id=request.request_id,
                    decision=decision,
                    decided_by=decided_by,
                    decision_note=decision_note,
                )
            )
        return RuntimeValidationChangeControlBulkActionResult(
            environment_name=self.settings.environment_name,
            action=f"bulk_{decision.strip().lower()}",
            matched_count=len(requests),
            changed_count=len(changed),
            requests=changed,
        )

    def get_change_control_request(self, request_id: str) -> RuntimeValidationChangeControlRequest:
        for request in self._rebuild_change_control_requests():
            if request.request_id == request_id:
                return request
        raise FileNotFoundError(f"Runtime-validation change-control request '{request_id}' was not found.")

    def process_change_control_requests(
        self,
        *,
        changed_by: str,
        reason: str | None = None,
        force: bool = False,
    ) -> list[RuntimeValidationChangeControlRequest]:
        governance_requests = [
            request
            for request in self._rebuild_governance_requests()
            if request.environment_name == self.settings.environment_name and request.status != "resolved"
        ]
        active_requests = [
            request
            for request in self._rebuild_change_control_requests()
            if request.environment_name == self.settings.environment_name and request.status != "resolved"
        ]
        changed: list[RuntimeValidationChangeControlRequest] = []
        if not governance_requests:
            for request in active_requests:
                changed.append(
                    self._resolve_change_control_request(
                        request_id=request.request_id,
                        resolved_by=changed_by,
                        resolution_note=reason or "Governance condition cleared.",
                        resolution_reason="governance_cleared",
                    )
                )
            return changed

        governance = governance_requests[0]
        existing = next(
            (request for request in active_requests if request.governance_request_id == governance.request_id),
            None,
        )
        if existing is None:
            changed.append(
                self._open_change_control_request(
                    governance_request=governance,
                    changed_by=changed_by,
                    reason=reason,
                )
            )
            return changed
        if force and len(active_requests) > 1:
            for request in active_requests:
                if request.request_id == existing.request_id:
                    continue
                changed.append(
                    self._resolve_change_control_request(
                        request_id=request.request_id,
                        resolved_by=changed_by,
                        resolution_note="Superseded by current change-control request.",
                        resolution_reason="superseded",
                    )
                )
        return changed

    def _review_sla(
        self,
        review: RuntimeValidationReviewRequest,
        *,
        fallback_policy: RuntimeValidationPolicy,
    ) -> RuntimeValidationReviewSLA:
        policy, _ = self._effective_policy(review.environment_name)
        effective_policy = policy.finalized(fallback_policy)
        if review.assigned_to is None:
            warning_age_hours = (
                effective_policy.unassigned_review_warning_age_hours
                or effective_policy.review_warning_age_hours
                or fallback_policy.unassigned_review_warning_age_hours
                or fallback_policy.review_warning_age_hours
                or 1.0
            )
            critical_age_hours = (
                effective_policy.unassigned_review_critical_age_hours
                or effective_policy.review_critical_age_hours
                or fallback_policy.unassigned_review_critical_age_hours
                or fallback_policy.review_critical_age_hours
                or warning_age_hours
            )
        else:
            warning_age_hours = (
                effective_policy.review_warning_age_hours
                or fallback_policy.review_warning_age_hours
                or 1.0
            )
            critical_age_hours = (
                effective_policy.review_critical_age_hours
                or fallback_policy.review_critical_age_hours
                or warning_age_hours
            )
        if critical_age_hours < warning_age_hours:
            critical_age_hours = warning_age_hours
        return RuntimeValidationReviewSLA(
            warning_age_hours=warning_age_hours,
            critical_age_hours=critical_age_hours,
        )

    def _fallback_policy(self) -> RuntimeValidationPolicy:
        return RuntimeValidationPolicy(
            review_warning_age_hours=(
                self.settings.control_plane_alert_reminder_interval_seconds / 3600.0
            ),
            review_critical_age_hours=(
                self.settings.control_plane_alert_escalation_interval_seconds / 3600.0
            ),
            unassigned_review_warning_age_hours=(
                self.settings.control_plane_alert_reminder_interval_seconds / 3600.0
            ),
            unassigned_review_critical_age_hours=(
                self.settings.control_plane_alert_escalation_interval_seconds / 3600.0
            ),
            reminder_interval_seconds=self.settings.control_plane_alert_reminder_interval_seconds,
            escalation_interval_seconds=self.settings.control_plane_alert_escalation_interval_seconds,
        )

    def _governance_required(
        self,
        review: RuntimeValidationReviewRequest,
        *,
        fallback_policy: RuntimeValidationPolicy,
    ) -> bool:
        if review.assigned_to is not None:
            return False
        sla = self._review_sla(review, fallback_policy=fallback_policy)
        age_hours = max((datetime.now(UTC) - datetime.fromisoformat(review.opened_at)).total_seconds() / 3600.0, 0.0)
        return age_hours >= sla.critical_age_hours

    def _open_governance_request(
        self,
        *,
        review: RuntimeValidationReviewRequest,
        changed_by: str,
        reason: str | None,
    ) -> RuntimeValidationGovernanceRequest:
        request_id = uuid4().hex[:16]
        self.job_service.record_maintenance_event(
            event_type=self.GOVERNANCE_OPENED_EVENT_TYPE,
            changed_by=changed_by,
            reason=reason,
            details={
                "request_id": request_id,
                "opened_at": _utc_now(),
                "opened_by": changed_by,
                "environment_name": review.environment_name,
                "review_id": review.review_id,
                "owner_team": review.owner_team,
                "review_opened_at": review.opened_at,
                "summary": (
                    f"Critical unassigned runtime-proof review debt requires governance for review {review.review_id}."
                ),
                "trigger_code": "runtime_validation_review_unassigned_overdue",
                "policy_source": review.policy_source,
                "assigned_to": review.assigned_to,
                "assigned_to_team": review.assigned_to_team,
            },
        )
        return next(
            request for request in self._rebuild_governance_requests() if request.request_id == request_id
        )

    def _resolve_governance_request(
        self,
        *,
        request_id: str,
        resolved_by: str,
        resolution_note: str | None,
        resolution_reason: str,
    ) -> RuntimeValidationGovernanceRequest:
        self.job_service.record_maintenance_event(
            event_type=self.GOVERNANCE_RESOLVED_EVENT_TYPE,
            changed_by=resolved_by,
            reason=resolution_note,
            details={
                "request_id": request_id,
                "resolved_at": _utc_now(),
                "resolved_by": resolved_by,
                "resolution_note": resolution_note,
                "resolution_reason": resolution_reason,
            },
        )
        return next(
            request for request in self._rebuild_governance_requests() if request.request_id == request_id
        )

    def _open_change_control_request(
        self,
        *,
        governance_request: RuntimeValidationGovernanceRequest,
        changed_by: str,
        reason: str | None,
    ) -> RuntimeValidationChangeControlRequest:
        request_id = uuid4().hex[:16]
        self.job_service.record_maintenance_event(
            event_type=self.CHANGE_CONTROL_OPENED_EVENT_TYPE,
            changed_by=changed_by,
            reason=reason,
            details={
                "request_id": request_id,
                "opened_at": _utc_now(),
                "opened_by": changed_by,
                "environment_name": governance_request.environment_name,
                "governance_request_id": governance_request.request_id,
                "review_id": governance_request.review_id,
                "owner_team": governance_request.owner_team,
                "summary": (
                    f"Change-control required for runtime-proof governance request {governance_request.request_id}."
                ),
                "trigger_code": "runtime_validation_change_control_required",
                "policy_source": governance_request.policy_source,
            },
        )
        return next(
            request for request in self._rebuild_change_control_requests() if request.request_id == request_id
        )

    def _resolve_change_control_request(
        self,
        *,
        request_id: str,
        resolved_by: str,
        resolution_note: str | None,
        resolution_reason: str,
    ) -> RuntimeValidationChangeControlRequest:
        self.job_service.record_maintenance_event(
            event_type=self.CHANGE_CONTROL_RESOLVED_EVENT_TYPE,
            changed_by=resolved_by,
            reason=resolution_note,
            details={
                "request_id": request_id,
                "resolved_at": _utc_now(),
                "resolved_by": resolved_by,
                "resolution_note": resolution_note,
                "resolution_reason": resolution_reason,
            },
        )
        return next(
            request for request in self._rebuild_change_control_requests() if request.request_id == request_id
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

    def _rebuild_governance_requests(self) -> list[RuntimeValidationGovernanceRequest]:
        requests: dict[str, RuntimeValidationGovernanceRequest] = {}
        events = list(reversed(self.job_repository.list_control_plane_maintenance_events(limit=2000)))
        for record in events:
            details = dict(record.details)
            if record.event_type == self.GOVERNANCE_OPENED_EVENT_TYPE:
                request_id = str(details["request_id"])
                requests[request_id] = RuntimeValidationGovernanceRequest(
                    request_id=request_id,
                    opened_at=str(details["opened_at"]),
                    opened_by=str(details["opened_by"]),
                    environment_name=str(details["environment_name"]),
                    review_id=str(details["review_id"]),
                    owner_team=_optional_str(details.get("owner_team")),
                    review_opened_at=str(details["review_opened_at"]),
                    summary=str(details["summary"]),
                    status="pending_review",
                    trigger_code=str(details["trigger_code"]),
                    policy_source=str(details.get("policy_source", "defaults")),
                    assigned_to=_optional_str(details.get("assigned_to")),
                    assigned_to_team=_optional_str(details.get("assigned_to_team")),
                )
            elif record.event_type == self.GOVERNANCE_RESOLVED_EVENT_TYPE:
                request_id = str(details["request_id"])
                existing = requests.get(request_id)
                if existing is None:
                    continue
                requests[request_id] = RuntimeValidationGovernanceRequest(
                    request_id=existing.request_id,
                    opened_at=existing.opened_at,
                    opened_by=existing.opened_by,
                    environment_name=existing.environment_name,
                    review_id=existing.review_id,
                    owner_team=existing.owner_team,
                    review_opened_at=existing.review_opened_at,
                    summary=existing.summary,
                    status="resolved",
                    trigger_code=existing.trigger_code,
                    policy_source=existing.policy_source,
                    assigned_to=existing.assigned_to,
                    assigned_to_team=existing.assigned_to_team,
                    resolved_at=str(details["resolved_at"]),
                    resolved_by=str(details["resolved_by"]),
                    resolution_note=_optional_str(details.get("resolution_note")),
                    resolution_reason=_optional_str(details.get("resolution_reason")),
                )
        return list(requests.values())

    def _rebuild_change_control_requests(self) -> list[RuntimeValidationChangeControlRequest]:
        requests: dict[str, RuntimeValidationChangeControlRequest] = {}
        events = list(reversed(self.job_repository.list_control_plane_maintenance_events(limit=2000)))
        for record in events:
            details = dict(record.details)
            if record.event_type == self.CHANGE_CONTROL_OPENED_EVENT_TYPE:
                request_id = str(details["request_id"])
                requests[request_id] = RuntimeValidationChangeControlRequest(
                    request_id=request_id,
                    opened_at=str(details["opened_at"]),
                    opened_by=str(details["opened_by"]),
                    environment_name=str(details["environment_name"]),
                    governance_request_id=str(details["governance_request_id"]),
                    review_id=str(details["review_id"]),
                    owner_team=_optional_str(details.get("owner_team")),
                    summary=str(details["summary"]),
                    status="pending_review",
                    trigger_code=str(details["trigger_code"]),
                    policy_source=str(details.get("policy_source", "defaults")),
                )
            elif record.event_type == self.CHANGE_CONTROL_ASSIGNED_EVENT_TYPE:
                request_id = str(details["request_id"])
                existing = requests.get(request_id)
                if existing is None:
                    continue
                requests[request_id] = RuntimeValidationChangeControlRequest(
                    request_id=existing.request_id,
                    opened_at=existing.opened_at,
                    opened_by=existing.opened_by,
                    environment_name=existing.environment_name,
                    governance_request_id=existing.governance_request_id,
                    review_id=existing.review_id,
                    owner_team=existing.owner_team,
                    summary=existing.summary,
                    status=existing.status,
                    trigger_code=existing.trigger_code,
                    policy_source=existing.policy_source,
                    assigned_to=str(details["assigned_to"]),
                    assigned_to_team=_optional_str(details.get("assigned_to_team")),
                    assigned_at=str(details["assigned_at"]),
                    assigned_by=str(details["assigned_by"]),
                    assignment_note=_optional_str(details.get("assignment_note")),
                )
            elif record.event_type == self.CHANGE_CONTROL_DECIDED_EVENT_TYPE:
                request_id = str(details["request_id"])
                existing = requests.get(request_id)
                if existing is None:
                    continue
                decision = str(details["decision"])
                requests[request_id] = RuntimeValidationChangeControlRequest(
                    request_id=existing.request_id,
                    opened_at=existing.opened_at,
                    opened_by=existing.opened_by,
                    environment_name=existing.environment_name,
                    governance_request_id=existing.governance_request_id,
                    review_id=existing.review_id,
                    owner_team=existing.owner_team,
                    summary=existing.summary,
                    status="approved" if decision == "approve" else "rejected",
                    trigger_code=existing.trigger_code,
                    policy_source=existing.policy_source,
                    assigned_to=existing.assigned_to,
                    assigned_to_team=existing.assigned_to_team,
                    assigned_at=existing.assigned_at,
                    assigned_by=existing.assigned_by,
                    assignment_note=existing.assignment_note,
                    resolved_at=str(details["decided_at"]),
                    resolved_by=str(details["decided_by"]),
                    resolution_note=_optional_str(details.get("decision_note")),
                    resolution_reason=decision,
                )
            elif record.event_type == self.CHANGE_CONTROL_RESOLVED_EVENT_TYPE:
                request_id = str(details["request_id"])
                existing = requests.get(request_id)
                if existing is None:
                    continue
                requests[request_id] = RuntimeValidationChangeControlRequest(
                    request_id=existing.request_id,
                    opened_at=existing.opened_at,
                    opened_by=existing.opened_by,
                    environment_name=existing.environment_name,
                    governance_request_id=existing.governance_request_id,
                    review_id=existing.review_id,
                    owner_team=existing.owner_team,
                    summary=existing.summary,
                    status="resolved",
                    trigger_code=existing.trigger_code,
                    policy_source=existing.policy_source,
                    assigned_to=existing.assigned_to,
                    assigned_to_team=existing.assigned_to_team,
                    assigned_at=existing.assigned_at,
                    assigned_by=existing.assigned_by,
                    assignment_note=existing.assignment_note,
                    resolved_at=str(details["resolved_at"]),
                    resolved_by=str(details["resolved_by"]),
                    resolution_note=_optional_str(details.get("resolution_note")),
                    resolution_reason=_optional_str(details.get("resolution_reason")),
                )
        return list(requests.values())

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
