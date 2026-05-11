from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from lsa.services.analytics_service import AnalyticsService
from lsa.services.oncall_policy import load_oncall_policy_bundle
from lsa.services.runtime_validation_policy import RuntimeValidationPolicy, load_runtime_validation_policy_bundle
from lsa.storage.files import JobRepository
from lsa.storage.models import (
    ControlPlaneAlertRecord,
    ControlPlaneAlertSilenceRecord,
    ControlPlaneOnCallChangeRequestRecord,
    ControlPlaneOnCallScheduleRecord,
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class ControlPlaneAlertService:
    job_repository: JobRepository
    analytics_service: AnalyticsService
    default_environment_name: str = "default"
    window_days: int = 7
    dedup_window_seconds: float = 300.0
    reminder_interval_seconds: float = 900.0
    escalation_interval_seconds: float = 1800.0
    policy_path: str | None = None
    runtime_validation_policy_path: str | None = None
    required_approver_roles: tuple[str, ...] = ("manager", "director", "admin")
    allow_self_approval: bool = False
    sink_path: str | None = None
    webhook_url: str | None = None
    escalation_webhook_url: str | None = None
    runtime_validation_review_service: object | None = None

    _RUNTIME_VALIDATION_ALERT_KEY_PREFIX = "control-plane-runtime-validation:"
    _RUNTIME_VALIDATION_REVIEW_ALERT_KEY_PREFIX = "control-plane-runtime-validation-review:"

    def emit_alerts(self, *, force: bool = False) -> list[ControlPlaneAlertRecord]:
        report = self.analytics_service.build_control_plane_analytics(days=self.window_days)
        report_payload = report.to_dict()
        emitted: list[ControlPlaneAlertRecord] = []
        candidates = [
            self._runtime_validation_candidate(
                report_payload,
                self._latest_alert_with_prefix(self._RUNTIME_VALIDATION_ALERT_KEY_PREFIX),
            ),
            self._runtime_validation_review_candidate(
                self._latest_alert_with_prefix(self._RUNTIME_VALIDATION_REVIEW_ALERT_KEY_PREFIX),
            ),
            self._candidate_alert(report_payload, self.job_repository.latest_control_plane_alert()),
        ]
        for candidate in candidates:
            if candidate is None:
                continue
            emitted_candidate = self._emit_candidate(candidate, force=force)
            if emitted_candidate is not None:
                emitted.append(emitted_candidate)
        return emitted

    def list_alerts(self, limit: int | None = None) -> list[ControlPlaneAlertRecord]:
        return self.job_repository.list_control_plane_alerts(limit)

    def get_alert(self, alert_id: str) -> ControlPlaneAlertRecord:
        return self.job_repository.get_control_plane_alert(alert_id)

    def acknowledge_alert(
        self,
        *,
        alert_id: str,
        acknowledged_by: str,
        acknowledgement_note: str | None = None,
    ) -> ControlPlaneAlertRecord:
        record = self.job_repository.get_control_plane_alert(alert_id)
        root_alert = self._root_incident_for_record(record)
        acknowledged_at = _utc_now()
        if root_alert.alert_id != record.alert_id:
            self.job_repository.acknowledge_control_plane_alert(
                alert_id=root_alert.alert_id,
                acknowledged_at=acknowledged_at,
                acknowledged_by=acknowledged_by,
                acknowledgement_note=acknowledgement_note,
            )
        return self.job_repository.acknowledge_control_plane_alert(
            alert_id=alert_id,
            acknowledged_at=acknowledged_at,
            acknowledged_by=acknowledged_by,
            acknowledgement_note=acknowledgement_note,
        )

    def create_silence(
        self,
        *,
        created_by: str,
        reason: str,
        duration_minutes: int,
        match_alert_key: str | None = None,
        match_finding_code: str | None = None,
    ) -> ControlPlaneAlertSilenceRecord:
        if not match_alert_key and not match_finding_code:
            raise ValueError("At least one of match_alert_key or match_finding_code must be provided.")
        if duration_minutes < 1:
            raise ValueError("duration_minutes must be at least 1.")
        created_at = datetime.now(UTC)
        return self.job_repository.append_control_plane_alert_silence(
            ControlPlaneAlertSilenceRecord(
                silence_id=uuid4().hex[:16],
                created_at=created_at.isoformat(),
                created_by=created_by,
                reason=reason,
                match_alert_key=match_alert_key,
                match_finding_code=match_finding_code,
                starts_at=created_at.isoformat(),
                expires_at=(created_at + timedelta(minutes=duration_minutes)).isoformat(),
            )
        )

    def list_silences(self, *, active_only: bool = False) -> list[ControlPlaneAlertSilenceRecord]:
        records = self.job_repository.list_control_plane_alert_silences()
        if not active_only:
            return records
        return [record for record in records if self._silence_is_active(record)]

    def cancel_silence(self, *, silence_id: str, cancelled_by: str) -> ControlPlaneAlertSilenceRecord:
        return self.job_repository.cancel_control_plane_alert_silence(
            silence_id=silence_id,
            cancelled_at=_utc_now(),
            cancelled_by=cancelled_by,
        )

    def create_oncall_schedule(
        self,
        *,
        created_by: str,
        created_by_team: str | None = None,
        created_by_role: str | None = None,
        environment_name: str | None = None,
        team_name: str,
        timezone_name: str,
        change_reason: str | None = None,
        approved_by: str | None = None,
        approved_by_team: str | None = None,
        approved_by_role: str | None = None,
        approval_note: str | None = None,
        weekdays: list[int],
        start_time: str,
        end_time: str,
        priority: int = 100,
        rotation_name: str | None = None,
        effective_start_date: str | None = None,
        effective_end_date: str | None = None,
        webhook_url: str | None = None,
        escalation_webhook_url: str | None = None,
    ) -> ControlPlaneOnCallScheduleRecord:
        self._validate_schedule_inputs(
            timezone_name=timezone_name,
            weekdays=weekdays,
            start_time=start_time,
            end_time=end_time,
            priority=priority,
            effective_start_date=effective_start_date,
            effective_end_date=effective_end_date,
        )
        if approval_note is not None and approved_by is None:
            raise ValueError("approval_note requires approved_by.")
        if approved_by_role is not None and approved_by is None:
            raise ValueError("approved_by_role requires approved_by.")
        if approved_by_team is not None and approved_by is None:
            raise ValueError("approved_by_team requires approved_by.")
        proposed_record = self._build_oncall_schedule_record(
            created_by=created_by,
            created_by_team=created_by_team,
            created_by_role=created_by_role,
            environment_name=environment_name,
            team_name=team_name,
            timezone_name=timezone_name,
            change_reason=change_reason,
            approved_by=approved_by,
            approved_by_team=approved_by_team,
            approved_by_role=approved_by_role,
            approval_note=approval_note,
            weekdays=weekdays,
            start_time=start_time,
            end_time=end_time,
            priority=priority,
            rotation_name=rotation_name,
            effective_start_date=effective_start_date,
            effective_end_date=effective_end_date,
            webhook_url=webhook_url,
            escalation_webhook_url=escalation_webhook_url,
        )
        effective_policy = self._effective_governance_policy(proposed_record)
        self._validate_policy_boundaries(proposed_record, effective_policy)
        self._validate_schedule_approval_requirements(
            proposed_record=proposed_record,
            effective_policy=effective_policy,
        )
        return self.job_repository.append_control_plane_oncall_schedule(proposed_record)

    def list_oncall_schedules(self, *, active_only: bool = False) -> list[ControlPlaneOnCallScheduleRecord]:
        records = self.job_repository.list_control_plane_oncall_schedules()
        if not active_only:
            return records
        return [
            record
            for record in records
            if record.environment_name == self.default_environment_name
            and self._schedule_is_active_now(record)
        ]

    def cancel_oncall_schedule(self, *, schedule_id: str, cancelled_by: str) -> ControlPlaneOnCallScheduleRecord:
        return self.job_repository.cancel_control_plane_oncall_schedule(
            schedule_id=schedule_id,
            cancelled_at=_utc_now(),
            cancelled_by=cancelled_by,
        )

    def submit_oncall_change_request(
        self,
        *,
        created_by: str,
        created_by_team: str | None = None,
        created_by_role: str | None = None,
        environment_name: str | None = None,
        team_name: str,
        timezone_name: str,
        change_reason: str | None,
        weekdays: list[int],
        start_time: str,
        end_time: str,
        priority: int = 100,
        rotation_name: str | None = None,
        effective_start_date: str | None = None,
        effective_end_date: str | None = None,
        webhook_url: str | None = None,
        escalation_webhook_url: str | None = None,
    ) -> ControlPlaneOnCallChangeRequestRecord:
        if change_reason is None or not change_reason.strip():
            raise ValueError("change_reason is required for on-call change requests.")
        proposed_record = self._build_oncall_schedule_record(
            created_by=created_by,
            created_by_team=created_by_team,
            created_by_role=created_by_role,
            environment_name=environment_name,
            team_name=team_name,
            timezone_name=timezone_name,
            change_reason=change_reason,
            approved_by=None,
            approved_by_team=None,
            approved_by_role=None,
            approval_note=None,
            weekdays=weekdays,
            start_time=start_time,
            end_time=end_time,
            priority=priority,
            rotation_name=rotation_name,
            effective_start_date=effective_start_date,
            effective_end_date=effective_end_date,
            webhook_url=webhook_url,
            escalation_webhook_url=escalation_webhook_url,
        )
        effective_policy = self._effective_governance_policy(proposed_record)
        self._validate_policy_boundaries(proposed_record, effective_policy)
        review_required = self._schedule_requires_approval(proposed_record)
        review_reasons = ["ambiguous_overlap"] if review_required else []
        if not review_required:
            applied_schedule = self.create_oncall_schedule(
                created_by=created_by,
                created_by_team=created_by_team,
                created_by_role=created_by_role,
                environment_name=environment_name,
                team_name=team_name,
                timezone_name=timezone_name,
                change_reason=change_reason,
                weekdays=weekdays,
                start_time=start_time,
                end_time=end_time,
                priority=priority,
                rotation_name=rotation_name,
                effective_start_date=effective_start_date,
                effective_end_date=effective_end_date,
                webhook_url=webhook_url,
                escalation_webhook_url=escalation_webhook_url,
            )
            return self.job_repository.append_control_plane_oncall_change_request(
                ControlPlaneOnCallChangeRequestRecord(
                    request_id=uuid4().hex[:16],
                    created_at=applied_schedule.created_at,
                    created_by=created_by,
                    created_by_team=proposed_record.created_by_team,
                    created_by_role=proposed_record.created_by_role,
                    change_reason=change_reason,
                    status="applied",
                    review_required=False,
                    review_reasons=review_reasons,
                    environment_name=proposed_record.environment_name,
                    team_name=team_name,
                    timezone_name=timezone_name,
                    weekdays=list(weekdays),
                    start_time=start_time,
                    end_time=end_time,
                    priority=priority,
                    rotation_name=rotation_name,
                    effective_start_date=effective_start_date,
                    effective_end_date=effective_end_date,
                    webhook_url=webhook_url,
                    escalation_webhook_url=escalation_webhook_url,
                    decision_at=applied_schedule.created_at,
                    decided_by=created_by,
                    decided_by_team=proposed_record.created_by_team,
                    decided_by_role=proposed_record.created_by_role,
                    decision_note="Auto-applied because no governed overlap was detected.",
                    applied_schedule_id=applied_schedule.schedule_id,
                )
            )
        return self.job_repository.append_control_plane_oncall_change_request(
            ControlPlaneOnCallChangeRequestRecord(
                request_id=uuid4().hex[:16],
                created_at=proposed_record.created_at,
                created_by=created_by,
                created_by_team=proposed_record.created_by_team,
                created_by_role=proposed_record.created_by_role,
                change_reason=change_reason,
                status="pending_review",
                review_required=True,
                review_reasons=review_reasons,
                environment_name=proposed_record.environment_name,
                team_name=team_name,
                timezone_name=timezone_name,
                weekdays=list(weekdays),
                start_time=start_time,
                end_time=end_time,
                priority=priority,
                rotation_name=rotation_name,
                effective_start_date=effective_start_date,
                effective_end_date=effective_end_date,
                webhook_url=webhook_url,
                escalation_webhook_url=escalation_webhook_url,
            )
        )

    def list_oncall_change_requests(
        self,
        *,
        status: str | None = None,
    ) -> list[ControlPlaneOnCallChangeRequestRecord]:
        return self.job_repository.list_control_plane_oncall_change_requests(status=status)

    def get_oncall_change_request(self, request_id: str) -> ControlPlaneOnCallChangeRequestRecord:
        return self.job_repository.get_control_plane_oncall_change_request(request_id)

    def review_oncall_change_request(
        self,
        *,
        request_id: str,
        decision: str,
        reviewed_by: str,
        reviewed_by_team: str | None = None,
        reviewed_by_role: str | None = None,
        review_note: str | None = None,
    ) -> ControlPlaneOnCallChangeRequestRecord:
        normalized_decision = decision.strip().lower()
        if normalized_decision not in {"approve", "reject"}:
            raise ValueError("decision must be either 'approve' or 'reject'.")
        request = self.job_repository.get_control_plane_oncall_change_request(request_id)
        if request.status != "pending_review":
            raise ValueError(
                f"On-call change request '{request_id}' is not pending review."
            )
        decision_at = _utc_now()
        normalized_reviewer_team = self._normalize_team(reviewed_by_team)
        normalized_reviewer_role = self._normalize_role(reviewed_by_role)
        if normalized_decision == "reject":
            if review_note is None or not review_note.strip():
                raise ValueError("review_note is required when rejecting an on-call change request.")
            return self.job_repository.decide_control_plane_oncall_change_request(
                request_id=request_id,
                status="rejected",
                decision_at=decision_at,
                decided_by=reviewed_by,
                decided_by_team=normalized_reviewer_team,
                decided_by_role=normalized_reviewer_role,
                decision_note=review_note,
                applied_schedule_id=None,
            )
        applied_schedule = self.create_oncall_schedule(
            created_by=request.created_by,
            created_by_team=request.created_by_team,
            created_by_role=request.created_by_role,
            environment_name=request.environment_name,
            team_name=request.team_name,
            timezone_name=request.timezone_name,
            change_reason=request.change_reason,
            approved_by=reviewed_by,
            approved_by_team=normalized_reviewer_team,
            approved_by_role=normalized_reviewer_role,
            approval_note=review_note,
            weekdays=list(request.weekdays),
            start_time=request.start_time,
            end_time=request.end_time,
            priority=request.priority,
            rotation_name=request.rotation_name,
            effective_start_date=request.effective_start_date,
            effective_end_date=request.effective_end_date,
            webhook_url=request.webhook_url,
            escalation_webhook_url=request.escalation_webhook_url,
        )
        return self.job_repository.decide_control_plane_oncall_change_request(
            request_id=request_id,
            status="applied",
            decision_at=decision_at,
            decided_by=reviewed_by,
            decided_by_team=normalized_reviewer_team,
            decided_by_role=normalized_reviewer_role,
            decision_note=review_note,
            applied_schedule_id=applied_schedule.schedule_id,
        )

    def assign_oncall_change_request(
        self,
        *,
        request_id: str,
        assigned_to: str,
        assigned_to_team: str | None = None,
        assigned_by: str,
        assignment_note: str | None = None,
    ) -> ControlPlaneOnCallChangeRequestRecord:
        request = self.job_repository.get_control_plane_oncall_change_request(request_id)
        if request.status != "pending_review":
            raise ValueError(
                f"On-call change request '{request_id}' is not pending review."
            )
        normalized_assigned_to = assigned_to.strip()
        if not normalized_assigned_to:
            raise ValueError("assigned_to must not be empty.")
        return self.job_repository.assign_control_plane_oncall_change_request(
            request_id=request_id,
            assigned_to=normalized_assigned_to,
            assigned_to_team=self._normalize_team(assigned_to_team),
            assigned_at=_utc_now(),
            assigned_by=assigned_by,
            assignment_note=assignment_note,
        )

    def resolve_active_oncall_route(
        self,
        *,
        reference_timestamp: datetime | None = None,
    ) -> ControlPlaneOnCallScheduleRecord | None:
        candidates = self._active_route_candidates(reference_timestamp=reference_timestamp)
        if not candidates:
            return None
        return candidates[0]

    def preview_oncall_route(
        self,
        *,
        reference_timestamp: datetime | None = None,
    ) -> dict:
        resolved_timestamp = reference_timestamp or datetime.now(UTC)
        candidates = self._active_route_candidates(reference_timestamp=resolved_timestamp)
        return {
            "reference_timestamp": resolved_timestamp.isoformat(),
            "resolved_route": candidates[0].to_dict() if candidates else None,
            "active_candidate_count": len(candidates),
            "active_candidates": [
                {
                    "rank": index + 1,
                    "selected": index == 0,
                    "priority": record.priority,
                    "specificity": self._route_specificity(record)[0],
                    "window_span_days": self._route_specificity(record)[1],
                    "reasons": self._route_reasons(record),
                    "route": record.to_dict(),
                }
                for index, record in enumerate(candidates)
            ],
        }

    def process_follow_ups(self, *, force: bool = False) -> list[ControlPlaneAlertRecord]:
        emitted: list[ControlPlaneAlertRecord] = []
        for active_alert in (
            self._active_incident_alert(
                exclude_prefixes=(
                    self._RUNTIME_VALIDATION_ALERT_KEY_PREFIX,
                    self._RUNTIME_VALIDATION_REVIEW_ALERT_KEY_PREFIX,
                )
            ),
            self._active_incident_alert(include_prefix=self._RUNTIME_VALIDATION_ALERT_KEY_PREFIX),
            self._active_incident_alert(include_prefix=self._RUNTIME_VALIDATION_REVIEW_ALERT_KEY_PREFIX),
        ):
            if active_alert is None:
                continue
            delivered = self._process_follow_up_for_alert(active_alert=active_alert, force=force)
            if delivered is not None:
                emitted.append(delivered)
        return emitted

    def _candidate_alert(self, report: dict, latest: ControlPlaneAlertRecord | None) -> ControlPlaneAlertRecord | None:
        evaluation = report["evaluation"]
        status = evaluation["status"]
        findings = list(evaluation["findings"])
        finding_codes = sorted(item["code"] for item in findings)

        if status == "healthy":
            if latest is None or latest.status == "healthy":
                return None
            alert_key = "control-plane:healthy:recovered"
            summary = "Control-plane evaluation returned to healthy after a degraded or critical condition."
            severity = "info"
        else:
            alert_key = f"control-plane:{status}:{','.join(finding_codes)}"
            summary = self._summary_for_status(status, findings)
            severity = "critical" if status == "critical" else "warning"

        return ControlPlaneAlertRecord(
            alert_id=uuid4().hex[:16],
            created_at=_utc_now(),
            alert_key=alert_key,
            status=status,
            severity=severity,
            summary=summary,
            finding_codes=finding_codes,
            delivery_state="skipped",
            payload={
                "report": report,
                "lifecycle_event": "recovery" if status == "healthy" else "incident",
                "source_alert_id": None,
            },
            error=None,
        )

    def _runtime_validation_candidate(
        self,
        report: dict,
        latest: ControlPlaneAlertRecord | None,
    ) -> ControlPlaneAlertRecord | None:
        runtime_validation = dict(report.get("runtime_validation", {}))
        status = str(runtime_validation.get("status", "missing"))
        cadence_status = str(runtime_validation.get("cadence_status", "missing"))
        latest_rehearsal_status = runtime_validation.get("latest_rehearsal_status")

        if status == "missing":
            finding_codes = ["runtime_rehearsal_missing"]
            alert_status = "critical"
            severity = "critical"
            summary = "No control-plane runtime rehearsal evidence exists for the active environment."
        elif status == "failed":
            finding_codes = ["runtime_rehearsal_failed"]
            alert_status = "critical"
            severity = "critical"
            summary = "The latest control-plane runtime rehearsal did not pass."
        elif cadence_status == "due_soon":
            finding_codes = ["runtime_rehearsal_due_soon"]
            alert_status = "degraded"
            severity = "warning"
            summary = "Control-plane runtime proof is approaching its warning threshold."
        elif status == "warning" or cadence_status == "aging":
            finding_codes = ["runtime_rehearsal_age"]
            alert_status = "degraded"
            severity = "warning"
            summary = "Control-plane runtime proof is older than the configured warning threshold."
        elif status == "critical" or cadence_status == "overdue":
            finding_codes = ["runtime_rehearsal_age"]
            alert_status = "critical"
            severity = "critical"
            summary = "Control-plane runtime proof is older than the configured critical threshold."
        else:
            if latest is None or latest.status == "healthy" or self._lifecycle_event(latest) == "recovery":
                return None
            finding_codes = []
            alert_status = "healthy"
            severity = "info"
            summary = "Control-plane runtime proof returned to a fresh state."

        if alert_status == "healthy":
            alert_key = f"{self._RUNTIME_VALIDATION_ALERT_KEY_PREFIX}healthy:recovered"
            lifecycle_event = "recovery"
        else:
            alert_key = f"{self._RUNTIME_VALIDATION_ALERT_KEY_PREFIX}{alert_status}:{','.join(sorted(finding_codes))}"
            lifecycle_event = "incident"

        return ControlPlaneAlertRecord(
            alert_id=uuid4().hex[:16],
            created_at=_utc_now(),
            alert_key=alert_key,
            status=alert_status,
            severity=severity,
            summary=summary,
            finding_codes=sorted(finding_codes),
            delivery_state="skipped",
            payload={
                "report": report,
                "runtime_validation": runtime_validation,
                "runtime_validation_status": status,
                "runtime_validation_cadence_status": cadence_status,
                "latest_rehearsal_status": latest_rehearsal_status,
                "alert_family": "runtime_validation",
                "lifecycle_event": lifecycle_event,
                "source_alert_id": None,
            },
            error=None,
        )

    def _runtime_validation_review_candidate(
        self,
        latest: ControlPlaneAlertRecord | None,
    ) -> ControlPlaneAlertRecord | None:
        if self.runtime_validation_review_service is None:
            return None
        state = self.runtime_validation_review_service.build_alert_state(force=False)
        if state is None:
            if latest is None or latest.status == "healthy" or self._lifecycle_event(latest) == "recovery":
                return None
            review_payload = dict(latest.payload.get("runtime_validation_review", {}))
            return ControlPlaneAlertRecord(
                alert_id=uuid4().hex[:16],
                created_at=_utc_now(),
                alert_key=f"{self._RUNTIME_VALIDATION_REVIEW_ALERT_KEY_PREFIX}healthy:recovered",
                status="healthy",
                severity="info",
                summary="Runtime-proof review queue returned to a healthy state.",
                finding_codes=[],
                delivery_state="skipped",
                payload={
                    "runtime_validation_review": review_payload,
                    "alert_family": "runtime_validation_review",
                    "policy_source": latest.payload.get("policy_source"),
                    "reminder_interval_seconds": latest.payload.get("reminder_interval_seconds"),
                    "escalation_interval_seconds": latest.payload.get("escalation_interval_seconds"),
                    "review_age_seconds": 0.0,
                    "lifecycle_event": "recovery",
                    "source_alert_id": None,
                },
                error=None,
            )

        return ControlPlaneAlertRecord(
            alert_id=uuid4().hex[:16],
            created_at=_utc_now(),
            alert_key=(
                f"{self._RUNTIME_VALIDATION_REVIEW_ALERT_KEY_PREFIX}"
                f"{state.status}:{state.review.review_id}:{','.join(sorted(state.finding_codes))}"
            ),
            status=state.status,
            severity=state.severity,
            summary=state.summary,
            finding_codes=sorted(state.finding_codes),
            delivery_state="skipped",
            payload={
                "runtime_validation_review": state.review.to_dict(),
                "alert_family": "runtime_validation_review",
                "policy_source": state.policy_source,
                "reminder_interval_seconds": state.reminder_interval_seconds,
                "escalation_interval_seconds": state.escalation_interval_seconds,
                "review_age_seconds": state.age_seconds,
                "lifecycle_event": "incident",
                "source_alert_id": None,
            },
            error=None,
        )

    def _summary_for_status(self, status: str, findings: list[dict]) -> str:
        if not findings:
            return f"Control-plane evaluation entered {status} state."
        top = findings[0]["summary"]
        if len(findings) == 1:
            return top
        return f"{top} ({len(findings)} findings in current control-plane evaluation.)"

    def _is_deduped(self, alert_key: str) -> bool:
        latest = self.job_repository.latest_control_plane_alert_by_key(alert_key)
        if latest is None:
            return False
        not_before = datetime.now(UTC) - timedelta(seconds=self.dedup_window_seconds)
        return datetime.fromisoformat(latest.created_at) >= not_before

    def _emit_candidate(
        self,
        candidate: ControlPlaneAlertRecord,
        *,
        force: bool,
    ) -> ControlPlaneAlertRecord | None:
        if not force and self._is_deduped(candidate.alert_key):
            return None
        matching_silences = self._matching_active_silences(candidate)
        if matching_silences:
            suppressed = self._suppress(candidate, matching_silences)
            self.job_repository.append_control_plane_alert(suppressed)
            return suppressed
        delivered = self._deliver(candidate)
        self.job_repository.append_control_plane_alert(delivered)
        return delivered

    def _matching_active_silences(self, record: ControlPlaneAlertRecord) -> list[ControlPlaneAlertSilenceRecord]:
        if record.status == "healthy":
            return []
        matches: list[ControlPlaneAlertSilenceRecord] = []
        for silence in self.job_repository.list_control_plane_alert_silences():
            if not self._silence_is_active(silence):
                continue
            if silence.match_alert_key and silence.match_alert_key != record.alert_key:
                continue
            if silence.match_finding_code and silence.match_finding_code not in record.finding_codes:
                continue
            matches.append(silence)
        return matches

    def _active_incident_alert(
        self,
        *,
        include_prefix: str | None = None,
        exclude_prefixes: tuple[str, ...] = (),
    ) -> ControlPlaneAlertRecord | None:
        for record in self.job_repository.list_control_plane_alerts():
            if include_prefix is not None and not record.alert_key.startswith(include_prefix):
                continue
            if exclude_prefixes and any(record.alert_key.startswith(prefix) for prefix in exclude_prefixes):
                continue
            if record.status == "healthy" or self._lifecycle_event(record) == "recovery":
                return None
            if record.delivery_state not in {"delivered", "partial"}:
                return None
            return record
        return None

    def _latest_alert_with_prefix(self, prefix: str) -> ControlPlaneAlertRecord | None:
        for record in self.job_repository.list_control_plane_alerts():
            if record.alert_key.startswith(prefix):
                return record
        return None

    def _root_incident_for_record(self, record: ControlPlaneAlertRecord) -> ControlPlaneAlertRecord:
        source_alert_id = self._source_alert_id(record)
        if source_alert_id:
            return self.job_repository.get_control_plane_alert(source_alert_id)
        return record

    def _next_follow_up_event(self, *, root_alert: ControlPlaneAlertRecord, force: bool) -> str | None:
        reminder_interval_seconds, escalation_interval_seconds = self._follow_up_intervals_for_alert(root_alert)
        if force:
            if escalation_interval_seconds <= reminder_interval_seconds:
                return "escalation"
            return "reminder"

        created_at = datetime.fromisoformat(root_alert.created_at)
        age_seconds = (datetime.now(UTC) - created_at).total_seconds()
        latest_escalation = self._latest_follow_up(root_alert.alert_id, "escalation")
        latest_reminder = self._latest_follow_up(root_alert.alert_id, "reminder")

        if age_seconds >= escalation_interval_seconds:
            if latest_escalation is None:
                return "escalation"
            last_escalation_age = (datetime.now(UTC) - datetime.fromisoformat(latest_escalation.created_at)).total_seconds()
            if last_escalation_age >= escalation_interval_seconds:
                return "escalation"

        if age_seconds >= reminder_interval_seconds:
            if latest_reminder is None:
                return "reminder"
            last_reminder_age = (datetime.now(UTC) - datetime.fromisoformat(latest_reminder.created_at)).total_seconds()
            if last_reminder_age >= reminder_interval_seconds:
                return "reminder"
        return None

    def _follow_up_intervals_for_alert(self, record: ControlPlaneAlertRecord) -> tuple[float, float]:
        alert_family = str(record.payload.get("alert_family"))
        if alert_family == "runtime_validation_review":
            return (
                _optional_float(record.payload.get("reminder_interval_seconds")) or self.reminder_interval_seconds,
                _optional_float(record.payload.get("escalation_interval_seconds")) or self.escalation_interval_seconds,
            )
        if alert_family != "runtime_validation":
            return (self.reminder_interval_seconds, self.escalation_interval_seconds)
        runtime_validation = dict(record.payload.get("runtime_validation", {}))
        environment_name = runtime_validation.get("environment_name") or self.default_environment_name
        bundle = load_runtime_validation_policy_bundle(self.runtime_validation_policy_path)
        policy = bundle.resolve(
            environment_name=str(environment_name),
            fallback=RuntimeValidationPolicy(
                reminder_interval_seconds=self.reminder_interval_seconds,
                escalation_interval_seconds=self.escalation_interval_seconds,
            ),
        )
        return (
            policy.reminder_interval_seconds or self.reminder_interval_seconds,
            policy.escalation_interval_seconds or self.escalation_interval_seconds,
        )

    def _process_follow_up_for_alert(
        self,
        *,
        active_alert: ControlPlaneAlertRecord,
        force: bool,
    ) -> ControlPlaneAlertRecord | None:
        root_alert = self._root_incident_for_record(active_alert)
        if root_alert.acknowledged_at is not None:
            return None
        if self._matching_active_silences(root_alert):
            return None

        lifecycle_event = self._next_follow_up_event(root_alert=root_alert, force=force)
        if lifecycle_event is None:
            return None
        follow_up = self._build_follow_up_alert(root_alert=root_alert, lifecycle_event=lifecycle_event)
        delivered = self._deliver(
            follow_up,
            webhook_url_override=self.escalation_webhook_url if lifecycle_event == "escalation" else None,
        )
        self.job_repository.append_control_plane_alert(delivered)
        return delivered

    def _latest_follow_up(self, source_alert_id: str, lifecycle_event: str) -> ControlPlaneAlertRecord | None:
        for record in self.job_repository.list_control_plane_alerts():
            if self._source_alert_id(record) != source_alert_id:
                continue
            if self._lifecycle_event(record) != lifecycle_event:
                continue
            return record
        return None

    def _build_follow_up_alert(self, *, root_alert: ControlPlaneAlertRecord, lifecycle_event: str) -> ControlPlaneAlertRecord:
        label = "escalated" if lifecycle_event == "escalation" else "reminder"
        age_minutes = int((datetime.now(UTC) - datetime.fromisoformat(root_alert.created_at)).total_seconds() // 60)
        return ControlPlaneAlertRecord(
            alert_id=uuid4().hex[:16],
            created_at=_utc_now(),
            alert_key=f"{root_alert.alert_key}:{lifecycle_event}",
            status=root_alert.status,
            severity=root_alert.severity,
            summary=f"Control-plane incident remains unacknowledged and has been {label} after {age_minutes} minutes.",
            finding_codes=list(root_alert.finding_codes),
            delivery_state="skipped",
            payload={
                "report": dict(root_alert.payload.get("report", {})),
                "alert_family": root_alert.payload.get("alert_family"),
                "runtime_validation": dict(root_alert.payload.get("runtime_validation", {})),
                "runtime_validation_review": dict(root_alert.payload.get("runtime_validation_review", {})),
                "policy_source": root_alert.payload.get("policy_source"),
                "reminder_interval_seconds": root_alert.payload.get("reminder_interval_seconds"),
                "escalation_interval_seconds": root_alert.payload.get("escalation_interval_seconds"),
                "lifecycle_event": lifecycle_event,
                "source_alert_id": root_alert.alert_id,
            },
            error=None,
        )

    def _lifecycle_event(self, record: ControlPlaneAlertRecord) -> str:
        return str(record.payload.get("lifecycle_event", "incident"))

    def _source_alert_id(self, record: ControlPlaneAlertRecord) -> str | None:
        source_alert_id = record.payload.get("source_alert_id")
        if source_alert_id in {None, ""}:
            return None
        return str(source_alert_id)

    def _silence_is_active(self, record: ControlPlaneAlertSilenceRecord) -> bool:
        now = datetime.now(UTC)
        if record.cancelled_at is not None:
            return False
        if record.starts_at is not None and datetime.fromisoformat(record.starts_at) > now:
            return False
        if record.expires_at is not None and datetime.fromisoformat(record.expires_at) <= now:
            return False
        return True

    def _suppress(
        self,
        record: ControlPlaneAlertRecord,
        silences: list[ControlPlaneAlertSilenceRecord],
    ) -> ControlPlaneAlertRecord:
        payload = dict(record.payload)
        payload["silenced_by"] = [item.to_dict() for item in silences]
        route = self.resolve_active_oncall_route()
        if route is not None:
            payload["route"] = route.to_dict()
        return ControlPlaneAlertRecord(
            alert_id=record.alert_id,
            created_at=record.created_at,
            alert_key=record.alert_key,
            status=record.status,
            severity=record.severity,
            summary=record.summary,
            finding_codes=list(record.finding_codes),
            delivery_state="suppressed",
            payload=payload,
            error=None,
        )

    def _deliver(
        self,
        record: ControlPlaneAlertRecord,
        *,
        webhook_url_override: str | None = None,
    ) -> ControlPlaneAlertRecord:
        route = self.resolve_active_oncall_route()
        sink_error: str | None = None
        webhook_error: str | None = None
        destinations: list[dict] = []
        if webhook_url_override is None:
            webhook_url = route.webhook_url if route and route.webhook_url else self.webhook_url
        else:
            webhook_url = (
                route.escalation_webhook_url
                if route and route.escalation_webhook_url
                else webhook_url_override
            )

        if webhook_url:
            payload_bytes = json.dumps(record.to_dict(), sort_keys=True).encode("utf-8")
            request = Request(
                webhook_url,
                data=payload_bytes,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urlopen(request, timeout=5) as response:
                    destinations.append(
                        {
                            "kind": "webhook",
                            "target": webhook_url,
                            "state": "delivered",
                            "status_code": getattr(response, "status", None),
                        }
                    )
            except (OSError, URLError) as exc:
                webhook_error = str(exc)
                destinations.append({"kind": "webhook", "target": webhook_url, "state": "failed"})

        if self.sink_path:
            destinations.append({"kind": "jsonl", "target": str(self.sink_path), "state": "pending"})

        if any(item["state"] == "failed" for item in destinations):
            delivery_state = "partial" if any(item["state"] == "delivered" for item in destinations) else "failed"
        elif destinations:
            delivery_state = "delivered"
        else:
            delivery_state = "skipped"

        error = sink_error or webhook_error
        payload = dict(record.payload)
        payload["destinations"] = destinations
        if route is not None:
            payload["route"] = route.to_dict()
        delivered = ControlPlaneAlertRecord(
            alert_id=record.alert_id,
            created_at=record.created_at,
            alert_key=record.alert_key,
            status=record.status,
            severity=record.severity,
            summary=record.summary,
            finding_codes=list(record.finding_codes),
            delivery_state=delivery_state,
            payload=payload,
            error=webhook_error,
        )
        if self.sink_path:
            sink = Path(self.sink_path)
            sink_target = str(sink)
            sink_error: str | None = None
            try:
                sink.parent.mkdir(parents=True, exist_ok=True)
                for item in delivered.payload["destinations"]:
                    if item["kind"] == "jsonl" and item["target"] == sink_target:
                        item["state"] = "delivered"
                with sink.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(delivered.to_dict(), sort_keys=True))
                    handle.write("\n")
            except OSError as exc:
                sink_error = str(exc)
                for item in delivered.payload["destinations"]:
                    if item["kind"] == "jsonl" and item["target"] == sink_target:
                        item["state"] = "failed"
            if sink_error:
                delivered.error = sink_error if delivered.error is None else f"{delivered.error}; {sink_error}"
                delivered.delivery_state = (
                    "partial"
                    if any(item["state"] == "delivered" for item in delivered.payload["destinations"])
                    else "failed"
                )
            elif delivered.delivery_state == "skipped":
                delivered.delivery_state = "delivered"
        return delivered

    def _schedule_is_active_now(
        self,
        record: ControlPlaneOnCallScheduleRecord,
        *,
        reference_timestamp: datetime | None = None,
    ) -> bool:
        if record.cancelled_at is not None:
            return False
        try:
            zone = ZoneInfo(record.timezone_name)
        except ZoneInfoNotFoundError:
            return False
        local_now = (reference_timestamp or datetime.now(UTC)).astimezone(zone)
        start_clock = self._parse_clock(record.start_time)
        end_clock = self._parse_clock(record.end_time)
        current_clock = local_now.time().replace(second=0, microsecond=0)
        current_weekday = local_now.weekday()
        current_date = local_now.date()
        if not self._schedule_is_overnight(record):
            if current_weekday not in record.weekdays:
                return False
            if not self._schedule_covers_date(record, current_date):
                return False
            return start_clock <= current_clock <= end_clock

        if current_weekday in record.weekdays and self._schedule_covers_date(record, current_date):
            if current_clock >= start_clock:
                return True

        previous_date = current_date - timedelta(days=1)
        previous_weekday = previous_date.weekday()
        if previous_weekday not in record.weekdays:
            return False
        if not self._schedule_covers_date(record, previous_date):
            return False
        return current_clock < end_clock

    def _schedule_is_overnight(self, record: ControlPlaneOnCallScheduleRecord) -> bool:
        return self._parse_clock(record.end_time) <= self._parse_clock(record.start_time)

    def _validate_schedule_inputs(
        self,
        *,
        timezone_name: str,
        weekdays: list[int],
        start_time: str,
        end_time: str,
        priority: int,
        effective_start_date: str | None,
        effective_end_date: str | None,
    ) -> None:
        try:
            ZoneInfo(timezone_name)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(f"Unknown timezone '{timezone_name}'.") from exc
        if not weekdays:
            raise ValueError("weekdays must not be empty.")
        for weekday in weekdays:
            if weekday < 0 or weekday > 6:
                raise ValueError("weekdays must contain values from 0 to 6.")
        if priority < 0:
            raise ValueError("priority must be greater than or equal to 0.")
        start_date = self._parse_local_date(effective_start_date) if effective_start_date is not None else None
        end_date = self._parse_local_date(effective_end_date) if effective_end_date is not None else None
        if start_date is not None and end_date is not None and end_date < start_date:
            raise ValueError("effective_end_date must be greater than or equal to effective_start_date.")
        self._parse_clock(start_time)
        self._parse_clock(end_time)

    def _parse_clock(self, raw_value: str) -> time:
        try:
            parsed = datetime.strptime(raw_value, "%H:%M")
        except ValueError as exc:
            raise ValueError("time values must use HH:MM 24-hour format.") from exc
        return parsed.time()

    def _parse_local_date(self, raw_value: str) -> date:
        try:
            return date.fromisoformat(raw_value)
        except ValueError as exc:
            raise ValueError("date values must use YYYY-MM-DD format.") from exc

    def _schedule_covers_date(self, record: ControlPlaneOnCallScheduleRecord, local_date: date) -> bool:
        if record.effective_start_date is not None:
            if local_date < self._parse_local_date(record.effective_start_date):
                return False
        if record.effective_end_date is not None:
            if local_date > self._parse_local_date(record.effective_end_date):
                return False
        return True

    def _active_route_candidates(
        self,
        *,
        reference_timestamp: datetime | None = None,
        environment_name: str | None = None,
    ) -> list[ControlPlaneOnCallScheduleRecord]:
        candidates = self._active_route_candidates_for_records(
            self.job_repository.list_control_plane_oncall_schedules(),
            reference_timestamp=reference_timestamp,
            environment_name=environment_name,
        )
        return candidates

    def _active_route_candidates_for_records(
        self,
        records: list[ControlPlaneOnCallScheduleRecord],
        *,
        reference_timestamp: datetime | None = None,
        environment_name: str | None = None,
    ) -> list[ControlPlaneOnCallScheduleRecord]:
        active_environment_name = self._normalize_environment(environment_name)
        candidates = [
            record
            for record in records
            if record.environment_name == active_environment_name
            and self._schedule_is_active_now(record, reference_timestamp=reference_timestamp)
        ]
        candidates.sort(key=self._route_sort_key)
        return candidates

    def _route_sort_key(self, record: ControlPlaneOnCallScheduleRecord) -> tuple[float, float, float, float]:
        specificity_level, window_span_days = self._route_specificity(record)
        created_at = datetime.fromisoformat(record.created_at).timestamp()
        return (-float(record.priority), -float(specificity_level), float(window_span_days), -created_at)

    def _route_specificity(self, record: ControlPlaneOnCallScheduleRecord) -> tuple[int, int]:
        if record.effective_start_date is None and record.effective_end_date is None:
            return (0, 999_999)
        if record.effective_start_date is None or record.effective_end_date is None:
            return (1, 999_998)
        start_date = self._parse_local_date(record.effective_start_date)
        end_date = self._parse_local_date(record.effective_end_date)
        return (2, (end_date - start_date).days)

    def _route_reasons(self, record: ControlPlaneOnCallScheduleRecord) -> list[str]:
        reasons = [f"priority={record.priority}"]
        reasons.append(f"environment={record.environment_name}")
        if record.rotation_name:
            reasons.append(f"rotation={record.rotation_name}")
        if record.created_by_team:
            reasons.append(f"created_by_team={record.created_by_team}")
        if record.approved_by:
            reasons.append(f"approved_by={record.approved_by}")
        if record.approved_by_team:
            reasons.append(f"approved_by_team={record.approved_by_team}")
        if record.approved_by_role:
            reasons.append(f"approved_by_role={record.approved_by_role}")
        if record.effective_start_date or record.effective_end_date:
            reasons.append(
                f"date_window={record.effective_start_date or '*'}..{record.effective_end_date or '*'}"
            )
        else:
            reasons.append("date_window=unbounded")
        reasons.append(f"clock_window={record.start_time}-{record.end_time}")
        reasons.append(f"timezone={record.timezone_name}")
        return reasons

    def _schedule_requires_approval(self, proposed_record: ControlPlaneOnCallScheduleRecord) -> bool:
        schedules = [
            record
            for record in self.job_repository.list_control_plane_oncall_schedules()
            if record.cancelled_at is None and record.environment_name == proposed_record.environment_name
        ]
        schedules.append(proposed_record)
        lookahead_end = datetime.now(UTC) + timedelta(days=14)
        cursor = datetime.now(UTC).replace(second=0, microsecond=0)
        step = timedelta(minutes=15)
        while cursor <= lookahead_end:
            active_records = self._active_route_candidates_for_records(
                schedules,
                reference_timestamp=cursor,
                environment_name=proposed_record.environment_name,
            )
            proposed_group = [
                record
                for record in active_records
                if self._ambiguity_key(record) == self._ambiguity_key(proposed_record)
            ]
            if len(proposed_group) >= 2 and any(record.schedule_id == proposed_record.schedule_id for record in proposed_group):
                return True
            cursor += step
        return False

    def _ambiguity_key(self, record: ControlPlaneOnCallScheduleRecord) -> tuple[int, int, int]:
        specificity, window_span_days = self._route_specificity(record)
        return (record.priority, specificity, window_span_days)

    def _build_oncall_schedule_record(
        self,
        *,
        created_by: str,
        created_by_team: str | None,
        created_by_role: str | None,
        environment_name: str | None,
        team_name: str,
        timezone_name: str,
        change_reason: str | None,
        approved_by: str | None,
        approved_by_team: str | None,
        approved_by_role: str | None,
        approval_note: str | None,
        weekdays: list[int],
        start_time: str,
        end_time: str,
        priority: int,
        rotation_name: str | None,
        effective_start_date: str | None,
        effective_end_date: str | None,
        webhook_url: str | None,
        escalation_webhook_url: str | None,
    ) -> ControlPlaneOnCallScheduleRecord:
        self._validate_schedule_inputs(
            timezone_name=timezone_name,
            weekdays=weekdays,
            start_time=start_time,
            end_time=end_time,
            priority=priority,
            effective_start_date=effective_start_date,
            effective_end_date=effective_end_date,
        )
        if approval_note is not None and approved_by is None:
            raise ValueError("approval_note requires approved_by.")
        if approved_by_role is not None and approved_by is None:
            raise ValueError("approved_by_role requires approved_by.")
        if approved_by_team is not None and approved_by is None:
            raise ValueError("approved_by_team requires approved_by.")
        return ControlPlaneOnCallScheduleRecord(
            schedule_id=uuid4().hex[:16],
            created_at=_utc_now(),
            created_by=created_by,
            environment_name=self._normalize_environment(environment_name),
            created_by_team=self._normalize_team(created_by_team),
            created_by_role=created_by_role,
            change_reason=change_reason,
            approved_by=approved_by,
            approved_by_team=self._normalize_team(approved_by_team),
            approved_by_role=self._normalize_role(approved_by_role),
            approved_at=_utc_now() if approved_by is not None else None,
            approval_note=approval_note,
            team_name=team_name,
            timezone_name=timezone_name,
            weekdays=weekdays,
            start_time=start_time,
            end_time=end_time,
            priority=priority,
            rotation_name=rotation_name,
            effective_start_date=effective_start_date,
            effective_end_date=effective_end_date,
            webhook_url=webhook_url,
            escalation_webhook_url=escalation_webhook_url,
        )

    def _validate_schedule_approval_requirements(
        self,
        *,
        proposed_record: ControlPlaneOnCallScheduleRecord,
        effective_policy,
    ) -> None:
        if not self._schedule_requires_approval(proposed_record):
            return
        if (
            proposed_record.approved_by is None
            or proposed_record.change_reason is None
            or proposed_record.approved_by_role is None
        ):
            raise ValueError(
                "Ambiguous on-call overlaps require change_reason, approved_by, and approved_by_role."
            )
        required_roles = effective_policy.required_approver_roles or self.required_approver_roles
        if proposed_record.approved_by_role not in required_roles:
            raise ValueError(
                f"approved_by_role must be one of: {', '.join(required_roles)}."
            )
        if (
            effective_policy.allowed_approver_ids
            and proposed_record.approved_by not in effective_policy.allowed_approver_ids
        ):
            raise ValueError(
                f"approved_by must be one of: {', '.join(effective_policy.allowed_approver_ids)}."
            )
        allow_self_approval = (
            self.allow_self_approval
            if effective_policy.allow_self_approval is None
            else effective_policy.allow_self_approval
        )
        if not allow_self_approval and proposed_record.approved_by == proposed_record.created_by:
            raise ValueError("Self-approval is not allowed for ambiguous on-call overlaps.")

    def _normalize_role(self, raw_value: str | None) -> str | None:
        if raw_value is None:
            return None
        normalized = raw_value.strip().lower()
        return normalized or None

    def _normalize_team(self, raw_value: str | None) -> str | None:
        if raw_value is None:
            return None
        normalized = raw_value.strip().lower()
        return normalized or None

    def _normalize_environment(self, raw_value: str | None) -> str:
        if raw_value is None:
            return self.default_environment_name
        normalized = raw_value.strip().lower()
        return normalized or self.default_environment_name

    def _effective_governance_policy(self, record: ControlPlaneOnCallScheduleRecord):
        bundle = load_oncall_policy_bundle(self.policy_path)
        return bundle.resolve(
            environment_name=record.environment_name,
            team_name=record.team_name,
            rotation_name=record.rotation_name,
        )

    def _validate_policy_boundaries(self, record: ControlPlaneOnCallScheduleRecord, effective_policy) -> None:
        if effective_policy.owner_team and record.created_by_team is None:
            raise ValueError("created_by_team is required by the on-call governance policy.")
        if effective_policy.allowed_requester_teams:
            if record.created_by_team not in effective_policy.allowed_requester_teams:
                raise ValueError(
                    "created_by_team is not allowed by the on-call governance policy."
                )
        elif effective_policy.owner_team and record.created_by_team is not None:
            if record.created_by_team != effective_policy.owner_team:
                raise ValueError(
                    "created_by_team does not match the owner_team required by the on-call governance policy."
                )
        if record.approved_by is not None:
            if effective_policy.allowed_approver_teams:
                if record.approved_by_team not in effective_policy.allowed_approver_teams:
                    raise ValueError(
                        "approved_by_team is not allowed by the on-call governance policy."
                    )
            elif effective_policy.owner_team and record.approved_by_team is not None:
                if record.approved_by_team != effective_policy.owner_team:
                    raise ValueError(
                        "approved_by_team does not match the owner_team required by the on-call governance policy."
                    )


def _optional_float(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
