from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from lsa.services.control_plane_runtime_validation_service import ControlPlaneRuntimeValidationService
from lsa.services.runtime_validation_policy import (
    RuntimeValidationPolicy,
    load_runtime_validation_policy_bundle,
)
from lsa.storage.files import JobRepository
from lsa.storage.models import ControlPlaneOnCallChangeRequestRecord, ControlPlaneOnCallScheduleRecord


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _day_from_timestamp(timestamp: str) -> str:
    return datetime.fromisoformat(timestamp).date().isoformat()


@dataclass(slots=True)
class QueueAnalyticsSummary:
    total_jobs: int
    queued_jobs: int
    running_jobs: int
    completed_jobs: int
    failed_jobs: int

    def to_dict(self) -> dict:
        return {
            "total_jobs": self.total_jobs,
            "queued_jobs": self.queued_jobs,
            "running_jobs": self.running_jobs,
            "completed_jobs": self.completed_jobs,
            "failed_jobs": self.failed_jobs,
        }


@dataclass(slots=True)
class WorkerDailyAnalytics:
    day_bucket: str
    total_heartbeats: int
    active_worker_count: int
    busy_worker_count: int
    stopped_worker_count: int

    def to_dict(self) -> dict:
        return {
            "day_bucket": self.day_bucket,
            "total_heartbeats": self.total_heartbeats,
            "active_worker_count": self.active_worker_count,
            "busy_worker_count": self.busy_worker_count,
            "stopped_worker_count": self.stopped_worker_count,
        }


@dataclass(slots=True)
class WorkerAnalyticsSummary:
    active_workers: int
    busy_workers: int
    idle_workers: int
    stale_workers: int
    total_workers_seen: int
    days: list[WorkerDailyAnalytics] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "active_workers": self.active_workers,
            "busy_workers": self.busy_workers,
            "idle_workers": self.idle_workers,
            "stale_workers": self.stale_workers,
            "total_workers_seen": self.total_workers_seen,
            "days": [item.to_dict() for item in self.days],
        }


@dataclass(slots=True)
class LeaseDailyAnalytics:
    day_bucket: str
    total_events: int
    claimed_count: int
    renewed_count: int
    expired_requeue_count: int
    completed_count: int
    failed_count: int
    affected_job_count: int
    affected_worker_count: int

    def to_dict(self) -> dict:
        return {
            "day_bucket": self.day_bucket,
            "total_events": self.total_events,
            "claimed_count": self.claimed_count,
            "renewed_count": self.renewed_count,
            "expired_requeue_count": self.expired_requeue_count,
            "completed_count": self.completed_count,
            "failed_count": self.failed_count,
            "affected_job_count": self.affected_job_count,
            "affected_worker_count": self.affected_worker_count,
        }


@dataclass(slots=True)
class LeaseAnalyticsSummary:
    total_events: int
    claimed_count: int
    renewed_count: int
    expired_requeue_count: int
    completed_count: int
    failed_count: int
    days: list[LeaseDailyAnalytics] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total_events": self.total_events,
            "claimed_count": self.claimed_count,
            "renewed_count": self.renewed_count,
            "expired_requeue_count": self.expired_requeue_count,
            "completed_count": self.completed_count,
            "failed_count": self.failed_count,
            "days": [item.to_dict() for item in self.days],
        }


@dataclass(slots=True)
class JobDailyAnalytics:
    day_bucket: str
    created_count: int
    started_count: int
    completed_count: int
    failed_count: int

    def to_dict(self) -> dict:
        return {
            "day_bucket": self.day_bucket,
            "created_count": self.created_count,
            "started_count": self.started_count,
            "completed_count": self.completed_count,
            "failed_count": self.failed_count,
        }


@dataclass(slots=True)
class JobAnalyticsSummary:
    submitted_count: int
    started_count: int
    completed_count: int
    failed_count: int
    success_rate: float | None
    days: list[JobDailyAnalytics] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "submitted_count": self.submitted_count,
            "started_count": self.started_count,
            "completed_count": self.completed_count,
            "failed_count": self.failed_count,
            "success_rate": self.success_rate,
            "days": [item.to_dict() for item in self.days],
        }


@dataclass(slots=True)
class OnCallConflictSummary:
    schedule_ids: list[str]
    team_names: list[str]
    rotation_names: list[str]
    sample_timestamp: str
    priority: int
    specificity: int
    window_span_days: int
    occurrence_count: int

    def to_dict(self) -> dict:
        return {
            "schedule_ids": list(self.schedule_ids),
            "team_names": list(self.team_names),
            "rotation_names": list(self.rotation_names),
            "sample_timestamp": self.sample_timestamp,
            "priority": self.priority,
            "specificity": self.specificity,
            "window_span_days": self.window_span_days,
            "occurrence_count": self.occurrence_count,
        }


@dataclass(slots=True)
class OnCallPendingReviewSample:
    request_id: str
    created_at: str
    team_name: str
    rotation_name: str | None
    age_hours: float
    change_reason: str | None
    assigned_to: str | None = None
    assigned_to_team: str | None = None

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "created_at": self.created_at,
            "team_name": self.team_name,
            "rotation_name": self.rotation_name,
            "age_hours": self.age_hours,
            "change_reason": self.change_reason,
            "assigned_to": self.assigned_to,
            "assigned_to_team": self.assigned_to_team,
        }


@dataclass(slots=True)
class OnCallAnalyticsSummary:
    total_schedules: int
    active_schedules: int
    conflict_count: int
    pending_review_count: int = 0
    stale_pending_review_count: int = 0
    oldest_pending_review_age_hours: float | None = None
    conflicts: list[OnCallConflictSummary] = field(default_factory=list)
    pending_review_samples: list[OnCallPendingReviewSample] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total_schedules": self.total_schedules,
            "active_schedules": self.active_schedules,
            "conflict_count": self.conflict_count,
            "pending_review_count": self.pending_review_count,
            "stale_pending_review_count": self.stale_pending_review_count,
            "oldest_pending_review_age_hours": self.oldest_pending_review_age_hours,
            "conflicts": [item.to_dict() for item in self.conflicts],
            "pending_review_samples": [item.to_dict() for item in self.pending_review_samples],
        }


@dataclass(slots=True)
class RuntimeValidationAnalyticsSummary:
    generated_at: str
    environment_name: str
    status: str
    severity: str
    cadence_status: str
    policy_source: str
    due_soon_age_hours: float
    warning_age_hours: float
    critical_age_hours: float
    reminder_interval_seconds: float | None = None
    escalation_interval_seconds: float | None = None
    latest_rehearsal_event_id: str | None = None
    latest_rehearsal_recorded_at: str | None = None
    latest_rehearsal_changed_by: str | None = None
    latest_rehearsal_status: str | None = None
    latest_expected_backend: str | None = None
    latest_expected_repository_layout: str | None = None
    latest_database_backend: str | None = None
    latest_repository_layout: str | None = None
    latest_mixed_backends: bool | None = None
    latest_checks: dict[str, bool] = field(default_factory=dict)
    age_hours: float | None = None
    next_due_at: str | None = None
    due_in_hours: float | None = None
    blockers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "generated_at": self.generated_at,
            "environment_name": self.environment_name,
            "status": self.status,
            "severity": self.severity,
            "cadence_status": self.cadence_status,
            "policy_source": self.policy_source,
            "due_soon_age_hours": self.due_soon_age_hours,
            "warning_age_hours": self.warning_age_hours,
            "critical_age_hours": self.critical_age_hours,
            "reminder_interval_seconds": self.reminder_interval_seconds,
            "escalation_interval_seconds": self.escalation_interval_seconds,
            "latest_rehearsal_event_id": self.latest_rehearsal_event_id,
            "latest_rehearsal_recorded_at": self.latest_rehearsal_recorded_at,
            "latest_rehearsal_changed_by": self.latest_rehearsal_changed_by,
            "latest_rehearsal_status": self.latest_rehearsal_status,
            "latest_expected_backend": self.latest_expected_backend,
            "latest_expected_repository_layout": self.latest_expected_repository_layout,
            "latest_database_backend": self.latest_database_backend,
            "latest_repository_layout": self.latest_repository_layout,
            "latest_mixed_backends": self.latest_mixed_backends,
            "latest_checks": dict(self.latest_checks),
            "age_hours": self.age_hours,
            "next_due_at": self.next_due_at,
            "due_in_hours": self.due_in_hours,
            "blockers": list(self.blockers),
        }


@dataclass(slots=True)
class RuntimeValidationReviewSample:
    review_id: str
    opened_at: str
    status: str
    age_hours: float
    owner_team: str | None = None
    assigned_to: str | None = None
    assigned_to_team: str | None = None
    policy_source: str = "defaults"
    summary: str | None = None

    def to_dict(self) -> dict:
        return {
            "review_id": self.review_id,
            "opened_at": self.opened_at,
            "status": self.status,
            "age_hours": self.age_hours,
            "owner_team": self.owner_team,
            "assigned_to": self.assigned_to,
            "assigned_to_team": self.assigned_to_team,
            "policy_source": self.policy_source,
            "summary": self.summary,
        }


@dataclass(slots=True)
class RuntimeValidationReviewAnalyticsSummary:
    active_review_count: int
    assigned_review_count: int
    unassigned_review_count: int
    stale_review_count: int
    stale_unassigned_review_count: int
    oldest_review_age_hours: float | None = None
    review_samples: list[RuntimeValidationReviewSample] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "active_review_count": self.active_review_count,
            "assigned_review_count": self.assigned_review_count,
            "unassigned_review_count": self.unassigned_review_count,
            "stale_review_count": self.stale_review_count,
            "stale_unassigned_review_count": self.stale_unassigned_review_count,
            "oldest_review_age_hours": self.oldest_review_age_hours,
            "review_samples": [item.to_dict() for item in self.review_samples],
        }


@dataclass(slots=True)
class ControlPlaneAlertThresholds:
    queue_warning_threshold: int = 5
    queue_critical_threshold: int = 20
    stale_worker_warning_threshold: int = 1
    stale_worker_critical_threshold: int = 3
    expired_lease_warning_threshold: int = 1
    expired_lease_critical_threshold: int = 3
    job_failure_rate_warning_threshold: float = 0.1
    job_failure_rate_critical_threshold: float = 0.25
    job_failure_rate_min_samples: int = 3
    oncall_conflict_warning_threshold: int = 1
    oncall_conflict_critical_threshold: int = 3
    oncall_pending_review_warning_threshold: int = 1
    oncall_pending_review_critical_threshold: int = 3
    oncall_pending_review_sla_hours: float = 24.0
    runtime_validation_review_warning_threshold: int = 1
    runtime_validation_review_critical_threshold: int = 3
    runtime_rehearsal_due_soon_age_hours: float = 18.0
    runtime_rehearsal_warning_age_hours: float = 24.0
    runtime_rehearsal_critical_age_hours: float = 72.0

    def to_dict(self) -> dict:
        return {
            "queue_warning_threshold": self.queue_warning_threshold,
            "queue_critical_threshold": self.queue_critical_threshold,
            "stale_worker_warning_threshold": self.stale_worker_warning_threshold,
            "stale_worker_critical_threshold": self.stale_worker_critical_threshold,
            "expired_lease_warning_threshold": self.expired_lease_warning_threshold,
            "expired_lease_critical_threshold": self.expired_lease_critical_threshold,
            "job_failure_rate_warning_threshold": self.job_failure_rate_warning_threshold,
            "job_failure_rate_critical_threshold": self.job_failure_rate_critical_threshold,
            "job_failure_rate_min_samples": self.job_failure_rate_min_samples,
            "oncall_conflict_warning_threshold": self.oncall_conflict_warning_threshold,
            "oncall_conflict_critical_threshold": self.oncall_conflict_critical_threshold,
            "oncall_pending_review_warning_threshold": self.oncall_pending_review_warning_threshold,
            "oncall_pending_review_critical_threshold": self.oncall_pending_review_critical_threshold,
            "oncall_pending_review_sla_hours": self.oncall_pending_review_sla_hours,
            "runtime_validation_review_warning_threshold": self.runtime_validation_review_warning_threshold,
            "runtime_validation_review_critical_threshold": self.runtime_validation_review_critical_threshold,
            "runtime_rehearsal_due_soon_age_hours": self.runtime_rehearsal_due_soon_age_hours,
            "runtime_rehearsal_warning_age_hours": self.runtime_rehearsal_warning_age_hours,
            "runtime_rehearsal_critical_age_hours": self.runtime_rehearsal_critical_age_hours,
        }


@dataclass(slots=True)
class ControlPlaneFinding:
    severity: str
    code: str
    metric: str
    summary: str
    observed_value: float
    threshold_value: float | None = None
    context: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "code": self.code,
            "metric": self.metric,
            "summary": self.summary,
            "observed_value": self.observed_value,
            "threshold_value": self.threshold_value,
            "context": dict(self.context),
        }


@dataclass(slots=True)
class ControlPlaneEvaluation:
    status: str
    findings: list[ControlPlaneFinding] = field(default_factory=list)
    thresholds: ControlPlaneAlertThresholds = field(default_factory=ControlPlaneAlertThresholds)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "findings": [item.to_dict() for item in self.findings],
            "thresholds": self.thresholds.to_dict(),
        }


@dataclass(slots=True)
class ControlPlaneAnalyticsReport:
    generated_at: str
    window_days: int
    window_start_day: str
    window_end_day: str
    queue: QueueAnalyticsSummary
    workers: WorkerAnalyticsSummary
    leases: LeaseAnalyticsSummary
    jobs: JobAnalyticsSummary
    oncall: OnCallAnalyticsSummary
    runtime_validation: RuntimeValidationAnalyticsSummary
    runtime_validation_reviews: RuntimeValidationReviewAnalyticsSummary
    evaluation: ControlPlaneEvaluation

    def to_dict(self) -> dict:
        return {
            "generated_at": self.generated_at,
            "window_days": self.window_days,
            "window_start_day": self.window_start_day,
            "window_end_day": self.window_end_day,
            "queue": self.queue.to_dict(),
            "workers": self.workers.to_dict(),
            "leases": self.leases.to_dict(),
            "jobs": self.jobs.to_dict(),
            "oncall": self.oncall.to_dict(),
            "runtime_validation": self.runtime_validation.to_dict(),
            "runtime_validation_reviews": self.runtime_validation_reviews.to_dict(),
            "evaluation": self.evaluation.to_dict(),
        }


@dataclass(slots=True)
class AnalyticsService:
    job_repository: JobRepository
    default_environment_name: str = "default"
    heartbeat_timeout_seconds: float = 5.0
    default_thresholds: ControlPlaneAlertThresholds = field(default_factory=ControlPlaneAlertThresholds)
    runtime_validation_policy_path: str | None = None
    runtime_validation_reminder_interval_seconds: float = 900.0
    runtime_validation_escalation_interval_seconds: float = 1800.0

    def build_control_plane_analytics(
        self,
        *,
        days: int = 30,
        thresholds: ControlPlaneAlertThresholds | None = None,
    ) -> ControlPlaneAnalyticsReport:
        if days < 1:
            raise ValueError("days must be at least 1.")

        now = _utc_now()
        end_day = now.date()
        start_day = end_day - timedelta(days=days - 1)
        day_buckets = [(start_day + timedelta(days=index)).isoformat() for index in range(days)]
        day_bucket_set = set(day_buckets)

        jobs = self.job_repository.list()
        workers = self.job_repository.list_workers()
        raw_heartbeats = self.job_repository.list_worker_heartbeats()
        raw_lease_events = self.job_repository.list_job_lease_events()
        heartbeat_rollups = self.job_repository.list_worker_heartbeat_rollups()
        lease_rollups = self.job_repository.list_job_lease_event_rollups()

        queue = self._build_queue_summary(jobs)
        worker_summary = self._build_worker_summary(
            workers=workers,
            raw_heartbeats=raw_heartbeats,
            heartbeat_rollups=heartbeat_rollups,
            day_buckets=day_buckets,
            day_bucket_set=day_bucket_set,
            now=now,
        )
        lease_summary = self._build_lease_summary(
            raw_lease_events=raw_lease_events,
            lease_rollups=lease_rollups,
            day_buckets=day_buckets,
            day_bucket_set=day_bucket_set,
        )
        job_summary = self._build_job_summary(
            jobs=jobs,
            day_buckets=day_buckets,
            day_bucket_set=day_bucket_set,
        )
        effective_thresholds = self._effective_thresholds(thresholds)
        oncall_summary = self._build_oncall_summary(
            now=now,
            pending_review_sla_hours=effective_thresholds.oncall_pending_review_sla_hours,
        )
        runtime_validation_summary = self._build_runtime_validation_summary(
            due_soon_age_hours=effective_thresholds.runtime_rehearsal_due_soon_age_hours,
            warning_age_hours=effective_thresholds.runtime_rehearsal_warning_age_hours,
            critical_age_hours=effective_thresholds.runtime_rehearsal_critical_age_hours,
        )
        runtime_validation_review_summary = self._build_runtime_validation_review_summary(now=now)
        evaluation = self._build_evaluation(
            queue=queue,
            workers=worker_summary,
            leases=lease_summary,
            jobs=job_summary,
            oncall=oncall_summary,
            runtime_validation=runtime_validation_summary,
            runtime_validation_reviews=runtime_validation_review_summary,
            thresholds=effective_thresholds,
        )

        return ControlPlaneAnalyticsReport(
            generated_at=now.isoformat(),
            window_days=days,
            window_start_day=start_day.isoformat(),
            window_end_day=end_day.isoformat(),
            queue=queue,
            workers=worker_summary,
            leases=lease_summary,
            jobs=job_summary,
            oncall=oncall_summary,
            runtime_validation=runtime_validation_summary,
            runtime_validation_reviews=runtime_validation_review_summary,
            evaluation=evaluation,
        )

    def _effective_thresholds(
        self,
        thresholds: ControlPlaneAlertThresholds | None,
    ) -> ControlPlaneAlertThresholds:
        effective = thresholds or self.default_thresholds
        if thresholds is not None:
            return effective
        bundle = load_runtime_validation_policy_bundle(self.runtime_validation_policy_path)
        runtime_policy = bundle.resolve(
            environment_name=self.default_environment_name,
            fallback=RuntimeValidationPolicy(
                due_soon_age_hours=effective.runtime_rehearsal_due_soon_age_hours,
                warning_age_hours=effective.runtime_rehearsal_warning_age_hours,
                critical_age_hours=effective.runtime_rehearsal_critical_age_hours,
                reminder_interval_seconds=self.runtime_validation_reminder_interval_seconds,
                escalation_interval_seconds=self.runtime_validation_escalation_interval_seconds,
            ),
        )
        payload = effective.to_dict()
        payload["runtime_rehearsal_due_soon_age_hours"] = (
            runtime_policy.due_soon_age_hours or effective.runtime_rehearsal_due_soon_age_hours
        )
        payload["runtime_rehearsal_warning_age_hours"] = (
            runtime_policy.warning_age_hours or effective.runtime_rehearsal_warning_age_hours
        )
        payload["runtime_rehearsal_critical_age_hours"] = (
            runtime_policy.critical_age_hours or effective.runtime_rehearsal_critical_age_hours
        )
        return ControlPlaneAlertThresholds(**payload)

    def _build_runtime_validation_summary(
        self,
        *,
        due_soon_age_hours: float,
        warning_age_hours: float,
        critical_age_hours: float,
    ) -> RuntimeValidationAnalyticsSummary:
        bundle = load_runtime_validation_policy_bundle(self.runtime_validation_policy_path)
        effective_policy = bundle.resolve(
            environment_name=self.default_environment_name,
            fallback=RuntimeValidationPolicy(
                due_soon_age_hours=due_soon_age_hours,
                warning_age_hours=warning_age_hours,
                critical_age_hours=critical_age_hours,
                reminder_interval_seconds=self.runtime_validation_reminder_interval_seconds,
                escalation_interval_seconds=self.runtime_validation_escalation_interval_seconds,
            ),
        )
        summary = ControlPlaneRuntimeValidationService(
            job_repository=self.job_repository,
            environment_name=self.default_environment_name,
            due_soon_age_hours=effective_policy.due_soon_age_hours or due_soon_age_hours,
            warning_age_hours=effective_policy.warning_age_hours or warning_age_hours,
            critical_age_hours=effective_policy.critical_age_hours or critical_age_hours,
            policy_source=bundle.source_for(environment_name=self.default_environment_name),
            reminder_interval_seconds=effective_policy.reminder_interval_seconds,
            escalation_interval_seconds=effective_policy.escalation_interval_seconds,
        ).build_summary()
        return RuntimeValidationAnalyticsSummary(
            generated_at=summary.generated_at,
            environment_name=summary.environment_name,
            status=summary.status,
            severity=summary.severity,
            cadence_status=summary.cadence_status,
            policy_source=summary.policy_source,
            due_soon_age_hours=summary.due_soon_age_hours,
            warning_age_hours=summary.warning_age_hours,
            critical_age_hours=summary.critical_age_hours,
            reminder_interval_seconds=summary.reminder_interval_seconds,
            escalation_interval_seconds=summary.escalation_interval_seconds,
            latest_rehearsal_event_id=summary.latest_rehearsal_event_id,
            latest_rehearsal_recorded_at=summary.latest_rehearsal_recorded_at,
            latest_rehearsal_changed_by=summary.latest_rehearsal_changed_by,
            latest_rehearsal_status=summary.latest_rehearsal_status,
            latest_expected_backend=summary.latest_expected_backend,
            latest_expected_repository_layout=summary.latest_expected_repository_layout,
            latest_database_backend=summary.latest_database_backend,
            latest_repository_layout=summary.latest_repository_layout,
            latest_mixed_backends=summary.latest_mixed_backends,
            latest_checks={} if summary.latest_checks is None else dict(summary.latest_checks),
            age_hours=summary.age_hours,
            next_due_at=summary.next_due_at,
            due_in_hours=summary.due_in_hours,
            blockers=[] if summary.blockers is None else list(summary.blockers),
        )

    def _build_runtime_validation_review_summary(
        self,
        *,
        now: datetime,
    ) -> RuntimeValidationReviewAnalyticsSummary:
        reviews = self._list_active_runtime_validation_reviews()
        if not reviews:
            return RuntimeValidationReviewAnalyticsSummary(
                active_review_count=0,
                assigned_review_count=0,
                unassigned_review_count=0,
                stale_review_count=0,
                stale_unassigned_review_count=0,
                oldest_review_age_hours=None,
                review_samples=[],
            )

        policy_bundle = load_runtime_validation_policy_bundle(self.runtime_validation_policy_path)
        fallback_policy = RuntimeValidationPolicy(
            reminder_interval_seconds=self.runtime_validation_reminder_interval_seconds,
            escalation_interval_seconds=self.runtime_validation_escalation_interval_seconds,
        )
        review_samples: list[RuntimeValidationReviewSample] = []
        stale_review_count = 0
        stale_unassigned_review_count = 0
        oldest_review_age_hours = 0.0
        assigned_review_count = 0
        unassigned_review_count = 0

        for review in reviews:
            age_hours = max((now - datetime.fromisoformat(str(review["opened_at"]))).total_seconds() / 3600.0, 0.0)
            oldest_review_age_hours = max(oldest_review_age_hours, age_hours)
            if review.get("assigned_to"):
                assigned_review_count += 1
            else:
                unassigned_review_count += 1
            effective_policy = policy_bundle.resolve(
                environment_name=str(review["environment_name"]),
                fallback=fallback_policy,
            )
            escalation_seconds = (
                effective_policy.escalation_interval_seconds or self.runtime_validation_escalation_interval_seconds
            )
            is_stale = age_hours * 3600.0 >= escalation_seconds
            if is_stale:
                stale_review_count += 1
                if not review.get("assigned_to"):
                    stale_unassigned_review_count += 1
            review_samples.append(
                RuntimeValidationReviewSample(
                    review_id=str(review["review_id"]),
                    opened_at=str(review["opened_at"]),
                    status=str(review["status"]),
                    age_hours=round(age_hours, 2),
                    owner_team=_optional_str(review.get("owner_team")),
                    assigned_to=_optional_str(review.get("assigned_to")),
                    assigned_to_team=_optional_str(review.get("assigned_to_team")),
                    policy_source=str(review.get("policy_source", "defaults")),
                    summary=_optional_str(review.get("summary")),
                )
            )

        review_samples.sort(key=lambda item: item.age_hours, reverse=True)
        return RuntimeValidationReviewAnalyticsSummary(
            active_review_count=len(reviews),
            assigned_review_count=assigned_review_count,
            unassigned_review_count=unassigned_review_count,
            stale_review_count=stale_review_count,
            stale_unassigned_review_count=stale_unassigned_review_count,
            oldest_review_age_hours=round(oldest_review_age_hours, 2) if reviews else None,
            review_samples=review_samples[:3],
        )

    def _build_queue_summary(self, jobs: list) -> QueueAnalyticsSummary:
        statuses = defaultdict(int)
        for record in jobs:
            statuses[record.status] += 1
        return QueueAnalyticsSummary(
            total_jobs=len(jobs),
            queued_jobs=statuses["queued"],
            running_jobs=statuses["running"],
            completed_jobs=statuses["completed"],
            failed_jobs=statuses["failed"],
        )

    def _build_worker_summary(
        self,
        *,
        workers: list,
        raw_heartbeats: list,
        heartbeat_rollups: list,
        day_buckets: list[str],
        day_bucket_set: set[str],
        now: datetime,
    ) -> WorkerAnalyticsSummary:
        threshold = now - timedelta(seconds=self.heartbeat_timeout_seconds)
        active_workers = 0
        busy_workers = 0
        idle_workers = 0
        stale_workers = 0

        for record in workers:
            last_seen = datetime.fromisoformat(record.last_heartbeat_at)
            if last_seen >= threshold:
                active_workers += 1
                if record.current_job_id:
                    busy_workers += 1
                else:
                    idle_workers += 1
            else:
                stale_workers += 1

        worker_day_stats = {
            day_bucket: {
                "total_heartbeats": 0,
                "active_workers": set(),
                "busy_workers": set(),
                "stopped_workers": set(),
            }
            for day_bucket in day_buckets
        }

        for record in raw_heartbeats:
            day_bucket = _day_from_timestamp(record.recorded_at)
            if day_bucket not in day_bucket_set:
                continue
            entry = worker_day_stats[day_bucket]
            entry["total_heartbeats"] += 1
            entry["active_workers"].add(record.worker_id)
            if record.current_job_id:
                entry["busy_workers"].add(record.worker_id)
            if record.status == "stopped":
                entry["stopped_workers"].add(record.worker_id)

        for record in heartbeat_rollups:
            if record.day_bucket not in day_bucket_set:
                continue
            entry = worker_day_stats[record.day_bucket]
            entry["total_heartbeats"] += record.event_count
            entry["active_workers"].add(record.worker_id)
            if record.current_job_id:
                entry["busy_workers"].add(record.worker_id)
            if record.status == "stopped":
                entry["stopped_workers"].add(record.worker_id)

        days = [
            WorkerDailyAnalytics(
                day_bucket=day_bucket,
                total_heartbeats=worker_day_stats[day_bucket]["total_heartbeats"],
                active_worker_count=len(worker_day_stats[day_bucket]["active_workers"]),
                busy_worker_count=len(worker_day_stats[day_bucket]["busy_workers"]),
                stopped_worker_count=len(worker_day_stats[day_bucket]["stopped_workers"]),
            )
            for day_bucket in day_buckets
        ]

        return WorkerAnalyticsSummary(
            active_workers=active_workers,
            busy_workers=busy_workers,
            idle_workers=idle_workers,
            stale_workers=stale_workers,
            total_workers_seen=len(workers),
            days=days,
        )

    def _build_lease_summary(
        self,
        *,
        raw_lease_events: list,
        lease_rollups: list,
        day_buckets: list[str],
        day_bucket_set: set[str],
    ) -> LeaseAnalyticsSummary:
        lease_day_stats = {
            day_bucket: {
                "total_events": 0,
                "claimed_count": 0,
                "renewed_count": 0,
                "expired_requeue_count": 0,
                "completed_count": 0,
                "failed_count": 0,
                "affected_jobs": set(),
                "affected_workers": set(),
            }
            for day_bucket in day_buckets
        }

        def accumulate(day_bucket: str, *, event_type: str, job_id: str, worker_id: str | None, count: int) -> None:
            if day_bucket not in day_bucket_set:
                return
            entry = lease_day_stats[day_bucket]
            entry["total_events"] += count
            if event_type == "lease_claimed":
                entry["claimed_count"] += count
            elif event_type == "lease_renewed":
                entry["renewed_count"] += count
            elif event_type == "lease_expired_requeued":
                entry["expired_requeue_count"] += count
            elif event_type == "job_completed":
                entry["completed_count"] += count
            elif event_type == "job_failed":
                entry["failed_count"] += count
            entry["affected_jobs"].add(job_id)
            if worker_id:
                entry["affected_workers"].add(worker_id)

        for record in raw_lease_events:
            accumulate(
                _day_from_timestamp(record.recorded_at),
                event_type=record.event_type,
                job_id=record.job_id,
                worker_id=record.worker_id,
                count=1,
            )

        for record in lease_rollups:
            accumulate(
                record.day_bucket,
                event_type=record.event_type,
                job_id=record.job_id,
                worker_id=record.worker_id,
                count=record.event_count,
            )

        days = [
            LeaseDailyAnalytics(
                day_bucket=day_bucket,
                total_events=lease_day_stats[day_bucket]["total_events"],
                claimed_count=lease_day_stats[day_bucket]["claimed_count"],
                renewed_count=lease_day_stats[day_bucket]["renewed_count"],
                expired_requeue_count=lease_day_stats[day_bucket]["expired_requeue_count"],
                completed_count=lease_day_stats[day_bucket]["completed_count"],
                failed_count=lease_day_stats[day_bucket]["failed_count"],
                affected_job_count=len(lease_day_stats[day_bucket]["affected_jobs"]),
                affected_worker_count=len(lease_day_stats[day_bucket]["affected_workers"]),
            )
            for day_bucket in day_buckets
        ]

        return LeaseAnalyticsSummary(
            total_events=sum(item.total_events for item in days),
            claimed_count=sum(item.claimed_count for item in days),
            renewed_count=sum(item.renewed_count for item in days),
            expired_requeue_count=sum(item.expired_requeue_count for item in days),
            completed_count=sum(item.completed_count for item in days),
            failed_count=sum(item.failed_count for item in days),
            days=days,
        )

    def _build_job_summary(
        self,
        *,
        jobs: list,
        day_buckets: list[str],
        day_bucket_set: set[str],
    ) -> JobAnalyticsSummary:
        job_day_stats = {
            day_bucket: {
                "created_count": 0,
                "started_count": 0,
                "completed_count": 0,
                "failed_count": 0,
            }
            for day_bucket in day_buckets
        }

        def increment(timestamp: str | None, key: str) -> None:
            if timestamp is None:
                return
            day_bucket = _day_from_timestamp(timestamp)
            if day_bucket in day_bucket_set:
                job_day_stats[day_bucket][key] += 1

        for record in jobs:
            increment(record.created_at, "created_count")
            increment(record.started_at, "started_count")
            if record.status == "completed":
                increment(record.completed_at, "completed_count")
            if record.status == "failed":
                increment(record.completed_at, "failed_count")

        days = [
            JobDailyAnalytics(
                day_bucket=day_bucket,
                created_count=job_day_stats[day_bucket]["created_count"],
                started_count=job_day_stats[day_bucket]["started_count"],
                completed_count=job_day_stats[day_bucket]["completed_count"],
                failed_count=job_day_stats[day_bucket]["failed_count"],
            )
            for day_bucket in day_buckets
        ]

        completed_count = sum(item.completed_count for item in days)
        failed_count = sum(item.failed_count for item in days)
        finished_count = completed_count + failed_count

        return JobAnalyticsSummary(
            submitted_count=sum(item.created_count for item in days),
            started_count=sum(item.started_count for item in days),
            completed_count=completed_count,
            failed_count=failed_count,
            success_rate=(completed_count / finished_count) if finished_count else None,
            days=days,
        )

    def _build_oncall_summary(
        self,
        *,
        now: datetime,
        pending_review_sla_hours: float,
    ) -> OnCallAnalyticsSummary:
        schedules = [
            record
            for record in self.job_repository.list_control_plane_oncall_schedules()
            if record.cancelled_at is None and record.environment_name == self.default_environment_name
        ]
        pending_reviews = [
            record
            for record in self.job_repository.list_control_plane_oncall_change_requests(status="pending_review")
            if record.environment_name == self.default_environment_name
        ]
        active_schedules = [
            record
            for record in schedules
            if self._schedule_is_active_at(record, now)
        ]

        lookahead_end = now + timedelta(days=14)
        step = timedelta(minutes=15)
        conflicts_by_group: dict[tuple[str, ...], OnCallConflictSummary] = {}
        cursor = now.replace(second=0, microsecond=0)
        while cursor <= lookahead_end:
            active_at_cursor = [
                record
                for record in schedules
                if self._schedule_is_active_at(record, cursor)
            ]
            ambiguous_groups: dict[tuple[int, int, int], list[ControlPlaneOnCallScheduleRecord]] = defaultdict(list)
            for record in active_at_cursor:
                ambiguous_groups[self._ambiguity_key(record)].append(record)
            for group in ambiguous_groups.values():
                if len(group) < 2:
                    continue
                schedule_ids = tuple(sorted(record.schedule_id for record in group))
                if schedule_ids not in conflicts_by_group:
                    ordered_group = sorted(group, key=lambda item: item.created_at, reverse=True)
                    representative = ordered_group[0]
                    specificity, window_span_days = self._route_specificity(representative)
                    conflicts_by_group[schedule_ids] = OnCallConflictSummary(
                        schedule_ids=list(schedule_ids),
                        team_names=[record.team_name for record in ordered_group],
                        rotation_names=[record.rotation_name for record in ordered_group if record.rotation_name],
                        sample_timestamp=cursor.isoformat(),
                        priority=representative.priority,
                        specificity=specificity,
                        window_span_days=window_span_days,
                        occurrence_count=0,
                    )
                conflicts_by_group[schedule_ids].occurrence_count += 1
            cursor += step

        conflicts = sorted(
            conflicts_by_group.values(),
            key=lambda item: (-item.priority, -item.specificity, item.window_span_days, item.sample_timestamp),
        )

        pending_review_ages = [
            (
                record,
                max(0.0, (now - datetime.fromisoformat(record.created_at)).total_seconds() / 3600.0),
            )
            for record in pending_reviews
        ]
        stale_pending_reviews = [
            (record, age_hours)
            for record, age_hours in pending_review_ages
            if age_hours >= pending_review_sla_hours
        ]
        stale_pending_reviews.sort(key=lambda item: item[1], reverse=True)

        return OnCallAnalyticsSummary(
            total_schedules=len(schedules),
            active_schedules=len(active_schedules),
            conflict_count=len(conflicts),
            pending_review_count=len(pending_reviews),
            stale_pending_review_count=len(stale_pending_reviews),
            oldest_pending_review_age_hours=(
                max((age_hours for _, age_hours in pending_review_ages), default=None)
            ),
            conflicts=conflicts,
            pending_review_samples=[
                OnCallPendingReviewSample(
                    request_id=record.request_id,
                    created_at=record.created_at,
                    team_name=record.team_name,
                    rotation_name=record.rotation_name,
                    age_hours=round(age_hours, 2),
                    change_reason=record.change_reason,
                    assigned_to=record.assigned_to,
                    assigned_to_team=record.assigned_to_team,
                )
                for record, age_hours in stale_pending_reviews[:3]
            ],
        )

    def _build_evaluation(
        self,
        *,
        queue: QueueAnalyticsSummary,
        workers: WorkerAnalyticsSummary,
        leases: LeaseAnalyticsSummary,
        jobs: JobAnalyticsSummary,
        oncall: OnCallAnalyticsSummary,
        runtime_validation: RuntimeValidationAnalyticsSummary,
        runtime_validation_reviews: RuntimeValidationReviewAnalyticsSummary,
        thresholds: ControlPlaneAlertThresholds,
    ) -> ControlPlaneEvaluation:
        findings: list[ControlPlaneFinding] = []

        findings.extend(
            self._threshold_findings(
                observed_value=queue.queued_jobs,
                warning_threshold=thresholds.queue_warning_threshold,
                critical_threshold=thresholds.queue_critical_threshold,
                code="queue_backlog",
                metric="queue.queued_jobs",
                warning_summary="Queued job backlog is above the configured warning threshold.",
                critical_summary="Queued job backlog is above the configured critical threshold.",
            )
        )
        findings.extend(
            self._threshold_findings(
                observed_value=workers.stale_workers,
                warning_threshold=thresholds.stale_worker_warning_threshold,
                critical_threshold=thresholds.stale_worker_critical_threshold,
                code="stale_workers",
                metric="workers.stale_workers",
                warning_summary="Stale workers are present in the control plane.",
                critical_summary="Too many stale workers are present in the control plane.",
            )
        )
        findings.extend(
            self._threshold_findings(
                observed_value=leases.expired_requeue_count,
                warning_threshold=thresholds.expired_lease_warning_threshold,
                critical_threshold=thresholds.expired_lease_critical_threshold,
                code="expired_leases",
                metric="leases.expired_requeue_count",
                warning_summary="Expired job leases have been requeued recently.",
                critical_summary="Expired lease churn is above the configured critical threshold.",
            )
        )

        finished_jobs = jobs.completed_count + jobs.failed_count
        if jobs.success_rate is not None and finished_jobs >= thresholds.job_failure_rate_min_samples:
            failure_rate = 1.0 - jobs.success_rate
            findings.extend(
                self._threshold_findings(
                    observed_value=failure_rate,
                    warning_threshold=thresholds.job_failure_rate_warning_threshold,
                    critical_threshold=thresholds.job_failure_rate_critical_threshold,
                    code="job_failure_rate",
                    metric="jobs.failure_rate",
                    warning_summary="Job failure rate is above the configured warning threshold.",
                    critical_summary="Job failure rate is above the configured critical threshold.",
                    context={"finished_jobs": finished_jobs},
                )
            )

        if queue.queued_jobs > 0 and workers.active_workers == 0:
            findings.append(
                ControlPlaneFinding(
                    severity="critical",
                    code="queue_without_active_workers",
                    metric="workers.active_workers",
                    summary="Jobs are queued but no active workers are currently heartbeating.",
                    observed_value=float(workers.active_workers),
                    threshold_value=1.0,
                    context={"queued_jobs": queue.queued_jobs},
                )
            )

        if oncall.conflict_count > 0:
            sample_conflicts = [item.to_dict() for item in oncall.conflicts[:3]]
            findings.extend(
                self._threshold_findings(
                    observed_value=oncall.conflict_count,
                    warning_threshold=thresholds.oncall_conflict_warning_threshold,
                    critical_threshold=thresholds.oncall_conflict_critical_threshold,
                    code="oncall_route_conflicts",
                    metric="oncall.conflict_count",
                    warning_summary="Ambiguous on-call route overlaps were detected in upcoming schedule coverage.",
                    critical_summary="Too many ambiguous on-call route overlaps were detected in upcoming schedule coverage.",
                    context={"sample_conflicts": sample_conflicts},
                )
            )

        if oncall.stale_pending_review_count > 0:
            findings.extend(
                self._threshold_findings(
                    observed_value=oncall.stale_pending_review_count,
                    warning_threshold=thresholds.oncall_pending_review_warning_threshold,
                    critical_threshold=thresholds.oncall_pending_review_critical_threshold,
                    code="oncall_pending_reviews_stale",
                    metric="oncall.stale_pending_review_count",
                    warning_summary="Pending on-call change reviews are older than the configured SLA.",
                    critical_summary="Too many pending on-call change reviews are older than the configured SLA.",
                    context={
                        "sla_hours": thresholds.oncall_pending_review_sla_hours,
                        "sample_requests": [item.to_dict() for item in oncall.pending_review_samples],
                    },
                )
            )

        if runtime_validation.status == "missing":
            findings.append(
                ControlPlaneFinding(
                    severity="critical",
                    code="runtime_rehearsal_missing",
                    metric="runtime_validation.latest_rehearsal_recorded_at",
                    summary="No control-plane runtime rehearsal evidence exists for the active environment.",
                    observed_value=0.0,
                    threshold_value=1.0,
                    context={"environment_name": self.default_environment_name},
                )
            )
        elif runtime_validation.status == "failed":
            findings.append(
                ControlPlaneFinding(
                    severity="critical",
                    code="runtime_rehearsal_failed",
                    metric="runtime_validation.latest_rehearsal_status",
                    summary="The latest control-plane runtime rehearsal did not pass.",
                    observed_value=0.0,
                    threshold_value=1.0,
                    context={
                        "latest_rehearsal_event_id": runtime_validation.latest_rehearsal_event_id,
                        "latest_rehearsal_status": runtime_validation.latest_rehearsal_status,
                        "latest_checks": runtime_validation.latest_checks,
                    },
                )
            )
        elif runtime_validation.cadence_status == "due_soon" and runtime_validation.age_hours is not None:
            findings.append(
                ControlPlaneFinding(
                    severity="warning",
                    code="runtime_rehearsal_due_soon",
                    metric="runtime_validation.due_in_hours",
                    summary="The latest control-plane runtime rehearsal is approaching its warning threshold.",
                    observed_value=runtime_validation.age_hours,
                    threshold_value=thresholds.runtime_rehearsal_warning_age_hours,
                    context={
                        "due_soon_age_hours": thresholds.runtime_rehearsal_due_soon_age_hours,
                        "latest_rehearsal_event_id": runtime_validation.latest_rehearsal_event_id,
                        "latest_rehearsal_recorded_at": runtime_validation.latest_rehearsal_recorded_at,
                        "next_due_at": runtime_validation.next_due_at,
                        "due_in_hours": runtime_validation.due_in_hours,
                    },
                )
            )
        elif runtime_validation.age_hours is not None:
            findings.extend(
                self._threshold_findings(
                    observed_value=runtime_validation.age_hours,
                    warning_threshold=thresholds.runtime_rehearsal_warning_age_hours,
                    critical_threshold=thresholds.runtime_rehearsal_critical_age_hours,
                    code="runtime_rehearsal_age",
                    metric="runtime_validation.age_hours",
                    warning_summary="The latest control-plane runtime rehearsal is older than the configured warning threshold.",
                    critical_summary="The latest control-plane runtime rehearsal is older than the configured critical threshold.",
                    context={
                        "latest_rehearsal_event_id": runtime_validation.latest_rehearsal_event_id,
                        "latest_rehearsal_recorded_at": runtime_validation.latest_rehearsal_recorded_at,
                        "latest_expected_backend": runtime_validation.latest_expected_backend,
                        "latest_repository_layout": runtime_validation.latest_repository_layout,
                    },
                )
            )

        if runtime_validation_reviews.stale_review_count > 0:
            findings.extend(
                self._threshold_findings(
                    observed_value=runtime_validation_reviews.stale_review_count,
                    warning_threshold=thresholds.runtime_validation_review_warning_threshold,
                    critical_threshold=thresholds.runtime_validation_review_critical_threshold,
                    code="runtime_validation_reviews_stale",
                    metric="runtime_validation_reviews.stale_review_count",
                    warning_summary="Runtime-validation reviews are older than their policy escalation interval.",
                    critical_summary="Too many runtime-validation reviews are older than their policy escalation interval.",
                    context={
                        "sample_reviews": [item.to_dict() for item in runtime_validation_reviews.review_samples],
                    },
                )
            )

        if runtime_validation_reviews.stale_unassigned_review_count > 0:
            findings.extend(
                self._threshold_findings(
                    observed_value=runtime_validation_reviews.stale_unassigned_review_count,
                    warning_threshold=thresholds.runtime_validation_review_warning_threshold,
                    critical_threshold=thresholds.runtime_validation_review_critical_threshold,
                    code="runtime_validation_reviews_unassigned_stale",
                    metric="runtime_validation_reviews.stale_unassigned_review_count",
                    warning_summary="Unassigned runtime-validation reviews are older than their policy escalation interval.",
                    critical_summary="Too many unassigned runtime-validation reviews are older than their policy escalation interval.",
                    context={
                        "sample_reviews": [
                            item.to_dict()
                            for item in runtime_validation_reviews.review_samples
                            if item.assigned_to is None
                        ],
                    },
                )
            )

        status = "healthy"
        if any(item.severity == "critical" for item in findings):
            status = "critical"
        elif any(item.severity == "warning" for item in findings):
            status = "degraded"

        return ControlPlaneEvaluation(
            status=status,
            findings=findings,
            thresholds=thresholds,
        )

    def _threshold_findings(
        self,
        *,
        observed_value: float,
        warning_threshold: float,
        critical_threshold: float,
        code: str,
        metric: str,
        warning_summary: str,
        critical_summary: str,
        context: dict | None = None,
    ) -> list[ControlPlaneFinding]:
        if observed_value < warning_threshold:
            return []
        severity = "critical" if observed_value >= critical_threshold else "warning"
        summary = critical_summary if severity == "critical" else warning_summary
        threshold_value = critical_threshold if severity == "critical" else warning_threshold
        return [
            ControlPlaneFinding(
                severity=severity,
                code=code,
                metric=metric,
                summary=summary,
                observed_value=float(observed_value),
                threshold_value=float(threshold_value),
                context={} if context is None else dict(context),
            )
        ]

    def _list_active_runtime_validation_reviews(self) -> list[dict]:
        reviews: dict[str, dict] = {}
        for record in reversed(self.job_repository.list_control_plane_maintenance_events(limit=2000)):
            details = dict(record.details)
            if record.event_type == "runtime_validation_review_opened":
                review_id = str(details.get("review_id", ""))
                if not review_id:
                    continue
                reviews[review_id] = {
                    "review_id": review_id,
                    "opened_at": str(details.get("opened_at", record.recorded_at)),
                    "environment_name": str(details.get("environment_name", self.default_environment_name)),
                    "status": "pending_review",
                    "summary": _optional_str(details.get("summary")),
                    "owner_team": _optional_str(details.get("owner_team")),
                    "assigned_to": None,
                    "assigned_to_team": None,
                    "policy_source": str(details.get("policy_source", "defaults")),
                }
            elif record.event_type == "runtime_validation_review_assigned":
                review_id = str(details.get("review_id", ""))
                if review_id not in reviews:
                    continue
                reviews[review_id]["status"] = "assigned"
                reviews[review_id]["assigned_to"] = _optional_str(details.get("assigned_to"))
                reviews[review_id]["assigned_to_team"] = _optional_str(details.get("assigned_to_team"))
            elif record.event_type == "runtime_validation_review_resolved":
                review_id = str(details.get("review_id", ""))
                if review_id not in reviews:
                    continue
                reviews[review_id]["status"] = "resolved"

        active = [
            review
            for review in reviews.values()
            if review["environment_name"] == self.default_environment_name and review["status"] != "resolved"
        ]
        active.sort(key=lambda item: str(item["opened_at"]), reverse=True)
        return active

    def _schedule_is_active_at(self, record: ControlPlaneOnCallScheduleRecord, reference_timestamp: datetime) -> bool:
        try:
            zone = ZoneInfo(record.timezone_name)
        except ZoneInfoNotFoundError:
            return False
        local_now = reference_timestamp.astimezone(zone)
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

    def _parse_clock(self, raw_value: str) -> time:
        return datetime.strptime(raw_value, "%H:%M").time()

    def _parse_local_date(self, raw_value: str) -> date:
        return date.fromisoformat(raw_value)

    def _schedule_covers_date(self, record: ControlPlaneOnCallScheduleRecord, local_date: date) -> bool:
        if record.effective_start_date is not None:
            if local_date < self._parse_local_date(record.effective_start_date):
                return False
        if record.effective_end_date is not None:
            if local_date > self._parse_local_date(record.effective_end_date):
                return False
        return True

    def _route_specificity(self, record: ControlPlaneOnCallScheduleRecord) -> tuple[int, int]:
        if record.effective_start_date is None and record.effective_end_date is None:
            return (0, 999_999)
        if record.effective_start_date is None or record.effective_end_date is None:
            return (1, 999_998)
        start_date = self._parse_local_date(record.effective_start_date)
        end_date = self._parse_local_date(record.effective_end_date)
        return (2, (end_date - start_date).days)

    def _ambiguity_key(self, record: ControlPlaneOnCallScheduleRecord) -> tuple[int, int, int]:
        specificity, window_span_days = self._route_specificity(record)
        return (record.priority, specificity, window_span_days)


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
