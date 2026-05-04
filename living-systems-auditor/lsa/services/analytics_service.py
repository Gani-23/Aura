from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from lsa.storage.files import JobRepository


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
            "evaluation": self.evaluation.to_dict(),
        }


@dataclass(slots=True)
class AnalyticsService:
    job_repository: JobRepository
    heartbeat_timeout_seconds: float = 5.0
    default_thresholds: ControlPlaneAlertThresholds = field(default_factory=ControlPlaneAlertThresholds)

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
        effective_thresholds = thresholds or self.default_thresholds
        evaluation = self._build_evaluation(
            queue=queue,
            workers=worker_summary,
            leases=lease_summary,
            jobs=job_summary,
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
            evaluation=evaluation,
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

    def _build_evaluation(
        self,
        *,
        queue: QueueAnalyticsSummary,
        workers: WorkerAnalyticsSummary,
        leases: LeaseAnalyticsSummary,
        jobs: JobAnalyticsSummary,
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
