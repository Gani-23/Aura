from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from lsa.services.analytics_service import AnalyticsService, ControlPlaneAnalyticsReport
from lsa.services.job_service import JobService
from lsa.storage.files import JobRepository


def _metric_name(name: str) -> str:
    return f"lsa_control_plane_{name}"


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _render_labels(labels: dict[str, str] | None) -> str:
    if not labels:
        return ""
    rendered = ",".join(f'{key}="{_escape_label(value)}"' for key, value in sorted(labels.items()))
    return f"{{{rendered}}}"


def _as_number(value: bool | int | float) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value)


@dataclass(slots=True)
class ControlPlaneMetricsService:
    job_repository: JobRepository
    job_service: JobService
    analytics_service: AnalyticsService
    environment_name: str
    worker_mode: str
    default_window_days: int = 1

    def render_prometheus(self, *, days: int | None = None) -> str:
        window_days = days or self.default_window_days
        database_status = self.job_repository.database_status()
        schema_status = self.job_repository.schema_status()
        maintenance_mode = self.job_repository.maintenance_mode_status()
        analytics = self.analytics_service.build_control_plane_analytics(days=window_days)
        lines: list[str] = []

        lines.extend(
            [
                self._line(
                    "info",
                    1,
                    {
                        "environment": self.environment_name,
                        "worker_mode": self.worker_mode,
                        "database_backend": str(database_status["backend"]),
                    },
                ),
                self._line("database_ready", bool(database_status["ready"])),
                self._line("database_writable", bool(database_status["writable"])),
                self._line("database_schema_version", int(schema_status["schema_version"])),
                self._line("database_expected_schema_version", int(schema_status["expected_schema_version"])),
                self._line("database_schema_ready", bool(schema_status["schema_ready"])),
                self._line("database_pending_migration_count", int(schema_status["pending_migration_count"])),
                self._line("maintenance_mode_active", bool(maintenance_mode["active"])),
                self._line("worker_running", self.job_service.is_worker_running()),
                self._line("active_worker_count", self.job_service.active_worker_count()),
            ]
        )

        lines.extend(self._queue_lines(analytics))
        lines.extend(self._worker_lines(analytics))
        lines.extend(self._lease_lines(analytics))
        lines.extend(self._job_lines(analytics))
        lines.extend(self._oncall_lines(analytics))
        lines.extend(self._evaluation_lines(analytics))
        lines.extend(self._alert_lines())
        lines.extend(self._maintenance_event_lines())

        return "\n".join(lines) + "\n"

    def _queue_lines(self, analytics: ControlPlaneAnalyticsReport) -> list[str]:
        queue = analytics.queue
        return [
            self._line("jobs", queue.total_jobs, {"status": "total"}),
            self._line("jobs", queue.queued_jobs, {"status": "queued"}),
            self._line("jobs", queue.running_jobs, {"status": "running"}),
            self._line("jobs", queue.completed_jobs, {"status": "completed"}),
            self._line("jobs", queue.failed_jobs, {"status": "failed"}),
        ]

    def _worker_lines(self, analytics: ControlPlaneAnalyticsReport) -> list[str]:
        workers = analytics.workers
        return [
            self._line("workers", workers.total_workers_seen, {"state": "total_seen"}),
            self._line("workers", workers.active_workers, {"state": "active"}),
            self._line("workers", workers.busy_workers, {"state": "busy"}),
            self._line("workers", workers.idle_workers, {"state": "idle"}),
            self._line("workers", workers.stale_workers, {"state": "stale"}),
        ]

    def _lease_lines(self, analytics: ControlPlaneAnalyticsReport) -> list[str]:
        leases = analytics.leases
        return [
            self._line("lease_events", leases.total_events, {"type": "total"}),
            self._line("lease_events", leases.claimed_count, {"type": "claimed"}),
            self._line("lease_events", leases.renewed_count, {"type": "renewed"}),
            self._line("lease_events", leases.expired_requeue_count, {"type": "expired_requeue"}),
            self._line("lease_events", leases.completed_count, {"type": "completed"}),
            self._line("lease_events", leases.failed_count, {"type": "failed"}),
        ]

    def _job_lines(self, analytics: ControlPlaneAnalyticsReport) -> list[str]:
        jobs = analytics.jobs
        lines = [
            self._line("job_submissions", jobs.submitted_count),
            self._line("job_starts", jobs.started_count),
            self._line("job_completions", jobs.completed_count),
            self._line("job_failures", jobs.failed_count),
        ]
        if jobs.success_rate is not None:
            lines.append(self._line("job_success_rate", jobs.success_rate))
        return lines

    def _oncall_lines(self, analytics: ControlPlaneAnalyticsReport) -> list[str]:
        oncall = analytics.oncall
        lines = [
            self._line("oncall_schedules", oncall.total_schedules, {"state": "total"}),
            self._line("oncall_schedules", oncall.active_schedules, {"state": "active"}),
            self._line("oncall_conflicts", oncall.conflict_count),
            self._line("oncall_pending_reviews", oncall.pending_review_count),
            self._line("oncall_stale_pending_reviews", oncall.stale_pending_review_count),
        ]
        if oncall.oldest_pending_review_age_hours is not None:
            lines.append(self._line("oncall_oldest_pending_review_age_hours", oncall.oldest_pending_review_age_hours))
        return lines

    def _evaluation_lines(self, analytics: ControlPlaneAnalyticsReport) -> list[str]:
        status_values = {
            "healthy": 1 if analytics.evaluation.status == "healthy" else 0,
            "degraded": 1 if analytics.evaluation.status == "degraded" else 0,
            "critical": 1 if analytics.evaluation.status == "critical" else 0,
        }
        lines = [
            self._line("evaluation_status", value, {"status": status})
            for status, value in status_values.items()
        ]
        severity_counts = Counter(finding.severity for finding in analytics.evaluation.findings)
        for severity in ("warning", "critical"):
            lines.append(self._line("findings", severity_counts.get(severity, 0), {"severity": severity}))
        for finding in analytics.evaluation.findings:
            lines.append(
                self._line(
                    "finding_active",
                    1,
                    {"severity": finding.severity, "code": finding.code},
                )
            )
        return lines

    def _alert_lines(self) -> list[str]:
        alerts = self.job_repository.list_control_plane_alerts()
        alert_state_counts = Counter((record.delivery_state, record.severity) for record in alerts)
        lines = []
        for (delivery_state, severity), count in sorted(alert_state_counts.items()):
            lines.append(
                self._line(
                    "persisted_alerts",
                    count,
                    {"delivery_state": delivery_state, "severity": severity},
                )
            )

        active_silences = [
            record
            for record in self.job_repository.list_control_plane_alert_silences()
            if record.cancelled_at is None
        ]
        lines.append(self._line("active_alert_silences", len(active_silences)))
        return lines

    def _maintenance_event_lines(self) -> list[str]:
        events = self.job_repository.list_control_plane_maintenance_events()
        lines = [self._line("maintenance_events", len(events), {"type": "total"})]
        event_type_counts = Counter(record.event_type for record in events)
        for event_type, count in sorted(event_type_counts.items()):
            lines.append(self._line("maintenance_events", count, {"type": event_type}))
        return lines

    def _line(self, name: str, value: bool | int | float, labels: dict[str, str] | None = None) -> str:
        return f"{_metric_name(name)}{_render_labels(labels)} {_as_number(value)}"
