from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class SnapshotRecord:
    snapshot_id: str
    created_at: str
    repo_path: str
    node_count: int
    edge_count: int
    snapshot_path: str

    def to_dict(self) -> dict:
        return {
            "snapshot_id": self.snapshot_id,
            "created_at": self.created_at,
            "repo_path": self.repo_path,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "snapshot_path": self.snapshot_path,
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "SnapshotRecord":
        return cls(
            snapshot_id=payload["snapshot_id"],
            created_at=payload["created_at"],
            repo_path=payload["repo_path"],
            node_count=payload["node_count"],
            edge_count=payload["edge_count"],
            snapshot_path=payload["snapshot_path"],
        )


@dataclass(slots=True)
class AuditRecord:
    audit_id: str
    created_at: str
    snapshot_id: str | None
    snapshot_path: str
    alert_count: int
    report_paths: list[str] = field(default_factory=list)
    alerts: list[dict] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)
    sessions: list[dict] = field(default_factory=list)
    explanation: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "audit_id": self.audit_id,
            "created_at": self.created_at,
            "snapshot_id": self.snapshot_id,
            "snapshot_path": self.snapshot_path,
            "alert_count": self.alert_count,
            "report_paths": list(self.report_paths),
            "alerts": list(self.alerts),
            "events": list(self.events),
            "sessions": list(self.sessions),
            "explanation": dict(self.explanation),
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "AuditRecord":
        return cls(
            audit_id=payload["audit_id"],
            created_at=payload["created_at"],
            snapshot_id=payload.get("snapshot_id"),
            snapshot_path=payload["snapshot_path"],
            alert_count=payload["alert_count"],
            report_paths=list(payload.get("report_paths", [])),
            alerts=list(payload.get("alerts", [])),
            events=list(payload.get("events", [])),
            sessions=list(payload.get("sessions", [])),
            explanation=dict(payload.get("explanation", {})),
        )


@dataclass(slots=True)
class JobRecord:
    job_id: str
    created_at: str
    job_type: str
    status: str
    request_payload: dict = field(default_factory=dict)
    result_payload: dict = field(default_factory=dict)
    error: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    claimed_by_worker_id: str | None = None
    lease_expires_at: str | None = None

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "created_at": self.created_at,
            "job_type": self.job_type,
            "status": self.status,
            "request_payload": dict(self.request_payload),
            "result_payload": dict(self.result_payload),
            "error": self.error,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "claimed_by_worker_id": self.claimed_by_worker_id,
            "lease_expires_at": self.lease_expires_at,
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "JobRecord":
        return cls(
            job_id=payload["job_id"],
            created_at=payload["created_at"],
            job_type=payload["job_type"],
            status=payload["status"],
            request_payload=dict(payload.get("request_payload", {})),
            result_payload=dict(payload.get("result_payload", {})),
            error=payload.get("error"),
            started_at=payload.get("started_at"),
            completed_at=payload.get("completed_at"),
            claimed_by_worker_id=payload.get("claimed_by_worker_id"),
            lease_expires_at=payload.get("lease_expires_at"),
        )


@dataclass(slots=True)
class WorkerRecord:
    worker_id: str
    mode: str
    status: str
    started_at: str
    last_heartbeat_at: str
    host_name: str
    process_id: int
    current_job_id: str | None = None

    def to_dict(self) -> dict:
        return {
            "worker_id": self.worker_id,
            "mode": self.mode,
            "status": self.status,
            "started_at": self.started_at,
            "last_heartbeat_at": self.last_heartbeat_at,
            "host_name": self.host_name,
            "process_id": self.process_id,
            "current_job_id": self.current_job_id,
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "WorkerRecord":
        return cls(
            worker_id=payload["worker_id"],
            mode=payload["mode"],
            status=payload["status"],
            started_at=payload["started_at"],
            last_heartbeat_at=payload["last_heartbeat_at"],
            host_name=payload["host_name"],
            process_id=payload["process_id"],
            current_job_id=payload.get("current_job_id"),
        )


@dataclass(slots=True)
class WorkerHeartbeatRecord:
    heartbeat_id: str
    worker_id: str
    recorded_at: str
    status: str
    current_job_id: str | None = None

    def to_dict(self) -> dict:
        return {
            "heartbeat_id": self.heartbeat_id,
            "worker_id": self.worker_id,
            "recorded_at": self.recorded_at,
            "status": self.status,
            "current_job_id": self.current_job_id,
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "WorkerHeartbeatRecord":
        return cls(
            heartbeat_id=payload["heartbeat_id"],
            worker_id=payload["worker_id"],
            recorded_at=payload["recorded_at"],
            status=payload["status"],
            current_job_id=payload.get("current_job_id"),
        )


@dataclass(slots=True)
class JobLeaseEventRecord:
    event_id: str
    job_id: str
    worker_id: str | None
    event_type: str
    recorded_at: str
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "job_id": self.job_id,
            "worker_id": self.worker_id,
            "event_type": self.event_type,
            "recorded_at": self.recorded_at,
            "details": dict(self.details),
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "JobLeaseEventRecord":
        return cls(
            event_id=payload["event_id"],
            job_id=payload["job_id"],
            worker_id=payload.get("worker_id"),
            event_type=payload["event_type"],
            recorded_at=payload["recorded_at"],
            details=dict(payload.get("details", {})),
        )


@dataclass(slots=True)
class WorkerHeartbeatRollupRecord:
    day_bucket: str
    worker_id: str
    status: str
    current_job_id: str | None
    event_count: int

    def to_dict(self) -> dict:
        return {
            "day_bucket": self.day_bucket,
            "worker_id": self.worker_id,
            "status": self.status,
            "current_job_id": self.current_job_id,
            "event_count": self.event_count,
        }


@dataclass(slots=True)
class JobLeaseEventRollupRecord:
    day_bucket: str
    job_id: str
    worker_id: str | None
    event_type: str
    event_count: int

    def to_dict(self) -> dict:
        return {
            "day_bucket": self.day_bucket,
            "job_id": self.job_id,
            "worker_id": self.worker_id,
            "event_type": self.event_type,
            "event_count": self.event_count,
        }


@dataclass(slots=True)
class ControlPlaneAlertRecord:
    alert_id: str
    created_at: str
    alert_key: str
    status: str
    severity: str
    summary: str
    finding_codes: list[str] = field(default_factory=list)
    delivery_state: str = "skipped"
    payload: dict = field(default_factory=dict)
    error: str | None = None
    acknowledged_at: str | None = None
    acknowledged_by: str | None = None
    acknowledgement_note: str | None = None

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "created_at": self.created_at,
            "alert_key": self.alert_key,
            "status": self.status,
            "severity": self.severity,
            "summary": self.summary,
            "finding_codes": list(self.finding_codes),
            "delivery_state": self.delivery_state,
            "payload": dict(self.payload),
            "error": self.error,
            "acknowledged_at": self.acknowledged_at,
            "acknowledged_by": self.acknowledged_by,
            "acknowledgement_note": self.acknowledgement_note,
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "ControlPlaneAlertRecord":
        return cls(
            alert_id=payload["alert_id"],
            created_at=payload["created_at"],
            alert_key=payload["alert_key"],
            status=payload["status"],
            severity=payload["severity"],
            summary=payload["summary"],
            finding_codes=list(payload.get("finding_codes", [])),
            delivery_state=payload.get("delivery_state", "skipped"),
            payload=dict(payload.get("payload", {})),
            error=payload.get("error"),
            acknowledged_at=payload.get("acknowledged_at"),
            acknowledged_by=payload.get("acknowledged_by"),
            acknowledgement_note=payload.get("acknowledgement_note"),
        )


@dataclass(slots=True)
class ControlPlaneAlertSilenceRecord:
    silence_id: str
    created_at: str
    created_by: str
    reason: str
    match_alert_key: str | None = None
    match_finding_code: str | None = None
    starts_at: str | None = None
    expires_at: str | None = None
    cancelled_at: str | None = None
    cancelled_by: str | None = None

    def to_dict(self) -> dict:
        return {
            "silence_id": self.silence_id,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "reason": self.reason,
            "match_alert_key": self.match_alert_key,
            "match_finding_code": self.match_finding_code,
            "starts_at": self.starts_at,
            "expires_at": self.expires_at,
            "cancelled_at": self.cancelled_at,
            "cancelled_by": self.cancelled_by,
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "ControlPlaneAlertSilenceRecord":
        return cls(
            silence_id=payload["silence_id"],
            created_at=payload["created_at"],
            created_by=payload["created_by"],
            reason=payload["reason"],
            match_alert_key=payload.get("match_alert_key"),
            match_finding_code=payload.get("match_finding_code"),
            starts_at=payload.get("starts_at"),
            expires_at=payload.get("expires_at"),
            cancelled_at=payload.get("cancelled_at"),
            cancelled_by=payload.get("cancelled_by"),
        )


@dataclass(slots=True)
class ControlPlaneOnCallScheduleRecord:
    schedule_id: str
    created_at: str
    created_by: str
    team_name: str
    timezone_name: str
    weekdays: list[int] = field(default_factory=list)
    start_time: str = "00:00"
    end_time: str = "23:59"
    webhook_url: str | None = None
    escalation_webhook_url: str | None = None
    cancelled_at: str | None = None
    cancelled_by: str | None = None

    def to_dict(self) -> dict:
        return {
            "schedule_id": self.schedule_id,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "team_name": self.team_name,
            "timezone_name": self.timezone_name,
            "weekdays": list(self.weekdays),
            "start_time": self.start_time,
            "end_time": self.end_time,
            "webhook_url": self.webhook_url,
            "escalation_webhook_url": self.escalation_webhook_url,
            "cancelled_at": self.cancelled_at,
            "cancelled_by": self.cancelled_by,
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "ControlPlaneOnCallScheduleRecord":
        return cls(
            schedule_id=payload["schedule_id"],
            created_at=payload["created_at"],
            created_by=payload["created_by"],
            team_name=payload["team_name"],
            timezone_name=payload["timezone_name"],
            weekdays=list(payload.get("weekdays", [])),
            start_time=payload.get("start_time", "00:00"),
            end_time=payload.get("end_time", "23:59"),
            webhook_url=payload.get("webhook_url"),
            escalation_webhook_url=payload.get("escalation_webhook_url"),
            cancelled_at=payload.get("cancelled_at"),
            cancelled_by=payload.get("cancelled_by"),
        )
