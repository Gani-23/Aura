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
