from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from threading import Event, Lock, Thread
from time import monotonic, sleep
from typing import Any
from uuid import uuid4

from lsa.drift.trace_parser import load_trace_events
from lsa.services.audit_service import AuditService
from lsa.services.control_plane_alert_service import ControlPlaneAlertService
from lsa.services.trace_collection_service import TraceCollectionRequest, TraceCollectionService
from lsa.storage.files import JobRepository
from lsa.storage.models import (
    ControlPlaneAlertRecord,
    ControlPlaneMaintenanceEventRecord,
    JobLeaseEventRecord,
    JobRecord,
    WorkerHeartbeatRecord,
    WorkerRecord,
)


@dataclass(slots=True)
class JobService:
    job_repository: JobRepository
    audit_service: AuditService
    trace_collection_service: TraceCollectionService
    worker_mode: str = "standalone"
    poll_interval_seconds: float = 0.1
    heartbeat_timeout_seconds: float = 5.0
    worker_history_retention_days: int = 14
    job_lease_history_retention_days: int = 30
    history_prune_interval_seconds: float = 300.0
    control_plane_alert_service: ControlPlaneAlertService | None = None
    runtime_validation_review_service: Any | None = None
    deployment_readiness_service: Any | None = None
    control_plane_alert_interval_seconds: float = 60.0
    control_plane_alerts_enabled: bool = True
    deployment_readiness_required_for_job_submission: bool = False
    _worker_thread: Thread | None = field(init=False, default=None)
    _stop_event: Event = field(init=False, default_factory=Event)
    _lock: Lock = field(init=False, default_factory=Lock)
    _worker_id: str = field(init=False)
    _worker_started_at: str = field(init=False)
    _host_name: str = field(init=False)
    _process_id: int = field(init=False)
    _last_prune_at: float = field(init=False, default=0.0)
    _last_alert_emit_at: float = field(init=False, default=0.0)

    def __post_init__(self) -> None:
        self._worker_started_at = _utc_now()
        self._host_name = socket.gethostname()
        self._process_id = os.getpid()
        self._worker_id = f"{self.worker_mode}-{self._process_id}-{uuid4().hex[:8]}"

    def start(self) -> None:
        with self._lock:
            if self._worker_thread is not None and self._worker_thread.is_alive():
                return
            self.job_repository.requeue_incomplete()
            self._stop_event.clear()
            self._mark_worker_running(current_job_id=None)
            self.prune_history(force=True)
            self._worker_thread = Thread(
                target=self._worker_loop,
                daemon=True,
                name="lsa-job-worker",
            )
            self._worker_thread.start()

    def stop(self) -> None:
        with self._lock:
            thread = self._worker_thread
            self._stop_event.set()
        if thread is not None:
            thread.join(timeout=2)
        self._mark_worker_stopped()
        with self._lock:
            self._worker_thread = None

    def is_worker_running(self) -> bool:
        with self._lock:
            return self._worker_thread is not None and self._worker_thread.is_alive()

    def worker_id(self) -> str:
        return self._worker_id

    def active_worker_count(self) -> int:
        return self.job_repository.count_workers_seen_since(self._heartbeat_threshold())

    def maintenance_mode_status(self) -> dict[str, object]:
        return self.job_repository.maintenance_mode_status()

    def is_maintenance_mode_active(self) -> bool:
        return bool(self.maintenance_mode_status()["active"])

    def enable_maintenance_mode(self, *, changed_by: str, reason: str | None = None) -> dict[str, object]:
        status = self.job_repository.set_maintenance_mode(active=True, changed_by=changed_by, reason=reason)
        self._record_maintenance_event(
            event_type="maintenance_mode_enabled",
            changed_by=changed_by,
            reason=reason,
            details={},
        )
        return status

    def disable_maintenance_mode(self, *, changed_by: str, reason: str | None = None) -> dict[str, object]:
        status = self.job_repository.set_maintenance_mode(active=False, changed_by=changed_by, reason=reason)
        self._record_maintenance_event(
            event_type="maintenance_mode_disabled",
            changed_by=changed_by,
            reason=reason,
            details={},
        )
        return status

    def emit_control_plane_alerts_if_due(self) -> list[ControlPlaneAlertRecord]:
        if not self.control_plane_alerts_enabled or self.control_plane_alert_service is None:
            return []
        now = monotonic()
        if now - self._last_alert_emit_at < self.control_plane_alert_interval_seconds:
            return []
        self.process_runtime_validation_reviews(changed_by="system", reason="scheduled control-plane cadence")
        self.process_runtime_validation_governance(changed_by="system", reason="scheduled control-plane cadence")
        self.process_runtime_validation_change_control(changed_by="system", reason="scheduled control-plane cadence")
        emitted = self.emit_control_plane_alerts()
        if emitted:
            return emitted
        return self.process_control_plane_alert_follow_ups()

    def emit_control_plane_alerts(self, *, force: bool = False) -> list[ControlPlaneAlertRecord]:
        if not self.control_plane_alerts_enabled or self.control_plane_alert_service is None:
            return []
        alerts = self.control_plane_alert_service.emit_alerts(force=force)
        self._last_alert_emit_at = monotonic()
        return alerts

    def process_control_plane_alert_follow_ups(self, *, force: bool = False) -> list[ControlPlaneAlertRecord]:
        if not self.control_plane_alerts_enabled or self.control_plane_alert_service is None:
            return []
        alerts = self.control_plane_alert_service.process_follow_ups(force=force)
        self._last_alert_emit_at = monotonic()
        return alerts

    def process_runtime_validation_reviews(
        self,
        *,
        changed_by: str,
        reason: str | None = None,
        force: bool = False,
    ):
        if self.runtime_validation_review_service is None:
            return []
        return self.runtime_validation_review_service.process_reviews(
            changed_by=changed_by,
            reason=reason,
            force=force,
        )

    def process_runtime_validation_governance(
        self,
        *,
        changed_by: str,
        reason: str | None = None,
        force: bool = False,
    ):
        if self.runtime_validation_review_service is None:
            return []
        return self.runtime_validation_review_service.process_governance_requests(
            changed_by=changed_by,
            reason=reason,
            force=force,
        )

    def process_runtime_validation_change_control(
        self,
        *,
        changed_by: str,
        reason: str | None = None,
        force: bool = False,
    ):
        if self.runtime_validation_review_service is None:
            return []
        return self.runtime_validation_review_service.process_change_control_requests(
            changed_by=changed_by,
            reason=reason,
            force=force,
        )

    def list_runtime_validation_reviews(
        self,
        *,
        status: str | None = None,
        owner_team: str | None = None,
        assignment_state: str | None = None,
    ):
        if self.runtime_validation_review_service is None:
            return []
        return self.runtime_validation_review_service.list_reviews(
            status=status,
            owner_team=owner_team,
            assignment_state=assignment_state,
        )

    def list_runtime_validation_governance_requests(
        self,
        *,
        status: str | None = None,
        owner_team: str | None = None,
    ):
        if self.runtime_validation_review_service is None:
            return []
        return self.runtime_validation_review_service.list_governance_requests(
            status=status,
            owner_team=owner_team,
        )

    def list_runtime_validation_change_control_requests(
        self,
        *,
        status: str | None = None,
        owner_team: str | None = None,
        assignment_state: str | None = None,
    ):
        if self.runtime_validation_review_service is None:
            return []
        return self.runtime_validation_review_service.list_change_control_requests(
            status=status,
            owner_team=owner_team,
            assignment_state=assignment_state,
        )

    def runtime_validation_change_control_queue_summary(
        self,
        *,
        status: str | None = None,
        owner_team: str | None = None,
        assignment_state: str | None = None,
    ):
        if self.runtime_validation_review_service is None:
            return None
        return self.runtime_validation_review_service.change_control_queue_summary(
            status=status,
            owner_team=owner_team,
            assignment_state=assignment_state,
        )

    def assign_runtime_validation_change_control_request(
        self,
        *,
        request_id: str,
        assigned_to: str,
        assigned_to_team: str | None,
        assigned_by: str,
        assignment_note: str | None = None,
    ):
        if self.runtime_validation_review_service is None:
            raise RuntimeError("Runtime-validation review service is not configured.")
        return self.runtime_validation_review_service.assign_change_control_request(
            request_id=request_id,
            assigned_to=assigned_to,
            assigned_to_team=assigned_to_team,
            assigned_by=assigned_by,
            assignment_note=assignment_note,
        )

    def decide_runtime_validation_change_control_request(
        self,
        *,
        request_id: str,
        decision: str,
        decided_by: str,
        decision_note: str | None = None,
    ):
        if self.runtime_validation_review_service is None:
            raise RuntimeError("Runtime-validation review service is not configured.")
        return self.runtime_validation_review_service.decide_change_control_request(
            request_id=request_id,
            decision=decision,
            decided_by=decided_by,
            decision_note=decision_note,
        )

    def bulk_assign_runtime_validation_change_control_requests(
        self,
        *,
        assigned_to: str,
        assigned_to_team: str | None,
        assigned_by: str,
        assignment_note: str | None = None,
        status: str | None = None,
        owner_team: str | None = None,
        assignment_state: str | None = None,
    ):
        if self.runtime_validation_review_service is None:
            raise RuntimeError("Runtime-validation review service is not configured.")
        return self.runtime_validation_review_service.bulk_assign_change_control_requests(
            assigned_to=assigned_to,
            assigned_to_team=assigned_to_team,
            assigned_by=assigned_by,
            assignment_note=assignment_note,
            status=status,
            owner_team=owner_team,
            assignment_state=assignment_state,
        )

    def bulk_decide_runtime_validation_change_control_requests(
        self,
        *,
        decision: str,
        decided_by: str,
        decision_note: str | None = None,
        status: str | None = None,
        owner_team: str | None = None,
        assignment_state: str | None = None,
    ):
        if self.runtime_validation_review_service is None:
            raise RuntimeError("Runtime-validation review service is not configured.")
        return self.runtime_validation_review_service.bulk_decide_change_control_requests(
            decision=decision,
            decided_by=decided_by,
            decision_note=decision_note,
            status=status,
            owner_team=owner_team,
            assignment_state=assignment_state,
        )

    def runtime_validation_review_queue_summary(
        self,
        *,
        status: str | None = None,
        owner_team: str | None = None,
        assignment_state: str | None = None,
    ):
        if self.runtime_validation_review_service is None:
            return None
        return self.runtime_validation_review_service.queue_summary(
            status=status,
            owner_team=owner_team,
            assignment_state=assignment_state,
        )

    def bulk_assign_runtime_validation_reviews(
        self,
        *,
        assigned_to: str,
        assigned_to_team: str | None,
        assigned_by: str,
        assignment_note: str | None = None,
        status: str | None = None,
        owner_team: str | None = None,
        assignment_state: str | None = None,
    ):
        if self.runtime_validation_review_service is None:
            raise RuntimeError("Runtime-validation review service is not configured.")
        return self.runtime_validation_review_service.bulk_assign_reviews(
            assigned_to=assigned_to,
            assigned_to_team=assigned_to_team,
            assigned_by=assigned_by,
            assignment_note=assignment_note,
            status=status,
            owner_team=owner_team,
            assignment_state=assignment_state,
        )

    def bulk_resolve_runtime_validation_reviews(
        self,
        *,
        resolved_by: str,
        resolution_reason: str,
        resolution_note: str | None = None,
        status: str | None = None,
        owner_team: str | None = None,
        assignment_state: str | None = None,
    ):
        if self.runtime_validation_review_service is None:
            raise RuntimeError("Runtime-validation review service is not configured.")
        return self.runtime_validation_review_service.bulk_resolve_reviews(
            resolved_by=resolved_by,
            resolution_reason=resolution_reason,
            resolution_note=resolution_note,
            status=status,
            owner_team=owner_team,
            assignment_state=assignment_state,
        )

    def assign_runtime_validation_review(
        self,
        *,
        review_id: str,
        assigned_to: str,
        assigned_to_team: str | None,
        assigned_by: str,
        assignment_note: str | None = None,
    ):
        if self.runtime_validation_review_service is None:
            raise RuntimeError("Runtime-validation review service is not configured.")
        return self.runtime_validation_review_service.assign_review(
            review_id=review_id,
            assigned_to=assigned_to,
            assigned_to_team=assigned_to_team,
            assigned_by=assigned_by,
            assignment_note=assignment_note,
        )

    def resolve_runtime_validation_review(
        self,
        *,
        review_id: str,
        resolved_by: str,
        resolution_note: str | None,
        resolution_reason: str,
    ):
        if self.runtime_validation_review_service is None:
            raise RuntimeError("Runtime-validation review service is not configured.")
        return self.runtime_validation_review_service.resolve_review(
            review_id=review_id,
            resolved_by=resolved_by,
            resolution_note=resolution_note,
            resolution_reason=resolution_reason,
        )

    def list_control_plane_alerts(self, limit: int | None = None) -> list[ControlPlaneAlertRecord]:
        if self.control_plane_alert_service is None:
            return self.job_repository.list_control_plane_alerts(limit)
        return self.control_plane_alert_service.list_alerts(limit)

    def acknowledge_control_plane_alert(
        self,
        *,
        alert_id: str,
        acknowledged_by: str,
        acknowledgement_note: str | None = None,
    ) -> ControlPlaneAlertRecord:
        if self.control_plane_alert_service is None:
            return self.job_repository.acknowledge_control_plane_alert(
                alert_id=alert_id,
                acknowledged_at=_utc_now(),
                acknowledged_by=acknowledged_by,
                acknowledgement_note=acknowledgement_note,
            )
        return self.control_plane_alert_service.acknowledge_alert(
            alert_id=alert_id,
            acknowledged_by=acknowledged_by,
            acknowledgement_note=acknowledgement_note,
        )

    def create_control_plane_alert_silence(
        self,
        *,
        created_by: str,
        reason: str,
        duration_minutes: int,
        match_alert_key: str | None = None,
        match_finding_code: str | None = None,
    ):
        if self.control_plane_alert_service is None:
            raise RuntimeError("Control-plane alert service is not configured.")
        return self.control_plane_alert_service.create_silence(
            created_by=created_by,
            reason=reason,
            duration_minutes=duration_minutes,
            match_alert_key=match_alert_key,
            match_finding_code=match_finding_code,
        )

    def list_control_plane_alert_silences(self, *, active_only: bool = False):
        if self.control_plane_alert_service is None:
            return self.job_repository.list_control_plane_alert_silences()
        return self.control_plane_alert_service.list_silences(active_only=active_only)

    def cancel_control_plane_alert_silence(self, *, silence_id: str, cancelled_by: str):
        if self.control_plane_alert_service is None:
            raise RuntimeError("Control-plane alert service is not configured.")
        return self.control_plane_alert_service.cancel_silence(
            silence_id=silence_id,
            cancelled_by=cancelled_by,
        )

    def prune_history_if_due(self) -> dict[str, int]:
        now = monotonic()
        if now - self._last_prune_at < self.history_prune_interval_seconds:
            return {
                "worker_heartbeats_compacted": 0,
                "job_lease_events_compacted": 0,
                "worker_heartbeats_pruned": 0,
                "job_lease_events_pruned": 0,
            }
        return self.prune_history()

    def prune_history(self, *, force: bool = False) -> dict[str, int]:
        now = monotonic()
        if not force and now - self._last_prune_at < self.history_prune_interval_seconds:
            return {
                "worker_heartbeats_compacted": 0,
                "job_lease_events_compacted": 0,
                "worker_heartbeats_pruned": 0,
                "job_lease_events_pruned": 0,
            }
        worker_cutoff = (
            datetime.now(UTC) - timedelta(days=self.worker_history_retention_days)
        ).isoformat()
        lease_cutoff = (
            datetime.now(UTC) - timedelta(days=self.job_lease_history_retention_days)
        ).isoformat()
        worker_heartbeats_compacted = self.job_repository.compact_worker_heartbeats_before(worker_cutoff)
        job_lease_events_compacted = self.job_repository.compact_job_lease_events_before(lease_cutoff)
        self._last_prune_at = now
        result = {
            "worker_heartbeats_compacted": worker_heartbeats_compacted,
            "job_lease_events_compacted": job_lease_events_compacted,
            "worker_heartbeats_pruned": worker_heartbeats_compacted,
            "job_lease_events_pruned": job_lease_events_compacted,
        }
        self._record_maintenance_event(
            event_type="history_pruned",
            changed_by="system",
            reason=None,
            details=result,
        )
        return result

    def submit_audit_trace(self, request_payload: dict) -> JobRecord:
        if self.is_maintenance_mode_active():
            raise RuntimeError("Control-plane maintenance mode is active.")
        if self.deployment_readiness_required_for_job_submission and self.deployment_readiness_service is not None:
            readiness = self.deployment_readiness_service.evaluate()
            if not readiness.ready:
                raise RuntimeError(
                    "Deployment readiness blocks job submission: " + ", ".join(sorted(readiness.blockers))
                )
        return self.job_repository.create(job_type="audit-trace", request_payload=request_payload)

    def submit_collect_audit(self, request_payload: dict) -> JobRecord:
        if self.is_maintenance_mode_active():
            raise RuntimeError("Control-plane maintenance mode is active.")
        if self.deployment_readiness_required_for_job_submission and self.deployment_readiness_service is not None:
            readiness = self.deployment_readiness_service.evaluate()
            if not readiness.ready:
                raise RuntimeError(
                    "Deployment readiness blocks job submission: " + ", ".join(sorted(readiness.blockers))
                )
        return self.job_repository.create(job_type="collect-audit", request_payload=request_payload)

    def list_jobs(self) -> list[JobRecord]:
        return self.job_repository.list()

    def list_workers(self) -> list[WorkerRecord]:
        return self.job_repository.list_workers()

    def list_worker_heartbeats(self, worker_id: str) -> list[WorkerHeartbeatRecord]:
        return self.job_repository.list_worker_heartbeats(worker_id)

    def list_job_lease_events(self, job_id: str) -> list[JobLeaseEventRecord]:
        return self.job_repository.list_job_lease_events(job_id)

    def get_job(self, job_id: str) -> JobRecord:
        return self.job_repository.get(job_id)

    def get_worker(self, worker_id: str) -> WorkerRecord:
        return self.job_repository.get_worker(worker_id)

    def count_jobs_by_status(self, status: str) -> int:
        return self.job_repository.count_by_status(status)

    def list_control_plane_maintenance_events(self, limit: int | None = None) -> list[ControlPlaneMaintenanceEventRecord]:
        return self.job_repository.list_control_plane_maintenance_events(limit=limit)

    def record_maintenance_event(
        self,
        *,
        event_type: str,
        changed_by: str,
        reason: str | None = None,
        details: dict | None = None,
    ) -> ControlPlaneMaintenanceEventRecord:
        return self._record_maintenance_event(
            event_type=event_type,
            changed_by=changed_by,
            reason=reason,
            details=details or {},
        )

    def wait_for_job(self, job_id: str, timeout_seconds: float = 5.0) -> JobRecord:
        deadline = monotonic() + timeout_seconds
        while monotonic() < deadline:
            record = self.job_repository.get(job_id)
            if record.status in {"completed", "failed"}:
                return record
            sleep(0.05)
        return self.job_repository.get(job_id)

    def run_foreground(
        self,
        *,
        max_jobs: int | None = None,
        idle_timeout_seconds: float | None = None,
    ) -> int:
        self.job_repository.requeue_incomplete()
        self._stop_event.clear()
        self._mark_worker_running(current_job_id=None)
        self.prune_history(force=True)
        processed_jobs = 0
        idle_started_at = monotonic()
        try:
            while not self._stop_event.is_set():
                self.prune_history_if_due()
                self.emit_control_plane_alerts_if_due()
                if max_jobs is not None and processed_jobs >= max_jobs:
                    break
                if self.is_maintenance_mode_active():
                    self._heartbeat(current_job_id=None)
                    if idle_timeout_seconds is not None and monotonic() - idle_started_at >= idle_timeout_seconds:
                        break
                    sleep(self.poll_interval_seconds)
                    continue
                processed = self.process_next_job()
                if processed:
                    processed_jobs += 1
                    idle_started_at = monotonic()
                    continue
                self._heartbeat(current_job_id=None)
                if idle_timeout_seconds is not None and monotonic() - idle_started_at >= idle_timeout_seconds:
                    break
                sleep(self.poll_interval_seconds)
        finally:
            self._mark_worker_stopped()
        return processed_jobs

    def process_next_job(self) -> bool:
        expired_jobs = self.job_repository.requeue_expired_leases(_utc_now())
        for expired_job in expired_jobs:
            self._record_lease_event(
                job_id=expired_job.job_id,
                worker_id=expired_job.claimed_by_worker_id,
                event_type="lease_expired_requeued",
                details={
                    "previous_lease_expires_at": expired_job.lease_expires_at,
                },
            )
        record = self.job_repository.claim_next_queued(
            started_at=_utc_now(),
            worker_id=self._worker_id,
            lease_expires_at=self._lease_expires_at(),
        )
        if record is None:
            return False
        self._record_lease_event(
            job_id=record.job_id,
            worker_id=self._worker_id,
            event_type="lease_claimed",
            details={
                "lease_expires_at": record.lease_expires_at,
            },
        )
        self._heartbeat(current_job_id=record.job_id)
        self._execute_claimed_job(record)
        self._heartbeat(current_job_id=None)
        return True

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set():
            self.prune_history_if_due()
            self.emit_control_plane_alerts_if_due()
            if self.is_maintenance_mode_active():
                self._heartbeat(current_job_id=None)
                self._stop_event.wait(self.poll_interval_seconds)
                continue
            processed = self.process_next_job()
            if not processed:
                self._heartbeat(current_job_id=None)
                self._stop_event.wait(self.poll_interval_seconds)
                continue

    def _execute_claimed_job(self, record: JobRecord) -> None:
        renew_stop_event, renew_thread = self._start_lease_renewer(record.job_id)
        try:
            result_payload = self._run_job(record)
        except Exception as exc:
            failed = self.job_repository.get(record.job_id)
            failed.status = "failed"
            failed.error = str(exc)
            failed.completed_at = _utc_now()
            failed.lease_expires_at = None
            self.job_repository.save(failed)
            self._record_lease_event(
                job_id=record.job_id,
                worker_id=self._worker_id,
                event_type="job_failed",
                details={"error": str(exc)},
            )
        else:
            completed = self.job_repository.get(record.job_id)
            completed.status = "completed"
            completed.result_payload = result_payload
            completed.error = None
            completed.completed_at = _utc_now()
            completed.lease_expires_at = None
            self.job_repository.save(completed)
            self._record_lease_event(
                job_id=record.job_id,
                worker_id=self._worker_id,
                event_type="job_completed",
                details={},
            )
        finally:
            renew_stop_event.set()
            renew_thread.join(timeout=1)

    def _run_job(self, record: JobRecord) -> dict:
        if record.job_type == "audit-trace":
            return self._run_audit_trace(record.request_payload)
        if record.job_type == "collect-audit":
            return self._run_collect_audit(record.request_payload)
        raise ValueError(f"Unsupported job type '{record.job_type}'.")

    def _run_audit_trace(self, request_payload: dict) -> dict:
        result = self.audit_service.audit(
            snapshot_id=request_payload.get("snapshot_id"),
            snapshot_path=request_payload.get("snapshot_path"),
            events=load_trace_events(
                request_payload["trace_path"],
                trace_format=request_payload.get("trace_format", "auto"),
            ),
            persist=request_payload.get("persist", True),
            report_dir=request_payload.get("report_dir"),
            audit_id=request_payload.get("audit_id"),
        )
        return self._serialize_audit_result(result)

    def _run_collect_audit(self, request_payload: dict) -> dict:
        program = request_payload["program"]
        observation = self.trace_collection_service.collect(
            TraceCollectionRequest(
                pid=request_payload.get("pid"),
                program_path=program,
                output_path=request_payload.get("output_path"),
                duration_seconds=request_payload.get("duration"),
                max_events=request_payload.get("max_events"),
                command=None if program.endswith(".bt") else ["/bin/sh", program],
                symbol_map_path=request_payload.get("symbol_map_path"),
                context_map_path=request_payload.get("context_map_path"),
            )
        )
        result = self.audit_service.audit(
            snapshot_id=request_payload.get("snapshot_id"),
            snapshot_path=request_payload.get("snapshot_path"),
            events=load_trace_events(
                observation.trace_path,
                trace_format=request_payload.get("trace_format", "bpftrace"),
            ),
            persist=request_payload.get("persist", True),
            report_dir=request_payload.get("report_dir"),
            audit_id=request_payload.get("audit_id"),
        )
        payload = self._serialize_audit_result(result)
        payload.update(
            {
                "trace_path": observation.trace_path,
                "trace_metadata_path": observation.metadata_path,
                "trace_symbol_map_path": observation.symbol_map_path,
                "trace_context_map_path": observation.context_map_path,
                "line_count": observation.line_count,
                "return_code": observation.return_code,
            }
        )
        return payload

    def _serialize_audit_result(self, result) -> dict:
        return {
            "alert_count": len(result.alerts),
            "report_paths": result.report_paths,
            "alerts": [alert.to_dict() for alert in result.alerts],
            "sessions": [session.to_dict() for session in result.sessions],
            "explanation": result.explanation.to_dict(),
            "audit_id": result.record.audit_id if result.record else None,
            "snapshot_id": result.snapshot_record.snapshot_id if result.snapshot_record else None,
            "snapshot_path": result.snapshot_path or "",
        }

    def _heartbeat(self, *, current_job_id: str | None) -> None:
        recorded_at = _utc_now()
        self.job_repository.save_worker(
            WorkerRecord(
                worker_id=self._worker_id,
                mode=self.worker_mode,
                status="running",
                started_at=self._worker_started_at,
                last_heartbeat_at=recorded_at,
                host_name=self._host_name,
                process_id=self._process_id,
                current_job_id=current_job_id,
            )
        )
        self.job_repository.append_worker_heartbeat(
            WorkerHeartbeatRecord(
                heartbeat_id=uuid4().hex[:16],
                worker_id=self._worker_id,
                recorded_at=recorded_at,
                status="running",
                current_job_id=current_job_id,
            )
        )

    def _mark_worker_running(self, *, current_job_id: str | None) -> None:
        self._heartbeat(current_job_id=current_job_id)

    def _mark_worker_stopped(self) -> None:
        recorded_at = _utc_now()
        self.job_repository.save_worker(
            WorkerRecord(
                worker_id=self._worker_id,
                mode=self.worker_mode,
                status="stopped",
                started_at=self._worker_started_at,
                last_heartbeat_at=recorded_at,
                host_name=self._host_name,
                process_id=self._process_id,
                current_job_id=None,
            )
        )
        self.job_repository.append_worker_heartbeat(
            WorkerHeartbeatRecord(
                heartbeat_id=uuid4().hex[:16],
                worker_id=self._worker_id,
                recorded_at=recorded_at,
                status="stopped",
                current_job_id=None,
            )
        )

    def _start_lease_renewer(self, job_id: str) -> tuple[Event, Thread]:
        stop_event = Event()
        thread = Thread(
            target=self._lease_renewal_loop,
            args=(job_id, stop_event),
            daemon=True,
            name=f"lsa-lease-renewer-{job_id}",
        )
        thread.start()
        return stop_event, thread

    def _lease_renewal_loop(self, job_id: str, stop_event: Event) -> None:
        renew_interval = max(self.heartbeat_timeout_seconds / 2, 0.1)
        while not stop_event.wait(renew_interval):
            next_lease_expires_at = self._lease_expires_at()
            renewed = self.job_repository.renew_lease(
                job_id=job_id,
                worker_id=self._worker_id,
                lease_expires_at=next_lease_expires_at,
            )
            if not renewed:
                break
            self._record_lease_event(
                job_id=job_id,
                worker_id=self._worker_id,
                event_type="lease_renewed",
                details={"lease_expires_at": next_lease_expires_at},
            )
            self._heartbeat(current_job_id=job_id)

    def _record_lease_event(
        self,
        *,
        job_id: str,
        worker_id: str | None,
        event_type: str,
        details: dict,
    ) -> None:
        self.job_repository.append_job_lease_event(
            JobLeaseEventRecord(
                event_id=uuid4().hex[:16],
                job_id=job_id,
                worker_id=worker_id,
                event_type=event_type,
                recorded_at=_utc_now(),
                details=details,
            )
        )

    def _record_maintenance_event(
        self,
        *,
        event_type: str,
        changed_by: str,
        reason: str | None,
        details: dict,
    ) -> ControlPlaneMaintenanceEventRecord:
        record = ControlPlaneMaintenanceEventRecord(
            event_id=uuid4().hex[:16],
            recorded_at=_utc_now(),
            event_type=event_type,
            changed_by=changed_by,
            reason=reason,
            details=details,
        )
        self.job_repository.append_control_plane_maintenance_event(record)
        return record

    def _heartbeat_threshold(self) -> str:
        threshold = datetime.now(UTC) - timedelta(seconds=self.heartbeat_timeout_seconds)
        return threshold.isoformat()

    def _lease_expires_at(self) -> str:
        lease_seconds = max(self.heartbeat_timeout_seconds * 2, 5.0)
        expires_at = datetime.now(UTC) + timedelta(seconds=lease_seconds)
        return expires_at.isoformat()


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()
