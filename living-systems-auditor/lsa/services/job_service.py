from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from threading import Event, Lock, Thread
from time import monotonic, sleep
from uuid import uuid4

from lsa.drift.trace_parser import load_trace_events
from lsa.services.audit_service import AuditService
from lsa.services.trace_collection_service import TraceCollectionRequest, TraceCollectionService
from lsa.storage.files import JobRepository
from lsa.storage.models import JobRecord, WorkerRecord


@dataclass(slots=True)
class JobService:
    job_repository: JobRepository
    audit_service: AuditService
    trace_collection_service: TraceCollectionService
    worker_mode: str = "standalone"
    poll_interval_seconds: float = 0.1
    heartbeat_timeout_seconds: float = 5.0
    _worker_thread: Thread | None = field(init=False, default=None)
    _stop_event: Event = field(init=False, default_factory=Event)
    _lock: Lock = field(init=False, default_factory=Lock)
    _worker_id: str = field(init=False)
    _worker_started_at: str = field(init=False)
    _host_name: str = field(init=False)
    _process_id: int = field(init=False)

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

    def submit_audit_trace(self, request_payload: dict) -> JobRecord:
        return self.job_repository.create(job_type="audit-trace", request_payload=request_payload)

    def submit_collect_audit(self, request_payload: dict) -> JobRecord:
        return self.job_repository.create(job_type="collect-audit", request_payload=request_payload)

    def list_jobs(self) -> list[JobRecord]:
        return self.job_repository.list()

    def list_workers(self) -> list[WorkerRecord]:
        return self.job_repository.list_workers()

    def get_job(self, job_id: str) -> JobRecord:
        return self.job_repository.get(job_id)

    def get_worker(self, worker_id: str) -> WorkerRecord:
        return self.job_repository.get_worker(worker_id)

    def count_jobs_by_status(self, status: str) -> int:
        return self.job_repository.count_by_status(status)

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
        processed_jobs = 0
        idle_started_at = monotonic()
        try:
            while not self._stop_event.is_set():
                if max_jobs is not None and processed_jobs >= max_jobs:
                    break
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
        record = self.job_repository.claim_next_queued(
            started_at=_utc_now(),
            worker_id=self._worker_id,
            lease_expires_at=self._lease_expires_at(),
        )
        if record is None:
            return False
        self._heartbeat(current_job_id=record.job_id)
        self._execute_claimed_job(record)
        self._heartbeat(current_job_id=None)
        return True

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set():
            processed = self.process_next_job()
            if not processed:
                self._heartbeat(current_job_id=None)
                self._stop_event.wait(self.poll_interval_seconds)
                continue

    def _execute_claimed_job(self, record: JobRecord) -> None:
        try:
            result_payload = self._run_job(record)
        except Exception as exc:
            failed = self.job_repository.get(record.job_id)
            failed.status = "failed"
            failed.error = str(exc)
            failed.completed_at = _utc_now()
            failed.lease_expires_at = None
            self.job_repository.save(failed)
        else:
            completed = self.job_repository.get(record.job_id)
            completed.status = "completed"
            completed.result_payload = result_payload
            completed.error = None
            completed.completed_at = _utc_now()
            completed.lease_expires_at = None
            self.job_repository.save(completed)

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
        self.job_repository.save_worker(
            WorkerRecord(
                worker_id=self._worker_id,
                mode=self.worker_mode,
                status="running",
                started_at=self._worker_started_at,
                last_heartbeat_at=_utc_now(),
                host_name=self._host_name,
                process_id=self._process_id,
                current_job_id=current_job_id,
            )
        )

    def _mark_worker_running(self, *, current_job_id: str | None) -> None:
        self._heartbeat(current_job_id=current_job_id)

    def _mark_worker_stopped(self) -> None:
        self.job_repository.save_worker(
            WorkerRecord(
                worker_id=self._worker_id,
                mode=self.worker_mode,
                status="stopped",
                started_at=self._worker_started_at,
                last_heartbeat_at=_utc_now(),
                host_name=self._host_name,
                process_id=self._process_id,
                current_job_id=None,
            )
        )

    def _heartbeat_threshold(self) -> str:
        threshold = datetime.now(UTC) - timedelta(seconds=self.heartbeat_timeout_seconds)
        return threshold.isoformat()

    def _lease_expires_at(self) -> str:
        lease_seconds = max(self.heartbeat_timeout_seconds * 2, 5.0)
        expires_at = datetime.now(UTC) + timedelta(seconds=lease_seconds)
        return expires_at.isoformat()


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()
