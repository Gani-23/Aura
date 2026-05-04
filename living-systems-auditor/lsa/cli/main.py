from __future__ import annotations

import argparse
import json
from pathlib import Path

from lsa.core.intent_graph import IntentGraph
from lsa.drift.comparator import DriftComparator
from lsa.drift.ebpf_observer import ObservationResult
from lsa.drift.models import ObservedEvent
from lsa.drift.signal_processor import load_events
from lsa.drift.trace_parser import load_trace_events
from lsa.remediation.llm_client import RuleBasedLLMClient
from lsa.services.audit_service import AuditService
from lsa.services.ingest_service import IngestService
from lsa.services.job_service import JobService
from lsa.services.trace_collection_service import TraceCollectionRequest, TraceCollectionService
from lsa.settings import resolve_workspace_settings
from lsa.storage.files import AuditRepository, JobRepository, SnapshotRepository


settings = resolve_workspace_settings()
graph = IntentGraph()
snapshot_repository = SnapshotRepository(settings, graph=graph)
audit_repository = AuditRepository(settings)
job_repository = JobRepository(settings)
ingest_service = IngestService(graph=graph, snapshot_repository=snapshot_repository)
audit_service = AuditService(
    graph=graph,
    snapshot_repository=snapshot_repository,
    audit_repository=audit_repository,
    drift_comparator=DriftComparator(),
    remediation_client=RuleBasedLLMClient(),
    settings=settings,
)
trace_collection_service = TraceCollectionService(settings=settings)
job_service = JobService(
    job_repository=job_repository,
    audit_service=audit_service,
    trace_collection_service=trace_collection_service,
    worker_mode="standalone",
    heartbeat_timeout_seconds=settings.worker_heartbeat_timeout_seconds,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lsa", description="Living Systems Auditor CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    ingest = subparsers.add_parser("ingest", help="Build an intent graph snapshot from a codebase.")
    ingest.add_argument("repo_path")
    ingest.add_argument("--out", dest="output_path", required=False)
    ingest.add_argument("--no-persist", action="store_true")
    ingest.add_argument("--snapshot-id", required=False)

    audit = subparsers.add_parser("audit", help="Compare observed events against a saved snapshot.")
    audit.add_argument("snapshot_ref")
    audit.add_argument("events_path")
    audit.add_argument("--snapshot-id", action="store_true")
    audit.add_argument("--out-dir", default=None)
    audit.add_argument("--no-persist", action="store_true")
    audit.add_argument("--audit-id", required=False)

    audit_trace = subparsers.add_parser("audit-trace", help="Audit a raw trace file against a snapshot.")
    audit_trace.add_argument("snapshot_ref")
    audit_trace.add_argument("trace_path")
    audit_trace.add_argument("--snapshot-id", action="store_true")
    audit_trace.add_argument("--trace-format", default="auto")
    audit_trace.add_argument("--out-dir", default=None)
    audit_trace.add_argument("--no-persist", action="store_true")
    audit_trace.add_argument("--audit-id", required=False)

    collect_trace = subparsers.add_parser("collect-trace", help="Collect raw trace lines from an observer command.")
    collect_trace.add_argument("pid", type=int)
    collect_trace.add_argument("--program", default="ebpf/network_observer.bt")
    collect_trace.add_argument("--duration", type=float, default=None)
    collect_trace.add_argument("--max-events", type=int, default=None)
    collect_trace.add_argument("--out", required=False)
    collect_trace.add_argument("--symbol-map", required=False)

    collect_audit = subparsers.add_parser(
        "collect-audit",
        help="Collect a trace from a live PID and immediately audit it against a snapshot.",
    )
    collect_audit.add_argument("snapshot_ref")
    collect_audit.add_argument("pid", type=int)
    collect_audit.add_argument("--snapshot-id", action="store_true")
    collect_audit.add_argument("--program", default="ebpf/network_observer.bt")
    collect_audit.add_argument("--duration", type=float, default=None)
    collect_audit.add_argument("--max-events", type=int, default=None)
    collect_audit.add_argument("--trace-format", default="bpftrace")
    collect_audit.add_argument("--out", required=False)
    collect_audit.add_argument("--symbol-map", required=False)
    collect_audit.add_argument("--audit-id", required=False)
    collect_audit.add_argument("--no-persist", action="store_true")

    parse_trace = subparsers.add_parser("parse-trace", help="Convert a trace file into normalized JSON events.")
    parse_trace.add_argument("trace_path")
    parse_trace.add_argument("--trace-format", default="auto")
    parse_trace.add_argument("--out", required=False)

    worker = subparsers.add_parser("worker", help="Run a standalone queue worker for persisted audit jobs.")
    worker.add_argument("--poll-interval", type=float, default=0.1)
    worker.add_argument("--idle-timeout", type=float, default=None)
    worker.add_argument("--max-jobs", type=int, default=None)
    worker.add_argument("--once", action="store_true")

    subparsers.add_parser("list-snapshots", help="List persisted snapshot records.")
    subparsers.add_parser("list-audits", help="List persisted audit records.")
    subparsers.add_parser("list-jobs", help="List persisted job records.")
    subparsers.add_parser("list-workers", help="List persisted worker records.")

    return parser


def run_ingest(
    repo_path: str,
    output_path: str | None,
    *,
    persist: bool,
    snapshot_id: str | None,
) -> int:
    result = ingest_service.ingest(
        repo_path,
        persist=persist,
        output_path=output_path,
        snapshot_id=snapshot_id,
    )
    payload = {
        "node_count": result.snapshot.node_count,
        "edge_count": result.snapshot.edge_count,
    }
    if result.snapshot_path:
        payload["snapshot_path"] = result.snapshot_path
    if result.record:
        payload["snapshot_id"] = result.record.snapshot_id
        payload["created_at"] = result.record.created_at
    print(json.dumps(payload, indent=2))
    return 0


def run_audit(
    snapshot_ref: str,
    events_path: str,
    *,
    snapshot_is_id: bool,
    out_dir: str | None,
    persist: bool,
    audit_id: str | None,
) -> int:
    result = audit_service.audit(
        snapshot_id=snapshot_ref if snapshot_is_id else None,
        snapshot_path=None if snapshot_is_id else snapshot_ref,
        events=[ObservedEvent.from_dict(item.to_dict()) for item in load_events(events_path)],
        persist=persist,
        report_dir=out_dir,
        audit_id=audit_id,
    )
    payload = {
        "alert_count": len(result.alerts),
        "alerts": [alert.to_dict() for alert in result.alerts],
        "report_paths": result.report_paths,
        "snapshot_path": result.snapshot_path,
        "sessions": [session.to_dict() for session in result.sessions],
        "explanation": result.explanation.to_dict(),
    }
    if result.record:
        payload["audit_id"] = result.record.audit_id
    print(json.dumps(payload, indent=2))
    return 0


def run_audit_trace(
    snapshot_ref: str,
    trace_path: str,
    *,
    snapshot_is_id: bool,
    trace_format: str,
    out_dir: str | None,
    persist: bool,
    audit_id: str | None,
) -> int:
    result = audit_service.audit(
        snapshot_id=snapshot_ref if snapshot_is_id else None,
        snapshot_path=None if snapshot_is_id else snapshot_ref,
        events=load_trace_events(trace_path, trace_format=trace_format),
        persist=persist,
        report_dir=out_dir,
        audit_id=audit_id,
    )
    payload = {
        "alert_count": len(result.alerts),
        "alerts": [alert.to_dict() for alert in result.alerts],
        "report_paths": result.report_paths,
        "snapshot_path": result.snapshot_path,
        "sessions": [session.to_dict() for session in result.sessions],
        "explanation": result.explanation.to_dict(),
    }
    if result.record:
        payload["audit_id"] = result.record.audit_id
    print(json.dumps(payload, indent=2))
    return 0


def run_parse_trace(trace_path: str, trace_format: str, output_path: str | None) -> int:
    events = load_trace_events(trace_path, trace_format=trace_format)
    payload = [event.to_dict() for event in events]
    rendered = json.dumps(payload, indent=2)
    if output_path:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    print(rendered)
    return 0


def run_collect_trace(
    pid: int,
    program: str,
    *,
    output_path: str | None,
    duration: float | None,
    max_events: int | None,
    symbol_map_path: str | None = None,
) -> int:
    result = trace_collection_service.collect(
        _build_trace_collection_request(
            pid=pid,
            program=program,
            output_path=output_path,
            duration=duration,
            max_events=max_events,
            symbol_map_path=symbol_map_path,
        )
    )
    _print_observation_result(result)
    return 0


def run_collect_audit(
    snapshot_ref: str,
    pid: int,
    *,
    snapshot_is_id: bool,
    program: str,
    duration: float | None,
    max_events: int | None,
    trace_format: str,
    output_path: str | None,
    persist: bool,
    audit_id: str | None,
    symbol_map_path: str | None = None,
) -> int:
    observation = trace_collection_service.collect(
        _build_trace_collection_request(
            pid=pid,
            program=program,
            output_path=output_path,
            duration=duration,
            max_events=max_events,
            symbol_map_path=symbol_map_path,
        )
    )
    result = audit_service.audit(
        snapshot_id=snapshot_ref if snapshot_is_id else None,
        snapshot_path=None if snapshot_is_id else snapshot_ref,
        events=load_trace_events(observation.trace_path, trace_format=trace_format),
        persist=persist,
        audit_id=audit_id,
    )
    payload = {
        "trace_path": observation.trace_path,
        "trace_metadata_path": observation.metadata_path,
        "trace_symbol_map_path": observation.symbol_map_path,
        "trace_context_map_path": observation.context_map_path,
        "line_count": observation.line_count,
        "alert_count": len(result.alerts),
        "alerts": [alert.to_dict() for alert in result.alerts],
        "report_paths": result.report_paths,
        "sessions": [session.to_dict() for session in result.sessions],
        "explanation": result.explanation.to_dict(),
    }
    if result.record:
        payload["audit_id"] = result.record.audit_id
    print(json.dumps(payload, indent=2))
    return 0


def run_worker(
    *,
    poll_interval: float,
    idle_timeout: float | None,
    max_jobs: int | None,
    once: bool,
) -> int:
    job_service.poll_interval_seconds = poll_interval
    processed_jobs = job_service.run_foreground(
        max_jobs=1 if once else max_jobs,
        idle_timeout_seconds=idle_timeout,
    )
    payload = {
        "worker_mode": "standalone",
        "worker_id": job_service.worker_id(),
        "processed_jobs": processed_jobs,
        "active_workers": job_service.active_worker_count(),
        "queued_jobs": job_service.count_jobs_by_status("queued"),
        "running_jobs": job_service.count_jobs_by_status("running"),
        "completed_jobs": job_service.count_jobs_by_status("completed"),
        "failed_jobs": job_service.count_jobs_by_status("failed"),
    }
    print(json.dumps(payload, indent=2))
    return 0


def _print_observation_result(result: ObservationResult) -> None:
    payload = {
        "command": result.command,
        "trace_path": result.trace_path,
        "trace_metadata_path": result.metadata_path,
        "trace_symbol_map_path": result.symbol_map_path,
        "trace_context_map_path": result.context_map_path,
        "line_count": result.line_count,
        "return_code": result.return_code,
    }
    print(json.dumps(payload, indent=2))


def _build_trace_collection_request(
    *,
    pid: int,
    program: str,
    output_path: str | None,
    duration: float | None,
    max_events: int | None,
    symbol_map_path: str | None,
) -> TraceCollectionRequest:
    program_path = Path(program)
    if program_path.suffix == ".bt":
        return TraceCollectionRequest(
            pid=pid,
            program_path=str(program_path),
            output_path=output_path,
            duration_seconds=duration,
            max_events=max_events,
            symbol_map_path=symbol_map_path,
        )
    return TraceCollectionRequest(
        pid=pid,
        program_path=str(program_path),
        output_path=output_path,
        duration_seconds=duration,
        max_events=max_events,
        command=["/bin/sh", str(program_path)],
        symbol_map_path=symbol_map_path,
    )


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "ingest":
        return run_ingest(
            args.repo_path,
            args.output_path,
            persist=not args.no_persist,
            snapshot_id=args.snapshot_id,
        )
    if args.command == "audit":
        if args.out_dir:
            Path(args.out_dir).mkdir(parents=True, exist_ok=True)
        return run_audit(
            args.snapshot_ref,
            args.events_path,
            snapshot_is_id=args.snapshot_id,
            out_dir=args.out_dir,
            persist=not args.no_persist,
            audit_id=args.audit_id,
        )
    if args.command == "audit-trace":
        if args.out_dir:
            Path(args.out_dir).mkdir(parents=True, exist_ok=True)
        return run_audit_trace(
            args.snapshot_ref,
            args.trace_path,
            snapshot_is_id=args.snapshot_id,
            trace_format=args.trace_format,
            out_dir=args.out_dir,
            persist=not args.no_persist,
            audit_id=args.audit_id,
        )
    if args.command == "collect-trace":
        return run_collect_trace(
            args.pid,
            args.program,
            output_path=args.out,
            duration=args.duration,
            max_events=args.max_events,
            symbol_map_path=args.symbol_map,
        )
    if args.command == "collect-audit":
        return run_collect_audit(
            args.snapshot_ref,
            args.pid,
            snapshot_is_id=args.snapshot_id,
            program=args.program,
            duration=args.duration,
            max_events=args.max_events,
            trace_format=args.trace_format,
            output_path=args.out,
            persist=not args.no_persist,
            audit_id=args.audit_id,
            symbol_map_path=args.symbol_map,
        )
    if args.command == "parse-trace":
        return run_parse_trace(args.trace_path, args.trace_format, args.out)
    if args.command == "worker":
        return run_worker(
            poll_interval=args.poll_interval,
            idle_timeout=args.idle_timeout,
            max_jobs=args.max_jobs,
            once=args.once,
        )
    if args.command == "list-snapshots":
        print(json.dumps([record.to_dict() for record in snapshot_repository.list()], indent=2))
        return 0
    if args.command == "list-audits":
        print(json.dumps([record.to_dict() for record in audit_repository.list()], indent=2))
        return 0
    if args.command == "list-jobs":
        print(json.dumps([record.to_dict() for record in job_repository.list()], indent=2))
        return 0
    if args.command == "list-workers":
        print(json.dumps([record.to_dict() for record in job_repository.list_workers()], indent=2))
        return 0
    parser.error(f"Unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
