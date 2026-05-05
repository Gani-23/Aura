from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from lsa.storage.files import AuditRepository, JobRepository, SnapshotRepository
from lsa.storage.models import (
    AuditRecord,
    ControlPlaneAlertRecord,
    ControlPlaneMaintenanceEventRecord,
    ControlPlaneAlertSilenceRecord,
    ControlPlaneOnCallChangeRequestRecord,
    ControlPlaneOnCallScheduleRecord,
    JobLeaseEventRecord,
    JobLeaseEventRollupRecord,
    JobRecord,
    SnapshotRecord,
    WorkerHeartbeatRecord,
    WorkerHeartbeatRollupRecord,
    WorkerRecord,
)


BUNDLE_VERSION = 1


@dataclass(slots=True)
class ControlPlaneBackupSummary:
    bundle_version: int
    exported_at: str
    environment_name: str
    database_backend: str
    database_url: str
    counts: dict[str, int]
    artifact_counts: dict[str, int]
    path: str
    replace_existing: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "bundle_version": self.bundle_version,
            "exported_at": self.exported_at,
            "environment_name": self.environment_name,
            "database_backend": self.database_backend,
            "database_url": self.database_url,
            "counts": dict(self.counts),
            "artifact_counts": dict(self.artifact_counts),
            "path": self.path,
        }
        if self.replace_existing is not None:
            payload["replace_existing"] = self.replace_existing
        return payload


class ControlPlaneBackupService:
    def __init__(
        self,
        *,
        settings: Any,
        snapshot_repository: SnapshotRepository,
        audit_repository: AuditRepository,
        job_repository: JobRepository,
    ) -> None:
        self.settings = settings
        self.snapshot_repository = snapshot_repository
        self.audit_repository = audit_repository
        self.job_repository = job_repository

    def export_bundle(self, output_path: str) -> ControlPlaneBackupSummary:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        exported_at = datetime.now(UTC).isoformat()
        records = self._collect_records()
        counts = {name: len(items) for name, items in records.items()}
        artifacts = self._collect_artifacts(records)
        artifact_counts = self._count_artifacts(artifacts)
        payload = {
            "bundle_version": BUNDLE_VERSION,
            "exported_at": exported_at,
            "environment_name": self.settings.environment_name,
            "database_backend": self.settings.database_backend,
            "database_url": self.settings.database_url,
            "counts": counts,
            "records": records,
            "artifacts": artifacts,
        }
        target.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return ControlPlaneBackupSummary(
            bundle_version=BUNDLE_VERSION,
            exported_at=exported_at,
            environment_name=self.settings.environment_name,
            database_backend=self.settings.database_backend,
            database_url=self.settings.database_url,
            counts=counts,
            artifact_counts=artifact_counts,
            path=str(target.resolve()),
        )

    def import_bundle(self, input_path: str, *, replace_existing: bool) -> ControlPlaneBackupSummary:
        source = Path(input_path)
        payload = json.loads(source.read_text(encoding="utf-8"))
        self._validate_bundle(payload)
        records = payload["records"]
        counts = {name: len(items) for name, items in records.items()}
        artifacts = payload.get("artifacts", {})
        artifact_counts = self._count_artifacts(artifacts)
        if not replace_existing and any(self._current_counts().values()):
            raise ValueError("Target control plane is not empty. Re-run with replace_existing=True to restore over it.")
        if replace_existing:
            self.job_repository.reset_control_plane()
            self._clear_restorable_artifacts()
        self._apply_records(records, artifacts)
        return ControlPlaneBackupSummary(
            bundle_version=int(payload["bundle_version"]),
            exported_at=payload["exported_at"],
            environment_name=payload.get("environment_name", self.settings.environment_name),
            database_backend=payload.get("database_backend", self.settings.database_backend),
            database_url=payload.get("database_url", self.settings.database_url),
            counts=counts,
            artifact_counts=artifact_counts,
            path=str(source.resolve()),
            replace_existing=replace_existing,
        )

    def _collect_records(self) -> dict[str, list[dict[str, Any]]]:
        return {
            "snapshots": [record.to_dict() for record in self.snapshot_repository.list()],
            "audits": [record.to_dict() for record in self.audit_repository.list()],
            "jobs": [record.to_dict() for record in self.job_repository.list()],
            "workers": [record.to_dict() for record in self.job_repository.list_workers()],
            "worker_heartbeats": [record.to_dict() for record in self.job_repository.list_worker_heartbeats()],
            "worker_heartbeat_rollups": [record.to_dict() for record in self.job_repository.list_worker_heartbeat_rollups()],
            "job_lease_events": [record.to_dict() for record in self.job_repository.list_job_lease_events()],
            "job_lease_event_rollups": [record.to_dict() for record in self.job_repository.list_job_lease_event_rollups()],
            "control_plane_alerts": [record.to_dict() for record in self.job_repository.list_control_plane_alerts()],
            "control_plane_maintenance_events": [
                record.to_dict() for record in self.job_repository.list_control_plane_maintenance_events()
            ],
            "control_plane_alert_silences": [
                record.to_dict() for record in self.job_repository.list_control_plane_alert_silences()
            ],
            "control_plane_oncall_schedules": [
                record.to_dict() for record in self.job_repository.list_control_plane_oncall_schedules()
            ],
            "control_plane_oncall_change_requests": [
                record.to_dict() for record in self.job_repository.list_control_plane_oncall_change_requests()
            ],
        }

    def _current_counts(self) -> dict[str, int]:
        return {name: len(items) for name, items in self._collect_records().items()}

    def _apply_records(self, records: dict[str, list[dict[str, Any]]], artifacts: dict[str, Any]) -> None:
        snapshot_artifacts = dict(artifacts.get("snapshots", {}))
        report_artifacts = dict(artifacts.get("reports", {}))
        for item in records["snapshots"]:
            record = SnapshotRecord.from_dict(item)
            artifact_content = snapshot_artifacts.get(record.snapshot_id)
            if isinstance(artifact_content, str):
                snapshot_path = self.settings.snapshots_dir / f"{record.snapshot_id}.json"
                snapshot_path.parent.mkdir(parents=True, exist_ok=True)
                snapshot_path.write_text(artifact_content, encoding="utf-8")
                record = SnapshotRecord.from_dict({**record.to_dict(), "snapshot_path": str(snapshot_path)})
            self.snapshot_repository.database.upsert_snapshot(record)
        for item in records["audits"]:
            record = AuditRecord.from_dict(item)
            report_files = report_artifacts.get(record.audit_id, [])
            if isinstance(report_files, list) and report_files:
                restored_paths: list[str] = []
                audit_report_dir = self.settings.reports_dir / record.audit_id
                audit_report_dir.mkdir(parents=True, exist_ok=True)
                for report_file in report_files:
                    file_name = str(report_file["name"])
                    destination = audit_report_dir / file_name
                    destination.write_text(str(report_file["content"]), encoding="utf-8")
                    restored_paths.append(str(destination))
                record = AuditRecord.from_dict({**record.to_dict(), "report_paths": restored_paths})
            if record.snapshot_id:
                restored_snapshot_path = self.settings.snapshots_dir / f"{record.snapshot_id}.json"
                if restored_snapshot_path.exists():
                    record = AuditRecord.from_dict(
                        {**record.to_dict(), "snapshot_path": str(restored_snapshot_path)}
                    )
            self.audit_repository.save(record)
        for item in records["jobs"]:
            self.job_repository.save(JobRecord.from_dict(item))
        for item in records["workers"]:
            self.job_repository.save_worker(WorkerRecord.from_dict(item))
        for item in records["worker_heartbeats"]:
            self.job_repository.append_worker_heartbeat(WorkerHeartbeatRecord.from_dict(item))
        for item in records["worker_heartbeat_rollups"]:
            self.job_repository.save_worker_heartbeat_rollup(WorkerHeartbeatRollupRecord.from_dict(item))
        for item in records["job_lease_events"]:
            self.job_repository.append_job_lease_event(JobLeaseEventRecord.from_dict(item))
        for item in records["job_lease_event_rollups"]:
            self.job_repository.save_job_lease_event_rollup(JobLeaseEventRollupRecord.from_dict(item))
        for item in records["control_plane_alerts"]:
            self.job_repository.append_control_plane_alert(ControlPlaneAlertRecord.from_dict(item))
        for item in records["control_plane_maintenance_events"]:
            self.job_repository.append_control_plane_maintenance_event(ControlPlaneMaintenanceEventRecord.from_dict(item))
        for item in records["control_plane_alert_silences"]:
            self.job_repository.append_control_plane_alert_silence(ControlPlaneAlertSilenceRecord.from_dict(item))
        for item in records["control_plane_oncall_schedules"]:
            self.job_repository.append_control_plane_oncall_schedule(ControlPlaneOnCallScheduleRecord.from_dict(item))
        for item in records["control_plane_oncall_change_requests"]:
            self.job_repository.append_control_plane_oncall_change_request(
                ControlPlaneOnCallChangeRequestRecord.from_dict(item)
            )

    def _validate_bundle(self, payload: dict[str, Any]) -> None:
        if int(payload.get("bundle_version", -1)) != BUNDLE_VERSION:
            raise ValueError(f"Unsupported control-plane backup bundle version: {payload.get('bundle_version')}.")
        if not isinstance(payload.get("records"), dict):
            raise ValueError("Control-plane backup bundle is missing a records object.")
        expected_keys = {
            "snapshots",
            "audits",
            "jobs",
            "workers",
            "worker_heartbeats",
            "worker_heartbeat_rollups",
            "job_lease_events",
            "job_lease_event_rollups",
            "control_plane_alerts",
            "control_plane_maintenance_events",
            "control_plane_alert_silences",
            "control_plane_oncall_schedules",
            "control_plane_oncall_change_requests",
        }
        actual_keys = set(payload["records"].keys())
        missing = expected_keys - actual_keys
        if missing:
            raise ValueError(f"Control-plane backup bundle is missing record collections: {sorted(missing)}")

    def _collect_artifacts(self, records: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
        snapshots: dict[str, str] = {}
        for item in records["snapshots"]:
            snapshot_path = Path(item["snapshot_path"])
            if snapshot_path.exists():
                snapshots[item["snapshot_id"]] = snapshot_path.read_text(encoding="utf-8")

        reports: dict[str, list[dict[str, str]]] = {}
        for item in records["audits"]:
            report_files: list[dict[str, str]] = []
            for report_path_str in item.get("report_paths", []):
                report_path = Path(report_path_str)
                if report_path.exists():
                    report_files.append(
                        {
                            "name": report_path.name,
                            "content": report_path.read_text(encoding="utf-8"),
                        }
                    )
            if report_files:
                reports[item["audit_id"]] = report_files
        return {
            "snapshots": snapshots,
            "reports": reports,
        }

    def _count_artifacts(self, artifacts: dict[str, Any]) -> dict[str, int]:
        return {
            "snapshots": len(dict(artifacts.get("snapshots", {}))),
            "reports": sum(len(files) for files in dict(artifacts.get("reports", {})).values()),
        }

    def _clear_restorable_artifacts(self) -> None:
        for root in (self.settings.snapshots_dir, self.settings.reports_dir):
            if not root.exists():
                continue
            for path in sorted(root.rglob("*"), reverse=True):
                if path.is_file():
                    path.unlink()
                elif path.is_dir():
                    path.rmdir()
