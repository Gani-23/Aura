from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
import shutil as shell_shutil
from typing import Any

from lsa.storage.control_plane_schema import (
    control_plane_schema_contract,
    postgres_control_plane_schema_script,
)


POSTGRES_BOOTSTRAP_VERSION = 1


@dataclass(slots=True)
class PostgresBootstrapPackageSummary:
    package_version: int
    generated_from_cutover_bundle: str
    generated_from_backup_bundle: str
    output_dir: str
    schema_sql_path: str
    data_sql_path: str
    manifest_path: str
    artifact_root: str
    snapshot_artifact_count: int
    report_artifact_count: int
    table_counts: dict[str, int]
    file_checksums: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_version": self.package_version,
            "generated_from_cutover_bundle": self.generated_from_cutover_bundle,
            "generated_from_backup_bundle": self.generated_from_backup_bundle,
            "output_dir": self.output_dir,
            "schema_sql_path": self.schema_sql_path,
            "data_sql_path": self.data_sql_path,
            "manifest_path": self.manifest_path,
            "artifact_root": self.artifact_root,
            "snapshot_artifact_count": self.snapshot_artifact_count,
            "report_artifact_count": self.report_artifact_count,
            "table_counts": dict(self.table_counts),
            "file_checksums": dict(self.file_checksums),
        }


@dataclass(slots=True)
class PostgresBootstrapPackageInspection:
    package_version: int
    manifest_path: str
    output_dir: str
    target_backend: str | None
    file_checksums: dict[str, str]
    files_present: list[str]
    missing_files: list[str]
    checksum_mismatches: list[str]
    table_counts: dict[str, int]
    artifact_counts: dict[str, int]

    @property
    def valid(self) -> bool:
        return not self.missing_files and not self.checksum_mismatches

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_version": self.package_version,
            "manifest_path": self.manifest_path,
            "output_dir": self.output_dir,
            "target_backend": self.target_backend,
            "file_checksums": dict(self.file_checksums),
            "files_present": list(self.files_present),
            "missing_files": list(self.missing_files),
            "checksum_mismatches": list(self.checksum_mismatches),
            "table_counts": dict(self.table_counts),
            "artifact_counts": dict(self.artifact_counts),
            "valid": self.valid,
        }


@dataclass(slots=True)
class PostgresBootstrapExecutionPlan:
    package_dir: str
    target_database_url: str
    psql_executable: str
    artifact_target_root: str | None
    commands: list[list[str]]
    copy_artifacts: bool
    valid_package: bool
    blockers: list[str]

    @property
    def executable(self) -> bool:
        return not self.blockers

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_dir": self.package_dir,
            "target_database_url": self.target_database_url,
            "psql_executable": self.psql_executable,
            "artifact_target_root": self.artifact_target_root,
            "commands": [list(command) for command in self.commands],
            "copy_artifacts": self.copy_artifacts,
            "valid_package": self.valid_package,
            "blockers": list(self.blockers),
            "executable": self.executable,
        }


@dataclass(slots=True)
class PostgresBootstrapExecutionResult:
    package_dir: str
    target_database_url: str
    psql_executable: str
    artifact_target_root: str | None
    dry_run: bool
    executed_commands: list[list[str]]
    copied_artifacts: bool
    verification_passed: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_dir": self.package_dir,
            "target_database_url": self.target_database_url,
            "psql_executable": self.psql_executable,
            "artifact_target_root": self.artifact_target_root,
            "dry_run": self.dry_run,
            "executed_commands": [list(command) for command in self.executed_commands],
            "copied_artifacts": self.copied_artifacts,
            "verification_passed": self.verification_passed,
        }


class PostgresBootstrapService:
    def generate_from_cutover_bundle(self, *, cutover_bundle_path: str, output_dir: str) -> PostgresBootstrapPackageSummary:
        cutover_path = Path(cutover_bundle_path)
        cutover_payload = json.loads(cutover_path.read_text(encoding="utf-8"))
        maintenance_workflow = cutover_payload["maintenance_workflow"]
        backup_bundle_path = Path(maintenance_workflow["backup_path"])
        backup_payload = json.loads(backup_bundle_path.read_text(encoding="utf-8"))
        records = dict(backup_payload["records"])
        artifacts = dict(backup_payload.get("artifacts", {}))

        target_dir = Path(output_dir)
        if target_dir.exists():
            shutil.rmtree(target_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        artifacts_dir = target_dir / "artifacts"
        snapshots_dir = artifacts_dir / "snapshots"
        reports_dir = artifacts_dir / "reports"
        snapshots_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)

        snapshot_count = self._materialize_snapshot_artifacts(records, artifacts, snapshots_dir)
        report_count = self._materialize_report_artifacts(records, artifacts, reports_dir)
        normalized_records = self._normalize_record_paths(records)

        schema_sql_path = target_dir / "schema.sql"
        data_sql_path = target_dir / "data.sql"
        apply_script_path = target_dir / "apply.sh"
        verify_sql_path = target_dir / "verify.sql"
        manifest_path = target_dir / "manifest.json"

        schema_sql_path.write_text(self._build_schema_sql(), encoding="utf-8")
        data_sql_path.write_text(
            self._build_data_sql(
                records=normalized_records,
                schema_status=maintenance_workflow["schema_status"],
            ),
            encoding="utf-8",
        )
        verify_sql_path.write_text(
            self._build_verify_sql(
                table_counts={name: len(items) for name, items in normalized_records.items()},
                schema_status=maintenance_workflow["schema_status"],
            ),
            encoding="utf-8",
        )
        apply_script_path.write_text(self._build_apply_script(), encoding="utf-8")
        apply_script_path.chmod(0o755)

        file_checksums = self._collect_file_checksums(target_dir)
        manifest = {
            "package_version": POSTGRES_BOOTSTRAP_VERSION,
            "source_cutover_bundle": str(cutover_path.resolve()),
            "source_backup_bundle": str(backup_bundle_path.resolve()),
            "target_database": cutover_payload["target"],
            "schema_contract": control_plane_schema_contract(),
            "schema_status": maintenance_workflow["schema_status"],
            "table_counts": {name: len(items) for name, items in normalized_records.items()},
            "artifact_counts": {
                "snapshots": snapshot_count,
                "reports": report_count,
            },
            "artifact_root": "artifacts",
            "file_checksums": file_checksums,
            "import_order": [
                "set TARGET_DATABASE_URL for the destination Postgres instance",
                "optionally set ARTIFACT_TARGET_ROOT for snapshot/report materialization",
                "./apply.sh",
            ],
        }
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

        return PostgresBootstrapPackageSummary(
            package_version=POSTGRES_BOOTSTRAP_VERSION,
            generated_from_cutover_bundle=str(cutover_path.resolve()),
            generated_from_backup_bundle=str(backup_bundle_path.resolve()),
            output_dir=str(target_dir.resolve()),
            schema_sql_path=str(schema_sql_path.resolve()),
            data_sql_path=str(data_sql_path.resolve()),
            manifest_path=str(manifest_path.resolve()),
            artifact_root=str(artifacts_dir.resolve()),
            snapshot_artifact_count=snapshot_count,
            report_artifact_count=report_count,
            table_counts={name: len(items) for name, items in normalized_records.items()},
            file_checksums=file_checksums,
        )

    def inspect_package(self, *, package_dir: str) -> PostgresBootstrapPackageInspection:
        target_dir = Path(package_dir)
        manifest_path = target_dir / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected_checksums = dict(manifest.get("file_checksums", {}))
        files_present: list[str] = []
        missing_files: list[str] = []
        checksum_mismatches: list[str] = []

        for relative_path, expected_checksum in sorted(expected_checksums.items()):
            file_path = target_dir / relative_path
            if not file_path.exists():
                missing_files.append(relative_path)
                continue
            files_present.append(relative_path)
            actual_checksum = self._sha256_file(file_path)
            if actual_checksum != expected_checksum:
                checksum_mismatches.append(relative_path)

        return PostgresBootstrapPackageInspection(
            package_version=int(manifest["package_version"]),
            manifest_path=str(manifest_path.resolve()),
            output_dir=str(target_dir.resolve()),
            target_backend=str(manifest.get("target_database", {}).get("backend")) if manifest.get("target_database") else None,
            file_checksums=expected_checksums,
            files_present=files_present,
            missing_files=missing_files,
            checksum_mismatches=checksum_mismatches,
            table_counts=dict(manifest.get("table_counts", {})),
            artifact_counts=dict(manifest.get("artifact_counts", {})),
        )

    def build_execution_plan(
        self,
        *,
        package_dir: str,
        target_database_url: str,
        artifact_target_root: str | None = None,
        psql_executable: str = "psql",
    ) -> PostgresBootstrapExecutionPlan:
        target_dir = Path(package_dir)
        inspection = self.inspect_package(package_dir=package_dir)
        blockers: list[str] = []
        if not inspection.valid:
            blockers.append("invalid_package")
        if not self._resolve_executable(psql_executable):
            blockers.append("psql_not_found")
        commands = [
            [psql_executable, target_database_url, "-v", "ON_ERROR_STOP=1", "-f", str(target_dir / "schema.sql")],
            [psql_executable, target_database_url, "-v", "ON_ERROR_STOP=1", "-f", str(target_dir / "data.sql")],
            [psql_executable, target_database_url, "-v", "ON_ERROR_STOP=1", "-f", str(target_dir / "verify.sql")],
        ]
        return PostgresBootstrapExecutionPlan(
            package_dir=str(target_dir.resolve()),
            target_database_url=target_database_url,
            psql_executable=psql_executable,
            artifact_target_root=artifact_target_root,
            commands=commands,
            copy_artifacts=artifact_target_root is not None,
            valid_package=inspection.valid,
            blockers=blockers,
        )

    def execute_package(
        self,
        *,
        package_dir: str,
        target_database_url: str,
        artifact_target_root: str | None = None,
        psql_executable: str = "psql",
        dry_run: bool = False,
    ) -> PostgresBootstrapExecutionResult:
        plan = self.build_execution_plan(
            package_dir=package_dir,
            target_database_url=target_database_url,
            artifact_target_root=artifact_target_root,
            psql_executable=psql_executable,
        )
        effective_blockers = list(plan.blockers)
        if dry_run:
            effective_blockers = [blocker for blocker in effective_blockers if blocker != "psql_not_found"]
        if effective_blockers:
            raise ValueError("Postgres bootstrap execution blocked: " + ", ".join(sorted(effective_blockers)))
        package_path = Path(package_dir)
        executed_commands: list[list[str]] = []
        copied_artifacts = False
        if dry_run:
            return PostgresBootstrapExecutionResult(
                package_dir=plan.package_dir,
                target_database_url=target_database_url,
                psql_executable=psql_executable,
                artifact_target_root=artifact_target_root,
                dry_run=True,
                executed_commands=plan.commands,
                copied_artifacts=plan.copy_artifacts,
                verification_passed=False,
            )

        for index, command in enumerate(plan.commands):
            subprocess.run(command, check=True)
            executed_commands.append(list(command))
            if index == 0 and artifact_target_root is not None:
                target_root = Path(artifact_target_root)
                target_root.mkdir(parents=True, exist_ok=True)
                self._copy_tree(package_path / "artifacts", target_root)
                copied_artifacts = True

        return PostgresBootstrapExecutionResult(
            package_dir=plan.package_dir,
            target_database_url=target_database_url,
            psql_executable=psql_executable,
            artifact_target_root=artifact_target_root,
            dry_run=False,
            executed_commands=executed_commands,
            copied_artifacts=copied_artifacts,
            verification_passed=True,
        )

    def _materialize_snapshot_artifacts(
        self,
        records: dict[str, list[dict[str, Any]]],
        artifacts: dict[str, Any],
        output_dir: Path,
    ) -> int:
        snapshot_artifacts = dict(artifacts.get("snapshots", {}))
        written = 0
        for item in records.get("snapshots", []):
            content = snapshot_artifacts.get(item["snapshot_id"])
            if not isinstance(content, str):
                continue
            destination = output_dir / f"{item['snapshot_id']}.json"
            destination.write_text(content, encoding="utf-8")
            written += 1
        return written

    def _materialize_report_artifacts(
        self,
        records: dict[str, list[dict[str, Any]]],
        artifacts: dict[str, Any],
        output_dir: Path,
    ) -> int:
        report_artifacts = dict(artifacts.get("reports", {}))
        written = 0
        for item in records.get("audits", []):
            report_files = report_artifacts.get(item["audit_id"], [])
            if not isinstance(report_files, list):
                continue
            audit_dir = output_dir / item["audit_id"]
            audit_dir.mkdir(parents=True, exist_ok=True)
            for report_file in report_files:
                destination = audit_dir / str(report_file["name"])
                destination.write_text(str(report_file["content"]), encoding="utf-8")
                written += 1
        return written

    def _normalize_record_paths(self, records: dict[str, list[dict[str, Any]]]) -> dict[str, list[dict[str, Any]]]:
        normalized = {name: [dict(item) for item in items] for name, items in records.items()}
        for item in normalized.get("snapshots", []):
            item["snapshot_path"] = f"artifacts/snapshots/{item['snapshot_id']}.json"
        for item in normalized.get("audits", []):
            audit_id = item["audit_id"]
            report_paths = []
            for report_path in item.get("report_paths", []):
                report_paths.append(f"artifacts/reports/{audit_id}/{Path(report_path).name}")
            item["report_paths"] = report_paths
            snapshot_id = item.get("snapshot_id")
            if snapshot_id:
                item["snapshot_path"] = f"artifacts/snapshots/{snapshot_id}.json"
        return normalized

    def _collect_file_checksums(self, target_dir: Path) -> dict[str, str]:
        checksums: dict[str, str] = {}
        for file_path in sorted(path for path in target_dir.rglob("*") if path.is_file() and path.name != "manifest.json"):
            relative_path = file_path.relative_to(target_dir).as_posix()
            checksums[relative_path] = self._sha256_file(file_path)
        return checksums

    def _sha256_file(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(65536)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()

    def _resolve_executable(self, executable: str) -> str | None:
        executable_path = Path(executable)
        if executable_path.is_absolute():
            return str(executable_path) if executable_path.exists() else None
        return shell_shutil.which(executable)

    def _copy_tree(self, source_dir: Path, target_dir: Path) -> None:
        if not source_dir.exists():
            return
        for source_path in source_dir.rglob("*"):
            relative_path = source_path.relative_to(source_dir)
            destination = target_dir / relative_path
            if source_path.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path, destination)

    def _build_schema_sql(self) -> str:
        return postgres_control_plane_schema_script()

    def _build_apply_script(self) -> str:
        return """#!/usr/bin/env sh
set -eu

PACKAGE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

if [ "${1:-}" = "--help" ]; then
  cat <<'EOF'
Usage:
  TARGET_DATABASE_URL=postgresql://... ./apply.sh

Optional:
  ARTIFACT_TARGET_ROOT=/path/to/runtime-artifacts ./apply.sh

The script applies schema.sql and data.sql through psql, optionally copies the
artifacts tree into ARTIFACT_TARGET_ROOT, and then runs verify.sql.
EOF
  exit 0
fi

: "${TARGET_DATABASE_URL:?Set TARGET_DATABASE_URL to the destination Postgres URL before running apply.sh.}"

echo "Applying schema.sql"
psql "$TARGET_DATABASE_URL" -v ON_ERROR_STOP=1 -f "$PACKAGE_DIR/schema.sql"

if [ -n "${ARTIFACT_TARGET_ROOT:-}" ]; then
  echo "Copying artifacts to $ARTIFACT_TARGET_ROOT"
  mkdir -p "$ARTIFACT_TARGET_ROOT"
  cp -R "$PACKAGE_DIR/artifacts/." "$ARTIFACT_TARGET_ROOT/"
else
  echo "ARTIFACT_TARGET_ROOT not set; leaving artifacts in package directory."
fi

echo "Applying data.sql"
psql "$TARGET_DATABASE_URL" -v ON_ERROR_STOP=1 -f "$PACKAGE_DIR/data.sql"

echo "Running verify.sql"
psql "$TARGET_DATABASE_URL" -v ON_ERROR_STOP=1 -f "$PACKAGE_DIR/verify.sql"
"""

    def _build_verify_sql(self, *, table_counts: dict[str, int], schema_status: dict[str, Any]) -> str:
        statements = ["BEGIN;"]
        schema_version = int(schema_status["schema_version"])
        statements.extend(
            [
                "DO $$",
                "DECLARE",
                "  actual_count BIGINT;",
                "  actual_schema_version TEXT;",
                "BEGIN",
                "  SELECT metadata_value INTO actual_schema_version",
                "  FROM control_plane_schema_metadata",
                "  WHERE metadata_key = 'schema_version';",
                f"  IF actual_schema_version IS DISTINCT FROM '{schema_version}' THEN",
                f"    RAISE EXCEPTION 'Expected schema_version {schema_version}, found %', actual_schema_version;",
                "  END IF;",
            ]
        )
        for table_name, expected_count in sorted(table_counts.items()):
            statements.extend(
                [
                    f"  SELECT COUNT(*) INTO actual_count FROM {table_name};",
                    f"  IF actual_count <> {int(expected_count)} THEN",
                    f"    RAISE EXCEPTION 'Expected {int(expected_count)} rows in {table_name}, found %', actual_count;",
                    "  END IF;",
                ]
            )
        statements.extend(
            [
                "END $$;",
                "COMMIT;",
                "",
            ]
        )
        return "\n".join(statements)

    def _build_data_sql(self, *, records: dict[str, list[dict[str, Any]]], schema_status: dict[str, Any]) -> str:
        lines = ["BEGIN;"]
        schema_version = int(schema_status["schema_version"])
        lines.append(
            "INSERT INTO control_plane_schema_metadata (metadata_key, metadata_value) VALUES "
            f"('schema_version', '{schema_version}') "
            "ON CONFLICT (metadata_key) DO UPDATE SET metadata_value = EXCLUDED.metadata_value;"
        )
        for migration in schema_status.get("migrations", []):
            lines.append(
                "INSERT INTO control_plane_schema_migrations (migration_id, schema_version, applied_at, description) VALUES "
                f"({self._text(migration['migration_id'])}, {int(migration['schema_version'])}, {self._text(migration['applied_at'])}, {self._text(migration['description'])}) "
                "ON CONFLICT (migration_id) DO NOTHING;"
            )

        for item in records.get("snapshots", []):
            lines.append(
                "INSERT INTO snapshots (snapshot_id, created_at, repo_path, node_count, edge_count, snapshot_path) VALUES "
                f"({self._text(item['snapshot_id'])}, {self._text(item['created_at'])}, {self._text(item['repo_path'])}, {int(item['node_count'])}, {int(item['edge_count'])}, {self._text(item['snapshot_path'])});"
            )
        for item in records.get("audits", []):
            lines.append(
                "INSERT INTO audits (audit_id, created_at, snapshot_id, snapshot_path, alert_count, report_paths_json, alerts_json, events_json, sessions_json, explanation_json) VALUES "
                f"({self._text(item['audit_id'])}, {self._text(item['created_at'])}, {self._nullable_text(item.get('snapshot_id'))}, {self._text(item['snapshot_path'])}, {int(item['alert_count'])}, {self._json(item.get('report_paths', []))}, {self._json(item.get('alerts', []))}, {self._json(item.get('events', []))}, {self._json(item.get('sessions', []))}, {self._json(item.get('explanation', {}))});"
            )
        for item in records.get("jobs", []):
            lines.append(
                "INSERT INTO jobs (job_id, created_at, job_type, status, request_payload_json, result_payload_json, error, started_at, completed_at, claimed_by_worker_id, lease_expires_at) VALUES "
                f"({self._text(item['job_id'])}, {self._text(item['created_at'])}, {self._text(item['job_type'])}, {self._text(item['status'])}, {self._json(item.get('request_payload', {}))}, {self._json(item.get('result_payload', {}))}, {self._nullable_text(item.get('error'))}, {self._nullable_text(item.get('started_at'))}, {self._nullable_text(item.get('completed_at'))}, {self._nullable_text(item.get('claimed_by_worker_id'))}, {self._nullable_text(item.get('lease_expires_at'))});"
            )
        for item in records.get("workers", []):
            lines.append(
                "INSERT INTO workers (worker_id, mode, status, started_at, last_heartbeat_at, host_name, process_id, current_job_id) VALUES "
                f"({self._text(item['worker_id'])}, {self._text(item['mode'])}, {self._text(item['status'])}, {self._text(item['started_at'])}, {self._text(item['last_heartbeat_at'])}, {self._text(item['host_name'])}, {int(item['process_id'])}, {self._nullable_text(item.get('current_job_id'))});"
            )
        for item in records.get("worker_heartbeats", []):
            lines.append(
                "INSERT INTO worker_heartbeats (heartbeat_id, worker_id, recorded_at, status, current_job_id) VALUES "
                f"({self._text(item['heartbeat_id'])}, {self._text(item['worker_id'])}, {self._text(item['recorded_at'])}, {self._text(item['status'])}, {self._nullable_text(item.get('current_job_id'))});"
            )
        for item in records.get("worker_heartbeat_rollups", []):
            lines.append(
                "INSERT INTO worker_heartbeat_rollups (day_bucket, worker_id, status, current_job_id, event_count) VALUES "
                f"({self._text(item['day_bucket'])}, {self._text(item['worker_id'])}, {self._text(item['status'])}, {self._nullable_text(item.get('current_job_id'))}, {int(item['event_count'])});"
            )
        for item in records.get("job_lease_events", []):
            lines.append(
                "INSERT INTO job_lease_events (event_id, job_id, worker_id, event_type, recorded_at, details_json) VALUES "
                f"({self._text(item['event_id'])}, {self._text(item['job_id'])}, {self._nullable_text(item.get('worker_id'))}, {self._text(item['event_type'])}, {self._text(item['recorded_at'])}, {self._json(item.get('details', {}))});"
            )
        for item in records.get("job_lease_event_rollups", []):
            lines.append(
                "INSERT INTO job_lease_event_rollups (day_bucket, job_id, worker_id, event_type, event_count) VALUES "
                f"({self._text(item['day_bucket'])}, {self._text(item['job_id'])}, {self._nullable_text(item.get('worker_id'))}, {self._text(item['event_type'])}, {int(item['event_count'])});"
            )
        for item in records.get("control_plane_maintenance_events", []):
            lines.append(
                "INSERT INTO control_plane_maintenance_events (event_id, recorded_at, event_type, changed_by, reason, details_json) VALUES "
                f"({self._text(item['event_id'])}, {self._text(item['recorded_at'])}, {self._text(item['event_type'])}, {self._text(item['changed_by'])}, {self._nullable_text(item.get('reason'))}, {self._json(item.get('details', {}))});"
            )
        for item in records.get("control_plane_alerts", []):
            lines.append(
                "INSERT INTO control_plane_alerts (alert_id, created_at, alert_key, status, severity, summary, finding_codes_json, delivery_state, payload_json, error, acknowledged_at, acknowledged_by, acknowledgement_note) VALUES "
                f"({self._text(item['alert_id'])}, {self._text(item['created_at'])}, {self._text(item['alert_key'])}, {self._text(item['status'])}, {self._text(item['severity'])}, {self._text(item['summary'])}, {self._json(item.get('finding_codes', []))}, {self._text(item['delivery_state'])}, {self._json(item.get('payload', {}))}, {self._nullable_text(item.get('error'))}, {self._nullable_text(item.get('acknowledged_at'))}, {self._nullable_text(item.get('acknowledged_by'))}, {self._nullable_text(item.get('acknowledgement_note'))});"
            )
        for item in records.get("control_plane_alert_silences", []):
            lines.append(
                "INSERT INTO control_plane_alert_silences (silence_id, created_at, created_by, reason, match_alert_key, match_finding_code, starts_at, expires_at, cancelled_at, cancelled_by) VALUES "
                f"({self._text(item['silence_id'])}, {self._text(item['created_at'])}, {self._text(item['created_by'])}, {self._text(item['reason'])}, {self._nullable_text(item.get('match_alert_key'))}, {self._nullable_text(item.get('match_finding_code'))}, {self._nullable_text(item.get('starts_at'))}, {self._nullable_text(item.get('expires_at'))}, {self._nullable_text(item.get('cancelled_at'))}, {self._nullable_text(item.get('cancelled_by'))});"
            )
        for item in records.get("control_plane_oncall_schedules", []):
            lines.append(
                "INSERT INTO control_plane_oncall_schedules (schedule_id, created_at, created_by, team_name, timezone_name, environment_name, created_by_team, created_by_role, change_reason, approved_by, approved_by_team, approved_by_role, approved_at, approval_note, weekdays_json, start_time, end_time, priority, rotation_name, effective_start_date, effective_end_date, webhook_url, escalation_webhook_url, cancelled_at, cancelled_by) VALUES "
                f"({self._text(item['schedule_id'])}, {self._text(item['created_at'])}, {self._text(item['created_by'])}, {self._text(item['team_name'])}, {self._text(item['timezone_name'])}, {self._text(item.get('environment_name', 'default'))}, {self._nullable_text(item.get('created_by_team'))}, {self._nullable_text(item.get('created_by_role'))}, {self._nullable_text(item.get('change_reason'))}, {self._nullable_text(item.get('approved_by'))}, {self._nullable_text(item.get('approved_by_team'))}, {self._nullable_text(item.get('approved_by_role'))}, {self._nullable_text(item.get('approved_at'))}, {self._nullable_text(item.get('approval_note'))}, {self._json(item.get('weekdays', []))}, {self._text(item.get('start_time', '00:00'))}, {self._text(item.get('end_time', '23:59'))}, {int(item.get('priority', 100))}, {self._nullable_text(item.get('rotation_name'))}, {self._nullable_text(item.get('effective_start_date'))}, {self._nullable_text(item.get('effective_end_date'))}, {self._nullable_text(item.get('webhook_url'))}, {self._nullable_text(item.get('escalation_webhook_url'))}, {self._nullable_text(item.get('cancelled_at'))}, {self._nullable_text(item.get('cancelled_by'))});"
            )
        for item in records.get("control_plane_oncall_change_requests", []):
            lines.append(
                "INSERT INTO control_plane_oncall_change_requests (request_id, created_at, created_by, team_name, timezone_name, status, environment_name, created_by_team, created_by_role, change_reason, review_required, review_reasons_json, weekdays_json, start_time, end_time, priority, rotation_name, effective_start_date, effective_end_date, webhook_url, escalation_webhook_url, assigned_to, assigned_to_team, assigned_at, assigned_by, assignment_note, decision_at, decided_by, decided_by_team, decided_by_role, decision_note, applied_schedule_id) VALUES "
                f"({self._text(item['request_id'])}, {self._text(item['created_at'])}, {self._text(item['created_by'])}, {self._text(item['team_name'])}, {self._text(item['timezone_name'])}, {self._text(item['status'])}, {self._text(item.get('environment_name', 'default'))}, {self._nullable_text(item.get('created_by_team'))}, {self._nullable_text(item.get('created_by_role'))}, {self._nullable_text(item.get('change_reason'))}, {self._bool(item.get('review_required', False))}, {self._json(item.get('review_reasons', []))}, {self._json(item.get('weekdays', []))}, {self._text(item.get('start_time', '00:00'))}, {self._text(item.get('end_time', '23:59'))}, {int(item.get('priority', 100))}, {self._nullable_text(item.get('rotation_name'))}, {self._nullable_text(item.get('effective_start_date'))}, {self._nullable_text(item.get('effective_end_date'))}, {self._nullable_text(item.get('webhook_url'))}, {self._nullable_text(item.get('escalation_webhook_url'))}, {self._nullable_text(item.get('assigned_to'))}, {self._nullable_text(item.get('assigned_to_team'))}, {self._nullable_text(item.get('assigned_at'))}, {self._nullable_text(item.get('assigned_by'))}, {self._nullable_text(item.get('assignment_note'))}, {self._nullable_text(item.get('decision_at'))}, {self._nullable_text(item.get('decided_by'))}, {self._nullable_text(item.get('decided_by_team'))}, {self._nullable_text(item.get('decided_by_role'))}, {self._nullable_text(item.get('decision_note'))}, {self._nullable_text(item.get('applied_schedule_id'))});"
            )
        lines.append("COMMIT;")
        return "\n".join(lines) + "\n"

    def _text(self, value: str) -> str:
        escaped = str(value).replace("'", "''")
        return f"'{escaped}'"

    def _nullable_text(self, value: Any) -> str:
        if value is None:
            return "NULL"
        return self._text(str(value))

    def _json(self, value: Any) -> str:
        escaped = json.dumps(value, sort_keys=True).replace("'", "''")
        return f"'{escaped}'::jsonb"

    def _bool(self, value: Any) -> str:
        return "TRUE" if bool(value) else "FALSE"
