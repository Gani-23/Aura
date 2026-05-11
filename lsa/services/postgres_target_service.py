from __future__ import annotations

import json
import shutil as shell_shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from lsa.services.postgres_bootstrap_service import (
    PostgresBootstrapPackageInspection,
    PostgresBootstrapService,
)
from lsa.storage.control_plane_schema import control_plane_schema_contract
from lsa.storage.database import inspect_database_config


@dataclass(slots=True)
class PostgresTargetInspection:
    target: dict[str, Any]
    psql_executable: str
    reachable: bool
    schema_version: int | None
    expected_schema_version: int
    schema_ready: bool
    maintenance_mode_active: bool | None
    table_presence: dict[str, bool]
    row_counts: dict[str, int | None]
    blockers: list[str]
    warnings: list[str]

    @property
    def inspectable(self) -> bool:
        return self.reachable and not self.blockers

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": dict(self.target),
            "psql_executable": self.psql_executable,
            "reachable": self.reachable,
            "schema_version": self.schema_version,
            "expected_schema_version": self.expected_schema_version,
            "schema_ready": self.schema_ready,
            "maintenance_mode_active": self.maintenance_mode_active,
            "table_presence": dict(self.table_presence),
            "row_counts": dict(self.row_counts),
            "blockers": list(self.blockers),
            "warnings": list(self.warnings),
            "inspectable": self.inspectable,
        }


@dataclass(slots=True)
class PostgresBootstrapTargetVerification:
    package_dir: str
    target_database_url: str
    psql_executable: str
    package_valid: bool
    target_reachable: bool
    schema_contract_match: bool
    schema_version_match: bool
    row_counts_match: bool
    missing_tables: list[str]
    row_count_mismatches: dict[str, dict[str, int | None]]
    blockers: list[str]
    package_inspection: dict[str, Any]
    target_inspection: dict[str, Any]

    @property
    def valid(self) -> bool:
        return (
            self.package_valid
            and self.target_reachable
            and self.schema_contract_match
            and self.schema_version_match
            and self.row_counts_match
            and not self.missing_tables
            and not self.blockers
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_dir": self.package_dir,
            "target_database_url": self.target_database_url,
            "psql_executable": self.psql_executable,
            "package_valid": self.package_valid,
            "target_reachable": self.target_reachable,
            "schema_contract_match": self.schema_contract_match,
            "schema_version_match": self.schema_version_match,
            "row_counts_match": self.row_counts_match,
            "missing_tables": list(self.missing_tables),
            "row_count_mismatches": dict(self.row_count_mismatches),
            "blockers": list(self.blockers),
            "package_inspection": dict(self.package_inspection),
            "target_inspection": dict(self.target_inspection),
            "valid": self.valid,
        }


class PostgresTargetService:
    def __init__(self, *, bootstrap_service: PostgresBootstrapService | None = None) -> None:
        self.bootstrap_service = bootstrap_service or PostgresBootstrapService()

    def inspect_target(
        self,
        *,
        target_database_url: str,
        psql_executable: str = "psql",
    ) -> PostgresTargetInspection:
        config = inspect_database_config(
            root_dir=Path.cwd(),
            default_path=Path.cwd() / "control_plane.db",
            raw_url=target_database_url,
        )
        if config.backend != "postgres":
            raise ValueError("Postgres target inspection requires a postgres:// or postgresql:// database URL.")

        blockers: list[str] = []
        warnings: list[str] = []
        resolved_psql = self._resolve_executable(psql_executable)
        if not resolved_psql:
            blockers.append("psql_not_found")
            return PostgresTargetInspection(
                target=self._target_dict(config),
                psql_executable=psql_executable,
                reachable=False,
                schema_version=None,
                expected_schema_version=int(control_plane_schema_contract()["schema_version"]),
                schema_ready=False,
                maintenance_mode_active=None,
                table_presence={name: False for name in control_plane_schema_contract()["table_names"]},
                row_counts={name: None for name in control_plane_schema_contract()["table_names"]},
                blockers=blockers,
                warnings=warnings,
            )

        sql = self._build_target_inspection_sql()
        try:
            payload = self._run_psql_json_query(
                psql_executable=resolved_psql,
                target_database_url=target_database_url,
                sql=sql,
            )
        except subprocess.CalledProcessError as exc:
            blockers.append("target_query_failed")
            warnings.append(exc.stderr.strip() if exc.stderr else str(exc))
            return PostgresTargetInspection(
                target=self._target_dict(config),
                psql_executable=resolved_psql,
                reachable=False,
                schema_version=None,
                expected_schema_version=int(control_plane_schema_contract()["schema_version"]),
                schema_ready=False,
                maintenance_mode_active=None,
                table_presence={name: False for name in control_plane_schema_contract()["table_names"]},
                row_counts={name: None for name in control_plane_schema_contract()["table_names"]},
                blockers=blockers,
                warnings=warnings,
            )

        schema_version = self._parse_optional_int(payload.get("schema_version"))
        expected_schema_version = int(control_plane_schema_contract()["schema_version"])
        table_presence = {
            str(name): bool(value)
            for name, value in dict(payload.get("table_presence", {})).items()
        }
        row_counts = {
            str(name): self._parse_optional_int(value)
            for name, value in dict(payload.get("row_counts", {})).items()
        }
        maintenance_mode_value = payload.get("maintenance_mode_active")
        maintenance_mode_active = None
        if maintenance_mode_value is not None:
            maintenance_mode_active = str(maintenance_mode_value) == "1"

        missing_tables = sorted(name for name, present in table_presence.items() if not present)
        if missing_tables:
            warnings.append("missing_tables:" + ",".join(missing_tables))

        return PostgresTargetInspection(
            target=self._target_dict(config),
            psql_executable=resolved_psql,
            reachable=True,
            schema_version=schema_version,
            expected_schema_version=expected_schema_version,
            schema_ready=schema_version == expected_schema_version,
            maintenance_mode_active=maintenance_mode_active,
            table_presence=table_presence,
            row_counts=row_counts,
            blockers=blockers,
            warnings=warnings,
        )

    def verify_bootstrap_package_against_target(
        self,
        *,
        package_dir: str,
        target_database_url: str,
        psql_executable: str = "psql",
    ) -> PostgresBootstrapTargetVerification:
        package_inspection = self.bootstrap_service.inspect_package(package_dir=package_dir)
        target_inspection = self.inspect_target(
            target_database_url=target_database_url,
            psql_executable=psql_executable,
        )
        manifest = json.loads((Path(package_dir) / "manifest.json").read_text(encoding="utf-8"))
        expected_contract = dict(manifest.get("schema_contract", {}))
        current_contract = control_plane_schema_contract()
        schema_contract_match = expected_contract == current_contract if expected_contract else False

        expected_schema_status = dict(manifest.get("schema_status", {}))
        expected_schema_version = self._parse_optional_int(expected_schema_status.get("schema_version"))
        schema_version_match = (
            expected_schema_version is not None
            and target_inspection.schema_version == expected_schema_version
        )

        expected_table_counts = {
            str(name): int(value)
            for name, value in dict(manifest.get("table_counts", {})).items()
        }
        missing_tables = sorted(
            name for name, present in target_inspection.table_presence.items() if not present
        )
        row_count_mismatches: dict[str, dict[str, int | None]] = {}
        for table_name, expected_count in expected_table_counts.items():
            actual_count = target_inspection.row_counts.get(table_name)
            if actual_count != expected_count:
                row_count_mismatches[table_name] = {
                    "expected": expected_count,
                    "actual": actual_count,
                }

        blockers = list(target_inspection.blockers)
        if not package_inspection.valid:
            blockers.append("invalid_package")
        if not schema_contract_match:
            blockers.append("schema_contract_mismatch")
        if not schema_version_match:
            blockers.append("schema_version_mismatch")
        if row_count_mismatches:
            blockers.append("row_count_mismatch")

        return PostgresBootstrapTargetVerification(
            package_dir=str(Path(package_dir).resolve()),
            target_database_url=target_database_url,
            psql_executable=psql_executable,
            package_valid=package_inspection.valid,
            target_reachable=target_inspection.reachable,
            schema_contract_match=schema_contract_match,
            schema_version_match=schema_version_match,
            row_counts_match=not row_count_mismatches,
            missing_tables=missing_tables,
            row_count_mismatches=row_count_mismatches,
            blockers=blockers,
            package_inspection=package_inspection.to_dict(),
            target_inspection=target_inspection.to_dict(),
        )

    def _build_target_inspection_sql(self) -> str:
        contract = control_plane_schema_contract()
        table_names = list(contract["table_names"])
        table_presence_entries = ", ".join(
            f"'{table_name}', (to_regclass('public.{table_name}') IS NOT NULL)"
            for table_name in table_names
        )
        row_count_entries = ", ".join(
            (
                f"'{table_name}', CASE "
                f"WHEN to_regclass('public.{table_name}') IS NULL THEN NULL "
                f"ELSE (SELECT COUNT(*) FROM {table_name}) END"
            )
            for table_name in table_names
        )
        return f"""
SELECT json_build_object(
  'schema_version',
  (SELECT metadata_value FROM control_plane_schema_metadata WHERE metadata_key = 'schema_version'),
  'maintenance_mode_active',
  (SELECT metadata_value FROM control_plane_schema_metadata WHERE metadata_key = 'maintenance_mode_active'),
  'table_presence',
  json_build_object({table_presence_entries}),
  'row_counts',
  json_build_object({row_count_entries})
)::text;
""".strip()

    def _run_psql_json_query(
        self,
        *,
        psql_executable: str,
        target_database_url: str,
        sql: str,
    ) -> dict[str, Any]:
        completed = subprocess.run(
            [psql_executable, target_database_url, "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql],
            check=True,
            text=True,
            capture_output=True,
        )
        output = completed.stdout.strip()
        if not output:
            raise ValueError("Postgres target inspection produced no output.")
        return dict(json.loads(output))

    def _resolve_executable(self, executable: str) -> str | None:
        executable_path = Path(executable)
        if executable_path.is_absolute():
            return str(executable_path) if executable_path.exists() else None
        return shell_shutil.which(executable)

    def _target_dict(self, config: Any) -> dict[str, Any]:
        return {
            "backend": config.backend,
            "url": config.url,
            "redacted_url": config.redacted_url,
            "runtime_supported": config.runtime_supported,
            "host": config.host,
            "port": config.port,
            "database_name": config.database_name,
            "username": config.username,
        }

    def _parse_optional_int(self, value: object) -> int | None:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
