from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from lsa.services.job_service import JobService
from lsa.services.postgres_bootstrap_service import (
    PostgresBootstrapExecutionResult,
    PostgresBootstrapService,
)
from lsa.services.postgres_target_service import (
    PostgresBootstrapTargetVerification,
    PostgresTargetInspection,
    PostgresTargetService,
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class PostgresCutoverRehearsalSummary:
    started_at: str
    completed_at: str
    changed_by: str
    reason: str | None
    package_dir: str
    target_database_url: str
    psql_executable: str
    artifact_target_root: str | None
    apply_to_target: bool
    steps: list[str]
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    package_inspection: dict[str, Any] = field(default_factory=dict)
    target_before: dict[str, Any] = field(default_factory=dict)
    execution_result: dict[str, Any] | None = None
    target_after: dict[str, Any] | None = None
    verification: dict[str, Any] | None = None

    @property
    def valid(self) -> bool:
        if self.blockers:
            return False
        if self.apply_to_target:
            return bool(self.verification and self.verification.get("valid"))
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "changed_by": self.changed_by,
            "reason": self.reason,
            "package_dir": self.package_dir,
            "target_database_url": self.target_database_url,
            "psql_executable": self.psql_executable,
            "artifact_target_root": self.artifact_target_root,
            "apply_to_target": self.apply_to_target,
            "steps": list(self.steps),
            "blockers": list(self.blockers),
            "warnings": list(self.warnings),
            "package_inspection": dict(self.package_inspection),
            "target_before": dict(self.target_before),
            "execution_result": None if self.execution_result is None else dict(self.execution_result),
            "target_after": None if self.target_after is None else dict(self.target_after),
            "verification": None if self.verification is None else dict(self.verification),
            "valid": self.valid,
        }


@dataclass(slots=True)
class PostgresCutoverRehearsalService:
    job_service: JobService
    bootstrap_service: PostgresBootstrapService
    target_service: PostgresTargetService

    def execute_rehearsal(
        self,
        *,
        package_dir: str,
        target_database_url: str,
        changed_by: str,
        reason: str | None = None,
        psql_executable: str = "psql",
        artifact_target_root: str | None = None,
        apply_to_target: bool = False,
    ) -> PostgresCutoverRehearsalSummary:
        started_at = _utc_now()
        steps: list[str] = []

        package_inspection = self.bootstrap_service.inspect_package(package_dir=package_dir)
        steps.append("package_inspected")
        target_before = self.target_service.inspect_target(
            target_database_url=target_database_url,
            psql_executable=psql_executable,
        )
        steps.append("target_inspected")

        blockers = list(target_before.blockers)
        warnings = list(target_before.warnings)
        if not package_inspection.valid:
            blockers.append("invalid_package")
        if not target_before.reachable:
            blockers.append("target_not_reachable")

        if blockers:
            summary = PostgresCutoverRehearsalSummary(
                started_at=started_at,
                completed_at=_utc_now(),
                changed_by=changed_by,
                reason=reason,
                package_dir=package_dir,
                target_database_url=target_database_url,
                psql_executable=psql_executable,
                artifact_target_root=artifact_target_root,
                apply_to_target=apply_to_target,
                steps=steps,
                blockers=blockers,
                warnings=warnings,
                package_inspection=package_inspection.to_dict(),
                target_before=target_before.to_dict(),
            )
            self._record(changed_by=changed_by, reason=reason, summary=summary)
            return summary

        execution_result = self.bootstrap_service.execute_package(
            package_dir=package_dir,
            target_database_url=target_database_url,
            artifact_target_root=artifact_target_root,
            psql_executable=psql_executable,
            dry_run=not apply_to_target,
        )
        steps.append("package_applied" if apply_to_target else "package_dry_run_planned")

        target_after: PostgresTargetInspection | None = None
        verification: PostgresBootstrapTargetVerification | None = None
        if apply_to_target:
            target_after = self.target_service.inspect_target(
                target_database_url=target_database_url,
                psql_executable=psql_executable,
            )
            steps.append("target_reinspected")
            verification = self.target_service.verify_bootstrap_package_against_target(
                package_dir=package_dir,
                target_database_url=target_database_url,
                psql_executable=psql_executable,
            )
            steps.append("package_verified_against_target")
            warnings.extend(target_after.warnings)
            blockers.extend(target_after.blockers)
            blockers.extend(
                blocker
                for blocker in verification.blockers
                if blocker not in blockers
            )

        summary = PostgresCutoverRehearsalSummary(
            started_at=started_at,
            completed_at=_utc_now(),
            changed_by=changed_by,
            reason=reason,
            package_dir=package_dir,
            target_database_url=target_database_url,
            psql_executable=psql_executable,
            artifact_target_root=artifact_target_root,
            apply_to_target=apply_to_target,
            steps=steps,
            blockers=blockers,
            warnings=warnings,
            package_inspection=package_inspection.to_dict(),
            target_before=target_before.to_dict(),
            execution_result=execution_result.to_dict(),
            target_after=None if target_after is None else target_after.to_dict(),
            verification=None if verification is None else verification.to_dict(),
        )
        self._record(changed_by=changed_by, reason=reason, summary=summary)
        return summary

    def _record(
        self,
        *,
        changed_by: str,
        reason: str | None,
        summary: PostgresCutoverRehearsalSummary,
    ) -> None:
        self.job_service.record_maintenance_event(
            event_type="postgres_cutover_rehearsed",
            changed_by=changed_by,
            reason=reason,
            details=summary.to_dict(),
        )
