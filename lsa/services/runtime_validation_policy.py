from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class RuntimeValidationPolicy:
    due_soon_age_hours: float | None = None
    warning_age_hours: float | None = None
    critical_age_hours: float | None = None
    reminder_interval_seconds: float | None = None
    escalation_interval_seconds: float | None = None
    owner_team: str | None = None
    allowed_assignee_teams: tuple[str, ...] | None = None
    auto_assign_to: str | None = None
    auto_assign_to_team: str | None = None

    @classmethod
    def from_dict(cls, payload: dict | None) -> "RuntimeValidationPolicy":
        payload = {} if payload is None else payload
        return cls(
            due_soon_age_hours=_optional_float(payload.get("due_soon_age_hours")),
            warning_age_hours=_optional_float(payload.get("warning_age_hours")),
            critical_age_hours=_optional_float(payload.get("critical_age_hours")),
            reminder_interval_seconds=_optional_float(payload.get("reminder_interval_seconds")),
            escalation_interval_seconds=_optional_float(payload.get("escalation_interval_seconds")),
            owner_team=_optional_normalized_string(payload.get("owner_team")),
            allowed_assignee_teams=_optional_normalized_csv(payload.get("allowed_assignee_teams")),
            auto_assign_to=_optional_string(payload.get("auto_assign_to")),
            auto_assign_to_team=_optional_normalized_string(payload.get("auto_assign_to_team")),
        )

    def merged(self, override: "RuntimeValidationPolicy") -> "RuntimeValidationPolicy":
        return RuntimeValidationPolicy(
            due_soon_age_hours=override.due_soon_age_hours
            if override.due_soon_age_hours is not None
            else self.due_soon_age_hours,
            warning_age_hours=override.warning_age_hours
            if override.warning_age_hours is not None
            else self.warning_age_hours,
            critical_age_hours=override.critical_age_hours
            if override.critical_age_hours is not None
            else self.critical_age_hours,
            reminder_interval_seconds=override.reminder_interval_seconds
            if override.reminder_interval_seconds is not None
            else self.reminder_interval_seconds,
            escalation_interval_seconds=override.escalation_interval_seconds
            if override.escalation_interval_seconds is not None
            else self.escalation_interval_seconds,
            owner_team=override.owner_team if override.owner_team is not None else self.owner_team,
            allowed_assignee_teams=override.allowed_assignee_teams
            if override.allowed_assignee_teams is not None
            else self.allowed_assignee_teams,
            auto_assign_to=override.auto_assign_to if override.auto_assign_to is not None else self.auto_assign_to,
            auto_assign_to_team=override.auto_assign_to_team
            if override.auto_assign_to_team is not None
            else self.auto_assign_to_team,
        )

    def finalized(self, fallback: "RuntimeValidationPolicy") -> "RuntimeValidationPolicy":
        return RuntimeValidationPolicy(
            due_soon_age_hours=self.due_soon_age_hours
            if self.due_soon_age_hours is not None
            else fallback.due_soon_age_hours,
            warning_age_hours=self.warning_age_hours
            if self.warning_age_hours is not None
            else fallback.warning_age_hours,
            critical_age_hours=self.critical_age_hours
            if self.critical_age_hours is not None
            else fallback.critical_age_hours,
            reminder_interval_seconds=self.reminder_interval_seconds
            if self.reminder_interval_seconds is not None
            else fallback.reminder_interval_seconds,
            escalation_interval_seconds=self.escalation_interval_seconds
            if self.escalation_interval_seconds is not None
            else fallback.escalation_interval_seconds,
            owner_team=self.owner_team if self.owner_team is not None else fallback.owner_team,
            allowed_assignee_teams=self.allowed_assignee_teams
            if self.allowed_assignee_teams is not None
            else fallback.allowed_assignee_teams,
            auto_assign_to=self.auto_assign_to if self.auto_assign_to is not None else fallback.auto_assign_to,
            auto_assign_to_team=self.auto_assign_to_team
            if self.auto_assign_to_team is not None
            else fallback.auto_assign_to_team,
        )

    def to_dict(self) -> dict:
        return {
            "due_soon_age_hours": self.due_soon_age_hours,
            "warning_age_hours": self.warning_age_hours,
            "critical_age_hours": self.critical_age_hours,
            "reminder_interval_seconds": self.reminder_interval_seconds,
            "escalation_interval_seconds": self.escalation_interval_seconds,
            "owner_team": self.owner_team,
            "allowed_assignee_teams": None
            if self.allowed_assignee_teams is None
            else list(self.allowed_assignee_teams),
            "auto_assign_to": self.auto_assign_to,
            "auto_assign_to_team": self.auto_assign_to_team,
        }


@dataclass(slots=True)
class RuntimeValidationPolicyBundle:
    default: RuntimeValidationPolicy = field(default_factory=RuntimeValidationPolicy)
    environments: dict[str, RuntimeValidationPolicy] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: dict | None) -> "RuntimeValidationPolicyBundle":
        payload = {} if payload is None else payload
        return cls(
            default=RuntimeValidationPolicy.from_dict(payload.get("default")),
            environments={
                _normalize_key(key): RuntimeValidationPolicy.from_dict(value)
                for key, value in dict(payload.get("environments", {})).items()
            },
        )

    def resolve(
        self,
        *,
        environment_name: str | None,
        fallback: RuntimeValidationPolicy,
    ) -> RuntimeValidationPolicy:
        effective = self.default
        if environment_name is not None:
            override = self.environments.get(_normalize_key(environment_name))
            if override is not None:
                effective = effective.merged(override)
        return effective.finalized(fallback)

    def source_for(self, *, environment_name: str | None) -> str:
        if environment_name is not None and _normalize_key(environment_name) in self.environments:
            return f"policy:{_normalize_key(environment_name)}"
        if any(value is not None for value in self.default.to_dict().values()):
            return "policy:default"
        return "defaults"


def load_runtime_validation_policy_bundle(
    policy_path: str | Path | None,
) -> RuntimeValidationPolicyBundle:
    if policy_path is None:
        return RuntimeValidationPolicyBundle()
    path = Path(policy_path)
    if not path.exists():
        return RuntimeValidationPolicyBundle()
    payload = json.loads(path.read_text(encoding="utf-8"))
    return RuntimeValidationPolicyBundle.from_dict(payload)


def _normalize_key(raw_value: object) -> str:
    if raw_value is None:
        return ""
    return str(raw_value).strip().lower()


def _optional_float(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _optional_normalized_string(value: object) -> str | None:
    text = _optional_string(value)
    if text is None:
        return None
    return text.lower()


def _optional_normalized_csv(value: object) -> tuple[str, ...] | None:
    if value is None:
        return None
    if isinstance(value, str):
        values = [item.strip().lower() for item in value.split(",") if item.strip()]
        return tuple(values) or None
    if isinstance(value, (list, tuple)):
        values = [str(item).strip().lower() for item in value if str(item).strip()]
        return tuple(values) or None
    return None
