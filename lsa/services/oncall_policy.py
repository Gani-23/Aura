from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class OnCallGovernancePolicy:
    owner_team: str | None = None
    allowed_requester_teams: tuple[str, ...] = ()
    allowed_approver_teams: tuple[str, ...] = ()
    allowed_approver_ids: tuple[str, ...] = ()
    required_approver_roles: tuple[str, ...] = ()
    allow_self_approval: bool | None = None

    @classmethod
    def from_dict(cls, payload: dict | None) -> "OnCallGovernancePolicy":
        if payload is None:
            return cls()
        return cls(
            owner_team=_normalize_optional(payload.get("owner_team")),
            allowed_requester_teams=_normalize_tuple(payload.get("allowed_requester_teams")),
            allowed_approver_teams=_normalize_tuple(payload.get("allowed_approver_teams")),
            allowed_approver_ids=_normalize_tuple(payload.get("allowed_approver_ids")),
            required_approver_roles=_normalize_tuple(payload.get("required_approver_roles")),
            allow_self_approval=payload.get("allow_self_approval"),
        )

    def merged(self, override: "OnCallGovernancePolicy") -> "OnCallGovernancePolicy":
        return OnCallGovernancePolicy(
            owner_team=override.owner_team or self.owner_team,
            allowed_requester_teams=override.allowed_requester_teams or self.allowed_requester_teams,
            allowed_approver_teams=override.allowed_approver_teams or self.allowed_approver_teams,
            allowed_approver_ids=override.allowed_approver_ids or self.allowed_approver_ids,
            required_approver_roles=override.required_approver_roles or self.required_approver_roles,
            allow_self_approval=(
                override.allow_self_approval
                if override.allow_self_approval is not None
                else self.allow_self_approval
            ),
        )

    def to_dict(self) -> dict:
        return {
            "owner_team": self.owner_team,
            "allowed_requester_teams": list(self.allowed_requester_teams),
            "allowed_approver_teams": list(self.allowed_approver_teams),
            "allowed_approver_ids": list(self.allowed_approver_ids),
            "required_approver_roles": list(self.required_approver_roles),
            "allow_self_approval": self.allow_self_approval,
        }


@dataclass(slots=True)
class OnCallPolicyBundle:
    default: OnCallGovernancePolicy = field(default_factory=OnCallGovernancePolicy)
    teams: dict[str, OnCallGovernancePolicy] = field(default_factory=dict)
    rotations: dict[str, OnCallGovernancePolicy] = field(default_factory=dict)
    environments: dict[str, "OnCallPolicyBundle"] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: dict | None) -> "OnCallPolicyBundle":
        payload = {} if payload is None else payload
        return cls(
            default=OnCallGovernancePolicy.from_dict(payload.get("default")),
            teams={
                _normalize_key(key): OnCallGovernancePolicy.from_dict(value)
                for key, value in dict(payload.get("teams", {})).items()
            },
            rotations={
                _normalize_key(key): OnCallGovernancePolicy.from_dict(value)
                for key, value in dict(payload.get("rotations", {})).items()
            },
            environments={
                _normalize_key(key): cls.from_dict(value)
                for key, value in dict(payload.get("environments", {})).items()
            },
        )

    def resolve(
        self,
        *,
        environment_name: str | None,
        team_name: str,
        rotation_name: str | None,
    ) -> OnCallGovernancePolicy:
        effective = self.default
        team_rule = self.teams.get(_normalize_key(team_name))
        if team_rule is not None:
            effective = effective.merged(team_rule)
        if rotation_name is not None:
            rotation_rule = self.rotations.get(_normalize_key(rotation_name))
            if rotation_rule is not None:
                effective = effective.merged(rotation_rule)
        if environment_name is not None:
            environment_bundle = self.environments.get(_normalize_key(environment_name))
            if environment_bundle is not None:
                effective = effective.merged(
                    environment_bundle.resolve(
                        environment_name=None,
                        team_name=team_name,
                        rotation_name=rotation_name,
                    )
                )
        return effective

    def to_dict(self) -> dict:
        return {
            "default": self.default.to_dict(),
            "teams": {key: value.to_dict() for key, value in self.teams.items()},
            "rotations": {key: value.to_dict() for key, value in self.rotations.items()},
            "environments": {
                key: value.to_dict() for key, value in self.environments.items()
            },
        }


def load_oncall_policy_bundle(policy_path: str | Path | None) -> OnCallPolicyBundle:
    if policy_path is None:
        return OnCallPolicyBundle()
    path = Path(policy_path)
    if not path.exists():
        return OnCallPolicyBundle()
    payload = json.loads(path.read_text(encoding="utf-8"))
    return OnCallPolicyBundle.from_dict(payload)


def _normalize_tuple(raw_value: object) -> tuple[str, ...]:
    if raw_value is None:
        return ()
    if isinstance(raw_value, str):
        values = [raw_value]
    else:
        values = list(raw_value)
    return tuple(_normalize_key(item) for item in values if _normalize_key(item))


def _normalize_optional(raw_value: object) -> str | None:
    normalized = _normalize_key(raw_value)
    return normalized or None


def _normalize_key(raw_value: object) -> str:
    if raw_value is None:
        return ""
    return str(raw_value).strip().lower()
