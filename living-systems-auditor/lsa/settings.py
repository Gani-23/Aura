from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class WorkspaceSettings:
    root_dir: Path
    data_dir: Path
    database_path: Path
    api_key: str | None
    run_embedded_worker: bool
    worker_heartbeat_timeout_seconds: float
    snapshots_dir: Path
    audits_dir: Path
    reports_dir: Path
    traces_dir: Path
    destination_aliases_path: Path


def resolve_workspace_settings(base_dir: str | Path | None = None) -> WorkspaceSettings:
    root = Path(base_dir).resolve() if base_dir else Path.cwd().resolve()
    data_dir = root / "data"
    return WorkspaceSettings(
        root_dir=root,
        data_dir=data_dir,
        database_path=data_dir / "control_plane.db",
        api_key=os.environ.get("LSA_API_KEY"),
        run_embedded_worker=_env_flag("LSA_RUN_EMBEDDED_WORKER", default=False),
        worker_heartbeat_timeout_seconds=_env_float("LSA_WORKER_HEARTBEAT_TIMEOUT_SECONDS", default=5.0),
        snapshots_dir=data_dir / "intent_graphs",
        audits_dir=data_dir / "audits",
        reports_dir=data_dir / "reports",
        traces_dir=data_dir / "traces",
        destination_aliases_path=data_dir / "destination_aliases.json",
    )


def _env_flag(name: str, *, default: bool) -> bool:
    raw_value = os.environ.get(name)
    if raw_value is None:
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, *, default: float) -> float:
    raw_value = os.environ.get(name)
    if raw_value is None:
        return default
    try:
        return float(raw_value)
    except ValueError:
        return default
