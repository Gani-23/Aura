from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass(slots=True)
class DatabaseConfig:
    backend: str
    url: str
    sqlite_path: Path
    sqlite_target: str
    sqlite_uri: bool


def build_sqlite_database_url(path: Path) -> str:
    return f"sqlite:///{path.resolve().as_posix()}"


def resolve_database_config(*, root_dir: Path, default_path: Path, raw_url: str | None) -> DatabaseConfig:
    if raw_url is None or not raw_url.strip():
        sqlite_path = default_path.resolve()
        return DatabaseConfig(
            backend="sqlite",
            url=build_sqlite_database_url(sqlite_path),
            sqlite_path=sqlite_path,
            sqlite_target=str(sqlite_path),
            sqlite_uri=False,
        )

    parsed = urlparse(raw_url)
    backend = parsed.scheme.lower()
    if backend != "sqlite":
        raise ValueError(f"Unsupported database backend '{backend}'. Only sqlite URLs are currently supported.")
    if parsed.netloc not in {"", "localhost"}:
        raise ValueError("SQLite database URLs must not include a network host.")
    if not parsed.path or parsed.path == "/":
        raise ValueError("SQLite database URLs must include an absolute file path.")

    sqlite_path = Path(parsed.path).expanduser()
    if not sqlite_path.is_absolute():
        sqlite_path = (root_dir / sqlite_path).resolve()
    else:
        sqlite_path = sqlite_path.resolve()

    normalized_url = build_sqlite_database_url(sqlite_path)
    if parsed.query:
        return DatabaseConfig(
            backend="sqlite",
            url=f"{normalized_url}?{parsed.query}",
            sqlite_path=sqlite_path,
            sqlite_target=f"file:{sqlite_path.as_posix()}?{parsed.query}",
            sqlite_uri=True,
        )

    return DatabaseConfig(
        backend="sqlite",
        url=normalized_url,
        sqlite_path=sqlite_path,
        sqlite_target=str(sqlite_path),
        sqlite_uri=False,
    )
