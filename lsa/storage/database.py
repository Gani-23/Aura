from __future__ import annotations

from dataclasses import dataclass
from importlib.util import find_spec
from pathlib import Path
from urllib.parse import ParseResult, quote, unquote, urlparse


RUNTIME_SUPPORTED_DATABASE_BACKENDS = ("sqlite",)
SQLITE_BACKENDS = {"sqlite"}
POSTGRES_BACKENDS = {"postgres", "postgresql"}
SQLITE_RUNTIME_DRIVER = "sqlite3"
POSTGRES_RUNTIME_DRIVER = "psycopg"


@dataclass(slots=True)
class DatabaseConfig:
    backend: str
    url: str
    redacted_url: str
    runtime_supported: bool
    sqlite_path: Path
    sqlite_target: str
    sqlite_uri: bool
    host: str | None = None
    port: int | None = None
    database_name: str | None = None
    username: str | None = None
    query: str = ""


@dataclass(slots=True)
class DatabaseRuntimeSupport:
    backend: str
    url: str
    redacted_url: str
    runtime_supported: bool
    runtime_driver: str
    runtime_dependency_installed: bool
    runtime_available: bool
    blockers: list[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "backend": self.backend,
            "url": self.url,
            "redacted_url": self.redacted_url,
            "runtime_supported": self.runtime_supported,
            "runtime_driver": self.runtime_driver,
            "runtime_dependency_installed": self.runtime_dependency_installed,
            "runtime_available": self.runtime_available,
            "runtime_blockers": list(self.blockers),
        }


def build_sqlite_database_url(path: Path) -> str:
    return f"sqlite:///{path.resolve().as_posix()}"


def inspect_database_config(*, root_dir: Path, default_path: Path, raw_url: str | None) -> DatabaseConfig:
    if raw_url is None or not raw_url.strip():
        sqlite_path = default_path.resolve()
        normalized_url = build_sqlite_database_url(sqlite_path)
        return DatabaseConfig(
            backend="sqlite",
            url=normalized_url,
            redacted_url=normalized_url,
            runtime_supported=True,
            sqlite_path=sqlite_path,
            sqlite_target=str(sqlite_path),
            sqlite_uri=False,
            database_name=sqlite_path.name,
        )

    parsed = urlparse(raw_url)
    backend = parsed.scheme.lower()
    if backend in SQLITE_BACKENDS:
        return _inspect_sqlite_config(root_dir=root_dir, parsed=parsed)
    if backend in POSTGRES_BACKENDS:
        return _inspect_postgres_config(parsed=parsed)
    raise ValueError(
        f"Unsupported database backend '{backend}'. Supported URL schemes are sqlite://, postgres://, and postgresql://."
    )


def resolve_database_config(
    *,
    root_dir: Path,
    default_path: Path,
    raw_url: str | None,
    supported_backends: tuple[str, ...] = RUNTIME_SUPPORTED_DATABASE_BACKENDS,
) -> DatabaseConfig:
    config = inspect_database_config(root_dir=root_dir, default_path=default_path, raw_url=raw_url)
    if config.backend not in supported_backends:
        supported = ", ".join(sorted(supported_backends))
        raise ValueError(
            f"Unsupported runtime database backend '{config.backend}'. This build currently supports: {supported}."
        )
    return config


def inspect_database_runtime_support(
    *,
    root_dir: Path,
    default_path: Path,
    raw_url: str | None,
    supported_backends: tuple[str, ...] = RUNTIME_SUPPORTED_DATABASE_BACKENDS,
) -> DatabaseRuntimeSupport:
    config = inspect_database_config(root_dir=root_dir, default_path=default_path, raw_url=raw_url)
    return build_database_runtime_support(config=config, supported_backends=supported_backends)


def build_database_runtime_support(
    config: DatabaseConfig,
    *,
    supported_backends: tuple[str, ...] = RUNTIME_SUPPORTED_DATABASE_BACKENDS,
) -> DatabaseRuntimeSupport:
    runtime_supported = config.backend in supported_backends
    blockers: list[str] = []
    if config.backend == "sqlite":
        runtime_driver = SQLITE_RUNTIME_DRIVER
        dependency_installed = True
    elif config.backend == "postgres":
        runtime_driver = POSTGRES_RUNTIME_DRIVER
        dependency_installed = find_spec(runtime_driver) is not None
        if not dependency_installed:
            blockers.append(f"missing_runtime_dependency:{runtime_driver}")
    else:
        runtime_driver = "unknown"
        dependency_installed = False
        blockers.append(f"unknown_runtime_driver:{config.backend}")
    if not runtime_supported:
        blockers.append(f"unsupported_runtime_backend:{config.backend}")
    return DatabaseRuntimeSupport(
        backend=config.backend,
        url=config.url,
        redacted_url=config.redacted_url,
        runtime_supported=runtime_supported,
        runtime_driver=runtime_driver,
        runtime_dependency_installed=dependency_installed,
        runtime_available=runtime_supported and dependency_installed,
        blockers=blockers,
    )


def _inspect_sqlite_config(*, root_dir: Path, parsed: ParseResult) -> DatabaseConfig:
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
        normalized_with_query = f"{normalized_url}?{parsed.query}"
        return DatabaseConfig(
            backend="sqlite",
            url=normalized_with_query,
            redacted_url=normalized_with_query,
            runtime_supported=True,
            sqlite_path=sqlite_path,
            sqlite_target=f"file:{sqlite_path.as_posix()}?{parsed.query}",
            sqlite_uri=True,
            database_name=sqlite_path.name,
            query=parsed.query,
        )

    return DatabaseConfig(
        backend="sqlite",
        url=normalized_url,
        redacted_url=normalized_url,
        runtime_supported=True,
        sqlite_path=sqlite_path,
        sqlite_target=str(sqlite_path),
        sqlite_uri=False,
        database_name=sqlite_path.name,
    )


def _inspect_postgres_config(*, parsed: ParseResult) -> DatabaseConfig:
    if not parsed.hostname:
        raise ValueError("Postgres database URLs must include a host name.")
    if not parsed.path or parsed.path == "/":
        raise ValueError("Postgres database URLs must include a database name in the path.")

    database_name = unquote(parsed.path.lstrip("/"))
    username = unquote(parsed.username) if parsed.username else None
    password = unquote(parsed.password) if parsed.password else None
    host = parsed.hostname
    port = parsed.port or 5432

    normalized_url = _build_postgres_url(
        scheme=parsed.scheme.lower(),
        username=username,
        password=password,
        host=host,
        port=port,
        database_name=database_name,
        query=parsed.query,
    )
    redacted_url = _build_postgres_url(
        scheme=parsed.scheme.lower(),
        username=username,
        password="***" if password is not None else None,
        host=host,
        port=port,
        database_name=database_name,
        query=parsed.query,
    )
    return DatabaseConfig(
        backend="postgres",
        url=normalized_url,
        redacted_url=redacted_url,
        runtime_supported=False,
        sqlite_path=Path("/dev/null"),
        sqlite_target="",
        sqlite_uri=False,
        host=host,
        port=port,
        database_name=database_name,
        username=username,
        query=parsed.query,
    )


def _build_postgres_url(
    *,
    scheme: str,
    username: str | None,
    password: str | None,
    host: str,
    port: int,
    database_name: str,
    query: str,
) -> str:
    credentials = ""
    if username is not None:
        credentials = quote(username, safe="")
        if password is not None:
            encoded_password = password if password == "***" else quote(password, safe="")
            credentials += f":{encoded_password}"
        credentials += "@"
    query_suffix = f"?{query}" if query else ""
    return f"{scheme}://{credentials}{host}:{port}/{quote(database_name, safe='')}{query_suffix}"
