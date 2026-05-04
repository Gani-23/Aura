from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from lsa.drift.ebpf_observer import EbpfObserver, ObservationResult, ObserverConfig
from lsa.drift.trace_parser import split_inline_context_lines, split_inline_symbol_lines
from lsa.settings import WorkspaceSettings


@dataclass(slots=True)
class TraceCollectionRequest:
    pid: int | None = None
    program_path: str | None = None
    output_path: str | None = None
    duration_seconds: float | None = None
    max_events: int | None = None
    command: list[str] | None = None
    symbol_map_path: str | None = None
    context_map_path: str | None = None


@dataclass(slots=True)
class TraceCollectionMetadata:
    collector_session_id: str
    collector_started_at: str
    collector_target_pid: str | None = None
    collector_program_path: str | None = None
    collector_command: str | None = None
    collector_duration_seconds: str | None = None
    collector_max_events: str | None = None
    collector_symbol_map_path: str | None = None
    collector_context_map_path: str | None = None


class TraceCollectionService:
    def __init__(self, settings: WorkspaceSettings) -> None:
        self.settings = settings

    def collect(self, request: TraceCollectionRequest) -> ObservationResult:
        output_path = request.output_path or str(self.settings.traces_dir / "latest-trace.log")
        observer = EbpfObserver(
            ObserverConfig(
                pid=request.pid,
                program_path=request.program_path,
                output_path=output_path,
                duration_seconds=request.duration_seconds,
                max_events=request.max_events,
                command=request.command,
            )
        )
        result = observer.collect()
        inline_lines, inline_context_map = split_inline_context_lines(result.lines, trace_format="auto")
        inline_lines, inline_symbol_map = split_inline_symbol_lines(inline_lines, trace_format="auto")
        if inline_symbol_map:
            pass
        if inline_context_map or inline_symbol_map:
            self._rewrite_trace_file(Path(result.trace_path), inline_lines)
            result.lines = inline_lines
            result.line_count = len(inline_lines)
        symbol_map_path = self._stage_symbol_map(request, result, inline_symbol_map=inline_symbol_map)
        result.symbol_map_path = symbol_map_path
        context_map_path = self._stage_context_map(request, result, inline_context_map=inline_context_map)
        result.context_map_path = context_map_path
        metadata_path = self._write_trace_metadata(request, result)
        result.metadata_path = metadata_path
        return result

    def _write_trace_metadata(self, request: TraceCollectionRequest, result: ObservationResult) -> str:
        metadata = TraceCollectionMetadata(
            collector_session_id=uuid4().hex[:12],
            collector_started_at=datetime.now(UTC).isoformat(),
            collector_target_pid=str(request.pid) if request.pid is not None else None,
            collector_program_path=request.program_path,
            collector_command=" ".join(result.command) if result.command else None,
            collector_duration_seconds=(
                str(request.duration_seconds) if request.duration_seconds is not None else None
            ),
            collector_max_events=str(request.max_events) if request.max_events is not None else None,
            collector_symbol_map_path=result.symbol_map_path,
            collector_context_map_path=result.context_map_path,
        )
        metadata_path = self._metadata_path_for_trace(Path(result.trace_path))
        metadata_path.write_text(json.dumps(asdict(metadata), indent=2), encoding="utf-8")
        return str(metadata_path)

    def _metadata_path_for_trace(self, trace_path: Path) -> Path:
        return trace_path.with_name(f"{trace_path.name}.meta.json")

    def _stage_symbol_map(
        self,
        request: TraceCollectionRequest,
        result: ObservationResult,
        *,
        inline_symbol_map: dict[str, str],
    ) -> str | None:
        merged_symbols: dict[str, str] = {}
        source_path = self._resolve_symbol_map_source(request)
        if source_path is not None:
            if not source_path.exists():
                raise FileNotFoundError(f"Unable to find symbol map '{source_path}'.")
            merged_symbols.update(self._load_symbol_map(source_path))

        if inline_symbol_map:
            merged_symbols.update(inline_symbol_map)

        if not merged_symbols:
            return None

        target_path = self._symbol_map_path_for_trace(Path(result.trace_path))
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(json.dumps({"symbols": merged_symbols}, indent=2), encoding="utf-8")
        return str(target_path)

    def _resolve_symbol_map_source(self, request: TraceCollectionRequest) -> Path | None:
        if request.symbol_map_path:
            return Path(request.symbol_map_path)
        if request.program_path:
            candidate = Path(f"{request.program_path}.symbols.json")
            if candidate.exists():
                return candidate
        return None

    def _stage_context_map(
        self,
        request: TraceCollectionRequest,
        result: ObservationResult,
        *,
        inline_context_map: dict[str, dict[str, str]],
    ) -> str | None:
        merged_contexts: dict[str, dict[str, str]] = {}
        source_path = self._resolve_context_map_source(request)
        if source_path is not None:
            if not source_path.exists():
                raise FileNotFoundError(f"Unable to find context map '{source_path}'.")
            merged_contexts.update(self._load_context_map(source_path))

        if inline_context_map:
            merged_contexts.update(inline_context_map)

        if not merged_contexts:
            return None

        target_path = self._context_map_path_for_trace(Path(result.trace_path))
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(json.dumps({"contexts": merged_contexts}, indent=2), encoding="utf-8")
        return str(target_path)

    def _resolve_context_map_source(self, request: TraceCollectionRequest) -> Path | None:
        if request.context_map_path:
            return Path(request.context_map_path)
        if request.program_path:
            candidate = Path(f"{request.program_path}.contexts.json")
            if candidate.exists():
                return candidate
        return None

    def _symbol_map_path_for_trace(self, trace_path: Path) -> Path:
        return trace_path.with_name(f"{trace_path.name}.symbols.json")

    def _context_map_path_for_trace(self, trace_path: Path) -> Path:
        return trace_path.with_name(f"{trace_path.name}.contexts.json")

    def _rewrite_trace_file(self, path: Path, lines: list[str]) -> None:
        rendered = "\n".join(lines)
        if lines:
            rendered += "\n"
        path.write_text(rendered, encoding="utf-8")

    def _load_symbol_map(self, path: Path) -> dict[str, str]:
        payload = json.loads(path.read_text(encoding="utf-8"))
        symbols = payload.get("symbols", payload) if isinstance(payload, dict) else {}
        if not isinstance(symbols, dict):
            return {}
        return {str(key): str(value) for key, value in symbols.items() if value is not None}

    def _load_context_map(self, path: Path) -> dict[str, dict[str, str]]:
        payload = json.loads(path.read_text(encoding="utf-8"))
        contexts = payload.get("contexts", payload) if isinstance(payload, dict) else {}
        if not isinstance(contexts, dict):
            return {}
        normalized: dict[str, dict[str, str]] = {}
        for key, value in contexts.items():
            if not isinstance(value, dict):
                continue
            normalized[str(key)] = {str(item_key): str(item_value) for item_key, item_value in value.items() if item_value is not None}
        return normalized
