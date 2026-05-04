from __future__ import annotations

import json
import re
import shlex
from dataclasses import replace
from pathlib import Path

from lsa.drift.models import ObservedEvent
from lsa.drift.enrichment import enrich_event


RAW_CONNECT_RE = re.compile(r"^CONNECT\s+(?P<process>\S+)\s+(?P<port>\d+)$")
INLINE_SYMBOL_EVENT_TYPES = {"symbol", "symbols", "symbol_map"}
INLINE_CONTEXT_EVENT_TYPES = {"context", "context_map", "correlation_context"}
ADDRESS_HINT_TARGETS = {
    "address": "symbol",
    "pc": "symbol",
    "ip": "symbol",
    "instruction_pointer": "symbol",
    "frame_addr": "frame_symbol",
    "callsite_addr": "callsite_symbol",
}
STACK_ADDRESS_TARGETS = {
    "stack_addrs": "stack",
    "frame_addrs": "frames",
    "address_stack": "stack",
    "callsite_addrs": "call_stack",
}
STACK_LIKE_KEYS = (
    "stack",
    "call_stack",
    "frames",
    "frame",
    "function_chain",
    "qualname_chain",
    "callsite",
    "code_stack",
)
STACK_SPLIT_RE = re.compile(r"\s*(?:>|[|,;])\s*")


def parse_trace_line(line: str, trace_format: str = "auto") -> ObservedEvent | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    if trace_format in {"auto", "jsonl"} and stripped.startswith("{"):
        payload = json.loads(stripped)
        return ObservedEvent.from_dict(payload)

    if trace_format in {"auto", "bpftrace"}:
        match = RAW_CONNECT_RE.match(stripped)
        if match:
            process = match.group("process")
            port = match.group("port")
            return enrich_event(ObservedEvent(
                function=process,
                event_type="network",
                target=f"port:{port}",
                metadata={
                    "process": process,
                    "port": port,
                    "source": "bpftrace_raw_connect",
                },
            ))

    if trace_format not in {"auto", "kv", "logfmt"} and trace_format != "bpftrace":
        raise ValueError(f"Unsupported trace format: {trace_format}")

    return _parse_key_value_trace(stripped)


def load_trace_events(source: str | Path, trace_format: str = "auto") -> list[ObservedEvent]:
    path = Path(source)
    trace_context = _load_trace_context(path)
    trace_symbol_map = _load_trace_symbol_map(path)
    trace_context_map = _load_trace_context_map(path)
    raw_lines = path.read_text(encoding="utf-8").splitlines()
    filtered_lines, inline_context_map = split_inline_context_lines(raw_lines, trace_format=trace_format)
    if inline_context_map:
        trace_context_map = dict(trace_context_map)
        trace_context_map.update(inline_context_map)
    filtered_lines, inline_symbol_map = split_inline_symbol_lines(filtered_lines, trace_format=trace_format)
    if inline_symbol_map:
        trace_symbol_map = dict(trace_symbol_map)
        trace_symbol_map.update(inline_symbol_map)
    events: list[ObservedEvent] = []
    for raw_line in filtered_lines:
        event = parse_trace_line(raw_line, trace_format=trace_format)
        if event is not None:
            event = _apply_trace_symbol_map(event, trace_symbol_map)
            event = _apply_trace_context_map(event, trace_context_map)
            event = _merge_trace_context(event, trace_context)
            events.append(event)
    return events


def split_inline_context_lines(
    lines: list[str],
    *,
    trace_format: str = "auto",
) -> tuple[list[str], dict[str, dict[str, str]]]:
    filtered_lines: list[str] = []
    context_map: dict[str, dict[str, str]] = {}
    for raw_line in lines:
        context_update = _parse_inline_context_definition(raw_line, trace_format=trace_format)
        if context_update:
            context_map.update(context_update)
            continue
        filtered_lines.append(raw_line)
    return filtered_lines, context_map


def split_inline_symbol_lines(
    lines: list[str],
    *,
    trace_format: str = "auto",
) -> tuple[list[str], dict[str, str]]:
    filtered_lines: list[str] = []
    symbol_map: dict[str, str] = {}
    for raw_line in lines:
        symbol_update = _parse_inline_symbol_definition(raw_line, trace_format=trace_format)
        if symbol_update:
            symbol_map.update(symbol_update)
            continue
        filtered_lines.append(raw_line)
    return filtered_lines, symbol_map


def _parse_key_value_trace(line: str) -> ObservedEvent:
    payload = _parse_key_value_payload(line)

    event_type = payload.get("event_type") or payload.get("event") or "network"
    explicit_function = payload.get("function") or payload.get("func")
    function = explicit_function or payload.get("process") or payload.get("comm")
    if not function:
        raise ValueError(f"Trace line missing function/process identifier: {line}")

    target = payload.get("target")
    if not target:
        host = payload.get("host") or payload.get("daddr") or payload.get("dest")
        port = payload.get("port") or payload.get("dport")
        if host and port:
            target = f"{host}:{port}"
        elif host:
            target = host
        elif port:
            target = f"port:{port}"
        else:
            raise ValueError(f"Trace line missing target fields: {line}")

    metadata = {
        key: value
        for key, value in payload.items()
        if key
        not in {
            "event_type",
            "event",
            "target",
        }
    }
    if explicit_function is None:
        metadata.setdefault("derived_function_from", "process" if payload.get("process") else "comm")
    return enrich_event(ObservedEvent(function=function, event_type=event_type, target=target, metadata=metadata))


def _parse_inline_symbol_definition(line: str, trace_format: str = "auto") -> dict[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    if trace_format in {"auto", "jsonl"} and stripped.startswith("{"):
        payload = json.loads(stripped)
        if not isinstance(payload, dict):
            return None
    else:
        payload = _parse_key_value_payload(stripped)

    event_type = payload.get("event_type") or payload.get("event") or payload.get("type")
    if event_type not in INLINE_SYMBOL_EVENT_TYPES:
        return None

    address = payload.get("address") or payload.get("addr") or payload.get("pc") or payload.get("ip")
    symbol = payload.get("symbol") or payload.get("value") or payload.get("name")
    if not address or not symbol:
        return None
    return {address: symbol}


def _parse_inline_context_definition(line: str, trace_format: str = "auto") -> dict[str, dict[str, str]] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    if trace_format in {"auto", "jsonl"} and stripped.startswith("{"):
        payload = json.loads(stripped)
        if not isinstance(payload, dict):
            return None
    else:
        payload = _parse_key_value_payload(stripped)

    event_type = payload.get("event_type") or payload.get("event") or payload.get("type")
    if event_type not in INLINE_CONTEXT_EVENT_TYPES:
        return None

    context_key = (
        payload.get("context_key")
        or payload.get("conn_id")
        or payload.get("flow_id")
        or payload.get("socket_id")
        or payload.get("request_id")
        or payload.get("trace_id")
    )
    if not context_key:
        return None

    context_payload = {
        key: value
        for key, value in payload.items()
        if key not in {"event_type", "event", "type", "context_key"}
    }
    return {context_key: context_payload} if context_payload else None


def _load_trace_context(path: Path) -> dict[str, str]:
    metadata_path = path.with_name(f"{path.name}.meta.json")
    if not metadata_path.exists():
        return {}
    payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    return {
        key: str(value)
        for key, value in payload.items()
        if value is not None
    }


def _merge_trace_context(event: ObservedEvent, trace_context: dict[str, str]) -> ObservedEvent:
    if not trace_context:
        return event
    metadata = dict(trace_context)
    metadata.update(event.metadata)
    return enrich_event(replace(event, metadata=metadata))


def _load_trace_symbol_map(path: Path) -> dict[str, str]:
    symbol_path = path.with_name(f"{path.name}.symbols.json")
    if not symbol_path.exists():
        return {}
    payload = json.loads(symbol_path.read_text(encoding="utf-8"))
    symbols = payload.get("symbols", payload) if isinstance(payload, dict) else {}
    if not isinstance(symbols, dict):
        return {}
    return {str(key): str(value) for key, value in symbols.items() if value is not None}


def _load_trace_context_map(path: Path) -> dict[str, dict[str, str]]:
    context_path = path.with_name(f"{path.name}.contexts.json")
    if not context_path.exists():
        return {}
    payload = json.loads(context_path.read_text(encoding="utf-8"))
    contexts = payload.get("contexts", payload) if isinstance(payload, dict) else {}
    if not isinstance(contexts, dict):
        return {}
    normalized: dict[str, dict[str, str]] = {}
    for key, value in contexts.items():
        if not isinstance(value, dict):
            continue
        normalized[str(key)] = {str(item_key): str(item_value) for item_key, item_value in value.items() if item_value is not None}
    return normalized


def _apply_trace_symbol_map(event: ObservedEvent, symbol_map: dict[str, str]) -> ObservedEvent:
    if not symbol_map:
        return event

    metadata = dict(event.metadata)
    changed = False

    for address_key, target_key in ADDRESS_HINT_TARGETS.items():
        address = metadata.get(address_key)
        if not address:
            continue
        mapped = symbol_map.get(address)
        if not mapped:
            continue
        metadata.setdefault(target_key, mapped)
        metadata.setdefault(f"{target_key}_address", address)
        metadata.setdefault(f"{target_key}_source", "trace_symbol_map")
        if target_key == "symbol":
            metadata.pop("normalized_symbol", None)
        changed = True

    for source_key, target_key in STACK_ADDRESS_TARGETS.items():
        raw_value = metadata.get(source_key)
        if not raw_value:
            continue
        resolved_value, replacements = _resolve_stack_symbols(raw_value, symbol_map)
        if replacements == 0:
            continue
        metadata.setdefault(target_key, resolved_value)
        metadata.setdefault(f"{target_key}_source", "trace_symbol_map")
        metadata.setdefault(f"raw_{source_key}", raw_value)
        metadata.pop(f"normalized_{target_key}", None)
        changed = True

    for stack_key in STACK_LIKE_KEYS:
        raw_value = metadata.get(stack_key)
        if not raw_value:
            continue
        resolved_value, replacements = _resolve_stack_symbols(raw_value, symbol_map)
        if replacements == 0:
            continue
        metadata.setdefault(f"raw_{stack_key}", raw_value)
        metadata[stack_key] = resolved_value
        metadata.setdefault(f"{stack_key}_source", "trace_symbol_map")
        metadata.pop(f"normalized_{stack_key}", None)
        changed = True

    if not changed:
        return event
    return enrich_event(replace(event, metadata=metadata))


def _apply_trace_context_map(event: ObservedEvent, context_map: dict[str, dict[str, str]]) -> ObservedEvent:
    if not context_map:
        return event

    metadata = dict(event.metadata)
    context_keys = _context_lookup_keys(event)
    matched_key = next((key for key in context_keys if key in context_map), None)
    if matched_key is None:
        return event

    merged = dict(context_map[matched_key])
    merged.update(metadata)
    merged.setdefault("context_key", matched_key)
    merged.setdefault("context_source", "trace_context_map")
    return enrich_event(replace(event, metadata=merged))


def _resolve_stack_symbols(raw_value: str, symbol_map: dict[str, str]) -> tuple[str, int]:
    tokens = [token for token in STACK_SPLIT_RE.split(raw_value) if token]
    if not tokens:
        return raw_value, 0

    replacements = 0
    resolved_tokens: list[str] = []
    for token in tokens:
        mapped = symbol_map.get(token)
        if mapped:
            replacements += 1
            resolved_tokens.append(mapped)
        else:
            resolved_tokens.append(token)
    return ">".join(resolved_tokens), replacements


def _context_lookup_keys(event: ObservedEvent) -> list[str]:
    metadata = event.metadata
    candidates = [
        metadata.get("context_key"),
        metadata.get("conn_id"),
        metadata.get("flow_id"),
        metadata.get("socket_id"),
        metadata.get("request_id"),
        metadata.get("trace_id"),
    ]
    seen: set[str] = set()
    ordered: list[str] = []
    for candidate in candidates:
        if candidate and candidate not in seen:
            seen.add(candidate)
            ordered.append(candidate)
    return ordered


def _parse_key_value_payload(line: str) -> dict[str, str]:
    tokens = shlex.split(line)
    payload: dict[str, str] = {}
    for token in tokens:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        payload[key] = value
    return payload
