from __future__ import annotations

from pathlib import PurePath
import re

from lsa.drift.models import ObservedEvent


PORT_SERVICE_HINTS = {
    "22": "ssh",
    "53": "dns",
    "80": "http",
    "123": "ntp",
    "1433": "mssql",
    "1521": "oracle",
    "3000": "dev-web",
    "3306": "mysql",
    "443": "https",
    "5432": "postgres",
    "6379": "redis",
    "8080": "http-alt",
    "8443": "https-alt",
    "9200": "elasticsearch",
}

STACK_HINT_KEYS = (
    "stack",
    "call_stack",
    "frames",
    "frame",
    "function_chain",
    "qualname_chain",
    "callsite",
    "code_stack",
)
SYMBOL_HINT_KEYS = ("symbol", "code_symbol", "frame_symbol", "callsite_symbol")
STACK_HINT_SPLIT_RE = re.compile(r"\s*(?:>|[|,;])\s*")
SOURCE_LOCATION_RE = re.compile(r"^(?P<file>.+\.py):(?P<line>\d+)$")
TRACEPARENT_RE = re.compile(
    r"^(?P<version>[0-9a-fA-F]{2})-(?P<trace_id>[0-9a-fA-F]{32})-(?P<span_id>[0-9a-fA-F]{16})-(?P<flags>[0-9a-fA-F]{2})$"
)
B3_RE = re.compile(
    r"^(?P<trace_id>[0-9a-fA-F]{16,32})-(?P<span_id>[0-9a-fA-F]{16})(?:-(?P<sampled>[01dD]))?(?:-(?P<parent_span_id>[0-9a-fA-F]{16}))?$"
)
UBER_TRACE_ID_RE = re.compile(
    r"^(?P<trace_id>[0-9a-fA-F]{16,32}):(?P<span_id>[0-9a-fA-F]{16}):(?P<parent_span_id>[0-9a-fA-F]{16}):(?P<flags>[0-9a-fA-F]{1,2})$"
)


def enrich_event(event: ObservedEvent) -> ObservedEvent:
    metadata = dict(event.metadata)
    _backfill_collection_identity(metadata)
    _derive_trace_context(metadata)
    _derive_symbol_hints(metadata)
    host = metadata.get("host") or metadata.get("daddr") or metadata.get("dest_addr")
    port = metadata.get("port") or metadata.get("dport") or metadata.get("dest_port")

    enriched_target = event.target
    if event.target.startswith("port:") and host:
        enriched_target = f"{host}:{port}" if port else host
    elif host and port and event.target == host:
        enriched_target = f"{host}:{port}"

    if port and "service_hint" not in metadata:
        hint = PORT_SERVICE_HINTS.get(port)
        if hint:
            metadata["service_hint"] = hint

    metadata.setdefault("normalized_target", enriched_target)
    _derive_runtime_correlation(metadata, event.function, enriched_target)
    return ObservedEvent(
        function=event.function,
        event_type=event.event_type,
        target=enriched_target,
        metadata=metadata,
    )


def _backfill_collection_identity(metadata: dict[str, str]) -> None:
    collector_pid = metadata.get("collector_target_pid")
    if collector_pid and "pid" not in metadata:
        metadata["pid"] = collector_pid
        metadata.setdefault("pid_source", "collector_target_pid")


def _derive_trace_context(metadata: dict[str, str]) -> None:
    request_id_source = _first_present_key(
        metadata,
        "request_id",
        "request-id",
        "x-request-id",
        "x_request_id",
        "req_id",
        "requestid",
        "http.request.header.x-request-id",
        "http_request_header_x_request_id",
        "request.header.x-request-id",
        "request_header_x_request_id",
    )
    request_id = _first_present(
        metadata,
        "request_id",
        "request-id",
        "x-request-id",
        "x_request_id",
        "req_id",
        "requestid",
        "http.request.header.x-request-id",
        "http_request_header_x_request_id",
        "request.header.x-request-id",
        "request_header_x_request_id",
    )
    baggage = _first_present(metadata, "baggage", "otel.baggage", "otel_baggage")
    baggage_items = _parse_baggage(baggage) if baggage else {}
    if not request_id:
        baggage_request_id_key = _first_present_mapping_key(
            baggage_items,
            "request_id",
            "request-id",
            "x-request-id",
            "x_request_id",
            "req_id",
            "requestid",
        )
        if baggage_request_id_key:
            request_id = baggage_items[baggage_request_id_key]
            request_id_source = "baggage"
    if request_id:
        metadata.setdefault("request_id", request_id)
        if "request_id_source" not in metadata:
            metadata["request_id_source"] = request_id_source or "request_id"

    trace_id_source = _first_present_key(
        metadata,
        "trace_id",
        "trace-id",
        "otel.trace_id",
        "otel_trace_id",
        "otel.trace.id",
        "otel_trace_id",
        "x-b3-traceid",
        "x_b3_traceid",
        "x-request-trace-id",
    )
    trace_id = _first_present(
        metadata,
        "trace_id",
        "trace-id",
        "otel.trace_id",
        "otel_trace_id",
        "otel.trace.id",
        "otel_trace_id",
        "x-b3-traceid",
        "x_b3_traceid",
        "x-request-trace-id",
    )
    span_id_source = _first_present_key(
        metadata,
        "span_id",
        "span-id",
        "otel.span_id",
        "otel_span_id",
        "otel.span.id",
        "x-b3-spanid",
        "x_b3_spanid",
    )
    span_id = _first_present(
        metadata,
        "span_id",
        "span-id",
        "otel.span_id",
        "otel_span_id",
        "otel.span.id",
        "x-b3-spanid",
        "x_b3_spanid",
    )
    parent_span_id_source = _first_present_key(
        metadata,
        "parent_span_id",
        "parent-span-id",
        "otel.parent_span_id",
        "otel_parent_span_id",
        "otel.parent.span.id",
        "x-b3-parentspanid",
        "x_b3_parentspanid",
    )
    parent_span_id = _first_present(
        metadata,
        "parent_span_id",
        "parent-span-id",
        "otel.parent_span_id",
        "otel_parent_span_id",
        "otel.parent.span.id",
        "x-b3-parentspanid",
        "x_b3_parentspanid",
    )

    traceparent = _first_present(metadata, "traceparent")
    if traceparent:
        parsed = _parse_traceparent(traceparent)
        if parsed:
            trace_id = trace_id or parsed.get("trace_id")
            span_id = span_id or parsed.get("span_id")
            metadata.setdefault("traceparent_source", "traceparent")

    b3_value = _first_present(metadata, "b3")
    if b3_value:
        parsed = _parse_b3(b3_value)
        if parsed:
            trace_id = trace_id or parsed.get("trace_id")
            span_id = span_id or parsed.get("span_id")
            parent_span_id = parent_span_id or parsed.get("parent_span_id")
            metadata.setdefault("b3_source", "b3")

    uber_trace_id = _first_present(metadata, "uber-trace-id", "uber_trace_id")
    if uber_trace_id:
        parsed = _parse_uber_trace_id(uber_trace_id)
        if parsed:
            trace_id = trace_id or parsed.get("trace_id")
            span_id = span_id or parsed.get("span_id")
            parent_span_id = parent_span_id or parsed.get("parent_span_id")
            metadata.setdefault("uber_trace_id_source", "uber-trace-id")

    if trace_id:
        metadata.setdefault("trace_id", trace_id.lower())
        metadata.setdefault(
            "trace_id_source",
            trace_id_source
            or ("traceparent" if traceparent else "b3" if b3_value else "uber-trace-id" if uber_trace_id else "trace_id"),
        )
    if span_id:
        metadata.setdefault("span_id", span_id.lower())
        metadata.setdefault(
            "span_id_source",
            span_id_source
            or ("traceparent" if traceparent else "b3" if b3_value else "uber-trace-id" if uber_trace_id else "span_id"),
        )
    if parent_span_id:
        metadata.setdefault("parent_span_id", parent_span_id.lower())
        metadata.setdefault(
            "parent_span_id_source",
            parent_span_id_source
            or ("b3" if b3_value else "uber-trace-id" if uber_trace_id else "parent_span_id"),
        )


def _derive_runtime_correlation(metadata: dict[str, str], function: str, target: str) -> None:
    process = metadata.get("process") or metadata.get("comm") or function
    pid = metadata.get("pid")
    tid = metadata.get("tid")
    fd = metadata.get("fd")
    collector_session_id = metadata.get("collector_session_id")

    scope = collector_session_id or "runtime"
    if process and pid and fd and "socket_id" not in metadata:
        metadata["socket_id"] = f"{scope}:{process}:{pid}:{fd}"
        metadata.setdefault("socket_id_source", "derived_from_process_pid_fd")

    flow_identity = tid or fd
    if process and pid and flow_identity and "flow_id" not in metadata:
        metadata["flow_id"] = f"{scope}:{process}:{pid}:{flow_identity}:{target}"
        metadata.setdefault("flow_id_source", "derived_from_process_pid_identity_target")


def _derive_symbol_hints(metadata: dict[str, str]) -> None:
    for key in SYMBOL_HINT_KEYS:
        value = metadata.get(key)
        if value:
            _apply_symbol_hint(metadata, value, key)

    for key in STACK_HINT_KEYS:
        value = metadata.get(key)
        if not value:
            continue
        normalized_entries = [_normalize_stack_entry(entry) for entry in STACK_HINT_SPLIT_RE.split(value) if entry]
        normalized_entries = [entry for entry in normalized_entries if entry]
        if normalized_entries:
            metadata.setdefault(f"normalized_{key}", ">".join(normalized_entries))


def _apply_symbol_hint(metadata: dict[str, str], raw_value: str, source_key: str) -> None:
    value = raw_value.strip()
    if not value:
        return

    source_match = SOURCE_LOCATION_RE.match(value)
    if source_match:
        metadata.setdefault("source_file", source_match.group("file"))
        metadata.setdefault("line", source_match.group("line"))
        metadata.setdefault("symbol_hint_source", source_key)
        return

    split = _split_module_function_hint(value)
    if split is None:
        if _looks_like_function_name(value):
            metadata.setdefault("function_name", value)
            metadata.setdefault("symbol_hint_source", source_key)
        return

    module_part, function_name = split
    if module_part.endswith(".py"):
        metadata.setdefault("source_file", module_part)
    else:
        metadata.setdefault("module", _normalize_module_part(module_part))
    metadata.setdefault("function_name", function_name)
    metadata.setdefault("normalized_symbol", _normalize_stack_entry(value))
    metadata.setdefault("symbol_hint_source", source_key)


def _normalize_stack_entry(entry: str) -> str:
    value = entry.strip()
    if not value:
        return value

    source_match = SOURCE_LOCATION_RE.match(value)
    if source_match:
        return f"{source_match.group('file')}:{source_match.group('line')}"

    split = _split_module_function_hint(value)
    if split is None:
        return value

    module_part, function_name = split
    if module_part.endswith(".py"):
        module_hint = _module_hint_from_file(module_part)
        if module_hint:
            return f"{module_hint}.{function_name}"
        return f"{module_part}:{function_name}"
    return f"{_normalize_module_part(module_part)}.{function_name}"


def _split_module_function_hint(value: str) -> tuple[str, str] | None:
    if "://" in value:
        return None
    if "::" in value:
        module_part, function_name = value.rsplit("::", 1)
    elif ":" in value:
        module_part, function_name = value.rsplit(":", 1)
        if function_name.isdigit():
            return None
    elif "." in value:
        module_part, function_name = value.rsplit(".", 1)
    else:
        return None

    if not module_part or not _looks_like_function_name(function_name):
        return None
    return module_part, function_name


def _normalize_module_part(module_part: str) -> str:
    return module_part.replace("/", ".").replace("\\", ".")


def _module_hint_from_file(file_hint: str) -> str | None:
    path = PurePath(file_hint)
    stem = path.stem
    if not stem:
        return None
    parent_parts = [part for part in path.parts[:-1] if part not in ("", ".", "..")]
    pythonish_parts = [stem if stem != "__init__" else ""]
    if parent_parts:
        pythonish_parts = parent_parts + pythonish_parts
    normalized = ".".join(part for part in pythonish_parts if part)
    return normalized or stem


def _looks_like_function_name(value: str) -> bool:
    if not value:
        return False
    return re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", value) is not None


def _first_present(metadata: dict[str, str], *keys: str) -> str | None:
    for key in keys:
        value = metadata.get(key)
        if value:
            return value
    return None


def _first_present_key(metadata: dict[str, str], *keys: str) -> str | None:
    for key in keys:
        value = metadata.get(key)
        if value:
            return key
    return None


def _parse_traceparent(value: str) -> dict[str, str] | None:
    match = TRACEPARENT_RE.match(value.strip())
    if not match:
        return None
    return {
        "trace_id": match.group("trace_id"),
        "span_id": match.group("span_id"),
    }


def _parse_b3(value: str) -> dict[str, str] | None:
    match = B3_RE.match(value.strip())
    if not match:
        return None
    payload = {
        "trace_id": match.group("trace_id"),
        "span_id": match.group("span_id"),
    }
    parent_span_id = match.group("parent_span_id")
    if parent_span_id:
        payload["parent_span_id"] = parent_span_id
    return payload


def _parse_uber_trace_id(value: str) -> dict[str, str] | None:
    match = UBER_TRACE_ID_RE.match(value.strip())
    if not match:
        return None
    return {
        "trace_id": match.group("trace_id"),
        "span_id": match.group("span_id"),
        "parent_span_id": match.group("parent_span_id"),
    }


def _parse_baggage(value: str) -> dict[str, str]:
    items: dict[str, str] = {}
    for part in value.split(","):
        token = part.strip()
        if not token or "=" not in token:
            continue
        key, raw_value = token.split("=", 1)
        key = key.strip()
        entry_value = raw_value.split(";", 1)[0].strip()
        if key and entry_value:
            items[key] = entry_value
    return items


def _first_present_mapping_key(mapping: dict[str, str], *keys: str) -> str | None:
    for key in keys:
        value = mapping.get(key)
        if value:
            return key
    return None
