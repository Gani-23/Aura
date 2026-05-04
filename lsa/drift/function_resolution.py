from __future__ import annotations

from dataclasses import replace
from pathlib import PurePath
import re

from lsa.core.models import FunctionIntent, IntentGraphSnapshot
from lsa.drift.models import ObservedEvent


STACK_HINT_SPLIT_RE = re.compile(r"\s*(?:>|[|,;])\s*")


def resolve_events(snapshot: IntentGraphSnapshot, events: list[ObservedEvent]) -> list[ObservedEvent]:
    resolved: list[ObservedEvent] = []
    correlation_bindings: dict[str, str] = {}

    for event in events:
        original_binding_keys = correlation_binding_keys(event)
        resolved_event = resolve_event(snapshot, event, correlation_bindings=correlation_bindings)
        resolved.append(resolved_event)
        if resolved_event.function in snapshot.functions:
            for binding_key in original_binding_keys:
                correlation_bindings[binding_key] = resolved_event.function
    return resolved


def resolve_event(
    snapshot: IntentGraphSnapshot,
    event: ObservedEvent,
    *,
    correlation_bindings: dict[str, str] | None = None,
) -> ObservedEvent:
    metadata = dict(event.metadata)
    current_identity = event.function

    if current_identity in snapshot.functions:
        metadata.setdefault("resolved_function", current_identity)
        metadata.setdefault("resolution_reason", "exact_qualname_match")
        return replace(event, metadata=metadata)

    hint_resolved = _resolve_from_trace_hints(snapshot, event)
    if hint_resolved is not None:
        return hint_resolved

    if correlation_bindings:
        for binding_key in correlation_binding_keys(event):
            if binding_key in correlation_bindings:
                bound_function = snapshot.functions.get(correlation_bindings[binding_key])
                if bound_function is not None:
                    reason = _binding_reason(binding_key)
                    return _resolved_event(event, bound_function, reason)

    name_candidates = _find_name_candidates(snapshot, event)
    if len(name_candidates) == 1:
        return _resolved_event(event, name_candidates[0], "name_or_process_match")

    host_candidates = _find_target_host_candidates(snapshot, event)
    if len(host_candidates) == 1:
        return _resolved_event(event, host_candidates[0], "unique_target_host_match")

    overlap_candidates = [candidate for candidate in host_candidates if candidate in name_candidates]
    if len(overlap_candidates) == 1:
        return _resolved_event(event, overlap_candidates[0], "target_and_process_overlap")

    metadata.setdefault("resolved_function", current_identity)
    metadata.setdefault("resolution_reason", "unresolved")
    return replace(event, metadata=metadata)


def _resolved_event(event: ObservedEvent, function: FunctionIntent, reason: str) -> ObservedEvent:
    metadata = dict(event.metadata)
    metadata["original_function"] = event.function
    metadata["resolved_function"] = function.qualname
    metadata["resolution_reason"] = reason
    return replace(event, function=function.qualname, metadata=metadata)


def _resolve_from_trace_hints(
    snapshot: IntentGraphSnapshot,
    event: ObservedEvent,
) -> ObservedEvent | None:
    metadata = event.metadata

    stack_resolved = _resolve_from_stack_hints(snapshot, event)
    if stack_resolved is not None:
        return stack_resolved

    qualname_hint = (
        metadata.get("qualname")
        or metadata.get("function_qualname")
        or metadata.get("resolved_function_hint")
    )
    if qualname_hint:
        hinted = snapshot.functions.get(qualname_hint)
        if hinted is not None:
            return _resolved_event(event, hinted, "trace_qualname_hint")

    name_hint = (
        metadata.get("function_name")
        or metadata.get("function_hint")
        or metadata.get("code_function")
        or metadata.get("symbol")
    )
    module_hint = metadata.get("module") or metadata.get("code_module")
    if name_hint and module_hint:
        candidates = [
            function
            for function in snapshot.functions.values()
            if function.name == name_hint and _module_matches_hint(function.module, module_hint)
        ]
        if len(candidates) == 1:
            return _resolved_event(event, candidates[0], "trace_module_function_hint")

    file_hint = metadata.get("source_file") or metadata.get("file") or metadata.get("filename")
    line_hint = metadata.get("line") or metadata.get("lineno")
    if file_hint and line_hint and line_hint.isdigit():
        candidates = _find_source_location_candidates(snapshot, file_hint, int(line_hint))
        if len(candidates) == 1:
            return _resolved_event(event, candidates[0], "trace_source_location_hint")

    if name_hint and not module_hint:
        candidates = [function for function in snapshot.functions.values() if function.name == name_hint]
        if len(candidates) == 1:
            return _resolved_event(event, candidates[0], "trace_function_name_hint")

    return None


def _find_name_candidates(snapshot: IntentGraphSnapshot, event: ObservedEvent) -> list[FunctionIntent]:
    labels = {event.function.lower()}
    for key in ("process", "comm"):
        value = event.metadata.get(key)
        if value:
            labels.add(value.lower())

    candidates: list[FunctionIntent] = []
    for function in snapshot.functions.values():
        haystacks = {
            function.name.lower(),
            function.qualname.lower(),
            function.module.lower(),
            function.module.split(".")[-1].lower(),
        }
        if labels & haystacks:
            candidates.append(function)
    return candidates


def _resolve_from_stack_hints(
    snapshot: IntentGraphSnapshot,
    event: ObservedEvent,
) -> ObservedEvent | None:
    for index, hint in enumerate(_trace_stack_hints(event.metadata)):
        exact = snapshot.functions.get(hint)
        if exact is not None:
            return _resolved_event_with_trace_hint(
                event,
                exact,
                "trace_stack_qualname_hint",
                hint,
                index,
            )

        module_function = _match_module_function_hint(snapshot, hint)
        if len(module_function) == 1:
            return _resolved_event_with_trace_hint(
                event,
                module_function[0],
                "trace_stack_module_function_hint",
                hint,
                index,
            )

        source_location = _match_source_location_hint(snapshot, hint)
        if len(source_location) == 1:
            return _resolved_event_with_trace_hint(
                event,
                source_location[0],
                "trace_stack_source_location_hint",
                hint,
                index,
            )

        function_name = _match_function_name_hint(snapshot, hint)
        if len(function_name) == 1:
            return _resolved_event_with_trace_hint(
                event,
                function_name[0],
                "trace_stack_function_name_hint",
                hint,
                index,
            )

    return None


def _find_source_location_candidates(
    snapshot: IntentGraphSnapshot,
    file_hint: str,
    line_number: int,
) -> list[FunctionIntent]:
    module_hint = _module_hint_from_file(file_hint)
    if module_hint is None:
        return []

    return [
        function
        for function in snapshot.functions.values()
        if _module_matches_hint(function.module, module_hint)
        and function.lineno <= line_number <= function.end_lineno
    ]


def _match_source_location_hint(
    snapshot: IntentGraphSnapshot,
    hint: str,
) -> list[FunctionIntent]:
    if ":" not in hint:
        return []
    file_hint, line_hint = hint.rsplit(":", 1)
    if not line_hint.isdigit():
        return []
    return _find_source_location_candidates(snapshot, file_hint, int(line_hint))


def _find_target_host_candidates(snapshot: IntentGraphSnapshot, event: ObservedEvent) -> list[FunctionIntent]:
    host = extract_target_host(event.target)
    if host is None:
        return []
    return [
        function
        for function in snapshot.functions.values()
        if host in function.external_hosts
    ]


def extract_target_host(target: str) -> str | None:
    if target.startswith("port:"):
        return None
    if "://" in target:
        return target.split("://", 1)[1].split("/", 1)[0]
    if ":" in target:
        return target.rsplit(":", 1)[0]
    return target


def _process_binding_key(event: ObservedEvent) -> str | None:
    process = event.metadata.get("process") or event.metadata.get("comm") or event.function
    if not process:
        return None
    pid = event.metadata.get("pid")
    if pid:
        return f"{process}:{pid}"
    return process


def correlation_binding_keys(event: ObservedEvent) -> list[str]:
    keys: list[str] = []
    metadata = event.metadata

    for field in ("request_id", "trace_id", "span_id", "conn_id", "socket_id", "flow_id"):
        value = metadata.get(field)
        if value:
            keys.append(f"{field}:{value}")

    process = metadata.get("process") or metadata.get("comm") or event.function
    pid = metadata.get("pid")
    tid = metadata.get("tid")
    fd = metadata.get("fd")

    if process and pid and fd:
        keys.append(f"process-pid-fd:{process}:{pid}:{fd}")
    if process and pid and tid:
        keys.append(f"process-pid-tid:{process}:{pid}:{tid}")

    process_key = _process_binding_key(event)
    if process_key:
        keys.append(f"process:{process_key}")

    # preserve order while removing duplicates
    seen: set[str] = set()
    ordered: list[str] = []
    for key in keys:
        if key not in seen:
            seen.add(key)
            ordered.append(key)
    return ordered


def _binding_reason(binding_key: str) -> str:
    if binding_key.startswith(("request_id:", "trace_id:", "span_id:", "conn_id:", "socket_id:", "flow_id:")):
        return "correlation_binding_inheritance"
    return "process_binding_inheritance"


def _resolved_event_with_trace_hint(
    event: ObservedEvent,
    function: FunctionIntent,
    reason: str,
    hint: str,
    hint_index: int,
) -> ObservedEvent:
    resolved = _resolved_event(event, function, reason)
    metadata = dict(resolved.metadata)
    metadata["trace_hint_value"] = hint
    metadata["trace_hint_index"] = str(hint_index)
    return replace(resolved, metadata=metadata)


def _trace_stack_hints(metadata: dict[str, str]) -> list[str]:
    hints: list[str] = []
    for key in (
        "normalized_stack",
        "stack",
        "normalized_call_stack",
        "call_stack",
        "normalized_frames",
        "frames",
        "normalized_frame",
        "frame",
        "normalized_function_chain",
        "function_chain",
        "normalized_qualname_chain",
        "qualname_chain",
        "normalized_callsite",
        "callsite",
        "normalized_code_stack",
        "code_stack",
    ):
        value = metadata.get(key)
        if not value:
            continue
        for item in STACK_HINT_SPLIT_RE.split(value):
            stripped = item.strip()
            if stripped and stripped not in hints:
                hints.append(stripped)
    return hints


def _match_module_function_hint(
    snapshot: IntentGraphSnapshot,
    hint: str,
) -> list[FunctionIntent]:
    split = _split_module_function_hint(hint)
    if split is None:
        return []
    module_hint, function_name = split
    return [
        function
        for function in snapshot.functions.values()
        if function.name == function_name and _module_matches_hint(function.module, module_hint)
    ]


def _match_function_name_hint(
    snapshot: IntentGraphSnapshot,
    hint: str,
) -> list[FunctionIntent]:
    if any(char in hint for char in ("/", "\\", ":")):
        return []
    return [function for function in snapshot.functions.values() if function.name == hint]


def _split_module_function_hint(hint: str) -> tuple[str, str] | None:
    if "://" in hint:
        return None
    if "::" in hint:
        module_hint, function_name = hint.rsplit("::", 1)
    elif ":" in hint:
        module_hint, function_name = hint.rsplit(":", 1)
        if function_name.isdigit():
            return None
    elif "." in hint:
        module_hint, function_name = hint.rsplit(".", 1)
    else:
        return None

    if not module_hint or not function_name:
        return None
    return module_hint, function_name


def _module_matches_hint(module_name: str, module_hint: str) -> bool:
    normalized_module = module_name.lower()
    normalized_hint = module_hint.lower().replace("/", ".").replace("\\", ".")
    return normalized_module == normalized_hint or normalized_module.endswith(f".{normalized_hint}")


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
