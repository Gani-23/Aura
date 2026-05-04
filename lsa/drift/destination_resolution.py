from __future__ import annotations

import ipaddress
import json
from dataclasses import replace
from pathlib import Path

from lsa.core.models import IntentGraphSnapshot
from lsa.drift.function_resolution import extract_target_host
from lsa.drift.models import ObservedEvent


def load_destination_aliases(path: str | Path) -> dict[str, str]:
    alias_path = Path(path)
    if not alias_path.exists():
        return {}
    payload = json.loads(alias_path.read_text(encoding="utf-8"))
    return {str(key): str(value) for key, value in payload.items()}


def resolve_destination_events(
    snapshot: IntentGraphSnapshot,
    events: list[ObservedEvent],
    alias_map: dict[str, str] | None = None,
) -> list[ObservedEvent]:
    return [resolve_destination_event(snapshot, event, alias_map=alias_map) for event in events]


def resolve_destination_event(
    snapshot: IntentGraphSnapshot,
    event: ObservedEvent,
    *,
    alias_map: dict[str, str] | None = None,
) -> ObservedEvent:
    metadata = dict(event.metadata)
    host = extract_target_host(event.target)
    port = metadata.get("port") or metadata.get("dport") or metadata.get("dest_port")

    resolved_host = _resolve_host_from_metadata(metadata)
    reason = None
    if resolved_host:
        reason = "trace_host_hint"
    else:
        resolved_host = _resolve_host_from_alias_map(alias_map or {}, host, port)
        if resolved_host:
            reason = "alias_map_match"

    if resolved_host and host != resolved_host:
        metadata["resolved_target_host"] = resolved_host
        metadata["target_resolution_reason"] = reason or "resolved"

    known_function = snapshot.functions.get(event.function)
    if known_function and resolved_host and resolved_host in known_function.external_hosts:
        metadata["target_matches_intent_via_alias"] = "true"

    return replace(event, metadata=metadata)


def target_host_candidates(event: ObservedEvent) -> list[str]:
    candidates: list[str] = []
    direct = extract_target_host(event.target)
    if direct:
        candidates.append(direct)

    for key in ("resolved_target_host", "host", "sni", "server_name", "resolved_host"):
        value = event.metadata.get(key)
        if value and value not in candidates:
            candidates.append(value)
    return candidates


def _resolve_host_from_metadata(metadata: dict[str, str]) -> str | None:
    for key in ("host", "sni", "server_name", "resolved_host"):
        value = metadata.get(key)
        if value:
            return value
    return None


def _resolve_host_from_alias_map(alias_map: dict[str, str], host: str | None, port: str | None) -> str | None:
    if not host:
        return None
    candidates = [host]
    if port:
        candidates.insert(0, f"{host}:{port}")
    for candidate in candidates:
        mapped = alias_map.get(candidate)
        if mapped:
            return mapped
    if _looks_like_ip(host):
        return alias_map.get(host)
    return None


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
