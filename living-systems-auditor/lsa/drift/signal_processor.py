from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from lsa.drift.enrichment import enrich_event
from lsa.drift.models import ObservedEvent
from lsa.drift.trace_parser import load_trace_events


def normalize_target(target: str) -> str:
    if "://" not in target and ":" in target and not target.startswith("port:"):
        return target
    parsed = urlparse(target)
    return parsed.netloc or target


def load_events(source: str | Path) -> list[ObservedEvent]:
    payload = json.loads(Path(source).read_text(encoding="utf-8"))
    return [ObservedEvent.from_dict(item) for item in payload]


def load_any_events(source: str | Path, trace_format: str = "json") -> list[ObservedEvent]:
    if trace_format == "json":
        return load_events(source)
    return load_trace_events(source, trace_format=trace_format)


def normalize_events(events: list[ObservedEvent]) -> list[ObservedEvent]:
    normalized: list[ObservedEvent] = []
    for event in events:
        normalized_event = ObservedEvent(
            function=event.function,
            event_type=event.event_type,
            target=normalize_target(event.target),
            metadata=dict(event.metadata),
        )
        normalized.append(enrich_event(normalized_event))
    return normalized
