from __future__ import annotations

import json
from pathlib import Path

from lsa.core.models import IntentGraphSnapshot
from lsa.ingest.graph_builder import GraphBuilder


class IntentGraph:
    def __init__(self, builder: GraphBuilder | None = None) -> None:
        self.builder = builder or GraphBuilder()

    def build_from_path(self, repo_path: str | Path) -> IntentGraphSnapshot:
        return self.builder.build(Path(repo_path))

    def save_snapshot(self, snapshot: IntentGraphSnapshot, destination: str | Path) -> Path:
        destination_path = Path(destination)
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        destination_path.write_text(json.dumps(snapshot.to_dict(), indent=2), encoding="utf-8")
        return destination_path

    def load_snapshot(self, source: str | Path) -> IntentGraphSnapshot:
        source_path = Path(source)
        payload = json.loads(source_path.read_text(encoding="utf-8"))
        return IntentGraphSnapshot.from_dict(payload)
