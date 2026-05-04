from __future__ import annotations

from dataclasses import dataclass

from lsa.core.intent_graph import IntentGraph
from lsa.core.models import IntentGraphSnapshot
from lsa.storage.files import SnapshotRepository
from lsa.storage.models import SnapshotRecord


@dataclass(slots=True)
class IngestResult:
    snapshot: IntentGraphSnapshot
    record: SnapshotRecord | None = None
    snapshot_path: str | None = None


class IngestService:
    def __init__(
        self,
        graph: IntentGraph,
        snapshot_repository: SnapshotRepository,
    ) -> None:
        self.graph = graph
        self.snapshot_repository = snapshot_repository

    def ingest(
        self,
        repo_path: str,
        *,
        persist: bool = True,
        output_path: str | None = None,
        snapshot_id: str | None = None,
    ) -> IngestResult:
        snapshot = self.graph.build_from_path(repo_path)
        record: SnapshotRecord | None = None
        snapshot_path: str | None = None

        if output_path:
            snapshot_path = str(self.graph.save_snapshot(snapshot, output_path))

        if persist:
            record = self.snapshot_repository.save(snapshot, repo_path=repo_path, snapshot_id=snapshot_id)
            if snapshot_path is None:
                snapshot_path = record.snapshot_path

        return IngestResult(snapshot=snapshot, record=record, snapshot_path=snapshot_path)
