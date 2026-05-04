from pathlib import Path
import tempfile
import unittest

from lsa.core.intent_graph import IntentGraph
from lsa.services.ingest_service import IngestService
from lsa.settings import resolve_workspace_settings
from lsa.storage.files import SnapshotRepository


class IngestServiceTests(unittest.TestCase):
    def test_explicit_output_path_is_written_even_when_persisting(self) -> None:
        root = Path("tests/fixtures/sample_service").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            settings = resolve_workspace_settings(tmpdir)
            service = IngestService(
                graph=IntentGraph(),
                snapshot_repository=SnapshotRepository(settings, graph=IntentGraph()),
            )
            export_path = Path(tmpdir) / "exports" / "snapshot.json"

            result = service.ingest(
                str(root),
                persist=True,
                output_path=str(export_path),
                snapshot_id="snap-explicit",
            )

            self.assertTrue(export_path.exists())
            self.assertIsNotNone(result.record)
            self.assertEqual(result.record.snapshot_id, "snap-explicit")
            self.assertEqual(result.snapshot_path, str(export_path))


if __name__ == "__main__":
    unittest.main()
