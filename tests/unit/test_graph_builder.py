from pathlib import Path
import unittest

from lsa.ingest.graph_builder import GraphBuilder


class GraphBuilderTests(unittest.TestCase):
    def test_builds_snapshot_for_python_service(self) -> None:
        root = Path("tests/fixtures/sample_service").resolve()
        snapshot = GraphBuilder().build(root)

        self.assertGreaterEqual(snapshot.node_count, 2)
        self.assertIn("charge_customer", snapshot.functions)
        self.assertIn("notify_customer", snapshot.functions)


if __name__ == "__main__":
    unittest.main()
