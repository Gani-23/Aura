from pathlib import Path
import json
import tempfile
import unittest

from lsa.drift.ebpf_observer import EbpfObserver, ObserverConfig
from lsa.services.trace_collection_service import TraceCollectionRequest, TraceCollectionService
from lsa.settings import resolve_workspace_settings


class EbpfObserverTests(unittest.TestCase):
    def test_collects_trace_lines_from_explicit_command(self) -> None:
        script = Path("tests/fixtures/scripts/emit_trace.sh").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "trace.log"
            observer = EbpfObserver(
                ObserverConfig(
                    command=["/bin/sh", str(script)],
                    output_path=str(output),
                    max_events=10,
                )
            )
            result = observer.collect()

            self.assertEqual(result.line_count, 2)
            self.assertTrue(output.exists())
            self.assertEqual(result.return_code, 0)

    def test_service_defaults_trace_output_into_workspace(self) -> None:
        script = Path("tests/fixtures/scripts/emit_trace.sh").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            service = TraceCollectionService(resolve_workspace_settings(tmpdir))
            result = service.collect(
                TraceCollectionRequest(
                    command=["/bin/sh", str(script)],
                )
            )

            self.assertTrue(Path(result.trace_path).exists())
            self.assertIn("data/traces", result.trace_path)
            self.assertIsNotNone(result.metadata_path)
            metadata = json.loads(Path(result.metadata_path or "").read_text(encoding="utf-8"))
            self.assertIn("collector_session_id", metadata)
            self.assertIn("collector_started_at", metadata)

    def test_service_stages_adjacent_symbol_map_when_present(self) -> None:
        script = Path("tests/fixtures/scripts/emit_symbolized_trace.sh").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            service = TraceCollectionService(resolve_workspace_settings(tmpdir))
            result = service.collect(
                TraceCollectionRequest(
                    command=["/bin/sh", str(script)],
                    program_path=str(script),
                    output_path=str(Path(tmpdir) / "trace.log"),
                )
            )

            self.assertIsNotNone(result.symbol_map_path)
            symbol_payload = json.loads(Path(result.symbol_map_path or "").read_text(encoding="utf-8"))
            self.assertIn("0x4010", symbol_payload["symbols"])
            metadata = json.loads(Path(result.metadata_path or "").read_text(encoding="utf-8"))
            self.assertEqual(metadata["collector_symbol_map_path"], result.symbol_map_path)

    def test_service_extracts_inline_symbol_lines_into_symbol_map(self) -> None:
        script = Path("tests/fixtures/scripts/emit_inline_symbolized_trace.sh").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            service = TraceCollectionService(resolve_workspace_settings(tmpdir))
            result = service.collect(
                TraceCollectionRequest(
                    command=["/bin/sh", str(script)],
                    program_path=str(script),
                    output_path=str(Path(tmpdir) / "trace.log"),
                )
            )

            self.assertEqual(result.line_count, 1)
            self.assertEqual(len(result.lines), 1)
            self.assertTrue(result.lines[0].startswith("event=network"))
            trace_body = Path(result.trace_path).read_text(encoding="utf-8")
            self.assertNotIn("event=symbol", trace_body)
            self.assertIsNotNone(result.symbol_map_path)
            symbol_payload = json.loads(Path(result.symbol_map_path or "").read_text(encoding="utf-8"))
            self.assertEqual(symbol_payload["symbols"]["0x4010"], "app:charge_customer")

    def test_service_extracts_inline_context_lines_into_context_map(self) -> None:
        script = Path("tests/fixtures/scripts/emit_inline_context_trace.sh").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            service = TraceCollectionService(resolve_workspace_settings(tmpdir))
            result = service.collect(
                TraceCollectionRequest(
                    command=["/bin/sh", str(script)],
                    program_path=str(script),
                    output_path=str(Path(tmpdir) / "trace.log"),
                )
            )

            self.assertEqual(result.line_count, 2)
            self.assertTrue(all(line.startswith("event=network") for line in result.lines))
            self.assertIsNotNone(result.context_map_path)
            context_payload = json.loads(Path(result.context_map_path or "").read_text(encoding="utf-8"))
            self.assertIn("conn-1", context_payload["contexts"])
            self.assertNotIn("event=context", Path(result.trace_path).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
