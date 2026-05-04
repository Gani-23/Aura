from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest

from lsa.cli import main as cli_main
from lsa.drift.function_resolution import resolve_events
from lsa.drift.trace_parser import load_trace_events, parse_trace_line
from lsa.settings import resolve_workspace_settings


class TraceParserTests(unittest.TestCase):
    def test_parses_key_value_trace(self) -> None:
        events = load_trace_events(Path("tests/fixtures/sample_trace.log").resolve(), trace_format="auto")
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].function, "charge_customer")
        self.assertEqual(events[1].target, "https://malicious.example.com/exfil")

    def test_parses_raw_bpftrace_line(self) -> None:
        event = parse_trace_line("CONNECT python 443", trace_format="auto")
        assert event is not None
        self.assertEqual(event.function, "python")
        self.assertEqual(event.target, "port:443")
        self.assertEqual(event.metadata["source"], "bpftrace_raw_connect")
        self.assertEqual(event.metadata["service_hint"], "https")

    def test_parses_structured_bpftrace_line(self) -> None:
        events = load_trace_events(
            Path("tests/fixtures/structured_bpftrace_trace.log").resolve(),
            trace_format="auto",
        )
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].target, "93.184.216.34:443")
        self.assertEqual(events[0].metadata["process"], "python")
        self.assertEqual(events[0].metadata["tid"], "4242")
        self.assertEqual(events[0].metadata["fd"], "9")
        self.assertIn("socket_id", events[0].metadata)
        self.assertIn("flow_id", events[0].metadata)
        self.assertEqual(events[0].metadata["service_hint"], "https")
        self.assertEqual(events[1].target, "10.0.0.5:8080")
        self.assertEqual(events[1].metadata["process"], "billing-worker")
        self.assertEqual(events[1].metadata["service_hint"], "http-alt")

    def test_load_trace_events_merges_sidecar_trace_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            trace_path = Path(tmpdir) / "trace.log"
            trace_path.write_text(
                "event=network process=python target=https://api.stripe.com/v1/charges\n",
                encoding="utf-8",
            )
            trace_meta_path = trace_path.with_name("trace.log.meta.json")
            trace_meta_path.write_text(
                json.dumps(
                    {
                        "collector_session_id": "sess-123",
                        "collector_target_pid": "4242",
                        "collector_command": "/bin/sh observer.sh",
                    }
                ),
                encoding="utf-8",
            )

            events = load_trace_events(trace_path, trace_format="auto")

            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].metadata["collector_session_id"], "sess-123")
            self.assertEqual(events[0].metadata["collector_target_pid"], "4242")
            self.assertEqual(events[0].metadata["collector_command"], "/bin/sh observer.sh")
            self.assertEqual(events[0].metadata["pid"], "4242")
            self.assertEqual(events[0].metadata["pid_source"], "collector_target_pid")

    def test_keeps_process_metadata_when_function_is_derived(self) -> None:
        event = parse_trace_line(
            "event=network process=python comm=python target=https://api.stripe.com/v1/charges",
            trace_format="auto",
        )
        assert event is not None
        self.assertEqual(event.function, "python")
        self.assertEqual(event.metadata["process"], "python")
        self.assertEqual(event.metadata["comm"], "python")
        self.assertEqual(event.metadata["derived_function_from"], "process")

    def test_derives_canonical_hints_from_raw_symbol_metadata(self) -> None:
        event = parse_trace_line(
            "event=network process=python symbol=app:charge_customer target=https://malicious.example.com/exfil",
            trace_format="auto",
        )
        assert event is not None
        self.assertEqual(event.metadata["module"], "app")
        self.assertEqual(event.metadata["function_name"], "charge_customer")
        self.assertEqual(event.metadata["normalized_symbol"], "app.charge_customer")
        self.assertEqual(event.metadata["symbol_hint_source"], "symbol")

    def test_derives_canonical_trace_fields_from_traceparent(self) -> None:
        event = parse_trace_line(
            "event=network process=python "
            "traceparent=00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01 "
            "target=https://api.stripe.com/v1/charges",
            trace_format="auto",
        )
        assert event is not None
        self.assertEqual(event.metadata["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736")
        self.assertEqual(event.metadata["span_id"], "00f067aa0ba902b7")
        self.assertEqual(event.metadata["trace_id_source"], "traceparent")
        self.assertEqual(event.metadata["span_id_source"], "traceparent")

    def test_derives_canonical_trace_fields_from_b3(self) -> None:
        event = parse_trace_line(
            "event=network process=python "
            "b3=4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-1-a2fb4a1d1a96d312 "
            "target=https://api.stripe.com/v1/charges",
            trace_format="auto",
        )
        assert event is not None
        self.assertEqual(event.metadata["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736")
        self.assertEqual(event.metadata["span_id"], "00f067aa0ba902b7")
        self.assertEqual(event.metadata["parent_span_id"], "a2fb4a1d1a96d312")
        self.assertEqual(event.metadata["trace_id_source"], "b3")

    def test_derives_request_id_from_common_header_name(self) -> None:
        event = parse_trace_line(
            "event=network process=python x-request-id=req-123 "
            "target=https://api.stripe.com/v1/charges",
            trace_format="auto",
        )
        assert event is not None
        self.assertEqual(event.metadata["request_id"], "req-123")
        self.assertEqual(event.metadata["request_id_source"], "x-request-id")

    def test_derives_trace_fields_from_otel_attribute_names(self) -> None:
        event = parse_trace_line(
            "event=network process=python "
            "otel.trace_id=4bf92f3577b34da6a3ce929d0e0e4736 "
            "otel.span_id=00f067aa0ba902b7 "
            "otel.parent_span_id=a2fb4a1d1a96d312 "
            "target=https://api.stripe.com/v1/charges",
            trace_format="auto",
        )
        assert event is not None
        self.assertEqual(event.metadata["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736")
        self.assertEqual(event.metadata["span_id"], "00f067aa0ba902b7")
        self.assertEqual(event.metadata["parent_span_id"], "a2fb4a1d1a96d312")
        self.assertEqual(event.metadata["trace_id_source"], "otel.trace_id")
        self.assertEqual(event.metadata["span_id_source"], "otel.span_id")

    def test_derives_trace_fields_from_uber_trace_id(self) -> None:
        event = parse_trace_line(
            "event=network process=python "
            "uber-trace-id=4bf92f3577b34da6:00f067aa0ba902b7:a2fb4a1d1a96d312:1 "
            "target=https://api.stripe.com/v1/charges",
            trace_format="auto",
        )
        assert event is not None
        self.assertEqual(event.metadata["trace_id"], "4bf92f3577b34da6")
        self.assertEqual(event.metadata["span_id"], "00f067aa0ba902b7")
        self.assertEqual(event.metadata["parent_span_id"], "a2fb4a1d1a96d312")
        self.assertEqual(event.metadata["trace_id_source"], "uber-trace-id")

    def test_derives_request_id_from_baggage(self) -> None:
        event = parse_trace_line(
            "event=network process=python baggage=request_id=req-123,tenant=acme "
            "target=https://api.stripe.com/v1/charges",
            trace_format="auto",
        )
        assert event is not None
        self.assertEqual(event.metadata["request_id"], "req-123")
        self.assertEqual(event.metadata["request_id_source"], "baggage")

    def test_normalizes_raw_stack_symbol_metadata(self) -> None:
        event = parse_trace_line(
            "event=network process=python stack=worker_loop>app:charge_customer>requests.post "
            "target=https://malicious.example.com/exfil",
            trace_format="auto",
        )
        assert event is not None
        self.assertEqual(
            event.metadata["normalized_stack"],
            "worker_loop>app.charge_customer>requests.post",
        )

    def test_load_trace_events_resolves_single_address_via_symbol_map(self) -> None:
        events = load_trace_events(
            Path("tests/fixtures/address_symbol_trace.log").resolve(),
            trace_format="auto",
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].metadata["symbol"], "app:charge_customer")
        self.assertEqual(events[0].metadata["module"], "app")
        self.assertEqual(events[0].metadata["function_name"], "charge_customer")
        self.assertEqual(events[0].metadata["symbol_address"], "0x4010")
        self.assertEqual(events[0].metadata["symbol_source"], "trace_symbol_map")

    def test_load_trace_events_resolves_inline_symbol_lines(self) -> None:
        events = load_trace_events(
            Path("tests/fixtures/inline_symbol_trace.log").resolve(),
            trace_format="auto",
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].function, "python")
        self.assertEqual(events[0].metadata["symbol"], "app:charge_customer")
        self.assertEqual(events[0].metadata["symbol_address"], "0x4010")
        self.assertEqual(events[0].metadata["module"], "app")
        self.assertEqual(events[0].metadata["function_name"], "charge_customer")

    def test_load_trace_events_resolves_stack_addresses_via_symbol_map(self) -> None:
        events = load_trace_events(
            Path("tests/fixtures/address_stack_trace.log").resolve(),
            trace_format="auto",
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].metadata["raw_stack"], "0x1000>0x4010>0x7777")
        self.assertEqual(events[0].metadata["stack"], "worker_loop>app:charge_customer>requests.post")
        self.assertEqual(
            events[0].metadata["normalized_stack"],
            "worker_loop>app.charge_customer>requests.post",
        )
        self.assertEqual(events[0].metadata["stack_source"], "trace_symbol_map")

    def test_load_trace_events_resolves_inline_symbol_stack_lines(self) -> None:
        events = load_trace_events(
            Path("tests/fixtures/inline_symbol_stack_trace.log").resolve(),
            trace_format="auto",
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].function, "python")
        self.assertEqual(
            events[0].metadata["normalized_stack"],
            "worker_loop>app.charge_customer>requests.post",
        )

    def test_load_trace_events_joins_context_sidecar(self) -> None:
        events = load_trace_events(
            Path("tests/fixtures/context_correlated_trace.log").resolve(),
            trace_format="auto",
        )
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].metadata["context_key"], "conn-1")
        self.assertEqual(events[0].metadata["context_source"], "trace_context_map")
        self.assertEqual(events[0].metadata["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736")
        self.assertEqual(events[0].metadata["request_id"], "req-123")

    def test_load_trace_events_joins_inline_context_lines(self) -> None:
        events = load_trace_events(
            Path("tests/fixtures/inline_context_correlated_trace.log").resolve(),
            trace_format="auto",
        )
        self.assertEqual(len(events), 2)
        self.assertEqual(events[1].metadata["context_key"], "conn-1")
        self.assertEqual(events[1].metadata["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736")
        self.assertEqual(events[1].metadata["request_id"], "req-123")

    def test_traceparent_normalization_supports_correlation_resolution(self) -> None:
        root = Path("tests/fixtures/sample_service").resolve()
        events = load_trace_events(
            Path("tests/fixtures/traceparent_correlated_trace.log").resolve(),
            trace_format="auto",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.snapshot_repository = cli_main.SnapshotRepository(cli_main.settings, graph=cli_main.graph)
            cli_main.ingest_service = cli_main.IngestService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
            )
            cli_main.run_ingest(str(root), None, persist=True, snapshot_id="traceparent-snapshot")
            snapshot_record = cli_main.snapshot_repository.get("traceparent-snapshot")
            snapshot = cli_main.graph.load_snapshot(snapshot_record.snapshot_path)

            resolved = resolve_events(snapshot, events)

            self.assertEqual(resolved[1].function, "charge_customer")
            self.assertEqual(
                resolved[1].metadata["resolution_reason"],
                "correlation_binding_inheritance",
            )

    def test_otel_trace_fields_support_correlation_resolution(self) -> None:
        root = Path("tests/fixtures/sample_service").resolve()
        events = load_trace_events(
            Path("tests/fixtures/otel_baggage_correlated_trace.log").resolve(),
            trace_format="auto",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.snapshot_repository = cli_main.SnapshotRepository(cli_main.settings, graph=cli_main.graph)
            cli_main.ingest_service = cli_main.IngestService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
            )
            cli_main.run_ingest(str(root), None, persist=True, snapshot_id="otel-snapshot")
            snapshot_record = cli_main.snapshot_repository.get("otel-snapshot")
            snapshot = cli_main.graph.load_snapshot(snapshot_record.snapshot_path)

            resolved = resolve_events(snapshot, events)

            self.assertEqual(resolved[1].function, "charge_customer")
            self.assertEqual(resolved[1].metadata["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736")
            self.assertEqual(resolved[1].metadata["request_id"], "req-123")
            self.assertEqual(
                resolved[1].metadata["resolution_reason"],
                "correlation_binding_inheritance",
            )

    def test_context_map_supports_correlation_resolution(self) -> None:
        root = Path("tests/fixtures/sample_service").resolve()
        events = load_trace_events(
            Path("tests/fixtures/context_correlated_trace.log").resolve(),
            trace_format="auto",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.snapshot_repository = cli_main.SnapshotRepository(cli_main.settings, graph=cli_main.graph)
            cli_main.ingest_service = cli_main.IngestService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
            )
            cli_main.run_ingest(str(root), None, persist=True, snapshot_id="context-snapshot")
            snapshot_record = cli_main.snapshot_repository.get("context-snapshot")
            snapshot = cli_main.graph.load_snapshot(snapshot_record.snapshot_path)

            resolved = resolve_events(snapshot, events)

            self.assertEqual(resolved[1].function, "charge_customer")
            self.assertEqual(resolved[1].metadata["request_id"], "req-123")
            self.assertEqual(
                resolved[1].metadata["resolution_reason"],
                "correlation_binding_inheritance",
            )

    def test_cli_audit_trace_flow(self) -> None:
        root = Path("tests/fixtures/sample_service").resolve()
        trace = Path("tests/fixtures/sample_trace.log").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.snapshot_repository = cli_main.SnapshotRepository(cli_main.settings, graph=cli_main.graph)
            cli_main.audit_repository = cli_main.AuditRepository(cli_main.settings)
            cli_main.ingest_service = cli_main.IngestService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
            )
            cli_main.audit_service = cli_main.AuditService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
                audit_repository=cli_main.audit_repository,
                drift_comparator=cli_main.DriftComparator(),
                remediation_client=cli_main.RuleBasedLLMClient(),
                settings=cli_main.settings,
            )

            sink = StringIO()
            with redirect_stdout(sink):
                cli_main.run_ingest(str(root), None, persist=True, snapshot_id="trace-snapshot")
                exit_code = cli_main.run_audit_trace(
                    "trace-snapshot",
                    str(trace),
                    snapshot_is_id=True,
                    trace_format="auto",
                    out_dir=None,
                    persist=True,
                    audit_id="trace-audit",
                )

            self.assertEqual(exit_code, 0)
            stored = cli_main.audit_repository.get("trace-audit")
            self.assertEqual(stored.alert_count, 1)

    def test_cli_audit_trace_resolves_process_identity(self) -> None:
        root = Path("tests/fixtures/sample_service").resolve()
        trace = Path("tests/fixtures/process_only_trace.log").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.snapshot_repository = cli_main.SnapshotRepository(cli_main.settings, graph=cli_main.graph)
            cli_main.audit_repository = cli_main.AuditRepository(cli_main.settings)
            cli_main.ingest_service = cli_main.IngestService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
            )
            cli_main.audit_service = cli_main.AuditService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
                audit_repository=cli_main.audit_repository,
                drift_comparator=cli_main.DriftComparator(),
                remediation_client=cli_main.RuleBasedLLMClient(),
                settings=cli_main.settings,
            )

            sink = StringIO()
            with redirect_stdout(sink):
                cli_main.run_ingest(str(root), None, persist=True, snapshot_id="resolved-snapshot")
                exit_code = cli_main.run_audit_trace(
                    "resolved-snapshot",
                    str(trace),
                    snapshot_is_id=True,
                    trace_format="auto",
                    out_dir=None,
                    persist=True,
                    audit_id="resolved-audit",
                )

            self.assertEqual(exit_code, 0)
            stored = cli_main.audit_repository.get("resolved-audit")
            self.assertEqual(stored.alert_count, 1)
            self.assertEqual(stored.events[0]["function"], "charge_customer")
            self.assertEqual(stored.events[0]["metadata"]["original_function"], "python")

    def test_cli_audit_trace_uses_request_correlation(self) -> None:
        root = Path("tests/fixtures/sample_service").resolve()
        trace = Path("tests/fixtures/correlated_trace.log").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.snapshot_repository = cli_main.SnapshotRepository(cli_main.settings, graph=cli_main.graph)
            cli_main.audit_repository = cli_main.AuditRepository(cli_main.settings)
            cli_main.ingest_service = cli_main.IngestService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
            )
            cli_main.audit_service = cli_main.AuditService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
                audit_repository=cli_main.audit_repository,
                drift_comparator=cli_main.DriftComparator(),
                remediation_client=cli_main.RuleBasedLLMClient(),
                settings=cli_main.settings,
            )

            sink = StringIO()
            with redirect_stdout(sink):
                cli_main.run_ingest(str(root), None, persist=True, snapshot_id="correlated-snapshot")
                exit_code = cli_main.run_audit_trace(
                    "correlated-snapshot",
                    str(trace),
                    snapshot_is_id=True,
                    trace_format="auto",
                    out_dir=None,
                    persist=True,
                    audit_id="correlated-audit",
                )

            self.assertEqual(exit_code, 0)
            stored = cli_main.audit_repository.get("correlated-audit")
            self.assertEqual(stored.events[1]["function"], "charge_customer")
            self.assertEqual(
                stored.events[1]["metadata"]["resolution_reason"],
                "correlation_binding_inheritance",
            )

    def test_cli_audit_trace_uses_traceparent_correlation(self) -> None:
        root = Path("tests/fixtures/sample_service").resolve()
        trace = Path("tests/fixtures/traceparent_correlated_trace.log").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.snapshot_repository = cli_main.SnapshotRepository(cli_main.settings, graph=cli_main.graph)
            cli_main.audit_repository = cli_main.AuditRepository(cli_main.settings)
            cli_main.ingest_service = cli_main.IngestService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
            )
            cli_main.audit_service = cli_main.AuditService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
                audit_repository=cli_main.audit_repository,
                drift_comparator=cli_main.DriftComparator(),
                remediation_client=cli_main.RuleBasedLLMClient(),
                settings=cli_main.settings,
            )

            sink = StringIO()
            with redirect_stdout(sink):
                cli_main.run_ingest(str(root), None, persist=True, snapshot_id="traceparent-snapshot")
                exit_code = cli_main.run_audit_trace(
                    "traceparent-snapshot",
                    str(trace),
                    snapshot_is_id=True,
                    trace_format="auto",
                    out_dir=None,
                    persist=True,
                    audit_id="traceparent-audit",
                )

            self.assertEqual(exit_code, 0)
            stored = cli_main.audit_repository.get("traceparent-audit")
            self.assertEqual(stored.events[1]["function"], "charge_customer")
            self.assertEqual(stored.events[1]["metadata"]["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736")
            self.assertEqual(
                stored.events[1]["metadata"]["resolution_reason"],
                "correlation_binding_inheritance",
            )

    def test_cli_audit_trace_uses_otel_and_baggage_correlation(self) -> None:
        root = Path("tests/fixtures/sample_service").resolve()
        trace = Path("tests/fixtures/otel_baggage_correlated_trace.log").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.snapshot_repository = cli_main.SnapshotRepository(cli_main.settings, graph=cli_main.graph)
            cli_main.audit_repository = cli_main.AuditRepository(cli_main.settings)
            cli_main.ingest_service = cli_main.IngestService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
            )
            cli_main.audit_service = cli_main.AuditService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
                audit_repository=cli_main.audit_repository,
                drift_comparator=cli_main.DriftComparator(),
                remediation_client=cli_main.RuleBasedLLMClient(),
                settings=cli_main.settings,
            )

            sink = StringIO()
            with redirect_stdout(sink):
                cli_main.run_ingest(str(root), None, persist=True, snapshot_id="otel-snapshot")
                exit_code = cli_main.run_audit_trace(
                    "otel-snapshot",
                    str(trace),
                    snapshot_is_id=True,
                    trace_format="auto",
                    out_dir=None,
                    persist=True,
                    audit_id="otel-audit",
                )

            self.assertEqual(exit_code, 0)
            stored = cli_main.audit_repository.get("otel-audit")
            self.assertEqual(stored.events[1]["function"], "charge_customer")
            self.assertEqual(stored.events[1]["metadata"]["trace_id_source"], "otel.trace_id")
            self.assertEqual(stored.events[1]["metadata"]["request_id_source"], "baggage")
            self.assertEqual(
                stored.events[1]["metadata"]["resolution_reason"],
                "correlation_binding_inheritance",
            )

    def test_cli_audit_trace_uses_context_map_correlation(self) -> None:
        root = Path("tests/fixtures/sample_service").resolve()
        trace = Path("tests/fixtures/context_correlated_trace.log").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.snapshot_repository = cli_main.SnapshotRepository(cli_main.settings, graph=cli_main.graph)
            cli_main.audit_repository = cli_main.AuditRepository(cli_main.settings)
            cli_main.ingest_service = cli_main.IngestService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
            )
            cli_main.audit_service = cli_main.AuditService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
                audit_repository=cli_main.audit_repository,
                drift_comparator=cli_main.DriftComparator(),
                remediation_client=cli_main.RuleBasedLLMClient(),
                settings=cli_main.settings,
            )

            sink = StringIO()
            with redirect_stdout(sink):
                cli_main.run_ingest(str(root), None, persist=True, snapshot_id="context-snapshot")
                exit_code = cli_main.run_audit_trace(
                    "context-snapshot",
                    str(trace),
                    snapshot_is_id=True,
                    trace_format="auto",
                    out_dir=None,
                    persist=True,
                    audit_id="context-audit",
                )

            self.assertEqual(exit_code, 0)
            stored = cli_main.audit_repository.get("context-audit")
            self.assertEqual(stored.events[1]["function"], "charge_customer")
            self.assertEqual(stored.events[1]["metadata"]["context_source"], "trace_context_map")
            self.assertEqual(
                stored.events[1]["metadata"]["resolution_reason"],
                "correlation_binding_inheritance",
            )

    def test_cli_collect_audit_flow(self) -> None:
        root = Path("tests/fixtures/sample_service").resolve()
        script = Path("tests/fixtures/scripts/emit_process_trace.sh").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.snapshot_repository = cli_main.SnapshotRepository(cli_main.settings, graph=cli_main.graph)
            cli_main.audit_repository = cli_main.AuditRepository(cli_main.settings)
            cli_main.ingest_service = cli_main.IngestService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
            )
            cli_main.audit_service = cli_main.AuditService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
                audit_repository=cli_main.audit_repository,
                drift_comparator=cli_main.DriftComparator(),
                remediation_client=cli_main.RuleBasedLLMClient(),
                settings=cli_main.settings,
            )
            cli_main.trace_collection_service = cli_main.TraceCollectionService(settings=cli_main.settings)

            sink = StringIO()
            with redirect_stdout(sink):
                cli_main.run_ingest(str(root), None, persist=True, snapshot_id="collect-snapshot")
                exit_code = cli_main.run_collect_audit(
                    "collect-snapshot",
                    1234,
                    snapshot_is_id=True,
                    program=str(script),
                    duration=None,
                    max_events=10,
                    trace_format="auto",
                    output_path=str(Path(tmpdir) / "collected.log"),
                    persist=True,
                    audit_id="collect-audit",
                )

            self.assertEqual(exit_code, 0)
            stored = cli_main.audit_repository.get("collect-audit")
            self.assertEqual(stored.alert_count, 1)
            self.assertEqual(stored.events[0]["function"], "charge_customer")
            self.assertIn("collector_session_id", stored.events[0]["metadata"])
            self.assertEqual(stored.events[0]["metadata"]["collector_target_pid"], "1234")

    def test_cli_collect_audit_uses_staged_symbol_map(self) -> None:
        root = Path("tests/fixtures/sample_service").resolve()
        script = Path("tests/fixtures/scripts/emit_symbolized_trace.sh").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.snapshot_repository = cli_main.SnapshotRepository(cli_main.settings, graph=cli_main.graph)
            cli_main.audit_repository = cli_main.AuditRepository(cli_main.settings)
            cli_main.ingest_service = cli_main.IngestService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
            )
            cli_main.audit_service = cli_main.AuditService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
                audit_repository=cli_main.audit_repository,
                drift_comparator=cli_main.DriftComparator(),
                remediation_client=cli_main.RuleBasedLLMClient(),
                settings=cli_main.settings,
            )
            cli_main.trace_collection_service = cli_main.TraceCollectionService(settings=cli_main.settings)

            sink = StringIO()
            with redirect_stdout(sink):
                cli_main.run_ingest(str(root), None, persist=True, snapshot_id="collect-symbol-snapshot")
                exit_code = cli_main.run_collect_audit(
                    "collect-symbol-snapshot",
                    1234,
                    snapshot_is_id=True,
                    program=str(script),
                    duration=None,
                    max_events=10,
                    trace_format="auto",
                    output_path=str(Path(tmpdir) / "collected-symbol.log"),
                    persist=True,
                    audit_id="collect-symbol-audit",
                    symbol_map_path=None,
                )

            self.assertEqual(exit_code, 0)
            stored = cli_main.audit_repository.get("collect-symbol-audit")
            self.assertEqual(stored.alert_count, 1)
            self.assertEqual(stored.events[0]["function"], "charge_customer")
            self.assertEqual(
                stored.events[0]["metadata"]["resolution_reason"],
                "trace_stack_module_function_hint",
            )
            self.assertEqual(stored.events[0]["metadata"]["trace_hint_value"], "app.charge_customer")
            self.assertIn("collector_symbol_map_path", stored.events[0]["metadata"])
            self.assertIn("trace_symbol_map_path", sink.getvalue())

    def test_cli_collect_audit_extracts_inline_symbol_lines(self) -> None:
        root = Path("tests/fixtures/sample_service").resolve()
        script = Path("tests/fixtures/scripts/emit_inline_symbolized_trace.sh").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.snapshot_repository = cli_main.SnapshotRepository(cli_main.settings, graph=cli_main.graph)
            cli_main.audit_repository = cli_main.AuditRepository(cli_main.settings)
            cli_main.ingest_service = cli_main.IngestService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
            )
            cli_main.audit_service = cli_main.AuditService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
                audit_repository=cli_main.audit_repository,
                drift_comparator=cli_main.DriftComparator(),
                remediation_client=cli_main.RuleBasedLLMClient(),
                settings=cli_main.settings,
            )
            cli_main.trace_collection_service = cli_main.TraceCollectionService(settings=cli_main.settings)

            sink = StringIO()
            output_path = Path(tmpdir) / "inline-collected.log"
            with redirect_stdout(sink):
                cli_main.run_ingest(str(root), None, persist=True, snapshot_id="collect-inline-snapshot")
                exit_code = cli_main.run_collect_audit(
                    "collect-inline-snapshot",
                    1234,
                    snapshot_is_id=True,
                    program=str(script),
                    duration=None,
                    max_events=10,
                    trace_format="auto",
                    output_path=str(output_path),
                    persist=True,
                    audit_id="collect-inline-audit",
                    symbol_map_path=None,
                )

            self.assertEqual(exit_code, 0)
            stored = cli_main.audit_repository.get("collect-inline-audit")
            self.assertEqual(stored.alert_count, 1)
            self.assertEqual(stored.events[0]["function"], "charge_customer")
            self.assertEqual(
                stored.events[0]["metadata"]["resolution_reason"],
                "trace_stack_module_function_hint",
            )
            self.assertEqual(stored.events[0]["metadata"]["trace_hint_value"], "app.charge_customer")
            self.assertTrue(output_path.with_name("inline-collected.log.symbols.json").exists())
            self.assertNotIn("event=symbol", output_path.read_text(encoding="utf-8"))

    def test_cli_collect_audit_extracts_inline_context_lines(self) -> None:
        root = Path("tests/fixtures/sample_service").resolve()
        script = Path("tests/fixtures/scripts/emit_inline_context_trace.sh").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.snapshot_repository = cli_main.SnapshotRepository(cli_main.settings, graph=cli_main.graph)
            cli_main.audit_repository = cli_main.AuditRepository(cli_main.settings)
            cli_main.ingest_service = cli_main.IngestService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
            )
            cli_main.audit_service = cli_main.AuditService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
                audit_repository=cli_main.audit_repository,
                drift_comparator=cli_main.DriftComparator(),
                remediation_client=cli_main.RuleBasedLLMClient(),
                settings=cli_main.settings,
            )
            cli_main.trace_collection_service = cli_main.TraceCollectionService(settings=cli_main.settings)

            sink = StringIO()
            output_path = Path(tmpdir) / "inline-context.log"
            with redirect_stdout(sink):
                cli_main.run_ingest(str(root), None, persist=True, snapshot_id="collect-context-snapshot")
                exit_code = cli_main.run_collect_audit(
                    "collect-context-snapshot",
                    1234,
                    snapshot_is_id=True,
                    program=str(script),
                    duration=None,
                    max_events=10,
                    trace_format="auto",
                    output_path=str(output_path),
                    persist=True,
                    audit_id="collect-context-audit",
                    symbol_map_path=None,
                )

            self.assertEqual(exit_code, 0)
            stored = cli_main.audit_repository.get("collect-context-audit")
            self.assertEqual(stored.alert_count, 1)
            self.assertEqual(stored.events[1]["function"], "charge_customer")
            self.assertEqual(stored.events[1]["metadata"]["request_id"], "req-123")
            self.assertEqual(stored.events[1]["metadata"]["context_source"], "trace_context_map")
            self.assertTrue(output_path.with_name("inline-context.log.contexts.json").exists())
            self.assertNotIn("event=context", output_path.read_text(encoding="utf-8"))

    def test_cli_audit_trace_uses_explicit_function_hints(self) -> None:
        root = Path("tests/fixtures/sample_service").resolve()
        trace = Path("tests/fixtures/hinted_trace.log").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.snapshot_repository = cli_main.SnapshotRepository(cli_main.settings, graph=cli_main.graph)
            cli_main.audit_repository = cli_main.AuditRepository(cli_main.settings)
            cli_main.ingest_service = cli_main.IngestService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
            )
            cli_main.audit_service = cli_main.AuditService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
                audit_repository=cli_main.audit_repository,
                drift_comparator=cli_main.DriftComparator(),
                remediation_client=cli_main.RuleBasedLLMClient(),
                settings=cli_main.settings,
            )

            sink = StringIO()
            with redirect_stdout(sink):
                cli_main.run_ingest(str(root), None, persist=True, snapshot_id="hinted-snapshot")
                exit_code = cli_main.run_audit_trace(
                    "hinted-snapshot",
                    str(trace),
                    snapshot_is_id=True,
                    trace_format="auto",
                    out_dir=None,
                    persist=True,
                    audit_id="hinted-audit",
                )

            self.assertEqual(exit_code, 0)
            stored = cli_main.audit_repository.get("hinted-audit")
            self.assertEqual(stored.alert_count, 1)
            self.assertEqual(stored.events[0]["function"], "charge_customer")
            self.assertEqual(
                stored.events[0]["metadata"]["resolution_reason"],
                "trace_module_function_hint",
            )

    def test_cli_audit_trace_uses_stack_hints(self) -> None:
        root = Path("tests/fixtures/sample_service").resolve()
        trace = Path("tests/fixtures/stack_hinted_trace.log").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.snapshot_repository = cli_main.SnapshotRepository(cli_main.settings, graph=cli_main.graph)
            cli_main.audit_repository = cli_main.AuditRepository(cli_main.settings)
            cli_main.ingest_service = cli_main.IngestService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
            )
            cli_main.audit_service = cli_main.AuditService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
                audit_repository=cli_main.audit_repository,
                drift_comparator=cli_main.DriftComparator(),
                remediation_client=cli_main.RuleBasedLLMClient(),
                settings=cli_main.settings,
            )

            sink = StringIO()
            with redirect_stdout(sink):
                cli_main.run_ingest(str(root), None, persist=True, snapshot_id="stack-hinted-snapshot")
                exit_code = cli_main.run_audit_trace(
                    "stack-hinted-snapshot",
                    str(trace),
                    snapshot_is_id=True,
                    trace_format="auto",
                    out_dir=None,
                    persist=True,
                    audit_id="stack-hinted-audit",
                )

            self.assertEqual(exit_code, 0)
            stored = cli_main.audit_repository.get("stack-hinted-audit")
            self.assertEqual(stored.alert_count, 1)
            self.assertEqual(stored.events[0]["function"], "charge_customer")
            self.assertEqual(
                stored.events[0]["metadata"]["resolution_reason"],
                "trace_stack_module_function_hint",
            )
            self.assertEqual(stored.events[0]["metadata"]["trace_hint_value"], "app.charge_customer")

    def test_cli_audit_trace_uses_raw_symbol_hints(self) -> None:
        root = Path("tests/fixtures/sample_service").resolve()
        trace = Path("tests/fixtures/raw_symbol_hinted_trace.log").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.snapshot_repository = cli_main.SnapshotRepository(cli_main.settings, graph=cli_main.graph)
            cli_main.audit_repository = cli_main.AuditRepository(cli_main.settings)
            cli_main.ingest_service = cli_main.IngestService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
            )
            cli_main.audit_service = cli_main.AuditService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
                audit_repository=cli_main.audit_repository,
                drift_comparator=cli_main.DriftComparator(),
                remediation_client=cli_main.RuleBasedLLMClient(),
                settings=cli_main.settings,
            )

            sink = StringIO()
            with redirect_stdout(sink):
                cli_main.run_ingest(str(root), None, persist=True, snapshot_id="raw-symbol-snapshot")
                exit_code = cli_main.run_audit_trace(
                    "raw-symbol-snapshot",
                    str(trace),
                    snapshot_is_id=True,
                    trace_format="auto",
                    out_dir=None,
                    persist=True,
                    audit_id="raw-symbol-audit",
                )

            self.assertEqual(exit_code, 0)
            stored = cli_main.audit_repository.get("raw-symbol-audit")
            self.assertEqual(stored.alert_count, 1)
            self.assertEqual(stored.events[0]["function"], "charge_customer")
            self.assertEqual(
                stored.events[0]["metadata"]["resolution_reason"],
                "trace_module_function_hint",
            )

    def test_cli_audit_trace_uses_raw_stack_symbol_hints(self) -> None:
        root = Path("tests/fixtures/sample_service").resolve()
        trace = Path("tests/fixtures/raw_stack_symbol_trace.log").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.snapshot_repository = cli_main.SnapshotRepository(cli_main.settings, graph=cli_main.graph)
            cli_main.audit_repository = cli_main.AuditRepository(cli_main.settings)
            cli_main.ingest_service = cli_main.IngestService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
            )
            cli_main.audit_service = cli_main.AuditService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
                audit_repository=cli_main.audit_repository,
                drift_comparator=cli_main.DriftComparator(),
                remediation_client=cli_main.RuleBasedLLMClient(),
                settings=cli_main.settings,
            )

            sink = StringIO()
            with redirect_stdout(sink):
                cli_main.run_ingest(str(root), None, persist=True, snapshot_id="raw-stack-snapshot")
                exit_code = cli_main.run_audit_trace(
                    "raw-stack-snapshot",
                    str(trace),
                    snapshot_is_id=True,
                    trace_format="auto",
                    out_dir=None,
                    persist=True,
                    audit_id="raw-stack-audit",
                )

            self.assertEqual(exit_code, 0)
            stored = cli_main.audit_repository.get("raw-stack-audit")
            self.assertEqual(stored.alert_count, 1)
            self.assertEqual(stored.events[0]["function"], "charge_customer")
            self.assertEqual(
                stored.events[0]["metadata"]["resolution_reason"],
                "trace_stack_module_function_hint",
            )
            self.assertEqual(stored.events[0]["metadata"]["trace_hint_value"], "app.charge_customer")

    def test_cli_audit_trace_uses_symbol_map_for_single_address(self) -> None:
        root = Path("tests/fixtures/sample_service").resolve()
        trace = Path("tests/fixtures/address_symbol_trace.log").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.snapshot_repository = cli_main.SnapshotRepository(cli_main.settings, graph=cli_main.graph)
            cli_main.audit_repository = cli_main.AuditRepository(cli_main.settings)
            cli_main.ingest_service = cli_main.IngestService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
            )
            cli_main.audit_service = cli_main.AuditService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
                audit_repository=cli_main.audit_repository,
                drift_comparator=cli_main.DriftComparator(),
                remediation_client=cli_main.RuleBasedLLMClient(),
                settings=cli_main.settings,
            )

            sink = StringIO()
            with redirect_stdout(sink):
                cli_main.run_ingest(str(root), None, persist=True, snapshot_id="address-symbol-snapshot")
                exit_code = cli_main.run_audit_trace(
                    "address-symbol-snapshot",
                    str(trace),
                    snapshot_is_id=True,
                    trace_format="auto",
                    out_dir=None,
                    persist=True,
                    audit_id="address-symbol-audit",
                )

            self.assertEqual(exit_code, 0)
            stored = cli_main.audit_repository.get("address-symbol-audit")
            self.assertEqual(stored.alert_count, 1)
            self.assertEqual(stored.events[0]["function"], "charge_customer")
            self.assertEqual(
                stored.events[0]["metadata"]["resolution_reason"],
                "trace_module_function_hint",
            )
            self.assertEqual(stored.events[0]["metadata"]["symbol_address"], "0x4010")

    def test_cli_audit_trace_uses_symbol_map_for_stack_addresses(self) -> None:
        root = Path("tests/fixtures/sample_service").resolve()
        trace = Path("tests/fixtures/address_stack_trace.log").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            cli_main.settings = resolve_workspace_settings(tmpdir)
            cli_main.snapshot_repository = cli_main.SnapshotRepository(cli_main.settings, graph=cli_main.graph)
            cli_main.audit_repository = cli_main.AuditRepository(cli_main.settings)
            cli_main.ingest_service = cli_main.IngestService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
            )
            cli_main.audit_service = cli_main.AuditService(
                graph=cli_main.graph,
                snapshot_repository=cli_main.snapshot_repository,
                audit_repository=cli_main.audit_repository,
                drift_comparator=cli_main.DriftComparator(),
                remediation_client=cli_main.RuleBasedLLMClient(),
                settings=cli_main.settings,
            )

            sink = StringIO()
            with redirect_stdout(sink):
                cli_main.run_ingest(str(root), None, persist=True, snapshot_id="address-stack-snapshot")
                exit_code = cli_main.run_audit_trace(
                    "address-stack-snapshot",
                    str(trace),
                    snapshot_is_id=True,
                    trace_format="auto",
                    out_dir=None,
                    persist=True,
                    audit_id="address-stack-audit",
                )

            self.assertEqual(exit_code, 0)
            stored = cli_main.audit_repository.get("address-stack-audit")
            self.assertEqual(stored.alert_count, 1)
            self.assertEqual(stored.events[0]["function"], "charge_customer")
            self.assertEqual(
                stored.events[0]["metadata"]["resolution_reason"],
                "trace_stack_module_function_hint",
            )
            self.assertEqual(stored.events[0]["metadata"]["trace_hint_value"], "app.charge_customer")


if __name__ == "__main__":
    unittest.main()
