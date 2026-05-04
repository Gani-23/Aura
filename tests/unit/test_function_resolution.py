import unittest

from lsa.core.models import FunctionIntent, IntentGraphSnapshot
from lsa.drift.destination_resolution import resolve_destination_event, target_host_candidates
from lsa.drift.function_resolution import (
    correlation_binding_keys,
    extract_target_host,
    resolve_event,
    resolve_events,
)
from lsa.drift.models import ObservedEvent


class FunctionResolutionTests(unittest.TestCase):
    def test_resolves_process_name_via_unique_target_host(self) -> None:
        snapshot = IntentGraphSnapshot(
            root_path="/tmp/sample",
            functions={
                "charge_customer": FunctionIntent(
                    name="charge_customer",
                    module="billing",
                    qualname="charge_customer",
                    lineno=1,
                    end_lineno=5,
                    external_hosts=["api.stripe.com"],
                ),
                "notify_customer": FunctionIntent(
                    name="notify_customer",
                    module="notifications",
                    qualname="notify_customer",
                    lineno=7,
                    end_lineno=10,
                    external_hosts=["api.mailgun.net"],
                ),
            },
            edges=[],
        )
        event = ObservedEvent(
            function="python",
            event_type="network",
            target="api.stripe.com",
            metadata={"process": "python"},
        )

        resolved = resolve_event(snapshot, event)

        self.assertEqual(resolved.function, "charge_customer")
        self.assertEqual(resolved.metadata["resolution_reason"], "unique_target_host_match")
        self.assertEqual(resolved.metadata["original_function"], "python")

    def test_extract_target_host_handles_host_port(self) -> None:
        self.assertEqual(extract_target_host("93.184.216.34:443"), "93.184.216.34")
        self.assertEqual(extract_target_host("api.stripe.com"), "api.stripe.com")
        self.assertIsNone(extract_target_host("port:443"))

    def test_inherits_resolved_function_for_same_process_sequence(self) -> None:
        snapshot = IntentGraphSnapshot(
            root_path="/tmp/sample",
            functions={
                "charge_customer": FunctionIntent(
                    name="charge_customer",
                    module="billing",
                    qualname="charge_customer",
                    lineno=1,
                    end_lineno=5,
                    external_hosts=["api.stripe.com"],
                ),
            },
            edges=[],
        )
        events = [
            ObservedEvent(
                function="python",
                event_type="network",
                target="api.stripe.com",
                metadata={"process": "python", "pid": "4242"},
            ),
            ObservedEvent(
                function="python",
                event_type="network",
                target="malicious.example.com",
                metadata={"process": "python", "pid": "4242"},
            ),
        ]

        resolved = resolve_events(snapshot, events)

        self.assertEqual(resolved[0].function, "charge_customer")
        self.assertEqual(resolved[1].function, "charge_customer")
        self.assertEqual(resolved[1].metadata["resolution_reason"], "process_binding_inheritance")

    def test_prefers_request_level_correlation_binding(self) -> None:
        snapshot = IntentGraphSnapshot(
            root_path="/tmp/sample",
            functions={
                "charge_customer": FunctionIntent(
                    name="charge_customer",
                    module="billing",
                    qualname="charge_customer",
                    lineno=1,
                    end_lineno=5,
                    external_hosts=["api.stripe.com"],
                ),
            },
            edges=[],
        )
        events = [
            ObservedEvent(
                function="python",
                event_type="network",
                target="api.stripe.com",
                metadata={"process": "python", "pid": "4242", "request_id": "req-123"},
            ),
            ObservedEvent(
                function="python",
                event_type="network",
                target="malicious.example.com",
                metadata={"process": "python", "pid": "4242", "request_id": "req-123"},
            ),
        ]

        resolved = resolve_events(snapshot, events)

        self.assertEqual(resolved[1].function, "charge_customer")
        self.assertEqual(resolved[1].metadata["resolution_reason"], "correlation_binding_inheritance")

    def test_builds_multiple_correlation_keys(self) -> None:
        event = ObservedEvent(
            function="python",
            event_type="network",
            target="api.stripe.com",
            metadata={
                "process": "python",
                "pid": "4242",
                "tid": "100",
                "fd": "17",
                "request_id": "req-123",
                "trace_id": "trace-abc",
            },
        )

        keys = correlation_binding_keys(event)

        self.assertIn("request_id:req-123", keys)
        self.assertIn("trace_id:trace-abc", keys)
        self.assertIn("process-pid-fd:python:4242:17", keys)
        self.assertIn("process-pid-tid:python:4242:100", keys)

    def test_inherits_resolution_via_derived_socket_identity(self) -> None:
        snapshot = IntentGraphSnapshot(
            root_path="/tmp/sample",
            functions={
                "charge_customer": FunctionIntent(
                    name="charge_customer",
                    module="billing",
                    qualname="charge_customer",
                    lineno=1,
                    end_lineno=5,
                    external_hosts=["api.stripe.com"],
                ),
            },
            edges=[],
        )
        events = [
            ObservedEvent(
                function="python",
                event_type="network",
                target="api.stripe.com",
                metadata={
                    "process": "python",
                    "collector_session_id": "sess-123",
                    "collector_target_pid": "4242",
                    "fd": "9",
                },
            ),
            ObservedEvent(
                function="python",
                event_type="network",
                target="malicious.example.com",
                metadata={
                    "process": "python",
                    "collector_session_id": "sess-123",
                    "collector_target_pid": "4242",
                    "fd": "9",
                },
            ),
        ]

        from lsa.drift.enrichment import enrich_event

        resolved = resolve_events(snapshot, [enrich_event(event) for event in events])

        self.assertEqual(resolved[0].function, "charge_customer")
        self.assertEqual(resolved[0].metadata["socket_id"], "sess-123:python:4242:9")
        self.assertEqual(resolved[1].function, "charge_customer")
        self.assertEqual(resolved[1].metadata["resolution_reason"], "correlation_binding_inheritance")

    def test_resolves_destination_alias_from_explicit_metadata_hint(self) -> None:
        snapshot = IntentGraphSnapshot(
            root_path="/tmp/sample",
            functions={
                "charge_customer": FunctionIntent(
                    name="charge_customer",
                    module="billing",
                    qualname="charge_customer",
                    lineno=1,
                    end_lineno=5,
                    external_hosts=["api.stripe.com"],
                ),
            },
            edges=[],
        )
        event = ObservedEvent(
            function="charge_customer",
            event_type="network",
            target="93.184.216.34:443",
            metadata={"host": "api.stripe.com", "dport": "443"},
        )

        resolved = resolve_destination_event(snapshot, event, alias_map={})

        self.assertEqual(resolved.metadata["resolved_target_host"], "api.stripe.com")
        self.assertEqual(resolved.metadata["target_resolution_reason"], "trace_host_hint")
        self.assertIn("api.stripe.com", target_host_candidates(resolved))

    def test_resolves_destination_alias_from_alias_map(self) -> None:
        snapshot = IntentGraphSnapshot(
            root_path="/tmp/sample",
            functions={
                "charge_customer": FunctionIntent(
                    name="charge_customer",
                    module="billing",
                    qualname="charge_customer",
                    lineno=1,
                    end_lineno=5,
                    external_hosts=["api.stripe.com"],
                ),
            },
            edges=[],
        )
        event = ObservedEvent(
            function="charge_customer",
            event_type="network",
            target="93.184.216.34:443",
            metadata={"daddr": "93.184.216.34", "dport": "443"},
        )

        resolved = resolve_destination_event(
            snapshot,
            event,
            alias_map={"93.184.216.34": "api.stripe.com"},
        )

        self.assertEqual(resolved.metadata["resolved_target_host"], "api.stripe.com")
        self.assertEqual(resolved.metadata["target_matches_intent_via_alias"], "true")

    def test_prefers_explicit_qualname_hint(self) -> None:
        snapshot = IntentGraphSnapshot(
            root_path="/tmp/sample",
            functions={
                "charge_customer": FunctionIntent(
                    name="charge_customer",
                    module="app",
                    qualname="charge_customer",
                    lineno=3,
                    end_lineno=6,
                    external_hosts=["api.stripe.com"],
                ),
            },
            edges=[],
        )
        event = ObservedEvent(
            function="python",
            event_type="network",
            target="malicious.example.com",
            metadata={"qualname": "charge_customer", "process": "python"},
        )

        resolved = resolve_event(snapshot, event)

        self.assertEqual(resolved.function, "charge_customer")
        self.assertEqual(resolved.metadata["resolution_reason"], "trace_qualname_hint")

    def test_resolves_from_module_and_function_hints(self) -> None:
        snapshot = IntentGraphSnapshot(
            root_path="/tmp/sample",
            functions={
                "charge_customer": FunctionIntent(
                    name="charge_customer",
                    module="app",
                    qualname="charge_customer",
                    lineno=3,
                    end_lineno=6,
                    external_hosts=["api.stripe.com"],
                ),
                "notify_customer": FunctionIntent(
                    name="notify_customer",
                    module="app",
                    qualname="notify_customer",
                    lineno=9,
                    end_lineno=11,
                    external_hosts=["api.mailgun.net"],
                ),
            },
            edges=[],
        )
        event = ObservedEvent(
            function="python",
            event_type="network",
            target="malicious.example.com",
            metadata={"module": "app", "function_name": "charge_customer", "process": "python"},
        )

        resolved = resolve_event(snapshot, event)

        self.assertEqual(resolved.function, "charge_customer")
        self.assertEqual(resolved.metadata["resolution_reason"], "trace_module_function_hint")

    def test_resolves_from_source_location_hint(self) -> None:
        snapshot = IntentGraphSnapshot(
            root_path="/tmp/sample",
            functions={
                "charge_customer": FunctionIntent(
                    name="charge_customer",
                    module="app",
                    qualname="charge_customer",
                    lineno=3,
                    end_lineno=6,
                    external_hosts=["api.stripe.com"],
                ),
                "notify_customer": FunctionIntent(
                    name="notify_customer",
                    module="app",
                    qualname="notify_customer",
                    lineno=9,
                    end_lineno=11,
                    external_hosts=["api.mailgun.net"],
                ),
            },
            edges=[],
        )
        event = ObservedEvent(
            function="python",
            event_type="network",
            target="malicious.example.com",
            metadata={"source_file": "app.py", "line": "4", "process": "python"},
        )

        resolved = resolve_event(snapshot, event)

        self.assertEqual(resolved.function, "charge_customer")
        self.assertEqual(resolved.metadata["resolution_reason"], "trace_source_location_hint")

    def test_resolves_from_stack_module_function_hint(self) -> None:
        snapshot = IntentGraphSnapshot(
            root_path="/tmp/sample",
            functions={
                "charge_customer": FunctionIntent(
                    name="charge_customer",
                    module="app",
                    qualname="charge_customer",
                    lineno=3,
                    end_lineno=6,
                    external_hosts=["api.stripe.com"],
                ),
                "notify_customer": FunctionIntent(
                    name="notify_customer",
                    module="app",
                    qualname="notify_customer",
                    lineno=9,
                    end_lineno=11,
                    external_hosts=["api.mailgun.net"],
                ),
            },
            edges=[],
        )
        event = ObservedEvent(
            function="python",
            event_type="network",
            target="malicious.example.com",
            metadata={"stack": "worker_loop>app.charge_customer>requests.post", "process": "python"},
        )

        resolved = resolve_event(snapshot, event)

        self.assertEqual(resolved.function, "charge_customer")
        self.assertEqual(resolved.metadata["resolution_reason"], "trace_stack_module_function_hint")
        self.assertEqual(resolved.metadata["trace_hint_value"], "app.charge_customer")
        self.assertEqual(resolved.metadata["trace_hint_index"], "1")

    def test_resolves_from_stack_source_location_hint(self) -> None:
        snapshot = IntentGraphSnapshot(
            root_path="/tmp/sample",
            functions={
                "charge_customer": FunctionIntent(
                    name="charge_customer",
                    module="app",
                    qualname="charge_customer",
                    lineno=3,
                    end_lineno=6,
                    external_hosts=["api.stripe.com"],
                ),
                "notify_customer": FunctionIntent(
                    name="notify_customer",
                    module="app",
                    qualname="notify_customer",
                    lineno=9,
                    end_lineno=11,
                    external_hosts=["api.mailgun.net"],
                ),
            },
            edges=[],
        )
        event = ObservedEvent(
            function="python",
            event_type="network",
            target="malicious.example.com",
            metadata={"call_stack": "scheduler|app.py:4|requests.post", "process": "python"},
        )

        resolved = resolve_event(snapshot, event)

        self.assertEqual(resolved.function, "charge_customer")
        self.assertEqual(resolved.metadata["resolution_reason"], "trace_stack_source_location_hint")
        self.assertEqual(resolved.metadata["trace_hint_value"], "app.py:4")


if __name__ == "__main__":
    unittest.main()
