import unittest

from lsa.core.models import FunctionIntent, IntentGraphSnapshot
from lsa.drift.comparator import DriftComparator
from lsa.drift.models import ObservedEvent


class DriftComparatorTests(unittest.TestCase):
    def test_flags_unexpected_outbound_target(self) -> None:
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
                )
            },
            edges=[],
        )
        events = [
            ObservedEvent(
                function="charge_customer",
                event_type="network",
                target="malicious.example.com",
            )
        ]

        alerts = DriftComparator().compare(snapshot, events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "medium")
        self.assertEqual(alerts[0].observed_target, "malicious.example.com")

    def test_accepts_host_port_when_host_matches_intent(self) -> None:
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
                )
            },
            edges=[],
        )
        events = [
            ObservedEvent(
                function="charge_customer",
                event_type="network",
                target="api.stripe.com:443",
            )
        ]

        alerts = DriftComparator().compare(snapshot, events)

        self.assertEqual(alerts, [])

    def test_accepts_resolved_target_host_alias(self) -> None:
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
                )
            },
            edges=[],
        )
        events = [
            ObservedEvent(
                function="charge_customer",
                event_type="network",
                target="93.184.216.34:443",
                metadata={"resolved_target_host": "api.stripe.com"},
            )
        ]

        alerts = DriftComparator().compare(snapshot, events)

        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
