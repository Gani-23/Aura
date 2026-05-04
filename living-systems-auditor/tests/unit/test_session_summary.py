import unittest

from lsa.drift.models import DriftAlert, ObservedEvent
from lsa.drift.session_summary import build_audit_explanation, find_relevant_session, summarize_sessions


class SessionSummaryTests(unittest.TestCase):
    def test_summarizes_correlated_session(self) -> None:
        events = [
            ObservedEvent(
                function="charge_customer",
                event_type="network",
                target="api.stripe.com",
                metadata={"process": "python", "request_id": "req-123", "resolution_reason": "unique_target_host_match"},
            ),
            ObservedEvent(
                function="charge_customer",
                event_type="network",
                target="malicious.example.com",
                metadata={"process": "python", "request_id": "req-123", "resolution_reason": "correlation_binding_inheritance"},
            ),
        ]
        alerts = [
            DriftAlert(
                function="charge_customer",
                observed_target="malicious.example.com",
                expected_targets=["api.stripe.com"],
                severity="medium",
                reason="Observed outbound target is not part of the known intent graph.",
            )
        ]

        sessions = summarize_sessions(events, alerts)

        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0].session_key, "request_id:req-123")
        self.assertEqual(sessions[0].event_count, 2)
        self.assertIn("malicious.example.com", sessions[0].drift_targets)
        self.assertIn("request_id", sessions[0].correlation_fields)

    def test_finds_relevant_session_for_alert(self) -> None:
        events = [
            ObservedEvent(
                function="charge_customer",
                event_type="network",
                target="malicious.example.com",
                metadata={"process": "python", "request_id": "req-123", "resolution_reason": "correlation_binding_inheritance"},
            ),
        ]
        alert = DriftAlert(
            function="charge_customer",
            observed_target="malicious.example.com",
            expected_targets=["api.stripe.com"],
            severity="medium",
            reason="Observed outbound target is not part of the known intent graph.",
        )

        sessions = summarize_sessions(events, [alert])
        session = find_relevant_session(sessions, alert)

        self.assertIsNotNone(session)
        assert session is not None
        self.assertEqual(session.session_key, "request_id:req-123")

    def test_builds_drift_explanation(self) -> None:
        events = [
            ObservedEvent(
                function="charge_customer",
                event_type="network",
                target="api.stripe.com",
                metadata={"process": "python", "request_id": "req-123", "resolution_reason": "seed_match"},
            ),
            ObservedEvent(
                function="charge_customer",
                event_type="network",
                target="malicious.example.com",
                metadata={"process": "python", "request_id": "req-123", "resolution_reason": "correlation_binding_inheritance"},
            ),
        ]
        alerts = [
            DriftAlert(
                function="charge_customer",
                observed_target="malicious.example.com",
                expected_targets=["api.stripe.com"],
                severity="medium",
                reason="Observed outbound target is not part of the known intent graph.",
            )
        ]

        explanation = build_audit_explanation(summarize_sessions(events, alerts), alerts)

        self.assertEqual(explanation.status, "drift_detected")
        self.assertEqual(explanation.primary_function, "charge_customer")
        self.assertEqual(explanation.primary_session_key, "request_id:req-123")
        self.assertIn("malicious.example.com", explanation.unexpected_targets)

    def test_builds_clean_explanation(self) -> None:
        events = [
            ObservedEvent(
                function="charge_customer",
                event_type="network",
                target="api.stripe.com",
                metadata={"process": "python", "request_id": "req-123", "resolution_reason": "seed_match"},
            ),
        ]

        explanation = build_audit_explanation(summarize_sessions(events, []), [])

        self.assertEqual(explanation.status, "clean")
        self.assertEqual(explanation.alert_count, 0)
        self.assertEqual(explanation.primary_session_key, "request_id:req-123")


if __name__ == "__main__":
    unittest.main()
