from __future__ import annotations

from lsa.core.models import IntentGraphSnapshot
from lsa.drift.destination_resolution import target_host_candidates
from lsa.drift.function_resolution import extract_target_host
from lsa.drift.models import DriftAlert, ObservedEvent


class DriftComparator:
    def compare(
        self,
        snapshot: IntentGraphSnapshot,
        events: list[ObservedEvent],
    ) -> list[DriftAlert]:
        alerts: list[DriftAlert] = []

        for event in events:
            if event.event_type != "network":
                continue

            function = snapshot.functions.get(event.function)
            if function is None:
                alerts.append(
                    DriftAlert(
                        function=event.function,
                        observed_target=event.target,
                        expected_targets=[],
                        severity="high",
                        reason="Observed network activity for an unknown function.",
                    )
                )
                continue

            observed_host = extract_target_host(event.target)
            expected_targets = list(function.external_hosts)
            candidate_hosts = target_host_candidates(event)
            matches_intent = event.target in function.external_hosts or (
                observed_host is not None and observed_host in function.external_hosts
            ) or any(
                candidate in function.external_hosts for candidate in candidate_hosts
            )

            if not matches_intent:
                severity = "medium" if function.external_hosts else "high"
                alerts.append(
                    DriftAlert(
                        function=event.function,
                        observed_target=event.target,
                        expected_targets=expected_targets,
                        severity=severity,
                        reason="Observed outbound target is not part of the known intent graph.",
                    )
                )

        return alerts
