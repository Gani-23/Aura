from __future__ import annotations

from lsa.core.models import FunctionIntent
from lsa.drift.models import DriftAlert, RemediationReport, TraceSessionSummary


class RuleBasedLLMClient:
    """Small deterministic stand-in until a local LLM is wired in."""

    def analyze(
        self,
        function: FunctionIntent,
        alert: DriftAlert,
        prompt: str,
        session: TraceSessionSummary | None = None,
    ) -> RemediationReport:
        expected = ", ".join(alert.expected_targets) or "no recorded targets"
        summary = (
            f"{function.qualname} reached {alert.observed_target}, which does not match "
            f"the current intent graph. The closest known outbound set is {expected}."
        )
        immediate_action = (
            "Verify whether the new outbound call was intentionally introduced. "
            "If not, disable or roll back the change and inspect recent deploys."
        )
        long_term_fix = (
            "Either update the code to remove the unintended dependency or update the "
            "intent graph generation path so the change is reviewed and recorded explicitly."
        )
        supporting_facts = [
            f"Prompt used for remediation: {prompt}",
            f"Known external hosts: {expected}",
            f"Observed target: {alert.observed_target}",
        ]
        if session is not None:
            supporting_facts.append(
                f"Session {session.session_key} observed {session.event_count} events across targets: "
                f"{', '.join(session.targets)}"
            )
        return RemediationReport(
            function=function.qualname,
            title=f"Drift report for {function.qualname}",
            summary=summary,
            risk=alert.severity.upper(),
            immediate_action=immediate_action,
            long_term_fix=long_term_fix,
            supporting_facts=supporting_facts,
        )
