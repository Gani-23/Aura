# Drift report for charge_customer

## Summary
charge_customer reached malicious.example.com, which does not match the current intent graph. The closest known outbound set is api.stripe.com.

## Risk
MEDIUM

## Recommended Immediate Action
Verify whether the new outbound call was intentionally introduced. If not, disable or roll back the change and inspect recent deploys.

## Recommended Long-Term Fix
Either update the code to remove the unintended dependency or update the intent graph generation path so the change is reviewed and recorded explicitly.

## Supporting Facts
- Prompt used for remediation: You are analyzing a semantic drift alert.
Function: charge_customer
Documented intent: Charge the payment provider and return a simple result.
Known invariants: Function should continue to satisfy its documented contract.; Outbound network activity should stay within known external hosts.
Expected outbound targets: api.stripe.com
Observed outbound target: malicious.example.com
Correlated session summary: Session key: request_id:req-123; event count: 2; targets seen: api.stripe.com, malicious.example.com; processes: charge_customer; correlation fields: request_id, process.
Alert severity: medium
Produce a concise explanation, risk assessment, immediate action, and long-term fix.
- Known external hosts: api.stripe.com
- Observed target: malicious.example.com
- Session request_id:req-123 observed 2 events across targets: api.stripe.com, malicious.example.com
