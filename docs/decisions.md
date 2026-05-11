# Key Decisions

## Control plane first

We intentionally hardened the control plane early instead of treating it as cleanup work later. Jobs, workers, alerts, on-call, maintenance, backup, schema, and cutover workflows are core product behavior, not side utilities.

## SQLite safe default, Postgres staged transition

SQLite remains the default because it is reliable for local and split-process development, while Postgres is being introduced through:

- schema contract unification
- export/cutover bundles
- bootstrap packages
- target inspection and rehearsal
- shadow sync
- feature-gated live runtime slices

This avoids a hand-wavy “future Postgres” promise and keeps the migration operationally testable.

## API and CLI parity matters

Most serious operator workflows are exposed through both API and CLI so the product can be used by humans, scripts, and future UI layers without rebuilding core behavior.

## Runtime proof is governance, not just telemetry

Runtime rehearsal and validation are treated as control-plane evidence. They feed analytics, metrics, alerts, reviews, maintenance preflight, and cutover/promotion gates.

## Review ownership should be policy-driven

Runtime-proof reviews are operational work, not generic notes. Ownership and assignment guardrails should come from environment policy so `prod` can route review debt into the right team automatically.

## Environment-aware policy over global policy

`prod`, `staging`, and future scopes should not share one operational policy by accident. On-call governance and runtime-validation freshness policy are both environment-aware by design.
