# Open Gaps

## Still missing for a complete production product

- full Postgres-first runtime backend instead of partial feature-gated slices
- real operator UI/dashboard
- tenant-aware authn/authz and RBAC
- comprehensive audit-log product surface for all privileged changes
- production observability integration beyond local metrics output:
  - dashboards
  - alert rules
  - log/trace export
- deployment hardening beyond Compose-level shaping
- real-world scale validation on messy live workloads
- customer-grade onboarding, policy management, and admin workflows

## Highest-risk technical gaps

- Postgres runtime is credible but not yet the dominant default path
- runtime telemetry and drift flows still need broader live-workload proof
- mixed-backend transition layouts increase operational complexity until cutover is completed

## “Breakout” gaps

- no operator UI that makes the system easy to adopt
- no undeniable public proof point on a real workload yet
- remediation/policy loop is useful, but not yet “must-talk-about-it” magical

