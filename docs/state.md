# Current State

## Product shape

Living Systems Auditor is no longer a thin prototype. It is a production-shaped backend and control plane for:

- intent snapshot ingestion
- runtime trace collection and normalization
- drift detection and remediation reporting
- operator-facing job, worker, alert, on-call, maintenance, and cutover workflows

## Runtime architecture

- API surface: FastAPI
- operator surface: CLI mirrors most maintenance and governance flows
- default control-plane backend: SQLite via `LSA_DATABASE_URL`
- staged runtime transition path: feature-gated Postgres slices for jobs and snapshot/audit metadata
- worker modes:
  - embedded worker for single-process/dev use
  - standalone worker for split API/worker deployment

## What is solid today

- snapshots, audits, jobs, workers, leases, and maintenance events persist durably
- worker heartbeats, stale-worker takeover, history retention, and rollups are implemented
- analytics, metrics, alerts, silences, reminders, escalations, and on-call routing are implemented
- governed on-call changes support approvals, review queues, assignment, and environment-aware policy
- maintenance mode, backup/restore, schema inspection/migration, and cutover runbooks exist
- Postgres cutover preparation, bootstrap packaging, inspection, rehearsal, readiness, and promotion gates exist
- runtime smoke, rehearsal, validation, cadence tracking, dedicated runtime-proof alerts, and runtime-proof review queues exist

## Current backend transition posture

- SQLite is still the safe default runtime backend
- Postgres support is real but still partial at live-runtime level
- shadow sync exists for maintenance metadata, jobs, workers, heartbeats, lease events, alerts, on-call state, and governance state
- feature-gated Postgres runtime slices exist for:
  - jobs
  - snapshot and audit metadata
- shared runtime bundle can report `shared` vs `mixed` backend layouts

## Important repo surfaces

- API: [lsa/api/main.py](../lsa/api/main.py)
- CLI: [lsa/cli/main.py](../lsa/cli/main.py)
- storage/runtime bundle: [lsa/storage/files.py](../lsa/storage/files.py)
- analytics: [lsa/services/analytics_service.py](../lsa/services/analytics_service.py)
- alerts: [lsa/services/control_plane_alert_service.py](../lsa/services/control_plane_alert_service.py)
- runtime validation: [lsa/services/control_plane_runtime_validation_service.py](../lsa/services/control_plane_runtime_validation_service.py)
- runtime validation reviews: [lsa/services/control_plane_runtime_validation_review_service.py](../lsa/services/control_plane_runtime_validation_review_service.py)
- roadmap: [docs/roadmap.md](roadmap.md)

## Latest important milestone

- environment-aware runtime-validation policy bundles are live
- runtime-proof has a dedicated alert family and follow-up chain
- runtime-proof now opens assignable review work before proof goes stale
- runtime-proof reviews now escalate through dedicated alert incidents when they sit unowned or unresolved
- runtime-validation policy can now stamp review ownership and optional auto-assignment rules per environment
