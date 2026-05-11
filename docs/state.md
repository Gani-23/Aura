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
- runtime-validation review analytics now expose owner-team queue rollups and filtered queue views
- runtime-validation review backlog now has a dedicated queue-summary API/CLI surface
- runtime-validation review queue now has a direct operator page and CSV export path
- runtime-validation policy now supports separate assigned vs unassigned review SLA thresholds per environment
- critical unassigned runtime-validation review debt now auto-opens governance escalation requests
- governance debt can now auto-open explicit change-control requests
- change-control requests now support assignment and approve/reject decisions
- unresolved or rejected runtime-validation change-control requests now block cutover readiness
- rejected change-control debt is now non-overridable during cutover promotion
- deployment readiness now has a first-class surface on top of runtime-validation and change-control state
- maintenance preflight and runtime rehearsal can now enforce deployment-readiness policy via explicit flags
- deployment readiness now has its own alert family and can optionally gate job submission
- control-plane analytics and metrics now carry deployment-readiness state, blocker counts, and change-control debt
- deployment readiness now has owner-team queue views plus bulk assign/review actions for linked change-control debt
- deployment readiness owner-team queue now exports CSV and marks stale rejected debt for stronger escalation
- deployment readiness owner-team queue now has direct browser page for bulk assign and bulk review
- deployment readiness now also has unified dashboard page tying readiness, owner-team debt, cutover readiness, and recent alerts
