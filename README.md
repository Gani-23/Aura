# Living Systems Auditor

Living Systems Auditor is a Python-first scaffold for an intent-aware runtime auditor. This repo starts with a minimal vertical slice:

- ingest a Python codebase and build an intent graph snapshot
- normalize observed runtime events
- parse raw trace logs into normalized runtime events
- detect drift when observed network calls fall outside declared or inferred intent
- generate a structured remediation report
- expose the flow through a CLI and FastAPI surface
- persist snapshots and audit runs so the system can be inspected over time
- persist job execution state in a SQLite-backed control plane
- support first-class database URL configuration and hardened SQLite runtime settings for split API/worker deployment

## Fast repo memory

For compact project context between long sessions, use:

- [docs/state.md](docs/state.md)
- [docs/open-gaps.md](docs/open-gaps.md)
- [docs/decisions.md](docs/decisions.md)
- [docs/next-steps.md](docs/next-steps.md)

## What works today

- Python source ingestion using the standard library `ast` module
- simple function and module extraction
- external URL and hostname inference from common HTTP call patterns
- drift detection for unexpected outbound network activity
- markdown remediation reports written to disk
- CLI commands for `ingest` and `audit`
- local persistence for snapshots and audit history
- SQLite-backed control-plane persistence for snapshots, audits, and queued jobs
- API endpoints to list and fetch persisted snapshots and audits
- API endpoints for live trace collection and collect-and-audit flows
- API-key protection for service endpoints when `LSA_API_KEY` is configured
- asynchronous audit job submission and polling over the API
- startup recovery for persisted jobs that were left `running` during a restart
- heartbeat-backed worker registry and job lease visibility in the control plane
- active lease renewal and stale-worker takeover for long-running jobs
- append-only worker heartbeat history and job lease event history for forensic review
- time-based retention and explicit pruning for the growing history tables
- daily rollup compaction for older heartbeat and lease-event history
- trace-based audit flow for `logfmt`-style lines and raw `bpftrace` connect output
- trace collection commands that can capture observer stdout straight into auditable trace files
- structured connect-event enrichment with `pid`, `tid`, `fd`, `process`, `daddr`, `dport`, and service hints
- optional destination alias resolution via trace hints or `data/destination_aliases.json`
- correlation-aware function binding across `request_id`, `trace_id`, `span_id`, `conn_id`, and process/socket context
- normalization of common tracing propagation formats like `traceparent`, `b3`, and `x-request-id` into canonical correlation fields
- normalization of OpenTelemetry-style attribute names, Jaeger `uber-trace-id`, and `baggage` strings into canonical correlation fields
- top-level audit explanations that summarize the primary drift storyline before the detailed session payloads and remediation reports
- automatic trace sidecar manifests that preserve collection context such as collector session id, target PID, and observer command
- derived `socket_id` and `flow_id` correlation keys when collector and observer metadata are rich enough to support them
- explicit function-resolution hints through trace metadata like `qualname`, `module` + `function_name`, or `source_file` + `line`
- stack-aware function-resolution hints through metadata like `stack`, `call_stack`, `frames`, or `callsite`
- raw symbol normalization for collector outputs like `app:charge_customer`, `app::charge_customer`, or `app.py:4`
- trace-local symbol map sidecars that resolve raw addresses into semantic function and stack hints
- collection-time staging of symbol maps so `collect-trace` and `collect-audit` can publish trace-local `.symbols.json` artifacts automatically
- inline symbol-definition extraction so collectors can emit `event=symbol ...` lines directly and let LSA materialize the symbol sidecar
- trace-local context map sidecars that join request and trace metadata onto raw runtime events before correlation
- dedicated runtime-proof review alerts and follow-up escalation paths so stale review work inherits the same alerting, acknowledgement, silencing, and on-call routing as other control-plane incidents

## Quick start

```bash
cd living-systems-auditor
python -m venv .venv
source .venv/bin/activate
pip install -e .

export LSA_API_KEY=change-me-in-production
export LSA_DATABASE_URL=sqlite:///$PWD/data/control_plane.db
export LSA_SQLITE_BUSY_TIMEOUT_MS=5000
# Optional when preparing a future Postgres runtime path:
# pip install -e ".[postgres]"
# Optional when explicitly activating the Postgres-backed snapshot/audit metadata path:
# export LSA_ENABLE_POSTGRES_RUNTIME_SNAPSHOTS_AUDITS=1
# export LSA_POSTGRES_RUNTIME_SNAPSHOTS_AUDITS_DATABASE_URL=postgresql://lsa:secret@db.example.com:5432/lsa_prod
# Optional when explicitly activating the Postgres-backed job repository path:
# export LSA_ENABLE_POSTGRES_RUNTIME_JOBS=1
# export LSA_POSTGRES_RUNTIME_JOBS_DATABASE_URL=postgresql://lsa:secret@db.example.com:5432/lsa_prod
# Optional for single-process dev mode only:
export LSA_RUN_EMBEDDED_WORKER=1
# Optional environment-aware runtime-proof policy bundle:
# export LSA_RUNTIME_VALIDATION_POLICY_PATH=$PWD/data/runtime_validation_policy.json

lsa ingest tests/fixtures/sample_service --out data/intent_graphs/sample.json
lsa audit data/intent_graphs/sample.json tests/fixtures/sample_events.json --out-dir data/reports
lsa parse-trace tests/fixtures/sample_trace.log --trace-format auto
lsa audit-trace demo-snapshot tests/fixtures/sample_trace.log --snapshot-id --trace-format auto
lsa collect-trace 1234 --program ebpf/network_observer.bt --duration 5 --out data/traces/live.log
lsa collect-audit demo-snapshot 1234 --snapshot-id --program ebpf/network_observer.bt --trace-format bpftrace
lsa worker --poll-interval 0.1
lsa list-snapshots
lsa list-audits
lsa list-jobs
lsa prune-history
lsa list-worker-heartbeat-rollups <worker_id>
lsa list-job-lease-event-rollups <job_id>
lsa control-plane-analytics --days 30
lsa control-plane-metrics --days 1
lsa control-plane-runtime-backend
lsa inspect-control-plane-runtime-backend --database-url postgresql://lsa:secret@db.example.com:5432/lsa_prod
lsa sync-postgres-runtime-shadow --target-database-url postgresql://lsa:secret@db.example.com:5432/lsa_prod --by operator --reason "shadow sync"
lsa emit-control-plane-alerts --force
lsa process-control-plane-alert-followups --force
lsa list-control-plane-alerts --limit 50
lsa acknowledge-control-plane-alert <alert_id> --by operator --note "Investigating"
lsa create-control-plane-alert-silence --by operator --reason "maintenance" --duration-minutes 30 --finding-code queue_without_active_workers
lsa list-control-plane-alert-silences --active-only
lsa cancel-control-plane-alert-silence <silence_id> --by operator
lsa create-control-plane-oncall-schedule --by operator --creator-team platform --creator-role engineer --team platform --timezone UTC --weekdays 0 1 2 3 4 5 6 --start-time 00:00 --end-time 23:59 --priority 100 --rotation primary
lsa create-control-plane-oncall-schedule --by operator --team platform-holiday --timezone UTC --weekdays 0 1 2 3 4 5 6 --start-time 00:00 --end-time 23:59 --priority 250 --rotation holiday --effective-start-date 2026-12-25 --effective-end-date 2026-12-26
lsa create-control-plane-oncall-schedule --by operator --creator-team platform --creator-role engineer --change-reason "Dual coverage during cutover" --approved-by director --approver-team platform --approver-role director --approval-note "Accepted one-day overlap" --team platform-shadow --timezone UTC --weekdays 0 1 2 3 4 5 6 --start-time 00:00 --end-time 23:59 --priority 250 --rotation holiday-shadow --effective-start-date 2026-12-25 --effective-end-date 2026-12-25
lsa list-control-plane-oncall-schedules --active-only
lsa resolve-control-plane-oncall-route --at 2026-12-25T12:00:00+00:00
lsa cancel-control-plane-oncall-schedule <schedule_id> --by operator
lsa control-plane-schema
lsa control-plane-schema-contract
lsa migrate-control-plane-schema
lsa control-plane-maintenance-mode
lsa control-plane-preflight
lsa run-control-plane-runtime-smoke --by operator --reason "deployment verification"
lsa run-control-plane-runtime-rehearsal --by operator --expected-backend sqlite --expected-layout shared --reason "deployment verification"
lsa control-plane-runtime-validation
lsa list-control-plane-runtime-validation-reviews
lsa process-control-plane-runtime-validation-reviews --by system
lsa assign-control-plane-runtime-validation-review <review_id> --assigned-to reviewer-prod --assigned-team platform --by system --note "Own the next refresh"
lsa resolve-control-plane-runtime-validation-review <review_id> --by reviewer-prod --reason manual_resolution --note "Fresh rehearsal completed"
lsa control-plane-cutover-preflight --target-database-url postgresql://lsa:secret@db.example.com:5432/lsa_prod
lsa inspect-postgres-bootstrap-package --package-dir data/backups/control-plane-cutover.postgres-bootstrap
lsa inspect-postgres-target --target-database-url postgresql://lsa:secret@db.example.com:5432/lsa_prod
lsa plan-postgres-bootstrap-execution --package-dir data/backups/control-plane-cutover.postgres-bootstrap --target-database-url postgresql://lsa:secret@db.example.com:5432/lsa_prod
lsa execute-postgres-bootstrap-package --package-dir data/backups/control-plane-cutover.postgres-bootstrap --target-database-url postgresql://lsa:secret@db.example.com:5432/lsa_prod --dry-run
lsa verify-postgres-bootstrap-package --package-dir data/backups/control-plane-cutover.postgres-bootstrap --target-database-url postgresql://lsa:secret@db.example.com:5432/lsa_prod
lsa run-postgres-cutover-rehearsal --package-dir data/backups/control-plane-cutover.postgres-bootstrap --target-database-url postgresql://lsa:secret@db.example.com:5432/lsa_prod --by operator
lsa decide-control-plane-cutover --package-dir data/backups/control-plane-cutover.postgres-bootstrap --target-database-url postgresql://lsa:secret@db.example.com:5432/lsa_prod --by operator --decision approve --reason "ready for promotion"
# Optional visible bypass when you intentionally want to override the default cutover gate:
# lsa evaluate-control-plane-cutover-readiness ... --skip-runtime-validation
# lsa decide-control-plane-cutover ... --skip-runtime-validation --allow-override --note "documented exception"
lsa enable-control-plane-maintenance-mode --by operator --reason "backup window"
lsa disable-control-plane-maintenance-mode --by operator --reason "done"
lsa run-control-plane-maintenance-workflow --out data/backups/control-plane-runbook.json --by operator --reason "schema repair"
lsa prepare-control-plane-cutover-bundle --out data/backups/control-plane-cutover.json --target-database-url postgresql://lsa:secret@db.example.com:5432/lsa_prod --by operator --reason "postgres cutover"
lsa export-control-plane-backup --out data/backups/control-plane.json
lsa import-control-plane-backup data/backups/control-plane.json --replace-existing
```

Example enriched trace line:

```text
event=network process=python comm=python pid=4242 tid=4242 fd=9 daddr=93.184.216.34 dport=443
```

This normalizes into a runtime event with target `93.184.216.34:443` and metadata that includes `service_hint=https`.

Collected traces now also get a sibling manifest such as `data/traces/latest-trace.log.meta.json`. When present, the parser automatically merges collector metadata like `collector_session_id`, `collector_target_pid`, and `collector_command` into each observed event before audit correlation.

Traces can also carry a sibling symbol map such as `data/traces/latest-trace.log.symbols.json`. When present, the parser can translate raw fields like `pc=0x4010` or `stack=0x1000>0x4010>0x7777` into semantic hints before function resolution runs.

Traces can also carry a sibling context map such as `data/traces/latest-trace.log.contexts.json`. When present, the parser can join request and trace metadata such as `traceparent`, `request_id`, or `b3` fields onto matching runtime events by `context_key`, `conn_id`, `flow_id`, `socket_id`, `request_id`, or `trace_id`.

The collection flow now stages that sidecar automatically when a collector program has an adjacent symbol file like `emit_symbolized_trace.sh.symbols.json`, or when you pass `--symbol-map /path/to/map.json` to `collect-trace` or `collect-audit`.

Collectors can also emit inline symbol-definition lines directly in the trace stream, for example:

```text
event=symbol addr=0x4010 value=app:charge_customer
event=symbol addr=0x7777 value=requests.post
event=network process=python stack=0x1000>0x4010>0x7777 target=https://malicious.example.com/exfil
```

During collection, LSA now strips those symbol-definition lines out of the stored trace body, writes a generated `.symbols.json` sidecar, and audits the remaining runtime events against that materialized symbol map.

Collectors can do the same thing for correlation context:

```text
event=context conn_id=conn-1 traceparent=00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01 request_id=req-123
event=network process=python comm=python conn_id=conn-1 target=https://api.stripe.com/v1/charges
```

During collection, LSA strips those `event=context` lines out of the stored trace body, materializes a `.contexts.json` sidecar, and joins that context back onto matching runtime events before correlation runs.

The FastAPI surface now mirrors the live collection workflow with:

```text
POST /collect-trace
POST /collect-audit
POST /jobs/audit-trace
POST /jobs/collect-audit
GET /jobs
GET /jobs/{job_id}
GET /workers
GET /workers/{worker_id}
GET /workers/{worker_id}/heartbeats
GET /workers/{worker_id}/heartbeat-rollups
GET /jobs/{job_id}/lease-events
GET /jobs/{job_id}/lease-event-rollups
GET /analytics/control-plane
GET /metrics
GET /control-plane-alerts
POST /control-plane-alerts/{alert_id}/acknowledge
GET /control-plane-alert-silences
POST /control-plane-alert-silences
POST /control-plane-alert-silences/{silence_id}/cancel
GET /control-plane-oncall-schedules
GET /control-plane-oncall-schedules/resolve
POST /control-plane-oncall-schedules
POST /control-plane-oncall-schedules/{schedule_id}/cancel
POST /maintenance/prune-history
GET /maintenance/mode
POST /maintenance/control-plane-runtime-smoke
POST /maintenance/control-plane-runtime-rehearsal
GET /maintenance/control-plane-runtime-validation
GET /maintenance/control-plane-runtime-validation-reviews
POST /maintenance/control-plane-runtime-validation-reviews/process
POST /maintenance/control-plane-runtime-validation-reviews/{review_id}/assign
POST /maintenance/control-plane-runtime-validation-reviews/{review_id}/resolve
POST /maintenance/mode/enable
POST /maintenance/mode/disable
GET /maintenance/control-plane-preflight
GET /maintenance/control-plane-runtime-backend
POST /maintenance/control-plane-runtime-backend/inspect
POST /maintenance/postgres-runtime-shadow-sync
POST /maintenance/control-plane-runbook
GET /maintenance/control-plane-cutover-preflight
POST /maintenance/control-plane-cutover-bundle
POST /maintenance/postgres-bootstrap-package/inspect
POST /maintenance/postgres-bootstrap-package/plan
POST /maintenance/postgres-bootstrap-package/execute
POST /maintenance/postgres-target/inspect
POST /maintenance/postgres-bootstrap-package/verify-target
POST /maintenance/postgres-cutover-rehearsal
POST /maintenance/control-plane-cutover-decision
GET /maintenance/control-plane-schema/contract
GET /maintenance/control-plane-schema
POST /maintenance/control-plane-schema/migrate
POST /maintenance/export-control-plane-backup
POST /maintenance/import-control-plane-backup
POST /maintenance/emit-control-plane-alerts
POST /maintenance/process-control-plane-alert-followups
```

Those endpoints return the staged `trace_metadata_path` and `trace_symbol_map_path` alongside the collected trace or audit result.
They also return `trace_context_map_path` when collection generated or staged a context sidecar.

When `LSA_API_KEY` is set, every endpoint except `/health` requires either `X-API-Key: <token>` or `Authorization: Bearer <token>`.

The control plane now treats the database as a first-class runtime contract instead of assuming one implicit local path. `LSA_DATABASE_URL` currently supports SQLite URLs, and `LSA_SQLITE_BUSY_TIMEOUT_MS` hardens lock wait behavior for split API/worker deployments sharing one SQLite file. The `/health` endpoint reports the resolved database backend, URL, path, readiness, writability, schema version state, and runtime-driver readiness in addition to worker state.

There is now also an explicit runtime-backend activation probe. `lsa control-plane-runtime-backend` and `GET /maintenance/control-plane-runtime-backend` report whether the currently configured database backend is runtime-supported, which driver it expects, whether that dependency is installed, and what blockers remain. `lsa inspect-control-plane-runtime-backend --database-url ...` and `POST /maintenance/control-plane-runtime-backend/inspect` do the same for an arbitrary candidate URL such as `postgresql://...`. That gives us a real operator-facing answer to “can this environment activate the Postgres runtime path yet?” instead of forcing teams to infer it from packaging and docs.

There is now also a first shadow-sync bridge for the future runtime store. `lsa sync-postgres-runtime-shadow` and `POST /maintenance/postgres-runtime-shadow-sync` take the current control-plane maintenance and queue slice from the active runtime store and copy it into a Postgres target using the shared schema contract. That slice now covers maintenance-mode metadata, append-only maintenance events, jobs, workers, worker heartbeats, and job lease events, which gives us a real Postgres-backed control-plane foothold before moving the wider alert and on-call surfaces.

The snapshot and audit metadata path is now also explicitly feature-gated. If `LSA_ENABLE_POSTGRES_RUNTIME_SNAPSHOTS_AUDITS=1` is set, the runtime bundle will try to place snapshot and audit records on `LSA_POSTGRES_RUNTIME_SNAPSHOTS_AUDITS_DATABASE_URL` (or fall back to `LSA_DATABASE_URL` if that override is unset). Activation uses the same runtime-availability checks as the job path, so a missing driver or unsupported backend still fails loudly instead of drifting into a half-activated state.

On top of that, the job repository bootstrap path is now explicitly feature-gated. If `LSA_ENABLE_POSTGRES_RUNTIME_JOBS=1` is set, the app will try to activate the job repository against `LSA_POSTGRES_RUNTIME_JOBS_DATABASE_URL` (or fall back to `LSA_DATABASE_URL` if that override is unset). Activation is not silent: the runtime backend still has to pass the same availability checks, including the required driver dependency. When activated, the Postgres-backed runtime slice now supports snapshot metadata persistence, audit metadata persistence, live queue claim, stale-lease requeue, lease renewal, worker-visibility counts, control-plane alert persistence and acknowledgement, alert silences, on-call schedule persistence, and governed on-call change-request persistence, while SQLite remains the safe default for the full control plane.

The API and CLI now bootstrap those repositories through one control-plane runtime bundle instead of constructing snapshots, audits, and jobs independently. That bundle exposes whether the current process is on a `shared` backend layout or a `mixed` transition layout. `/health` now reports `snapshot_repository_backend`, `audit_repository_backend`, `job_repository_backend`, `control_plane_repository_layout`, and `control_plane_mixed_backends`, so operators can see when the system is intentionally straddling SQLite and Postgres during a staged backend transition, or when all three repository surfaces have moved together onto one backend.

`/health` now also exposes explicit activation state for both staged Postgres runtime slices: `snapshots_audits_repository_runtime_enabled`, `snapshots_audits_repository_runtime_active`, `job_repository_runtime_enabled`, and `job_repository_runtime_active`. That makes it obvious whether the feature flags are only configured or whether the live repositories have actually crossed onto the intended backend.

There is now also a cleanup-safe runtime smoke path for that bundle. `lsa run-control-plane-runtime-smoke` and `POST /maintenance/control-plane-runtime-smoke` create a synthetic snapshot, audit, and job through the live repositories, verify that each one round-trips, record a maintenance event, and then remove the records and generated artifacts by default. That gives operators a direct “does this backend actually work for the control-plane surfaces we enabled?” probe without leaving junk state behind.

On top of that, there is now a first-class runtime rehearsal path. `lsa run-control-plane-runtime-rehearsal` and `POST /maintenance/control-plane-runtime-rehearsal` combine explicit backend/layout expectations with the live smoke flow and persist an audited maintenance event stating whether the current runtime actually matches the intended deployment posture. This is the structured path for assertions like “all three repository surfaces are really on Postgres in a shared layout right now,” instead of forcing operators to compare individual health fields by hand.

That rehearsal evidence is now surfaced directly too. `lsa control-plane-runtime-validation` and `GET /maintenance/control-plane-runtime-validation` report whether the latest runtime rehearsal is missing, failed, aging, critical, or healthy for the active environment, including the latest rehearsal age, expected backend/layout, and recorded check results.

That validation surface now also carries an explicit cadence state. Runtime proof can be `fresh`, `due_soon`, `aging`, `overdue`, `missing`, or `failed`, with `next_due_at` and `due_in_hours` surfaced for operators. That gives the alert loop a chance to warn before proof crosses the main warning/critical age gates.

Runtime validation now also supports an environment-aware policy bundle at `LSA_RUNTIME_VALIDATION_POLICY_PATH`. That file can keep one default posture and override cadence and follow-up behavior per environment, for example:

```json
{
  "default": {
    "due_soon_age_hours": 18,
    "warning_age_hours": 24,
    "critical_age_hours": 72,
    "reminder_interval_seconds": 900,
    "escalation_interval_seconds": 1800
  },
  "environments": {
    "prod": {
      "due_soon_age_hours": 8,
      "warning_age_hours": 12,
      "critical_age_hours": 24,
      "reminder_interval_seconds": 300,
      "escalation_interval_seconds": 900
    }
  }
}
```

`lsa control-plane-runtime-validation` and `GET /maintenance/control-plane-runtime-validation` now report the effective `policy_source` plus the active reminder/escalation intervals, so operators can see exactly which runtime-proof rules are in force for the current environment.

The same runtime-validation policy bundle can now also govern review ownership with optional fields like:

- `owner_team`
- `allowed_assignee_teams`
- `auto_assign_to`
- `auto_assign_to_team`

That lets `prod` reviews open directly into the right team lane instead of relying on ad hoc assignment after the fact.

On top of that, runtime proof now has a first-class review queue. `lsa process-control-plane-runtime-validation-reviews` and `POST /maintenance/control-plane-runtime-validation-reviews/process` open review requests when proof is `due_soon`, `aging`, `overdue`, `missing`, or `failed`, and automatically resolve them when proof returns to policy. Reviews are rebuilt from the append-only maintenance-event stream, so the workflow stays durable and audit-friendly without introducing a second fragile state store.

Runtime proof now also has its own alert family in the control-plane pipeline. When proof is `due_soon`, `aging`, `overdue`, `missing`, or `failed`, the worker can emit a dedicated `control-plane-runtime-validation:*` incident alongside the broader aggregate control-plane evaluation alert. That keeps runtime-proof freshness visible even when other degraded conditions are present, and it gives reminders/escalations a stable chain to follow for this one operator concern.

That signal is now part of the risky operator gates too. Control-plane maintenance preflight includes the current runtime-validation summary, and Postgres cutover readiness/promotion now require passing runtime-validation evidence by default. In practice, that means the expected operator order is no longer “prepare bundle, rehearse cutover, promote.” It is:

```text
run control-plane runtime rehearsal
prepare cutover bundle
run Postgres cutover rehearsal
evaluate cutover readiness
record cutover decision
```

If a team intentionally needs to bypass that last-known-good runtime proof during investigation or lower-risk work, maintenance gating can stay advisory by default and cutover CLI/API flows can explicitly skip runtime-validation enforcement when the operator makes that choice visible.

The default policy knobs are:
- `LSA_MAINTENANCE_RUNTIME_VALIDATION_REQUIRED`
- `LSA_CUTOVER_RUNTIME_VALIDATION_REQUIRED`

By default, maintenance only surfaces runtime-validation problems in preflight while cutover readiness and promotion enforce them. That keeps routine maintenance usable while making backend-cutover decisions harder to fake.

The `/health` endpoint now reports whether auth is enabled, whether the local control-plane database is ready, whether the API is running in `embedded` or `external` worker mode, and how many workers are currently heartbeating. Long-running or collector-backed audits can also be submitted asynchronously through `/jobs/*`, which persist `queued`, `running`, `completed`, and `failed` states in `data/control_plane.db` along with their serialized result payloads.

For continuous scraping, the control plane now also exposes Prometheus-style metrics through `GET /metrics` and `lsa control-plane-metrics`. That surface includes queue depth by status, worker activity, lease churn, on-call backlog, schema drift, evaluation state, and persisted alert counts. If `LSA_API_KEY` is set, the metrics endpoint is protected by the same API-key requirement as the rest of the service endpoints.

Production shape now assumes a split deployment by default: the API accepts and persists jobs, while a separate `lsa worker` process drains the queue. If you explicitly set `LSA_RUN_EMBEDDED_WORKER=1`, the API will also start an embedded worker for single-process development. In both modes, startup recovery requeues stale `running` jobs before processing resumes. `/health` reports `worker_running`, `active_workers`, `queued_jobs`, and `running_jobs`, while job records now include `claimed_by_worker_id` and `lease_expires_at` so operators can see which worker owns a running lease. Workers also renew those leases while a job is still running, and a healthy worker can reclaim an expired lease from a stale owner without waiting for a process restart. Worker records are queryable through `/workers/*`.

There is now a matching container deployment path under [docker/compose.control.yml](/Users/gani/Desktop/Intent-drive/living-systems-auditor/docker/compose.control.yml) and [docker/Dockerfile.control](/Users/gani/Desktop/Intent-drive/living-systems-auditor/docker/Dockerfile.control). The default compose stack runs the API and `lsa worker` as separate services against a shared `lsa_data` volume, with SQLite-oriented defaults shown in [docker/control.env.example](/Users/gani/Desktop/Intent-drive/living-systems-auditor/docker/control.env.example).

Example:

```bash
docker compose --env-file docker/control.env.example -f docker/compose.control.yml up --build
```

There is now also an opt-in Postgres deployment profile in that same compose file. The `postgres` profile starts a local Postgres 16 container on its own volume and pairs with [docker/control.postgres.env.example](/Users/gani/Desktop/Intent-drive/living-systems-auditor/docker/control.postgres.env.example), which enables both Postgres runtime feature gates and points snapshots, audits, and jobs at the same Postgres service:

```bash
docker compose \
  --profile postgres \
  --env-file docker/control.postgres.env.example \
  -f docker/compose.control.yml \
  up --build
```

That profile also turns on `LSA_PIP_INSTALL_EXTRAS=postgres`, so the API and worker images install the `psycopg` runtime dependency needed for the live Postgres-backed control-plane slice instead of only enabling the feature flags. The default SQLite profile leaves that extra empty.

That profile keeps the default SQLite deployment untouched while giving us a concrete multi-service runtime shape for the staged Postgres control-plane path.

There is also an operator rehearsal harness for that Postgres profile in [docker/run_postgres_runtime_rehearsal.sh](/Users/gani/Desktop/Intent-drive/living-systems-auditor/docker/run_postgres_runtime_rehearsal.sh). It brings the compose stack up, waits for API readiness, runs the first-class runtime rehearsal against the live service, asserts a shared Postgres layout, and tears the stack back down unless `--keep-up` is set.

Example:

```bash
bash docker/run_postgres_runtime_rehearsal.sh
```

The control plane now also supports full-fidelity backup and restore. `lsa export-control-plane-backup` and `POST /maintenance/export-control-plane-backup` write a versioned JSON bundle that includes both database records and the critical snapshot/report artifacts those records depend on. Restore is intentionally strict: import only succeeds into an empty control plane unless you explicitly pass `--replace-existing` or `replace_existing=true`, and replace mode clears restorable snapshot/report artifacts before writing the recovered bundle.

Database lifecycle is now visible too. `lsa control-plane-schema` and `GET /maintenance/control-plane-schema` report the current schema version, the expected schema version, readiness, pending migration count, and the applied migration records. `lsa control-plane-schema-contract` and `GET /maintenance/control-plane-schema/contract` expose the shared schema contract itself: schema version, migration identity, runtime-supported backends, bootstrap-supported backends, and the canonical table list used by both the SQLite runtime and the Postgres cutover path. `lsa migrate-control-plane-schema` and `POST /maintenance/control-plane-schema/migrate` then apply the idempotent schema repair path for this build and return the resulting version state. That gives deployments a stable way to distinguish “database file exists” from “database is on the schema this build expects,” and a direct repair command when metadata drifts or an older local DB needs to be reconciled.

There is now also a first-class control-plane maintenance switch. `lsa control-plane-maintenance-mode` and `GET /maintenance/mode` show the current state, while the enable/disable commands and endpoints let operators pause mutating API flows and worker job execution during backups, schema work, or environment cutovers. Health and metrics surfaces both expose whether maintenance mode is active.

On top of that switch, the control plane now has a guarded maintenance workflow. `lsa control-plane-preflight` and `GET /maintenance/control-plane-preflight` surface the operator checks that matter before risky work starts: database readiness and writability, schema drift, current maintenance state, worker mode, active workers, and live queue counts, plus explicit blockers and warnings. `lsa run-control-plane-maintenance-workflow` and `POST /maintenance/control-plane-runbook` then sequence preflight, maintenance-mode enablement, versioned backup export, schema repair, and optional maintenance-mode disablement into one audited runbook path instead of relying on manual operator ordering.

There is now also an explicit database cutover bridge for moving beyond the current SQLite runtime safely. `lsa control-plane-cutover-preflight` and `GET /maintenance/control-plane-cutover-preflight` validate a target database URL such as `postgresql://...`, redact credentials for operator-safe output, and combine that target validation with the source maintenance preflight. `lsa prepare-control-plane-cutover-bundle` and `POST /maintenance/control-plane-cutover-bundle` then run the guarded maintenance workflow, export a versioned control-plane backup bundle, and write a cutover manifest that captures source metadata, target database details, the maintenance workflow result, and a recommended restore order for the target system. This does not pretend the runtime already executes on Postgres, but it gives production operators a real audited bridge artifact for the eventual cutover.

For Postgres targets, that cutover bundle now also emits a concrete bootstrap package next to the manifest. The package contains:

```text
apply.sh
schema.sql
data.sql
verify.sql
manifest.json
artifacts/snapshots/*
artifacts/reports/*
```

`schema.sql` creates a Postgres-shaped control-plane schema, `data.sql` inserts the bundled records with normalized artifact paths, `verify.sql` checks imported row counts and schema version state, `apply.sh` sequences the package through `psql`, and the `artifacts/` tree materializes the snapshot and report files the imported records refer to. That means the cutover flow now produces something a future Postgres-backed repository can actually ingest, instead of only a planning document.

The bootstrap package also now carries integrity metadata. `manifest.json` includes SHA-256 digests for the generated SQL and extracted artifact files, plus the shared control-plane schema contract the package was generated against. You can verify the package with `lsa inspect-postgres-bootstrap-package` or `POST /maintenance/postgres-bootstrap-package/inspect`. That surface reports missing files, checksum mismatches, and a `valid` result so operators can verify the handoff artifact before applying it to a target Postgres environment.

There is now also a first-class execution-planning layer around that package. `lsa plan-postgres-bootstrap-execution` and `POST /maintenance/postgres-bootstrap-package/plan` build the exact `psql` command sequence, artifact-copy decision, and blockers for a target database URL and `psql` binary path. `lsa execute-postgres-bootstrap-package` and `POST /maintenance/postgres-bootstrap-package/execute` then either perform a safe dry run anywhere or execute the full schema/data/verification flow when a real `psql` binary is available.

On top of package generation, the cutover path can now inspect a live Postgres target directly. `lsa inspect-postgres-target` and `POST /maintenance/postgres-target/inspect` query a target database through `psql`, report schema version state, maintenance-mode metadata, table presence, and per-table row counts, and evaluate that against the shared control-plane schema contract. `lsa verify-postgres-bootstrap-package` and `POST /maintenance/postgres-bootstrap-package/verify-target` then compare a generated bootstrap package against that live target, checking contract identity, expected schema version, and row-count alignment before a real cutover or rehearsal is declared safe.

There is now also a first-class cutover rehearsal workflow above those primitives. `lsa run-postgres-cutover-rehearsal` and `POST /maintenance/postgres-cutover-rehearsal` run an audited rehearsal that inspects the package, inspects the target, executes either a dry-run package application or a real apply-to-target rehearsal, and then, when applying for real, re-inspects and verifies the target afterward. Each run is persisted as a maintenance event, so cutover rehearsals become part of the control-plane operational history instead of an undocumented shell session.

On top of readiness, there is now also an explicit cutover decision workflow. `lsa decide-control-plane-cutover` and `POST /maintenance/control-plane-cutover-decision` evaluate the current readiness evidence, then persist an audited decision for the exact package and target combination. The flow can record straightforward approvals, manual rejections, automatic blocks when readiness gates fail, and governed overrides when an operator intentionally approves an unready cutover with an explicit note. That gives the control plane a durable approval trail instead of treating the final promotion step as an unlogged human judgment call.

## North Star

The long-form build direction we are driving toward is:

- a real Postgres-backed runtime store, not just SQLite plus cutover tooling
- multi-worker and eventually multi-node operation with durable queue ownership
- tenant-aware authz, RBAC, audit logs, and ownership boundaries
- a real operator UI for audits, alerts, on-call routing, and governed changes
- first-class observability with metrics, traces, dashboards, and incident workflows
- live runtime collection on noisy production workloads, not just curated fixtures
- stronger function attribution from real symbol, stack, request, and trace context
- local-LLM remediation and policy review that feels meaningfully better than static runbooks
- customer-grade deploy, backup, restore, rollback, and disaster-recovery workflows
- breakout-level proof on one undeniable use case where intent-aware runtime truth beats conventional tooling

The point of keeping these ideas here is practical: this README is now part current-state contract and part active build ledger, so we can keep shipping against the same north-star target without losing the thread.

The control plane now also keeps append-only history for worker heartbeats and job lease transitions. That means you can inspect not just the latest worker row or job row, but the timeline of `lease_claimed`, `lease_renewed`, `lease_expired_requeued`, `job_completed`, and `job_failed` events, plus the corresponding worker heartbeat trail through `/workers/{worker_id}/heartbeats` and `/jobs/{job_id}/lease-events`.

History retention is now time-based and configurable. Worker heartbeat history defaults to `14` days, job lease event history defaults to `30` days, and the worker performs periodic maintenance in the background. Older raw history is compacted into daily rollup tables before it is removed, so the control plane keeps coarse longitudinal visibility without keeping every row forever. You can also trigger maintenance directly through `lsa prune-history` or `POST /maintenance/prune-history`, and inspect the summarized buckets through the rollup endpoints and CLI commands.

Those same rollups now feed a control-plane analytics surface for operators. `GET /analytics/control-plane?days=30` and `lsa control-plane-analytics --days 30` summarize queue shape, current worker health, lease churn, and job throughput over a bounded time window by merging both raw recent history and already-compacted day buckets. That keeps the newest operating window accurate instead of making the post-compaction timeline look artificially sparse.

That analytics payload now also includes a `runtime_validation` block derived from the latest runtime rehearsal evidence, and the evaluation layer can raise findings like `runtime_rehearsal_missing`, `runtime_rehearsal_failed`, or `runtime_rehearsal_age` when control-plane runtime proof is absent or stale.

It can also now raise `runtime_rehearsal_due_soon` before the warning-age threshold is actually crossed, so teams can refresh runtime proof proactively instead of finding out at cutover or promotion time.

The analytics response now also includes an `evaluation` block with:

```text
status=healthy|degraded|critical
findings=[...]
thresholds={...}
```

Current built-in findings cover:
- queued backlog above warning or critical thresholds
- stale workers above warning or critical thresholds
- expired lease requeue churn above warning or critical thresholds
- elevated job failure rate once enough finished jobs exist in the window
- queued work with zero active workers, which is treated as critical
- ambiguous on-call route overlaps detected in upcoming schedule coverage
- stale governed on-call change reviews that exceed the configured SLA

Those findings can now flow into a durable control-plane alert pipeline. The worker evaluates the control plane on a schedule, deduplicates repeated alert signatures inside a configurable cooldown window, persists emitted alerts in SQLite, writes them to a JSONL sink, and can optionally POST the same payload to a webhook.

Thresholds are configurable through environment variables:

```text
LSA_ANALYTICS_QUEUE_WARNING_THRESHOLD
LSA_ANALYTICS_QUEUE_CRITICAL_THRESHOLD
LSA_ANALYTICS_STALE_WORKER_WARNING_THRESHOLD
LSA_ANALYTICS_STALE_WORKER_CRITICAL_THRESHOLD
LSA_ANALYTICS_EXPIRED_LEASE_WARNING_THRESHOLD
LSA_ANALYTICS_EXPIRED_LEASE_CRITICAL_THRESHOLD
LSA_ANALYTICS_JOB_FAILURE_RATE_WARNING_THRESHOLD
LSA_ANALYTICS_JOB_FAILURE_RATE_CRITICAL_THRESHOLD
LSA_ANALYTICS_JOB_FAILURE_RATE_MIN_SAMPLES
LSA_ANALYTICS_ONCALL_CONFLICT_WARNING_THRESHOLD
LSA_ANALYTICS_ONCALL_CONFLICT_CRITICAL_THRESHOLD
LSA_ANALYTICS_ONCALL_PENDING_REVIEW_WARNING_THRESHOLD
LSA_ANALYTICS_ONCALL_PENDING_REVIEW_CRITICAL_THRESHOLD
LSA_ANALYTICS_ONCALL_PENDING_REVIEW_SLA_HOURS
```

Alert emission is controlled through:

```text
LSA_CONTROL_PLANE_ALERTS_ENABLED
LSA_CONTROL_PLANE_ALERT_WINDOW_DAYS
LSA_CONTROL_PLANE_ALERT_INTERVAL_SECONDS
LSA_CONTROL_PLANE_ALERT_DEDUP_WINDOW_SECONDS
LSA_CONTROL_PLANE_ALERT_REMINDER_INTERVAL_SECONDS
LSA_CONTROL_PLANE_ALERT_ESCALATION_INTERVAL_SECONDS
LSA_CONTROL_PLANE_ALERT_WEBHOOK_URL
LSA_CONTROL_PLANE_ALERT_ESCALATION_WEBHOOK_URL
```

By default, emitted alerts are also appended to `data/control_plane_alerts.jsonl`. Operators can force a fresh evaluation and emission cycle with `lsa emit-control-plane-alerts --force` or `POST /maintenance/emit-control-plane-alerts`, then inspect persisted alert history through `lsa list-control-plane-alerts` or `GET /control-plane-alerts`.

Timed follow-ups are now part of the same lifecycle. If a degraded or critical incident stays unacknowledged, `lsa process-control-plane-alert-followups --force` or `POST /maintenance/process-control-plane-alert-followups` can emit reminders or escalations immediately, while the worker also checks for them on its normal alert cadence. Escalations can be routed to a separate webhook target through `LSA_CONTROL_PLANE_ALERT_ESCALATION_WEBHOOK_URL`.

That follow-up path now tracks runtime-proof incidents independently too. If a dedicated runtime-validation alert is active, its reminders and escalations are processed separately from the aggregate control-plane incident chain, so “runtime proof is expiring” cannot get buried behind an unrelated queue or on-call finding. Those follow-up timers can also come from the environment-aware runtime-validation policy, so `prod` can chase expiring proof much more aggressively than `staging`.

Runtime proof now also has an owned review workflow before it turns into a stale-proof problem. Active reviews can be listed, assigned, and resolved through the new runtime-validation review commands and endpoints, and the worker opens or auto-resolves those reviews on its normal control-plane cadence. That gives teams a durable “who owns refreshing runtime proof for this environment?” queue instead of relying only on alert acknowledgements.

Alert delivery can now also follow persisted on-call schedules. A schedule defines:
- team name
- IANA timezone like `UTC` or `Asia/Kolkata`
- schedule owner/requester via `created_by`
- optional `created_by_team`, `created_by_role`, `change_reason`, `approved_by`, `approved_by_team`, `approved_by_role`, and `approval_note` metadata for governed changes
- weekdays as `0-6` for Monday-Sunday
- a local start and end time
- rotation name for primary, secondary, holiday, or temporary handoff coverage
- numeric priority so the strongest active route wins during overlap
- optional local-date bounds for holiday overrides or temporary coverage swaps
- optional route-specific webhook and escalation webhook overrides

When schedules overlap, the router prefers the highest priority active match, then the most date-specific window, then the newest record. That lets you layer holiday overrides and handoff windows on top of a stable baseline rotation. Emitted incidents, reminders, escalations, and suppressed alerts include the selected route in their payload and prefer the route-specific webhooks over the global defaults.

Operators can now also preview the effective route before an incident fires. `lsa resolve-control-plane-oncall-route` and `GET /control-plane-oncall-schedules/resolve?at=...` return the selected route plus the ranked active candidates and the reasons each candidate was ordered where it was. The timestamp must use ISO 8601 format and include a timezone offset when provided explicitly.

The control-plane analytics layer now also scans upcoming schedule coverage for ambiguous overlaps. If multiple active routes would tie on routing precedence and only fall back to record creation order, analytics emits an `oncall_route_conflicts` finding with sample conflicting schedule groups. That means bad overlap policy can alert before it misroutes a real incident.

That same `oncall` analytics block now tracks governed review backlog for the active environment. Pending change requests older than the configured SLA contribute `pending_review_count`, `stale_pending_review_count`, `oldest_pending_review_age_hours`, and sample stale requests, and can emit an `oncall_pending_reviews_stale` finding when approvals are waiting too long.

Those same ambiguous overlaps are now governed at write time. If a new schedule would introduce that kind of ambiguous overlap, creation is rejected unless the request includes `change_reason`, `approved_by`, and `approved_by_role`. This keeps risky routing changes auditable instead of letting them slip in as silent config drift.

That approval path is now policy-aware too. By default, ambiguous overlaps require:
- `approved_by_role` to be one of `manager`, `director`, or `admin`
- no self-approval by the same `created_by` identity

These policy defaults are configurable through:

```text
LSA_ENVIRONMENT_NAME
LSA_ONCALL_POLICY_PATH
LSA_ONCALL_APPROVAL_REQUIRED_ROLES
LSA_ONCALL_ALLOW_SELF_APPROVAL
```

Each schedule and governed change request now also carries an `environment_name`. When omitted, the service uses `LSA_ENVIRONMENT_NAME`, which defaults to `default`. Active route resolution and risky-overlap review checks are scoped to the current environment, so a `prod` overlap does not force approval in `staging`.

If `LSA_ONCALL_POLICY_PATH` points at a JSON policy file, the service now resolves governance rules by environment, then team and rotation, before falling back to the global defaults. A minimal example looks like:

```json
{
  "default": {
    "required_approver_roles": ["director", "admin"],
    "allow_self_approval": false
  },
  "teams": {
    "platform": {
      "owner_team": "platform",
      "allowed_requester_teams": ["platform"],
      "allowed_approver_teams": ["platform"],
      "allowed_approver_ids": ["director-platform"]
    }
  },
  "rotations": {
    "holiday": {
      "required_approver_roles": ["admin"]
    }
  },
  "environments": {
    "prod": {
      "default": {
        "required_approver_roles": ["admin"]
      },
      "teams": {
        "payments": {
          "allowed_requester_teams": ["platform"],
          "allowed_approver_teams": ["platform"]
        }
      }
    }
  }
}
```

That policy layer now lets governance vary by environment, owning team, or rotation instead of relying on one global approval rule for every schedule change.

Governed changes can now move through an explicit review workflow instead of relying only on inline approval fields. `lsa submit-control-plane-oncall-change-request` and `POST /control-plane-oncall-change-requests` persist a durable change request with `pending_review`, `rejected`, or `applied` status. Safe requests auto-apply immediately with an audit trail, while ambiguous overlap requests stay pending until `lsa review-control-plane-oncall-change-request` or `POST /control-plane-oncall-change-requests/{request_id}/review` approves or rejects them. Pending requests can now also be explicitly owned through `lsa assign-control-plane-oncall-change-request` or `POST /control-plane-oncall-change-requests/{request_id}/assign`, which records assignee, assignee team, assigner, assignment time, and an optional ownership note. Approved requests create the schedule and preserve reviewer identity, reviewer team, reviewer role, review note, and the applied schedule ID on the request record.

Alert records can now also be acknowledged in place. Acknowledgement does not suppress future alerts by itself; it marks that a human has taken ownership of a specific emission and records who acknowledged it plus an optional note.

Acknowledging either the original incident alert or a reminder/escalation follow-up marks the root incident as owned and stops further follow-up emissions for that incident.

Silences are a separate control. A silence matches either an exact `alert_key`, a `finding_code`, or both, and suppresses future degraded or critical alert emissions for a bounded duration. Silenced conditions still appear in analytics; the silence only changes outbound alert delivery. Recovery alerts are not silenced, so operators can still see when the control plane returns to healthy after a muted incident window.

When a trace includes fields like `fd`, `tid`, or collector-scoped PID metadata, enrichment now derives stable `socket_id` and `flow_id` values automatically. That gives the resolver stronger binding keys than plain process-name continuity on real runtime traces.

If an upstream collector can emit code-level hints, the resolver now prefers them before heuristic matching. Useful fields include:

```text
qualname=charge_customer
module=app function_name=charge_customer
source_file=app.py line=4
stack=worker_loop>app.charge_customer>requests.post
call_stack=scheduler|app.py:4|requests.post
symbol=app:charge_customer
frame_symbol=app.py:4
```

Those hints let the audit path attribute drift directly to the intended function even when the runtime process label is generic. When a collector only has rough symbol strings, enrichment now normalizes common forms like `app:charge_customer` into canonical module/function hints before resolution. When a stack-like hint is used, the resolved event also records which stack entry won via `trace_hint_value` and `trace_hint_index`.

For lower-level collector output, a symbol sidecar can bridge addresses into those same hints. Example:

```json
{
  "symbols": {
    "0x4010": "app:charge_customer",
    "0x7777": "requests.post"
  }
}
```

You can also provide a local alias map at `data/destination_aliases.json`, for example:

```json
{
  "93.184.216.34": "api.stripe.com",
  "10.0.0.5:8080": "internal-billing.local"
}
```

When present, alias matches are considered during drift comparison and preserved in event metadata.

When traces include correlation keys such as `request_id=req-123` or `trace_id=trace-abc`, the auditor can carry a resolved function identity across related events in the same runtime sequence.

Common tracing headers are normalized automatically, so collectors do not need to pre-convert them into LSA-specific keys. Supported examples include:

```text
traceparent=00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
b3=4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-1-a2fb4a1d1a96d312
x-request-id=req-123
otel.trace_id=4bf92f3577b34da6a3ce929d0e0e4736
otel.span_id=00f067aa0ba902b7
uber-trace-id=4bf92f3577b34da6:00f067aa0ba902b7:a2fb4a1d1a96d312:1
baggage=request_id=req-123,tenant=acme
```

These are normalized into canonical `trace_id`, `span_id`, `parent_span_id`, and `request_id` fields before correlation runs.

Each audit now also returns an `explanation` object with a concise summary, impacted functions, unexpected targets, primary session key, and supporting evidence lines. This makes the result easier to feed into dashboards or operator review flows without re-deriving the narrative from raw events.

## Repository shape

```text
living-systems-auditor/
├── lsa/
│   ├── api/
│   ├── cli/
│   ├── core/
│   ├── drift/
│   ├── ingest/
│   └── remediation/
├── tests/
├── docs/
├── dashboard/
├── ebpf/
└── docker/
```

## Near-term roadmap

1. Replace the Python-only parser with tree-sitter for multi-language support.
2. Swap the rule-based remediation stub with a local LLM adapter.
3. Push collector-side context further so live traces emit richer correlation and identity fields directly.
4. Replace the local API-key model with a fuller auth and multi-tenant identity layer.
5. Move background jobs off in-process threads and onto a durable worker model.

## Flashpoint target

The first real proof point is not a large feature list. It is one credible case where the system flags semantic drift before a service failure is obvious, and produces an explanation an engineer would actually trust.
