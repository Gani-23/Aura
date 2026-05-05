# Roadmap

## Phase 0

- Stand up the local Linux VM and verify the eBPF toolchain.
- Finalize the local model runtime choice and measure memory headroom on the target Mac Mini M2.
- Keep a short setup log so the environment can be recreated without guesswork.

## Phase 1

- Replace the Python `ast` ingest path with tree-sitter.
- Expand graph extraction to cover imports, call edges, and test assertions more deeply.
- Add snapshot versioning so changes can be diffed over time.

## Phase 2

- Turn real bpftrace output into normalized `ObservedEvent` payloads.
- Emit structured connect traces with PID, process name, destination address, and destination port.
- Return a concise audit explanation summary alongside correlated session evidence.
- Preserve collector session metadata next to trace artifacts so later audits retain runtime collection context.
- Derive socket- and flow-level correlation identifiers from collector metadata when request IDs are absent.
- Accept explicit module/function/source-location hints from upstream collectors to reduce heuristic attribution.
- Accept stack or callsite chains from upstream collectors and bind to the strongest matching function in the graph.
- Normalize rough collector symbol formats into canonical hint fields before function resolution.
- Resolve raw collector addresses through trace-local symbol maps when full semantic hints are not emitted directly.
- Stage collector-provided symbol maps automatically during trace collection so live audits can consume them without manual file wiring.
- Materialize inline collector symbol definitions into generated trace-local symbol maps during collection.
- Keep API and CLI collection surfaces aligned so live collection features are available over both interfaces.
- Normalize common tracing propagation formats from collectors into canonical correlation fields automatically.
- Normalize OpenTelemetry attribute names, Jaeger trace IDs, and baggage-carried request identity into the same correlation model.
- Stage and join trace-local context maps so collectors can emit correlation metadata separately from raw network events.
- Persist snapshots, audits, and asynchronous job state in a SQLite-backed local control plane.
- Protect the API with deploy-time API keys so live collection endpoints are not open by default in production-like environments.
- Expose queueable audit endpoints so long-running trace workflows can run asynchronously and be polled by operators.
- Recover stale `running` jobs on startup so the local worker can resume after a process restart.
- Split queue execution into a standalone worker process so the API can run without owning job execution.
- Track worker heartbeats and job leases explicitly so the API can report live execution health instead of only queue depth.
- Renew active leases during long-running jobs and let healthy workers reclaim expired leases from stale owners.
- Persist append-only heartbeat and lease-event history so ownership changes can be reviewed after incidents.
- Enforce retention windows and explicit pruning for the new history tables so forensic state does not grow unbounded.
- Compact older raw heartbeat and lease-event records into daily summaries before pruning them.
- Expose control-plane analytics over API and CLI so operators can review worker health, lease churn, and queue throughput across mixed raw and rolled-up history.
- Add config-backed control-plane evaluation so analytics windows can be marked healthy, degraded, or critical with explicit findings.
- Persist and emit deduplicated control-plane alerts so degraded or critical evaluations can reach operators through durable local sinks and optional webhooks.
- Add acknowledgement and bounded silencing so operators can own or temporarily mute specific control-plane alert classes without losing analytics visibility.
- Add reminder timers and escalation routing so unacknowledged incidents can follow an explicit follow-up path.
- Add calendar-aware on-call schedules so alert routing can follow team coverage windows instead of one global destination.
- Add rotation-aware handoffs and holiday override windows so schedule routing can model temporary coverage changes without mutating the baseline rota.
- Expose route-resolution preview so operators can inspect which overlapping schedule would win before an incident is emitted.
- Detect ambiguous route overlaps proactively in control-plane analytics so schedule conflicts can page operators before incident misrouting.
- Require explicit approval metadata for risky overlap changes so schedule governance is enforced at write time, not only detected later.
- Enforce approver-role policy and self-approval restrictions on risky overlap changes so governance is machine-checkable instead of convention-only.
- Add a reusable team- and rotation-aware governance policy object so ownership boundaries and approver mapping can vary by schedule domain.
- Persist governed on-call change requests with explicit pending-review, rejected, and applied states so risky routing edits are reviewed before they take effect.
- Add environment-aware governance bundles so `prod`, `staging`, and other deployment tiers can enforce different approval and ownership rules.
- Add drift thresholds for new hosts, latency shifts, and novel exception classes.
- Capture repeatable demo traces for the first live proof point.

## Phase 3

- Wire in a local LLM client behind the current rule-based remediation interface.
- Let operator review flows accept, annotate, or reject the generated audit explanation.
- Store remediation reports in a queryable format.
- Add operator review loops so the system can learn from accepted and rejected reports.
- Replace in-process background threads with a durable worker/executor model.
- Extend the standalone worker into a supervised multi-worker model with explicit concurrency control and heartbeats.
- Add worker heartbeat history and lease event auditing for forensic visibility.
- Add retention, pruning, and rollup policy for the growing heartbeat and lease-event history tables.
- Add historical rollups and summary compaction so old heartbeat and lease-event data can stay queryable at lower cost.
- Replace the single shared API-key model with tenant-aware identity, authz, and audit logging.
- Add alerting hooks and operator SLO thresholds on top of the new control-plane analytics surface.
- Add acknowledgement, silencing, and escalation policy on top of control-plane alert history.
- Add escalation routing, reminder timers, and on-call policy on top of acknowledgements and silences.
- Add calendar-aware on-call schedules and team routing on top of the current reminder/escalation primitives.
- Extend schedule governance into external calendar sync, richer ownership policy, and review workflows that can route through real change-management systems.

## Flashpoint note

The breakout milestone is one high-confidence example where LSA catches meaningful semantic drift before an outage is obvious and produces an explanation an engineer would endorse after review.
