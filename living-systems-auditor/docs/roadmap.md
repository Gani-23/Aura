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
- Add drift thresholds for new hosts, latency shifts, and novel exception classes.
- Capture repeatable demo traces for the first live proof point.

## Phase 3

- Wire in a local LLM client behind the current rule-based remediation interface.
- Let operator review flows accept, annotate, or reject the generated audit explanation.
- Store remediation reports in a queryable format.
- Add operator review loops so the system can learn from accepted and rejected reports.
- Replace in-process background threads with a durable worker/executor model.
- Extend the standalone worker into a supervised multi-worker model with explicit concurrency control and heartbeats.
- Add lease renewal and stale-worker takeover logic for long-running jobs.
- Replace the single shared API-key model with tenant-aware identity, authz, and audit logging.

## Flashpoint note

The breakout milestone is one high-confidence example where LSA catches meaningful semantic drift before an outage is obvious and produces an explanation an engineer would endorse after review.
