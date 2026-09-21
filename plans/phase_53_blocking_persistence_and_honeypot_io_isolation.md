# Phase 53 Plan: Blocking Persistence and Honeypot I/O Isolation

Status: implemented and closed; retained as historical handoff detail. Closeout: `architecture/performance_optimization_closeout.md`.

Roadmap: `plans/performance_optimization_roadmap.md`.

Depends on: Phase 49 persistence/event-loop baseline complete.

## Objective

Keep synchronous SQLite/filesystem work out of Tokio core workers, reduce avoidable honeypot payload work, and make queued writer shutdown/drain explicit while preserving the public `HoneypotStorage` and `HoneypotWriter` API/capability.

## Current execution issue

`HoneypotWriter` correctly accepts records through a bounded Tokio mpsc channel and batches writes, but `flush_records()` executes synchronous `rusqlite` transaction operations directly from the async writer task.

Periodic pruning in `runner.rs` also invokes synchronous storage methods from Tokio tasks.

The concern is scheduler fairness/tail latency during filesystem or SQLite stalls, not that SQLite itself is necessarily slow.

## Workstream A — Isolate batch flushes from Tokio core workers

Keep at most one batch flush in flight per writer.

Acceptable implementations:

- await one `tokio::task::spawn_blocking` per batch from the single writer task; or
- use one dedicated blocking writer thread owned by `HoneypotWriter`.

Prefer the simpler bounded design supported by Phase 49 measurements.

Requirements:

- no unbounded spawn fanout;
- preserve mpsc `queue_capacity` backpressure;
- preserve `batch_size` and `flush_interval_ms`;
- preserve insertion/error metrics;
- preserve record ordering to the degree the current single consumer provides;
- do not silently drop a batch on blocking-task join failure without recording failure.

If `spawn_blocking` is used, the async writer awaits it before accepting the next flush, so the number of blocking flush operations is naturally bounded.

## Workstream B — Isolate maintenance operations

Move:

- initial `prune_old_records`;
- `enforce_max_records`;
- periodic hourly maintenance;
- mesh-publishing storage reads/writes if measurements show they can block the runtime materially

onto an appropriate blocking boundary.

Periodic maintenance must not accumulate overlapping jobs. Await completion before scheduling the next maintenance cycle or use a single dedicated storage executor.

## Workstream C — Remove payload clone during retention

`apply_retention()` currently clones the complete payload before hashing.

Instead:

1. record original length from `record.payload.len()`;
2. hash `&record.payload` directly;
3. apply None/HashOnly/Truncated/Full mutation to the original buffer.

Preserve the exact SHA-256 digest and retention outputs.

Add tests for empty, small, truncation-boundary, and large payloads across all retention modes.

## Workstream D — Reuse SQLite statements/transaction machinery

Within a batch, avoid reparsing the same INSERT statement for every record.

Evaluate `prepare_cached()` or a transaction-scoped prepared statement.

Preserve:

- schema/column ordering;
- confidence formatting;
- optional payload hash/length representation;
- error counter behavior;
- transaction atomicity semantics currently expected by tests.

Do not switch database libraries in this phase.

## Workstream E — Make shutdown a real drain contract

Current `HoneypotWriter::shutdown(&self)` drops a clone of the sender, which does not close the channel while the writer and other clones still hold senders.

Implement private shared lifecycle state so `shutdown().await` can:

1. signal the writer to stop accepting new work according to existing caller expectations;
2. close the receiver or equivalent intake boundary;
3. drain already queued records;
4. flush the final partial batch;
5. wait for the writer task to exit.

Preserve the public `shutdown(&self)` signature if at all possible. If Tokio primitives require a new internal owner/JoinHandle arrangement, hide it inside the struct.

Define behavior for concurrent clones calling shutdown and for writes racing shutdown. Add deterministic tests.

## Workstream F — Event-loop and persistence evidence

Repeat Phase 49 fixtures:

- enqueue throughput;
- batch flush latency;
- 1/full batch;
- all payload retention modes;
- concurrent HTTP/event-loop heartbeat while flushes occur;
- prune/max-record maintenance.

The desired result is lower event-loop lag/tail latency without materially reducing database throughput.

## Acceptance criteria

Phase 53 is complete when:

- no synchronous SQLite transaction/prune operation runs directly on a Tokio core worker in the targeted honeypot paths;
- blocking concurrency is explicitly bounded;
- queue/batch/retention/public APIs remain compatible;
- payload hashing no longer clones the payload;
- repeated INSERT preparation is removed if measurement shows a useful benefit;
- `shutdown().await` drains queued records and waits for the writer to stop;
- persistence/error behavior remains covered by tests;
- event-loop lag under database activity improves or is at least not materially worse;
- no record-loss regression is introduced.

## Verification

```bash
cargo test -p synvoid-honeypot --profile ci
cargo xtask verify
cargo xtask verify-full
```

Run the Phase 49 honeypot/event-loop fixture with the same database configuration.

## Rejection criteria

Reject a change that:

- replaces the bounded mpsc with an unbounded queue;
- spawns one blocking task per incoming record;
- changes retention/hash semantics;
- weakens persistence error handling;
- returns from shutdown before the final queued batch is accounted for;
- changes the public storage API solely to expose a new executor;
- reports faster enqueue latency while making actual flush durability or event-loop behavior worse.
