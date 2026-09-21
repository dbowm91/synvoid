# Phase 56 Plan: Performance Campaign Corrective Runtime and Evidence Closure

Status: implementation landed at `57ad3158754b2f4851e1ce408043d33104106974`; final closure follow-up active under `plans/phase_57_performance_final_corrective_closeout.md`. Retained as historical handoff detail.

Registered in: `plans/roadmap.md`.

Post-implementation note: the Phase 56 writer-shutdown, maintenance-task,
`TeeBody`, and provenance corrections landed. A later audit found a narrower
real-`PortHoneypotRunner::run()/stop()` lifecycle race plus incomplete
immutable WAF-concurrency requalification. Those final closure items belong to
Phase 57; do not reinterpret the landed Phase 56 fixes as reverted.

Parent campaign: Phases 49-55 performance optimization, implemented at
`892c2dd3ccf4c4d37bf4b0b90e7a61cc2bc5015b` and documented by
`architecture/performance_optimization_closeout.md`.

Baseline for this corrective pass: `main` at
`92f606b95ee9bb55c5d61115de04e70cebdfe288` (2026-09-21).

## Primary goal

Close the small set of correctness and evidence-quality residuals found after
the Phase 49-55 performance campaign without reopening the completed
performance architecture.

This is a corrective closure pass, not Phase 50-54 redesign. The expected
runtime changes are limited to:

1. making `HoneypotWriter::shutdown()` completion signaling immune to lost
   wakeups across concurrent clones;
2. binding periodic honeypot maintenance to the runner lifecycle and removing
   the current initial-maintenance overlap;
3. enforcing the cache-governor reservation as an actual upper bound in
   `TeeBody`;
4. correcting benchmark/provenance documentation and requalifying the
   headline evidence from immutable revisions where practical.

The known isolated 10 KiB WAF latency tradeoff is not, by itself, a Phase 56
runtime defect. Keep it explicit and reopen WAF scheduling only if new
event-loop or workload evidence justifies doing so.

## Why this plan exists

The Phase 49-55 implementation materially improved the request path and passed
the repository's broad verification gates, but a post-closeout audit found
three narrow runtime/lifecycle gaps and one evidence-state gap.

### 1. Honeypot shutdown completion uses edge-triggered notification around state

`crates/synvoid-honeypot/src/storage_writer.rs` currently implements
`shutdown(&self)` as:

- signal `shutdown_notify`;
- loop checking an atomic `done`;
- await `done_notify.notified()` while `done` is false.

The writer sets `done = true` and then calls `notify_waiters()`.

A caller can observe `done == false`, then completion can set the flag and
broadcast before that caller is actually registered as a waiter. The
completion state is durable, but the wakeup is not. A late/concurrent shutdown
caller can therefore wait indefinitely in the narrow check-to-wait window.

The current concurrent-shutdown test starts all callers together and does not
deterministically exercise this interleaving.

### 2. Honeypot maintenance is detached and initially duplicated

`crates/synvoid-honeypot/src/runner.rs` currently starts:

- one detached initial `spawn_blocking` prune/max-record maintenance job; and
- one detached hourly maintenance task whose `tokio::time::interval` first
  tick is immediately ready.

Those two initial jobs can overlap against the same storage connection. The
hourly task also has no shutdown receiver and is not joined by `run()`, so it
can outlive the runner after `stop()`. Repeated run/stop cycles can therefore
leave detached maintenance tasks alive longer than the runtime component they
belong to.

### 3. `TeeBody` reserves a size hint but does not enforce that reservation

`crates/synvoid-proxy/src/streaming.rs` reserves exactly the response body's
upper `size_hint` through `GlobalCacheGovernor`, then appends while only
checking `max_size`.

If a body implementation emits more bytes than its advertised upper hint,
`TeeBody` can retain more buffered memory than the governor reserved. A size
hint should normally be truthful, but the governor contract must remain
correct even for a buggy or adversarial body implementation.

Phase 54 explicitly required cache fill to abort if the body exceeds the
reserved/max size.

### 4. Phase 49 benchmark provenance is not fully reproducible from its stated SHA

The baseline and closeout documents identify `015e790d` as the Phase 49
implementation/baseline head, but the corrected benchmark harnesses and all
Phase 49-55 implementation files landed together in `892c2dd3`.

The benchmark numbers may accurately reflect intermediate working-tree states,
but checking out `015e790d` does not reproduce the benchmark harness
described by `architecture/performance_optimization_baseline.md`.

The host description also says Apple M4 Pro with an `x86_64` target build.
That may be intentional Rosetta/cross-target execution, but the evidence must
record host and target separately so future comparisons are unambiguous.

## Scope and non-goals

Phase 56 owns:

- the private honeypot writer lifecycle/completion machinery;
- honeypot runner maintenance task ownership and shutdown;
- `TeeBody` reservation enforcement and immediate reservation release when
  cache buffering is abandoned;
- focused tests for the above;
- immutable/reproducible benchmark provenance correction;
- a corrective closeout evidence record;
- planning/status reconciliation for this corrective pass.

Phase 56 does **not** own:

- changing the WAF detector set, scoring, enforcement, or public API;
- reintroducing per-detector `JoinSet` fanout;
- adding whole-stage WAF offload without new evidence;
- redesigning `BufferPool`;
- changing proxy-cache admission policy;
- changing the public `HoneypotWriter`/`PortHoneypotRunner` APIs solely for
  implementation convenience;
- replacing SQLite;
- rerunning a broad architecture audit;
- rewriting historical Phase 49-55 evidence as though the original runs never
  occurred.

## Workstream A — Make writer shutdown completion stateful and race-free

Canonical owner:

`crates/synvoid-honeypot/src/storage_writer.rs`

Preserve:

`pub async fn HoneypotWriter::shutdown(&self)`

and the existing cloneability/backpressure behavior.

### Required behavior

After Phase 56:

- the first shutdown request causes the single writer task to close intake;
- records already accepted by the mpsc channel drain in order;
- the final partial batch flushes;
- all concurrent shutdown callers complete after the same writer completion;
- a shutdown caller arriving after completion returns immediately;
- writes after intake closes fail with the existing send/try-send errors;
- no caller can sleep forever because a completion notification happened
  between a state check and waiter registration.

### Preferred implementation

Replace completion waiting with a stateful private primitive such as
`tokio::sync::watch`:

- writer lifecycle owns a completion sender;
- shutdown callers subscribe/read the durable completion state;
- writer publishes completion after final drain/flush;
- late subscribers observe the completed state without relying on a transient
  notification edge.

An equivalent implementation may retain `Notify` only if it follows Tokio's
documented no-lost-wakeup pattern and the code/test demonstrates why the
check-to-wait race cannot occur.

Do not solve this by polling/sleeping.

The one-way shutdown-request signal may remain a `Notify` because there is
one writer consumer and `Notify` retains a permit when no waiter is present.
If changed, keep the request idempotent across clones.

### Tests

Add bounded-timeout tests for:

1. one caller drains and completes;
2. three or more clones call shutdown concurrently;
3. a second caller invokes shutdown after the writer is already complete;
4. a caller races writer completion repeatedly and never hangs;
5. writes racing closed intake fail cleanly;
6. the final queued partial batch is present immediately when shutdown
   returns.

Use `tokio::time::timeout` around shutdown tests so a regression fails rather
than hanging the suite.

## Workstream B — Bind honeypot maintenance to the runner lifecycle

Canonical owner:

`crates/synvoid-honeypot/src/runner.rs`

### Remove initial overlap

Do not keep both:

- a detached one-shot initial maintenance job; and
- an interval whose first tick is immediately ready.

Use one lifecycle-owned maintenance task.

Acceptable shape:

1. subscribe to `shutdown_tx` **before** spawning the maintenance task so a
   stop signal cannot be missed;
2. execute initial prune/max-record maintenance once;
3. wait one configured/current hourly interval before the next cycle;
4. on each cycle, await one bounded `spawn_blocking` maintenance operation;
5. select the next wait against the shutdown receiver;
6. keep the maintenance `JoinHandle` in `run()` and await it during runner
   shutdown.

A `time::sleep(Duration::from_secs(3600))` loop or
`interval_at(now + one_hour, one_hour)` avoids the immediate-second-run
behavior of `interval()`.

### Lifecycle invariants

- at most one prune/max-record operation is in flight for this runner;
- no periodic maintenance task survives successful return from `run()`;
- an in-progress blocking SQLite maintenance operation may finish during
  shutdown, but no new cycle starts afterward;
- repeated run/stop cycles do not accumulate maintenance tasks;
- `stop(&self)` may remain synchronous;
- public runner APIs/config remain unchanged.

Because Workstream A makes writer shutdown idempotent, `stop()` and
`run()` may both converge on the same private writer completion path if that
simplifies owned shutdown, but do not require callers to adopt a new async
stop API.

### Tests

Add a test-only short maintenance interval/hook if needed; do not change the
operator-facing interval/config solely for tests.

Pin:

- initial maintenance executes once, not twice;
- periodic maintenance does not overlap itself;
- stop causes the maintenance task to exit;
- `run()` does not return while its periodic maintenance task remains live;
- a restart creates one new maintenance lifecycle, not an accumulating set.

## Workstream C — Enforce the `TeeBody` governor reservation

Canonical owners:

- `crates/synvoid-proxy/src/streaming.rs`
- `crates/synvoid-proxy/src/governor.rs` only if a test seam/helper is needed.

No public API change is required.

### Buffering invariant

When `TeeBody::new()` successfully reserves `reserved_bytes`, the amount
retained by the tee buffer must never exceed:

`min(reserved_bytes, max_size)`

Before every append, use checked arithmetic and require the new length to stay
within that bound.

If the stream would exceed the reservation:

1. abandon caching for that response;
2. drop the pooled tee buffer;
3. call `GlobalCacheGovernor::release(reserved_bytes)` immediately;
4. set `reserved_bytes = 0` so `Drop` cannot release twice;
5. continue forwarding the body unchanged to the client.

A small private helper such as `abandon_cache_buffering()` is preferred if
it makes all oversize/error paths share exact release semantics.

The proxy must not truncate, stall, or reject the response merely because its
cache hint was wrong. Only cache admission is abandoned.

### Required tests

Use a deterministic fake `Body` to cover:

- upper hint 4 bytes, actual body exactly 4 bytes: cache succeeds;
- upper hint 4 bytes, body emits >4 bytes: cache fill is abandoned;
- an overshooting body still reaches the downstream caller byte-for-byte;
- governor usage returns to its pre-test value immediately after abandonment;
- no double release occurs at `Drop`;
- a body at `max_size` still caches when the reservation matches;
- a body above `max_size` is never reserved/cached;
- error-after-partial-body releases reservation no later than wrapper drop
  (immediate release is preferable if the helper naturally supports it).

Tests that modify the process-global governor maximum/usage must serialize or
restore state reliably so they cannot make unrelated proxy tests flaky.

## Workstream D — Correct performance evidence provenance

Do not delete or silently rewrite the original Phase 49-55 measurements.
Create an explicit corrective evidence record:

`architecture/performance_optimization_corrective_closeout.md`

and add short addendum pointers from:

- `architecture/performance_optimization_baseline.md`;
- `architecture/performance_optimization_closeout.md`.

### Record immutable revision roles correctly

The corrective record must distinguish:

- planning/source baseline: `015e790d2f739fe47669a5ac347989b7b18c03a3`;
- Phase 49-55 implementation commit:
  `892c2dd3ccf4c4d37bf4b0b90e7a61cc2bc5015b`;
- Phase 55 hash-recording commit:
  `92f606b95ee9bb55c5d61115de04e70cebdfe288`;
- final Phase 56 implementation/qualification head.

Do not call `015e790d` a commit containing the corrected benchmark harness;
it does not.

### Reproduce the high-value before/after comparisons

Use separate worktrees/checkouts so source revisions are immutable.

For the baseline checkout at `015e790d`, apply only the minimum benchmark
harness/registration patch required to measure the old production
implementation. Keep this patch as a recorded diff/hash or checked-in
reproduction note so another developer can repeat the experiment.

Do not apply Phase 50-54 production optimizations to the baseline worktree.

At minimum requalify the claims that motivate the campaign:

- WAF path-only/query/form/1 KiB/10 KiB;
- WAF concurrency 1/8/32/128;
- upstream round-robin, least-connections, weighted RR, and IP hash across
  representative pool sizes;
- existing-site metric start/end;
- honeypot enqueue/retention/heartbeat if the harness can be transplanted
  without production changes;
- buffer-pool numbers only where baseline semantics are comparable.

For WASM `get_all_wasm_metrics`, explicitly document that the old
implementation self-deadlocks and cannot be treated as an ordinary timing
baseline. Do not manufacture a numerical "before" result for a non-completing
operation.

If a benchmark cannot be reproduced from an immutable source plus a recorded
benchmark-only patch, downgrade the old number to historical working-tree
evidence rather than presenting it as commit-reproducible.

### Record host and target independently

Capture at least:

```bash
uname -a
uname -m
rustc -vV
cargo -vV
rustc --print cfg
env | grep -E '^(CARGO_BUILD_TARGET|RUSTFLAGS|RUSTUP_TOOLCHAIN)=' || true
```

If the Apple M4 Pro run is an x86_64/Rosetta build, say so explicitly.
If it is native arm64/aarch64, correct the old ambiguous target description.

Never compare a native-aarch64 final run to an x86_64 baseline as though they
were the same target. Re-run both sides under one target for any claimed
ratio.

## Workstream E — Preserve the known WAF tradeoff truthfully

The current closeout records an isolated single-request 10 KiB WAF regression
(~102-114 µs before versus ~170-190 µs after) while concurrent batches improve.

Phase 56 should:

- keep this result visible in `AGENTS.md`, `architecture/waf.md`, and the
  corrective closeout where those surfaces discuss the Phase 50 model;
- remeasure it under the corrected immutable-revision methodology;
- retain inline borrowed evaluation if concurrent throughput/event-loop
  evidence remains favorable;
- **not** add whole-stage offload merely to erase one benchmark regression.

Open a new focused performance plan later only if a representative workload
shows event-loop starvation or unacceptable large-body p99.

## Workstream F — Verification and corrective closeout

Focused verification:

```bash
cargo fmt --all -- --check
cargo test -p synvoid-honeypot --profile ci
cargo test -p synvoid-proxy --profile ci
cargo test -p synvoid-waf --profile ci
cargo test -p synvoid-upstream --profile ci
cargo xtask test guards
```

Repository gates:

```bash
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo xtask verify
cargo xtask verify-full
cargo deny check
cargo audit
```

Run focused benchmark requalification outside routine CI.

The final `architecture/performance_optimization_corrective_closeout.md`
must contain:

1. baseline and final commits;
2. exact runtime defects found after Phase 55;
3. fixes and tests;
4. immutable benchmark reproduction method;
5. corrected host/target provenance;
6. before/after headline requalification;
7. known WAF large-body tradeoff;
8. full verification results;
9. residual opportunities/non-goals;
10. final compatibility statement.

After the implementation and evidence are green:

- mark Phase 56 implemented/closed;
- update `plans/roadmap.md` so no active performance-corrective handoff
  remains;
- keep `plans/performance_optimization_roadmap.md` historical, adding only a
  pointer to Phase 56/corrective evidence rather than rewriting the original
  campaign.

## Acceptance criteria

Phase 56 is complete only when:

- `HoneypotWriter::shutdown(&self)` has stateful/no-lost-wakeup completion
  semantics;
- concurrent, late, and racing shutdown callers complete under bounded tests;
- queued records are flushed before shutdown returns;
- the initial honeypot maintenance pass cannot overlap an immediate periodic
  pass;
- periodic honeypot maintenance exits with the runner and cannot accumulate
  across successful run/stop cycles;
- no more than one maintenance SQLite operation is in flight per runner;
- `TeeBody` never buffers beyond the bytes reserved from
  `GlobalCacheGovernor`;
- a lying/incorrect upper size hint causes cache abandonment only, never
  response corruption or truncation;
- abandoned tee buffering releases the governor reservation exactly once;
- Phase 49/55 docs no longer imply that `015e790d` contains benchmark code it
  does not contain;
- the benchmark-only baseline reproduction method is recorded and repeatable;
- host architecture and Rust compilation target are recorded separately;
- the WAF 10 KiB tradeoff remains explicit and is not hidden by aggregate
  speedup language;
- public Rust APIs/config/protocol/WAF/metric/cache/honeypot behavior remains
  compatible except for the concrete correctness fixes above;
- focused suites, `cargo xtask verify`, `verify-full`, `cargo deny`, and
  `cargo audit` are green at the corrective closeout head, or an
  environment-specific inability is recorded without claiming success.

## Rejection criteria

Reject the corrective implementation if it:

- changes public shutdown/runner APIs solely to avoid private lifecycle work;
- replaces the lost-wakeup risk with sleep/poll loops;
- allows detached periodic maintenance to survive runner shutdown;
- starts more than one blocking maintenance operation per runner at a time;
- increases the governor reservation after the fact when a body exceeds its
  advertised upper hint instead of abandoning cache fill;
- truncates or rejects a proxied response because its cache size hint was
  wrong;
- changes WAF coverage/scoring or reintroduces per-detector async fanout;
- rewrites historical benchmark numbers without recording their original
  provenance;
- claims commit-reproducible evidence from a dirty/intermediate working tree;
- mixes x86_64 and aarch64 benchmark results in one ratio;
- broadens into unrelated performance or architecture work.
