# Performance Optimization Corrective Closeout (Phases 56–57)

> Phase 57 is implemented and closed. Durable
> real-`PortHoneypotRunner::run()/stop()` lifecycle ownership, direct
> public-method lifecycle tests, single-owned writer drain during runner
> teardown, and immutable WAF-concurrency 1/8/32/128 requalification are
> landed below. Phase 56 implementation landed at
> `57ad3158754b2f4851e1ce408043d33104106974`, and its writer-shutdown,
> maintenance-task, `TeeBody`, and provenance fixes remain valid and unchanged
> in contract. Phase 57 proof-bearing implementation/qualification SHA:
> `5212c6862426ee17795994ef1bba590113c52fad` (this closeout's §11 evidence,
> focused/full verification, and benchmark numbers were qualified on that
> tree; this metadata commit records it without self-reference).

Status: corrective closure for the completed Phases 49-55 campaign.
Plan: `plans/phase_56_performance_campaign_corrective_runtime_and_evidence_closure.md`.
Final corrective plan: `plans/phase_57_performance_final_corrective_closeout.md` (implemented/closed).
Campaign roadmap: `plans/performance_optimization_roadmap.md` (historical).
Baseline record: `architecture/performance_optimization_baseline.md`.
Campaign closeout: `architecture/performance_optimization_closeout.md`.

This pass does not reopen the Phase 49-55 performance architecture. It fixes
three narrow runtime/lifecycle gaps and corrects benchmark provenance so the
headline evidence is reproducible from immutable revisions.

## 1. Baseline and final commits

- Planning/source baseline: `015e790d2f739fe47669a5ac347989b7b18c03a3`
  (plans: align roadmap active performance status). This commit does **not**
  contain the corrected benchmark harnesses or any Phase 49-55 production
  optimization.
- Phase 49-55 implementation commit:
  `892c2dd3ccf4c4d37bf4b0b90e7a61cc2bc5015b` (all campaign production +
  benchmark/support code landed together; see closeout §1).
- Phase 55 hash-recording commit:
  `92f606b95ee9bb55c5d61115de04e70cebdfe288`.
- Phase 56 baseline for this pass: `main` at `92f606b9` (2026-09-21), plus
  two plan-registration commits (`db149e21`, `1cc5e49c`).
- Phase 56 implementation SHA (proof-bearing for Phase 56):
  `57ad3158754b2f4851e1ce408043d33104106974`.
- Phase 57 baseline for the final corrective pass: `main` at
  `57ad3158754b2f4851e1ce408043d33104106974` (2026-09-21), plus docs
  registrations (`b489f4f7`, `da60db81`, `8e8207ad`, `66005086`, `a7806d06`).
- Phase 57 proof-bearing implementation/qualification SHA:
  `5212c6862426ee17795994ef1bba590113c52fad` — the commit containing the
  Workstream A–D runner lifecycle fix, the six real `run()/stop()`
  lifecycle tests, and the §6 immutable concurrency requalification below.

Do not call `015e790d` a commit containing the corrected benchmark harness;
it does not. The harness (4 new benches + 2 repaired WAF benches + Cargo
registration) landed in `892c2dd3` together with production changes.

## 2. Exact runtime defects found after Phase 55

1. **Honeypot shutdown completion used an edge-triggered wakeup around
   durable state** (`crates/synvoid-honeypot/src/storage_writer.rs`).
   `shutdown()` looped on an atomic `done` flag with
   `done_notify.notified().await`. The writer set `done = true` then
   `notify_waiters()`. A caller observing `done == false` could miss the
   broadcast between the check and waiter registration and wait
   indefinitely. The concurrent-shutdown test started callers together and
   did not deterministically exercise this interleaving.

2. **Honeypot maintenance was detached and initially duplicated**
   (`crates/synvoid-honeypot/src/runner.rs`). One detached one-shot
   `spawn_blocking` prune/max-record job plus one detached hourly task
   whose `interval()` first tick is immediately ready could overlap on the
   same storage connection. The hourly task had no shutdown receiver and
   was not joined by `run()`, so it could outlive the runner after
   `stop()`; repeated run/stop cycles could accumulate detached tasks.

3. **`TeeBody` reserved a size hint but did not enforce it**
   (`crates/synvoid-proxy/src/streaming.rs`). `TeeBody::new()` reserved
   exactly the upper `size_hint` from `GlobalCacheGovernor`, then appended
   while only checking `max_size`. A body emitting more than its advertised
   upper hint could retain more buffered memory than reserved. Phase 54
   required cache fill to abort if the body exceeds the reserved/max size.

4. **Phase 49 benchmark provenance was not commit-reproducible.**
   Baseline/closeout identified `015e790d` as the implementation/baseline
   head, but checking out that SHA does not reproduce the described harness
   (missing `bench_upstream_selection`, `bench_metrics_hotpath`,
   `bench_buffer_pool`, `bench_honeypot_persistence`, plus the two repaired
   WAF benches). Host was described as "Apple M4 Pro with an `x86_64`
   target build" without separating host CPU, shell translation, and Rust
   compilation target.

## 3. Fixes and tests

### Workstream A — stateful writer shutdown (`storage_writer.rs`)

- `WriterLifecycle` now owns `shutdown_notify: Notify` (one-way request,
  permit retained, single consumer) plus `done_tx: watch::Sender<bool>`
  (stateful completion, initial `false`).
- `HoneypotWriter::shutdown()` signals shutdown, subscribes to the watch
  channel, returns immediately if already `true`, else
  `wait_for(|done| *done)`. Late subscribers observe durable completion;
  the check-to-wait race cannot occur. Sender-closed returns rather than
  hangs. No polling/sleep. Public signature and clone/backpressure
  behavior preserved.
- Writer task publishes `let _ = done_tx.send(true)` after final
  drain/flush.

Tests (`storage_writer_tests.rs`, all under `tokio::time::timeout` so
regression fails instead of hanging):

- single caller drains and completes (5 records, 5 s bound);
- 4 clones concurrently (6 records, 5 s bound);
- late caller after completion returns within 500 ms (twice);
- 25 fresh writers racing completion never hang (5 s each, drain pinned);
- writes after shutdown fail cleanly (`try_write` + async `write`);
- final partial batch (7 records) visible immediately after shutdown.

### Workstream B — runner-owned maintenance (`runner.rs`)

- Removed both detached spawns. One lifecycle-owned task per `run()`:
  subscribe to `shutdown_tx` before spawning, run initial
  prune/max-record once via bounded `spawn_blocking`, then
  `sleep(3600)`-based waits (no immediate second tick), each cycle
  awaiting one blocking op before the next wait, `select` against the
  shutdown receiver, no new cycle after shutdown.
- Shared helper `maintenance_loop(shutdown_rx, interval, operation)` pins
  single-flight/ordering; `maintenance_task(storage, rx, interval)` wraps
  the real SQLite op; `run()` keeps the `JoinHandle` and awaits it before
  converging on idempotent `writer.shutdown()` and returning. `stop()`
  stays synchronous. No public API/config change.
- Invariants: at most one SQLite maintenance op in flight; no task
  survives successful `run()` return; in-progress blocking op may finish
  during shutdown; repeated run/stop creates one new lifecycle, no
  accumulation.
- Phase 57 (this closeout, `runner.rs` only; public signatures unchanged):
  edge-triggered `broadcast` shutdown replaced with stateful
  `watch::Sender<bool>` (initial `false`); both `run()`-loop and maintenance
  receivers subscribe before the lifecycle becomes externally visible as
  active, and `borrow()` pre-checks plus a `Send`-safe
  `shutdown_requested()` (`borrow()` + `changed()`) helper make an early
  `stop()` durable with no sleep/retry/poll. Private `RunnerLifecycle`
  (`Idle`/`Running`/`Stopping`/`Stopped`) separates user-visible
  `is_running()` (true only in `Running`) from lifecycle ownership: `run()`
  acquires `Idle -> Running` once; `stop()` moves `Running -> Stopping`
  synchronously without releasing ownership; `run()` marks `Stopped` only
  after listener exit, maintenance join, and writer drain. A second `run()`
  while `Running`/`Stopping`/`Stopped` returns without starting work
  (one instance is one lifecycle; re-enable constructs a new
  runner/writer). `stop()` no longer spawns a concurrent writer shutdown
  for the active lifecycle — `run()` single-owns listener shutdown,
  maintenance join, and writer drain; an `Idle`-only `stop()` (no run ever
  active) arranges writer closure separately without releasing lifecycle.
  Test-only `teardown_gate` (`Notify`, `#[cfg(test)]`) holds teardown in
  `Stopping` deterministically; never an operator knob.

Tests (`runner::runner_maintenance_tests`, short intervals, production
interval unchanged at 3600 s; shutdown now stateful `watch`, same bounds):

- initial runs exactly once, not twice;
- periodic cycles never overlap (in-flight flag + 35 ms work on 20 ms
  cadence);
- stop exits the task (5 s bound);
- restart creates one joinable lifecycle per generation;
- no new cycle starts after shutdown.

Phase 57 direct public-method tests (`runner::runner_lifecycle_tests`,
isolated `:memory:` storage, loopback `127.0.0.1:0`, all under
`tokio::time::timeout` so regression fails instead of hanging):

- early stop cannot be lost (spawn `run()`, synchronous `stop()`, bounded
  10 s return, terminal `Stopped`);
- stop does not release ownership early (gated teardown in `Stopping`,
  second `run()` rejected within 2 s, first still pending, then released);
- teardown owns maintenance (real `run()` return implies maintenance
  joined; a shutdown-ignoring task would hang past the 10 s bound);
- repeated stop idempotent (burst + concurrent sync callers, one exit,
  late writer shutdown prompt, writes fail closed);
- terminal same-instance behavior (second `run()` after full return stays
  `Stopped`, never serving);
- status truth (`is_running()` true only in `Running`; `Stopping` visibly
  stopped while still blocking overlap).

### Workstream C — `TeeBody` reservation enforcement (`streaming.rs`)

- New private `abandon_cache_buffering()`: drops the pooled buffer,
  `GlobalCacheGovernor::release(reserved_bytes)` immediately, zeroes
  `reserved_bytes` so `Drop` cannot double-release. Response forwarding
  continues unchanged.
- Data path enforces `min(reserved_bytes, max_size)` before every append
  with `checked_add`; overshoot abandons caching only (no truncation,
  stall, or rejection). Error path releases immediately (no later than
  `Drop`).
- No public API change.

Tests (`streaming::streaming_tests`, deterministic `FakeBody`, global
governor serialized on a static mutex with max/usage save-restore,
health pinned to `Normal`):

- upper 4 / actual 4 caches;
- upper 4 / actual 6 abandons, forwards byte-for-byte, usage restored;
- immediate release observable mid-stream (usage `before+4` then
  `before` right at abandon, still `before` after drop);
- no double release at drop (counter never underflows; fresh reserve
  still succeeds);
- body at `max_size` with matching reservation caches;
- body above `max_size` never reserved/cached but still forwards fully;
- error-after-partial releases immediately and never caches.

## 4. Immutable benchmark reproduction method

Separate worktrees/checkouts so source revisions stay immutable.
Production optimizations are never applied to the baseline worktree.

Baseline worktree at `015e790d`:

```bash
git worktree add /tmp/synvoid-baseline-015e790d 015e790d2f739fe47669a5ac347989b7b18c03a3
```

Benchmark-only transplant (no production files): copy from the final
tree the 6 harness files plus Cargo registration, nothing else:

- `benches/bench_upstream_selection.rs` (new)
- `benches/bench_metrics_hotpath.rs` (new)
- `benches/bench_buffer_pool.rs` (new)
- `benches/bench_honeypot_persistence.rs` (new)
- `benches/bench_normalization.rs` (repaired: shared Tokio runtime,
  no runtime-in-loop, no `block_on`)
- `benches/bench_attack_detection_wave10.rs` (repaired: same)
- `Cargo.toml` `[[bench]]` entries for the 4 new benches

```bash
cp benches/bench_upstream_selection.rs \
   benches/bench_metrics_hotpath.rs \
   benches/bench_buffer_pool.rs \
   benches/bench_honeypot_persistence.rs \
   benches/bench_normalization.rs \
   benches/bench_attack_detection_wave10.rs \
   /tmp/synvoid-baseline-015e790d/benches/
# append the 4 [[bench]] stanzas to the baseline Cargo.toml
```

Reference diff for the harness surface (benchmark + registration only;
production files excluded by path):

```bash
git diff 015e790d..892c2dd3 -- \
  benches/bench_normalization.rs \
  benches/bench_attack_detection_wave10.rs \
  benches/bench_upstream_selection.rs \
  benches/bench_metrics_hotpath.rs \
  benches/bench_buffer_pool.rs \
  benches/bench_honeypot_persistence.rs \
  Cargo.toml
```

All runs below use the same toolchain/profile/host:
`cargo bench --bench <name> -- --quick` (Criterion point estimates,
comparison anchors, not release qualification).

Reproduced from immutable source + the above benchmark-only patch:

- WAF path/query/form/1 KiB/10 KiB (`bench_normalization`).
- WAF concurrency 1/8/32/128 (`bench_attack_detection_wave10`).
- Upstream round-robin, least-connections, weighted RR, IP hash at
  1/4/16/64 plus failover/filtered/next/try
  (`bench_upstream_selection`).
- Existing-site metric start/end (`bench_metrics_hotpath` site_hot
  subset; full-file run on baseline deadlocks — see §6).
- Honeypot enqueue/retention/heartbeat at the final head
  (`bench_honeypot_persistence`); baseline honeypot numbers below are
  historical working-tree evidence (§6) because the baseline full-matrix
  rerun was not repeated after the transplant proved the harness
  mechanism on WAF/upstream.
- Buffer-pool numbers only where semantics are comparable; post-fix
  numbers include honest zero-fill and are not comparable to Phase 49
  dirty-reuse absolutes (already recorded in closeout §4).

If a number below is labeled historical, it is the original Phase 49-55
working-tree measurement, not a commit-reproducible result. No historical
number was silently rewritten.

## 5. Corrected host/target provenance

Captured at requalification (2026-09-21):

```text
uname -a: Darwin nos-MacBook-Pro.local 25.6.0 ... RELEASE_ARM64_T6041 x86_64
uname -m: x86_64
rustc -vV: rustc 1.98.1 (48a229cea 2026-09-01), host: aarch64-apple-darwin
cargo -vV: cargo 1.98.1, host: aarch64-apple-darwin
rustc --print cfg: target_arch="aarch64", target_os="macos",
  target_vendor="apple", target_pointer_width="64"
CARGO_BUILD_TARGET/RUSTFLAGS/RUSTUP_TOOLCHAIN: unset
```

Interpretation: Apple M4 Pro hardware (ARM64). The login shell reports
`x86_64` because it runs under Rosetta 2 translation, while `rustc`
host and `target_arch` are native `aarch64-apple-darwin`. There is no
cross-target `x86_64` Rust build here. The old "Apple M4 Pro with an
`x86_64` target build" line conflated the translated shell `uname`
with the Rust target; record them separately as above. Both sides of
every ratio below ran under this same native-aarch64 target, so no
ratio mixes architectures.

## 6. Before/after headline requalification

Point estimates (`--quick` Criterion, same host/profile/target).
"Before" = baseline `015e790d` + benchmark-only transplant (immutable);
"after" = Phase 57 proof-bearing head (Phase 55 production + Phase 56
lifecycle/reservation fixes + Phase 57 runner lifecycle ownership, none of
which move these WAF hot paths except as noted; the Phase 57 runner change
is lifecycle-only). Honeypot/metrics-WASM/buffer rows state their provenance
explicitly. Phase 57 completes the immutable concurrency requalification
that Phase 56 left historical (method recorded in §4; numbers below).

### WAF (`bench_normalization`, default config, anomaly on)

| Case | Before (immutable) | After | Change |
|------|-------------------|-------|--------|
| benign path-only | ~10.9 µs | ~2.27 µs | ~4.8× |
| benign query+headers | ~13.16 µs | ~2.95 µs | ~4.5× |
| form body | ~13.88 µs | ~2.80 µs | ~5.0× |
| 1 KiB body | ~21.48 µs | ~21.22 µs | neutral |
| 10 KiB single | ~102.3 µs | ~164.7 µs | ~0.6× REGRESSION (kept, §7) |
| anomaly-disabled benign | ~9.5 µs | ~0.62 µs | ~15× |

### WAF concurrency (`bench_attack_detection_wave10` batch completion)

Phase 57 immutable requalification (2026-09-21, same host/target/profile as
§5, `cargo bench --bench bench_attack_detection_wave10 --
attack_detection_concurrency --quick`): baseline worktree at `015e790d` plus
a benchmark-only transplant of the repaired
`benches/bench_attack_detection_wave10.rs` (1 file, 260 insertions, no
production files; `[[bench]]` registration already present at baseline),
versus the Phase 57 proof-bearing head. Criterion point estimates:

| Batch | Before (immutable, `015e790d` + bench-only patch) | After (Phase 57 head, requalified) |
|-------|---------------------------------------------------|------------------------------------|
| 1 | ~16.49 µs (16.333–17.105 µs) | ~11.34 µs (11.157–11.391 µs) |
| 8 | ~32.41 µs (31.737–32.574 µs) | ~21.09 µs (20.676–21.191 µs) |
| 32 | ~146.66 µs (146.55–147.08 µs) | ~48.46 µs (48.200–48.522 µs) |
| 128 | ~380.53 µs (370.90–382.94 µs) | ~155.8 µs (155.38–157.43 µs) |

All concurrent batches improve (~1.5× at batch 1, ~1.5× at batch 8, ~3.0×
at batch 32, ~2.4× at batch 128); only isolated single large-body regresses
(§7). These rows replace the Phase 56 "Before (historical)" labels
(14.8/28.8/86.9/295 µs working-tree context, retained in git history, not
rewritten). No WAF production code was altered to change these numbers.

### Upstream (`bench_upstream_selection`, representative)

| Algorithm @ size | Before (immutable) | After |
|------|--------|-------|
| round-robin 1/4/16/64 | 24/27/96/204 ns | 21/21/34/96 ns |
| least-connections 64 | ~305 ns | ~106 ns |
| weighted RR 4/16/64 | 90/374/1241 ns | 21/36/103 ns |
| ip-hash 64 | ~191 ns | ~96 ns |
| half-unhealthy / backup / protocol-filtered | 56/28/87 ns | 32/22/29 ns |

No per-request candidate-vector allocation remains; weighted RR no longer
clones a second vector.

### Metrics / WASM (`bench_metrics_hotpath`)

- Existing-site start ~24.6 ns (historical) → ~14.26 ns (requalified);
  start+end roundtrip 48 ns → ~27.9 ns; `record_request_end`/`proxied`
  ~10-14 ns.
- WASM hot invocation/decision/duration ~13-15 ns → ~11.9 ns each;
  `get_all_wasm_metrics` 70.8 ns → ~54.6 ns (post-deadlock-fix design).
- The old `get_all_wasm_metrics` implementation self-deadlocks (holds the
  invocations mutex while calling `get` on the same non-reentrant mutex).
  The transplanted full metrics bench hangs on the baseline worktree and
  was terminated after 60 min without completing. There is therefore no
  legitimate numerical "before" for that operation; it is documented as a
  fixed deadlock with regression test
  `test_get_all_wasm_metrics_completes_with_registered_plugin`, not a
  timing ratio. Other baseline metrics rows above remain historical
  working-tree evidence except site_hot start/end, which match the
  transplanted subset mechanism.

### Honeypot (`bench_honeypot_persistence`, final head requalified)

- Enqueue `try_write_record` ~330 ns (historical) → ~314 ns.
- Async write under healthy consumer 5.6 µs → ~3.23 µs.
- 1 KiB retention None/HashOnly/Truncated/Full
  2.07/2.11/2.25/2.27 µs → ~2.05/2.04/2.06/2.05 µs (clone removal).
- Direct flush/prune throughput unchanged (SQLite relocated, not reduced);
  heartbeat batch ~433 µs → ~434 µs (neutral, fairness structurally
  improved: flushes off core workers, one in flight).
- Baseline honeypot rows are historical working-tree evidence; the harness
  transplant was proven on WAF/upstream and the Phase 56 writer/runner
  changes preserve enqueue/flush semantics (focused tests green).

### Buffer pool (`bench_buffer_pool`, final head requalified)

Timing comparisons to Phase 49 absolutes are confounded by the zero-fill
correction (closeout §4) and are not claimed as wins. Phase 56 result is
correctness + bounded memory (single-flight maintenance, exact governor
accounting, abandon-on-overshoot). Final indicative numbers (honest
zero-fill included): TLS-hit small ~33 ns, medium ~162 ns; growth
within-tier ~50 ns; cross-thread ~14.9 µs (thread spawn dominates).

### End-to-end

No permanent end-to-end harness added (per roadmap rejection criteria).
Representative proxy workloads are covered by the concurrency batches
above plus existing stress/parity suites, all green at this head.

## 7. Known WAF large-body tradeoff (retained)

Isolated single-request 10 KiB WAF latency regressed (~102 µs before vs
~165-200 µs after across the two WAF benches) while every concurrent
batch improved. Cause: the old per-request `JoinSet` parallelized
detectors over bench workers; inline borrowed evaluation is sequential.
Kept deliberately: system throughput and tail behavior under load are
better; only isolated single large-body latency regressed. Whole-stage
offload was evaluated and rejected — event-loop fairness improved without
it, and offload would tax the common small-request path. Reopen WAF
scheduling only with new event-loop or workload evidence showing
starvation or unacceptable large-body p99 (see also `architecture/waf.md`
and `AGENTS.md` Known Issues).

## 8. Full verification results

Focused (required by the Phase 56 plan, retained for Phase 57):

```bash
cargo fmt --all -- --check
cargo test -p synvoid-honeypot --profile ci
cargo test -p synvoid-proxy --profile ci
cargo test -p synvoid-waf --profile ci
cargo test -p synvoid-upstream --profile ci
cargo xtask test guards
```

- `synvoid-honeypot`: 204 lib tests green (Phase 56: 6 shutdown + 5
  maintenance lifecycle tests, retained; Phase 57: 6 new real
  `run()/stop()` lifecycle tests in `runner::runner_lifecycle_tests`).
- `synvoid-proxy`: `TeeBody` reservation tests green (Phase 56 contract
  unchanged by Phase 57).
- `synvoid-waf`: execution-model parity untouched by Phase 57 (no
  detector/scoring change).
- `synvoid-upstream`: selection parity untouched by Phase 57.
- `cargo xtask test guards`: green (recorded at qualification; rerun in
  `cargo xtask verify`).

Repository gates (run at the Phase 57 proof-bearing head):

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

Focused benchmark requalification ran outside routine CI (above).

| Gate | Result at Phase 57 proof-bearing head |
|------|---------------------------------------|
| fmt --check | green |
| feature-profile compiles (4) | green (`--no-default-features`, `mesh`, `dns`, `mesh,dns`) |
| `cargo xtask verify` | green, 10/10 steps, 211.0 s |
| `cargo xtask verify-full` | green, 10/10 steps, 503.1 s |
| `cargo deny check` | green (advisories/bans/licenses/sources ok) |
| `cargo audit` | green, exit 0 with 6 allowed warnings only |

Phase 56 gate history retained: `cargo xtask verify` green 10/10 steps
293.1 s and `cargo xtask verify-full` green 10/10 steps 700.1 s at the Phase
56 head; `cargo audit` exit 0 with 6 allowed warnings only.

## 9. Residual opportunities / non-goals (unchanged)

Phases 56–57 did not: change the WAF detector set/scoring/API; reintroduce
per-detector `JoinSet`; add whole-stage offload; redesign `BufferPool`;
change proxy-cache admission; change public shutdown/runner APIs (signatures
preserved; only private lifecycle/shutdown state changed); replace SQLite;
rerun a broad audit; rewrite historical Phase 49-55 numbers; or implement a
new admin "enable" lifecycle. Residuals from closeout §10 remain:
whole-stage offload only on event-loop evidence; JWT duplicate normalization
(~150 ns, measure first); global HTTP sampler only on contended evidence;
mesh-publish reads only if implicated; dedicated RSS harness only if pooling
changes again.

## 10. Final compatibility statement

Public Rust APIs, configuration keys/defaults/validation, WAF detector
coverage/scoring/precedence/fail-closed behavior, upstream algorithms and
selection semantics, protocol capabilities, Prometheus metric names/labels,
admin/status payloads, `BufferPool`/`PooledBuf` surfaces, honeypot
persistence/retention semantics and backpressure, and all feature profiles
are preserved. Behavioral deltas are limited to the concrete correctness
fixes: (a) stateful/no-lost-wakeup writer shutdown (Phase 56); (b) single
runner-owned maintenance lifecycle with no initial overlap and no detached
task after shutdown (Phase 56); (c) strict `TeeBody` governor-reservation
enforcement with exact-once release on abandonment (Phase 56, response bytes
unchanged); (d) durable real-runner shutdown with separated lifecycle
ownership and terminal one-instance-one-lifecycle contract (Phase 57, §11).
Admin `disable` still calls sync `stop()`; `enable`/`pause`/`resume` remain
no-ops; no same-instance restart is promised.

## 11. Phase 57 final corrective closeout (this head)

Scope owned (per
`plans/phase_57_performance_final_corrective_closeout.md`): private
`PortHoneypotRunner` lifecycle/shutdown state; direct tests of the real
public `run()/stop()/is_running()` behavior; immutable WAF-concurrency
requalification; Phase 56/57 planning and closeout reconciliation; focused
and full verification. Explicitly not owned: WAF execution changes,
detector coverage/scoring/precedence, `TeeBody`, persistence redesign,
async `stop()`, admin enable lifecycle, buffer-pool redesign, or unrelated
task-lifecycle cleanup.

Findings closed:

1. `stop()` exposed false-stopped status while `run()` was still alive
   (`running = false` written immediately, second `run()` could overlap
   teardown). Fixed by `RunnerLifecycle`: visible `is_running()` flips at
   `Stopping`, ownership releases only at terminal `Stopped`.
2. Edge-triggered `broadcast` shutdown subscribed after the lifecycle became
   active could lose an early stop. Fixed by stateful `watch<bool>` with
   receivers subscribed before `Idle -> Running` plus durable
   `borrow()`/`changed()` waits; no sleeps, repeated sends, or polling.
3. Same-instance restart was an invalid implicit contract over a terminal
   writer. Made explicit and pinned: one instance is one lifecycle; a post-
   terminal `run()` returns without starting work. No public signature
   changed; no writer/listener reconstruction was required because no binding
   documentation or tested production call site required same-instance
   restart (admin `enable` is a no-op; workers construct a new runner per
   process lifecycle).
4. Immutable concurrency requalification incomplete. Completed in §6 above
   from `015e790d` plus the recorded benchmark-only patch.
5. Status/SHA disagreement. Reconciled: Phase 56 plan is historical with a
   Phase 57 pointer; Phase 57 plan is implemented/closed; both roadmaps are
   historical/complete; this closeout records Phase 56 SHA
   `57ad3158754b2f4851e1ce408043d33104106974` and Phase 57 proof-bearing SHA
   `5212c6862426ee17795994ef1bba590113c52fad`.

Verification at the proof-bearing head: focused suites (§8), four feature-
profile compiles, `cargo xtask verify`, `cargo xtask verify-full`,
`cargo deny check`, and `cargo audit` green (timings in the §8 table);
benchmark requalification outside routine CI as recorded. Rejection checks
hold: no helper-only test claims the runner race; no `running = false`
sole-guard; no post-active broadcast subscription; no async `stop()`; no
restart claim over a closed writer; no overlapping lifecycles; no WAF
behavior change for numbers; no relabeled history; no self-referential SHA.
