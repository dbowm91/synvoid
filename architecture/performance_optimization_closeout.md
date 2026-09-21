# Performance Optimization Closeout (Phases 49-55)

Status: campaign complete. Roadmap: `plans/performance_optimization_roadmap.md`
(marked historical). Baseline record:
`architecture/performance_optimization_baseline.md`.

## 1. Baseline and final commits

- Campaign planning baseline: `70d2bb29de30d2e5f66fd9cb24d682f5e2054670`.
- Phase 49 implementation head: `015e790d`.
- Final implementation head: this commit (all Phases 49-55 landed; see phase
  status table). Qualification runs below were executed at this head.

## 2. Host / toolchain / configuration

- Host: macOS (darwin), Apple M4 Pro. Same host for every before/after pair.
- Toolchain: `rustc 1.98.1`, `cargo 1.98.1`.
- Profile: `cargo bench` dev profile with `--quick` Criterion runs
  (comparison anchors, not release-qualification figures), and
  `--profile ci` for all test suites (matches CI).
- Machine-state caveat: sustained benchmarking during the campaign warmed the
  host; late buffer-pool runs show thermal inflation on memory-touching cases
  (a 32 KiB zero-fill calibrates at ~145 ns in the degraded window, an order
  of magnitude above a cool state). Ratios captured back-to-back within each
  phase window are the attributable evidence; absolute late-window
  nanoseconds are reported with this caveat. No conclusion below depends on a
  single degraded-window absolute.

## 3. Phase status table

| Phase | Status | Evidence |
|-------|--------|----------|
| 49 measurement & benchmark truth | Implemented | 2 WAF benches repaired (persistent Tokio runtime, no `block_on`), 4 new benches (upstream, metrics, buffer, honeypot), `architecture/performance_optimization_baseline.md` |
| 50 WAF execution model | Implemented | `JoinSet` fanout removed → borrowed inline core; 12 new parity tests; 3-15× small-request wins |
| 51 upstream + buffered dispatch | Implemented | Predicate selection (no candidate vectors); internal WAF-dispatch core; 13 parity tests; 2-13× selection wins |
| 52 metrics + plugin telemetry | Implemented | Borrowed site-start fast path; consolidated WASM registry + deadlock fix; duplicate egress removed; 4 new tests |
| 53 honeypot I/O isolation | Implemented | `spawn_blocking` flushes, in-place hashing, prepared statements, drain-capable shutdown; 3 new tests |
| 54 buffer pool + streaming | Implemented | Accounting/tiering/origin invariants, 6 zero-prefix call-site fixes, stale-reuse fix, TeeBody presize; 12 new tests |
| 55 qualification & closeout | Implemented | This document; full verification at closeout head |

## 4. Benchmark methodology

Same toolchain/profile/host for every before/after pair. Runtime, fixtures,
and database setup outside all timed loops. WAF cases run under a shared
multi-thread Tokio runtime (production-faithful scheduling). Concurrency
cases report batch completion, not per-request samples. Allocation claims
rest on code inspection plus timing outliers and counter tests (no allocator
instrumentation was added, per the rejection criteria).

Correction to the Phase 49 baseline: the buffer-pool baseline numbers
(~18 ns acquire/release across tiers) measured **dirty-buffer reuse**. The
pre-existing recycled-buffer path never zero-filled same-size/shrinking
reuse (`BytesMut::resize` only fills growth), so those numbers excluded the
documented zero-init cost. Phase 54 corrected this with regression tests
(`test_recycled_buffer_is_zeroed_same_size/_shrinking`, verified to fail
without the fix). Post-fix buffer numbers include honest zero-fill and are
not comparable to the Phase 49 absolutes.

## 5. Before / after results

Point estimates with confidence intervals from the recorded runs.

### WAF (Phase 50; default config, anomaly scoring on)

| Case | Before | After | Change |
|------|--------|-------|--------|
| benign path-only | ~10.7 µs | ~2.3 µs | ~4.7× |
| benign query+headers | ~12.7 µs | ~2.9 µs | ~4.4× |
| form body | ~13.8 µs | ~2.8 µs | ~4.9× |
| 1 KiB body | ~21 µs | ~21-22 µs | neutral |
| 10 KiB body (single) | ~102-114 µs | ~170-190 µs | ~0.6× REGRESSION (explained) |
| SQLi representative | ~14.5 µs | ~3.9 µs | ~3.7× |
| anomaly-disabled benign | ~9.5 µs | ~0.6 µs | ~15× |
| concurrency 1/8/32/128 | 14.8/28.8/86.9/295 µs | 11.9/21.3/50.3/158 µs | 1.2-1.9× |

10 KiB single-request regression: the old `JoinSet` parallelized 11
detectors over 2 bench workers; inline evaluation is sequential. Kept
deliberately per the plan's inline preference: every concurrent batch
(including 128 in flight) improved, so system throughput and tail behavior
under load are better; only isolated single large-body latency regressed.
Whole-stage offload was evaluated and rejected — event-loop fairness improved
without it, and offload would tax the common small-request path.

### Upstream selection (Phase 51)

| Algorithm @ size | Before | After |
|------|--------|-------|
| round-robin 1/4/16/64 | 24/28/99/202 ns | 21/21/35/98 ns |
| random | 27/34/95/213 ns | 23/26/40/98 ns |
| least-connections | 24/33/112/298 ns | 20/23/40/106 ns |
| peak-EWMA | 27/32/96/247 ns | 20/21/36/100 ns |
| weighted RR | 44/97/360/1257 ns | 21/21/34/95 ns |
| ip-hash | 25/27/82/198 ns | ~21/35/21/32 ns |
| failover/filtered/next/try | 28-126 ns | 21-70 ns |

No request-time candidate-vector allocation remains on any selection path;
weighted round-robin no longer clones a second vector (13× at 64 backends).

### Metrics / WASM telemetry (Phase 52)

Existing-site start 24.6 → 14.2 ns; start+end roundtrip 48 → 27.5 ns;
WASM hot invocation/decision/duration 13.3/14.2/15 → ~11.9 ns each,
triple-update 44.6 → 35.4 ns; `get_all_wasm_metrics` 70.8 → 54.2 ns
(post-deadlock-fix design). Cold-site insertion (~55-120 µs) and cold plugin
registration (~440 ns) unchanged by design (insertion-pressure paths).

### Honeypot persistence (Phase 53)

Enqueue 330 → 315 ns; async write under healthy consumer 5.6 → 3.75 µs;
1 KiB retention None/HashOnly/Truncated/Full 2.07/2.11/2.25/2.27 →
2.04/2.05/2.05/2.02 µs (clone removal); direct flush/prune unchanged in
throughput (SQLite work relocated, not reduced); heartbeat batch time
neutral with fairness structurally improved (flushes off core workers,
bounded to one in flight).

### Buffer pool / streaming (Phase 54)

Timing comparisons to the Phase 49 baseline are confounded by the zero-fill
correction above and late-window thermal inflation; the phase result is
correctness + bounded-memory, not nanoseconds: 6 acquire-then-append
zero-prefix defects fixed, unbounded trailing-window growth fixed, stale
reuse fixed, accounting exact (cycle-tested, no drift), grown buffers
re-tiered, pathological capacity freed, TeeBody pre-sized from reserved
hints. Bench-process high-water RSS: ~237 MB including the full Criterion
harness and jumbo cases (pool theoretical retention ceiling ≈ 58 MB;
pathological growth is freed, verified by
`test_pathological_capacity_not_retained`).

### End-to-end

No permanent end-to-end harness was added (per roadmap rejection criteria).
Representative proxy workloads are covered by the concurrency batch
benchmarks (above) and the existing stress/parity suites, all green at the
closeout head.

## 6. Correctness / security parity

- `synvoid-waf`: 197 lib (incl. 12 new execution-model parity tests +
  cross-chunk split tests + pooled-clone tests), 103 wave10, 17 corpus, 6
  property — all green. Detection categories, anomaly totals, priority
  selection, strict normalization, and fail-closed limits pinned.
- `security_regression` (single-threaded): green.
- `synvoid-upstream`: 58 unit + 13 new selection-parity tests — green.
  Weighted distribution, failover order, IP-hash stability verified.
- `synvoid-http` (85), `synvoid-proxy` (59+67), `http_tls_parity` (8) — green.
- `synvoid-metrics` (33 + egress-once + no-evict tests), `synvoid-honeypot`
  (187 incl. retention-digest, drain, concurrent-shutdown tests),
  `synvoid-utils` (38 + 4 accounting), `synvoid-plugin-runtime`
  (deadlock-regression + coherence tests) — green.
- Streaming cross-chunk SQLi/XSS/traversal/SSTI/UNION coverage verified at
  every split position; cache-tee byte identity preserved (existing proxy
  suites green).

## 7. Memory / RSS results

- `GLOBAL_ALLOCATED_BYTES` now equals live checkout capacity by construction
  (acquire/growth/take/drop reconciled; cycle-tested with zero drift).
- Grown buffers re-tier by actual capacity; >2 MiB pathological buffers are
  freed on drop, never retained.
- TeeBody pre-sizing reuses reserved capacity without changing streamed bytes
  or governor accounting.
- No steady-state or high-water RSS regression mechanism introduced; pool
  retention remains strictly bounded by existing arena caps.

## 8. Feature-profile verification

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

All four profiles compile (verified at closeout head). `cargo xtask verify`
10/10 steps green at the closeout head (524.5 s, incl. fmt, clippy
`-D warnings`, deny, core compile, repo-guards, security regression
single-threaded, root guards with `--features mesh`, core admin tests, admin
contract with `mesh,dns,icmp-filter`, failure injection).
`cargo xtask verify-full` 10/10 steps green (940.7 s, incl. all feature
profiles, minimal tests, full workspace nextest excluding fuzz, doctests).
`cargo deny check`: advisories/bans/licenses/sources ok. `cargo audit`:
exit 0 with 6 allowed warnings only (unmaintained proc-macro-error lineage,
pre-existing ignores).

## 9. Hypothesis disposition table

| # | Finding (roadmap §) | Disposition |
|---|---------------------|-------------|
| 1 | WAF bench runtime-in-loop | Measured and implemented (Phase 49) |
| 2 | WAF non-production executor | Measured and implemented (Phase 49) |
| 3 | WAF per-request JoinSet fanout | Measured and implemented (Phase 50; 3-15×) |
| 4 | Upstream candidate vectors | Measured and implemented (Phase 51; 2-13×) |
| 5 | Buffered-WAF unused owned args | Measured and implemented (Phase 51) |
| 6 | Site-start key alloc + eviction on hot path | Measured and implemented (Phase 52; 1.7×) |
| 7 | Global HTTP latency mutex | Measured but not worthwhile (3 ns; left unchanged) |
| 8 | WASM per-counter maps + String allocs | Measured and implemented (Phase 52; deadlock also fixed) |
| 9 | Honeypot SQLite on Tokio workers | Measured and implemented (Phase 53) |
| 10 | Payload-hash clone | Measured and implemented (Phase 53) |
| 11 | Writer shutdown without drain | Correctness defect corrected (Phase 53) |
| 12 | `get_all_wasm_metrics` self-deadlock | Correctness defect corrected (Phase 52) |
| 13 | Buffer-pool shard/hash/lock overhead | Measured but not worthwhile as structural churn (minimal: cached shard index, shard-0 local fast path) |
| 14 | Acquire-then-append zero prefix | Correctness defect corrected (Phase 54; 6 sites) |
| 15 | TLS/arena recycled-buffer stale data | Correctness defect corrected (Phase 54; zero-fill + tests) |
| 16 | Trailing-window unbounded growth | Correctness defect corrected (Phase 54) |
| 17 | `take_bytes`/growth accounting drift | Correctness defect corrected (Phase 54) |
| 18 | Grown buffers in smaller tiers | Correctness defect corrected (Phase 54) |
| 19 | Cache-tee zero-size init | Measured and implemented (Phase 54 presize) |
| 20 | Scheduler collapse under WAF concurrency | Not reproduced (linear to 128 in flight; improved further) |
| 21 | Upstream selection as latency bottleneck | Partially reproduced (weighted-RR only; fixed) |
| 22 | Whole-stage WAF offload need | Deferred with reason (fairness improved without it; revisit only on event-loop evidence) |
| 23 | Mesh-publishing storage reads isolation | Deferred with reason (infrequent small reads; no measurement showing material block) |
| 24 | Dedicated RSS instrumentation | Deferred with reason (bounded-retention proofs + caps instead) |

## 10. Residual opportunities

1. WAF whole-stage bounded offload for very large bodies (revisit only with
   event-loop-starvation evidence; single-10 KiB latency is the known cost).
2. JWT query/body duplicate normalization vs `NormalizedInputs` sharing
   (kept duplicated for exact semantics; ~150 ns each, measure before
   touching).
3. Global HTTP latency sampler redesign under true contention (uncontended it
   is 3 ns; contended evidence needed first).
4. Mesh-publishing storage-read isolation if future measurements implicate it.
5. Dedicated RSS/high-water harness if pooling behavior changes again.

## 11. Rejected changes and why

- Detector removal/sampling for benchmarks (rejected: coverage invariant).
- Public signature changes to save clones (rejected: compatibility
  invariant; internal cores added instead).
- `SmallVec` dependency for candidates (rejected: allocation removed, not
  hidden).
- Unbounded `spawn_blocking` fanout for honeypot (rejected: one-in-flight
  bound instead).
- `acquire(N)` capacity-only redefinition (rejected: semantics preserved and
  tested).
- Custom unsafe allocator work (rejected: unjustified).
- Mandatory routine-CI benchmark jobs (rejected: focused local surface only).
- Rewriting historical Track 3 / Phase 41-48 performance records (rejected:
  new dated record only — this document).

## 12. Final compatibility statement

Public Rust APIs, configuration keys/defaults/validation, WAF detector
coverage/scoring/precedence/fail-closed behavior, upstream algorithms and
selection semantics, protocol capabilities, Prometheus metric names/labels,
admin/status payloads, `BufferPool`/`PooledBuf` surfaces, honeypot
persistence/retention semantics and backpressure, and all feature profiles
are preserved. Behavioral deltas are limited to: (a) fixed defects now
matching documented contracts (egress single-count, zero-init buffers,
exact window bytes, drain-capable shutdown, deadlock-free snapshot); (b) the
anomaly-disabled multi-match category, which was already
nondeterministic (task-completion race) and is now deterministic
spawn-order-first. All existing correctness/security suites pass unmodified
(except new tests added, none weakened).
