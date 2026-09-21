# Performance Optimization Baseline (Phase 49)

Status: Phase 49 evidence record. Campaign roadmap: `plans/performance_optimization_roadmap.md`.

Production code changed in this phase: exactly one correctness prerequisite
(`crates/synvoid-plugin-runtime/src/wasm_metrics.rs` — consolidated WASM
telemetry registry + `get_all_wasm_metrics` self-deadlock fix). The deadlock
blocked the new metrics benchmark from running at all, and the plan names
this fix as a correctness prerequisite for the telemetry refactor. Everything
else in Phase 49 is benchmark/support code and this document.

## 1. Baseline commit / toolchain / host

- Baseline implementation head: `015e790d` (plans: align roadmap active
  performance status; first commit after the Phase 49-55 plan registration).
  Campaign planning baseline: `70d2bb29de30d2e5f66fd9cb24d682f5e2054670`.
- Toolchain: `rustc 1.98.1`, `cargo 1.98.1`.
- Host: macOS (darwin), Apple M4 Pro, `x86_64` target build. Same host and
  profile (`cargo bench` dev profile, `--quick`) for every number below.
- Profile note: numbers are `--quick` Criterion point estimates with
  confidence intervals; they are comparison anchors for Phases 50-54, not
  release-qualification figures. Phase 55 re-runs this matrix at the final
  head on the same host/profile.

## 2. Benchmark methodology corrections

1. `benches/bench_normalization.rs` constructed `tokio::runtime::Runtime::new()`
   **inside** `b.iter` for `check_request_benign`, `check_request_form_body`,
   and `check_request_10kb_body`. Runtime construction/teardown dominated the
   reported latency. Fixed: one shared multi-thread Tokio runtime (2 workers)
   built per benchmark case, outside the timed loop.
2. `benches/bench_attack_detection_wave10.rs` drove Tokio-spawning detector
   code with `futures::executor::block_on`, which cannot reproduce Tokio
   scheduling. Fixed: all async cases run under the shared Tokio runtime.
3. New coverage (fixture construction outside the timed loop in every case):
   - `benches/bench_upstream_selection.rs` — all six algorithms × 1/4/16/64
     backends, unhealthy mixes, backup fallback, protocol filter,
     `select_next_backend`, `try_select_backend`, IP-hash clients.
   - `benches/bench_metrics_hotpath.rs` — site hot path (pre-warmed key),
     site cold insertion (separate case), global request-end + HTTP latency
     sampler, WASM hot-plugin record/get paths (pre-warmed key), WASM cold
     registration (separate case).
   - `benches/bench_buffer_pool.rs` — per-tier acquire/release, TLS-cache
     hits, global pool, cross-thread acquire/drop/reacquire, growth
     within/across tiers, jumbo, zero-then-incremental growth.
   - `benches/bench_honeypot_persistence.rs` — enqueue-only, async write
     under healthy consumer, flush sizes, prune/max-record maintenance,
     all four retention modes, Tokio heartbeat-during-flush fairness probe.
4. Registered in root `Cargo.toml` (`bench_upstream_selection`,
   `bench_metrics_hotpath`, `bench_buffer_pool`,
   `bench_honeypot_persistence`). No benchmark runs in routine CI.

## 3. Benchmark commands

```bash
cargo bench --bench bench_normalization -- --quick
cargo bench --bench bench_attack_detection_wave10 -- --quick
cargo bench --bench bench_upstream_selection -- --quick
cargo bench --bench bench_metrics_hotpath -- --quick
cargo bench --bench bench_buffer_pool -- --quick
cargo bench --bench bench_honeypot_persistence -- --quick
```

## 4. WAF results (point estimates)

Benign `check_request` (default config, anomaly scoring on): path-only
~10.7 µs, query+headers ~12.7 µs, form body ~13.8 µs, 1 KiB body ~21.3 µs,
10 KiB body ~102-114 µs. Suspicious inputs through the full detector set:
SQLi ~14.5 µs, XSS ~19-25 µs, path traversal ~14.7-16.6 µs, smuggling headers
~10.3 µs, JWT bearer ~10.3 µs, strict-normalization overlong ~17.5 µs.
Anomaly-disabled fast path: benign ~9.5 µs, SQLi first-hit ~13.1 µs —
narrower than the anomaly-enabled delta, consistent with per-request `JoinSet`
fanout + `Arc` snapshot allocation dominating over detector work on small
inputs. Concurrency batches (mixed benign/suspicious): 1× ~14.8 µs, 8×
~28.8 µs, 32× ~86.9 µs, 128× ~295 µs — near-linear scaling, no collapse.

## 5. Upstream results (point estimates)

Selection is nanosecond-scale at all pool sizes: round-robin 24 ns (1) →
202 ns (64); random 27 ns → 213 ns; least-connections 24 ns → 298 ns;
Peak-EWMA 27 ns → 247 ns; IP-hash 25 ns → 198 ns. Weighted round-robin is the
outlier: 44 ns (1) → 97 ns (4) → ~360-385 ns (16) → ~1.26 µs (64), consistent
with the double allocation (candidate `Vec<&Backend>` + cloned
`Vec<Backend>`). Failover paths: half-unhealthy 57 ns, backup fallback 28 ns,
protocol-filtered 96 ns, `select_next_backend`/`try_select_backend` ~125 ns.

## 6. Metrics / plugin results (point estimates)

Existing-site accounting: start ~24.6 ns, end ~14.1 ns, proxied ~10.5 ns,
upstream-success ~11.7 ns, start+end roundtrip ~48 ns. New-site insertion is
the outlier: ~55-120 µs with wide variance — the eviction scan
(`retain` + idle-entry search) runs on the hot path even though the key is
fresh. Global `record_request_end` ~9 ns; `record_http_request_latency`
~3 ns (private mutex immaterial at this contention level — hypothesis
rejected unless a contended case proves otherwise). WASM hot-key (post-fix
consolidated registry): invocation ~13.3 ns, decision ~14.2 ns, duration
~15 ns, triple-update ~44.6 ns, `get_wasm_metrics` ~17 ns,
`get_all_wasm_metrics` ~71 ns. Cold plugin registration ~442 ns.

Pre-existing defect found while benchmarking (measured, now fixed):
`get_all_wasm_metrics` held the invocations mutex while calling `get`, which
locks the same non-reentrant mutex — the benchmark hung. Fixed by the
consolidated-registry rewrite; regression test
`test_get_all_wasm_metrics_completes_with_registered_plugin` pins it.

## 7. Buffer-pool results (point estimates)

Acquire/release is uniformly ~18 ns across small/medium/large tiers and
~21 ns for jumbo — TLS-cache fast path dominates and tier has no measurable
effect at these sizes. Global acquire ~17-18 ns. Growth within tier ~48 ns;
growth across tiers (1 KiB → 100 KiB realloc) ~515 ns; zero-length acquire +
8× incremental 1 KiB growth ~119 ns; 1 KiB `extend_from_slice` ~36 ns.
Cross-thread acquire/drop/reacquire ~16.4 µs (thread spawn dominates, not the
pool). RSS/high-water experiment: not run with dedicated instrumentation in
this phase — Phase 54 repeats the acquire/grow/drop cycles with RSS tracking
before changing retention behavior.

## 8. Honeypot / event-loop results (point estimates)

Enqueue-only `try_write_record` ~330 ns; async `write_record` under healthy
consumer ~5.6 µs (dominated by batch-flush cadence, not the enqueue path);
direct `record_connection` ~4.3 µs regardless of payload size (SQLite
transaction dominates); prune ~1.9 µs; max-record enforcement ~1.2 µs.
Retention-mode enqueue (1 KiB): None ~2.07 µs, HashOnly ~2.11 µs, Truncated
~2.25 µs, Full ~2.27 µs — hashing cost is visible but small. Heartbeat
probe (50 yields + 16 synchronous 512 B inserts): ~433 µs batch completion —
establishes the fairness baseline Phase 53 must beat on p99/event-loop lag
rather than on raw SQLite throughput.

## 9. End-to-end results

No new permanent end-to-end harness was introduced (per plan: do not add a
permanent dependency for this campaign). Representative end-to-end proxy
workloads (WAF benign/suspicious, multi-upstream, cacheable streaming, plugin
traffic) are qualified at Phase 55 using existing stress/local harnesses with
requests/second + p50/p95/p99 + errors + event-loop lag + RSS. Microbenchmark
matrices above are the attributable comparison surface for Phases 50-54.

## 10. Measurement limitations

- `--quick` Criterion runs: comparison anchors, not release qualification.
- Single host (macOS M4 Pro); Linux CI numbers will differ in absolute terms.
- No dedicated RSS/high-water instrumentation yet (Phase 54).
- No allocation-counter tooling wired; allocation claims rest on code
  inspection + the weighted-RR/cold-insert timing outliers until Phase 51/52
  re-measure.
- WASM hot-key numbers are post-fix (consolidated registry); there is no
  meaningful pre-fix steady-state number because the old `get_all` path
  deadlocked and per-counter maps allocated per update by construction.

## 11. Ranked hypotheses for Phases 50-54

1. **Phase 50 (measured, implement):** per-request `JoinSet` fanout + owned
   snapshots (`Arc<HeaderMap>`, `Arc<[u8]>`, `into_owned`) dominate small-
   request WAF latency. Borrowed inline evaluation should win clearly.
2. **Phase 51 (measured, implement):** weighted round-robin double allocation
   scales worst with pool size (1.26 µs at 64 backends vs ~200 ns for other
   algorithms). Candidate-vector elimination across all algorithms.
3. **Phase 52 (measured, implement):** cold-site insertion pays ~55-120 µs
   eviction scan on the hot path; fix borrowed-hit fast path (done for WASM,
   still open for `WorkerMetrics::record_site_request_start`).
4. **Phase 52 (measured, reject unless contended):** global HTTP latency mutex
   (~3 ns) is immaterial uncontended; leave unless a contended case proves it.
5. **Phase 53 (measured, implement):** synchronous SQLite flush/prune on Tokio
   tasks; isolate with one bounded `spawn_blocking` per batch + drain-capable
   shutdown; remove payload-hash clone; reuse prepared statements.
6. **Phase 54 (weakly indicated, gate on RSS):** pool timing is flat (~18 ns)
   so structural churn must be minimal; correctness first (acquire-then-append
   zero-prefix audit), then tier/accounting invariants, then cache-tee
   pre-sizing — all gated on RSS/high-water evidence.
7. **Not reproduced:** scheduler collapse under WAF concurrency (scales
   linearly to 128 in flight); upstream selection as a latency bottleneck
   except weighted-RR at large pools.
