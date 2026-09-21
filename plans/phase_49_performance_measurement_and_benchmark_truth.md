# Phase 49 Plan: Performance Measurement and Benchmark Truth

Status: implemented and closed; retained as historical handoff detail. Closeout: `architecture/performance_optimization_closeout.md`.

Roadmap: `plans/performance_optimization_roadmap.md`.

Baseline: `main` at `70d2bb29de30d2e5f66fd9cb24d682f5e2054670` before this campaign's planning commits.

Depends on: Phase 48 closed.

## Objective

Establish trustworthy, reproducible performance evidence for the current request path before changing production execution. Correct benchmark methodology that currently measures runtime setup or uses a non-production executor, add coverage for the newly identified hot paths, and record a campaign baseline that later phases can compare against.

This phase should change benchmark/support code and documentation only unless a tiny testability seam is strictly required. Do not optimize production code here.

## Confirmed benchmark defects

### WAF runtime construction inside the timed loop

`benches/bench_normalization.rs` creates `tokio::runtime::Runtime::new()` inside multiple Criterion iterations before calling `AttackDetector::check_request()`.

That makes runtime construction, allocator setup, driver initialization, and teardown part of the reported detector latency. Move runtime construction outside the timed loop and reuse one runtime for the benchmark case.

### Non-production executor for Tokio-spawning WAF code

`benches/bench_attack_detection_wave10.rs` uses `futures::executor::block_on`, while the current `AttackDetector::check_request()` can call `tokio::task::JoinSet::spawn`.

Run the benchmark inside a real Tokio runtime. Do not rely on a futures executor that cannot reproduce Tokio scheduling behavior.

## Workstream A — Repair WAF benchmarks

Update the existing benches rather than creating overlapping copies where possible.

Required cases:

- benign GET/path-only fast path;
- benign query/header request;
- benign POST with approximately 1 KiB body;
- benign POST with approximately 10 KiB body;
- representative SQLi/XSS/path traversal/request-smuggling/JWT inputs;
- anomaly scoring enabled, because it is the default and changes whether all detector results must be accumulated;
- a focused anomaly-disabled case to preserve the early-terminal path;
- strict normalization enabled;
- default detector set.

Runtime/fixture creation MUST be outside Criterion's timed body.

Add a concurrent batch benchmark or focused harness for at least:

- 1 request in flight;
- 8 requests;
- 32 requests;
- 128 requests where the test host can support it without swapping.

The concurrency test should report total throughput and batch completion latency rather than pretending each spawned request is an independent Criterion sample.

## Workstream B — Add upstream selection benchmarks

Add a dedicated benchmark for `synvoid-upstream::UpstreamPool`.

Cover algorithms:

- RoundRobin;
- Random;
- LeastConnections;
- PeakEwma;
- WeightedRoundRobin;
- IpHash.

Cover pool sizes:

- 1;
- 4;
- 16;
- 64 backends.

Include:

- all healthy primaries;
- a mix of unavailable primaries;
- backup fallback;
- protocol-filtered selection;
- `select_next_backend`;
- IP-hash selection.

Fixture construction and backend mutation occur outside the timed loop.

Record enough information to compare allocation-elimination work in Phase 51.

## Workstream C — Add observability hot-path benchmarks

Add focused benchmarks for:

- `WorkerMetrics::record_request_end`;
- per-site request start/end/proxied/upstream-success paths with an existing site;
- insertion of a new site as a separate cold-path case;
- global `record_http_request_latency`;
- WASM plugin invocation/decision/duration/pool metrics for a pre-existing plugin key;
- `get_wasm_metrics` and `get_all_wasm_metrics` separately from record operations.

The hot-key benchmark must pre-register or warm the plugin/site so it does not conflate first-use allocation with steady-state accounting.

## Workstream D — Add buffer-pool evidence

Add or extend Criterion coverage for:

- TLS-cache hit at small/medium/large tiers;
- local spill into the arena;
- global pool acquire/release;
- same-thread reuse;
- cross-thread acquire/drop/reacquire;
- grow within tier;
- grow across tier boundaries;
- jumbo allocation;
- zero-length logical buffer followed by incremental growth;
- an equivalent pre-sized/capacity-oriented construction if Phase 54 adds the seam.

Also record a bounded RSS/high-water experiment outside Criterion for repeated acquire/grow/drop cycles. The goal is to detect retained-memory amplification that nanosecond microbenchmarks hide.

## Workstream E — Add honeypot persistence baseline

Using a temporary SQLite database, measure:

- enqueue-only `try_write_record`;
- async `write_record` under a healthy consumer;
- flush of 1 record;
- configured batch-size flush;
- payload modes None, HashOnly, Truncated, Full with representative payload sizes;
- prune/max-record maintenance separately.

Do not include database creation/schema initialization in flush timing.

Record event-loop lag or an equivalent scheduler-fairness experiment while SQLite flushes are occurring, because Phase 53 targets blocking leakage more than raw SQLite throughput.

## Workstream F — Representative end-to-end request baseline

Use an existing local benchmark/stress harness if one already satisfies this requirement; do not introduce a new permanent dependency merely for this campaign.

Capture same-host baselines for at least:

1. WAF-enabled benign proxy traffic;
2. WAF-enabled suspicious traffic that reaches full detectors;
3. weighted or round-robin multi-upstream traffic;
4. cacheable streaming responses;
5. plugin-enabled traffic if the fixture is already supportable.

Record:

- requests/second;
- p50;
- p95;
- p99;
- errors/timeouts;
- worker event-loop lag;
- RSS/high-water memory where available.

Keep configuration, connection count, payload size, and duration in the evidence document.

## Deliverable

Create:

`architecture/performance_optimization_baseline.md`

Required sections:

1. exact baseline commit/toolchain/host;
2. benchmark methodology corrections;
3. benchmark commands;
4. WAF results;
5. upstream results;
6. metrics/plugin results;
7. buffer-pool results;
8. honeypot/event-loop results;
9. end-to-end results;
10. measurement limitations;
11. ranked hypotheses for Phases 50-54.

Do not claim a bottleneck merely because static inspection suggested one. Label each finding measured, weakly indicated, or not reproduced.

## Suggested verification

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo bench --bench bench_normalization
cargo bench --bench bench_attack_detection_wave10
# plus newly added focused benches
cargo xtask verify
```

Do not add long benchmark runs to routine CI.

## Acceptance criteria

Phase 49 is complete when:

- no WAF Criterion timed loop constructs a Tokio runtime;
- WAF async benchmarks execute under Tokio when production code requires Tokio;
- current WAF default configuration has benign, suspicious, body-size, and concurrency evidence;
- all upstream algorithms have representative selection benchmarks;
- metrics/plugin hot-key accounting has steady-state evidence;
- buffer-pool local/global/growth behavior has timing plus memory evidence;
- honeypot persistence has flush and event-loop-fairness evidence;
- `architecture/performance_optimization_baseline.md` records exact commands and results;
- no production API/capability has changed.

## Rejection criteria

Reject Phase 49 if it:

- changes detector/config defaults to make numbers better;
- times fixture/runtime/database construction as though it were request work;
- compares runs from materially different hosts/configurations without disclosure;
- adds benchmark-only production branches;
- turns performance runs into mandatory routine CI jobs;
- begins Phase 50+ production refactors before a usable baseline exists.
