# Performance Optimization and Request-Path Efficiency Roadmap

Status: active implementation roadmap.

Baseline reviewed: `main` at `70d2bb29de30d2e5f66fd9cb24d682f5e2054670` (2026-09-19).

Registered in: `plans/roadmap.md`.

## Primary goal

Improve SynVoid throughput, tail latency, allocator pressure, and async-runtime fairness without removing or narrowing any existing public API, protocol support, WAF capability, observability surface, configuration behavior, or supported feature profile.

This campaign is measurement-first. It must not turn plausible micro-optimizations into architecture churn. Every production-path change needs a representative before/after benchmark and the existing correctness/security suites must remain authoritative.

## Findings that justify implementation work

1. The current WAF benchmark harness does not faithfully model production execution. `bench_normalization` constructs a Tokio runtime inside Criterion iterations, while `bench_attack_detection_wave10` uses `futures::executor::block_on` even though `AttackDetector::check_request()` may spawn Tokio tasks.
2. `AttackDetector::check_request()` creates a per-request `JoinSet` and may spawn roughly a dozen synchronous detector routines as Tokio tasks. This forces owned request snapshots, task allocation, scheduler traffic, and Arc cloning inside the latency-sensitive unified worker.
3. `synvoid-upstream::UpstreamPool` materializes candidate vectors on request selection. Weighted round-robin creates a second cloned vector. IP-hash/protocol/next-backend paths also allocate candidate vectors.
4. The HTTP buffered-WAF path still constructs/clones owned arguments that the canonical crate-level dispatcher does not consume. The root compatibility adapter can additionally copy body bytes solely to satisfy that owned signature.
5. Hot-path metrics still contain avoidable lock/allocation work. In particular, per-site start accounting allocates `site_id.to_string()` before `HashMap::entry` even on hits and executes eviction logic on the request path; global HTTP latency sampling serializes on one mutex. WASM plugin metrics use many mutex-protected maps and allocate a `String` for repeated updates.
6. Honeypot writes are sensibly bounded through an mpsc queue, but the consumer performs synchronous `rusqlite` transactions from a Tokio task. Pruning also invokes synchronous SQLite from async tasks. Payload retention clones the payload before hashing, and shutdown does not currently provide a strong drain/join contract.
7. `BufferPool` combines a TLS cache with a thread-local multi-shard/mutex pool and a global pool using the same structure. The local pool therefore pays shard/hash/lock costs that provide no cross-thread benefit. Capacity/tier/accounting behavior after buffer growth also needs evidence before further zero-copy work.
8. `TeeBody` knows a cacheable response size hint but initializes its pooled body buffer at zero logical size/capacity intent, leaving avoidable growth/reallocation on cacheable streaming responses.

## Global compatibility invariants

All phases MUST preserve the following unless a separate, explicitly approved compatibility change is opened:

- public Rust function/type/module names and signatures;
- configuration keys, defaults, validation behavior, and feature-gate truthfulness;
- WAF detector coverage, anomaly-scoring semantics, enforcement precedence, fail-closed behavior, and supported attack classes;
- upstream algorithms and externally observable selection semantics;
- HTTP/1.1, HTTP/2, HTTP/3, WebSocket, gRPC, UDS, tunnel, mesh, DNS, plugin, and serverless capability;
- Prometheus metric names/labels and admin/status payload fields;
- `BufferPool`/`PooledBuf` public methods and call-site capability;
- honeypot persistence/retention semantics and bounded backpressure;
- release/default/minimal feature profiles.

Optimization is not permission to lower security checks, sample away required accounting, silently skip work under load, or alter failure policy.

## Measurement rules

Use the same toolchain/profile and the same host for before/after comparisons. Record:

- Criterion point estimates and confidence intervals;
- throughput and p50/p95/p99 for representative request workloads where practical;
- allocation/copy counts or a defensible proxy when the change targets allocation;
- runtime event-loop lag when the change moves CPU/blocking work;
- RSS/high-water memory when changing pooling/retention behavior.

A benchmark result is not acceptance evidence if setup dominates the operation under test. Runtime construction, fixture construction, database creation, regex compilation, or server startup must occur outside the timed loop unless that startup cost is itself the subject of the benchmark.

Treat an apparent regression greater than 5% in a primary hot-path benchmark or tail-latency workload as material until explained. Smaller changes still require judgment when confidence intervals are tight or the operation runs on every request.

## Phase order

### Phase 49 — Performance measurement and benchmark truth

Plan: `plans/phase_49_performance_measurement_and_benchmark_truth.md`.

Correct the WAF async benchmark methodology, add missing upstream/metrics/pool/persistence coverage, and capture a fresh baseline at the campaign head. No production optimization should be merged solely from static inspection before this phase produces usable evidence.

### Phase 50 — WAF execution-model optimization

Plan: `plans/phase_50_waf_execution_model_optimization.md`.

Use Phase 49 evidence to remove per-request scheduler/ownership overhead from synchronous detector execution while preserving detector coverage, scoring, priority, and enforcement behavior. Prefer borrowed inline evaluation when it wins; only offload the whole expensive stage if measurements show event-loop starvation that inline evaluation cannot satisfy.

### Phase 51 — Request-path allocation and upstream-selection optimization

Plan: `plans/phase_51_request_path_allocation_and_upstream_selection.md`.

Remove candidate-vector allocation from upstream selection and eliminate unused ownership/copy churn around buffered WAF dispatch without changing public APIs or load-balancing semantics.

### Phase 52 — Metrics and plugin telemetry hot-path optimization

Plan: `plans/phase_52_metrics_and_plugin_telemetry_hot_path.md`.

Reduce private telemetry mutex/string-allocation overhead while preserving metric names, payloads, counters, and public struct/API compatibility. Audit duplicate accounting while touching the path.

### Phase 53 — Blocking persistence and honeypot I/O isolation

Plan: `plans/phase_53_blocking_persistence_and_honeypot_io_isolation.md`.

Keep synchronous SQLite off Tokio core workers, remove the payload hash clone, reuse prepared statements where beneficial, and make writer shutdown/drain explicit without changing caller-facing persistence APIs.

### Phase 54 — Buffer-pool and streaming-memory efficiency

Plan: `plans/phase_54_buffer_pool_and_streaming_memory_efficiency.md`.

Simplify local/global reuse internals, correct capacity/tier/accounting invariants, and pre-size cache tee buffers from trustworthy size hints. This phase is benchmark/RSS gated because retained-memory regressions are more damaging than small nanosecond gains.

### Phase 55 — End-to-end qualification and closeout

Plan: `plans/phase_55_performance_qualification_and_closeout.md`.

Re-run focused microbenchmarks plus representative end-to-end workloads, verify all supported feature profiles, reconcile performance documentation, and record which static findings were validated, rejected, or deferred.

## Dependency order and safe parallelism

Phase 49 lands first.

After the baseline exists:

- Phase 50 should run independently because WAF scheduling changes can dominate event-loop behavior and would contaminate other comparisons.
- Phase 51 can proceed in parallel with Phase 52 because they touch different canonical owners.
- Phase 53 can proceed in parallel with Phases 50-52 after the persistence benchmark fixture exists.
- Phase 54 should use the post-Phase-50/51 tree for final memory evidence because WAF/request ownership changes can alter buffer traffic.
- Phase 55 runs last.

Avoid combining Phases 50, 51, and 54 into one large request-path rewrite. The point of the campaign is attributable evidence.

## Roadmap-wide acceptance criteria

This campaign is complete only when:

- the async WAF benchmarks use a persistent Tokio runtime and faithfully exercise production scheduling;
- representative WAF benign/suspicious/body/concurrency baselines are recorded;
- upstream selection has dedicated per-algorithm benchmarks and no request-time candidate-vector allocation remains where measurements justify removal;
- WAF optimization preserves all detection/enforcement semantics and improves or at minimum does not materially regress the measured production-like workload;
- the canonical HTTP path no longer creates unused owned WAF-dispatch arguments/copies;
- hot telemetry paths avoid unnecessary repeated key allocation/locking without changing exported metrics or payload semantics;
- synchronous honeypot SQLite work is isolated from Tokio core workers and graceful shutdown can drain queued records;
- buffer-pool changes preserve public API and memory-limit semantics while improving or not materially regressing throughput/RSS;
- default, minimal, mesh, dns, and mesh+dns compile/verification profiles remain green;
- `cargo xtask verify` and `cargo xtask verify-full` pass at the closeout head;
- a final evidence report distinguishes measured wins, neutral changes, rejected hypotheses, and deliberate residuals.

## Rejection criteria

Reject an implementation that:

- removes or disables a detector to improve a benchmark;
- changes WAF anomaly scoring, enforcement precedence, or fail-closed semantics unintentionally;
- changes a public signature/type solely to save a clone or lock;
- replaces bounded work with unbounded `spawn_blocking` or unbounded background queues;
- changes upstream load-balancing distribution or backup/failover behavior without an explicit compatibility decision;
- drops metric samples/counters under contention without documenting and approving the semantic change;
- increases steady-state or high-water RSS materially in exchange for an insignificant latency gain;
- reports a speedup measured mostly from benchmark setup differences;
- expands routine CI with large benchmark jobs; performance evidence remains a focused local/release qualification surface unless a later plan explicitly changes CI policy.
