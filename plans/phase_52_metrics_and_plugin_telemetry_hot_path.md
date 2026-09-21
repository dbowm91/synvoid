# Phase 52 Plan: Metrics and Plugin Telemetry Hot-Path Optimization

Status: implemented and closed; retained as historical handoff detail. Closeout: `architecture/performance_optimization_closeout.md`.

Roadmap: `plans/performance_optimization_roadmap.md`.

Depends on: Phase 49 complete. May run in parallel with Phase 51.

## Objective

Reduce synchronization and key-allocation overhead in request/plugin observability without changing metric names, labels, admin/status payloads, public metric APIs, or the meaning of counters and latency summaries.

This phase must respect that several `WorkerMetrics` fields are public. Do not retype/remove public fields merely to obtain a lock-free implementation.

## Workstream A — Optimize per-site request-start accounting without changing public storage types

Current `WorkerMetrics::record_site_request_start()`:

- locks the per-site `HashMap`;
- may execute capacity cleanup logic whenever the map is at the limit;
- constructs `site_id.to_string()` as part of `entry()` even when the site already exists.

Refactor the method so the common existing-site path:

1. performs borrowed lookup with `get_mut(site_id)`;
2. records the request immediately without allocating a key;
3. only performs capacity/eviction work when the site is actually absent;
4. only allocates an owned site key when insertion is required.

Preserve:

- `MAX_PER_SITE_ENTRIES`;
- active-site retention behavior;
- all existing public fields/types;
- `SiteMetrics` counters and latency semantics.

Add a test proving repeated accounting for one existing site does not create a new key and does not run eviction that can remove unrelated idle entries.

## Workstream B — Optimize private global HTTP latency sampling

`record_http_request_latency()` currently serializes every completed HTTP/TLS request on a private global mutex-backed deque.

Because the storage is private, its implementation may change as long as these observable APIs preserve their semantics.

Evaluate:

- fixed atomic ring;
- per-worker/sharded rings merged on read;
- another bounded design with coherent snapshots.

Requirements:

- bounded memory;
- no unbounded allocation;
- retain recent-sample behavior;
- percentile/average readers remain correct for the recorded sample set;
- no data race/unsafe code required;
- no sample dropping merely to avoid contention unless the existing metric contract is explicitly changed outside this phase.

If the Phase 49 benchmark shows the current mutex is immaterial, leave it alone and record the rejected hypothesis.

## Workstream C — Consolidate WASM metric storage

Canonical owner:

`crates/synvoid-plugin-runtime/src/wasm_metrics.rs`

Current implementation uses many independent `Mutex<HashMap<String, AtomicU64>>` registries. Each record function locks one map and calls `plugin_name.to_string()` before `entry`, allocating even for an existing plugin.

Refactor private storage to one registry keyed by plugin name whose value contains the complete atomic counter set, for example an internal `Arc<WasmMetricCounters>`.

Preserve public functions such as:

- `record_wasm_invocation`;
- decision/error/fuel/duration recorders;
- pool/fresh-instance/timeout recorders;
- `get_wasm_metrics`;
- `get_all_wasm_metrics`;
- `WasmPluginMetrics` output fields.

Steady-state recording for an already-known plugin should not allocate a new `String`.

If practical, have the plugin runtime cache an internal counter handle after plugin load so repeated invocations can update atomics without registry lookup. Do this only through private/internal fields; do not change public plugin API merely for telemetry.

## Workstream D — Fix `get_all_wasm_metrics` lock re-entry

The current implementation iterates keys while holding `WASM_PLUGIN_INVOCATIONS.lock()` and calls `WasmPluginMetrics::get(name)`, which locks the same registry again.

With the current non-reentrant mutex this can self-block.

The consolidated registry should make snapshotting straightforward:

- acquire registry lock only long enough to clone key/Arc-handle pairs;
- release it;
- load atomics outside the lock.

Add a regression test with at least one registered plugin that calls `get_all_wasm_metrics()` and completes under a bounded timeout.

Treat this as a correctness prerequisite for the telemetry refactor.

## Workstream E — Audit duplicate request accounting

While simplifying request metrics, add focused tests proving one logical event increments each exported counter once.

In particular, inspect blocked/challenged egress handling in `crates/synvoid-http/src/http_request_postlude.rs`, where the `RequestMetricsAdapter` already updates bandwidth/site egress and surrounding closures may also update the underlying `WorkerMetrics` directly.

If tests confirm duplicate accounting:

- remove only the duplicate write;
- preserve metric names and intended per-event value;
- document the correction in the phase completion evidence.

Do not use a performance plan to silently redefine metric meaning.

## Workstream F — Benchmarks

Use Phase 49 evidence and add contention cases where useful:

- existing-site request start/end;
- 8/32 concurrent metric writers;
- global HTTP latency recorder;
- WASM hot plugin invocation + decision + duration;
- first-use plugin registration separately;
- `get_wasm_metrics`;
- `get_all_wasm_metrics`.

Measure allocations for hot plugin updates if tooling is already available.

## Acceptance criteria

Phase 52 is complete when:

- public metrics structs/functions and exported metric names/labels are unchanged;
- existing-site per-site start accounting avoids owned-key allocation;
- capacity cleanup executes on insertion pressure rather than every hot hit;
- private global latency sampling is improved if Phase 49 proves it material, otherwise explicitly left unchanged;
- WASM steady-state recording no longer allocates a plugin-name `String` per counter update;
- WASM metrics use a coherent single per-plugin counter set or equivalently efficient design;
- `get_all_wasm_metrics()` cannot self-deadlock;
- one logical request/plugin event is counted exactly once;
- Phase 49-comparable benchmarks show no material regression and preferably reduced lock/allocation cost.

## Verification

```bash
cargo test -p synvoid-metrics --profile ci
cargo test -p synvoid-plugin-runtime --profile ci
cargo test -p synvoid-http --profile ci
cargo xtask test guards
cargo xtask verify
```

Run the Phase 49 metrics/plugin benchmarks on the same host/profile.

## Rejection criteria

Reject a change that:

- changes/removes public metric fields or function signatures;
- renames Prometheus metrics or labels;
- drops samples opportunistically under contention without approval;
- changes percentile semantics merely to become lock-free;
- caches unbounded plugin/site keys;
- hides duplicate accounting by changing dashboards rather than fixing the producer;
- adds unsafe lock-free structures for a negligible measured gain.
