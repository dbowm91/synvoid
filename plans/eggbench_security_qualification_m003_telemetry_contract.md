# Plan: Eggbench Security Qualification M003 Telemetry Contract

Status: READY.

Consumer: `eggstack/eggbench` Security Qualification M003c/M003d.

Planning baseline: `30e68af8f6e79ce0fe07f0c1871f1d0caa6be6f2`.

Related completed handoff:

- `plans/eggbench_security_qualification_asset_contract.md`
- `architecture/eggbench_security_qualification_asset_contract_closeout.md`

This plan is an independent cross-repo qualification-support handoff. It does not reopen the closed M002 asset contract and does not block or depend on the unrelated Phase 96-101 architecture-maintenance campaign.

## Goal

Provide a SynVoid-owned, versioned, loopback-only live telemetry contract that Eggbench can observe during security-performance trials without:

- importing SynVoid Rust crates;
- parsing SynVoid IPC;
- scraping authenticated admin internals;
- inventing metric names/semantics downstream;
- changing WAF/security behavior.

The contract must expose the bounded target-level performance signals that already exist in SynVoid's worker/CPU-worker metrics path and make them stable enough for external qualification.

## Research basis

At the planning baseline:

- the M002 Eggbench qualification asset contract is closed and live-proven;
- the generated M002 minimal config deliberately disables admin and metrics;
- `crates/synvoid-config/src/admin.rs` has a metrics configuration with enabled/port fields;
- `src/admin/prometheus_exporter.rs` has a Prometheus exporter that binds `127.0.0.1:<port>`;
- repository search shows the exporter entrypoint is not currently a proven lifecycle path for the M002 minimal qualification runtime;
- many production/security counters already emit through the `metrics` facade;
- the target performance fields Eggbench M003 needs are primarily carried in `WorkerMetricsPayload` / CPU-worker heartbeat state rather than a frozen Prometheus contract.

Current worker payloads include:

- `event_loop_lag_ms`;
- `request_queue_time_ms` avg/p50/p95/p99;
- `active_connections`;
- `memory_bytes`;
- `cpu_percent`;
- `inline_cpu_phase_times_ms`;
- `body_buffering_bytes_total`;
- `offload_submissions_total`;
- `offload_timeouts_total`;
- `offload_rejections_total`;
- `offload_fallbacks_total`.

CPU-worker state also carries:

- worker RSS;
- offload queue/active/task counters;
- task-duration summaries;
- event-loop lag.

These signals should be exported by their owner rather than reconstructed downstream.

## Ownership boundary

SynVoid owns:

- metric source semantics;
- stable external metric names;
- gauge/counter classification;
- aggregation across SynVoid workers where required;
- the qualification metrics endpoint lifecycle;
- the materialized telemetry contract/provenance;
- tests proving the exported values correspond to live internal state.

Eggbench owns:

- generic Prometheus scraping;
- trial-window sampling;
- mapping requested owner metrics into Eggbench `subject_*` names;
- trial aggregation/delta calculation;
- benchmark evidence/gates.

Do not add an Eggbench dependency to SynVoid.

## Contract identifier

Create a versioned owner contract:

~~~text
synvoid.eggbench-telemetry.v1
~~~

Any incompatible metric-name/type/meaning change requires a new contract identifier/version.

Adding optional metrics may remain compatible only when the contract schema explicitly permits additive optional fields.

## Workstream A — choose and wire the live exporter lifecycle

Re-audit the current Prometheus exporter and minimal runtime startup.

Preferred outcome:

- reuse the existing `metrics_exporter_prometheus` surface;
- wire it into the normal owned runtime lifecycle when `metrics.enabled = true`;
- bind loopback only;
- ensure it shuts down with the process;
- ensure enabling metrics does not require enabling the browser admin/API surface.

Qualification runtime remains:

~~~text
cargo build --locked --release --no-default-features
synvoid --foreground --config-path <generated-config>
~~~

If the current exporter architecture cannot safely expose the required worker metrics, add the smallest bridge necessary at the owner boundary. Do not add a second general observability stack.

## Workstream B — canonical initial metric set

Export a bounded initial set sufficient for M003.

Required categories:

### Gauges / sampled values

- unified worker event-loop lag;
- request-queue p95 (and optionally avg/p50/p99);
- active connections;
- worker memory bytes;
- worker CPU percent;
- CPU-worker RSS where available.

### Monotonic counters

- body-buffering bytes total;
- offload submissions total;
- offload timeouts total;
- offload rejections total;
- offload fallbacks total.

If a value is aggregated across multiple workers, define the aggregation explicitly.

Do not expose unbounded site IDs, request paths, client addresses, plugin names, or other high-cardinality labels for qualification.

Prefer stable production-oriented `synvoid_...` metric names over Eggbench-specific duplicate counters where a canonical name can be defined cleanly.

## Workstream C — qualification telemetry manifest

Extend `cargo xtask eggbench-qualification export` with an optional telemetry mode/metrics port.

Recommended interface:

~~~text
cargo xtask eggbench-qualification export \
  --output <dir> \
  --listen-port <port> \
  --origin-port <port> \
  --metrics-port <port>
~~~

When telemetry is requested, emit:

~~~text
telemetry-contract.json
~~~

containing at least:

- schema version;
- contract identifier;
- SynVoid package version;
- exact git SHA;
- metrics endpoint scheme/host/port/path;
- required metric names;
- metric kind (`gauge` or `counter`);
- unit;
- source owner/semantic description;
- whether metric is required or optional;
- worker aggregation rule when applicable;
- contract digest.

The endpoint must be loopback-only and credential-free in the qualification profile.

Update `provenance.json` to bind:

- telemetry contract digest;
- metrics port;
- generated config digest.

Do not place arbitrary environment data in the manifest.

## Workstream D — generated config

When telemetry is requested:

- enable the metrics exporter;
- bind it to `127.0.0.1:<metrics-port>`;
- keep browser/admin control surfaces disabled unless the exporter is inseparable from them and a narrower separation cannot be implemented safely;
- retain all existing M002 loopback/WAF/minimal-runtime constraints;
- reject metrics-port collision with data-plane/origin ports;
- keep all state/log paths within the qualification-owned directory where current configuration supports it.

When telemetry is not requested, byte/semantic behavior of the closed M002 export should remain unchanged.

## Workstream E — bridge worker telemetry truthfully

Wire owner metrics from existing worker/CPU-worker state to the external exporter.

Requirements:

- no duplicate independent measurement of event-loop lag or queue timing;
- no fake/synthetic zero for unavailable metrics;
- counters remain monotonic within one process generation;
- gauge semantics are documented;
- process/worker restart behavior is explicit;
- if a metric is not meaningful in the minimal runtime, omit/classify it optional rather than fabricating it.

Prefer a single aggregation owner rather than multiple modules emitting conflicting values for the same metric name.

## Workstream F — self-tests

Add deterministic tests for:

1. telemetry-off export remains compatible with the existing M002 contract;
2. telemetry-on config binds loopback only;
3. metrics port appears exactly once and does not collide with other ports;
4. telemetry manifest is deterministic;
5. manifest names map to actual exported metrics;
6. gauge/counter kinds remain stable;
7. high-cardinality labels are absent from the qualification metric set;
8. configtest succeeds with telemetry enabled on the minimal binary;
9. provenance digest changes when telemetry contract/config changes;
10. exporter lifecycle stops cleanly.

## Workstream G — live qualification proof

Add or extend the opt-in live proof.

It must:

1. materialize telemetry-enabled owner assets;
2. configtest the real minimal binary;
3. start the controlled origin and real SynVoid process;
4. wait for both data-plane and metrics endpoints;
5. scrape a baseline metrics snapshot;
6. drive the existing benign perf path and at least one WAF/body-bearing path that changes relevant counters;
7. scrape during/after load;
8. prove required metrics are present, finite, and semantically plausible;
9. prove at least one monotonic counter does not decrease;
10. prove at least one gauge changes or remains valid under load;
11. terminate the subject and exporter cleanly.

The proof must not assert universal capacity thresholds.

## Workstream H — documentation

Update:

- `architecture/metrics.md`;
- `docs/PERFORMANCE.md`;
- the Eggbench qualification contract closeout/addendum as appropriate;
- operator configuration docs for the metrics exporter if lifecycle wiring changes.

Document the distinction between production observability support and the bounded owner contract promised to Eggbench.

## Routine verification

At minimum:

~~~text
cargo fmt --all -- --check
cargo test -p synvoid-metrics --profile ci
cargo test -p xtask --profile ci
cargo xtask test guards
cargo xtask verify
cargo build --locked --release --no-default-features
~~~

Plus the telemetry-enabled materializer/configtest and opt-in live proof.

Do not add a permanent high-load benchmark to routine CI.

## Acceptance criteria

This plan closes only when:

1. `synvoid.eggbench-telemetry.v1` exists;
2. the real minimal runtime can expose the qualification metrics endpoint;
3. the endpoint is loopback-only and bounded;
4. event-loop/queue/connection/resource/offload metrics are owner-published with explicit semantics;
5. a deterministic telemetry manifest is emitted by the owner materializer;
6. provenance binds that manifest/config;
7. telemetry-off M002 export remains compatible;
8. telemetry-enabled configtest passes;
9. live proof scrapes real values while traffic executes;
10. no Eggbench dependency or second load generator is introduced;
11. no WAF/security semantic changes are made for the benchmark;
12. routine verification remains green.

## Rejection criteria

Reject an implementation that:

- makes Eggbench parse SynVoid IPC;
- exposes metrics publicly by default;
- enables a broad authenticated admin surface solely for qualification when a narrow exporter can be used;
- invents downstream metric semantics not owned by SynVoid;
- exports raw request/path/client identifiers as metric labels;
- fabricates zeros for unavailable metrics;
- changes detection/enforcement behavior to produce prettier telemetry;
- adds a SynVoid-side benchmark/load generator.

## Handoff and closure

This plan is dependency-ready and may execute in parallel with Eggbench M003a/M003b and unrelated SynVoid roadmap phases.

On closure, add a proof-bearing architecture record with:

- implementation SHA;
- package/Cargo.lock identity;
- telemetry contract identifier/digest;
- exported metric inventory and semantics;
- generated config/provenance digests;
- minimal binary digest/build command;
- configtest result;
- live scrape proof;
- routine verification;
- unresolved findings.

Downstream Eggbench M003c may develop against hermetic fixture endpoints before this closes, but real SynVoid M003 telemetry qualification must wait for owner-side closure.
