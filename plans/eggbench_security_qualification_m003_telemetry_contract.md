# Plan: Eggbench Security Qualification M003 Telemetry Contract

Status: **READY — REBASED 2026-09-29**.

Consumer: eggstack/eggbench Security Qualification M003c/M003d.

Current SynVoid planning baseline:
f3cdfda2416147e12b464bd55b0240acfffe58f1.

Architecture-maintenance proof-bearing predecessor:
2bfc3c6cfd1a1f2454f801cc02c01a0cbafa2e30
(Phases 96–101 CLOSED QUALIFIED; hosted CI/dependency-security run 36515438452 passed).

Current Eggbench consumer baseline observed during rebase:
18b1c1c8398d559d38bd74d717ff3dc79e3b20ad.

Generic Eggbench Prometheus subject-telemetry implementation:
2742e0eafaaef38899db5978f1721611ce58a7bc.

Original planning baseline, now superseded for implementation:
30e68af8f6e79ce0fe07f0c1871f1d0caa6be6f2.

Related completed handoff:

- plans/eggbench_security_qualification_asset_contract.md
- architecture/eggbench_security_qualification_asset_contract_closeout.md

This plan is an independent cross-repo qualification-support handoff. It does
not reopen the closed M002 asset contract. The Phase 96–101 architecture
campaign is now a completed predecessor rather than parallel work.

## Rebase verdict

The handoff remains valid and dependency-ready, but the original implementation
shape needed correction in four places.

1. **The existing Prometheus exporter cannot simply be wired as-is.**
   src/admin/prometheus_exporter.rs is currently dead code. It calls
   PrometheusBuilder::build(), drops the returned recorder, and detaches the
   exporter future in an unowned tokio::spawn. With the current
   metrics-exporter-prometheus 0.18.3 API, build() returns a
   PrometheusRecorder plus ExporterFuture; the recorder must be installed or
   otherwise explicitly used. The exporter task must also join the supervisor
   lifecycle rather than outlive its shutdown receiver.

   Reference:
   https://docs.rs/metrics-exporter-prometheus/0.18.3/metrics_exporter_prometheus/struct.PrometheusBuilder.html

2. **SynVoid is multi-process, so process-local metrics macros are not the M003
   source of truth.** HTTP data-plane telemetry is produced in Unified Server
   worker processes and sent in WorkerMetricsPayload heartbeats. CPU-worker
   telemetry is sent separately in CpuOffloadStats. The supervisor already
   retains both through ProcessManager. Installing a recorder only in the
   supervisor does not magically collect metrics emitted in child processes.

3. **Phase 99 changed the configuration ownership boundary.** MetricsConfig
   remains correctly owned by synvoid-config runtime/config management.
   synvoid-config-model is deliberately a small, low-capability DTO leaf and
   must not gain exporter lifecycle, filesystem, IPC, or runtime telemetry
   authority merely for this handoff.

4. **Eggbench M003c is no longer hypothetical.** Its generic
   prometheus-http collector is implemented. It already owns bounded scrape
   parsing, exact mapping digests, gauge aggregation, counter deltas/reset
   handling, private-endpoint validation, and subject_* normalized output.
   SynVoid therefore needs to publish stable owner metrics plus a deterministic
   mapping/provenance artifact; it does not need to design or implement a
   downstream collector.

No separate SynVoid corrective phase is required before this plan. These
findings are incorporated below.

## Goal

Provide a SynVoid-owned, versioned, loopback-only live telemetry contract that
Eggbench can observe during security-performance trials without:

- importing SynVoid Rust crates;
- parsing SynVoid IPC;
- scraping authenticated admin APIs or WebSockets;
- inventing SynVoid metric names or source semantics downstream;
- enabling a broad admin surface;
- changing WAF/security behavior.

The contract identifier remains:

~~~text
synvoid.eggbench-telemetry.v1
~~~

Any incompatible owner metric name, type, unit, aggregation-source meaning, or
availability requirement requires a new owner contract version.

## Current source-of-truth inventory

### Unified Server workers

ProcessManager::handle_unified_server_worker_heartbeat stores the latest
WorkerMetricsPayload for each Unified Server worker, and
ProcessManager::get_all_unified_server_worker_metrics returns those snapshots.

Current payload fields needed by M003 include:

- event_loop_lag_ms;
- request_queue_time_ms avg/p50/p95/p99;
- active_connections;
- memory_bytes;
- cpu_percent;
- body_buffering_bytes_total;
- offload_submissions_total;
- offload_timeouts_total;
- offload_rejections_total;
- offload_fallbacks_total.

Unified Server worker heartbeats are currently emitted on a five-second
cadence. The owner contract must state that source cadence. M003 telemetry is
diagnostic initially; do not claim request-exact accounting from a five-second
heartbeat snapshot.

### CPU worker

ProcessManager::handle_cpu_worker_heartbeat retains CpuOffloadStats and
get_cpu_worker_cpu_offload_stats returns the latest snapshot.

CpuOffloadStats includes:

- queued/active/completed counters by CPU task kind;
- submitted/rejected/timeout/failed/fallback totals;
- task-duration summaries;
- event_loop_lag_ms;
- worker_rss_bytes.

CPU-worker RSS is useful but should be optional in v1 unless qualification
proves a CPU worker is always present and ready in the supported minimal
runtime.

### Existing admin metrics publisher

src/admin/metrics.rs is not the canonical M003 source. It currently reads the
legacy ProcessManager::get_worker_metrics path, while production HTTP serving
uses Unified Server workers, and it computes presentation-oriented aggregate
latency approximations.

Do not route M003 through AdminState or require admin.enabled=true.

## Ownership boundary after Phases 96–101

SynVoid owns:

- source telemetry semantics;
- the supervisor-side aggregation/bridge from worker heartbeats;
- stable external Prometheus names;
- Prometheus gauge/counter classification;
- units;
- worker aggregation rules;
- source refresh cadence and restart/reset semantics;
- loopback exporter lifecycle;
- owner telemetry manifest;
- materialized Eggbench mapping interoperability artifact;
- live proof that exported samples correspond to real worker/CPU-worker state.

Eggbench owns:

- generic Prometheus HTTP collection;
- trial start/stop synchronization and polling;
- bounded exposition parsing;
- subject_* normalized output names;
- per-trial gauge aggregation and counter deltas;
- trial evidence and qualification gates.

No Eggbench Rust dependency enters SynVoid.

## Binding architecture decision

### Supervisor is the exporter owner

The Prometheus listener for this contract belongs to the supervisor/root
composition process because that process owns ProcessManager and therefore has
the authoritative cross-process heartbeat snapshots.

Do not add synvoid-ipc -> root or synvoid-metrics -> synvoid-ipc dependency
cycles. Any aggregation that needs both WorkerMetricsPayload and CpuOffloadStats
stays at the root composition boundary.

The current file src/admin/prometheus_exporter.rs may remain the composition
owner if architecture ownership remains accurate, but the endpoint must not
depend on the admin router or AdminState. If implementation moves it, update
the root ownership ledger rather than creating a second exporter.

### Repair the recorder/exporter lifecycle

When metrics are explicitly enabled:

1. build the Prometheus recorder/exporter against 127.0.0.1:<port>;
2. install the recorder globally exactly once in the supervisor process before
   the supervisor-side bridge emits contract metrics;
3. own the exporter future through SupervisorTaskRegistry rather than an
   untracked tokio::spawn;
4. make shutdown drop/cancel and join the exporter task within the supervisor's
   bounded shutdown contract;
5. make bind/build/recorder-install failures observable and deterministic.

PrometheusBuilder::install() is acceptable only if its detached lifecycle can
still satisfy SynVoid task ownership. The preferred implementation for this
repository is explicit build() + global recorder installation + a registered
exporter future so shutdown ownership is visible.

The exporter crate responds to GET on any request path; the owner contract
should nevertheless publish one canonical scrape URL, recommended:

~~~text
http://127.0.0.1:<metrics-port>/metrics
~~~

### Default-runtime behavior must be reconciled explicitly

MetricsConfig currently defaults enabled=true even though the exporter has not
been wired into production lifecycle. Wiring it will therefore make an
existing documented configuration setting live and may open the loopback port
in default deployments.

Do not hide that behavior change inside qualification work.

Implementation must:

- verify current operator documentation/default config intent;
- add startup/config tests for enabled and disabled modes;
- keep the listener loopback-only;
- define whether ordinary exporter bind failure is non-fatal or startup-fatal;
- require the telemetry-enabled qualification runtime to fail its readiness
  proof when the endpoint cannot bind or expose the contract.

The M003 generated config explicitly selects enabled=true and a caller-provided
port, so qualification never relies on the default port.

## Workstream A — supervisor-side subject telemetry aggregation

Add one bounded aggregation owner at the root supervisor boundary.

It must use:

- ProcessManager::get_all_unified_server_worker_metrics();
- ProcessManager::get_cpu_worker_cpu_offload_stats();
- CPU-worker readiness when deciding whether optional CPU metrics exist.

It must not use ProcessManager::get_worker_metrics() for M003 subject data.

Initial aggregate semantics:

| Owner metric | Kind | Source aggregation |
|---|---|---|
| synvoid_subject_event_loop_lag_ms | gauge | max latest event_loop_lag_ms across Unified Server workers |
| synvoid_subject_request_queue_p95_ms | gauge | max latest request_queue_time_ms.p95_ms across Unified Server workers |
| synvoid_subject_active_connections | gauge | sum latest active_connections across Unified Server workers |
| synvoid_subject_worker_memory_bytes | gauge | sum latest memory_bytes across Unified Server workers |
| synvoid_subject_worker_cpu_percent | gauge | sum latest worker cpu_percent values; never clamp to 100 |
| synvoid_subject_body_buffering_bytes_total | counter | supervisor-lifetime monotonic bridge of worker absolute totals |
| synvoid_subject_offload_submissions_total | counter | supervisor-lifetime monotonic bridge of worker absolute totals |
| synvoid_subject_offload_timeouts_total | counter | supervisor-lifetime monotonic bridge of worker absolute totals |
| synvoid_subject_offload_rejections_total | counter | supervisor-lifetime monotonic bridge of worker absolute totals |
| synvoid_subject_offload_fallbacks_total | counter | supervisor-lifetime monotonic bridge of worker absolute totals |
| synvoid_subject_cpu_worker_rss_bytes | gauge | latest ready CPU-worker worker_rss_bytes; optional in v1 |

Names may be adjusted during implementation only if the owner manifest and
Eggbench mapping are updated together before live qualification. Prefer
underscore-only names so Prometheus name sanitization does not become part of
the compatibility contract.

No worker IDs, site IDs, paths, client addresses, plugin names, attack
families, or other variable-cardinality labels are needed in v1.

## Workstream B — preserve monotonic counters across worker generations

Worker payload counters are absolute per-process counters. Simply setting a
Prometheus counter is impossible and simply summing current worker snapshots
can decrease after a worker restart.

Maintain bounded supervisor bridge state per current worker identity and each
v1 counter:

- first observation contributes the current absolute value;
- normal observation contributes current - previous;
- a lower current value is a generation/reset boundary and contributes current
  as the first value of the new generation;
- removed worker state is retired with a bounded retention policy;
- no negative delta is emitted;
- optionally expose a bounded
  synvoid_subject_worker_metric_resets_total counter so resets remain
  observable.

This yields monotonic supervisor-lifetime counters while preserving work across
worker generations.

Do not fake absent CPU-worker gauges as zero. Omit optional metrics until their
source is available.

## Workstream C — bridge heartbeat snapshots without changing security behavior

Publish/refresh contract gauges and counters when authoritative heartbeat state
changes or on a bounded supervisor refresh path.

Do not:

- change request-path instrumentation merely to make benchmarks prettier;
- lower security limits;
- alter WAF decisions;
- add per-request IPC;
- make the request path synchronously wait for telemetry;
- increase heartbeat frequency solely to improve benchmark resolution unless a
  separately measured decision proves the overhead acceptable.

The contract records the current five-second Unified Server heartbeat cadence.
Eggbench scenarios that expect visible movement must run long enough to
observe at least one source refresh. Counter telemetry is diagnostic until
repeatability proves stronger gating is justified.

## Workstream D — canonical metric registration

Register the v1 metric descriptions/types before first use so Prometheus emits
stable TYPE/HELP metadata where supported.

For every metric freeze:

- exact Prometheus name;
- gauge/counter kind;
- unit;
- source field;
- worker aggregation rule;
- required/optional status;
- source refresh cadence;
- restart/reset behavior.

Do not expose the existing arbitrary process-local metrics corpus as part of
synvoid.eggbench-telemetry.v1. The v1 contract is the bounded inventory above.

## Workstream E — qualification materializer rebase

Extend the existing M002 owner materializer instead of creating a second
SynVoid qualification tool.

Supported interface:

~~~text
cargo xtask eggbench-qualification export \
  --output <dir> \
  --listen-port <port> \
  --origin-port <port> \
  --metrics-port <port> \
  [--configtest] \
  [--configtest-binary <path>]
~~~

check must recognize and verify the telemetry-enabled form.

When --metrics-port is absent:

- preserve the closed M002 v1 export semantics;
- keep metrics disabled in generated config;
- do not emit telemetry artifacts;
- do not change corpus/policy semantics.

When --metrics-port is present:

- reject collision with listen-port and origin-port;
- emit [metrics] enabled=true and the requested metrics port;
- keep [admin] enabled=false;
- keep the listener loopback-only through the runtime contract;
- retain every existing M002 WAF/corpus/minimal-profile constraint.

Phase 99 made the generated comment claiming that the documented [tokio] table
is rejected stale. While touching the materializer, correct that comment or
remove it; do not change Tokio runtime semantics merely for M003.

## Workstream F — owner manifest and Eggbench mapping artifact

Telemetry-enabled export emits two deterministic files.

### telemetry-contract.json

Owner schema:

~~~text
synvoid.eggbench-telemetry.v1
~~~

It records at least:

- schema/contract identifier;
- SynVoid package version;
- exact SynVoid git SHA;
- canonical loopback scrape URL;
- metrics port;
- source refresh/cadence statement;
- ordered owner metric inventory;
- exact Prometheus names;
- kind;
- unit;
- source field;
- owner aggregation rule;
- required/optional status;
- restart/reset semantics;
- mapping artifact path + SHA-256;
- contract digest.

### telemetry-mapping.json

Emit an interoperability mapping matching Eggbench's already-landed
prometheus-http mapping schema v1:

~~~json
{
  "schema_version": 1,
  "source": "prometheus",
  "fields": [
    {
      "output_name": "subject_event_loop_lag_ms",
      "prometheus_name": "synvoid_subject_event_loop_lag_ms",
      "kind": "gauge",
      "unit": "ms",
      "aggregation": "max",
      "required": true
    }
  ]
}
~~~

The complete mapping should cover the initial inventory. Eggbench remains the
semantic owner of subject_* normalized names and trial aggregation; this file
is a versioned interoperability artifact produced for the handoff, not a
SynVoid Rust API.

Use no wildcard/high-cardinality selectors in v1.

## Workstream G — provenance extension

Extend provenance.json only in the telemetry-enabled form with:

- metrics port;
- telemetry contract digest;
- telemetry mapping digest;
- telemetry-enabled generated config digest.

Do not silently change the M002 no-telemetry provenance schema/bytes if the
existing checker treats them as frozen. If additive optional fields would
violate the closed M002 schema, use a telemetry-specific provenance addendum
referenced from telemetry-contract.json instead.

The implementation must decide this from the current materializer's strict
equality/check logic rather than assuming additive JSON is harmless.

## Workstream H — configuration ownership

MetricsConfig remains in synvoid-config.

Do not move it into synvoid-config-model. The latter must retain its Phase 99
dependency/authority budget and remain free of:

- runtime task ownership;
- ProcessManager/IPC;
- metrics recorder/exporter state;
- filesystem/network listeners;
- exporter lifecycle.

If MetricsConfig needs validation such as nonzero port/collision checks, keep
that validation in the runtime configuration owner or the materializer as
appropriate.

## Workstream I — live owner proof

Add or extend the opt-in owner live proof.

It must:

1. materialize telemetry-enabled assets at the exact SynVoid source SHA;
2. build/configtest the real --no-default-features SynVoid binary;
3. start the controlled loopback origin;
4. start real SynVoid with admin disabled and metrics enabled;
5. prove the scrape endpoint is reachable only on loopback;
6. parse telemetry-contract.json and telemetry-mapping.json;
7. scrape a baseline;
8. drive existing benign and body/WAF-relevant qualification traffic long
   enough to cross the documented source refresh cadence;
9. scrape during and after traffic;
10. prove every required owner metric is present, finite, and has the declared
    Prometheus type;
11. prove at least one gauge is plausible under live load;
12. prove at least one contract counter is monotonic;
13. prove optional absent data is omitted rather than emitted as synthetic
    zero;
14. terminate the subject and prove the registered exporter task/listener
    stops.

The live proof must not freeze universal capacity thresholds.

## Workstream J — downstream interoperability proof

After the owner live proof passes, exercise the actual Eggbench
prometheus-http consumer against the emitted mapping.

Required interoperability facts:

- Eggbench accepts telemetry-mapping.json without hand-edited names;
- its private-endpoint policy accepts the loopback URL;
- required metrics parse without duplicate/ambiguous samples;
- declared TYPE agrees with mapping kind;
- gauge aggregation succeeds;
- monotonic counter delta succeeds;
- a renamed/missing required owner metric fails closed;
- Gregg host_* metrics remain a distinct namespace from subject_* target
  telemetry.

No SynVoid IPC parsing or admin scraping is allowed as a fallback.

## Required tests

At minimum add/retain tests for:

1. exporter disabled means no listener/task;
2. enabled listener is loopback only;
3. recorder is installed exactly once and contract metrics reach that recorder;
4. exporter task is registered and bounded on shutdown;
5. Unified Server aggregation uses get_all_unified_server_worker_metrics, not
   the legacy worker list;
6. gauge max/sum semantics;
7. per-worker monotonic counter delta;
8. worker counter reset/generation handling;
9. absent CPU worker does not fabricate zero RSS;
10. telemetry-off materializer compatibility;
11. telemetry-on port collision rejection;
12. deterministic telemetry contract;
13. deterministic Eggbench mapping;
14. manifest names/types/units agree with emitted exposition;
15. provenance/check detects telemetry artifact tampering;
16. configtest succeeds with telemetry enabled on the minimal binary;
17. admin remains disabled;
18. live exporter teardown leaves no listener/task;
19. no new high-cardinality labels enter the v1 inventory;
20. no synvoid-config-model runtime dependency is introduced.

## Routine verification

At minimum:

~~~text
cargo fmt --all -- --check
cargo test -p synvoid-metrics --profile ci
cargo test -p synvoid-ipc --profile ci
cargo test -p xtask --profile ci
cargo xtask test guards
cargo xtask verify
cargo check --no-default-features --profile ci
cargo build --locked --release --no-default-features
~~~

Plus:

- telemetry-enabled materializer export/check/configtest;
- the opt-in live owner proof;
- Eggbench prometheus-http interoperability against the emitted mapping.

Do not add a high-load benchmark to routine CI.

## Documentation

Update current-authority documents as applicable:

- architecture/metrics.md;
- architecture/supervisor_lifecycle.md if task ownership changes;
- architecture/root_dependency_ownership.md if exporter ownership changes;
- docs/PERFORMANCE.md;
- xtask help/output for --metrics-port;
- the M002 qualification closeout only with an additive pointer if needed;
- this plan and plans/roadmap.md on closure.

Document explicitly:

- supervisor/process ownership of the scrape endpoint;
- child-worker source cadence;
- which metrics are bridged from worker heartbeats;
- that v1 is a bounded subject telemetry contract, not a promise that every
  process-local SynVoid metrics:: macro is exported from one endpoint.

## Acceptance criteria

This handoff closes only when:

1. synvoid.eggbench-telemetry.v1 exists as a checked-in/materialized owner
   contract;
2. the real minimal runtime exposes the endpoint with admin disabled;
3. the endpoint is loopback-only;
4. the recorder/exporter lifecycle is real, installed, registered, and
   drainable;
5. Unified Server and CPU-worker source metrics are bridged from supervisor
   heartbeat truth rather than process-local assumptions;
6. stable names/kinds/units/aggregation rules are frozen;
7. the deterministic Eggbench prometheus-http mapping is emitted and bound by
   digest;
8. telemetry-off M002 export remains compatible;
9. telemetry-enabled configtest passes;
10. the owner live proof observes real values under real proxy/WAF traffic;
11. actual Eggbench M003c generic ingestion consumes the emitted mapping;
12. missing/drifted required metrics fail closed downstream;
13. no Eggbench Rust dependency, admin dependency, second load generator, or
    security-semantic change is introduced;
14. routine verification remains green;
15. a proof-bearing closeout records the exact SynVoid and Eggbench revisions.

## Rejection criteria

Reject an implementation that:

- merely calls the current start_prometheus_exporter without installing its
  recorder;
- leaves the exporter in an unowned tokio::spawn;
- assumes supervisor-local metrics macros contain child-worker telemetry;
- uses legacy get_worker_metrics for Unified Server telemetry;
- makes Eggbench parse SynVoid IPC;
- requires authenticated admin routes;
- makes the endpoint public or LAN-bound;
- fabricates zeros for absent worker/CPU-worker sources;
- pushes exporter/runtime authority into synvoid-config-model;
- exports worker/site/request identifiers as variable-cardinality labels;
- changes WAF/security semantics to produce telemetry;
- changes worker heartbeat cadence without measuring and documenting its
  effect;
- adds a SynVoid-side benchmark/load generator;
- closes on a fake Prometheus endpoint without real SynVoid + real Eggbench
  interoperability.

## Handoff and closure

The plan is dependency-ready now.

Eggbench M003a and M003b are closed. M003c's generic Prometheus collector is
implemented at 2742e0eafaaef38899db5978f1721611ce58a7bc and is waiting for
this owner contract plus real live evidence. M003d's independent Eggsec load
slice has also landed but its terminal closure remains downstream-gated.

On SynVoid closure, create a proof-bearing architecture record containing:

- implementation SHA;
- exact package/Cargo.lock identity;
- telemetry contract identifier/digest;
- telemetry mapping digest;
- metric inventory and aggregation/restart semantics;
- source heartbeat cadence;
- generated config/provenance digests;
- minimal binary digest/build command;
- configtest result;
- real owner scrape proof;
- real Eggbench M003c interoperability proof;
- routine verification;
- hosted CI/dependency-security result if required by the then-current SynVoid
  closure convention;
- unresolved findings.

Downstream Eggbench can continue generic collector/profile work independently,
but terminal real-SynVoid M003 telemetry qualification must wait for this
owner-side closure.
