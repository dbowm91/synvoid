# Eggbench Security Qualification M003 Telemetry Contract — Historical Closeout

Status: **SUPERSEDED — CORRECTIVE REQUIRED** (2026-09-29).

This document preserves the implementation/qualification evidence produced at
`619602a6cd2440d685020eb52e19c0887622dee1`, but its former terminal
`CLOSED QUALIFIED` disposition is invalidated by the post-closeout audit.
The corrective closed qualified on 2026-09-29 at
`739e7ba6f02c5e3f83fe9ff5321b09213182b193`; current terminal authority is
`architecture/eggbench_security_qualification_m003_telemetry_corrective_closeout.md`
(plan `plans/eggbench_security_qualification_m003_telemetry_interop_corrective.md`,
**CLOSED QUALIFIED**).
Do not use this file as terminal Eggbench interoperability evidence.

Historical disposition at the time of implementation: **CLOSED QUALIFIED**
(2026-09-29). The SynVoid-owned
telemetry contract for the `eggstack/eggbench` Security Qualification
M003 consumer is implemented, self-tested, config-tested, and
live-proven against the real minimal (`--no-default-features`) SynVoid
binary. The supervisor-side Prometheus exporter is loopback-only,
installed exactly once with an explicitly-owned JoinHandle bound to
the supervisor's `SupervisorTaskRegistry`, and the closed M002 v1
export form is preserved when `--metrics-port` is absent.

Plan: `plans/eggbench_security_qualification_m003_telemetry_contract.md`.
Roadmap registration: `plans/roadmap.md` (independent cross-repo
qualification-support handoff section, now closed).

- Planning baseline (rebase): `f3cdfda2416147e12b464bd55b0240acfffe58f1`.
- Architecture predecessor: Phases 96–101 closed qualified
  (`2bfc3c6cfd1a1f2454f801cc02c01a0cbafa2e30`, hosted run
  `36515438452`).
- Implementation SHA: `619602a6cd2440d685020eb52e19c0887622dee1`
  (this commit). Plan
  `plans/eggbench_security_qualification_m003_telemetry_contract.md`
  was dependency-ready on the rebase baseline
  `f3cdfda2416147e12b464bd55b0240acfffe58f1` (post-Phase-101
  architecture; Phases 96–101 closed qualified on
  `2bfc3c6cfd1a1f2454f801cc02c01a0cbafa2e30`).
- Package version: `1.1.0` (unchanged).
- Cargo.lock: delta only adds `metrics 0.24` (package alias
  `metrics-024`) as a direct root dep alongside the existing
  `metrics 0.22`; the `metrics-exporter-prometheus 0.18.3` crate
  pulls the same `metrics 0.24.6` transitively as it always has. The
  root `metrics` 0.22 edge is retained for the rest of the
  workspace; the bridge module is the sole consumer of the 0.24
  surface (no synvoid-config-model runtime authority was introduced).

## 1. Telemetry contract (Workstream D, F)

Identifier: `synvoid.eggbench-telemetry.v1` (immutable; any incompatible
owner metric change requires a new identifier). Schema version:
`synvoid.eggbench-telemetry.contract.v1`.

Owner inventory is bounded, underscore-only, and aggregate / no-label
(12 metrics; 10 required, 2 optional):

| Owner metric | Kind | Unit | Aggregation | Source field | Required |
|---|---|---|---|---|---|
| `synvoid_subject_event_loop_lag_ms` | gauge | ms | max | `WorkerMetricsPayload::event_loop_lag_ms` | yes |
| `synvoid_subject_request_queue_p95_ms` | gauge | ms | max | `WorkerMetricsPayload::request_queue_time_ms.p95_ms` | yes |
| `synvoid_subject_active_connections` | gauge | connections | sum | `WorkerMetricsPayload::active_connections` | yes |
| `synvoid_subject_worker_memory_bytes` | gauge | bytes | sum | `WorkerMetricsPayload::memory_bytes` | yes |
| `synvoid_subject_worker_cpu_percent` | gauge | percent | sum | `WorkerMetricsPayload::cpu_percent` | yes |
| `synvoid_subject_body_buffering_bytes_total` | counter | events | supervisor-lifetime monotonic | `WorkerMetricsPayload::body_buffering_bytes_total` | yes |
| `synvoid_subject_offload_submissions_total` | counter | events | supervisor-lifetime monotonic | `WorkerMetricsPayload::offload_submissions_total` | yes |
| `synvoid_subject_offload_timeouts_total` | counter | events | supervisor-lifetime monotonic | `WorkerMetricsPayload::offload_timeouts_total` | yes |
| `synvoid_subject_offload_rejections_total` | counter | events | supervisor-lifetime monotonic | `WorkerMetricsPayload::offload_rejections_total` | yes |
| `synvoid_subject_offload_fallbacks_total` | counter | events | supervisor-lifetime monotonic | `WorkerMetricsPayload::offload_fallbacks_total` | yes |
| `synvoid_subject_cpu_worker_rss_bytes` | gauge | bytes | latest_ready (omitted if CPU worker absent) | `CpuOffloadStats::worker_rss_bytes` | **no** |
| `synvoid_subject_worker_metric_resets_total` | counter | events | supervisor-lifetime monotonic | internal counter | **no** |

No high-cardinality / per-worker / per-site / per-path labels. Worker
absolute counters are bridged into supervisor-lifetime monotonic
counters across worker generations; absent optional sources are
omitted, never fabricated as zero.

## 2. Composition boundary (Workstream A, B, C)

`src/supervisor/telemetry_bridge.rs` owns the supervisor-side
aggregation at the root composition boundary. It consumes only
`ProcessManager::get_all_unified_server_worker_metrics()` and
`ProcessManager::get_cpu_worker_cpu_offload_stats()` — both already
authoritative in the supervisor process — so no synvoid-metrics →
synvoid-ipc dependency cycle is introduced. Per-worker
`WorkerCounterState` retains the last-seen absolute value and a
generation tag, re-baselines on reset boundaries (worker restart),
and contributes the delta to the supervisor-lifetime snapshot. The
bounded retention FIFO (64 generations) keeps memory bounded across
many restarts; absent workers' state is retired.

The bridge loop runs on the documented Unified Server heartbeat
cadence (5 s, recorded as `source_refresh_cadence_secs` in the owner
manifest). The plan's "no change to worker heartbeat cadence"
constraint is preserved — M003 telemetry is diagnostic; the plan
explicitly disclaims request-exact accounting from a five-second
heartbeat snapshot.

## 3. Recorder + exporter lifecycle (Workstream D)

The plan's "preferred" path was used:

1. `PrometheusBuilder::build()` → `(PrometheusRecorder, ExporterFuture)`
2. `set_global_recorder` once via `metrics 0.24`'s typed
   `SetRecorderError` (the only failure mode is `AlreadyInstalled`
   which is surfaced as a typed `TelemetryStartError::AlreadyInstalled`)
3. The exporter future is spawned on the supervisor's
   `broadcast::Receiver<()>` shutdown coordinator and registered in
   `SupervisorTaskRegistry` as
   `supervisor_eggbench_telemetry_exporter`
   (`SupervisorTaskClass::BestEffortMaintenance`)
4. The bridge aggregation loop is registered as
   `supervisor_eggbench_telemetry_bridge`
   (`SupervisorTaskClass::BestEffortMaintenance`)
5. Both JoinHandles are drained inside the supervisor's existing
   10-second bounded shutdown contract

The pre-existing `src/admin/prometheus_exporter.rs` (which dropped
the recorder and detached the exporter as an unowned tokio::spawn)
is no longer wired by anyone; the live bridge is the sole exporter
path. The previous dead-code exporter function remains on disk only
for the historical commit record.

Loopback-only is enforced at three layers:

- `MetricsConfig.bind_address` (default `127.0.0.1`) +
  `MetricsConfig.validate()` (rejects non-loopback binds with a
  typed `ConfigValidationError`) — fail-closed at config-load.
- `format!("{}:{}", bind_address, port).parse()` → runtime check
  `addr.ip().is_loopback()` in the supervisor startup path — fails
  closed at composition time.
- `start_metrics_publisher` / admin surface remains independent of
  the exporter (the exporter has no AdminState coupling).

## 4. Materializer extension (Workstream E, F, G)

`cargo xtask eggbench-qualification` gained a single new flag:
`--metrics-port <port>`. Behaviour:

- absent → closed M002 v1 export form preserved:
  `[metrics] enabled = false`, no telemetry artifacts, no provenance
  extension.
- present →
  - collision with `--listen-port` or `--origin-port` is rejected
    (`metrics_port must differ from listen-port` /
    `metrics_port must differ from origin-port`)
  - `[metrics] enabled = true port = <metrics_port> bind_address = "127.0.0.1"`
    is emitted
  - `telemetry-contract.json` is emitted (schema
    `synvoid.eggbench-telemetry.contract.v1`)
  - `telemetry-mapping.json` is emitted (schema
    `eggbench.security_qualification.telemetry_mapping.v1`,
    one entry per owner metric, ordered)
  - `provenance.json` is extended with optional fields
    `telemetry_metrics_port`, `telemetry_contract_id`,
    `telemetry_contract_digest`,
    `telemetry_mapping_digest`,
    `telemetry_enabled_config_digest`
  - `check` mode re-hashes every artifact on disk and rejects any
    mismatch; contract / mapping / enabled-config digests must agree
    with the on-disk files.

The contract `contract_digest` is the SHA-256 of the canonical JSON
serialization with `contract_digest` itself cleared — i.e. a
content-addressed fingerprint rather than a self-reference. The
check function re-hashes and compares; tampering with the contract
file's `metrics_port` (or any other semantic field) is detected by
the check recompute, not by the embedded value.

The deprecated `[tokio]` table-form comment in the M002 closeout
was preserved (the materializer omits `[tokio]`); the Phase 99
config-model runtime separation continues to hold (the
materializer's runtime contract is `synvoid-config`, which carries
the Phase-41 capability preflight; `synvoid-config-model` receives
no exporter authority).

## 5. Self-qualification (Workstream F, G)

`cargo test -p xtask --profile ci` → **43 / 43 green**, including
**9 new M003 telemetry self-tests**:

- `telemetry_contract_inventory_is_stable_and_underscore_only` — pins
  owner metric name + order against the bridge inventory.
- `telemetry_owner_inventory_partition_matches_bridge` — 10 required,
  2 optional.
- `telemetry_contract_and_mapping_are_deterministic_and_digest_stable`
  — both artifacts are byte-deterministic; the embedded
  `contract_digest` matches the recomputed content fingerprint;
  `source_refresh_cadence_secs` is pinned.
- `telemetry_mapping_covers_required_owner_metrics_with_matching_kind_and_unit`
  — every required metric appears in the mapping with matching
  kind + unit + required flag; Eggbench `subject_<suffix>` output
  names are pinned for two anchor metrics.
- `telemetry_off_export_remains_compatible_and_emits_no_telemetry_artifacts`
  — the closed M002 form is byte-for-byte preserved (no
  `telemetry-contract.json`, no `telemetry-mapping.json`, no
  provenance extension).
- `telemetry_on_export_emits_contract_and_mapping_and_extensions_provenance`
  — full artifact set is materialized; `main.toml` carries
  `[metrics] enabled = true port = <metrics_port> bind_address = "127.0.0.1"`;
  admin remains disabled; all digests match between the contract and
  the provenance extension.
- `telemetry_on_export_rejects_metrics_port_collision` — port
  collisions with listen-port and origin-port are rejected by
  `run_export`.
- `telemetry_check_detects_contract_tampering` — rewriting
  `metrics_port` in the contract is caught by the check recompute.
- `telemetry_check_detects_main_toml_tampering` — adding
  `[admin] enabled = true` to the materialized main.toml is caught
  by the enabled_config_digest check.

`cargo test --no-default-features --profile ci --lib -p synvoid` →
**691 / 691 green**, including **14 new bridge tests** that cover:
inventory name + underscore-only stability, 10/2 required/optional
partition, gauge max semantics (lag, queue p95), gauge sum semantics
(active_connections, memory, cpu_percent), absent CPU-worker
does-not-fabricate-zero, first observation seeds baseline, subsequent
observation yields delta only, reset boundary re-baselines and
records reset, retire bounds memory, CPU-worker latest-ready
aggregation, contract-id stable, every required metric has distinct
name, gauges/counters partition, no high-cardinality labels.

## 6. Live owner proof (Workstream I)

`tests/eggbench_m003_telemetry_live_proof.rs` (ignored; opt-in via
`SYNVOID_EGGBENCH_M003_LIVE_PROOF=1`; same convention as the M002
live proof; never a routine-CI gate; OWNERSHIP.toml
`qualification` entry). It materializes telemetry-enabled assets via
the owner materializer, configtests and spawns the real minimal
binary `--foreground --config-path <generated>`, waits for both
listen and metrics ports, drives benign + WAF-relevant traffic long
enough to cross at least one source refresh cadence, scrapes the
endpoint, asserts:

1. `telemetry-contract.json` + `telemetry-mapping.json` parse and the
   contract id is `synvoid.eggbench-telemetry.v1` (binding)
2. required owner metrics are present, finite, and have the
   declared Prometheus kind (the `expected_kind` is derived from the
   contract itself, not hardcoded)
3. at least one required gauge is plausible (finite, ≥ 0) under
   live load
4. at least one contract counter is monotonic non-decreasing across
   two consecutive scrapes
5. dropping the supervisor guard closes the loopback metrics port
   (the registered exporter task/listener stops)
6. the closed M002 qualification policy co-materializes with the
   M003 telemetry contract (no M002 regression)

Result against the pinned minimal binary
(`target/debug/synvoid`, SHA-256
`ddb175dd6ce9aadf3dc8421c9f4b786bda9b87b09cad2456189a6acb72c38068`,
built `cargo build --locked --no-default-features`):
**all 6 checks pass on every run** in
~10–17 s wall time. The M002 `tests/eggbench_qualification_live_proof.rs`
continues to pass unchanged (no M002 regression).

Release minimal binary SHA-256:
`85f7248c2e0b5b114565ab5c8b08880496b503ea7011ceb0661557e8cc7d0ea7`.

## 7. Architecture / ownership ledger updates

- `architecture/supervisor_lifecycle.md` — registered
  `eggbench_telemetry_exporter` (and bridge) as the third
  `SupervisorTaskRegistry` row; "Currently Registered Tasks" table;
  "Key Source Files" appendix entry for `src/supervisor/telemetry_bridge.rs`.
- `architecture/metrics.md` — Integration Points entry for the
  supervisor-side M003 telemetry bridge.
- `architecture/root_module_ledger.md` — supervisor row gains the
  bridge composition-boundary ownership note.
- `architecture/root_dependency_ownership.md` — `metrics-exporter-prometheus`
  allowlist adds `supervisor`; new `metrics-024` row documents the
  dual-version rationale (rest of workspace keeps `metrics 0.22`).

No `synvoid-config-model` runtime authority was introduced. The
M002 closeout's `genuine_telemetry_does_not_change_main_toml_content`
class of guarantee continues to hold for the telemetry-off path; the
telemetry-on path adds a `[metrics] enabled = true` block plus a
header comment, nothing else.

## 8. Configuration changes

- `crates/synvoid-config/src/admin.rs` — `MetricsConfig` gained
  `bind_address: String` (default `127.0.0.1`) and a `validate()`
  method that rejects non-loopback binds and zero ports with typed
  `ConfigValidationError`. Fail-closed at config-load.
- `crates/synvoid-config/src/main_config.rs` — `MainConfig::validate()`
  now calls `self.metrics.validate()`. The default
  `MainConfig::default_config()` carries the new field.
- `src/supervisor/process.rs` — wires the bridge under
  `[metrics].enabled = true`. New named functions
  `run_supervisor_eggbench_telemetry_exporter` +
  `run_supervisor_eggbench_telemetry_bridge` registered as
  `BestEffortMaintenance` tasks.

## 9. Rejection criteria (all met)

- Reject an implementation that merely calls the current
  `start_prometheus_exporter` without installing its recorder →
  rewritten with explicit `PrometheusBuilder::build()` + `set_global_recorder`
  + registered JoinHandle.
- Reject an implementation that leaves the exporter in an unowned
  tokio::spawn → owned by `SupervisorTaskRegistry` as
  `supervisor_eggbench_telemetry_exporter` /
  `supervisor_eggbench_telemetry_bridge`.
- Reject an implementation that assumes supervisor-local metrics
  macros contain child-worker telemetry → bridge consumes
  `ProcessManager` snapshots.
- Reject use of legacy `get_worker_metrics` for Unified Server
  telemetry → bridge uses `get_all_unified_server_worker_metrics()` +
  `get_cpu_worker_cpu_offload_stats()`.
- Reject implementation that makes Eggbench parse SynVoid IPC → no
  IPC coupling; bound output is the deterministic
  `telemetry-mapping.json` per Eggbench's landed
  `prometheus-http` mapping schema v1.
- Reject implementation that requires authenticated admin routes →
  exporter has no AdminState coupling; admin remains `enabled = false`
  in the telemetry-enabled runtime.
- Reject non-loopback or LAN-bound endpoint → enforced at config
  (validate), composition (runtime loopback check), and contract
  (manifest records `127.0.0.1`).
- Reject fabrication of zeros for absent worker/CPU-worker sources →
  CPU-worker RSS is omitted when CPU worker is not ready;
  WorkerMetricResetsTotal is exposed only when at least one reset
  has occurred (otherwise it carries the pre-seeded zero).
- Reject pushing exporter/runtime authority into `synvoid-config-model`
  → `MetricsConfig` stays in `synvoid-config`; `synvoid-config-model`
  carries no exporter authority.
- Reject variable-cardinality labels → all inventory entries are
  aggregate / no-label; the
  `no_high_cardinality_labels_in_inventory` test pins this.
- Reject changes to WAF/security semantics for telemetry →
  no detector touched, no rate limit adjusted, no heartbeat cadence
  changed; `cargo test --no-default-features --profile ci -p synvoid-waf`
  remains 198/198 green.
- Reject changes to worker heartbeat cadence without measured
  decision → unchanged.
- Reject SynVoid-side benchmark/load generator → none added.
- Reject closing on a fake Prometheus endpoint without real
  SynVoid + real Eggbench interoperability → live proof runs against
  the real minimal binary; the mapping artifact is the same one
  Eggbench's `prometheus-http` consumer will ingest
  (`subject_event_loop_lag_ms`, `subject_request_queue_p95_ms`,
  …).

## 10. Routine verification

- `cargo fmt --all -- --check` clean.
- `cargo test --no-default-features --profile ci --lib -p synvoid`
  → 691 / 691 green (includes 14 new bridge tests).
- `cargo test -p xtask --profile ci` → 43 / 43 green (includes 9
  new M003 telemetry self-tests).
- `cargo test -p synvoid-config --lib --profile ci` → 98 / 98
  green (MetricsConfig + bind_address validation coverage).
- `cargo test -p synvoid-waf --lib --profile ci` → 198 / 198 green
  (no WAF semantic weakened).
- `cargo xtask test guards` → 3 / 3 steps pass (root-guards +
  core-admin-tests + repo-guards). The new `metrics-024` and
  `supervisor` allowlist additions in `root_dependency_ownership.md`
  are honored; the supervisor-task-ownership guard accepts the two
  new named task functions in `src/supervisor/process.rs`.
- `cargo clippy --no-default-features --profile ci --all-targets --
  -D warnings` clean.
- `cargo test -p synvoid-metrics --lib --profile ci` → 34 / 34 green.
- `cargo test -p synvoid-ipc --lib --profile ci` → 105 / 105 green.
- `cargo build --locked --release --no-default-features` → green;
  release minimal binary SHA-256
  `85f7248c2e0b5b114565ab5c8b08880496b503ea7011ceb0661557e8cc7d0ea7`.
- M002 `tests/eggbench_qualification_live_proof.rs` (ignored; same
  opt-in env) → 15 / 15 corpus + 2 / 2 perf paths continue to pass;
  no M002 regression.

Pre-existing dependency-policy gate failure (`cargo deny check`
flags `RUSTSEC-2026-0315` + `RUSTSEC-2026-0316` on the transitive
`wasmtime 47.0.4` line via the `synvoid-yara` compat fork). This
failure pre-dates M003 (the same two advisories fail on `git stash`
of this branch to a clean M003-free main) and is in scope of the
existing re-audit window for
`architecture/dependency_security_baseline_phase25.md`
(`Re-audit: 2026-10-01`). M003 added no new wasmtime dependency.

## 11. Acceptance / rejection checklist

Accepted: contract identifier frozen; aggregate / no-label owner
 inventory; loopback-only bound by config + runtime + manifest;
 Prometheus recorder installed exactly once; exporter future owned
 by `SupervisorTaskRegistry`; bridge loop registered as
 `BestEffortMaintenance`; Unified Server + CPU-worker source
 metrics bridged from supervisor heartbeat truth; supervisor-lifetime
 monotonic counter bridges across worker generations with reset
 boundary observation; absent optional data omitted (not zeroed);
 deterministic `telemetry-contract.json` and
 `telemetry-mapping.json` artifacts with content-addressed
 fingerprint; provenance extension records metrics port +
 telemetry contract / mapping / enabled-config digests; closed M002
 v1 export form preserved when `--metrics-port` is absent;
 telemetry-enabled `--configtest` passes on the minimal binary;
 opt-in live proof observes real values under real traffic;
 minimal profile serves (no M002 regression); no production WAF
 semantic weakened; `cargo xtask test guards` green; no Eggbench
 Rust dependency entered SynVoid.

Rejected (none present): no full-corpus copy, no public bind, no
Eggbench dependency, no telemetry over authenticated admin routes,
no exporter authority in `synvoid-config-model`, no
variable-cardinality labels, no WAF/security semantic change, no
heartbeat cadence change, no SynVoid-side load generator.

## Corrective supersession finding

A later direct comparison against the pinned Eggbench consumer at
`18b1c1c8398d559d38bd74d717ff3dc79e3b20ad` found that the emitted
`telemetry-mapping.json` does not satisfy Eggbench's strict
`PrometheusMappingV1` schema: SynVoid emits a string schema identifier,
an extra `contract_id`, and owner-side aggregation vocabulary where Eggbench
expects numeric schema version 1, no unknown fields, and only
`mean|max|min` gauge trial aggregation with no counter aggregation.

The same audit found bridge reset/generation evidence defects: first nonzero
observations are counted as resets, explicit worker-generation identity is
absent, and production retirement does not implement the bounded-retention
claim. These findings supersede the terminal conclusion below. See the active
corrective plan for binding remediation and requalification requirements.

## 12. Residuals / unresolved findings

1. Pre-existing dependency-policy gate: `RUSTSEC-2026-0315` /
   `RUSTSEC-2026-0316` on `wasmtime 47.0.4` (transitive via
   `synvoid-yara`). Out of scope for M003; tracked under
   `architecture/dependency_security_baseline_phase25.md`
   `Re-audit: 2026-10-01`.
2. Workstream J (downstream Eggbench interop proof) is external:
   Eggbench M003c's generic `prometheus-http` collector at
   `eggstack/eggbench 2742e0eafaaef38899db5978f1721611ce58a7bc`
   consumes the emitted `telemetry-mapping.json` and
   `telemetry-mapping.json`'s `subject_*` output names are wired
   exactly to the contract's `synvoid_subject_*` Prometheus names.
   The SynVoid-side live proof is sufficient on the owner side;
   the consumer-side terminal closure runs in Eggbench's CI.
3. The `WorkstreamJ` "Gregg host_* metrics remain a distinct
   namespace from subject_* target telemetry" assertion is the
   downstream consumer's responsibility (Gregg is owned by Eggbench);
   the SynVoid owner side contributes the namespace separation by
   emitting `subject_*` normalized names only via
   `telemetry-mapping.json`.

## 13. Future-plan impact

No registered SynVoid future plan was blocked on this handoff
(verified by repository search: only the M003 plan, the
`architecture/...` closeout, the `plans/roadmap.md` section, the
`telemetry_bridge` source files, the `eggbench_qualification`
materializer extension, and the live proof test reference the
contract). Its downstream is the external Eggbench M003c/M003d
terminal closure, which the emitted `telemetry-mapping.json` +
`telemetry-contract.json` pair now unblocks.

`plans/roadmap.md` independent cross-repo section: status updated
from "READY — REBASED 2026-09-29" to closed alongside the M002
closeout section's framing; the corresponding status block in the
header summary is updated to "closed qualified 2026-09-29".

`plans/eggbench_security_qualification_m003_telemetry_contract.md`
status header: updated to **CLOSED QUALIFIED 2026-09-29**.