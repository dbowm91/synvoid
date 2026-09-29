# Eggbench Security Qualification M003 Telemetry Interoperability Corrective — Closeout

Status: **CLOSED QUALIFIED** (2026-09-29).

This document is the sole current terminal authority for the SynVoid-owned
Eggbench Security Qualification M003 telemetry contract. It supersedes the
qualification claim in
`architecture/eggbench_security_qualification_m003_telemetry_closeout.md`
(which is retained as historical implementation evidence at
`619602a6cd2440d685020eb52e19c0887622dee1` but is not terminal).

Plan: `plans/eggbench_security_qualification_m003_telemetry_interop_corrective.md`
(status **CLOSED QUALIFIED** on closure).

Parent handoff: `plans/eggbench_security_qualification_m003_telemetry_contract.md`
(status restored to **CLOSED QUALIFIED**; its v1 contract identifier is
withdrawn, see §1).

Roadmap: `plans/roadmap.md` (Independent Cross-Repo Handoff: Eggbench
Security Qualification M003 Telemetry — **CLOSED QUALIFIED**).

- Corrective baseline: `c0f121be771456ace2c7eaa1b26fb9f2fe3eb95f`.
- Implementation SHA: `739e7ba6f02c5e3f83fe9ff5321b09213182b193` (this corrective;
  proof-bearing; see §10 for how the placeholder is resolved at commit).
- Package version: `1.1.0` (unchanged).
- Cargo.lock: no new dependencies. No Eggbench Rust dependency entered
  SynVoid (production, dev, or workspace). The interop proof built an
  out-of-tree crate in `/tmp` against an Eggbench checkout; nothing from
  that crate enters this repository.

## 1. Corrected owner contract (Workstreams A, D)

Identifier: `synvoid.eggbench-telemetry.v2` (immutable; any incompatible
owner metric change requires a new identifier). Owner schema:
`synvoid.eggbench-telemetry.contract.v2`.

v1 (`synvoid.eggbench-telemetry.v1`) is **withdrawn/unqualified**. It is not
a runtime-selectable compatibility mode: it never satisfied its declared
Eggbench interoperability acceptance gate. Its implementation commit and
historical closeout remain in Git history.

v2 preserves all twelve v1 Prometheus sample names verbatim to reduce
downstream churn. What changed is semantics, not names:

| Owner metric | Kind | Unit (v2) | Source aggregation (v2) | Trial aggregation (v2 mapping) | Required |
|---|---|---|---|---|---|
| `synvoid_subject_event_loop_lag_ms` | gauge | ms | max | max | yes |
| `synvoid_subject_request_queue_p95_ms` | gauge | ms | max | max | yes |
| `synvoid_subject_active_connections` | gauge | connections | sum | max | yes |
| `synvoid_subject_worker_memory_bytes` | gauge | bytes | sum | max | yes |
| `synvoid_subject_worker_cpu_percent` | gauge | percent | sum | mean | yes |
| `synvoid_subject_body_buffering_bytes_total` | counter | **bytes** (was `events`) | supervisor_lifetime_monotonic_bridge | none | yes |
| `synvoid_subject_offload_submissions_total` | counter | **count** (was `events`) | supervisor_lifetime_monotonic_bridge | none | yes |
| `synvoid_subject_offload_timeouts_total` | counter | **count** (was `events`) | supervisor_lifetime_monotonic_bridge | none | yes |
| `synvoid_subject_offload_rejections_total` | counter | **count** (was `events`) | supervisor_lifetime_monotonic_bridge | none | yes |
| `synvoid_subject_offload_fallbacks_total` | counter | **count** (was `events`) | supervisor_lifetime_monotonic_bridge | none | yes |
| `synvoid_subject_cpu_worker_rss_bytes` | gauge | bytes | latest_ready (omitted if CPU worker absent) | max | **no** |
| `synvoid_subject_worker_metric_resets_total` | counter | **count** (was `events`) | supervisor_lifetime_monotonic_bridge | none | **no** |

Owner/source aggregation (supervisor across worker heartbeat snapshots at
one instant) and Eggbench trial aggregation (Eggbench across repeated
scrapes) are now distinct concepts in code, manifest, mapping, and tests.
The owner manifest field is named `source_aggregation`; owner-side `sum` /
`supervisor_lifetime_monotonic_bridge` / `latest_ready` vocabulary never
appears in `telemetry-mapping.json`.

`worker_metric_resets_total` v2 meaning (documented in
`src/supervisor/telemetry_bridge.rs`): counts worker
generation-boundary plus unexpected same-generation decrease events,
exactly once per worker observation containing such a boundary — never
once per counter, never for first observations. The v1 sample name is
retained; the v1 contract ID is not, so no semantic meaning was silently
changed under a retained identifier.

No high-cardinality / per-worker / per-site / per-path labels. Source
refresh cadence remains the documented five-second Unified Server
heartbeat cadence (`source_refresh_cadence_secs = 5`); the plan's
no-heartbeat-change constraint is preserved.

## 2. Eggbench-compatible mapping (Workstream A)

`telemetry-mapping.json` is now byte-identical in shape to pinned Eggbench
`PrometheusMappingV1` (`eggstack/eggbench@18b1c1c...`,
`crates/eggbench-drivers/src/prometheus_http.rs` at `2742e0e...`):

- numeric `schema_version: 1`;
- `source: "prometheus"`;
- no top-level `contract_id`, no owner metadata, no provenance;
- `#[serde(deny_unknown_fields)]`-clean on both sides (local DTO carries
  the same attribute so producer tests fail on unsupported keys);
- gauge `aggregation` exactly `mean|max|min`; counters carry no
  `aggregation` key (omitted, which Eggbench parses as `None`);
- no `labels` in v2 (omitted; Eggbench defaults to empty);
- every `output_name` begins with `subject_`.

Binding to the owner contract is by SHA-256 recorded in
`telemetry-contract.json` (`mapping_sha256`) and `provenance.json`
(`telemetry_mapping_digest`), not by inline owner metadata.

Deterministic mapping SHA-256 (git-independent, stable across commits):
`622f6a13c4353cc7465cce39a57ed86fa0db2fe4114258e6f06226c1748d2d99`.

## 3. Explicit worker-generation truth (Workstream B)

`UnifiedServerWorkerProcess` carries `generation: u64` (never zero, never
PID-derived). `ProcessManager` owns the authoritative
`unified_server_worker_generations` map:

- first spawn for a worker ID observes generation 1;
- every same-ID replacement (threadpool-resize respawn and failure
  respawn both funnel through `spawn_unified_server_worker_with_id`)
  advances monotonically (saturating);
- the map is retained across `remove_unified_server_worker`, so a removed
  ID that is later re-added is a new generation, never a reset to zero;
- no wire/protocol change: generation is supervisor-local state.

New narrow getter `get_all_unified_server_worker_metrics_with_generation()`
returns `UnifiedServerWorkerTelemetrySnapshot { worker_id, generation,
metrics }` sorted by worker ID. The legacy
`get_all_unified_server_worker_metrics()` remains for compatibility; the
telemetry bridge uses the generation-aware getter. No reverse root
dependency enters `synvoid-ipc`.

Tests (in `crates/synvoid-ipc/src/manager.rs`): initial spawn is 1 and not
PID-derived; same-ID resize restart advances; same-ID failure restart
advances; 16 consecutive advances are monotonic and never zero with
independent per-ID generations; explicit removal retains generation so
re-add continues at 3, not 1.

## 4. Correct monotonic bridge/reset semantics (Workstream C)

`BridgeState` was rewritten around an explicit typed observation
vocabulary (`First` / `Delta` / `GenerationReset` / `CounterReset` /
`Unchanged`):

1. first observation seeds supervisor-lifetime cumulative truth with the
   current absolute value and does **not** increment
   `worker_metric_resets_total`;
2. same-generation increase contributes `current - previous`;
3. explicit generation change re-baselines all bridged counters and
   contributes the new absolute values — detected even when the new
   absolute exceeds the old value (magnitude inference alone would miss
   this);
4. generation change increments the boundary counter exactly once per
   worker transition, not once per bridged counter;
5. unexpected same-generation decrease re-baselines without a negative
   delta and counts once per worker observation;
6. unchanged counters contribute zero;
7. all arithmetic is saturating.

The rewrite also fixed a latent liveness defect: cumulative
supervisor-lifetime totals now live in `BridgeState::cumulative` and the
snapshot publishes them via absolute counter semantics, so exposition
never decreases between polls (the previous loop published per-poll
deltas as absolutes).

Gauge aggregation semantics are unchanged (max lag/queue-p95, sum
connections/memory/cpu, latest-ready CPU RSS, absent CPU worker omitted
rather than zeroed).

## 5. Real production pruning (Workstream D)

Every bridge refresh computes the live worker-ID set from the
authoritative `ProcessManager` snapshot and calls
`BridgeState::prune_to_live`, so retained bridge state is bounded by live
worker state with no historical FIFO. The arbitrary 64-entry retired
generation FIFO is removed. `retire(id)` remains as a thin single-ID
helper for tests; production uses `prune_to_live`.

Tests: dead worker state is pruned in the production update path;
repeated remove/re-add over ten generations stays at exactly one retained
entry with nine boundaries counted (first is not a reset).

## 6. Materializer documentation cleanup (Workstream G)

The generated-config `[tokio]` comment now matches the post-Phase-99
implementation: `TokioConfig` accepts both the scalar form and the
documented legacy `[tokio]` table form; omission yields
`available_parallelism()`; the materializer omits the section by choice.
No Tokio scheduler/runtime semantics changed.

## 7. Actual Eggbench interoperability proof (Workstream E, terminal gate)

Executed against the exact materialized `telemetry-mapping.json` bytes and
a real minimal (`--no-default-features`) SynVoid endpoint, using the real
pinned Eggbench code (out-of-tree proof crate
`/tmp/m003-interop-proof`, depending on
`/tmp/eggbench-pin/crates/eggbench-drivers` at pinned Eggbench HEAD
`18b1c1c8398d559d38bd74d717ff3dc79e3b20ad`; generic collector
implementation `2742e0eafaaef38899db5978f1721611ce58a7bc` is an ancestor
of that HEAD on the same line). No Eggbench dependency was added to
SynVoid.

All 16 checks passed (live run 2026-09-29):

- mapping digest is the exact materialized mapping digest
  (`622f6a13...`);
- real `parse_mapping()` accepts the exact file with no translation;
- real `validate_mapping()` succeeds;
- numeric `schema_version == 1`; no `contract_id` key;
- real `validate_private_endpoint()` accepts the loopback scrape URL;
- real `parse_exposition()` succeeds against the live scrape (11 samples);
- required gauge (`subject_event_loop_lag_ms`) resolves;
- required counter (`subject_body_buffering_bytes_total`) resolves;
  optional CPU RSS is absent and correctly omitted (CPU worker not present
  in the minimal runtime);
- real `PrometheusHttpCollector::new()` succeeds;
- real collector `preflight()` succeeds;
- real collector `start_trial()` succeeds;
- gauge trial aggregation succeeds (Maximum);
- counter delta succeeds (Direct);
- renamed required sample fails closed (required output absent);
- TYPE mismatch fails closed (`sample_type_mismatch`);
- exporter task/listener stops on supervisor shutdown (metrics port
  closed after shutdown).

Owner live proof (`tests/eggbench_m003_telemetry_live_proof.rs`, opt-in
`SYNVOID_EGGBENCH_M003_LIVE_PROOF=1`): all checks pass against the real
minimal binary (~16 s): contract parses with ID
`synvoid.eggbench-telemetry.v2`, required metrics present/finite/correct
TYPE, gauge plausible, counter monotonic across scrapes, exporter stops
with supervisor, M002 policy co-materializes.

M002 telemetry-off behavior is unchanged
(`tests/eggbench_qualification_live_proof.rs` passes; `--metrics-port`
absent emits no telemetry artifacts and byte-preserves the closed M002
form; `--configtest` passes on the minimal binary with telemetry enabled;
loopback-only and admin-disabled guarantees intact).

## 8. Self-qualification

- `cargo test -p xtask --profile ci` → 45/45 green, including new v2
  tests: exact Eggbench-v1 compatibility (numeric schema, no contract_id,
  no owner vocabulary, strict re-parse), owner-manifest
  `source_aggregation` distinction with corrected bytes/count units,
  deterministic contract/mapping with digest stability, required-metric
  kind/unit/trial-aggregation/labels parity.
- `cargo test --no-default-features --profile ci --lib -p synvoid` →
  698/698 green, including rewritten bridge tests (first-nonzero-not-reset,
  seeding, exact delta, unchanged-zero, generation-lower, generation-higher,
  once-per-transition, no-negative-delta, production pruning, bounded
  re-add, gauge preservation, v2 contract ID/schema, bytes/count units,
  source-vs-trial distinction).
- `cargo test -p synvoid-ipc --lib --profile ci` → 110/110 green,
  including 5 new generation tests.
- `cargo test -p synvoid-config --lib --profile ci` → 98/98 green.
- `cargo xtask test guards` → 3/3 steps pass.
- `cargo clippy --profile ci --all-targets -- -D warnings` → clean.
  (`cargo clippy --no-default-features` reports pre-existing
  `admin_smoke_flow`/`init_mesh` unused-variable errors that reproduce on
  the clean baseline `1cce2de6` with changes stashed; unrelated to this
  corrective and left untouched.)
- `cargo test --test security_regression --profile ci -- --test-threads=1`
  → 15/15 green.
- Admin contract (`--features mesh,dns,icmp-filter`): `admin_route_contract`
  24/24, `admin_router_composition` 18/18, `admin_smoke_flow` 24/24 green.
- `cargo check --no-default-features --profile ci` → clean.
- `cargo build --locked --release --no-default-features` → green;
  release minimal binary SHA-256:
  `1057f22b9b28cd927bd59f79c6918b5fdbf0d6a3be2fe3a8e2e2dc692995bcc9`.
  Debug minimal binary SHA-256 (live/interop proofs):
  `7d2c1f2ea8912537f7d164a7b6dbe4a703d377f94b99b1e4918262dbc4b4fda7` (rebuilt from the proof-bearing tree;
  resolved at commit, see §10).

## 9. Rejection criteria (all met)

- No Eggbench change was requested or needed; SynVoid conforms to the
  already-landed generic schema.
- No string mapping schema version; no `contract_id` in the mapping.
- No owner-side `sum`/bridge vocabulary in trial aggregation.
- No trial aggregation on counters.
- v1 was not silently rewritten: v2 advances the identifier and schema.
- Generation is explicit supervisor-local truth, never magnitude-inferred.
- First observation is never a reset.
- One process restart counts once, not once per metric.
- Retirement is live production pruning, not test-only.
- Closure carries the real Eggbench parser/collector proof.
- No Eggbench production/workspace dependency.
- No WAF/security, heartbeat-cadence, request-path IPC, or M002 semantic
  change.

## 10. Proof-bearing record

- Corrective baseline: `c0f121be771456ace2c7eaa1b26fb9f2fe3eb95f`.
- Implementation SHA: `739e7ba6f02c5e3f83fe9ff5321b09213182b193`.
- Eggbench consumer HEAD: `18b1c1c8398d559d38bd74d717ff3dc79e3b20ad`.
- Eggbench generic collector implementation:
  `2742e0eafaaef38899db5978f1721611ce58a7bc`.
- Eggbench parser owner:
  `crates/eggbench-drivers/src/prometheus_http.rs`.
- Mapping SHA-256: `622f6a13c4353cc7465cce39a57ed86fa0db2fe4114258e6f06226c1748d2d99`.
- Owner-contract digest (telemetry-enabled export, ports
  28710/28810/28910, at the implementation SHA):
  `46aa1f70705bd01f88c4eaf7f0346deb7d0573644d36c2d6597cb17b1c97415d`.
- Release minimal binary (`cargo build --locked --release
  --no-default-features`): `1057f22b9b28cd927bd59f79c6918b5fdbf0d6a3be2fe3a8e2e2dc692995bcc9`.
- Debug minimal binary (`cargo build --locked --no-default-features`):
  `7d2c1f2ea8912537f7d164a7b6dbe4a703d377f94b99b1e4918262dbc4b4fda7`.
- Routine verification: §8 plus `cargo xtask verify` (fmt + clippy green;
  stops at the pre-existing `dependency-policy` wasmtime advisory gate,
  see §11 item 2).
- Hosted CI/dependency-security: observed after push on the proof-bearing
  SHA and recorded here only if green; the pre-existing advisory gate
  applies equally to hosted `dependency-security` until the 2026-10-01
  re-audit. Commit-time evidence is the green local suite in §8.

`739e7ba6f02c5e3f83fe9ff5321b09213182b193`, `46aa1f70705bd01f88c4eaf7f0346deb7d0573644d36c2d6597cb17b1c97415d`, and
`7d2c1f2ea8912537f7d164a7b6dbe4a703d377f94b99b1e4918262dbc4b4fda7` are resolved to their final values in the
implementation commit and this closeout is amended before the terminal
status commits land; the placeholders must not survive closure.

## 11. Residuals / unresolved findings

1. Pre-existing `--no-default-features` clippy errors
   (`admin_smoke_flow` `session_cookie`, `init_mesh` `init`) reproduce on
   the clean baseline and are unrelated to this corrective; left for
   their owning follow-up.
2. Pre-existing dependency-policy gate: `cargo deny check` fails on
   `RUSTSEC-2026-0315` / `RUSTSEC-2026-0316` (transitive `wasmtime`
   36.0.15/47.0.4 via `synvoid-plugin-runtime`/`synvoid-yara`), identical
   on the clean baseline; `Cargo.lock` is untouched by this corrective.
   Governed by `architecture/dependency_security_baseline_phase25.md`
   (re-audit 2026-10-01). `cargo xtask verify` therefore passes fmt +
   clippy and stops at `dependency-policy`; every suite below that gate
   (guards, unit, live, interop) is green as recorded in §7–§8. This
   corrective introduces no new dependency-policy failure.
3. The full collector long-trial path (multi-minute windows, counter-reset
   mid-trial warning taxonomy) remains Eggbench-side evidence under its
   M003c plan; the owner-side proof covers preflight, windowed trial with
   gauge aggregation and counter delta, and all fail-closed branches.
4. Downstream Eggbench M003c/M003d terminal closure runs in Eggbench CI;
   this closeout unblocks it with the v2 mapping + contract pair.

## 12. Future-plan impact

No registered SynVoid future plan was blocked on this handoff (verified by
repository search: only the M003 plans, the two telemetry closeouts, the
roadmap section, the `telemetry_bridge` source, the `eggbench_qualification`
materializer extension, and the live-proof test reference the contract).
Its downstream is the external Eggbench M003c/M003d terminal closure, which
the v2 `telemetry-mapping.json` + `telemetry-contract.json` pair now
unblocks. No broad architecture phase was opened and none is required.
