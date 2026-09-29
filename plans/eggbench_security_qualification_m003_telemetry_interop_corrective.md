# Plan: Eggbench Security Qualification M003 Telemetry Interoperability Corrective

Status: **CLOSED QUALIFIED** (2026-09-29).

Registered in: `plans/roadmap.md`.

Corrective baseline:
`c0f121be771456ace2c7eaa1b26fb9f2fe3eb95f`.

Implementation being corrected:
`619602a6cd2440d685020eb52e19c0887622dee1`.

Corrective implementation:
`739e7ba6f02c5e3f83fe9ff5321b09213182b193`.

Terminal closeout:
`architecture/eggbench_security_qualification_m003_telemetry_corrective_closeout.md`
(sole current terminal authority).

Historical closeout being superseded for terminal qualification:
`architecture/eggbench_security_qualification_m003_telemetry_closeout.md`.

Parent handoff:
`plans/eggbench_security_qualification_m003_telemetry_contract.md`.

Pinned downstream consumer reviewed for this corrective:

- repository: `eggstack/eggbench`
- current reviewed HEAD: `18b1c1c8398d559d38bd74d717ff3dc79e3b20ad`
- generic Prometheus collector implementation:
  `2742e0eafaaef38899db5978f1721611ce58a7bc`
- parser owner:
  `crates/eggbench-drivers/src/prometheus_http.rs`
- consumer plan:
  `plans/implementation/security-qualification/003c-subject-telemetry-and-synvoid-metrics-ingestion.md`

## 1. Corrective disposition

The M003 implementation is substantially retained. This corrective does **not**
roll back:

- the supervisor/root composition ownership of subject telemetry;
- the loopback-only Prometheus listener;
- explicit global-recorder installation;
- `SupervisorTaskRegistry` ownership of exporter and bridge tasks;
- `ProcessManager` heartbeat truth as the source of worker telemetry;
- the closed M002 telemetry-off materialization path;
- admin-disabled qualification;
- the no-Eggbench-Rust-dependency boundary;
- the five-second Unified Server heartbeat cadence;
- WAF/security semantics.

The terminal `CLOSED QUALIFIED` claim is nevertheless invalid until this
corrective closes. The current materialized mapping is not consumable by the
pinned Eggbench M003c parser, and the counter-generation bridge has correctness
gaps that invalidate the claimed reset/generation semantics.

The corrective therefore supersedes the **qualification claim**, not the useful
implementation already present.

## 2. Trigger findings

### 2.1 The emitted mapping does not parse in Eggbench

Current SynVoid `TelemetryMapping` emits:

- `schema_version: String`, currently
  `"eggbench.security_qualification.telemetry_mapping.v1"`;
- `source: "prometheus"`;
- an extra top-level `contract_id`;
- `aggregation: String` on every field;
- owner-side aggregation vocabulary including:
  - `sum`,
  - `latest_ready`,
  - `supervisor_lifetime_monotonic_bridge`.

Pinned Eggbench `PrometheusMappingV1` instead requires:

- numeric `schema_version: 1`;
- `#[serde(deny_unknown_fields)]` at the mapping and field levels;
- no top-level `contract_id`;
- `aggregation: Option<PrometheusAggregation>`;
- gauge aggregation limited to `mean|max|min`;
- counters with `aggregation = None`;
- optional exact `labels` only;
- output names beginning with `subject_`.

The current SynVoid mapping therefore fails during deserialization/validation
before a trial can begin.

### 2.2 Owner aggregation and trial aggregation were conflated

SynVoid needs two different aggregation concepts:

1. **owner/source aggregation**, performed by the supervisor across worker
   heartbeat snapshots at one instant, for example:
   - max worker event-loop lag;
   - sum active connections;
   - sum worker memory;
   - supervisor-lifetime counter bridge;

2. **trial aggregation**, performed by Eggbench across repeated Prometheus
   scrapes during a measured trial, for example:
   - max event-loop lag;
   - max active connections;
   - mean aggregate CPU;
   - counter delta.

They are not interchangeable vocabularies. A producer-side `sum` must not be
placed in Eggbench's trial-aggregation field.

### 2.3 One unit is objectively wrong

`synvoid_subject_body_buffering_bytes_total` is sourced from
`WorkerMetricsPayload::body_buffering_bytes_total` but the current owner
inventory assigns generic counter unit `events`.

The corrected unit is `bytes`.

Offload/reset counters should use a count unit, not inherit the body-byte unit.

### 2.4 v1 cannot be silently rewritten

The parent plan states that incompatible owner name/type/unit/source-aggregation
meaning requires a new owner contract version.

Because this corrective changes at least one declared unit and clarifies
aggregation semantics, do not rewrite the already-materialized
`synvoid.eggbench-telemetry.v1` identity in place.

Use:

`synvoid.eggbench-telemetry.v2`

for the corrected owner contract.

The historical v1 artifact is **withdrawn/unqualified**. It need not remain a
runtime-selectable compatibility mode because it never satisfied its declared
Eggbench interoperability acceptance gate, but its historical closeout and
commit remain in Git history.

### 2.5 Initial observations are incorrectly counted as resets

Current `WorkerCounterState::apply()` returns one boolean for both:

- first observation;
- actual counter reset.

`BridgeState::apply_worker()` increments
`worker_metric_resets_total` when that boolean is true and the first value is
nonzero.

A worker first observed with nonzero counters is therefore falsely reported as
a reset. Because this happens per bridged counter, one initial worker snapshot
can also increment the reset metric multiple times.

### 2.6 Worker generation identity is absent

Unified Server workers restart with the same `WorkerId`.
The current bridge only detects a generation boundary when a new absolute
counter is lower than the previous value.

That is insufficient. If a restarted process accumulates a value greater than
the previous process before the next bridge poll, the bridge treats the new
process as the same generation and undercounts.

The bridge must receive an explicit generation identity from
`ProcessManager`; it must not infer process generations from counter
magnitude.

### 2.7 The claimed bounded retirement policy is not live

`BridgeState::retire()` and its retired-generation FIFO are currently
test/dead-code only. The production bridge does not retire IDs that disappear
from `ProcessManager` snapshots, while the closeout claims that it does.

Either make production pruning real or remove the claim. This corrective
requires real pruning.

### 2.8 Workstream J was closed without its required proof

The rebased plan required the actual Eggbench `prometheus-http` consumer to
ingest the emitted mapping.

The implementation closeout instead moved that proof to an external residual
and declared the owner side closed. Since the emitted mapping is currently
incompatible, this is a terminal-evidence defect rather than merely deferred
CI.

### 2.9 One stale materializer comment remains

The generated qualification config still claims the documented `[tokio]`
table form is rejected, despite the post-Phase-99 configuration behavior.

Correct the comment while touching the materializer. Do not alter Tokio runtime
semantics as part of this corrective.

## 3. Binding contract decisions

### 3.1 Corrected owner contract

Advance the owner contract to:

`synvoid.eggbench-telemetry.v2`

and owner schema to:

`synvoid.eggbench-telemetry.contract.v2`

unless implementation demonstrates a compelling structural reason to retain
the v1 JSON schema identifier. The semantic owner contract ID **must** advance
to v2.

Preserve existing Prometheus sample names unless a separate concrete defect
requires otherwise. Stable names reduce downstream churn.

The owner manifest should use an unambiguous field name such as
`source_aggregation` rather than an undifferentiated `aggregation` field.

### 3.2 Exact Eggbench mapping schema

`telemetry-mapping.json` must be a document accepted directly by pinned
Eggbench `PrometheusMappingV1`.

Required top level:

~~~json
{
  "schema_version": 1,
  "source": "prometheus",
  "fields": []
}
~~~

Do not put `contract_id`, owner source-aggregation vocabulary, provenance, or
other owner metadata into this file. Bind the mapping to the owner contract by
SHA-256 from `telemetry-contract.json` and provenance.

Each field must contain only Eggbench-supported keys.

Recommended v2 trial mapping:

| Output | Prometheus source | Kind | Unit | Eggbench trial aggregation | Required |
|---|---|---|---|---|---|
| `subject_event_loop_lag_ms` | `synvoid_subject_event_loop_lag_ms` | gauge | ms | max | yes |
| `subject_request_queue_p95_ms` | `synvoid_subject_request_queue_p95_ms` | gauge | ms | max | yes |
| `subject_active_connections` | `synvoid_subject_active_connections` | gauge | connections | max | yes |
| `subject_worker_memory_bytes` | `synvoid_subject_worker_memory_bytes` | gauge | bytes | max | yes |
| `subject_worker_cpu_percent` | `synvoid_subject_worker_cpu_percent` | gauge | percent | mean | yes |
| `subject_body_buffering_bytes_total` | `synvoid_subject_body_buffering_bytes_total` | counter | bytes | none | yes |
| `subject_offload_submissions_total` | `synvoid_subject_offload_submissions_total` | counter | count | none | yes |
| `subject_offload_timeouts_total` | `synvoid_subject_offload_timeouts_total` | counter | count | none | yes |
| `subject_offload_rejections_total` | `synvoid_subject_offload_rejections_total` | counter | count | none | yes |
| `subject_offload_fallbacks_total` | `synvoid_subject_offload_fallbacks_total` | counter | count | none | yes |
| `subject_cpu_worker_rss_bytes` | `synvoid_subject_cpu_worker_rss_bytes` | gauge | bytes | max | no |
| `subject_worker_metric_resets_total` | `synvoid_subject_worker_metric_resets_total` | counter | count | none | no |

For counters, serialize `aggregation` as absent or `null` only if the pinned
Eggbench parser accepts that exact form. Add a compatibility test against the
chosen bytes.

No labels are required in v2.

## 4. Workstream A — materializer/schema correction

Replace the SynVoid-specific mapping DTO with an Eggbench-compatible DTO:

- `schema_version: u32`;
- `source: String`;
- no `contract_id`;
- field `aggregation: Option<...>`;
- optional empty labels only if needed;
- `#[serde(deny_unknown_fields)]` on local DTOs is recommended so SynVoid's
  producer tests fail when unsupported keys are introduced.

Keep owner-only metadata in `telemetry-contract.json`.

Update deterministic digest/provenance tests for v2.

The materializer must continue to preserve byte-compatible M002 behavior when
`--metrics-port` is absent.

## 5. Workstream B — explicit worker-generation truth

Add an internal generation identity for Unified Server worker telemetry.

Preferred shape:

~~~text
UnifiedServerWorkerTelemetrySnapshot {
    worker_id: WorkerId,
    generation: u64,
    metrics: WorkerMetricsPayload,
}
~~~

Requirements:

- first spawn for a worker ID receives a generation;
- every same-ID process respawn advances generation monotonically;
- generation is not PID-derived;
- existing public/internal `get_all_unified_server_worker_metrics()` remains
  available for compatibility;
- add a narrow generation-aware getter used by the root telemetry bridge;
- no reverse root dependency enters `synvoid-ipc`;
- no protocol/wire change is required because generation is supervisor-local
  process-manager state.

A generation counter may live on `UnifiedServerWorkerProcess` or in a small
manager-owned generation map, but respawn replacement must not reset it to zero.

Add tests for initial spawn, same-ID resize restart, failure restart, and
monotonic generation progression.

## 6. Workstream C — correct monotonic bridge/reset semantics

Refactor counter observation so first observation and reset/generation change
are distinct states.

Suggested internal vocabulary:

~~~text
First(value)
Delta(value)
GenerationReset(value)
CounterReset(value)
Unchanged
~~~

or an equivalent typed representation.

Rules:

1. first observation seeds the supervisor-lifetime counter with the current
   absolute value and does **not** increment
   `worker_metric_resets_total`;
2. same-generation increase contributes `current - previous`;
3. explicit generation change re-baselines all bridged counters and contributes
   the new absolute values as the new generation's first contribution;
4. generation change increments reset/generation-boundary telemetry exactly
   once per worker transition, not once per counter;
5. an unexpected same-generation counter decrease is observable and
   re-baselined without a negative delta; count the event once for that worker
   observation;
6. unchanged counters contribute zero;
7. arithmetic remains saturating/bounded.

Document what `worker_metric_resets_total` means under v2. If
"generation boundaries" is clearer than "metric resets", consider a new metric
name under v2 rather than preserving a misleading name. Do not silently change
the semantic meaning of a v1 metric while retaining the v1 contract ID.

## 7. Workstream D — real production pruning

On every bridge refresh, compute the set of currently reported Unified Server
worker IDs/generations and prune bridge state that no longer exists in the
authoritative ProcessManager snapshot.

Acceptance:

- bridge state is bounded by live ProcessManager worker state plus a small,
  explicitly bounded transition allowance;
- no dead-code-only retirement path is cited as production proof;
- a remove/re-add test demonstrates bounded state and correct first-generation
  semantics;
- closeout wording matches actual implementation.

Do not retain an arbitrary historical generation FIFO unless it is required for
correctness.

## 8. Workstream E — actual Eggbench interoperability proof

This is the terminal gate that the previous closeout missed.

Using the materialized `telemetry-mapping.json` bytes from the corrected
SynVoid tree and the pinned Eggbench consumer:

1. feed the exact file to Eggbench's real `parse_mapping()` /
   `PrometheusMappingV1` path;
2. require parse + validation success with no translation or hand editing;
3. start the real minimal SynVoid telemetry endpoint;
4. run Eggbench's real `prometheus-http` collector against it;
5. request at least:
   - one required gauge;
   - one required counter;
   - one optional gauge when available;
6. prove:
   - preflight succeeds;
   - required metrics resolve;
   - gauge trial aggregation succeeds;
   - counter delta succeeds;
   - missing/renamed required sample fails closed;
   - TYPE mismatch fails closed;
   - mapping digest is the exact materialized mapping digest.

The proof may be an opt-in cross-repo qualification lane rather than routine
SynVoid CI. It must pin:

- exact SynVoid SHA;
- exact Eggbench SHA;
- exact mapping SHA-256;
- exact owner-contract digest;
- minimal SynVoid binary digest.

Do **not** add Eggbench as a SynVoid Rust dependency.

If a small companion fixture/test is needed in Eggbench, that is downstream
M003c implementation evidence and should be committed there under its existing
M003c plan rather than copied into SynVoid production dependencies.

## 9. Workstream F — evidence/status reconciliation

Before implementation begins, historical evidence must remain truthful:

- parent plan status must say corrective required;
- roadmap must say the terminal qualification is superseded;
- historical closeout must be visibly marked as superseded/not terminal;
- implementation SHA `619602a6...` remains valid historical implementation
  evidence;
- do not delete prior test/binary hashes.

On corrective closure, either:

1. amend the historical closeout with a clearly identified corrective addendum;
   or
2. create
   `architecture/eggbench_security_qualification_m003_telemetry_corrective_closeout.md`
   and make it the sole current terminal authority.

Option 2 is preferred for auditability.

## 10. Workstream G — materializer documentation cleanup

Correct the stale generated-config comment about `[tokio]` table rejection to
match the current post-Phase-99 configuration implementation.

No Tokio scheduler/runtime configuration change is authorized by this work.

## 11. Required tests

At minimum:

### Mapping/contract

1. emitted mapping parses with a local DTO structurally identical to pinned
   Eggbench v1;
2. numeric `schema_version == 1`;
3. no unknown top-level mapping fields;
4. gauges have only `mean|max|min`;
5. counters have no trial aggregation;
6. body-buffering unit is bytes;
7. offload/reset counters use count;
8. owner manifest distinguishes source aggregation from Eggbench trial
   aggregation;
9. v2 contract ID/schema are deterministic and digest-stable;
10. telemetry-off M002 output remains unchanged.

### Generation/counter bridge

11. first nonzero observation is not a reset;
12. first observation still seeds cumulative counter truth;
13. same-generation delta is exact;
14. explicit generation change with new value lower than old is exact;
15. explicit generation change with new value **higher** than old is also
    detected and re-baselined correctly;
16. generation transition increments reset/boundary count once, not once per
    metric;
17. unexpected same-generation decrease never emits negative delta;
18. dead worker state is pruned in the production update path;
19. repeated remove/re-add remains bounded;
20. existing gauge aggregation semantics remain unchanged.

### Live/cross-repo

21. corrected minimal SynVoid configtest passes;
22. real endpoint remains loopback only and admin disabled;
23. real Eggbench parser accepts exact materialized mapping bytes;
24. real Eggbench collector preflight succeeds;
25. required gauge and counter observations complete a trial;
26. required-name drift fails closed;
27. endpoint/task shutdown remains bounded.

## 12. Routine SynVoid verification

At minimum:

~~~text
cargo fmt --all -- --check
cargo test -p synvoid-ipc --profile ci
cargo test --no-default-features --profile ci --lib -p synvoid
cargo test -p xtask --profile ci
cargo test -p synvoid-config --profile ci
cargo xtask test guards
cargo xtask verify
cargo check --no-default-features --profile ci
cargo build --locked --release --no-default-features
~~~

Also rerun:

- M002 owner materializer export/check/configtest;
- M002 live proof;
- M003 v2 owner live proof;
- pinned Eggbench real-parser/collector interoperability proof.

The pre-existing Wasmtime advisories remain governed by the existing dependency
security baseline. This corrective must not introduce a new dependency-policy
failure.

## 13. Acceptance criteria

This corrective closes only when all of the following are true:

1. the roadmap no longer relies on the invalid v1 terminal claim;
2. corrected owner contract is versioned as v2;
3. mapping bytes are directly accepted by pinned Eggbench
   `PrometheusMappingV1`;
4. owner/source aggregation and Eggbench trial aggregation are distinct;
5. body-buffering is correctly unitized as bytes;
6. explicit worker generation identity is available to the bridge;
7. first observation is not counted as a reset;
8. same-ID restart is detected even when new absolute counters exceed old
   values;
9. reset/generation counting is once per defined boundary, not once per metric;
10. production pruning bounds retained bridge worker state;
11. M002 telemetry-off behavior remains unchanged;
12. loopback/admin/security/lifecycle guarantees remain intact;
13. real minimal SynVoid live proof passes;
14. actual pinned Eggbench parser and collector consume the exact generated
    mapping and live endpoint;
15. exact SynVoid/Eggbench revisions and digests are recorded in a corrective
    closeout.

Terminal status after proof may return to **CLOSED QUALIFIED**.

## 14. Rejection criteria

Reject an implementation that:

- modifies Eggbench merely to accept SynVoid's currently invalid mapping when
  SynVoid can conform to the already-landed generic schema;
- keeps string mapping schema version;
- keeps `contract_id` in the Eggbench mapping;
- emits owner-side `sum`/bridge vocabulary as Eggbench trial aggregation;
- assigns a trial aggregation to counters;
- silently rewrites v1 unit/semantic claims under the v1 identifier;
- infers worker generation only from counter decrease;
- counts first observation as reset;
- counts one process restart once per bridged metric;
- leaves worker-state retirement test-only;
- closes without the real Eggbench parser/collector proof;
- adds Eggbench as a production or workspace dependency;
- changes WAF/security behavior, heartbeat cadence, request-path IPC, or M002
  qualification semantics.

## 15. Handoff order

Implementation order:

1. reconcile statuses/document authority;
2. introduce generation-aware ProcessManager snapshot;
3. correct bridge generation/reset/pruning semantics;
4. advance owner contract to v2 and separate source aggregation;
5. make mapping exactly Eggbench-v1-compatible;
6. correct units and Tokio comment;
7. rerun SynVoid unit/materializer/live qualification;
8. execute pinned Eggbench parser/collector interoperability proof;
9. write proof-bearing corrective closeout;
10. restore terminal `CLOSED QUALIFIED` only after all gates pass.

No separate broad architecture phase is required. No Eggbench feature redesign is
required; its existing M003c plan remains the downstream consumer authority.
