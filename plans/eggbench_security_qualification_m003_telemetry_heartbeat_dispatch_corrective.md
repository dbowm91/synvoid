# Plan: Eggbench M003 Telemetry Heartbeat Dispatch Corrective

Status: **READY**.

Registered in: `plans/roadmap.md`.

Corrective baseline:
`2002b6f82b5b94d9684390d132de535379c0644f`.

Parent telemetry contract:

- `plans/eggbench_security_qualification_m003_telemetry_contract.md`
- `plans/eggbench_security_qualification_m003_telemetry_interop_corrective.md`
- terminal v2 closeout:
  `architecture/eggbench_security_qualification_m003_telemetry_corrective_closeout.md`

Downstream consumer/evidence baseline:

- `eggstack/eggbench@7689716c1b3cfaaab366756afc284a8eda0e0b64`
- Eggbench M003 milestone:
  `plans/closure/security-qualification/003-status.md`
- Eggbench M003c closure:
  `plans/closure/security-qualification/003c-status.md`
- current-head normal CI:
  `36995287800` — Linux stable, Linux Rust 1.89, macOS stable, Windows stable all green
- current-head live qualification:
  `36995287756` — every live job green except `live-m003-linux`
- `live-m003-linux` terminal result: exit 10 because `m003c-13b` is the single stopped qualification gate.

Proposed corrective closeout:

`architecture/eggbench_security_qualification_m003_telemetry_heartbeat_dispatch_corrective_closeout.md`.

## 1. Corrective disposition

The `synvoid.eggbench-telemetry.v2` contract, mapping schema, exporter lifecycle,
generation-aware bridge, loopback-only binding, and materializer remain retained.

This corrective does **not** redesign the telemetry contract and does not advance
the owner contract to v3 unless implementation uncovers a separate incompatible
semantic change.

The defect is narrower: the Unified Server worker emits
`Message::UnifiedServerWorkerHeartbeat`, and `ProcessManager` already owns
`handle_unified_server_worker_heartbeat()`, but the supervisor IPC dispatcher
does not route that message to the handler.

As a result:

1. Unified Server workers produce heartbeat payloads;
2. the supervisor receives/deserializes the message;
3. the message falls through the supervisor dispatch match;
4. `ProcessManager` retains the default/stale `WorkerMetricsPayload`;
5. the v2 telemetry bridge faithfully reads that default/stale state;
6. Prometheus exposes the required v2 inventory, but its worker-backed values
   remain zero/default under real traffic;
7. Eggbench correctly stops `m003c-13b` instead of accepting fabricated
   telemetry.

The terminal owner-side v2 qualification claim is therefore incomplete for the
specific live-value path even though its schema/interoperability corrective is
closed.

## 2. Trigger evidence

### 2.1 Worker emission exists

`src/worker/unified_server/lifecycle.rs` sends:

~~~text
Message::UnifiedServerWorkerHeartbeat {
    id,
    timestamp,
    metrics,
}
~~~

on the existing heartbeat cadence.

No new worker heartbeat producer or cadence is required.

### 2.2 ProcessManager storage exists

`crates/synvoid-ipc/src/manager.rs` already exposes:

~~~text
handle_unified_server_worker_heartbeat(worker_id, metrics)
~~~

and the telemetry bridge reads the resulting state through:

~~~text
get_all_unified_server_worker_metrics_with_generation()
~~~

No new telemetry storage model is required.

### 2.3 Supervisor dispatch is missing

At the corrective baseline, `src/supervisor/ipc.rs` handles:

- `WorkerHeartbeat` -> `handle_heartbeat`;
- `CpuWorkerHeartbeat` -> `handle_cpu_worker_heartbeat`;
- `UnifiedServerWorkerReady` -> `handle_unified_server_worker_ready`;

but has no `UnifiedServerWorkerHeartbeat` arm. The message reaches the default
`_ => {}` branch.

This is the direct root cause for the Eggbench live-value failure.

### 2.4 Worker identity classification is also incomplete

The same supervisor path performs worker-ID extraction before dispatch for:

- per-worker IPC rate limiting;
- peer-PID binding verification on an established worker connection.

`UnifiedServerWorkerStarted` participates in startup identity binding, but
`UnifiedServerWorkerHeartbeat` currently falls through to `worker_id = None`.
Therefore a heartbeat uses the global limiter and does not receive the normal
per-worker peer-PID identity check.

The corrective must restore routing and identity-classification parity together.

### 2.5 Downstream proof is already precise

Eggbench current head reports all M003-owned work complete except
`m003c-13b`. The current live workflow intentionally exits nonzero when the
required owner series do not carry live values.

Do not weaken that gate or reinterpret a present-at-zero inventory as success.

## 3. Scope and non-goals

### In scope

- route `UnifiedServerWorkerHeartbeat` through the supervisor IPC dispatcher;
- classify the heartbeat with its `WorkerId` for normal per-worker security and
  rate-limit handling;
- add regression tests at the actual dispatch boundary;
- prove `ProcessManager` receives and stores a non-default heartbeat payload;
- prove the telemetry bridge consumes the updated state;
- rerun the real minimal SynVoid owner telemetry proof;
- rerun Eggbench's exact live M003 consumer qualification against the corrected
  SynVoid revision;
- reconcile owner status/closeout/roadmap truth.

### Out of scope

- telemetry schema or metric-name changes;
- heartbeat cadence changes;
- Prometheus mapping changes;
- new metrics;
- new labels/cardinality;
- WAF/security behavior changes;
- Eggbench production changes;
- IPC wire-format changes;
- new load generators;
- broad supervisor IPC redesign;
- unrelated Unified Server lifecycle behavior unless the audit below proves it
  shares the exact same classification defect.

## 4. Workstream A — centralize worker-origin identity classification

The current worker-ID extraction match is production security/control logic but
its unit test duplicates a separate match rather than exercising the production
classifier.

Extract the logic into a small private typed helper used by the real dispatcher.

Suggested shape:

~~~text
WorkerMessageIdentity {
    worker_id: Option<u64>,
    startup_pid: Option<u32>,
    is_startup: bool,
}
~~~

or an equivalent representation.

Requirements:

1. preserve existing behavior for generic workers and CPU workers;
2. preserve `UnifiedServerWorkerStarted` startup PID binding;
3. classify `UnifiedServerWorkerReady` and
   `UnifiedServerWorkerHeartbeat` with their real worker ID;
4. audit the remaining worker-originated Unified Server lifecycle messages
   (`ShutdownComplete`, `Error`, resize/drain acknowledgements) and classify
   them where they are actually worker -> supervisor messages;
5. do not classify supervisor -> worker command variants as worker-originated;
6. use the helper in production for rate limiting/PID verification;
7. make tests call the helper rather than reimplementing its match logic.

If this audit reveals a separate missing lifecycle action beyond classification,
record it as a finding. Do not broaden this corrective unless it directly
affects the M003 heartbeat/live-value path or an obvious existing
worker-lifecycle invariant.

## 5. Workstream B — route Unified Server heartbeat to ProcessManager

Add the missing dispatch arm:

~~~text
Message::UnifiedServerWorkerHeartbeat {
    id,
    timestamp: _,
    metrics,
} => {
    process_manager.handle_unified_server_worker_heartbeat(id, metrics);
}
~~~

Requirements:

- use the existing ProcessManager handler;
- do not copy telemetry aggregation logic into the supervisor dispatcher;
- do not mutate the v2 bridge;
- do not reinterpret or normalize payload values at IPC dispatch;
- preserve message validation before dispatch;
- preserve panic isolation/error handling;
- preserve existing rate-limit behavior except that the message now uses the
  correct per-worker bucket;
- preserve peer-PID verification and make it apply to the heartbeat through
  Workstream A.

## 6. Workstream C — dispatch-boundary regression tests

Add tests that fail on the corrective baseline and pass only when the real
routing path is fixed.

### C1. Identity classification

Verify a `UnifiedServerWorkerHeartbeat { id: WorkerId(N), ... }` is classified
as worker N.

Where a startup message establishes the peer-PID binding, verify the subsequent
heartbeat follows the same worker identity path rather than the global path.

### C2. ProcessManager mutation

Construct a non-default `WorkerMetricsPayload` with distinctive values, for
example:

- `total_requests`;
- `memory_bytes`;
- `cpu_percent`;
- `event_loop_lag_ms`;
- `request_queue_time_ms.p95_ms`;
- `body_buffering_bytes_total`;
- `offload_submissions_total`;
- `active_connections`.

Route it through the supervisor message handler and assert the generation-aware
ProcessManager snapshot contains those exact values.

Do not satisfy this acceptance test by calling
`handle_unified_server_worker_heartbeat()` directly; the regression is the
missing supervisor dispatch.

### C3. Multiple heartbeats

Send at least two heartbeats for one live generation and verify the later
payload replaces the current absolute snapshot while the generation remains
unchanged.

This protects the v2 bridge's existing same-generation delta semantics.

### C4. Unknown/stale worker behavior

Verify the existing ProcessManager policy for a heartbeat whose worker ID is not
currently owned. Preserve the current fail-safe behavior; do not silently create
an unmanaged worker record merely to make telemetry appear.

## 7. Workstream D — bridge integration proof

Add a focused integration test proving the fixed dispatcher reaches the existing
v2 bridge without a synthetic direct ProcessManager write.

Required chain:

~~~text
UnifiedServerWorkerHeartbeat message
  -> supervisor IPC dispatch
  -> ProcessManager worker metrics
  -> generation-aware snapshot
  -> telemetry bridge
  -> Prometheus value
~~~

At least one gauge and one monotonic counter must carry the injected non-default
value through the chain.

This test should use a bounded local fixture and must not depend on wall-clock
load generation.

Keep the existing bridge tests intact; this is a missing composition test, not
a replacement.

## 8. Workstream E — real minimal owner live proof

Rerun the existing opt-in M003 telemetry live proof against the exact corrective
SHA and real `--no-default-features` minimal binary.

The proof must establish more than inventory presence.

Under controlled loopback traffic:

1. the real Unified Server worker emits heartbeats;
2. the supervisor stores a non-default live payload;
3. the bridge observes that payload;
4. required v2 series remain finite and correctly typed;
5. at least one traffic/resource gauge demonstrates live worker-backed state;
6. at least one workload-relevant monotonic counter or owner observation
   demonstrates non-default/live state when the exercised path is expected to
   increment it;
7. legitimately zero counters such as timeout/rejection counters are not forced
   nonzero merely for proof;
8. exporter shutdown remains bounded;
9. M002 live qualification remains green.

Record the exact release/minimal binary digest.

## 9. Workstream F — downstream Eggbench terminal proof

The authoritative acceptance test is the actual downstream consumer.

Pin a corrected SynVoid revision in the Eggbench M003 live workspace and run:

~~~text
scripts/qualification/synvoid-m003/run-live-qualification.sh
~~~

Acceptance:

- `m003c-13b` passes;
- no other previously green M003c/M003d stage regresses;
- no owner-contract translation or hand editing is introduced;
- exact v2 mapping/contract digests continue to match;
- the live harness exits zero rather than stopped/exit 10.

Then require on the exact Eggbench closing revision:

- normal four-lane CI green;
- `live-m003-linux` green.

Current Eggbench head `7689716c...` and runs `36995287800` /
`36995287756` are the pre-corrective reference evidence, not terminal
post-corrective evidence.

No Eggbench semantic relaxation is authorized.

## 10. Workstream G — owner evidence reconciliation

The existing v2 closeout remains valid for the schema/interoperability work it
proved, but its terminal live-value claim must be qualified by this corrective.

During implementation:

- do not delete or rewrite historical v1/v2 evidence;
- mark this corrective as the active owner-side condition for Eggbench M003
  terminal closure;
- do not claim the current `739e7ba6...` proof fully satisfies downstream
  live-value qualification.

On closure create:

`architecture/eggbench_security_qualification_m003_telemetry_heartbeat_dispatch_corrective_closeout.md`

and record:

- corrective baseline and implementation SHA;
- exact files changed;
- message-classification test evidence;
- dispatch -> ProcessManager mutation evidence;
- dispatch -> bridge -> Prometheus integration evidence;
- owner minimal binary digest;
- M002 live regression result;
- M003 owner live-proof result;
- downstream Eggbench SHA;
- Eggbench four-lane run ID;
- Eggbench live M003 run ID;
- `m003c-13b` terminal result;
- remaining unrelated findings.

After closure, roadmap wording should make the new corrective closeout the
latest authority for the live-value path while retaining the v2 interoperability
closeout as the authority for schema/generation semantics.

## 11. Required tests

At minimum:

1. production worker-message classifier recognizes
   `UnifiedServerWorkerHeartbeat`;
2. production classifier recognizes `UnifiedServerWorkerReady`;
3. Unified Server startup -> heartbeat maintains the same worker identity;
4. heartbeat uses per-worker rate-limit/identity classification, not global
   fallback;
5. supervisor dispatcher calls the existing ProcessManager heartbeat handler;
6. distinctive non-default heartbeat fields reach the generation-aware
   snapshot;
7. second same-generation heartbeat updates the snapshot;
8. heartbeat does not create an unknown unmanaged worker;
9. dispatch -> bridge gauge propagation works;
10. dispatch -> bridge counter propagation works;
11. existing generation/reset tests remain green;
12. existing telemetry mapping/contract tests remain byte/semantic stable;
13. existing telemetry-off M002 materializer output remains stable;
14. M002 owner live proof remains green;
15. M003 owner live proof demonstrates live worker-backed values;
16. actual Eggbench `m003c-13b` passes on the corrected revision.

## 12. Routine verification

At minimum:

~~~text
cargo fmt --all -- --check
cargo test -p synvoid-ipc --profile ci
cargo test --no-default-features --profile ci --lib -p synvoid
cargo test -p xtask --profile ci
cargo test -p synvoid-config --profile ci
cargo test -p synvoid-metrics --profile ci
cargo xtask test guards
cargo xtask verify
cargo check --no-default-features --profile ci
cargo clippy --no-default-features --profile ci --all-targets -- -D warnings
cargo build --locked --release --no-default-features
~~~

Also run the opt-in M002 and M003 owner live proofs.

Any current dependency-security gate must remain green at the corrective SHA;
do not waive or reclassify an unrelated new advisory as part of this work.

## 13. Acceptance criteria

This corrective closes only when:

1. the supervisor routes `UnifiedServerWorkerHeartbeat` to
   `ProcessManager::handle_unified_server_worker_heartbeat`;
2. heartbeat identity participates in the same per-worker IPC
   rate-limit/peer-PID path as the worker connection that emitted it;
3. regression tests exercise the real production classifier/dispatcher rather
   than a duplicated test-only match;
4. non-default payload fields reach the generation-aware ProcessManager
   snapshot;
5. the existing v2 bridge publishes worker-backed values from that routed
   heartbeat;
6. no telemetry contract/schema/name/unit change was needed;
7. no heartbeat cadence or WAF/security semantic changed;
8. M002 telemetry-off and live qualification remain green;
9. real minimal SynVoid M003 owner live proof shows live worker-backed
   telemetry;
10. Eggbench's unchanged `m003c-13b` passes against the corrected owner;
11. exact-head Eggbench four-lane CI is green;
12. exact-head Eggbench `live-m003-linux` is green;
13. proof-bearing SHAs, run IDs, and binary/contract/mapping digests are
    recorded in the corrective closeout.

Terminal status may then return to **CLOSED QUALIFIED** for the live-value path,
and Eggbench M003 may remove its upstream conditional-closure gate.

## 14. Rejection criteria

Reject an implementation that:

- changes Eggbench to accept zeros;
- weakens or removes `m003c-13b`;
- writes metrics directly from the supervisor IPC branch instead of updating
  ProcessManager truth;
- adds a second heartbeat producer;
- changes heartbeat cadence to make the test pass;
- creates worker records from unknown heartbeat IDs;
- bypasses message validation, rate limiting, or peer identity checks;
- adds a new Prometheus contract/version without an independent incompatible
  semantic reason;
- changes WAF/security behavior;
- makes Eggbench a SynVoid dependency or SynVoid an Eggbench Rust dependency;
- closes only on a unit test without the real minimal owner proof and actual
  Eggbench live consumer proof.

## 15. Handoff

This corrective is dependency-ready.

Expected production change is narrow and should primarily touch:

- `src/supervisor/ipc.rs`;
- focused supervisor/IPC regression tests;
- possibly a small private message-classification helper.

`crates/synvoid-ipc/src/manager.rs` and
`src/supervisor/telemetry_bridge.rs` should require no semantic redesign. If
implementation requires substantial changes there, stop and re-audit the root
cause before broadening the corrective.

No unrelated architecture phase is blocked on this work. Its direct downstream
is Eggbench Security Qualification M003 terminal closure.
