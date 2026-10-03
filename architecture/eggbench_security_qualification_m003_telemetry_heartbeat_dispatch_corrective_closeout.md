# Eggbench Security Qualification M003 Telemetry Heartbeat-Dispatch Corrective — Closeout

Status: **CLOSED QUALIFIED** (2026-10-02).

Plan:
`plans/eggbench_security_qualification_m003_telemetry_heartbeat_dispatch_corrective.md`
(status **CLOSED QUALIFIED** on closure).

The v2 interoperability closeout
(`architecture/eggbench_security_qualification_m003_telemetry_corrective_closeout.md`)
remains the authority for the schema/generation contract. This document is the
authority for the **live-value path**: four defects, each of which
independently kept the `synvoid.eggbench-telemetry.v2` series at zero or
unverified under real traffic, are repaired here and nothing else changes.

- Corrective baseline: `2002b6f82b5b94d9684390d132de535379c0644f`.
- Implementation SHAs: `ccf92694...` (supervisor routing + identity
  classification), then `1338ce7b...` (worker-side live-value wiring;
  **proof-bearing**). Full SHAs:
  `ccf926947acf5d7aaf07e5aa152bd7ecfc9798a2`,
  `1338ce7b60f3793701091b4c329f80eb542f802d`.
- Package version: `1.1.0` (unchanged).
- Cargo.lock: no new dependencies. No Eggbench Rust dependency entered SynVoid.

## 1. Root causes (four, all on the live-value path)

### 1a. Missing supervisor dispatch arm

`src/supervisor/ipc.rs` handled `UnifiedServerWorkerReady` but had no
`UnifiedServerWorkerHeartbeat` arm. Every heartbeat fell through `_ => {}`:
the worker produced payloads, the supervisor deserialized them, and
`ProcessManager` kept its default/stale `WorkerMetricsPayload` while the v2
bridge faithfully published a correct-but-zero inventory.

### 1b. Missing worker-ID classification

The same message was absent from the worker-ID extraction match, so it used
the global IPC rate-limit bucket and skipped the established per-worker
peer-PID identity path. The extraction match is now a single production
classifier, `WorkerMessageIdentity`, used by the real dispatcher for rate
limiting and PID verification. Tests call it directly; the old duplicated
test-only match is gone. Unified Server lifecycle messages that are genuinely
worker -> supervisor (`Ready`, `Heartbeat`, `ShutdownComplete`, `Error`,
`Drained`, `ResizeAck`) classify with their worker ID; supervisor -> worker
commands (`Drain`, `Resize`, generic `WorkerDrain`) stay unclassified.
Generic/CPU worker behavior is byte-identical.

### 1c. Second `WorkerMetrics` instance in the worker

`src/worker/unified_server/startup_plan.rs` rebound `metrics` to a fresh
`WorkerMetrics::shared()` in the Phase 11 block (an Iteration 93
decomposition leftover) after Phase 5 had already installed a different
instance into the server. The request path recorded every request-derived
field into the Phase 5 instance while the heartbeat serialized `state.metrics`
(the fresh one), so `total_requests`, `blocked`, `proxied`,
`body_buffering_bytes_total`, and the offload counters were permanently zero
even once dispatch worked. The rebinding is removed; one process holds
exactly one `WorkerMetrics`.

### 1d. Lag accumulator seeded one cadence ahead

`src/worker/unified_server/lifecycle.rs` seeded `next_heartbeat_at` to
`Instant::now() + heartbeat_interval`, but `tokio::time::interval` fires its
first tick immediately. The accumulator therefore sat exactly one cadence
ahead of every tick and `saturating_duration_since` clamped the measured lag
to zero unconditionally: `event_loop_lag_ms` reported a constant 0 however
late a heartbeat ran. It is now seeded to `Instant::now()` so it tracks the
schedule it measures. The 5s cadence is unchanged.

### What did not change (plan §3 non-goals held)

No telemetry schema/metric-name change, no heartbeat cadence change, no
Prometheus mapping change, no new metrics, no new labels/cardinality, no
WAF/security behavior change, no Eggbench production change, no IPC wire-format
change, no new load generator, no broad supervisor IPC redesign, no owner
contract v3 (`synvoid.eggbench-telemetry.v2` stands).

## 2. Files changed

At `ccf92694` (routing + classification):

- `src/supervisor/ipc.rs` — `WorkerMessageIdentity` classifier used by the
  production rate-limit/PID path; the `UnifiedServerWorkerHeartbeat`
  dispatch arm; production-classifier unit tests replacing the duplicated
  test-only match (`unified_server_worker_messages_are_classified_with_their_worker_id`,
  `unified_server_worker_startup_binds_pid_and_heartbeat_keeps_identity`,
  `supervisor_to_worker_commands_are_never_classified_as_worker_origin`,
  `cpu_worker_classification_is_unchanged`, `non_worker_messages_stay_unclassified`).
- `crates/synvoid-ipc/src/worker.rs` — `UnifiedServerWorkerProcess::new_record`
  (childless record, mirroring the existing `WorkerProcess::new_placeholder`).
- `crates/synvoid-ipc/src/manager.rs` —
  `ProcessManager::register_unified_server_worker_record` plus unit tests
  (recorded heartbeat stored generation-aware; unknown-ID heartbeat creates
  no record).
- `src/supervisor/telemetry_bridge.rs` — the refresh body extracted into a
  caller-owned `BridgeAggregator` (semantics verbatim; the cadence loop now
  calls it).
- `tests/unified_server_heartbeat_dispatch.rs` (new; composition proof, see §3).
- `tests/OWNERSHIP.toml` — ownership entry for the new test.
- `tests/eggbench_m003_telemetry_live_proof.rs` — first live-value
  strengthening (worker-backed values rather than inventory presence).

At `1338ce7b` (live-value wiring; proof-bearing):

- `src/worker/unified_server/startup_plan.rs` — remove the shadowing
  `WorkerMetrics` rebinding (§1c).
- `src/worker/unified_server/lifecycle.rs` — seed the lag accumulator at the
  schedule it measures (§1d).
- `tests/eggbench_m003_telemetry_live_proof.rs` — slow-origin path,
  full-body origin reads, concurrent above-threshold POST load, and a 24 s
  live-value scrape window requiring worker-backed memory, in-flight active
  connections, a workload-derived monotonic counter, and non-zero lag
  (§5).

## 3. Dispatch -> ProcessManager mutation evidence (Workstream C)

`tests/unified_server_heartbeat_dispatch.rs` drives the real
`handle_worker_connection` over real IPC streams; no test calls the
`ProcessManager` heartbeat handler directly. `--no-default-features`,
`--profile ci`:

- 6/6 green (`cargo test --no-default-features --profile ci --test
  unified_server_heartbeat_dispatch`).
- Reverting only the dispatch arm (§1a) fails 4 of 6
  (`routed_heartbeat_reaches_generation_aware_snapshot_with_exact_values`,
  `heartbeat_uses_the_per_worker_rate_limit_bucket`,
  `later_same_generation_heartbeat_replaces_absolute_snapshot`,
  `routed_heartbeat_propagates_through_bridge_to_prometheus`); the two
  negative tests still pass.
- Reverting only the classification entries (§1b) fails exactly the
  per-worker-bucket test with "the over-limit heartbeat must be dropped by
  the per-worker bucket".
- Positive coverage: startup -> heartbeat keeps one worker identity; spoofed
  startup PID is refused with nothing recorded; a second same-generation
  heartbeat replaces the absolute snapshot with generation unchanged;
  an unowned worker ID creates no record.
- The new crate-level seams are covered in-tree:
  `synvoid-ipc` 112–147 unit tests green (includes the two new heartbeat
  tests); root lib 704/704 green.

`crate::metrics::WorkerMetricsPayload::default()`-at-zero is what a dropped
heartbeat looks like, so every assertion uses distinctive non-zero values.

## 4. Dispatch -> bridge -> Prometheus integration evidence (Workstream D)

`routed_heartbeat_propagates_through_bridge_to_prometheus` (in the same file,
green above): wire heartbeat -> supervisor IPC dispatch -> ProcessManager ->
generation-aware snapshot -> `BridgeAggregator::refresh` (the exact production
aggregation used by the cadence loop) -> rendered exposition. A gauge
(`synvoid_subject_worker_memory_bytes = 987654321.0`, `# TYPE gauge`) and a
counter (`synvoid_subject_body_buffering_bytes_total = 8675309.0`, `# TYPE
counter`) carry the injected values; a second refresh accumulates the
same-generation counter monotonically with `worker_metric_resets_total = 0`.
No wall-clock cadence wait.

## 5. Owner live proofs (Workstream E)

Real minimal binary: `cargo build --locked --release --no-default-features`
at `1338ce7b`, `sha256
251ac1d2e0c45be399570b3e2abcbb2925589bc01102eb2869585bcd7f8030f7`.

- M002 (`tests/eggbench_qualification_live_proof.rs`,
  `SYNVOID_EGGBENCH_LIVE_PROOF=1`): green.
- M003 (`tests/eggbench_m003_telemetry_live_proof.rs`,
  `SYNVOID_EGGBENCH_M003_LIVE_PROOF=1`): green. Live worker-backed maxima over
  48 scrapes: `worker_memory_bytes = 69619712`, `active_connections = 5`,
  `event_loop_lag_ms = 65`, `worker_cpu_percent = 28.83`,
  `body_buffering_bytes_total = 177733632`. Offload submission/timeout/
  rejection/fallback counters remain 0 because the minimal runtime runs no
  CPU offload worker; they were deliberately not forced non-zero (plan E.7).
  Required series stay finite and correctly typed; counters never decrease
  across the whole window; exporter shutdown stays bounded (metrics port
  closed after supervisor shutdown).

## 6. Downstream Eggbench terminal proof (Workstream F)

Eggbench `eggstack/eggbench@3cc40480ef0e7475c5c379cced0e9ed907736313`, closing
revision `30a38251bccb5157beb68202ffe630f6253771e0` carrying the evidence. The pin
advance to `1338ce7b...` is one line of owner SHA in
`scripts/qualification/synvoid-m003/run-live-qualification.sh`. The later
Eggbench commits fix defects in Eggbench's own measurement and reporting that
had to be repaired before the owner's corrected telemetry could be observed as
correct; they are listed with their evidence in §9 and none of them changes the
telemetry contract, the mapping, a gate, an allowance, or a trial count.

- Local full-harness run against the corrected owner: `pass=30 stopped=0
  notexec=0`, exit 0. `m003c-13b required subject series carry live owner
  values` **PASS**. Per-trial observations (3 trials, all identical):
  `subject_active_connections = 8.0`, `subject_event_loop_lag_ms = 1.0`,
  `subject_body_buffering_bytes_total = 0.0`,
  `subject_offload_rejections_total = 0.0`; 20 in-window samples each,
  `poll_error_count = 0`, `dropped_sample_count = 0`, loopback authority.
  Exact v2 mapping/contract digests continue to match
  (`synvoid.eggbench-telemetry.v2`, mapping
  `622f6a13c4353cc7465cce39a57ed86fa0db2fe4114258e6f06226c1748d2d99`,
  content identity
  `dd7d58dd204a691ab0b83b82a83d49f3438b67e3ea6d0e14c7c1fba3832584b0`).
- Hosted four-lane CI on the closing revision: run `37143714313` —
  `linux-stable`, `linux-msrv`, `windows-stable`, and `macos-stable` all
  **success**.
- Hosted `live-m003-linux` on the closing revision: the `live-m003-linux`
  job inside live-workflow run `37143714261` — **success**, with all five
  live jobs green. Harness summary `pass=29 stopped=0 notexec=1`; the single
  `NOT-EXECUTED` is `m003d-4`, which needs `oha` installed on the runner.
  `m003c-13b required subject series carry live owner values` **PASS** against
  the real pinned owner, as do `m003c-13`, `m003c-14`, `m003d-2`, `m003d-6`,
  `m003d-7`, and `m003d-8`. Minimal owner binary built by the harness:
  `6a9a169236b24656f4d853fca914ce0ecbe9d49e42273fe6ba929a66d62f0870`.

## 7. Routine verification

- `cargo fmt --all -- --check`: clean.
- `cargo clippy --profile ci --all-targets -- -D warnings` (default +
  `--no-default-features` lib/tests): clean except **pre-existing** failures
  that reproduce on the clean baseline and are out of scope:
  `tests/admin_smoke_flow.rs:400` unused `session_cookie` under
  `--no-default-features`, `jail_process.rs` dead `fail_ids`,
  `jail_protocol_golden.rs` `vec!` macro (see §8: baseline-verified).
- `cargo deny check`, `cargo audit` (via `cargo xtask verify`): green.
- `cargo check --no-default-features --profile ci`: clean.
- `cargo nextest ... synvoid-repo-guards`, all root guard suites,
  `cargo xtask test guards`: green (no guard was edited; the
  cert-reload `tokio::spawn` stays in `handle_worker_connection_internal`,
  so the lifecycle spawn allowlist is untouched).
- `cargo xtask verify`: 10/10 steps green.

## 8. Remaining findings (none blocking)

- Hosted evidence is terminal: four-lane CI `37143714313` and live
  `37143714261` are both green on the same closing revision `30a3825`, so
  acceptance criteria 11 and 12 are satisfied on one exact head rather than
  across revisions.
- Audit finding (recorded, not broadened): routing is still asymmetric for
  `UnifiedServerWorkerShutdownComplete` — it is classified with its worker ID
  but has no dispatch arm to `mark_unified_server_worker_stopped`. A
  ProcessManager child-reaping monitor already owns stop detection, so no
  orphan exists; routing it is a separate lifecycle change and is out of this
  corrective. Generic `WorkerShutdownComplete` keeps its existing
  unclassified behavior by design (plan §4 requirement 1).
- Pinned pre-existing lints (baseline-verified, untouched by this work):
  `admin_smoke_flow` unused variable under `--no-default-features`,
  `synvoid-ipc` jail `fail_ids` / `jail_protocol_golden` `vec!`. New code
  introduces no clippy failure.

## 9. Downstream defects found and fixed while proving this correct

The owner's corrected telemetry could not be observed as correct until three
real defects in Eggbench's own measurement and reporting were repaired, plus one
portability bound. Each is a separate Eggbench commit with its own test
evidence. None changes the telemetry contract, the mapping, metric names or
units, the heartbeat cadence, any gate, any allowance, or any trial count, and
none relaxes an assertion to make a failure disappear.

1. **Baseline and candidate arms were a whole suite apart.** The performance
   profiles materialized every baseline and then ran one whole-profile candidate
   pass, so a scenario's two arms were separated by the remainder of the suite
   and the candidate arm always ran second. The `statistical_relative` gate
   compares paired per-trial log differences, which measures the candidate only
   when both arms saw the same machine conditions, so on a shared runner the
   drift in that gap was attributed entirely to the candidate. Symptom:
   macOS reported roughly 0.7 degradation for byte-identical code, and a
   same-build pair failed. The profiles now qualify one scenario at a time with
   each baseline immediately before its own candidate run. Preserved: the 10 ms
   and 100 ms plan-invisible throttles still fail their performance gates while
   owner security outcomes stay correct, a correctness-corpus mutation still
   fails the suite, and a workload-concurrency change is still reported
   incomparable (exit 8) rather than as a performance result.
2. **`m003c-13b` demanded a non-zero health gauge.** The live-value check
   required every required gauge to exceed `0.0`, but `event_loop_lag_ms` is a
   health reading whose correct value is zero whenever the event loop was never
   late. A healthy subject was therefore reported upstream as an unpopulated
   series, intermittently, depending on how loaded the runner happened to be.
   The check is now classified per metric: in-flight `subject_active_connections`
   must exceed zero, a health gauge only has to report a valid reading, and any
   unclassified required gauge keeps the strict must-exceed-zero rule so nothing
   is weakened silently. The reader was differentially verified to behave
   identically to the previous one on all 27 combinations of zero, non-zero, and
   missing gauge and counter values without the classification flags. An
   intermediate version of this change briefly made the counter branch
   unreachable and produced a false "no delta" finding against a correctly
   reporting owner; that was caught on the next hosted run and fixed.
3. **Stopped stages pointed at evidence that had been deleted.** Every
   "see `$WORK/<log>`" reference named a file the harness removed on exit, so a
   stop was only ever an exit code. The bounded per-stage driver output is now
   retained and uploaded as `live-m003-stage-diagnostics`, and the `m003c-13b`
   stop text no longer names a `UnifiedServerWorkerHeartbeat` dispatch arm that
   this corrective already routes.
4. **Portability bound, not a defect.** The v1 perf, control, and smoke
   scenarios' per-trial measurement bound moved from 120 s to 300 s after macOS
   finalized a baseline with `primary_failure TimedOut`. The bound exists to stop
   a hung run, not to express a speed target, and on a contended shared runner it
   was measuring the runner. The oracle scenarios keep their own 60 s bound and
   the v2 profile is untouched. This follows the M002 C001 precedent, which
   replaced a 500 ms readiness bound with a bounded retry after macOS slow binds
   produced spurious transport failures.

### Recorded, not blocking

- `m003d-4` executes only where `oha` is installed; hosted it is
  `NOT-EXECUTED`, locally it executes. This is external-tool availability, not a
  verdict.
- The M002b same-source performance proof remains `#[cfg(target_os = "linux")]`.
  It was briefly re-enabled to test the fix on the failing platform; macOS still
  failed it with the arms adjacent, which confirms the original note that this
  particular Python proxy stand-in cannot reproduce a same-build pair on macOS
  at any concurrency while its direct-origin controls pass. That is a fixture
  property, distinct from the arm-gap defect, so the gate was restored.
- SynVoid's own `event_loop_lag_ms` remains a truthful health reading: zero on
  an idle, never-late loop. Nothing in this corrective makes it non-zero, and
  the plan's live proof drives enough load to observe a non-zero value
  (65 ms) without relying on the loop being busy.
