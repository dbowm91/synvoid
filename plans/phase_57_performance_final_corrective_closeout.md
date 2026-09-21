# Phase 57 Plan: Performance Campaign Final Corrective Closeout

Status: implemented/closed. Proof-bearing implementation/qualification SHA: `5212c6862426ee17795994ef1bba590113c52fad`. Retained as historical handoff detail.

Registered in: `plans/roadmap.md`.

Supersedes only the **closure claim** of Phase 56; it does not supersede the
landed Phase 56 runtime fixes.

Phase 56 implementation reviewed:
`57ad3158754b2f4851e1ce408043d33104106974`.

Baseline for this final corrective pass:
`main` at `57ad3158754b2f4851e1ce408043d33104106974` (2026-09-21).

Parent records:

- `plans/phase_56_performance_campaign_corrective_runtime_and_evidence_closure.md`
- `architecture/performance_optimization_corrective_closeout.md`
- `architecture/performance_optimization_closeout.md`
- `architecture/performance_optimization_baseline.md`

## Primary goal

Close the remaining post-Phase-56 lifecycle and evidence defects without
reopening the completed Phase 49-56 performance work.

Phase 56 correctly landed the stateful `HoneypotWriter::shutdown()`
completion fix, lifecycle-owned maintenance task, strict `TeeBody` governor
reservation enforcement, and most benchmark provenance cleanup. A
post-implementation review found that the final closure claim is still
premature for three reasons:

1. the **real** `PortHoneypotRunner::run()/stop()` state machine can miss an
   early stop and can advertise itself as stopped before teardown completes;
2. the immutable WAF-concurrency baseline requested by Phase 56 was not
   actually reproduced;
3. planning/evidence surfaces disagree about Phase 56 status and do not record
   the proof-bearing Phase 56 SHA.

This phase is the final corrective closeout for that line. It should be small.

## Findings that require this pass

### 1. `stop()` can expose a false-stopped state while `run()` is still alive

Current `PortHoneypotRunner::stop()`:

- broadcasts on `shutdown_tx`;
- immediately writes `running = false`;
- spawns `writer.shutdown()`.

Current `run()` only writes `running = false` again after:

- the listener loop exits;
- the maintenance task joins;
- writer shutdown completes.

Therefore `is_running() == false` does **not** currently mean the runner
lifecycle has finished. A second `run()` can pass the boolean guard while the
first `run()` is still tearing down.

That violates Phase 56's no-accumulation intent and makes user-visible/admin
status race the actual lifecycle.

### 2. Runner shutdown notification is edge-triggered at the wrong boundary

`shutdown_tx` is a Tokio broadcast channel. In `run()`, the listener-loop
receiver is created inside the loop, after the runner has already set
`running = true`, selected a port, and started other lifecycle work.

A call to `stop()` during the interval before that subscription exists is
not retained for future broadcast subscribers. The maintenance receiver is
subscribed earlier, but the main runner loop can still miss the stop request.

The test added in Phase 56 for "restart" only exercises
`maintenance_loop()`; it does not spawn the real
`PortHoneypotRunner::run()`, call the real public `stop()`, or prove the
public state machine cannot overlap/miss shutdown.

### 3. Same-instance restart behavior is not a valid implicit contract today

The runner owns one `HoneypotWriter`. Phase 56 made writer shutdown
deliberately terminal: intake closes, queued records drain, and all later
writes fail.

The current code therefore cannot truthfully promise that the **same**
`PortHoneypotRunner` instance can be stopped and then fully restarted merely
because `running` becomes `false`.

No public signature change is needed, but Phase 57 must make the lifecycle
contract explicit and test it.

Default disposition for this pass:

- a `PortHoneypotRunner` instance is one lifecycle;
- `run()` may transition that instance from idle to active once;
- `stop()` requests shutdown synchronously;
- once terminal shutdown begins/completes, the same instance must not start a
  second overlapping or partially-functional lifecycle;
- a future operational "enable after disable" feature should construct a new
  runner/writer instance unless a separate plan deliberately makes the writer
  restartable.

If binding current documentation or a tested production call site proves
same-instance restart is already a required contract, do **not** paper over
that requirement. In that case, implement private writer/listener lifecycle
reconstruction and add full restart tests in this phase. Do not change public
method signatures.

### 4. Immutable WAF-concurrency requalification remains incomplete

Phase 56 required immutable baseline reproduction for WAF concurrency
1/8/32/128. The corrective closeout still labels the "before" concurrency
rows as historical working-tree measurements.

That is acceptable historical context, but it does not satisfy the Phase 56
acceptance criterion that specifically requested an immutable
baseline-plus-benchmark-only-patch rerun.

### 5. Closure/status evidence is internally inconsistent

At `57ad3158`:

- `plans/roadmap.md` says Phase 56 is implemented and closed;
- `plans/performance_optimization_roadmap.md` says Phase 56 is closed;
- `plans/phase_56_performance_campaign_corrective_runtime_and_evidence_closure.md`
  still says `Status: implementation handoff plan.`;
- `architecture/performance_optimization_corrective_closeout.md` describes
  the implementation/qualification head indirectly and does not record
  `57ad3158754b2f4851e1ce408043d33104106974` as the proof-bearing Phase 56
  SHA.

The final closeout must use immutable SHA roles and avoid a self-referential
"final commit contains its own hash" requirement.

## Scope

Phase 57 owns only:

1. the private `PortHoneypotRunner` lifecycle/shutdown state;
2. direct tests of the real public `run()/stop()/is_running()` behavior;
3. immutable WAF-concurrency baseline requalification;
4. Phase 56/57 planning and corrective-closeout evidence reconciliation;
5. final focused/full verification.

Phase 57 does **not** own:

- further WAF execution optimization;
- changing detector coverage, scoring, or precedence;
- changing `TeeBody`, unless verification finds a direct regression in the
  already-landed Phase 56 fix;
- redesigning honeypot SQLite persistence;
- making the public `stop()` method async;
- broad controller/admin feature work;
- implementing a new admin "enable" lifecycle;
- redesigning the buffer pool;
- unrelated task-lifecycle cleanup elsewhere in the repository.

## Workstream A — Make runner shutdown durable before exposing active state

Canonical owner:

`crates/synvoid-honeypot/src/runner.rs`

### Required invariant

A stop request must be durable for the active runner lifecycle. There must be
no interval where:

1. `run()` has committed to being active;
2. `stop()` can be called;
3. the only runner-loop shutdown receiver does not yet exist; and
4. the stop can be lost.

### Preferred shape

Use a stateful private shutdown primitive for the runner lifecycle, preferably
`tokio::sync::watch` or an equivalent durable cancellation state already
available in the workspace.

The receiver used by the main `run()` loop must exist before the lifecycle
is made externally visible as active.

The maintenance task should observe the same lifecycle cancellation state or a
receiver derived from it. Do not reintroduce detached maintenance work.

If retaining `broadcast`, prove by construction and direct tests that every
necessary receiver is subscribed before `run()` becomes active. A
stateful cancellation primitive is preferred because it makes late receivers
observe an already-requested stop.

Do not solve this with sleeps, repeated sends, or polling.

## Workstream B — Separate active, stopping, and terminal state

The current `running: RwLock<bool>` is doing two incompatible jobs:

- public "is it serving?" status;
- mutual exclusion for lifecycle ownership.

Replace or augment it with a private lifecycle state that can distinguish at
least:

- Idle;
- Running;
- Stopping;
- Stopped/Terminal.

An equivalent atomic/state representation is acceptable.

### Semantics

- `run()` atomically acquires lifecycle ownership before spawning/starting
  child work.
- a second `run()` while Running or Stopping returns without starting
  anything;
- `stop()` transitions Running -> Stopping (or sets durable cancellation);
- `stop()` must **not** make lifecycle ownership available to another
  `run()` before teardown is complete;
- `run()` transitions to terminal/stopped only after listener activity,
  maintenance, and writer drain have completed;
- repeated `stop()` calls are idempotent;
- a stop requested immediately after `run()` begins cannot be missed.

Preserve the public signatures:

```rust
pub async fn run(self: &Arc<Self>)
pub fn stop(&self)
pub fn is_running(&self) -> bool
```

`is_running()` should retain its user-facing meaning. It may report false
once Stopping begins, but that visible status must no longer be the guard that
permits a second lifecycle to start.

### Terminal/restart contract

Because `HoneypotWriter::shutdown()` is terminal, the preferred Phase 57
contract is that one runner instance is one lifecycle. A call to `run()`
after terminal stop should not create a partial second lifecycle.

Pin that behavior in documentation/tests.

If repository evidence shows same-instance restart is required today, make the
private writer/listener resources reconstructable before accepting Phase 57.
Do not claim restart support while reusing a writer whose intake is already
closed.

## Workstream C — Test the real runner, not only maintenance helpers

Helper-loop tests from Phase 56 remain useful, but they are insufficient for
closure.

Add direct tests that construct a real `PortHoneypotRunner` with isolated
temporary storage and loopback-safe configuration, then exercise the public
methods.

At minimum:

1. **early stop cannot be lost**
   - spawn `runner.run()`;
   - issue `runner.stop()` as early as deterministically possible;
   - assert the real run task returns within a bounded timeout.

2. **stop does not release lifecycle ownership early**
   - start the real run task;
   - request stop;
   - attempt a second `run()` while teardown is intentionally held at a
     deterministic private test barrier;
   - assert no second listener/maintenance lifecycle starts.

3. **actual teardown owns maintenance**
   - real `run()` return implies the maintenance task is gone.

4. **repeated stop is idempotent**
   - several callers invoke the real sync `stop()`;
   - one real `run()` exits;
   - writer drain completes without hang/panic.

5. **terminal same-instance behavior**
   - after the first real `run()` has fully returned, a second `run()`
     obeys the explicitly chosen contract (preferred: no second lifecycle on
     the terminal instance).

6. **status truth**
   - `is_running()` transitions agree with the documented visible semantics;
   - the internal lifecycle guard continues to block overlap while Stopping.

Use private test hooks/barriers if needed for deterministic interleavings.
Do not add operator-facing timing knobs solely for tests.

All async lifecycle tests must use bounded `tokio::time::timeout` so a
regression fails instead of hanging.

## Workstream D — Keep writer shutdown single-owned during runner teardown

Phase 56 currently has both:

- `stop()` spawning `writer.shutdown()`; and
- `run()` awaiting `writer.shutdown()` after joining maintenance.

Stateful writer completion makes that safe, but it obscures runner ownership.

Prefer one lifecycle owner:

- `stop()` requests runner cancellation synchronously;
- the active `run()` path owns listener shutdown, maintenance join, and
  writer drain;
- if `stop()` is called when no run lifecycle was ever active and the
  existing API contract requires writer closure, handle that explicit state
  separately.

Do not return from `run()` before writer drain completes.

Do not weaken the Phase 56 concurrent/late writer-shutdown guarantees.

## Workstream E — Complete immutable WAF-concurrency requalification

Use the Phase 56 immutable baseline method:

- production baseline: `015e790d2f739fe47669a5ac347989b7b18c03a3`;
- benchmark-only transplant: repaired
  `benches/bench_attack_detection_wave10.rs` plus only the registration
  needed to run it;
- no Phase 50-56 production code in the baseline worktree;
- after side: Phase 57 proof-bearing implementation head;
- same host, Rust target, profile, Criterion mode, and environment.

Re-run and record at minimum:

- concurrency batch 1;
- batch 8;
- batch 32;
- batch 128.

Replace the Phase 56 table's "Before (historical)" label for these rows only
after the immutable run actually completes.

If the immutable baseline harness cannot complete, record the exact blocker
and retain the rows as historical; in that case Phase 57 must not claim that
the immutable-concurrency acceptance criterion was satisfied.

Do not alter WAF production code merely to change the benchmark result.

## Workstream F — Reconcile Phase 56/57 evidence without self-referential SHAs

Update:

- `plans/phase_56_performance_campaign_corrective_runtime_and_evidence_closure.md`
- `plans/performance_optimization_roadmap.md`
- `plans/roadmap.md`
- `architecture/performance_optimization_corrective_closeout.md`

### Required Phase 56 history

Phase 56 should be represented as:

- implementation landed at
  `57ad3158754b2f4851e1ce408043d33104106974`;
- its writer/`TeeBody`/maintenance fixes remain valid;
- final closure required the Phase 57 runner-state/evidence correction.

Do not rewrite Phase 56 as a failure. It fixed the defects it actually fixed.

### Proof-bearing SHA protocol

Avoid requiring a commit to contain its own SHA.

Use two roles:

1. **proof-bearing implementation/qualification SHA** — contains all runtime
   fixes, tests, benchmark evidence content, and was the tree on which the
   final verification commands ran;
2. **closure metadata SHA** — optional docs-only follow-up that records the
   proof-bearing SHA and marks plans closed.

The closeout and roadmap must record role (1) explicitly. They do not need to
contain the hash of role (2).

At final close:

- Phase 56 plan status becomes historical/implemented with Phase 57 pointer;
- Phase 57 plan status becomes implemented/closed;
- performance roadmap returns to historical/complete;
- top-level roadmap says no active performance-corrective handoff remains;
- corrective closeout records both Phase 56 implementation SHA and Phase 57
  proof-bearing SHA.

## Workstream G — Verification

Focused verification:

```bash
cargo fmt --all -- --check
cargo test -p synvoid-honeypot --profile ci
cargo test -p synvoid-proxy --profile ci
cargo test -p synvoid-waf --profile ci
cargo xtask test guards
```

The honeypot suite must include the real `PortHoneypotRunner::run()/stop()`
lifecycle tests from Workstream C, not only helper-loop tests.

Feature profiles:

```bash
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
```

Repository gates:

```bash
cargo xtask verify
cargo xtask verify-full
cargo deny check
cargo audit
```

Focused benchmark requalification remains outside routine CI.

## Acceptance criteria

Phase 57 is complete only when:

- a stop request made at any point after real `run()` lifecycle acquisition
  cannot be lost because of a late subscription;
- `stop()` cannot make a second `run()` lifecycle start while the first is
  still tearing down;
- the lifecycle state distinguishes active ownership from user-visible
  running/stopping status;
- real public-method tests pin early-stop, overlapping-run rejection,
  maintenance ownership, repeated-stop idempotence, terminal behavior, and
  status transitions;
- the same-instance restart contract is explicit and matches the writer's
  actual terminal behavior, or private resources are genuinely rebuilt if
  same-instance restart is required;
- `run()` does not return before maintenance has exited and queued writer
  records have drained;
- the Phase 56 writer lost-wakeup fix and `TeeBody` reservation fix remain
  green and unchanged in contract;
- WAF concurrency 1/8/32/128 "before" values are reproduced from
  `015e790d` plus a recorded benchmark-only patch, or the closeout
  explicitly records why that criterion remains unsatisfied instead of
  claiming success;
- the Phase 56 plan no longer says "implementation handoff plan" while
  roadmaps call it closed;
- `57ad3158754b2f4851e1ce408043d33104106974` is explicitly recorded as
  the Phase 56 implementation SHA;
- the final Phase 57 proof-bearing implementation/qualification SHA is
  explicitly recorded without requiring self-reference;
- `plans/roadmap.md`,
  `plans/performance_optimization_roadmap.md`, Phase 56, Phase 57, and the
  corrective closeout agree on status;
- focused tests, feature profiles, `cargo xtask verify`,
  `cargo xtask verify-full`, `cargo deny check`, and `cargo audit` are
  green at the proof-bearing SHA, or any environmental inability is recorded
  truthfully without a green claim.

## Rejection criteria

Reject the Phase 57 closeout if it:

- adds another helper-only maintenance test while leaving the real
  `run()/stop()` race untested;
- keeps `running = false` as the sole mechanism that both exposes stopped
  status and permits lifecycle reacquisition during teardown;
- relies on an edge-triggered broadcast subscription created after the
  lifecycle is externally active;
- makes public `stop()` async or changes public signatures solely for
  implementation convenience;
- claims same-instance restart support while reusing a terminally shut-down
  writer;
- creates overlapping maintenance/listener/writer lifecycles;
- changes WAF behavior to improve the requalification numbers;
- relabels historical concurrency numbers as immutable without actually
  rerunning the immutable baseline;
- claims a self-referential "final SHA" that cannot exist;
- broadens into unrelated performance, admin-control, mesh, or architecture
  work.
