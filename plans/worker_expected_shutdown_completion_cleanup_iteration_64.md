# Worker Expected-Shutdown Completion Cleanup — Iteration 64

## Purpose

Iteration 63 corrected the primary worker supervision edge cases: exit subscription now happens before task spawn, the worker uses a persistent supervision loop, successful pre-shutdown task returns can be classified as `UnexpectedCompletion`, the unified-server run task is registry-owned, bandwidth persistence performs a final flush, and broadcast lag/closure policies are explicit.

One final lifecycle gap remains: expected shutdown intent is not yet connected to task-exit classification early enough.

During `MasterShutdown`, the IPC loop records an expected `IpcLoopExit::MasterShutdown`, clears the worker running flag, and returns `Ok(())`. However, `WorkerTaskRegistry::shutdown_started_arc` is not set until the worker later calls `shutdown_and_join()`. The IPC wrapper can therefore classify the normal return as `UnexpectedCompletion`, which is fatal for a `CriticalService`. The same race can affect the registry-owned `server_run` task after the running flag is cleared.

The current typed IPC exit-cause object is returned by `spawn_ipc_loop()` but discarded by the composition root, so it does not influence supervision. `WorkerShutdownCause` is also not yet the authoritative source for process exit status and supervisor notification. Finally, the normal `MasterShutdown` path sends `UnifiedServerWorkerShutdownComplete` before registry-owned tasks are joined, and does not visibly enforce the requested graceful drain timeout.

This pass should make coordinated shutdown a first-class runtime state, carry expected completion through task supervision, enforce the intended shutdown ordering, and make `WorkerShutdownCause` authoritative.

The invariant is:

> Expected shutdown intent must be recorded before critical services are asked to return, and shutdown completion must not be reported until all owned work has stopped or been forcibly terminated.

## Current Known State

At `e413f6bb0d5a19d6becdac9d90c139e253df6267`:

- `WorkerTaskRegistry` owns heartbeat, bandwidth persistence, IPC, and `server_run`.
- `subscribe_exits()` is called before supervised task spawn.
- The worker supervision loop continues on nonfatal background exits.
- `TaskExitReason::UnexpectedCompletion` is implemented using `shutdown_started_arc`.
- `is_fatal_exit()` treats abnormal critical exits as fatal.
- `WorkerShutdownCause` exists with exit-code/notification/expectedness helpers.
- `IpcLoopExit`, `IpcLoopError`, and `IpcLoopExitCause` exist.
- `spawn_ipc_loop()` returns `(task_id, IpcLoopExitCause)`.
- The composition root discards `_ipc_exit_cause`.
- `MasterShutdown` sends `stop_accepting_tx`, stops app servers, clears `running`, persists bandwidth, sends `UnifiedServerWorkerShutdownComplete`, and then returns `Ok(())`.
- Registry shutdown and joins happen after the supervision loop exits.
- `graceful` and `timeout_secs` are received but are not yet authoritative over the full worker drain/join sequence.

## Non-Goals

Do not broaden into another task-migration wave.

Do not redesign the supervisor protocol unless a minimal message-order correction is required.

Do not weaken `UnexpectedCompletion` globally.

Do not make all background-task failures fatal.

Do not change request-path, blocklist, threat-intel, mesh-ID, or composition-root behavior.

Do not replace the registry’s broadcast/watch architecture.

Do not introduce process-wide global shutdown state outside the worker composition root.

## Phase 1 — Introduce Explicit Coordinated-Shutdown Intent

Add a registry/lifecycle API that marks coordinated shutdown intent before service tasks are asked to return.

Suggested registry API:

```rust
pub fn begin_shutdown(&self) {
    self.shutdown_started.store(true, Ordering::Release);
    self.shutdown_started_arc.store(true, Ordering::Release);
}
```

Separate intent from cancellation if useful:

```rust
pub fn begin_shutdown(&self);
pub fn broadcast_shutdown(&self);
pub fn shutdown(&self) {
    self.begin_shutdown();
    self.broadcast_shutdown();
}
```

Required semantics:

- `begin_shutdown()` is idempotent.
- Calling it changes completion classification immediately.
- It does not necessarily cancel tasks until orchestration reaches the cancellation phase.
- `shutdown_and_join()` still calls full shutdown defensively.

The composition root must call `begin_shutdown()` before clearing `running`, stopping the server, or allowing IPC/server tasks to return normally.

## Phase 2 — Define A Worker Shutdown Coordinator

Move normal shutdown initiation out of the IPC task’s deep branch and into the worker composition root.

Preferred architecture:

1. IPC task receives `MasterShutdown`.
2. IPC task emits a typed shutdown command/event to the composition root.
3. Composition root records `WorkerShutdownCause::SupervisorShutdown`.
4. Composition root calls `registry.begin_shutdown()`.
5. Composition root executes the shutdown sequence.
6. IPC task remains alive until cancellation or returns with a typed expected outcome after shutdown intent is recorded.

Suggested channel/event:

```rust
pub enum WorkerLifecycleEvent {
    MasterShutdown {
        graceful: bool,
        timeout: Duration,
    },
    WorkerResize {
        worker_threads: usize,
    },
    SupervisorDisconnected,
}
```

Use `mpsc`, `watch`, or a small dedicated channel owned by the worker state.

Minimal acceptable alternative:

- Keep IPC branch orchestration in place.
- Give it access to registry `begin_shutdown()` through a narrow shutdown coordinator handle.
- Invoke `begin_shutdown()` before `stop_accepting_tx`, `running.stop()`, or task return.

Preferred outcome is composition-root orchestration because task code should report lifecycle events rather than own full process shutdown ordering.

## Phase 3 — Replace Or Consume `IpcLoopExitCause`

The current shared `RwLock<Option<IpcLoopExit>>` is written by the IPC task but discarded by its caller.

Choose one coherent outcome.

### Preferred Outcome A — Typed Task Completion

Allow registry result tasks to return a typed completion outcome:

```rust
pub enum ManagedTaskCompletion<T> {
    Expected(T),
    Unexpected,
}
```

or add a registration API:

```rust
spawn_critical_managed<F, T, E>(...)
where F: Future<Output = Result<ManagedTaskCompletion<T>, E>>
```

The registry exit record can then carry:

```rust
TaskExitReason::ExpectedCompletion(String)
```

or preserve typed metadata separately.

### Acceptable Outcome B — Supervision Reads Exit Cause

Retain `IpcLoopExitCause`, store it in the composition root, and consult it when the `ipc_loop` exit event arrives.

If cause is one of:

- `MasterShutdown`
- `WorkerResize`
- `RegistryShutdown`
- `RunningFlagCleared`

then convert or treat the exit as expected, provided coordinated shutdown intent was already recorded.

Do not leave the cause object unused.

Recommended: use a lifecycle-event channel and remove the side-channel `RwLock` if feasible.

## Phase 4 — Make Expected Completion Explicit Per Task

Global shutdown intent is necessary but may not be sufficient for every task.

Define expected-completion semantics for:

### IPC Loop

Expected:

- `MasterShutdown`
- `WorkerResize`
- registry cancellation
- intentionally cleared running flag

Unexpected:

- connection loss
- unclassified return
- panic/error

### Server Run

Expected:

- explicit coordinated shutdown after stop-accepting/listener cancellation

Unexpected:

- normal `Ok(())` return while worker is active
- server error
- panic

### Heartbeat/Bandwidth

Expected:

- registry cancellation during coordinated shutdown

Unexpected but nonfatal:

- return while worker is active

Add task identity-aware handling where needed. Do not rely only on `Ok(())` plus one global boolean if a task can finish normally for an unrelated reason.

## Phase 5 — Make `WorkerShutdownCause` Authoritative

Use `WorkerShutdownCause` as the single primary shutdown result selected by the supervision loop or lifecycle-event handler.

Required uses:

- final log message;
- process exit status;
- supervisor error notification policy;
- expected/unexpected telemetry;
- shutdown ordering policy where relevant.

Replace scattered final exit-code inference with:

```rust
let exit_code = if shutdown_cause.nonzero_exit_code() { 1 } else { 0 };
```

Preserve special resize exit code `100` explicitly:

```rust
pub enum WorkerShutdownCause {
    ...
    WorkerResize { worker_threads: usize },
}

impl WorkerShutdownCause {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::WorkerResize { .. } => 100,
            cause if cause.nonzero_exit_code() => 1,
            _ => 0,
        }
    }
}
```

If `master_dead` remains useful for state/metrics, it should not independently override a previously selected primary shutdown cause.

## Phase 6 — Correct `ServerExited` Semantics

`WorkerShutdownCause::ServerExited` currently treats server completion as expected and zero-exit, but a server task returning while the worker is active should be abnormal.

Refine the model:

```rust
pub enum WorkerShutdownCause {
    ServerExitedUnexpectedly,
    ServerStoppedForShutdown,
    ...
}
```

or:

```rust
ServerExited {
    expected: bool,
    error: Option<String>,
}
```

Required policy:

- server error before shutdown -> nonzero exit.
- server `Ok(())` before shutdown -> nonzero unexpected critical completion.
- server completion after coordinated shutdown -> expected zero exit.

Do not retain a blanket `ServerExited => expected` rule.

## Phase 7 — Implement One Ordered Shutdown Procedure

Create an explicit composition-root function:

```rust
async fn shutdown_unified_worker(
    state: &UnifiedServerWorkerState,
    registry: &mut WorkerTaskRegistry,
    cause: &WorkerShutdownCause,
    options: ShutdownOptions,
) -> WorkerShutdownReport
```

Suggested options:

```rust
pub struct ShutdownOptions {
    pub graceful: bool,
    pub drain_timeout: Duration,
    pub critical_join_timeout: Duration,
    pub background_join_timeout: Duration,
}
```

Required ordering:

1. Record primary shutdown cause.
2. Call `registry.begin_shutdown()`.
3. Stop accepting new connections.
4. If graceful, wait for active connections to drain up to `drain_timeout`.
5. Stop app servers and protocol listeners.
6. Clear running flag / signal server run loop.
7. Broadcast registry cancellation.
8. Await critical tasks with bounded timeout.
9. Await background tasks with bounded timeout.
10. Abort-and-await remaining tasks.
11. Perform/confirm final persistence flushes.
12. Send shutdown-complete acknowledgement if appropriate.
13. Return a structured report.

This ordering should be used for:

- `MasterShutdown`;
- critical-task failure;
- supervisor disconnect;
- server failure;
- external stop;
- resize, with its specific semantics.

Branches may customize drain/notification behavior but should share the same primitive.

## Phase 8 — Apply `graceful` And `timeout_secs`

The supervisor-provided shutdown fields must influence actual behavior.

For `MasterShutdown`:

- `graceful=true`: stop accepting, call `wait_for_drain()` using `timeout_secs`, then stop services.
- `graceful=false`: skip connection drain and proceed directly to cancellation.
- Clamp unreasonable values to configured minimum/maximum bounds if necessary.
- Use explicit defaults if `timeout_secs == 0`.

Do not hold the IPC mutex while waiting for drain or joining tasks.

Document whether the timeout is:

- drain-only; or
- total shutdown budget.

Recommended first implementation: treat it as drain timeout, with separate fixed registry join budgets.

## Phase 9 — Delay `ShutdownComplete` Until Completion Is True

`UnifiedServerWorkerShutdownComplete` must not be sent before registry-owned tasks have terminated.

Move the acknowledgement out of the IPC task branch and into the composition-root shutdown completion path.

Required conditions before send:

- stop accepting has occurred;
- graceful drain has completed or timed out;
- server/app listeners have been stopped;
- registry shutdown/join has completed;
- timed-out tasks have been aborted and awaited;
- final bandwidth/persistence flush has completed.

If the IPC loop itself owns the same IPC stream needed for acknowledgement, resolve ownership cleanly:

- have the IPC loop emit the shutdown event, then remain paused awaiting coordinator result;
- or let the coordinator use the shared IPC handle after IPC task cancellation/join;
- avoid deadlock by ensuring the IPC task is not holding the mutex while the coordinator sends.

The acknowledgement should include failure/degraded detail only if the protocol already supports it; otherwise log locally.

## Phase 10 — Avoid Double Bandwidth Flush Ambiguity

Bandwidth is currently persisted in the IPC `MasterShutdown` branch and again by the bandwidth task’s final flush.

Choose one owner for the final flush.

Preferred:

- bandwidth background task owns periodic and final flush;
- composition root waits for that task to finish;
- remove the direct IPC-branch persistence call.

Alternative:

- composition-root shutdown procedure owns the final flush;
- bandwidth task only stops periodic work.

Whichever is chosen:

- document ownership;
- test exactly-once or at-least-once semantics as appropriate;
- ensure no flush occurs after `ShutdownComplete`.

At-least-once is acceptable if persistence is idempotent.

## Phase 11 — Supervisor Notification Policy

Use `WorkerShutdownCause::should_notify_supervisor()` before attempting error notification.

Rules:

- Do not notify on normal `MasterShutdown`.
- Do not notify on expected resize acknowledgement beyond existing protocol.
- Notify on critical task failure while IPC is available.
- Supervisor disconnect cannot notify the disconnected supervisor; log and exit nonzero.
- Registry infrastructure failure should notify if IPC remains functional.

Avoid sending both a fatal error and a normal shutdown-complete acknowledgement for the same cause.

## Phase 12 — Remove Redundant Shutdown State

Audit these state carriers:

- `worker_exit_code`
- `master_dead`
- `running`
- `shutdown_started`
- `IpcLoopExitCause`
- `WorkerShutdownCause`

Keep each only for a distinct purpose.

Recommended roles:

- `running`: cooperative runtime/listener stop signal.
- registry shutdown state: task completion classification and cancellation.
- `WorkerShutdownCause`: primary process outcome.
- `master_dead`: optional health observation, not final exit-code authority.
- remove `worker_exit_code` if `WorkerShutdownCause::exit_code()` fully replaces it.
- remove `IpcLoopExitCause` if lifecycle events replace it.

Do not retain overlapping flags merely for compatibility without documenting precedence.

## Phase 13 — Integration Tests For Real MasterShutdown

Add an end-to-end-ish worker lifecycle test using test doubles for IPC, server, drain state, and persistence.

Required scenario:

1. Start registry-owned heartbeat, bandwidth, IPC, and server tasks.
2. Deliver `MasterShutdown { graceful: true, timeout_secs: N }`.
3. Assert coordinated shutdown intent is marked before IPC/server tasks return.
4. Assert IPC/server exits are not classified as `UnexpectedCompletion`.
5. Assert no `CriticalTaskExit` is selected.
6. Assert stop-accepting occurs before drain.
7. Assert drain occurs before listener/task cancellation.
8. Assert registry tasks are joined or aborted-and-awaited.
9. Assert final bandwidth persistence completes.
10. Assert `ShutdownComplete` is sent last.
11. Assert final exit code is zero.
12. Assert no task remains active.

This test must exercise actual task wrappers, not merely instantiate `WorkerShutdownCause::SupervisorShutdown`.

## Phase 14 — Additional Shutdown-Cause Tests

Add focused cases:

### Server Failure

- server task returns error while active;
- cause is unexpected server/critical failure;
- exit code nonzero;
- all other tasks shut down;
- no normal shutdown-complete acknowledgement.

### Server Clean Early Return

- server task returns `Ok(())` while active;
- classified as unexpected;
- nonzero exit.

### Supervisor Disconnect

- IPC returns `ConnectionLost`;
- cause is `SupervisorDisconnected`;
- nonzero exit;
- no attempt to send acknowledgement to dead supervisor.

### Resize

- expected task completions;
- exit code `100`;
- no critical-failure classification;
- resize acknowledgement ordering preserved.

### Ungraceful MasterShutdown

- stop accepting;
- skip drain wait;
- cancel/join tasks;
- final flush;
- send completion last;
- zero exit.

## Phase 15 — Registry API Tests

Add unit tests for the new intent/cancellation split.

Suggested tests:

- `begin_shutdown_marks_expected_completion_without_broadcasting_cancel`
- `shutdown_begins_and_broadcasts_cancellation`
- `critical_return_after_begin_shutdown_is_clean`
- `critical_return_before_begin_shutdown_is_unexpected`
- `begin_shutdown_is_idempotent`
- `shutdown_and_join_defensively_begins_shutdown`

If task-specific expected outcomes are introduced, add typed completion tests.

## Phase 16 — Guardrail Updates

Update `tests/background_task_ownership_guard.rs` and/or add a lifecycle ordering guard.

Guardrail goals:

- `MasterShutdown` path must call coordinated shutdown intent before `running.stop()`.
- `UnifiedServerWorkerShutdownComplete` must be emitted from the final shutdown coordinator, not directly from the IPC receive branch.
- graceful shutdown fields must be consumed by the drain path.
- `IpcLoopExitCause` cannot be returned and discarded.
- final exit code must derive from `WorkerShutdownCause`.
- server task completion cannot be blanket-classified as expected.

Behavioral tests are primary; source scans are regression reinforcement only.

## Phase 17 — Documentation Cleanup

Update:

- `architecture/worker_task_lifecycle.md`
- `docs/adr/ADR-003-unified-worker-process.md`
- `architecture/worker_data_plane_composition_root.md`
- `AGENTS.md`
- `src/worker/AGENTS.override.md`

Document:

- shutdown intent versus cancellation;
- typed expected completion;
- authoritative shutdown-cause selection;
- graceful drain semantics;
- shutdown-complete acknowledgement ordering;
- final persistence ownership;
- exit-code mapping including resize;
- removal/deprecation of redundant flags or side channels.

Correct any current statement implying `MasterShutdown` is already fully distinguished by the registry if it is not until this pass lands.

## Phase 18 — Verification Commands

Run:

```bash
cargo test worker::task_registry
cargo test worker_supervision_control_flow
cargo test unified_server --lib
cargo test --test background_task_ownership_guard
cargo test --test data_plane_composition_boundary_guard
cargo test --test mesh_id_boundary_guard
cargo test --test threat_intel_boundary_guard
cargo test --test threat_intel_consumer_actionability_guard
cargo test --test manual_enforcement_provenance_guard
cargo test --lib --no-run
cargo fmt --check
cargo clippy --lib -- -D warnings
```

If IPC/lifecycle types change across crates:

```bash
cargo test --workspace --no-run
```

## Acceptance Criteria

This cleanup is complete when:

1. Coordinated shutdown intent is recorded before IPC/server tasks are asked to return.
2. Normal `MasterShutdown` does not produce `UnexpectedCompletion` for IPC or server tasks.
3. Typed IPC completion is consumed by supervision or replaced by a lifecycle-event channel.
4. `WorkerShutdownCause` is the authoritative source for exit code and notification policy.
5. Server completion while active is treated as abnormal.
6. Server completion after coordinated shutdown is treated as expected.
7. `graceful` and `timeout_secs` drive the actual drain path.
8. `ShutdownComplete` is sent only after all registry-owned tasks stop and final persistence completes.
9. Final bandwidth persistence has one documented owner.
10. Normal `MasterShutdown` exits zero without critical-failure classification.
11. Supervisor disconnect and server failure exit nonzero.
12. Resize preserves its special exit code and expected completion semantics.
13. End-to-end MasterShutdown coverage verifies ordering and no surviving tasks.
14. Existing request-path, blocklist, threat-intel, provenance, mesh-ID, composition, and task-ownership guardrails remain green.

## Notes for the Implementer

This should be the final correctness cleanup for the initial structured-concurrency track.

Do not migrate more tasks until expected shutdown completion, process outcome selection, and acknowledgement ordering are all mechanically correct.

The desired end state is:

- tasks know whether their completion is expected;
- the composition root owns shutdown ordering;
- the supervisor is told “complete” only when shutdown is actually complete;
- one typed cause determines worker exit behavior.
