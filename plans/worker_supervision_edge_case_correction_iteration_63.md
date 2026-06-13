# Worker Supervision Edge-Case Correction — Iteration 63

## Purpose

Iteration 62 corrected the original timeout defect and established real runtime integration for `WorkerTaskRegistry`. Heartbeat, bandwidth persistence, and the supervisor/worker IPC loop are now registry-owned; timeout paths explicitly abort and await tasks; immediate exit notifications are available through `subscribe_exits()`.

The remaining risk is in the worker supervision control flow rather than the registry’s basic ownership model.

Current review identified five edge cases:

1. The unified worker’s main `select!` exits on any task notification, including noncritical background exits and broadcast receiver errors.
2. The exit receiver is subscribed after supervised tasks are spawned, leaving a race where early exits can be missed.
3. `TaskExitReason::UnexpectedCompletion` exists but successful task returns are always classified as clean and expected.
4. The unified-server run task remains outside the registry and can be detached when the critical-exit branch wins the `select!`.
5. Bandwidth persistence does not guarantee a final flush on every shutdown cause.

This pass should correct these supervision edge cases without broadening into another large task-migration wave.

The invariant is:

> Supervision must distinguish critical from noncritical exits, retain ownership of every task across branch selection, and preserve required finalization for every shutdown cause.

## Current Known State

At commit `50b128abab50c7bbd1af81ace0403341b957b064`:

- `WorkerTaskRegistry::join_task_until()` aborts and awaits timed-out tasks.
- Shared-deadline exhaustion paths also abort and await remaining tasks.
- `NamedTaskExit`, `TaskId`, `TaskExitReason`, and exit broadcasts exist.
- Exit metrics are deduplicated through `reported_exits`.
- `UnifiedServerWorkerState` owns `Arc<TokioMutex<WorkerTaskRegistry>>`.
- Heartbeat and bandwidth persistence are registered as background tasks.
- IPC loop is registered as a critical task.
- Unified worker subscribes to task exits and selects between server completion and one received exit.
- The unified-server run task still returns a raw `JoinHandle<()>`.
- `ThreatFeedClient` has accurate `is_running()` and bounded `join_with_timeout()`.

## Non-Goals

Do not migrate every remaining task.

Do not redesign the supervisor protocol.

Do not add automatic restart for all background tasks.

Do not change request-path behavior.

Do not change blocklist, threat-intel, mesh-ID, or composition-root semantics.

Do not replace Tokio broadcast/watch primitives unless necessary.

Do not introduce a full process-wide service orchestrator.

## Phase 1 — Subscribe Before Spawning Supervised Tasks

Move exit-receiver creation before the first supervised task is spawned.

Current risky order:

```rust
spawn heartbeat
spawn bandwidth
spawn ipc
subscribe_exits()
```

Required order:

```rust
let mut exit_rx = registry.subscribe_exits();
spawn heartbeat
spawn bandwidth
spawn ipc
```

Implementation constraints:

- Hold the registry lock only long enough to subscribe and register tasks.
- Do not hold the registry lock while awaiting worker runtime events.
- Ensure every supervised task has at least one live receiver before it can complete.

Add a regression test where a critical task exits immediately after spawn and confirm the worker-side receiver observes it.

## Phase 2 — Replace One-Shot `select!` With A Supervision Loop

The current worker `select!` terminates on the first exit notification regardless of task class.

Replace it with a loop that continues on nonfatal events.

Suggested shape:

```rust
let shutdown_cause = loop {
    tokio::select! {
        result = &mut server_handle => {
            break WorkerShutdownCause::ServerExited(result);
        }
        event = exit_rx.recv() => {
            match event {
                Ok(exit) if is_fatal_critical_exit(&exit, registry_shutdown_started) => {
                    break WorkerShutdownCause::CriticalTaskExit(exit);
                }
                Ok(exit) => {
                    handle_noncritical_exit(exit);
                    continue;
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    handle_exit_receiver_lag(skipped);
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    break WorkerShutdownCause::RegistryExitChannelClosed;
                }
            }
        }
    }
};
```

Required behavior:

- Noncritical background exits do not automatically stop the worker.
- Critical panic/error/unexpected completion initiates shutdown.
- Expected task completion during coordinated shutdown does not trigger a second fatal path.
- Receiver lag is not silently treated as successful completion.
- Closed exit channel has an explicit policy.

## Phase 3 — Define `WorkerShutdownCause`

Introduce an explicit shutdown-cause enum in the unified worker lifecycle.

Suggested shape:

```rust
pub enum WorkerShutdownCause {
    ServerExited(Result<(), ServerRunError>),
    CriticalTaskExit(NamedTaskExit),
    SupervisorShutdown,
    SupervisorDisconnected,
    RegistryExitChannelClosed,
    ExternalStop,
}
```

The exact type may be simpler, but shutdown cause should be explicit enough to drive:

- exit code;
- log severity;
- whether final shutdown is expected;
- whether supervisor notification is possible;
- metrics/diagnostics.

Avoid deriving shutdown behavior only from scattered flags.

## Phase 4 — Implement Real `UnexpectedCompletion`

`TaskExitReason::UnexpectedCompletion` must reflect pre-shutdown successful return of a long-lived task.

Pass shared shutdown state into task wrappers.

Suggested registry state:

```rust
shutdown_started: Arc<AtomicBool>
```

Spawn wrapper logic:

```rust
let shutdown_started = Arc::clone(&self.shutdown_started);

let exit = match result {
    Ok(()) if shutdown_started.load(Ordering::Acquire) => NamedTaskExit {
        reason: TaskExitReason::CleanCompletion,
        expected_during_shutdown: true,
        ..
    },
    Ok(()) => NamedTaskExit {
        reason: TaskExitReason::UnexpectedCompletion,
        expected_during_shutdown: false,
        ..
    },
    ...
};
```

For `Result`-returning tasks:

- `Ok(Ok(()))` before shutdown -> `UnexpectedCompletion`.
- `Ok(Ok(()))` during shutdown -> `CleanCompletion`.
- `Ok(Err(e))` -> `Error`.
- panic -> `Panic`.

Metrics:

- Add `tasks_unexpectedly_completed` if useful.
- Do not count pre-shutdown critical return as clean completion.
- Preserve no-double-count behavior.

Tests:

- critical task returning before shutdown -> `UnexpectedCompletion`.
- background task returning before shutdown -> `UnexpectedCompletion`.
- cancellation-aware task returning after shutdown -> `CleanCompletion` or `Cancelled`, per chosen convention.

## Phase 5 — Define Fatality Policy By Class And Reason

Add a helper:

```rust
fn is_fatal_exit(exit: &NamedTaskExit, shutdown_started: bool) -> bool
```

Recommended policy:

### CriticalService

Fatal before shutdown when reason is:

- `UnexpectedCompletion`
- `Panic`
- `Error`
- possibly `Cancelled` if cancellation was not requested

Not fatal when:

- `CleanCompletion` during shutdown
- expected cancellation during shutdown

### RestartableBackground

Not immediately fatal by default.

- Log `UnexpectedCompletion`, `Panic`, or `Error`.
- Increment metrics.
- Mark subsystem degraded if a health model exists.
- Leave restart policy for a later iteration unless a specific task already has one.

### BoundedChild / CpuOffload / Detached

Not part of this worker-level exit channel in this iteration unless already registered.

Document the policy in `architecture/worker_task_lifecycle.md`.

## Phase 6 — Bring The Unified-Server Run Task Under Explicit Ownership

The raw `server_handle` must not be detached if another supervision branch wins.

Choose one outcome.

### Preferred Outcome A — Registry-Owned Critical Server Task

Register the unified-server run future as `CriticalService` through `spawn_critical_result()`.

Benefits:

- one ownership model;
- immediate exit notification;
- bounded shutdown/abort-and-await already implemented;
- no separate raw `JoinHandle` branch.

Challenges:

- Need a distinct way to recognize server task identity in the supervision loop.
- Server normal return may represent shutdown completion and must not be misclassified if shutdown already began.

### Acceptable Outcome B — Explicitly Managed Raw Handle

Keep the server handle outside the registry, but:

- declare it `mut`;
- await it by reference in the supervision loop;
- after another shutdown cause wins, trigger server shutdown;
- await it with timeout;
- abort and await if timeout expires.

Do not drop the handle while the underlying task is running.

Recommended: Outcome A unless server shutdown wiring makes registry ownership awkward.

## Phase 7 — Add A Server Shutdown Contract

Ensure the worker can actively tell `UnifiedServer::run()` to stop rather than only setting `RunningFlag`.

Audit existing mechanisms:

- stop-accepting sender;
- server shutdown broadcast;
- listener-specific shutdown channels;
- `UnifiedServer` shutdown method if present.

Required behavior on critical-task failure:

1. Stop accepting new work.
2. Signal server/listener shutdown.
3. Drain or wait within configured bound.
4. Await server task.
5. Abort and await on timeout.

If no single server shutdown method exists, add a narrow orchestration helper at the composition root rather than leaking lifecycle details into task registry.

## Phase 8 — Guarantee Final Bandwidth Persistence

The bandwidth task must flush on every shutdown path.

Preferred implementation:

```rust
loop {
    tokio::select! {
        _ = interval.tick() => persist(),
        _ = shutdown.changed() => break,
    }
}

persist_global_bandwidth_tracker();
```

This ensures:

- supervisor-requested shutdown flushes;
- server failure flushes;
- critical IPC panic flushes;
- registry-triggered shutdown flushes.

Avoid double-flush concerns unless persistence is non-idempotent. If needed, centralize final flush in shutdown orchestration and remove duplicate IPC-branch flush.

Tests:

- normal registry shutdown performs final flush.
- critical task failure path performs final flush.
- server task failure path performs final flush.
- no persistence call occurs after bandwidth task join returns.

Use an injectable/test persistence callback if the global function is difficult to observe.

## Phase 9 — Handle Broadcast Receiver Errors Explicitly

`broadcast::Receiver::recv()` can return `Lagged` or `Closed`.

Required policy:

### Lagged

- Log the number of skipped exit events.
- Treat loss of critical exit information conservatively.
- Recommended: inspect registry state or trigger controlled worker shutdown because supervision integrity has been compromised.
- Alternative: continue only if an internal registry snapshot can prove no unseen critical failure occurred.

### Closed

- If registry is shutting down normally, treat as expected.
- If registry is active, treat as lifecycle infrastructure failure and initiate shutdown.

Do not let either error simply fall through and terminate the main select without a classified cause.

## Phase 10 — Remove Shutdown Races

Audit interactions among:

- `state.running.stop()`;
- `master_dead.stop()`;
- IPC `MasterShutdown` handling;
- critical exit notification;
- server completion;
- registry `shutdown()`;
- worker exit code updates.

Required properties:

- only one primary shutdown cause is selected;
- later expected task exits do not overwrite the primary cause;
- `MasterShutdown` does not get logged as a critical task failure simply because IPC loop returns afterward;
- supervisor disconnect still sets nonzero exit code;
- server error sets an appropriate exit code;
- normal shutdown remains zero exit code.

Use `WorkerShutdownCause` as the source of truth where possible.

## Phase 11 — Correct IPC Loop Completion Semantics

The IPC loop is critical, but some returns are expected.

Expected cases:

- `MasterShutdown` processed successfully;
- resize/restart command processed;
- registry cancellation during coordinated shutdown;
- worker running flag intentionally cleared.

Unexpected cases:

- supervisor connection lost;
- panic;
- task returns without a shutdown/resize/disconnect cause;

Recommended approach:

Use `spawn_critical_result()` and return a typed result:

```rust
Result<IpcLoopExit, IpcLoopError>
```

or map expected exits to explicit worker shutdown causes before returning.

At minimum, record an atomic/shared expected-exit marker so a normal `MasterShutdown` does not become `UnexpectedCompletion`.

Prefer typed completion over fragile flag inference.

## Phase 12 — Integration Tests For Supervision Control Flow

Add focused tests around the supervision loop, preferably by extracting it into a testable helper.

Suggested helper:

```rust
async fn supervise_worker_tasks(
    server: ManagedServerTask,
    exit_rx: broadcast::Receiver<NamedTaskExit>,
    shutdown_state: ...,
) -> WorkerShutdownCause
```

Required scenarios:

1. Background task exits unexpectedly; worker remains running.
2. Critical task panics; worker begins shutdown.
3. Critical task returns unexpectedly; worker begins shutdown.
4. Critical task exits immediately after spawn; pre-created receiver observes it.
5. Receiver reports `Lagged`; configured conservative policy is applied.
6. Receiver closes while registry active; worker shuts down.
7. Normal `MasterShutdown`; IPC completion is expected and exit code remains zero.
8. Supervisor disconnect; nonzero exit code is preserved.
9. Server task exits first; all registry tasks are cancelled and joined.
10. Critical task exits first; server task is shut down and joined/aborted.
11. No owned task remains after worker shutdown returns.

## Phase 13 — Registry Tests

Extend `src/worker/task_registry.rs` tests.

Add:

- `test_pre_shutdown_unit_return_is_unexpected_completion`
- `test_post_shutdown_unit_return_is_clean_completion`
- `test_result_task_pre_shutdown_ok_is_unexpected_completion`
- `test_background_exit_notification_does_not_imply_fatality`
- `test_exit_receiver_subscribed_before_spawn_observes_immediate_exit`
- `test_abort_path_does_not_emit_duplicate_exit_metrics`

Remove debug `eprintln!` statements from unit tests unless intentionally needed.

## Phase 14 — Guardrail Updates

Update `tests/background_task_ownership_guard.rs`.

Guardrail additions:

- server run task must be registry-owned or explicitly managed with abort-and-await semantics;
- unified worker must subscribe before registry task spawning;
- supervision loop must handle noncritical exits without unconditional shutdown;
- bandwidth persistence task must contain final-flush behavior;
- forbid dropping a raw server `JoinHandle` through one-shot `select!` without a documented join path.

Source-scan heuristics are acceptable, but tests should also cover behavior directly.

## Phase 15 — Documentation Updates

Update:

- `architecture/worker_task_lifecycle.md`
- `docs/adr/ADR-003-unified-worker-process.md`
- `architecture/worker_data_plane_composition_root.md`
- `AGENTS.md`
- `src/worker/AGENTS.override.md`

Document:

- subscription-before-spawn invariant;
- fatality policy by task class/reason;
- true `UnexpectedCompletion` semantics;
- server task ownership;
- broadcast lag/closure policy;
- final persistence guarantees;
- primary shutdown-cause selection.

Do not state that every background task is restartable unless restart behavior actually exists.

## Phase 16 — Verification Commands

Run:

```bash
cargo test worker::task_registry
cargo test unified_server --lib
cargo test threat_feed
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

If server lifecycle signatures or registry output types change:

```bash
cargo test --workspace --no-run
```

## Acceptance Criteria

This pass is complete when:

1. Exit receiver is subscribed before supervised tasks are spawned.
2. The worker supervision loop does not terminate on ordinary background-task exits.
3. Critical panic/error/unexpected completion initiates shutdown immediately.
4. `UnexpectedCompletion` is produced for successful pre-shutdown returns.
5. Expected shutdown returns remain clean/expected.
6. The unified-server run task cannot be detached by branch selection.
7. Server shutdown is explicit, bounded, and joined or aborted-and-awaited.
8. Bandwidth persistence performs a final flush for every shutdown cause.
9. Broadcast lag/closure has explicit conservative handling.
10. Normal `MasterShutdown` is not misclassified as critical failure.
11. Supervisor disconnect and server failure retain correct nonzero exit behavior.
12. Tests prove background exit does not stop the worker.
13. Tests prove critical exit does stop the worker.
14. Tests prove no owned server or registry task survives shutdown.
15. Existing request-path, blocklist, threat-intel, provenance, and mesh-ID guardrails remain green.

## Notes for the Implementer

This is a supervision-control correction, not a migration wave.

Fix the control-flow invariants first. Do not add more registry-owned tasks until the worker can reliably distinguish background degradation, critical failure, normal shutdown, and server completion.
