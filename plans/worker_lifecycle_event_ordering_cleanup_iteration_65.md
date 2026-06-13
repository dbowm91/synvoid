# Worker Lifecycle Event Ordering Cleanup — Iteration 65

## Purpose

Iteration 64 moved worker shutdown orchestration into the composition root, separated shutdown intent from cancellation, made `WorkerShutdownCause` authoritative for exit status, delayed `UnifiedServerWorkerShutdownComplete` until after registry joins, and consolidated bandwidth persistence ownership.

The remaining issues are narrow but correctness-sensitive:

1. The IPC task still writes a lifecycle event into shared state and immediately returns before the composition root calls `WorkerTaskRegistry::begin_shutdown()`. The registry wrapper can therefore classify normal `MasterShutdown` or resize completion as `UnexpectedCompletion`.
2. Resize currently flows through the generic shutdown-complete acknowledgement path instead of restoring the dedicated resize acknowledgement.
3. Legacy `state.task_handles` are aborted but not awaited before shutdown completion is reported.
4. Fatal causes suppress normal shutdown-complete, but the composition root does not consistently send an explicit worker error when IPC remains available.

This pass should close those final ordering and acknowledgement gaps without broadening the structured-concurrency scope.

The invariant is:

> Lifecycle intent must reach the composition root before the emitting critical task returns, and no completion acknowledgement may be sent while any owned task is still terminating.

## Current Known State

At `25393d4aba66df71c7090845a3bfbbacf2505bb9`:

- `WorkerTaskRegistry::begin_shutdown()` and `broadcast_shutdown()` are separate.
- The composition root owns the ordered shutdown sequence.
- `WorkerShutdownCause::exit_code()` is authoritative.
- `WorkerLifecycleEvent` is stored in `Arc<RwLock<Option<...>>>` by the IPC task.
- The IPC task returns immediately after writing `MasterShutdown`, `WorkerResize`, or `SupervisorDisconnected`.
- The composition root learns the lifecycle event only after the task exit reaches the registry exit channel.
- `UnifiedServerWorkerShutdownComplete` is sent after registry shutdown.
- Resize no longer visibly emits `UnifiedServerWorkerResizeAck`.
- Legacy task handles are aborted but not awaited.

## Non-Goals

Do not migrate additional background tasks.

Do not redesign the registry.

Do not change blocklist, threat-intel, mesh-ID, request-path, or composition-root boundaries.

Do not add automatic task restart.

Do not replace Tokio IPC primitives.

Do not change supervisor protocol messages beyond restoring correct acknowledgement routing.

## Phase 1 — Replace Shared Lifecycle State With A Real Event Channel

Replace:

```rust
Arc<RwLock<Option<WorkerLifecycleEvent>>>
```

with an explicit channel from IPC task to composition root.

Recommended:

```rust
let (lifecycle_tx, mut lifecycle_rx) = tokio::sync::mpsc::channel::<WorkerLifecycleEvent>(4);
```

or `oneshot` if exactly one terminal lifecycle event is allowed.

Preferred model:

- IPC loop sends terminal lifecycle event.
- IPC loop then waits for registry cancellation or coordinator acknowledgement instead of immediately returning.
- Composition root receives event directly in its supervision `select!`.
- Composition root calls `begin_shutdown()` before any critical task is allowed to return.

Suggested event variants:

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

## Phase 2 — Add Coordinator Acknowledgement To IPC Task

For expected lifecycle events, the IPC task should not return immediately after send.

Suggested handshake:

```rust
pub struct LifecycleRequest {
    pub event: WorkerLifecycleEvent,
    pub accepted: oneshot::Sender<()>,
}
```

IPC flow:

1. Receive `MasterShutdown` or resize.
2. Send lifecycle request to composition root.
3. Await `accepted` acknowledgement or registry cancellation.
4. Return only after the composition root has called `begin_shutdown()`.

Minimal acceptable alternative:

- IPC task receives a narrow `ShutdownIntentHandle` exposing only `begin_shutdown()`.
- It calls `begin_shutdown()` before sending the lifecycle event and returning.

Preferred outcome remains composition-root acknowledgement because it keeps process shutdown ownership in one place.

## Phase 3 — Supervise Lifecycle Events And Task Exits Together

Update the main supervision loop to select over:

- registry task exits;
- lifecycle events from IPC;
- lifecycle channel closure.

Suggested shape:

```rust
let preliminary_cause = loop {
    tokio::select! {
        event = lifecycle_rx.recv() => {
            match event {
                Some(event) => {
                    registry.begin_shutdown();
                    acknowledge_event();
                    break cause_from_event(event);
                }
                None => {
                    break WorkerShutdownCause::RegistryExitChannelClosed;
                }
            }
        }
        exit = exit_rx.recv() => {
            // existing fatality handling
        }
    }
};
```

Required ordering:

1. lifecycle event arrives;
2. composition root calls `begin_shutdown()`;
3. IPC task is released to return;
4. IPC task completion is classified cleanly;
5. composition root proceeds with teardown.

## Phase 4 — Remove Or Retire `IpcLoopExitCause`

The old `IpcLoopExitCause` side channel is now redundant.

Preferred:

- remove the type and related methods entirely;
- remove documentation describing it;
- remove any returned/discarded values.

If retained temporarily, mark deprecated and ensure no runtime logic depends on it.

Do not keep two lifecycle signaling mechanisms active.

## Phase 5 — Add A Real MasterShutdown Classification Test

Add an integration test that exercises the actual runtime ordering.

Required scenario:

1. Create registry and subscribe to exit events.
2. Spawn an IPC-like critical task using the real lifecycle handshake.
3. Send `MasterShutdown` event.
4. Composition root receives event and calls `begin_shutdown()`.
5. IPC task returns.
6. Assert exit reason is `CleanCompletion`, not `UnexpectedCompletion`.
7. Assert `tasks_unexpectedly_completed == 0`.
8. Assert no `CriticalTaskExit` is selected.

This must not manually call `begin_shutdown()` before the event is emitted.

## Phase 6 — Restore Dedicated Resize Acknowledgement

Audit the supervisor protocol for resize.

For:

```rust
WorkerShutdownCause::WorkerResize { worker_threads }
```

send:

```rust
Message::UnifiedServerWorkerResizeAck {
    id: worker_id,
    worker_threads,
}
```

or the exact existing schema.

Do not send `UnifiedServerWorkerShutdownComplete` for resize unless the protocol explicitly requires both.

Acknowledgement routing:

- `SupervisorShutdown` -> `UnifiedServerWorkerShutdownComplete`
- `WorkerResize { .. }` -> `UnifiedServerWorkerResizeAck`
- fatal cause with live IPC -> `WorkerError`
- `SupervisorDisconnected` -> no send
- external/local stop -> no supervisor acknowledgement unless existing protocol requires it

Add tests asserting the message type per cause.

## Phase 7 — Abort And Await Legacy Handles

Replace the current abort-only loop over `state.task_handles`.

Required shape:

```rust
let handles = {
    let mut guard = state.task_handles.lock().await;
    std::mem::take(&mut *guard)
};

for handle in handles {
    handle.abort();
    let _ = handle.await;
}
```

Prefer a bounded shared deadline if legacy tasks can resist abort cleanup due to nested blocking work.

Required semantics:

- no legacy handle remains in the vector after shutdown;
- every aborted handle is awaited;
- shutdown acknowledgement is sent only afterward.

Add a drop-guard test proving legacy task resources are released before completion acknowledgement.

## Phase 8 — Add Explicit Fatal Supervisor Notification

When `shutdown_cause.should_notify_supervisor()` is true and IPC is still usable, send a structured worker error before closing down.

Suggested mapping:

- `CriticalTaskExit` -> critical worker error with task name/reason;
- `RegistryExitChannelClosed` -> lifecycle infrastructure failure;
- `ServerExitedUnexpectedly` -> server runtime failure;
- `SupervisorDisconnected` -> skip send because channel is unavailable.

Use existing:

```rust
Message::WorkerError {
    id,
    error,
    severity,
    error_code,
}
```

Avoid sending both `WorkerError` and normal completion acknowledgement for the same cause.

## Phase 9 — Make Acknowledgement Routing Explicit

Extract a helper:

```rust
async fn notify_supervisor_of_worker_exit(
    state: &UnifiedServerWorkerState,
    cause: &WorkerShutdownCause,
) -> Result<(), IpcError>
```

This helper should encode the routing table rather than relying on a boolean condition around one message type.

Suggested behavior:

```text
SupervisorShutdown        -> ShutdownComplete
WorkerResize              -> ResizeAck
CriticalTaskExit          -> WorkerError
ServerExitedUnexpectedly  -> WorkerError
RegistryExitChannelClosed -> WorkerError
SupervisorDisconnected    -> no-op
ExternalStop              -> no-op
RunningFlagCleared        -> no-op or existing expected protocol
ServerStoppedForShutdown  -> no-op unless paired with supervisor shutdown
```

## Phase 10 — Verify Shutdown Ordering

Add an event recorder in tests.

Expected order for `MasterShutdown`:

1. lifecycle event received;
2. shutdown intent recorded;
3. stop accepting;
4. graceful drain;
5. app servers stop;
6. running flag clears;
7. registry cancellation broadcast;
8. registry tasks join/abort;
9. legacy handles abort and join;
10. bandwidth final flush complete;
11. shutdown-complete sent.

Expected order for resize:

1. lifecycle event received;
2. shutdown intent recorded;
3. stop accepting;
4. drain if required;
5. stop services;
6. join tasks;
7. resize acknowledgement sent;
8. exit code 100.

## Phase 11 — Strengthen Guardrails

Update `tests/background_task_ownership_guard.rs`.

Add source-level checks:

- IPC terminal lifecycle branches must not `return Ok(())` immediately after only writing shared state.
- lifecycle signaling must use a channel or explicit coordinator acknowledgement.
- `IpcLoopExitCause` must not remain as an unused side channel.
- resize cause must route to resize acknowledgement.
- legacy handles must be awaited after abort.
- fatal causes must not route to normal shutdown-complete.

Behavioral tests remain authoritative.

## Phase 12 — Documentation Cleanup

Update:

- `architecture/worker_task_lifecycle.md`
- `docs/adr/ADR-003-unified-worker-process.md`
- `AGENTS.md`
- `src/worker/AGENTS.override.md`

Document:

- lifecycle-event handshake ordering;
- why event delivery must precede critical-task return;
- acknowledgement routing by `WorkerShutdownCause`;
- legacy-handle abort-and-await policy;
- fatal supervisor notification behavior;
- removal of `IpcLoopExitCause` if removed.

## Phase 13 — Verification Commands

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

If IPC message schemas or process coordination types change:

```bash
cargo test --workspace --no-run
```

## Acceptance Criteria

This cleanup is complete when:

1. IPC lifecycle signaling uses a real channel or equivalent handshake.
2. `begin_shutdown()` is called before expected IPC/server task return.
3. Real `MasterShutdown` produces clean task completion, not `UnexpectedCompletion`.
4. Normal shutdown does not increment unexpected-completion metrics.
5. `IpcLoopExitCause` is removed or no longer redundant/unused.
6. Resize sends the dedicated resize acknowledgement.
7. `ShutdownComplete` is reserved for actual supervisor shutdown completion.
8. Legacy handles are aborted and awaited before acknowledgement.
9. Fatal causes send `WorkerError` when IPC remains available.
10. Supervisor disconnect performs no impossible notification attempt.
11. Tests verify exact shutdown and acknowledgement ordering.
12. Existing request-path, blocklist, threat-intel, provenance, mesh-ID, composition, and task-ownership guardrails remain green.

## Notes for the Implementer

This should close the initial structured-concurrency track.

Do not add more task migrations in this iteration. The only target is to make lifecycle intent delivery, task completion classification, and supervisor acknowledgement ordering mechanically correct.
