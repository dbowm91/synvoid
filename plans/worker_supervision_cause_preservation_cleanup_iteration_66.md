# Worker Supervision Cause Preservation Cleanup — Iteration 66

## Purpose

Iteration 65 fixed the lifecycle-event ordering problem: the IPC task now sends a `LifecycleRequest` over an `mpsc` channel, waits for a oneshot acknowledgement, and returns only after the composition root has called `WorkerTaskRegistry::begin_shutdown()`. Resize acknowledgement, fatal-notification routing, and legacy-handle abort-and-await behavior also landed.

One final correctness defect remains in the worker supervision loop: direct task failures and registry-channel failures are collapsed into `WorkerLifecycleEvent::SupervisorDisconnected` before the composition root maps them to `WorkerShutdownCause`. This discards the real cause and makes the new cause-specific notification branches effectively unreachable.

This pass should preserve direct shutdown causes through the supervision loop, make lifecycle-channel delivery failures explicit, and add behavioral tests proving that server failure, critical-task failure, registry-channel failure, and supervisor disconnection remain distinct end-to-end.

The invariant is:

> The primary shutdown cause selected by supervision must preserve the original failing subsystem, task identity, and failure reason through final notification and exit-code selection.

## Current Known State

At `d66c0f8f9ab831eae349ef515fc76030bb0dcec0`:

- `LifecycleRequest` uses an `mpsc` channel plus oneshot acknowledgement.
- IPC expected lifecycle events are acknowledged only after `begin_shutdown()`.
- Normal `MasterShutdown` can now classify IPC completion as clean.
- Resize routes to `UnifiedServerWorkerResizeAck`.
- Legacy handles are aborted and awaited.
- Fatal-cause notification branches exist for:
  - `CriticalTaskExit`
  - `ServerExitedUnexpectedly`
  - `RegistryExitChannelClosed`
- `SupervisorDisconnected` intentionally sends no notification.

Known defect:

- Any fatal `NamedTaskExit` currently becomes `WorkerLifecycleEvent::SupervisorDisconnected` in the supervision loop.
- Broadcast lag and unexpected exit-channel closure also become `SupervisorDisconnected`.
- The composition root maps that event to `WorkerShutdownCause::SupervisorDisconnected`.
- Actual `CriticalTaskExit`, `ServerExitedUnexpectedly`, and `RegistryExitChannelClosed` runtime causes are lost.

Secondary defect:

- IPC lifecycle sends ignore `lifecycle_tx.send(...)` failures and then await the oneshot receiver.
- Channel closure is not returned as an explicit IPC/lifecycle error.

## Non-Goals

Do not migrate additional tasks.

Do not redesign `WorkerTaskRegistry` ownership or timeout semantics.

Do not alter the successful lifecycle-event handshake for `MasterShutdown` and resize.

Do not change blocklist, threat-intel, mesh-ID, request-path, or composition-root dependency boundaries.

Do not add automatic restart policy.

Do not change supervisor message schemas unless required for an existing error code.

## Phase 1 — Introduce A Typed Supervision Outcome

Replace the supervision loop’s current implicit `(WorkerLifecycleEvent, Option<oneshot::Sender<()>>)` result with a type that can carry either an IPC lifecycle request or a direct worker shutdown cause.

Recommended shape:

```rust
pub enum SupervisionOutcome {
    Lifecycle {
        event: WorkerLifecycleEvent,
        accepted: tokio::sync::oneshot::Sender<()>,
    },
    DirectCause(WorkerShutdownCause),
}
```

If lifecycle channel closure can produce an expected transition, allow:

```rust
LifecycleChannelClosed {
    shutdown_started: bool,
}
```

but prefer mapping it immediately to a direct `WorkerShutdownCause`.

Required properties:

- Lifecycle events retain their acknowledgement sender.
- Task failures retain the full `NamedTaskExit`.
- Registry infrastructure failures retain their own cause.
- No direct failure is converted into a fake `SupervisorDisconnected` event.

## Phase 2 — Preserve Fatal Task Exit Identity

Update the task-exit branch.

Required mapping:

```rust
if is_fatal_exit(&exit, shutdown_started) {
    let cause = if exit.name == "server_run" {
        WorkerShutdownCause::ServerExitedUnexpectedly
    } else if exit.name == "ipc_loop"
        && matches!(exit.reason, TaskExitReason::Error(ref msg) if msg.contains("connection_lost"))
    {
        WorkerShutdownCause::SupervisorDisconnected
    } else {
        WorkerShutdownCause::CriticalTaskExit(exit)
    };

    break SupervisionOutcome::DirectCause(cause);
}
```

Avoid brittle string inspection if possible. Preferred alternatives:

- preserve typed `IpcLoopError` metadata through the registry exit record;
- or let the IPC loop send `WorkerLifecycleEvent::SupervisorDisconnected` first, then treat its subsequent task exit as expected/non-primary.

Preferred final behavior:

- `server_run` unexpected completion/error/panic -> `ServerExitedUnexpectedly`.
- non-IPC critical task failure -> `CriticalTaskExit(NamedTaskExit)`.
- IPC connection loss -> `SupervisorDisconnected`.
- IPC panic unrelated to connection loss -> `CriticalTaskExit`.

## Phase 3 — Keep Supervisor Disconnect On The Lifecycle Path

The IPC loop already sends a `SupervisorDisconnected` lifecycle event before returning `Err(IpcLoopError::ConnectionLost)`.

Use that event as the authoritative cause.

Required ordering:

1. IPC detects connection loss.
2. IPC sends `LifecycleRequest { event: SupervisorDisconnected, accepted }`.
3. Composition root receives it and records `begin_shutdown()`.
4. Composition root acknowledges.
5. IPC returns its connection-loss error.
6. Later IPC task exit does not replace the primary cause.

This avoids parsing task-error strings and ensures no supervisor notification is attempted.

The supervision loop should stop selecting new primary causes after a lifecycle event wins.

## Phase 4 — Map Registry Receiver Failures Correctly

Update exit-channel error handling.

### `RecvError::Lagged(skipped)`

Map to:

```rust
WorkerShutdownCause::RegistryExitChannelClosed
```

or introduce a more precise variant:

```rust
WorkerShutdownCause::RegistryExitStreamLagged { skipped: u64 }
```

A dedicated variant is preferable if it materially improves diagnostics, but not required.

### `RecvError::Closed`

- If shutdown intent is already recorded, treat as an expected shutdown-side condition and continue only if another authoritative cause already exists.
- If no shutdown is active, map to `RegistryExitChannelClosed`.

Do not map either case to `SupervisorDisconnected`.

## Phase 5 — Make Lifecycle Channel Closure Explicit

Handle `lifecycle_rx.recv() == None` separately from supervisor disconnection.

Recommended policy:

- If registry shutdown has already started and an authoritative cause is known, ignore channel closure.
- If active and IPC task/channel disappears without a lifecycle request, classify as:
  - `CriticalTaskExit` if an IPC exit record is available; or
  - `RegistryExitChannelClosed` / a new `LifecycleChannelClosed` cause.

Do not synthesize a graceful `MasterShutdown` event.

The current fallback that manufactures:

```rust
WorkerLifecycleEvent::MasterShutdown {
    graceful: true,
    timeout: Duration::from_secs(30),
}
```

should be removed. Channel closure is not evidence of supervisor-requested graceful shutdown.

## Phase 6 — Refactor Cause Selection Into A Testable Helper

Extract supervision mapping logic from `run_unified_server_worker()`.

Suggested helper:

```rust
fn map_task_exit_to_shutdown_cause(
    exit: NamedTaskExit,
    shutdown_started: bool,
) -> Option<WorkerShutdownCause>
```

and:

```rust
fn map_exit_recv_error_to_shutdown_cause(
    error: broadcast::error::RecvError,
    shutdown_started: bool,
) -> Option<WorkerShutdownCause>
```

Or extract the full async loop:

```rust
async fn supervise_worker(
    lifecycle_rx: &mut mpsc::Receiver<LifecycleRequest>,
    exit_rx: &mut broadcast::Receiver<NamedTaskExit>,
    shutdown_flag: Arc<AtomicBool>,
) -> SupervisionOutcome
```

Preferred: extract the full loop so behavioral tests exercise actual branch ordering.

## Phase 7 — Remove Cause Re-Mapping Through `WorkerLifecycleEvent`

After supervision returns:

```rust
match outcome {
    SupervisionOutcome::Lifecycle { event, accepted } => {
        registry.begin_shutdown();
        let cause = WorkerShutdownCause::from(event);
        let _ = accepted.send(());
        ...
    }
    SupervisionOutcome::DirectCause(cause) => {
        registry.begin_shutdown();
        ...
    }
}
```

Do not convert direct causes back into lifecycle events and then remap them.

Add:

```rust
impl From<&WorkerLifecycleEvent> for WorkerShutdownCause
```

or a dedicated conversion helper for expected IPC-originated lifecycle events only.

## Phase 8 — Make IPC Lifecycle Send Failures Explicit

Replace ignored send results such as:

```rust
let _ = lifecycle_tx.send(request).await;
let _ = ack_rx.await;
```

with explicit error handling.

Suggested helper:

```rust
async fn request_lifecycle_transition(
    lifecycle_tx: &mpsc::Sender<LifecycleRequest>,
    event: WorkerLifecycleEvent,
) -> Result<(), IpcLoopError>
```

Implementation:

```rust
let (accepted, ack_rx) = oneshot::channel();
lifecycle_tx
    .send(LifecycleRequest { event, accepted })
    .await
    .map_err(|_| IpcLoopError::Unexpected(
        "worker lifecycle coordinator channel closed".to_string()
    ))?;

ack_rx.await.map_err(|_| {
    IpcLoopError::Unexpected(
        "worker lifecycle coordinator dropped acknowledgement".to_string()
    )
})
```

Required behavior:

- failed lifecycle send returns a typed IPC error;
- dropped acknowledgement returns a typed IPC error;
- neither failure silently masquerades as clean completion;
- error is visible in `NamedTaskExit` and final shutdown cause.

## Phase 9 — Preserve Fatal Notification Reachability

After cause preservation, verify runtime reachability of notification arms.

Required routes:

- `CriticalTaskExit(exit)` -> `WorkerError` including task name and reason.
- `ServerExitedUnexpectedly` -> server-runtime `WorkerError`.
- `RegistryExitChannelClosed` -> lifecycle-infrastructure `WorkerError`.
- `SupervisorDisconnected` -> no notification.

Ensure `WorkerShutdownCause::should_notify_supervisor()` is consistent with explicit routing. Current semantics mark `SupervisorDisconnected` as notify-worthy even though routing intentionally skips it; correct this mismatch.

Recommended:

```rust
pub fn should_notify_supervisor(&self) -> bool {
    matches!(
        self,
        Self::CriticalTaskExit(_)
            | Self::ServerExitedUnexpectedly
            | Self::RegistryExitChannelClosed
    )
}
```

Update tests and docs accordingly.

## Phase 10 — Preserve Full Server Failure Details

`ServerExitedUnexpectedly` currently carries no error detail.

Consider changing to:

```rust
ServerExitedUnexpectedly {
    reason: TaskExitReason,
}
```

or retain the full `NamedTaskExit`:

```rust
ServerTaskExit(NamedTaskExit)
```

Benefits:

- final logs show panic/error/unexpected completion distinctly;
- supervisor `WorkerError` includes actual failure detail;
- no information is discarded.

Recommended if low-impact. Otherwise, log the `NamedTaskExit` before mapping and document the loss.

## Phase 11 — Add End-To-End Supervision Tests

Extend `tests/worker_supervision_control_flow.rs` with tests that drive the actual `SupervisionOutcome` helper.

### Critical Task Failure

- spawn a non-IPC critical task that returns `Err` or panics;
- supervision returns `DirectCause(CriticalTaskExit(...))`;
- task name/reason are preserved;
- final cause exit code is `1`;
- notification route is `WorkerError`.

### Server Failure

- spawn `server_run` that returns `Err`;
- supervision returns `ServerExitedUnexpectedly` or detailed server cause;
- it is not mapped to `SupervisorDisconnected`;
- exit code is `1`;
- notification route is server `WorkerError`.

### Registry Exit Lag

- force exit receiver lag;
- supervision returns `RegistryExitChannelClosed` or dedicated lag cause;
- it is not mapped to `SupervisorDisconnected`;
- notification route is lifecycle `WorkerError`.

### Registry Exit Closure

- close the exit channel before shutdown intent;
- cause is registry infrastructure failure;
- nonzero exit.

### Supervisor Disconnect

- deliver real lifecycle request for `SupervisorDisconnected`;
- cause remains `SupervisorDisconnected`;
- no notification is attempted;
- exit code is `1`.

### Normal MasterShutdown

- lifecycle request wins;
- cause is `SupervisorShutdown`;
- IPC task exits cleanly;
- no fatal cause replaces it.

### Competing Event Ordering

- lifecycle event and later IPC error occur close together;
- the lifecycle request selected first remains authoritative.

## Phase 12 — Test Lifecycle Channel Failure Paths

Add tests for:

- lifecycle receiver dropped before `MasterShutdown` send;
- acknowledgement sender dropped after request delivery;
- IPC task reports `IpcLoopError::Unexpected`;
- task exit becomes a real critical failure;
- no deadlock or indefinite wait occurs.

Use short timeouts in tests.

## Phase 13 — Strengthen Notification Tests

Current tests mostly inspect `WorkerShutdownCause` properties.

Extract acknowledgement/notification routing into a testable function or enum:

```rust
pub enum SupervisorExitNotification {
    ShutdownComplete,
    ResizeAck { worker_threads: usize },
    WorkerError { message: String, code: ErrorCode },
    None,
}
```

Then test exact mapping:

- shutdown -> `ShutdownComplete`;
- resize -> `ResizeAck`;
- critical task -> `WorkerError`;
- server failure -> `WorkerError`;
- registry failure -> `WorkerError`;
- supervisor disconnect -> `None`.

The actual IPC-send helper can consume this enum.

## Phase 14 — Guardrail Updates

Update `tests/background_task_ownership_guard.rs`.

Add checks that:

- fatal task exits are not converted to `SupervisorDisconnected`;
- `RegistryExitChannelClosed` is reachable from lag/closure paths;
- lifecycle channel closure does not synthesize `MasterShutdown`;
- lifecycle sends and acknowledgements are not ignored;
- `SupervisorDisconnected` is produced only by the IPC disconnect lifecycle path;
- cause-specific `WorkerError` branches remain reachable through supervision mapping.

Behavioral tests remain primary.

## Phase 15 — Documentation Cleanup

Update:

- `architecture/worker_task_lifecycle.md`
- `docs/adr/ADR-003-unified-worker-process.md`
- `AGENTS.md`
- `src/worker/AGENTS.override.md`

Document:

- `SupervisionOutcome` or equivalent typed outcome;
- distinction between IPC lifecycle events and direct task failures;
- primary-cause preservation rules;
- registry lag/closure policy;
- lifecycle send/ack failure behavior;
- supervisor notification reachability;
- corrected `should_notify_supervisor()` semantics.

## Phase 16 — Verification Commands

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

If shutdown-cause or IPC lifecycle types change across crates:

```bash
cargo test --workspace --no-run
```

## Acceptance Criteria

This cleanup is complete when:

1. The supervision loop returns a typed outcome that can preserve direct `WorkerShutdownCause` values.
2. Fatal critical task identity and reason survive through final shutdown handling.
3. Unexpected server exit is not misclassified as supervisor disconnection.
4. Registry lag/closure is not misclassified as supervisor disconnection.
5. Lifecycle channel closure does not synthesize graceful `MasterShutdown`.
6. IPC connection loss remains the only runtime path to `SupervisorDisconnected`.
7. Cause-specific `WorkerError` notification branches are reachable in behavioral tests.
8. Lifecycle send and acknowledgement failures return explicit `IpcLoopError` values.
9. `should_notify_supervisor()` matches actual notification routing.
10. Normal `MasterShutdown` and resize behavior remain clean and expected.
11. Tests cover competing lifecycle-event/task-exit ordering.
12. Existing request-path, blocklist, threat-intel, provenance, mesh-ID, composition, and task-ownership guardrails remain green.

## Notes for the Implementer

This is the final cause-preservation correction for the initial structured-concurrency work.

Do not add more task migrations. The goal is only to ensure that the lifecycle supervisor reports what actually failed, retains diagnostic context, and sends the correct final message to the supervisor.
