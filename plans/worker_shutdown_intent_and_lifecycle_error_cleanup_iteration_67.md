# Worker Shutdown Intent and Lifecycle Error Cleanup — Iteration 67

## Purpose

Iteration 66 fixed the primary supervision-cause preservation defect. The worker now distinguishes lifecycle requests from direct failures through `SupervisionOutcome`, preserves critical task identity through `CriticalTaskExit`, maps server failures to `ServerExitedUnexpectedly`, and maps registry-channel failures to `RegistryExitChannelClosed` rather than collapsing everything into `SupervisorDisconnected`.

Two narrow correctness issues remain:

1. `request_lifecycle_transition()` returns explicit `IpcLoopError` values, but the IPC loop still discards those results with `let _ = ...` and then returns its original result.
2. Direct-failure branches in the supervision loop call `state.running.stop()` before the composition root calls `WorkerTaskRegistry::begin_shutdown()`. Secondary task exits can therefore be misclassified as `UnexpectedCompletion` during the short transition window.

A smaller diagnostic improvement is also available: `ServerExitedUnexpectedly` currently drops the original `NamedTaskExit`, losing the exact panic/error/completion reason.

This pass should close those final lifecycle-ordering and error-propagation gaps without expanding into further task migration.

The invariant is:

> Failure selection must record coordinated shutdown intent before any shared stop signal can cause secondary tasks to return, and lifecycle-transition failures must propagate as real task failures rather than being discarded.

## Current Known State

At `81e7e96672168593c420f7ec8ea60549cb4ca92d`:

- `SupervisionOutcome` preserves lifecycle requests and direct causes.
- `map_task_exit_to_shutdown_cause()` preserves non-server critical task identity.
- `map_exit_recv_error_to_shutdown_cause()` maps lag/closure to registry failure.
- `map_lifecycle_channel_closed()` no longer synthesizes graceful shutdown.
- `request_lifecycle_transition()` converts lifecycle channel or acknowledgement closure into `IpcLoopError::Unexpected`.
- `should_notify_supervisor()` matches actual notification routing.
- Direct failures reach the composition root without being remapped through lifecycle events.

Known remaining issues:

- `MasterShutdown`, resize, and supervisor-disconnect call sites discard `request_lifecycle_transition()` errors.
- Direct failure branches call `state.running.stop()` before `begin_shutdown()`.
- Secondary service tasks can return in that interval and be recorded as unexpected completions.
- `ServerExitedUnexpectedly` carries no `NamedTaskExit` detail.

## Non-Goals

Do not migrate additional tasks.

Do not redesign `WorkerTaskRegistry`.

Do not alter timeout, abort, or join semantics.

Do not change the lifecycle request/oneshot handshake design.

Do not change blocklist, threat-intel, mesh-ID, request-path, or composition-root boundaries.

Do not add automatic restart behavior.

Do not broaden this pass into supervisor protocol redesign.

## Phase 1 — Propagate Lifecycle Transition Errors

Replace ignored results at every terminal lifecycle call site.

Current pattern:

```rust
let _ = request_lifecycle_transition(&lifecycle_tx, event).await;
return Ok(());
```

Required pattern:

```rust
request_lifecycle_transition(&lifecycle_tx, event).await?;
return Ok(());
```

Apply to:

- `MasterShutdown`
- `WorkerResize`
- `SupervisorDisconnected`

For supervisor disconnect:

```rust
request_lifecycle_transition(
    &lifecycle_tx,
    WorkerLifecycleEvent::SupervisorDisconnected,
)
.await?;

Err(IpcLoopError::ConnectionLost)
```

Required semantics:

- coordinator channel closure becomes `IpcLoopError::Unexpected`;
- dropped acknowledgement becomes `IpcLoopError::Unexpected`;
- lifecycle failure is visible in the task exit reason;
- normal transition still preserves the original intended result.

## Phase 2 — Decide Primary Error Semantics For Supervisor Disconnect

When the supervisor connection is already lost and lifecycle delivery also fails, determine which error should be returned.

Recommended policy:

- If lifecycle transition succeeds, return `IpcLoopError::ConnectionLost`.
- If lifecycle transition fails, return that lifecycle coordination error because it explains why the composition root did not receive the authoritative shutdown event.

Do not hide the coordination failure behind `ConnectionLost`.

Add tests covering both outcomes.

## Phase 3 — Remove Premature `running.stop()` From Supervision

The supervision loop should select a cause only. It should not mutate shared runtime shutdown state before coordinated shutdown intent is recorded.

Remove `state.running.stop()` from:

- fatal task-exit branch;
- registry exit receiver lag branch;
- registry exit receiver unexpected-closure branch;
- lifecycle channel unexpected-closure branch.

The supervision loop should return:

```rust
SupervisionOutcome::DirectCause(cause)
```

without performing teardown side effects.

## Phase 4 — Record Shutdown Intent Before Any Stop Signal

In Phase 16, preserve this ordering for both lifecycle and direct outcomes:

1. Resolve `WorkerShutdownCause`.
2. Call `registry.begin_shutdown()`.
3. Acknowledge lifecycle request if present.
4. Stop accepting new requests.
5. Drain if applicable.
6. Stop app servers.
7. Call `state.running.stop()`.
8. Broadcast registry cancellation.
9. Join/abort owned tasks.

The critical invariant is:

```text
begin_shutdown() happens before running.stop()
```

for every shutdown cause, including server failure, registry failure, and non-IPC critical task failure.

## Phase 5 — Verify Secondary Exit Classification

After a direct critical failure initiates shutdown, other long-lived tasks may return because `running` becomes false or cancellation is broadcast.

Required behavior:

- secondary exits are classified as `CleanCompletion` or expected cancellation;
- no secondary task increments `tasks_unexpectedly_completed`;
- no secondary fatal cause replaces the primary cause;
- final registry shutdown report does not include false-positive unexpected exits.

Add an integration test with:

- one critical task that fails first;
- one critical task waiting on `running`/cancellation;
- one background task waiting on `running`/cancellation;
- direct failure selected as primary cause;
- `begin_shutdown()` called before stop/cancel;
- secondary tasks exit cleanly.

## Phase 6 — Preserve Server Exit Detail

Preferred change:

```rust
pub enum WorkerShutdownCause {
    ServerExitedUnexpectedly(NamedTaskExit),
    ...
}
```

Then:

```rust
pub fn map_task_exit_to_shutdown_cause(exit: NamedTaskExit) -> WorkerShutdownCause {
    if exit.name == "server_run" {
        WorkerShutdownCause::ServerExitedUnexpectedly(exit)
    } else {
        WorkerShutdownCause::CriticalTaskExit(exit)
    }
}
```

Update:

- `Display`
- `nonzero_exit_code()`
- `should_notify_supervisor()`
- `is_expected()`
- supervisor `WorkerError` message
- tests

If this change is judged too invasive, retain the current variant but ensure the full server exit is logged before mapping. Preferred outcome remains preserving the structured detail.

## Phase 7 — Make Supervisor Error Messages Cause-Specific

For preserved server details:

```text
Server task 'server_run' exited unexpectedly: panic/error/unexpected_completion
```

For lifecycle coordination failure in IPC:

```text
Critical task 'ipc_loop' exited: error: unexpected: worker lifecycle coordinator channel closed
```

Ensure the final `WorkerError` uses the retained reason rather than a generic string where possible.

## Phase 8 — Extract Shutdown Intent Transition Helper

To prevent ordering drift, introduce a small composition-root helper:

```rust
async fn begin_coordinated_shutdown(
    registry: &Arc<TokioMutex<WorkerTaskRegistry>>,
    lifecycle_ack: Option<oneshot::Sender<()>>,
) {
    {
        let registry = registry.lock().await;
        registry.begin_shutdown();
    }

    if let Some(ack) = lifecycle_ack {
        let _ = ack.send(());
    }
}
```

The helper should be called before any stop-accepting, running-flag, listener, or cancellation action.

This is optional but recommended because the ordering is now a critical invariant.

## Phase 9 — Add Lifecycle Transition Failure Tests

Add tests for `request_lifecycle_transition()`:

### Coordinator Channel Closed

- drop lifecycle receiver;
- call helper;
- assert `IpcLoopError::Unexpected`;
- assert message identifies coordinator channel closure.

### Acknowledgement Dropped

- receive request but drop `accepted` sender without sending;
- assert `IpcLoopError::Unexpected`;
- assert message identifies dropped acknowledgement.

### Successful Transition

- receive request;
- record shutdown intent;
- acknowledge;
- helper returns `Ok(())`.

### Call-Site Propagation

- IPC-like task uses `?`;
- lifecycle helper failure produces `TaskExitReason::Error`;
- task does not return clean completion.

## Phase 10 — Add Direct Failure Ordering Tests

Add tests that reproduce the previous race.

### Critical Failure With Secondary Critical Exit

1. Spawn primary critical task that returns error.
2. Spawn secondary critical task that exits when `running` becomes false.
3. Supervision selects primary cause.
4. Call `begin_shutdown()`.
5. Clear running flag.
6. Assert secondary exit is clean/expected.
7. Assert unexpected-completion metric remains unchanged.

### Registry Failure With Secondary Background Exit

- simulate `RegistryExitChannelClosed`;
- begin shutdown before stop signal;
- background task exits cleanly;
- primary cause remains registry failure.

### Server Failure

- server task fails;
- server `NamedTaskExit` detail is preserved;
- secondary IPC/background exits are expected.

## Phase 11 — Prevent Primary Cause Replacement

Document and test that once `SupervisionOutcome` is selected:

- later task exits are cleanup observations only;
- they cannot replace `WorkerShutdownCause`;
- they may be logged if abnormal;
- they do not alter exit code or supervisor notification route.

If needed, add a `PrimaryShutdownCause` wrapper or keep the immutable local binding as the source of truth.

## Phase 12 — Guardrail Updates

Update `tests/background_task_ownership_guard.rs`.

Add checks that:

- terminal `request_lifecycle_transition()` calls use `?` or explicit error handling;
- no terminal lifecycle call discards the result with `let _ =`;
- supervision loop does not call `state.running.stop()` before returning the cause;
- `begin_shutdown()` appears before `state.running.stop()` in the composition-root teardown;
- server failure detail remains preserved or explicitly logged;
- secondary task exits are tested as expected during direct-failure teardown.

Behavioral tests remain authoritative.

## Phase 13 — Documentation Cleanup

Update:

- `architecture/worker_task_lifecycle.md`
- `docs/adr/ADR-003-unified-worker-process.md`
- `AGENTS.md`
- `src/worker/AGENTS.override.md`

Document:

- lifecycle transition errors are propagated;
- supervision is side-effect free with respect to shutdown state;
- composition root records shutdown intent before stop signals;
- secondary exits after primary cause selection are expected cleanup;
- server failure diagnostic preservation.

## Phase 14 — Verification Commands

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

If `WorkerShutdownCause` changes shape:

```bash
cargo test --workspace --no-run
```

## Acceptance Criteria

This cleanup is complete when:

1. Every terminal lifecycle transition propagates helper errors.
2. Closed lifecycle channels and dropped acknowledgements become explicit IPC task errors.
3. Supervision selects causes without clearing `running` or broadcasting cancellation.
4. `begin_shutdown()` occurs before every shared stop signal.
5. Secondary task exits after direct failure are classified as expected.
6. Secondary exits do not increment unexpected-completion metrics.
7. Primary shutdown cause cannot be replaced during teardown.
8. Server exit detail is preserved or explicitly logged before mapping.
9. Supervisor `WorkerError` contains the real task/lifecycle failure reason.
10. Normal `MasterShutdown`, resize, and supervisor-disconnect behavior remain correct.
11. Existing request-path, blocklist, threat-intel, provenance, mesh-ID, composition, and task-ownership guardrails remain green.

## Notes for the Implementer

This is the final narrow correction for the initial structured-concurrency track.

Do not add new migrations or restart logic. The only goal is to make lifecycle error propagation and shutdown-intent ordering mechanically correct for every shutdown cause.
