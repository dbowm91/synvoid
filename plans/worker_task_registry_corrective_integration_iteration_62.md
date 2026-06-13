# Worker Task Registry Corrective Integration — Iteration 62

## Purpose

Iteration 61 established a useful structured-concurrency foundation: a task inventory, task classes, `WorkerTaskRegistry`, `ManagedService`, lifecycle metrics, a background-task guardrail, and an owned/cancellable `ThreatFeedClient` task.

The review identified two correctness gaps and one integration gap:

1. Timed-out `JoinHandle`s are passed by value into `timeout_at`; when the timeout expires, dropping the handle detaches the task instead of aborting it.
2. Critical-task panics or early exits are only observed during later shutdown, not while the worker is running.
3. `WorkerTaskRegistry` is not yet integrated into the unified-worker runtime; it currently exists as staged infrastructure plus tests/docs.

This corrective pass should make the registry semantics true, add immediate critical-task supervision, and integrate a small first set of unified-worker tasks without expanding into a repository-wide migration.

The invariant is:

> A task reported as stopped must actually be stopped, and a critical task that exits unexpectedly must be surfaced while the worker is still running.

## Current Known State

Iteration 61 added:

- `src/worker/task_registry.rs`.
- `TaskClass` with `CriticalService`, `RestartableBackground`, `BoundedChild`, `CpuOffload`, and `Detached`.
- `TaskExitReason` and `TaskRegistryMetrics`.
- `WorkerTaskRegistry::spawn_critical()`.
- `WorkerTaskRegistry::spawn_background()`.
- `WorkerTaskRegistry::spawn_cancellable_background()`.
- shared watch-based cancellation via `child_token()`.
- `shutdown_and_join()` with separate critical/background deadlines.
- `ManagedService` with `name()`, `shutdown()`, and `join()`.
- `ThreatFeedClient` with retained handle, duplicate-start rejection, cancellation, `shutdown()`, and `join()`.
- `architecture/worker_task_lifecycle.md` with task inventory.
- `tests/background_task_ownership_guard.rs`.

Known defects:

- `timeout_at(deadline, task.handle)` consumes the `JoinHandle`.
- On timeout, the consumed handle is dropped and the Tokio task is detached.
- The code records `TaskExitReason::Aborted` even though the task may continue running.
- Tests check only the returned reason, not whether the task actually ceased execution.
- Critical task handles sit in a `Vec` and are not polled until `shutdown_and_join()`.
- Registry usage is not wired into the unified-worker composition root.
- `ThreatFeedClient::is_running()` returns true whenever the handle slot is populated, even if the task already finished.
- `ThreatFeedClient::join()` is not bounded by a caller-supplied timeout.

## Non-Goals

Do not migrate every background task in the repository.

Do not redesign the entire worker lifecycle.

Do not replace Tokio or introduce a new async runtime.

Do not alter request-path behavior.

Do not change blocklist, threat-intel actionability, mesh-ID, or composition-root semantics.

Do not implement automatic restart policy for every background task in this pass.

Do not add a global task manager spanning supervisor and every crate.

Do not convert bounded per-request tasks into registry-managed long-lived services.

## Phase 1 — Fix Timeout Semantics Correctly

Refactor `shutdown_and_join()` so a timed-out task is explicitly aborted and awaited.

Current unsafe pattern:

```rust
match tokio::time::timeout_at(deadline, task.handle).await {
    ...
}
```

Required pattern:

```rust
let mut handle = task.handle;

match tokio::time::timeout_at(deadline, &mut handle).await {
    Ok(join_result) => {
        // classify clean, panic, cancelled, or error
    }
    Err(_) => {
        handle.abort();
        let abort_join = handle.await;
        // record Aborted, preserving any unexpected post-abort join information
    }
}
```

For tasks skipped because the shared class deadline is already exhausted:

```rust
let handle = task.handle;
handle.abort();
let _ = handle.await;
```

Required semantics:

- No timed-out task is left detached.
- `shutdown_and_join()` does not return until each timed-out handle has been aborted and observed as terminated.
- `TaskExitReason::Aborted` means the task has actually ceased execution.
- `tasks_aborted` increments only for explicit aborts.
- `tasks_remaining_at_timeout` reflects the count of tasks that required forced termination.

## Phase 2 — Extract A Shared Join/Abort Helper

Avoid duplicating subtle timeout logic for critical and background tasks.

Suggested helper:

```rust
async fn join_task_until(
    task: RegisteredTask,
    deadline: tokio::time::Instant,
    metrics: &TaskRegistryMetrics,
) -> NamedTaskExit
```

Suggested result:

```rust
pub struct NamedTaskExit {
    pub name: &'static str,
    pub class: TaskClass,
    pub reason: TaskExitReason,
    pub expected_during_shutdown: bool,
}
```

The helper should:

- retain mutable handle ownership;
- await until the deadline;
- abort and re-await on timeout;
- classify panic/cancel/error cleanly;
- update metrics in one place;
- emit consistent structured logs.

Do not call a task `CleanCompletion` merely because `JoinHandle<Output=()>` returned `Ok(())`; whether completion is expected depends on task class and whether shutdown was active.

## Phase 3 — Distinguish Expected And Unexpected Completion

A long-lived critical task returning `Ok(())` before shutdown is not necessarily a clean success.

Track registry state:

```rust
shutdown_started: bool
```

or infer from the shutdown watch value.

Classify exits:

- Before shutdown:
  - `CriticalService` completion -> unexpected critical exit.
  - `RestartableBackground` completion -> unexpected background exit unless explicitly finite.
- During shutdown:
  - cooperative return -> expected clean/cancelled exit.

Possible new reason:

```rust
TaskExitReason::UnexpectedCompletion
```

or carry an `expected` flag on `NamedTaskExit`.

Acceptance behavior:

- A critical task that returns before shutdown is surfaced as failure/unhealthy.
- A cancellation-aware task returning after shutdown is not treated as a fault.

## Phase 4 — Add Immediate Critical-Task Supervision

The registry must detect critical exits while the worker is running.

Recommended design: task-exit reporting channel.

On spawn, wrap the future:

```rust
let exit_tx = self.exit_tx.clone();
let handle = tokio::spawn(async move {
    let result = AssertUnwindSafe(future).catch_unwind().await;
    let exit = classify_wrapped_result(name, class, result);
    let _ = exit_tx.send(exit.clone());
    exit
});
```

Alternative: keep `JoinHandle` output as `NamedTaskExit` and manage critical tasks in a `JoinSet` polled by the worker.

Required API:

```rust
pub async fn next_critical_exit(&mut self) -> Option<NamedTaskExit>
```

or:

```rust
pub fn subscribe_exits(&self) -> broadcast::Receiver<NamedTaskExit>
```

Recommended worker integration:

- worker lifecycle `select!` waits on normal server completion, supervisor shutdown, and critical task exit notifications;
- unexpected critical exit marks worker unhealthy and initiates coordinated shutdown;
- expected shutdown exits do not recursively trigger failure handling.

Do not rely solely on polling `JoinHandle::is_finished()`.

## Phase 5 — Decide Task Wrapper Panic Strategy

Tokio reports panic through `JoinError`, but immediate supervision requires observing exits without consuming the only join handle prematurely.

Choose one coherent strategy:

### Strategy A — Wrapped Future Reports Exit, Handle Still Retained

- Wrapper uses `catch_unwind` and sends `NamedTaskExit`.
- Wrapper returns normally after reporting.
- Join handle remains available for final join.

Pros:

- immediate notification;
- retained handle;
- panic message can be extracted explicitly.

### Strategy B — JoinSet Is The Owner

- Registry owns tasks in a `JoinSet`.
- Worker/registry supervisor continuously polls `join_next_with_id()`.
- Completed tasks are removed immediately.

Pros:

- native structured ownership.

Cons:

- shutdown ordering by task class may require separate sets or metadata maps.

Recommended: Strategy A for minimal disruption in this corrective pass.

## Phase 6 — First Unified-Worker Runtime Integration

Wire `WorkerTaskRegistry` into the unified-worker runtime for a deliberately small initial set.

Suggested first tasks:

1. Heartbeat task — `RestartableBackground`.
2. Bandwidth persistence task — `RestartableBackground`.
3. Supervisor/worker IPC loop — `CriticalService`.

Likely files:

- `src/worker/unified_server/state.rs`
- `src/worker/unified_server/lifecycle.rs`
- `src/worker/unified_server/mod.rs`
- `src/worker/task_registry.rs`

Required changes:

- Add registry ownership to `UnifiedServerWorkerState` or the lifecycle owner.
- Replace direct `tokio::spawn()` + `task_handles.push()` for selected tasks with registry spawn APIs.
- Pass registry child cancellation tokens into the task loops.
- Integrate critical-exit receiver into the main worker lifecycle `select!`.
- On critical exit, mark `running` stopped/unhealthy and begin coordinated shutdown.
- At normal shutdown, call registry cancellation and bounded join.

Keep non-migrated tasks in the existing handle collection for now, but document dual ownership as transitional.

## Phase 7 — Heartbeat Migration Details

For the worker heartbeat task:

- use registry `child_token()`;
- select between interval tick, existing running state, and cancellation;
- classify as `RestartableBackground`;
- preserve current heartbeat frequency and IPC behavior;
- unexpected task exit should be observable but need not terminate worker immediately unless heartbeat is considered critical;
- remove its guardrail allowlist entry after migration.

Tests:

- cancellation stops heartbeat loop;
- no heartbeat occurs after registry shutdown completion;
- unexpected panic is reported through the registry exit channel.

## Phase 8 — Bandwidth Persistence Migration Details

For bandwidth persistence:

- classify as `RestartableBackground` unless durability requirements justify `CriticalService`;
- add explicit cancellation select;
- perform final persistence flush after cancellation if dirty state exists;
- join before process exit;
- preserve persistence cadence;
- remove “unowned” status from architecture inventory;
- remove its spawn allowlist entry after migration.

Tests:

- final flush runs during shutdown;
- task is actually stopped after timeout/abort;
- no writes occur after join completion.

## Phase 9 — IPC Loop Migration Details

For supervisor/worker IPC:

- classify as `CriticalService`;
- registry owns handle;
- task exit sends immediate critical-exit notification;
- EOF/master death/current error behavior remains intact;
- normal supervisor-requested shutdown is marked expected;
- unexpected IPC task panic or early return initiates worker shutdown;
- avoid double-triggering shutdown when `MasterShutdown` is already being processed.

Tests:

- unexpected IPC loop return is surfaced immediately;
- panic is surfaced immediately;
- normal `MasterShutdown` does not count as unexpected critical failure;
- registry shutdown joins the IPC task.

## Phase 10 — Correct ThreatFeedClient Lifecycle Semantics

Improve `ThreatFeedClient` without broad refactoring.

### Accurate `is_running()`

Current behavior checks only whether the handle slot is `Some`.

Change to:

```rust
self.task_handle
    .read()
    .as_ref()
    .is_some_and(|handle| !handle.is_finished())
```

Consider clearing finished handles before restart or join.

### Bounded Join

Add:

```rust
pub async fn join_with_timeout(
    &self,
    timeout: Duration,
) -> Result<ThreatFeedExit, ThreatFeedJoinError>
```

On timeout:

- explicitly abort;
- await the aborted handle;
- return timeout/aborted classification.

Do not implement bounded join by dropping the handle.

### Shutdown During Fetch

The HTTP fetch is already bounded by request timeout, but document that shutdown is cooperative at fetch boundaries.

Optional improvement:

- select cancellation against `fetch_and_process()` so shutdown can cancel the in-flight fetch future if safe;
- only do this if dropping the HTTP future does not violate client invariants.

### Restart Behavior

Decide whether a completed task may be restarted:

- if finished handle exists, consume/classify it before allowing restart;
- duplicate active start remains rejected;
- shutdown signal may need reset semantics if restart is supported.

Recommended: do not support restart after shutdown in this pass; return a specific error.

## Phase 11 — Make Registry APIs Expressive Enough

Current spawn APIs only accept `Future<Output=()>`, which cannot distinguish service errors from clean completion.

Consider changing to:

```rust
F: Future<Output = Result<(), E>>
```

with `E: Display`, or provide parallel APIs:

```rust
spawn_critical_result(...)
spawn_background_result(...)
```

Minimal acceptable outcome:

- panics and early completion are supervised;
- task-internal errors are reported through explicit wrapper/result channels.

Preferred outcome:

```rust
pub fn spawn_critical<F, E>(...) where
    F: Future<Output = Result<(), E>>,
    E: Display + Send + 'static
```

Do not force every migrated loop to invent an error type if it genuinely cannot fail.

## Phase 12 — Fix Metrics Semantics

Review metric counters:

- `tasks_completed_cleanly`
- `tasks_cancelled`
- `tasks_panicked`
- `tasks_aborted`
- `tasks_errored`
- `tasks_remaining_at_timeout`
- `shutdown_duration_ms`

Required corrections:

- A timed-out task increments `tasks_remaining_at_timeout` and `tasks_aborted` only after explicit abort.
- Unexpected clean return of a critical task should not increment `tasks_completed_cleanly`.
- Panic should be counted when observed immediately, without double counting during final join.
- Exit reporting and join cleanup must use one source of truth or deduplication marker.

Add task IDs to exit records if necessary:

```rust
pub struct TaskId(u64);
```

This avoids duplicate accounting by name.

## Phase 13 — Partial Startup Rollback For Migrated Tasks

Once the registry is wired into worker state, ensure startup failure cleans up registered tasks.

Required behavior:

- if heartbeat starts and IPC setup later fails, registry is cancelled and joined;
- if IPC starts and server initialization later fails, IPC is stopped;
- startup error path has a bounded cleanup timeout;
- no migrated task survives a failed worker initialization.

Suggested helper:

```rust
async fn rollback_started_tasks(registry: &mut WorkerTaskRegistry)
```

or an explicit startup guard.

## Phase 14 — Correct The Guardrail

Update `tests/background_task_ownership_guard.rs`.

Required changes:

- remove allowlist entries for migrated heartbeat, bandwidth persistence, and IPC tasks;
- guard recognizes registry spawn APIs as owned spawns;
- intentionally detached tasks require a reason-bearing exception structure;
- known-issue exceptions include an owner and planned migration note;
- add a source check rejecting comments that claim dropping a `JoinHandle` aborts a task.

Suggested exception type:

```rust
struct SpawnException {
    path_suffix: &'static str,
    function: &'static str,
    class: TaskClass,
    reason: &'static str,
    planned_owner: &'static str,
}
```

## Phase 15 — Tests For True Termination

Add tests that prove tasks actually stop.

### Timeout Abort Test

Use an external atomic heartbeat:

```rust
let alive = Arc<AtomicU64>;
spawn loop increments alive;
shutdown_and_join(short_timeout).await;
let after = alive.load(...);
sleep(...).await;
assert_eq!(alive.load(...), after);
```

This test must fail under the current detach-on-timeout bug.

### Drop Guard Test

Use a guard object whose `Drop` sets an atomic flag. After forced abort and awaited join, assert the guard was dropped.

### Immediate Critical Exit Test

- spawn critical task that returns immediately;
- await exit notification without calling shutdown;
- assert unexpected critical completion is reported.

### Immediate Panic Test

- spawn panicking critical task;
- assert panic notification arrives before shutdown.

### No Double Count Test

- observe immediate exit;
- later call shutdown/join;
- assert panic/error metrics count exactly once.

### Shared Deadline Tests

- first task consumes most deadline;
- subsequent tasks are explicitly aborted and awaited;
- none remain active after return.

## Phase 16 — Worker Integration Tests

Add focused lifecycle tests around the migrated worker tasks.

Scenarios:

- normal worker shutdown cancels heartbeat/bandwidth/IPC and joins all three;
- IPC panic initiates worker stop;
- bandwidth final flush occurs before registry join returns;
- partial startup failure rolls back tasks;
- worker shutdown completes within configured bound;
- no migrated task remains after shutdown.

Use test doubles for IPC and persistence where possible rather than binding real sockets.

## Phase 17 — Documentation Corrections

Update:

- `architecture/worker_task_lifecycle.md`
- `docs/adr/ADR-003-unified-worker-process.md`
- `architecture/worker_data_plane_composition_root.md`
- `AGENTS.md`
- `src/worker/AGENTS.override.md`

Correct overstatements from Iteration 61:

- Before this pass, registry was staged infrastructure, not worker-wide active ownership.
- Critical exits were not previously observed immediately.
- Timeout previously reported abort without guaranteed termination.

After implementation, document exactly which tasks are registry-owned and which remain transitional.

Task inventory should update rows for:

- heartbeat;
- bandwidth persistence;
- IPC loop;
- threat feed.

Use explicit status labels:

- `Migrated`
- `LegacyOwned`
- `UnownedKnownGap`
- `DetachedApproved`

## Phase 18 — Verification Commands

Run focused tests:

```bash
cargo test worker::task_registry
cargo test --test background_task_ownership_guard
cargo test threat_feed
cargo test unified_server --lib
cargo test --test data_plane_composition_boundary_guard
cargo test --test mesh_id_boundary_guard
cargo test --test threat_intel_boundary_guard
cargo test --test threat_intel_consumer_actionability_guard
cargo test --test manual_enforcement_provenance_guard
cargo test --lib --no-run
```

If worker state or lifecycle signatures change:

```bash
cargo test --workspace --no-run
```

Also run:

```bash
cargo fmt --check
cargo clippy --lib -- -D warnings
```

Adjust filters to actual test names.

## Acceptance Criteria

This corrective pass is complete when:

1. `shutdown_and_join()` never detaches a timed-out task.
2. Timed-out tasks are explicitly aborted and awaited.
3. Tests prove timed-out tasks cease execution before shutdown returns.
4. Critical task panic/exit is observable before worker shutdown begins.
5. Unexpected critical completion is distinguished from expected shutdown completion.
6. Panic/error metrics are not double counted.
7. `WorkerTaskRegistry` is integrated into unified-worker runtime ownership.
8. Heartbeat, bandwidth persistence, and IPC loop are registry-owned or a similarly small documented first set is migrated.
9. Partial startup failure cancels and joins migrated tasks.
10. Threat-feed `is_running()` reflects actual handle state.
11. Threat-feed has bounded join/abort semantics.
12. Guardrail allowlists are reduced for migrated tasks.
13. Documentation accurately distinguishes migrated and legacy task ownership.
14. Existing request-path, blocklist, threat-intel, provenance, and mesh-ID guardrails remain green.

## Notes for the Implementer

This is a correctness and first-integration pass, not a broad migration.

The highest-priority defect is the false-abort behavior. Fix and test that before integrating more tasks.

The desired end-state for this iteration is:

- the registry’s shutdown claims are true;
- critical failures are supervised at runtime;
- a small real slice of the unified worker uses the registry;
- remaining lifecycle debt is explicitly inventoried for later passes.
