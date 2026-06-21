# Worker Task Registry Abort-Join Cleanup — Iteration 90

## Purpose

Iteration 89 completed the worker mesh composition-root closure work: optional startup now hands `MeshGenerationSupport` back to the composition root, required readiness is gated on support registration, stop-report accounting is corrected, and the DHT startup hook now fires after initialization.

The remaining issue is narrow and localized to `WorkerTaskRegistry::cancel_then_join_tasks()`.

At current head `f4443fbbb92ee09251c632d5a5dfe6c155de2ab4`, the forced cleanup path still does:

```rust
handle.abort();
let join_result = tokio::time::timeout_at(forced_deadline, handle).await;
```

If the timeout fires, the `JoinHandle` has been moved into the timeout future and is dropped. The task was already removed from the registry, so ownership is lost without proof that the task ended. This violates the repository-wide lifecycle invariant:

> Abort is not cleanup until the handle is awaited, or ownership is explicitly retained as incomplete residue.

This plan performs the final micro-cleanup for the worker mesh supervision track.

---

## Non-Goals

Do not change mesh transport lifecycle.

Do not implement worker-level mesh restart.

Do not refactor the whole task registry.

Do not add a new task supervision framework.

Do not alter normal whole-worker shutdown behavior except where the same helper is reused.

---

# Part A — Remove Post-Abort Timeout Handle Dropping

## Phase 1 — Change Forced Cleanup To Abort Then Await

In `src/worker/task_registry.rs`, update `cancel_then_join_tasks()` forced cleanup.

Current risky shape:

```rust
let forced_deadline = tokio::time::Instant::now() + forced_timeout;
for task in still_pending {
    task.handle.abort();
    let join_result = tokio::time::timeout_at(forced_deadline, task.handle).await;
    ...
}
```

Replace with:

```rust
for task in still_pending {
    task.handle.abort();

    let join_result = task.handle.await;
    let reason = match join_result {
        Ok(()) => TaskExitReason::CleanCompletion,
        Err(error) => classify_join_error(error),
    };

    let already_reported = self.reported_exits.lock().unwrap().remove(&task.id);
    let final_reason = already_reported.unwrap_or(reason);

    exits.push(NamedTaskExit {
        id: task.id,
        name: task.name,
        class: task.class,
        reason: final_reason,
        expected_during_shutdown,
    });
}
```

Rationale:

- after `abort()`, Tokio tasks normally resolve once cancellation is observed;
- the registry owns the handle after extracting it;
- cleanup must not return until every extracted handle is settled;
- if a task never yields after abort, that is a stronger lifecycle problem and should not be hidden by dropping the handle.

## Phase 2 — Keep Cooperative Timeout Only

The cooperative timeout remains useful:

```rust
cooperative_timeout
```

It gives tasks a graceful window before forced abort. After the force boundary is crossed, do not apply a second deadline unless the API explicitly returns an owned unjoined residue.

The `forced_timeout` parameter becomes unnecessary if no residue path is implemented.

Choose one:

### Preferred Narrow Change

Keep the parameter for API stability, but do not use it after abort. Rename it later in a separate API cleanup.

Add a comment:

```rust
// `forced_timeout` is retained for API compatibility. Once a task is aborted,
// this function awaits the handle to preserve ownership. Do not wrap the aborted
// handle in timeout unless unjoined ownership residue is returned.
```

### Optional Cleanup

Rename the parameter to `_forced_timeout` and update call sites later.

Do not remove the parameter if it causes broad churn.

## Phase 3 — Remove Misleading Error Log

Delete the current log branch:

```rust
"subset force-join timeout after abort"
```

That state should no longer exist.

---

# Part B — Make Support Stop Diagnostics Account For Not-Found IDs

## Phase 4 — Add `not_found` To `MeshSupportStopReport`

Current report:

```rust
pub struct MeshSupportStopReport {
    pub generation: u64,
    pub cooperative: usize,
    pub aborted: usize,
    pub failed: usize,
}
```

Add:

```rust
pub not_found: usize,
```

Update construction in `stop_mesh_generation_support()`:

```rust
MeshSupportStopReport {
    generation: support.generation,
    cooperative: ...,
    aborted: report.aborted_count(),
    failed: ...,
    not_found: report.not_found_ids.len(),
}
```

## Phase 5 — Treat Not-Found As Non-Clean By Default

Update:

```rust
impl MeshSupportStopReport {
    pub fn clean(&self) -> bool {
        self.aborted == 0 && self.failed == 0 && self.not_found == 0
    }
}
```

Rationale:

- a missing task ID during first teardown can indicate lost ownership bookkeeping;
- duplicate teardown should be prevented by `active_mesh_support.take()`;
- if a task finished and was removed elsewhere, the code should explicitly account for that path rather than silently classifying it clean.

## Phase 6 — Improve Not-Found Log Context

The registry already logs not-found IDs. Ensure the support-level log includes:

- generation;
- stop context;
- not-found count;
- task IDs if not too noisy.

Do not add high-cardinality metric labels.

---

# Part C — Tests

## Phase 7 — Add Forced Abort Join Test

Add a test in `src/worker/task_registry.rs` module tests.

Test idea:

```rust
#[tokio::test]
async fn cancel_then_join_tasks_aborts_and_awaits_pending_handle() {
    let mut registry = WorkerTaskRegistry::new_for_test();

    let started = Arc::new(Notify::new());
    let never = Arc::new(Notify::new());
    let never_clone = never.clone();
    let started_clone = started.clone();

    let id = registry.spawn_background("hung_support", async move {
        started_clone.notify_one();
        never_clone.notified().await;
    });

    started.notified().await;

    let report = registry
        .cancel_then_join_tasks(
            &[TaskId(id as u64)],
            Duration::from_millis(0),
            Duration::from_millis(1),
            false,
        )
        .await;

    assert_eq!(report.not_found_ids.len(), 0);
    assert_eq!(report.exits.len(), 1);
    assert!(matches!(report.exits[0].reason, TaskExitReason::Aborted));
    assert!(!registry.contains_task(TaskId(id as u64)));
}
```

This test should not rely on the forced timeout expiring. It should prove the aborted task was joined and removed.

## Phase 8 — Add Panic Preservation Test

A task that panics before or during cleanup should be classified as `Panic`, not as `Aborted`.

```rust
#[tokio::test]
async fn cancel_then_join_tasks_preserves_panic_classification() {
    let mut registry = WorkerTaskRegistry::new_for_test();
    let id = registry.spawn_background("panic_support", async move {
        panic!("boom");
    });

    tokio::task::yield_now().await;

    let report = registry
        .cancel_then_join_tasks(
            &[TaskId(id as u64)],
            Duration::from_millis(10),
            Duration::from_millis(10),
            false,
        )
        .await;

    assert!(report.exits.iter().any(|e| matches!(e.reason, TaskExitReason::Panic(_))));
}
```

## Phase 9 — Add Not-Found Support Report Test

Add a focused unit test for `MeshSupportStopReport::clean()` or the support cleanup helper.

Required assertions:

- `not_found = 0` and no failures -> clean;
- `not_found > 0` -> not clean;
- aborted > 0 -> not clean;
- failed > 0 -> not clean.

## Phase 10 — Add Guard Test For No Timeout Around Aborted Handle

Update `tests/worker_mesh_supervision_boundary_guard.rs` or a task-registry guard to assert that `cancel_then_join_tasks()` does not contain the pattern:

```text
timeout_at(..., task.handle)
```

after `task.handle.abort()`.

This guard should be narrow; avoid banning all timeout use in the registry because cooperative timeout is still valid.

Suggested source check:

- locate function body for `cancel_then_join_tasks`;
- locate `abort();`;
- assert no `timeout_at` appears after that point before the function ends.

---

# Part D — Documentation

## Phase 11 — Update Worker Ownership Docs

Update:

- `AGENTS.md`;
- `src/worker/AGENTS.override.md`;
- any worker lifecycle ownership docs touched in previous iterations.

Clarify:

```text
cancel_then_join_tasks performs cooperative waiting to a deadline. Remaining tasks are then aborted and awaited without a second timeout, preserving handle ownership. A future hard-deadline variant must return explicit unjoined residue rather than dropping handles.
```

## Phase 12 — Update Plan/Skill References If Needed

If `skills/synvoid_mesh.md` or worker skills mention forced timeout after abort, correct them.

---

# Ordered Execution Sequence

A smaller model should implement in this order:

1. Change forced cleanup to abort then await.
2. Remove the post-abort timeout log branch.
3. Add `not_found` to `MeshSupportStopReport`.
4. Update `clean()` semantics.
5. Update stop-support construction and logs.
6. Add forced-abort join test.
7. Add panic-preservation test.
8. Add not-found clean semantics test.
9. Add source guard against timeout-wrapping aborted handles.
10. Update documentation.

---

# Verification Commands

Run focused tests:

```bash
cargo test -p synvoid --lib worker::task_registry --features mesh,dns
cargo test -p synvoid --lib worker::unified_server --features mesh,dns
cargo test --test worker_task_registry_lifecycle --features mesh,dns
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns
cargo test --test worker_supervision_control_flow --features mesh,dns
```

Run mesh/worker regression suites:

```bash
cargo test -p synvoid-mesh --features mesh startup
cargo test -p synvoid-mesh --features mesh dht
cargo test --test mesh_startup_rollback --features mesh,dns
cargo test --test mesh_task_ownership_guard --features mesh,dns
cargo test --test composition_root_behavioral --features mesh,dns
cargo test --test background_task_ownership_guard
cargo test --test data_plane_composition_boundary_guard
```

Run final hygiene:

```bash
cargo test --lib --no-run
cargo fmt --check
cargo clippy --workspace --all-targets --features mesh,dns -- -D warnings
```

---

# Acceptance Criteria

This cleanup is complete when:

1. `cancel_then_join_tasks()` does not wrap an already-aborted `JoinHandle` in a timeout.
2. Every matched task handle extracted from the registry is awaited before cleanup returns.
3. No matched handle can be dropped silently after forced timeout.
4. Panic/error classification is preserved during subset cleanup.
5. `MeshSupportStopReport` includes not-found task count.
6. `MeshSupportStopReport::clean()` returns false when not-found IDs exist.
7. Focused tests cover abort-and-await, panic preservation, not-found accounting, and unrelated task preservation.
8. A source guard prevents reintroducing the post-abort timeout/drop pattern.
9. Documentation reflects the final ownership invariant.
10. Existing worker mesh supervision and mesh lifecycle tests remain green.

---

## Notes For The Implementer

This is intentionally a micro-pass.

Do not introduce a hard deadline after abort unless the API returns explicit owned residue.

The correct final state is simple:

> cooperative timeout -> abort remaining -> await every remaining handle -> report exact exits.
