# Worker Mesh Composition-Root Final Closure — Iteration 89

## Purpose

Iteration 88 corrected the DHT startup order, checked startup peer insertion, direct YARA cancellation, and subset cleanup APIs. The current head at `d92a8b681cf8b7eae25c6c6e52ab75c4f3a9517c` still has four correctness defects and two diagnostic/test gaps:

1. Optional mesh startup registers `MeshGenerationSupport` inside the one-shot task and discards the returned bundle, so later optional degradation cannot stop that generation’s DNS/YARA support.
2. Required mesh support-registration failure still proceeds to `UnifiedServerWorkerReady`, creating a brief false-ready state before immediate shutdown.
3. `cancel_then_join_tasks()` can time out after abort and drop ownership of an unjoined `JoinHandle`, violating the abort-and-await invariant.
4. `MeshSupportStopReport.cooperative` counts panic/error exits as cooperative because it is derived as `total - aborted`.
5. The `BeforePeerConnect` startup hook currently fires before DHT initialization, so it cannot prove the intended initialized-before-connect invariant.
6. Existing tests do not exercise the actual composition-root dataflow for optional support bundle handoff or required support-registration failure.

This pass should close the final composition-root ownership gaps without introducing automatic restart or reopening lower-level mesh lifecycle work.

The governing invariants are:

> Optional startup completion must return ownership facts to the composition root; background tasks must not retain or discard lifecycle ownership objects.

> A required worker is not ready until both transport startup and required support registration succeed.

> Aborted task handles remain owned until they are awaited or retained in an explicit incomplete-cleanup residue.

---

## Non-Goals

Do not implement worker-level automatic mesh restart.

Do not redesign `MeshTaskGroup`.

Do not change DHT routing semantics.

Do not add a generic actor framework.

Do not broaden this pass into unrelated worker readiness or IPC refactors.

---

# Part A — Return Optional Startup Completion To The Composition Root

## Phase 1 — Introduce A Typed Optional Startup Result

Add a private composition-root result type:

```rust
#[cfg(feature = "mesh")]
#[derive(Debug)]
enum OptionalMeshStartupResult {
    Started {
        generation: u64,
        support: MeshGenerationSupport,
    },
    Failed {
        generation: u64,
        cause: crate::worker::mesh_supervision::MeshFailureCause,
    },
}
```

The startup task may perform the transport startup, but the composition root must receive the resulting ownership object.

## Phase 2 — Add A Dedicated Completion Channel

Before spawning optional startup:

```rust
let (optional_startup_tx, mut optional_startup_rx) =
    tokio::sync::mpsc::channel::<OptionalMeshStartupResult>(1);
```

The one-shot task should:

1. await transport startup;
2. register support only after success;
3. send the resulting `MeshGenerationSupport` bundle back to the composition root;
4. send failure with the typed cause if startup or support registration fails;
5. never discard the bundle.

Example:

```rust
registry.spawn_one_shot("mesh_startup", async move {
    let generation = 1;

    let result = match mesh_transport
        .start_with_policy(synvoid_mesh::lifecycle::MeshStartupPolicy::default())
        .await
    {
        Ok(report) => {
            tracing::info!(?report, generation, "optional mesh transport started");

            match support_for_startup {
                Some(support) => match register_mesh_generation_support(
                    &state_for_startup,
                    support,
                    generation,
                )
                .await
                {
                    Ok(bundle) => OptionalMeshStartupResult::Started {
                        generation,
                        support: bundle,
                    },
                    Err(cause) => OptionalMeshStartupResult::Failed {
                        generation,
                        cause: MeshFailureCause::StartupFailed(format!(
                            "support registration failed: {cause}"
                        )),
                    },
                },
                None => OptionalMeshStartupResult::Started {
                    generation,
                    support: MeshGenerationSupport::empty(generation),
                },
            }
        }
        Err(error) => OptionalMeshStartupResult::Failed {
            generation,
            cause: MeshFailureCause::StartupFailed(error.to_string()),
        },
    };

    let _ = optional_startup_tx.send(result).await;
});
```

Add:

```rust
impl MeshGenerationSupport {
    fn empty(generation: u64) -> Self { ... }
}
```

only if an empty bundle simplifies control flow.

## Phase 3 — Handle Completion In The Main Supervision Loop

Add a `tokio::select!` branch for optional startup completion.

Example:

```rust
optional_result = optional_startup_rx.recv(), if optional_startup_pending => {
    optional_startup_pending = false;

    match optional_result {
        Some(OptionalMeshStartupResult::Started { generation, support }) => {
            if active_mesh_support.is_some() {
                return invariant_failure("optional startup produced duplicate support bundle");
            }

            active_mesh_support = Some(support);
            let _ = event_tx
                .send(MeshSupervisionEvent::Started)
                .await;

            tracing::info!(generation, "optional mesh startup committed");
        }
        Some(OptionalMeshStartupResult::Failed { generation, cause }) => {
            let _ = event_tx
                .send(MeshSupervisionEvent::StartupFailed(cause.exit_reason()))
                .await;
            tracing::warn!(generation, reason = %cause.exit_reason(), "optional mesh startup failed");
        }
        None => {
            return invariant_failure("optional mesh startup completion channel closed");
        }
    }
}
```

The composition root must be the only owner of `active_mesh_support`.

## Phase 4 — Avoid Dual Status Mutation

The optional startup one-shot must not directly mutate `WorkerMeshStatus` terminal state.

Required ownership:

- composition root sets `Starting` before spawning;
- completion result is converted to `Started` or `StartupFailed` event;
- coordinator performs the terminal transition.

Do not both store the bundle and independently send another status transition from inside the one-shot closure.

## Phase 5 — Handle Completion/Degradation Races

Possible race:

1. optional startup completes;
2. mesh emits a critical exit immediately;
3. degradation decision arrives before completion result is processed.

Use a small state enum:

```rust
enum OptionalMeshRuntimeState {
    Starting,
    Running,
    Failed,
}
```

Rules:

- if degradation arrives while `Starting`, remember `pending_optional_failure = true`;
- when startup completion arrives with a support bundle and failure is pending, immediately stop that bundle before setting `Running`;
- if completion arrives first, store bundle normally;
- duplicate terminal outcomes are invariant violations or ignored with explicit diagnostics.

A simpler acceptable approach is to order all optional startup facts through one coordinator-owned channel, but ownership of the support bundle still must return to the composition root.

## Phase 6 — Optional Startup Tests

Required behavioral tests:

- optional startup success returns a support bundle to the composition root;
- `active_mesh_support` becomes `Some`;
- optional degradation invokes `stop_mesh_generation_support()` with that bundle’s task IDs;
- no DNS/YARA support survives degradation;
- startup failure produces no bundle;
- support-registration failure produces no bundle and marks optional mesh degraded;
- immediate exit after startup cannot leak the newly created bundle;
- completion channel closure is treated as an invariant failure.

---

# Part B — Gate Required Readiness On Support Registration

## Phase 7 — Make Required Startup A Two-Stage Commit

Required readiness requires:

```text
transport startup success
AND
support registration success
```

Do not send ready after transport startup alone.

Refactor:

```rust
let required_startup_result: Result<Option<MeshGenerationSupport>, MeshFailureCause> =
    match start_mesh_generation(&mesh_transport, 0).await {
        Ok(()) => {
            let support_bundle = match support_tasks.take() {
                Some(support) => register_mesh_generation_support(
                    &state,
                    support,
                    1,
                )
                .await
                .map(Some)
                .map_err(|cause| MeshFailureCause::StartupFailed(format!(
                    "support registration failed: {cause}"
                )))?,
                None => None,
            };

            Ok(support_bundle)
        }
        Err(cause) => Err(cause),
    };
```

Only after `Ok(...)`:

- transition `Running`;
- assign `active_mesh_support`;
- send ready.

On any error:

- transition `Failed`;
- set `required_mesh_startup_failure`;
- do not send ready.

## Phase 8 — Roll Back Transport If Required Support Registration Fails

If support registration is part of required readiness, failure after transport startup should not leave the mesh running while the worker enters shutdown indirectly.

Preferred:

```rust
if let Err(cause) = register_mesh_generation_support(...).await {
    let shutdown_report = mesh_transport.shutdown(Duration::from_secs(5)).await;
    tracing::warn!(?shutdown_report, "rolled back mesh after support registration failure");
    return Err(MeshFailureCause::StartupFailed(...));
}
```

Use the worker’s startup cleanup policy/deadline rather than a hard-coded duration if one exists.

At minimum, set the direct fatal cause before any ready signal and enter coordinated shutdown immediately.

## Phase 9 — Keep Status Transitions Singular

Recommended sequence:

```text
Starting
transport start succeeds
support registration succeeds
Running
ready
```

Failure sequence:

```text
Starting
transport or support registration fails
Failed
no ready
coordinated shutdown
```

Do not briefly transition to `Running` before support registration succeeds.

## Phase 10 — Required Readiness Tests

Required behavioral tests:

- transport success + support success -> exactly one ready message;
- transport success + support failure -> no ready message;
- support failure transitions directly `Starting -> Failed`, not through `Running`;
- support failure initiates transport cleanup;
- ready is not emitted before `active_mesh_support` is assigned;
- empty support set still permits ready;
- repeated ready emission remains impossible.

---

# Part C — Preserve Handle Ownership Through Forced Cleanup

## Phase 11 — Remove The Post-Abort Timeout That Drops Handles

Current problematic pattern:

```rust
let join_result = timeout_at(forced_deadline, task.handle).await;
```

After `abort()`, prefer:

```rust
task.handle.abort();
let join_result = task.handle.await;
```

Tokio abort should resolve promptly once the task reaches cancellation. This preserves the invariant that every owned handle is awaited.

If absolute worker shutdown boundedness requires a hard deadline, ownership must be retained rather than dropped.

## Phase 12 — Add Explicit Incomplete Cleanup Residue If Needed

If a task can fail to yield after abort, add:

```rust
pub struct UnjoinedTaskResidue {
    pub id: TaskId,
    pub name: &'static str,
    pub class: TaskClass,
    pub handle: tokio::task::JoinHandle<()>,
}
```

And extend:

```rust
pub struct TaskSubsetCleanupReport {
    pub exits: Vec<NamedTaskExit>,
    pub not_found_ids: Vec<TaskId>,
    pub unjoined: Vec<UnjoinedTaskResidue>,
}
```

However, because `JoinHandle` is not `Clone` and should not normally remain after abort, use this only if a hard deadline is mandatory.

Preferred for this pass: abort, then await without a second timeout.

## Phase 13 — Do Not Remove Registry Ownership Before Cleanup Is Settled

Current code removes matched tasks from registry before waiting. This is acceptable only if the cleanup function retains exclusive ownership until every handle is settled.

Document this explicitly:

```text
Once extracted from the registry, cancel_then_join_tasks() is the sole owner of every matched handle and must return only after each handle is joined or returned as explicit residue.
```

## Phase 14 — Correct Forced Cleanup Classification

After `abort()`:

```rust
match task.handle.await {
    Err(error) if error.is_cancelled() => TaskExitReason::Aborted,
    Err(error) if error.is_panic() => TaskExitReason::Panic(error.to_string()),
    Err(error) => TaskExitReason::Error(error.to_string()),
    Ok(()) => TaskExitReason::CleanCompletion,
}
```

Do not classify an abort timeout as successfully cleaned.

## Phase 15 — Forced Cleanup Tests

Required tests:

- hung cooperative task is aborted and awaited;
- registry no longer contains the task only after join completes;
- no handle is dropped after timeout;
- panicking task preserves panic classification;
- already-finished task joins cleanly;
- unrelated task remains in registry;
- zero cooperative timeout still aborts and awaits;
- cleanup report contains no unjoined residue in normal Tokio tasks.

---

# Part D — Correct Support Stop Accounting

## Phase 16 — Replace Ambiguous `cooperative` Count

Current calculation:

```rust
cooperative = exits.len() - aborted_count
```

This counts panic/error exits as cooperative.

Preferred report:

```rust
pub struct MeshSupportStopReport {
    pub generation: u64,
    pub clean: usize,
    pub cancelled: usize,
    pub aborted: usize,
    pub failed: usize,
    pub not_found: usize,
}
```

Classification:

```rust
for exit in &report.exits {
    match exit.reason {
        TaskExitReason::CleanCompletion => clean += 1,
        TaskExitReason::Cancelled => cancelled += 1,
        TaskExitReason::Aborted => aborted += 1,
        TaskExitReason::Panic(_) | TaskExitReason::Error(_) => failed += 1,
        TaskExitReason::UnexpectedCompletion => failed += 1,
    }
}
```

Then:

```rust
pub fn clean(&self) -> bool {
    self.aborted == 0
        && self.failed == 0
        && self.not_found == 0
}
```

If preserving the existing field is necessary, rename it to `non_aborted`.

## Phase 17 — Include Not-Found IDs In Diagnostics

`not_found_ids` can mean:

- task already completed and was removed elsewhere;
- duplicate teardown;
- lost ownership bookkeeping.

Do not silently discard this signal.

For first teardown of an active bundle, not-found IDs should generally be treated as suspicious unless the registry reaper removes completed one-shot/background tasks eagerly.

Log them and add tests for expected cases.

## Phase 18 — Accounting Tests

Required cases:

- clean exits counted as clean;
- cooperative cancellation counted as cancelled;
- forced abort counted as aborted;
- panic/error counted only as failed;
- no double counting;
- not-found IDs surfaced;
- `clean()` semantics match the final ownership guarantee.

---

# Part E — Move The DHT Startup Hook To The Correct Boundary

## Phase 19 — Replace Or Reposition `BeforePeerConnect`

The hook currently fires before DHT initialization. It should prove the final invariant immediately before peer connection.

Preferred:

```rust
StartupFailurePoint::AfterDhtInitialization
```

Sequence:

```rust
// initialize DHT
...
#[cfg(test)]
self.check_startup_failure_hook(
    StartupFailurePoint::AfterDhtInitialization
).await?;

// connect seeds
```

Alternatively move `BeforePeerConnect` to this location and update its documentation.

## Phase 20 — Add State-Aware Hook Test

The hook should inspect the real routing manager:

```rust
transport.set_startup_hook(|point| {
    if point == StartupFailurePoint::AfterDhtInitialization {
        assert!(routing_manager.is_initialized().await);
    }
    Ok(())
});
```

If the existing hook is synchronous, add a test-only atomic set after initialization and assert it before connection begins.

Required proof:

- hook fires after initialization;
- no seed/configured peer connection begins first;
- disabled DHT skips the initialized-state assertion appropriately.

---

# Part F — Composition-Root Behavioral Test Harness

## Phase 21 — Add A Fake Optional Mesh Startup Service

Use a fake service with:

- controllable startup barrier;
- controllable support-registration success/failure;
- emitted critical exit;
- shutdown call counter;
- support task exit barriers;
- ready-message capture.

Tests should invoke the actual Phase 14.5 orchestration helper, not only isolated policy functions.

## Phase 22 — Extract A Testable Startup Orchestrator

If `run_unified_server_worker()` is too large to test directly, extract:

```rust
async fn start_worker_mesh_runtime(
    state: &UnifiedServerWorkerState,
    mesh_transport: Arc<MeshTransport>,
    policy: MeshSupervisionPolicy,
    support_tasks: Option<MeshSupportTasks>,
    ready_sender: &mut dyn WorkerReadySender,
) -> Result<WorkerMeshRuntimeStart, WorkerShutdownCause>
```

Suggested result:

```rust
pub struct WorkerMeshRuntimeStart {
    pub decision_rx: mpsc::Receiver<MeshSupervisorDecision>,
    pub optional_startup_rx: Option<mpsc::Receiver<OptionalMeshStartupResult>>,
    pub active_support: Option<MeshGenerationSupport>,
}
```

Keep it crate-private.

## Phase 23 — Direct Tests

Required end-to-end composition tests:

- required support failure never emits ready;
- optional success returns/stores bundle;
- optional degradation performs bounded subset cleanup;
- optional immediate-exit race leaves no support tasks;
- cleanup report classifications are correct;
- forced abort path awaits every handle;
- no task ID remains registered after support teardown.

---

# Part G — File-Level Implementation Guide

## `src/worker/unified_server/mod.rs`

Implement:

- `OptionalMeshStartupResult`;
- optional completion channel;
- composition-root ownership of optional support bundle;
- required two-stage startup commit;
- no-ready-on-support-failure;
- optional startup/degradation race handling;
- corrected stop report accounting.

## `src/worker/task_registry.rs`

Implement:

- abort-then-await without dropping handles;
- optional explicit residue only if unavoidable;
- precise cleanup classifications;
- tests proving registry removal and handle completion.

## `crates/synvoid-mesh/src/mesh/transport.rs`

Implement:

- repositioned/renamed startup hook after DHT initialization;
- matching guard tests.

## Tests

Add actual composition-root orchestration tests rather than only source guards.

---

# Part H — Ordered Execution Sequence For A Smaller Model

Implement in this exact order:

1. Gate required ready on support-registration success.
2. Add tests proving no ready on support failure.
3. Add optional startup completion result channel.
4. Return and store optional `MeshGenerationSupport` in the composition root.
5. Handle optional startup/degradation races.
6. Remove post-abort forced timeout or add explicit unjoined residue.
7. Correct support cleanup accounting.
8. Move the DHT startup hook after initialization.
9. Add direct composition-root behavioral tests.
10. Update guardrails and documentation.

Do not implement automatic restart.

---

# Part I — Guardrails

Update worker and mesh guards to enforce:

- optional startup does not discard `register_mesh_generation_support()` result;
- composition root stores optional support bundle;
- required ready block is conditional on support-registration success;
- required support failure cannot execute ready send;
- no timeout wraps an already-aborted `JoinHandle` unless ownership residue is retained;
- stop accounting does not derive cooperative count as `total - aborted`;
- startup hook occurs after DHT initialization;
- behavioral composition-root tests exist for optional bundle handoff and required support failure.

Behavioral tests remain authoritative.

---

# Verification Commands

Run focused worker tests:

```bash
cargo test -p synvoid --lib worker::unified_server --features mesh,dns
cargo test -p synvoid --lib worker::mesh_supervision --features mesh,dns
cargo test --test worker_supervision_control_flow --features mesh,dns
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns
cargo test --test worker_task_registry_lifecycle --features mesh,dns
```

Run focused mesh tests:

```bash
cargo test -p synvoid-mesh --features mesh startup
cargo test -p synvoid-mesh --features mesh dht
cargo test --test mesh_startup_rollback --features mesh,dns
cargo test --test mesh_task_ownership_guard --features mesh,dns
```

Run broader checks:

```bash
cargo test --test background_task_ownership_guard
cargo test --test data_plane_composition_boundary_guard
cargo test --test mesh_id_boundary_guard
cargo test --test threat_intel_boundary_guard
cargo test --test threat_intel_consumer_actionability_guard
cargo test --lib --no-run
cargo fmt --check
cargo clippy --workspace --all-targets --features mesh,dns -- -D warnings
```

---

# Acceptance Criteria

This pass is complete only when all of the following are true:

1. Optional startup returns its support bundle to the composition root.
2. `active_mesh_support` is populated for optional mesh success.
3. Optional degradation cancels, joins, and removes that exact support generation.
4. Optional startup failure creates no support bundle.
5. Immediate startup/exit races leave no support tasks behind.
6. Required support-registration failure emits no ready message.
7. Required readiness is sent only after transport and support commit.
8. Required support failure transitions directly to failed and begins cleanup.
9. Every aborted subset task handle is awaited or returned as explicit residue.
10. Registry removal occurs only after cleanup ownership is settled.
11. Support-stop accounting distinguishes clean, cancelled, aborted, failed, and not-found outcomes accurately.
12. The DHT startup hook proves initialization immediately before peer connection.
13. Direct composition-root behavioral tests cover optional bundle handoff and required support failure.
14. Existing mesh transport, DHT rollback, topology, worker supervision, threat-intel, provenance, and lifecycle guardrails remain green.

---

## Notes For The Implementer

This should be the final closure pass for worker-level mesh supervision.

Three rules govern the implementation:

> Background startup tasks may report facts, but the composition root owns lifecycle objects.

> Required readiness is a commit point, not a progress notification.

> Abort does not end ownership; joining or explicit residue transfer does.
