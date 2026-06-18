# Worker Mesh Final Corrective Pass — Iteration 88

## Purpose

Iteration 87 moved DHT initialization into transactional mesh startup, added generation-scoped worker support bundles, introduced direct YARA helper tests and metrics, and replaced synthetic topology/DHT builder tests with real component tests.

The current head at `ebe26bbbd79d1f17b9c29c25672ebcda0df5ddad` still has six concrete issues:

1. DHT initialization occurs after configured-peer connection, so `dht_on_peer_connected()` can silently lose configured-peer routing inserts before the table exists.
2. Optional mesh degradation cancels generation support but does not join or remove those task handles before discarding the bundle.
3. YARA support creates a detached bridge task to combine worker and generation shutdown signals.
4. DHT degraded-path reporting can claim initialization succeeded even when it did not, and maintenance can still be registered against absent routing state.
5. `cancel_and_join_tasks()` contains dead code and hard-codes shutdown expectedness even when used during live optional degradation.
6. Documentation still mentions DHT init in `MeshSupportTasks` and does not fully describe the final ownership semantics.

This is the final corrective pass before subsystem closure.

The governing invariants are:

> DHT state exists before any peer connection can mutate it.

> Generation support teardown is complete only after cooperative cancellation, bounded join, abort fallback, and registry removal.

> No detached bridge task may exist solely to combine cancellation signals.

---

## Non-Goals

Do not implement automatic mesh restart.

Do not redesign DHT routing semantics.

Do not change HTTP framing or peer-session lifecycle.

Do not add a new general cancellation framework if the existing watch-channel model can be composed directly.

---

# Part A — Move DHT Initialization Before Any Peer Connection

## Phase 1 — Reorder Startup Phases

Current order:

```text
Phase 4: connect seeds
Phase 5: connect configured peers
Phase 5.5: initialize DHT routing
Phase 6: DHT bootstrap
```

Required order:

```text
Phase 3.5: initialize or restore DHT routing
Phase 4: connect seeds
Phase 5: connect configured peers
Phase 6: DHT bootstrap
Phase 7: register topology/DHT maintenance
```

Move the full DHT initialization block before both seed and configured-peer connection.

Example:

```rust
// Phase 3.5: initialize or restore DHT routing before any peer connection.
let dht_ready = if let Some(ref rm) = self.routing_manager {
    if rm.is_enabled() {
        let was_initialized = rm.is_initialized().await;

        if !was_initialized {
            rm.init().await;
        }

        let initialized = rm.is_initialized().await;
        report.dht_routing_initialized = initialized;

        stage.record_dht_init(DhtInitializationSnapshot {
            was_initialized_this_attempt: !was_initialized && initialized,
        });

        if !initialized {
            let reason = "DHT routing initialization did not create a routing table";
            if policy.require_dht_initialization {
                return Err(MeshTransportError::StartupFailed(reason.into()));
            }
            report.degraded_reasons.push(reason.into());
        }

        initialized
    } else {
        false
    }
} else {
    false
};
```

Store `dht_ready` for later bootstrap and maintenance gating.

## Phase 2 — Use Checked Peer Insertion From Connection Paths

`dht_on_peer_connected()` currently calls the silent `add_peer()` method.

Change it to a checked path:

```rust
pub(crate) async fn dht_on_peer_connected(
    &self,
    peer_node_id: &str,
    peer_address: &str,
    peer_role: MeshNodeRole,
) -> Result<(), MeshTransportError> {
    if let Some(ref rm) = self.routing_manager {
        if rm.is_enabled() {
            rm.add_peer_checked(
                peer_node_id.to_string(),
                peer_address.to_string(),
                443,
                peer_role,
                None,
                false,
                None,
                None,
                None,
            )
            .await
            .map_err(|e| {
                MeshTransportError::StartupFailed(format!(
                    "failed to add connected peer {peer_node_id} to DHT: {e}"
                ))
            })?;
        }
    }

    // Existing ping/serverless/YARA/threat-intel/catchup work follows.
    Ok(())
}
```

If changing the existing return type is too invasive, add a startup-only checked helper:

```rust
async fn dht_on_peer_connected_checked(...) -> Result<(), MeshTransportError>
```

Use the checked helper during seed/configured-peer startup. Keep the best-effort helper only for already-running runtime connections.

## Phase 3 — Propagate Checked Failures Through Startup

Connection helpers must not swallow checked DHT insertion errors.

Example:

```rust
self.dht_on_peer_connected_checked(&node_id, &address, role)
    .await?;
```

Policy behavior:

- required DHT initialization -> fail startup;
- optional DHT initialization -> connection may remain established, but record degraded state and skip DHT-specific bootstrap/maintenance;
- never silently report a peer as inserted when the table was absent.

## Phase 4 — Gate Bootstrap And Maintenance On Actual Initialization

Do not bootstrap or register DHT maintenance unless `dht_ready == true`.

Example:

```rust
if dht_ready {
    match self.dht_bootstrap_from_seeds(rm.clone()).await {
        Ok(()) => report.dht_bootstrapped = true,
        Err(e) if policy.require_dht_bootstrap => {
            return Err(MeshTransportError::StartupFailed(format!(
                "DHT bootstrap required but failed: {e}"
            )));
        }
        Err(e) => report.degraded_reasons.push(format!(
            "DHT bootstrap failed: {e}"
        )),
    }
}
```

And in Phase 7:

```rust
if dht_ready {
    let dht_specs = rm.build_background_tasks(shutdown_rx.clone());
    stage.task_group.register_background_specs(dht_specs);
}
```

Do not set `report.dht_routing_initialized = true` unconditionally.

## Phase 5 — Add DHT Ordering Tests

Required tests using real startup helpers/components:

- routing table exists before first seed connection callback;
- routing table exists before first configured-peer connection callback;
- configured peer is present after startup;
- seed peer and configured peer both remain in routing state;
- uninitialized checked insertion returns an error;
- optional initialization failure skips bootstrap and DHT maintenance;
- required initialization failure aborts startup;
- rollback clears a table created by the failed attempt;
- pre-existing initialized table is preserved on rollback.

A useful test hook:

```rust
#[cfg(test)]
startup_hook.before_peer_connect
```

The hook should assert `rm.is_initialized().await` before allowing peer connection to proceed.

---

# Part B — Make Support Teardown Cooperative, Bounded, And Verified

## Phase 6 — Replace `cancel()`-Only Teardown

Current degradation path:

```rust
if let Some(support) = active_mesh_support.take() {
    support.cancel();
}
```

Required path:

```rust
if let Some(support) = active_mesh_support.take() {
    let report = stop_mesh_generation_support(
        &state,
        support,
        Duration::from_secs(5),
        SupportStopContext::OptionalMeshDegraded,
    )
    .await;

    if !report.clean() {
        tracing::warn!(?report, "mesh support generation required forced cleanup");
    }
}
```

## Phase 7 — Add `stop_mesh_generation_support()`

Suggested types:

```rust
#[derive(Debug, Clone, Copy)]
pub enum SupportStopContext {
    OptionalMeshDegraded,
    WorkerShutdown,
    StartupRollback,
}

#[derive(Debug)]
pub struct MeshSupportStopReport {
    pub generation: u64,
    pub cooperative: usize,
    pub aborted: usize,
    pub failed: usize,
}

impl MeshSupportStopReport {
    pub fn clean(&self) -> bool {
        self.aborted == 0 && self.failed == 0
    }
}
```

Helper sketch:

```rust
async fn stop_mesh_generation_support(
    state: &UnifiedServerWorkerState,
    support: MeshGenerationSupport,
    timeout: Duration,
    context: SupportStopContext,
) -> MeshSupportStopReport {
    support.cancel();

    let cooperative_budget = timeout / 2;
    let forced_budget = timeout.saturating_sub(cooperative_budget);

    let mut registry = state.task_registry.lock().await;

    let cooperative = registry
        .join_tasks_until(
            &support.task_ids,
            cooperative_budget,
            context.expected_during_shutdown(),
        )
        .await;

    let remaining_ids: Vec<TaskId> = cooperative
        .remaining_task_ids;

    let forced = registry
        .abort_and_join_tasks(
            &remaining_ids,
            forced_budget,
            context.expected_during_shutdown(),
        )
        .await;

    MeshSupportStopReport::from_parts(
        support.generation,
        cooperative,
        forced,
    )
}
```

A simpler implementation may use one method if it performs cooperative wait first and aborts only on deadline.

## Phase 8 — Refactor Registry Subset APIs

Replace the current immediate-abort-only method with two explicit operations or one context-aware operation.

Preferred API:

```rust
pub struct TaskSubsetJoinReport {
    pub exits: Vec<NamedTaskExit>,
    pub remaining_task_ids: Vec<TaskId>,
}

pub async fn join_tasks_until(
    &mut self,
    task_ids: &[TaskId],
    timeout: Duration,
    expected_during_shutdown: bool,
) -> TaskSubsetJoinReport;

pub async fn abort_and_join_tasks(
    &mut self,
    task_ids: &[TaskId],
    timeout: Duration,
    expected_during_shutdown: bool,
) -> Vec<NamedTaskExit>;
```

Acceptable compact API:

```rust
pub async fn cancel_then_join_tasks(
    &mut self,
    task_ids: &[TaskId],
    cooperative_timeout: Duration,
    forced_timeout: Duration,
    expected_during_shutdown: bool,
) -> TaskSubsetCleanupReport;
```

Remove the no-op `retain()` block entirely.

## Phase 9 — Preserve Correct Expectedness

For optional degradation while the worker remains active:

```rust
expected_during_shutdown = false
```

For whole-worker shutdown:

```rust
expected_during_shutdown = true
```

Do not hard-code `true` in registry subset cleanup.

## Phase 10 — Verify Registry Removal

After support cleanup:

- every bundle task ID must be absent from critical/background registries;
- every handle must have been joined;
- the bundle is dropped only after verification;
- repeated degradation events remain idempotent because `active_mesh_support.take()` returns `None` after the first cleanup.

Add a helper if useful:

```rust
pub fn contains_task(&self, id: TaskId) -> bool
```

for tests and assertions.

## Phase 11 — Add Support Teardown Tests

Required real tests:

- cooperative DNS/YARA support exits within grace period;
- hung support task is aborted and awaited;
- task IDs are removed from registry;
- optional degradation marks exits as not expected-during-shutdown;
- worker shutdown marks exits expected;
- repeated teardown is idempotent;
- unrelated worker tasks remain registered;
- active bundle is cleared only after cleanup completes.

---

# Part C — Remove The Detached YARA Shutdown Bridge

## Phase 12 — Pass Both Shutdown Receivers Directly

Change the helper signature from one combined receiver:

```rust
async fn run_yara_broadcast_loop(
    ...,
    mut shutdown_rx: watch::Receiver<bool>,
    drain_timeout: Duration,
) -> YaraBroadcastReport
```

To:

```rust
async fn run_yara_broadcast_loop(
    ...,
    mut worker_shutdown_rx: watch::Receiver<bool>,
    mut generation_shutdown_rx: watch::Receiver<bool>,
    drain_timeout: Duration,
) -> YaraBroadcastReport
```

Then select directly:

```rust
loop {
    tokio::select! {
        biased;

        _ = worker_shutdown_rx.changed() => {
            tracing::debug!("YARA loop received worker shutdown");
            break;
        }

        _ = generation_shutdown_rx.changed() => {
            tracing::debug!("YARA loop received generation shutdown");
            break;
        }

        Some(result) = children.join_next(), if !children.is_empty() => {
            classify_yara_child_result(result, &mut report);
        }

        msg = broadcast_rx.recv() => {
            // existing admission logic
        }
    }
}
```

No bridge task is needed.

## Phase 13 — Remove Bridge Spawn And Allowlist Entry

Delete:

```rust
tokio::spawn(async move {
    tokio::select! {
        _ = ws.changed() => { let _ = tx.send(true); }
        _ = gc.changed() => { let _ = tx.send(true); }
    }
});
```

Remove any ownership-guard allowlist entry added for that spawn.

## Phase 14 — Handle Already-True Receivers

Watch receivers may already contain `true` before `changed()` is called.

At loop start and before each select, check:

```rust
if *worker_shutdown_rx.borrow() || *generation_shutdown_rx.borrow() {
    break;
}
```

Otherwise a receiver initialized to `true` can wait forever for a future change.

## Phase 15 — Add Bridge-Free YARA Tests

Required direct helper tests:

- worker shutdown stops loop;
- generation shutdown stops loop;
- either signal already true before helper starts stops immediately;
- channel closure stops loop;
- no detached bridge task remains;
- support teardown waits for YARA outer task to return;
- hung children still follow bounded drain/abort-and-await.

---

# Part D — Correct DHT Degraded Reporting And Maintenance Gating

## Phase 16 — Set Report Fields From Actual State

Replace unconditional assignment:

```rust
report.dht_routing_initialized = true;
```

With:

```rust
let initialized = rm.is_initialized().await;
report.dht_routing_initialized = initialized;
```

Record the rollback snapshot only when the current attempt actually created a table:

```rust
stage.record_dht_init(DhtInitializationSnapshot {
    was_initialized_this_attempt: !was_initialized && initialized,
});
```

## Phase 17 — Skip DHT Maintenance When Initialization Failed

Example:

```rust
if dht_ready {
    let specs = rm.build_background_tasks(shutdown_rx.clone());
    stage.task_group.register_background_specs(specs);
} else {
    tracing::warn!("DHT routing unavailable; skipping DHT maintenance tasks");
}
```

## Phase 18 — Make `add_peer()` Behavior Explicit

Long-term preferred API:

```rust
pub async fn add_peer(...) -> Result<bool, DhtRoutingError>
```

For this pass, acceptable minimum:

- startup code uses `add_peer_checked()`;
- runtime best-effort `add_peer()` logs a warning when enabled-but-uninitialized rather than silently returning;
- tests cover both paths.

Example:

```rust
let Some(table) = rt.as_mut() else {
    tracing::warn!(peer = %peer_node_id, "DHT peer insert skipped: routing table not initialized");
    return;
};
```

---

# Part E — Documentation And Cleanup

## Phase 19 — Correct `MeshSupportTasks` Documentation

Remove references to DHT routing init.

Correct text:

```text
MeshSupportTasks contains worker-owned post-commit support only:
DNS verification and YARA broadcast.
DHT routing initialization belongs to MeshTransport transactional startup.
```

## Phase 20 — Remove Dead Registry Code

Delete the no-op retain block in `cancel_and_join_tasks()`.

Also rename or replace the method so the name matches behavior. An API named `cancel_and_join_tasks()` should not immediately abort unless that is explicitly documented.

## Phase 21 — Document Final Ownership

Update:

- `AGENTS.md`;
- `skills/synvoid_mesh.md`;
- worker lifecycle architecture docs;
- ownership tables.

Final ownership model:

```text
DHT initialization/restore     MeshTransport startup stage
Seed/configured peer DHT add   MeshTransport checked startup path
Topology/DHT maintenance       MeshTaskGroup
DNS/YARA support               WorkerTaskRegistry + MeshGenerationSupport
YARA child broadcasts          YARA task-local JoinSet
Optional degradation cleanup   composition root cancel + bounded subset join
```

---

# Part F — File-Level Implementation Guide

## `crates/synvoid-mesh/src/mesh/transport.rs`

- move DHT initialization before seed/configured-peer connection;
- retain `dht_ready` through later phases;
- gate bootstrap and maintenance;
- correct report/snapshot assignment;
- add startup hooks/tests.

## `crates/synvoid-mesh/src/mesh/transport_connection.rs`

- add checked startup peer-connect DHT insertion;
- propagate errors during startup;
- log explicit runtime best-effort failures.

## `crates/synvoid-mesh/src/mesh/dht/routing/manager.rs`

- keep `add_peer_checked()` authoritative for startup;
- make silent runtime no-op observable;
- add tests.

## `src/worker/unified_server/mod.rs`

- add `stop_mesh_generation_support()`;
- use it on optional degradation and worker shutdown where appropriate;
- pass both shutdown receivers directly to YARA helper;
- remove detached bridge spawn;
- update docs.

## `src/worker/task_registry.rs`

- remove dead retain block;
- add cooperative subset wait and forced subset cleanup;
- accept expectedness/context;
- add registry-removal verification tests.

---

# Part G — Ordered Execution Sequence For A Smaller Model

Implement in this exact order:

1. Move DHT initialization before all peer connection phases.
2. Introduce `dht_ready` and gate bootstrap/maintenance.
3. Switch startup peer insertion to `add_peer_checked()`.
4. Correct startup report and snapshot semantics.
5. Add DHT ordering and configured-peer insertion tests.
6. Remove YARA bridge task and pass both shutdown receivers directly.
7. Add already-true shutdown checks and YARA tests.
8. Refactor registry subset cleanup APIs.
9. Add `stop_mesh_generation_support()` with cooperative then forced cleanup.
10. Use bounded teardown on optional degradation.
11. Verify task IDs are removed and unrelated tasks remain.
12. Clean documentation and guardrails.

Do not implement automatic restart in this pass.

---

# Part H — Guardrails

Update source/boundary guards to enforce:

- DHT initialization appears before seed/configured-peer connection;
- startup peer insertion uses `add_peer_checked()`;
- DHT bootstrap and maintenance are gated by actual initialization;
- no detached YARA bridge `tokio::spawn()` exists;
- YARA helper accepts worker and generation shutdown directly;
- optional degradation calls bounded support cleanup, not only `cancel()`;
- subset cleanup supports non-shutdown expectedness;
- no dead retain block remains;
- `MeshSupportTasks` docs do not mention DHT init.

Behavioral tests remain authoritative.

---

# Verification Commands

Run focused mesh tests:

```bash
cargo test -p synvoid-mesh --features mesh dht
cargo test -p synvoid-mesh --features mesh startup
cargo test --test mesh_startup_rollback --features mesh,dns
cargo test --test mesh_lifecycle_tests --features mesh,dns
cargo test --test mesh_task_ownership_guard --features mesh,dns
```

Run focused worker tests:

```bash
cargo test -p synvoid --lib worker::mesh_supervision --features mesh,dns
cargo test worker::unified_server --features mesh,dns
cargo test --test worker_supervision_control_flow --features mesh,dns
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns
cargo test --test worker_task_registry_lifecycle --features mesh,dns
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

1. DHT routing state exists before any seed or configured-peer connection callback can mutate it.
2. Configured peers are not silently lost from the routing table.
3. Startup peer insertion uses a checked DHT path.
4. DHT bootstrap and maintenance are skipped when initialization is unavailable.
5. Startup reports reflect actual initialization state.
6. Optional degradation cancels, joins, removes, and verifies all generation support tasks.
7. Cooperative support teardown is attempted before abort fallback.
8. Support cleanup expectedness is correct for degradation versus worker shutdown.
9. No generation support task handle remains in the registry after cleanup.
10. No detached YARA shutdown bridge task exists.
11. YARA responds directly to worker and generation cancellation, including already-true signals.
12. Registry subset cleanup contains no dead code and preserves unrelated tasks.
13. Documentation reflects the final ownership model.
14. Existing mesh transport, DHT rollback, topology, worker supervision, threat-intel, provenance, and lifecycle guardrails remain green.

---

## Notes For The Implementer

This is the final corrective pass before subsystem closure.

Three rules govern the implementation:

> Initialize DHT before connecting anything that writes to it.

> Cancellation is not cleanup until the task handles are joined or abort-and-joined.

> Cancellation composition should be direct; do not create detached bridge tasks.
