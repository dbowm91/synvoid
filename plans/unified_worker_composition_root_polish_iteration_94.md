# Unified Worker Composition Root Polish — Iteration 94

## Purpose

Iteration 93 successfully decomposed the unified worker composition root into typed internal modules:

- `startup_plan.rs`
- `supervision_loop.rs`
- `shutdown_executor.rs`
- `supervisor_notify.rs`

The result is a major improvement, but two corrective issues remain before moving to the next roadmap item:

1. `run_unified_server_worker()` still contains the supervision-outcome-to-shutdown-cause mapping block. The wrapper is much smaller, but it is not yet a pure orchestration shell.
2. `WorkerShutdownContext` carries `active_mesh_support`, but `shutdown_executor::execute_worker_shutdown()` currently destructures it as unused. This risks losing the explicit `stop_mesh_generation_support(..., SupportStopContext::WorkerShutdown)` reporting path for active support bundles during whole-worker shutdown.

This polish pass should address those two issues and tighten the guardrails added in Iteration 93. It should not start the larger worker mesh attachment extraction yet.

## Non-Goals

Do not redesign mesh startup.

Do not introduce a `WorkerMeshAttachment` abstraction in this pass.

Do not move mesh support helper types out of `mod.rs` unless doing so is required for the corrective changes.

Do not change startup ordering, readiness semantics, supervision policy, shutdown ordering, supervisor IPC messages, or exit-code mapping.

Do not add dependencies.

Do not loosen existing guard tests to make failures disappear.

## Current State To Correct

### Remaining Wrapper Mapping

`run_unified_server_worker()` now delegates startup and supervision, but still maps `SupervisionOutcome` to shutdown settings inline:

```rust
let (shutdown_cause, lifecycle_ack, graceful, drain_timeout) = match supervision_result.outcome {
    SupervisionOutcome::Lifecycle { event, accepted } => { ... }
    SupervisionOutcome::DirectCause(cause) => { ... }
};
```

This mapping belongs in a helper module so the wrapper only coordinates.

### Active Mesh Support Is Ignored During Shutdown

`WorkerShutdownContext` includes:

```rust
pub active_mesh_support: Option<MeshGenerationSupport>,
```

But `execute_worker_shutdown()` currently destructures it as:

```rust
active_mesh_support: _,
```

That should be corrected. During whole-worker shutdown, an active support bundle should be stopped explicitly with `SupportStopContext::WorkerShutdown`, and the resulting `MeshSupportStopReport` should be logged. Registry-wide shutdown should remain the fallback, not the only cleanup mechanism.

## Desired End State

After this pass:

- `run_unified_server_worker()` delegates startup, supervision, shutdown-plan construction, and shutdown execution.
- Supervision outcome mapping is moved to a typed helper, preferably in `shutdown_executor.rs` or `supervision_loop.rs`.
- `shutdown_executor.rs` explicitly stops active mesh generation support during whole-worker shutdown when present.
- Support stop reports are logged with context and counts.
- The composition-root guard enforces a stricter threshold or stronger structural assertions.
- Existing behavior and ordering remain unchanged.

A desirable final wrapper shape:

```rust
pub async fn run_unified_server_worker(
    args: UnifiedServerWorkerArgs,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let startup = startup_plan::build_worker_startup(args).await?;

    let supervision = supervision_loop::run_worker_supervision(
        &startup.state,
        startup.lifecycle_rx,
        startup.exit_rx,
        startup.mesh_decision_rx(),
        startup.required_mesh_startup_failure(),
        startup.active_mesh_support(),
    )
    .await;

    let shutdown_ctx = shutdown_executor::WorkerShutdownContext::from_startup_and_supervision(
        startup,
        supervision,
    );
    shutdown_executor::execute_worker_shutdown(shutdown_ctx).await?;

    Ok(())
}
```

Exact helper names can differ. The key is that the wrapper no longer owns shutdown-cause mapping logic.

## Phase 1 — Move Supervision Outcome Mapping Out Of `mod.rs`

Add a helper type and constructor. Preferred location: `shutdown_executor.rs`, because the mapping produces shutdown execution inputs.

### Suggested Types

```rust
pub struct WorkerShutdownPlan {
    pub shutdown_cause: WorkerShutdownCause,
    pub lifecycle_ack: Option<tokio::sync::oneshot::Sender<()>>,
    pub graceful: bool,
    pub drain_timeout: std::time::Duration,
}
```

Then add:

```rust
impl WorkerShutdownPlan {
    pub fn from_supervision_outcome(
        outcome: crate::worker::task_registry::SupervisionOutcome,
    ) -> Self {
        match outcome {
            crate::worker::task_registry::SupervisionOutcome::Lifecycle { event, accepted } => {
                // Preserve current mapping exactly.
            }
            crate::worker::task_registry::SupervisionOutcome::DirectCause(cause) => {
                // Preserve current direct-cause graceful/drain mapping exactly.
            }
        }
    }
}
```

Then update `WorkerShutdownContext`:

```rust
pub struct WorkerShutdownContext {
    pub worker_id: WorkerId,
    pub state: UnifiedServerWorkerState,
    pub plan: WorkerShutdownPlan,
    pub active_mesh_support: Option<MeshGenerationSupport>,
}
```

Or keep flattened fields if preferred:

```rust
pub fn from_supervision_result(
    worker_id: WorkerId,
    state: UnifiedServerWorkerState,
    result: WorkerSupervisionResult,
) -> WorkerShutdownContext;
```

### Required Mapping Semantics

Preserve the current lifecycle mapping:

- `MasterShutdown { graceful, timeout }` → `WorkerShutdownCause::SupervisorShutdown`, same graceful and timeout values.
- `WorkerResize { worker_threads }` → `WorkerShutdownCause::WorkerResize { worker_threads }`, graceful `true`, timeout `30s`.
- `SupervisorDisconnected` → `WorkerShutdownCause::SupervisorDisconnected`, graceful `false`, timeout `0s`.

Preserve the current direct-cause mapping:

Non-graceful direct causes:

- `ServerExitedUnexpectedly(_)`
- `CriticalTaskExit(_)`
- `RegistryExitChannelClosed`
- `SupervisorDisconnected`
- mesh startup/shutdown/service/restart/config invariant causes when `mesh` feature is enabled.

All other direct causes remain graceful with `30s` drain timeout.

### Acceptance Criteria

- `run_unified_server_worker()` no longer contains a `match supervision_result.outcome` block.
- The mapping is unit-testable without running the worker.
- Existing tests still pass.

## Phase 2 — Add Mapping Unit Tests

Add focused tests near the helper, ideally inside `shutdown_executor.rs` under `#[cfg(test)]`.

Test these cases:

```rust
#[test]
fn lifecycle_master_shutdown_preserves_graceful_and_timeout() { ... }

#[test]
fn lifecycle_resize_is_graceful_with_default_timeout() { ... }

#[test]
fn lifecycle_supervisor_disconnected_is_immediate() { ... }

#[test]
fn direct_critical_task_exit_is_immediate() { ... }

#[test]
fn direct_external_stop_is_graceful() { ... }
```

If constructing `NamedTaskExit` is noisy, choose a simpler fatal cause that is easy to construct. Do not weaken the production mapping to make tests easier.

For mesh feature builds, add mesh-cause tests behind `#[cfg(feature = "mesh")]` if construction is straightforward.

## Phase 3 — Restore Explicit Active Mesh Support Shutdown

In `shutdown_executor::execute_worker_shutdown()`, consume `active_mesh_support` and stop it explicitly during whole-worker shutdown.

### Placement

Place this after mesh transport shutdown classification and before registry-wide broadcast shutdown.

Recommended position:

1. Stop accepting.
2. Drain.
3. Stop app servers.
4. Shut down mesh transport.
5. Stop active mesh support bundle explicitly.
6. Clear running flag.
7. Broadcast registry shutdown.
8. Join registry tasks.

Reasoning: the support bundle belongs to the mesh generation and should be given an explicit cooperative stop/report path before the generic registry shutdown broadcast.

### Suggested Code Shape

```rust
#[cfg(feature = "mesh")]
if let Some(support) = active_mesh_support.take() {
    let remaining = remaining_budget();
    let timeout = if remaining.is_zero() {
        std::time::Duration::from_secs(5)
    } else {
        remaining.min(std::time::Duration::from_secs(5))
    };

    let stop_report = crate::worker::unified_server::stop_mesh_generation_support(
        &state.task_registry,
        support,
        timeout,
        crate::worker::unified_server::SupportStopContext::WorkerShutdown,
    )
    .await;

    if stop_report.clean() {
        tracing::info!(
            generation = stop_report.generation,
            cooperative = stop_report.cooperative,
            "mesh support generation stopped cleanly during worker shutdown"
        );
    } else {
        tracing::warn!(
            generation = stop_report.generation,
            cooperative = stop_report.cooperative,
            aborted = stop_report.aborted,
            failed = stop_report.failed,
            not_found = stop_report.not_found,
            "mesh support generation required cleanup during worker shutdown"
        );
    }
}
```

Use the actual remaining-budget logic already present in the executor. Avoid a zero timeout if it would force immediate abort; if the worker is already out of budget, a small bounded fallback is acceptable only if it matches the prior intended behavior. If uncertain, use `remaining_budget()` and document the fallback.

### Important Constraints

Do not stop support twice. If optional mesh degradation already took the support bundle, `active_mesh_support` should be `None`.

Do not rely only on `registry.broadcast_shutdown()` for support cleanup; explicit stop/reporting is the point of this corrective pass.

Do not change `stop_mesh_generation_support()` semantics.

## Phase 4 — Add Shutdown Support Tests Or Guardrails

Add one or both of the following.

### Option A — Source Guard

Extend `tests/unified_worker_composition_root_guard.rs` with a test that checks `shutdown_executor.rs` references `stop_mesh_generation_support` and `SupportStopContext::WorkerShutdown` when mesh is enabled.

Example:

```rust
#[test]
fn shutdown_executor_explicitly_stops_active_mesh_support() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(
        repo.join("src/worker/unified_server/shutdown_executor.rs")
    ).unwrap();

    assert!(source.contains("stop_mesh_generation_support"));
    assert!(source.contains("SupportStopContext::WorkerShutdown"));
    assert!(!source.contains("active_mesh_support: _,"));
}
```

This is crude but useful as a regression tripwire.

### Option B — Unit Test

If feasible, add a unit test around a helper function that converts support-stop report into a log disposition or shutdown disposition. Avoid building a full async worker state just to test this; that would be too heavy for this polish pass.

## Phase 5 — Tighten The Wrapper Guard

`tests/unified_worker_composition_root_guard.rs` currently allows up to 150 lines. After moving the mapping out, lower the threshold to something closer to the desired wrapper shape.

Suggested threshold: `<= 80` lines.

Also add a guard that the wrapper no longer contains:

```text
match supervision_result.outcome
```

Suggested test:

```rust
#[test]
fn run_unified_server_worker_does_not_map_supervision_outcome_inline() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(repo.join("src/worker/unified_server/mod.rs")).unwrap();
    let function = extract_run_unified_server_worker_body(&source);

    assert!(!function.contains("match supervision_result.outcome"));
    assert!(!function.contains("SupervisionOutcome::Lifecycle"));
    assert!(!function.contains("SupervisionOutcome::DirectCause"));
}
```

If no helper extractor exists, use the same crude slicing logic already in the file. Keep it simple.

## Phase 6 — Re-check Source Guard Updates From Iteration 93

Iteration 93 updated several source-text scanning guards:

- `tests/background_task_ownership_guard.rs`
- `tests/worker_mesh_supervision_boundary_guard.rs`
- `tests/data_plane_composition_boundary_guard.rs`
- `tests/worker_supervision_control_flow.rs`

Review those edits for over-broad allowlisting. The goal is to account for new module locations, not to weaken the guards.

If the edits simply add the new files to the scan set or approved module list, keep them.

If they skip entire files such as `startup_plan.rs` or `shutdown_executor.rs` without a targeted reason, narrow them.

## Phase 7 — Verification Commands

Minimum:

```bash
cargo fmt
cargo check -p synvoid
cargo test --test unified_worker_composition_root_guard
cargo test --test root_facade_boundary_guard
cargo test --test root_module_ledger_guard
```

Worker/mesh-focused:

```bash
cargo test --test composition_root_behavioral --features mesh,dns
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns
cargo test --test worker_supervision_control_flow --features mesh,dns
cargo test --test background_task_ownership_guard
cargo test --test mesh_task_ownership_guard --features mesh,dns
```

Package checks:

```bash
cargo check -p synvoid-http3
cargo check -p synvoid-http
cargo check -p synvoid-waf
cargo check -p synvoid-mesh --features mesh
cargo check --no-default-features --features mesh,dns
```

Known caveat remains: if `cargo check --no-default-features` still fails on a pre-existing `stop_mesh_generation_support` import issue, document it rather than treating it as introduced by this pass.

## Acceptance Criteria

This polish pass is complete when:

- `run_unified_server_worker()` delegates outcome mapping rather than owning it inline.
- `shutdown_executor.rs` uses `active_mesh_support` explicitly.
- Whole-worker shutdown invokes `stop_mesh_generation_support(..., SupportStopContext::WorkerShutdown)` when a support bundle exists.
- The support stop report is logged with cooperative, aborted, failed, and not-found counts.
- Guard tests prevent regression to inline outcome mapping and ignored active mesh support.
- Existing worker/mesh supervision tests pass or failures are documented as pre-existing and unrelated.

## Expected Files To Touch

Likely:

```text
src/worker/unified_server/mod.rs
src/worker/unified_server/shutdown_executor.rs
tests/unified_worker_composition_root_guard.rs
```

Possibly:

```text
src/worker/unified_server/supervision_loop.rs
src/worker/unified_server/supervisor_notify.rs
tests/worker_supervision_control_flow.rs
tests/worker_mesh_supervision_boundary_guard.rs
```

Avoid touching `startup_plan.rs` unless needed for type movement or helper construction.

## Handoff Summary

Iteration 93 did the hard extraction. Iteration 94 should finish the polish: make the wrapper truly thin, restore explicit mesh support shutdown/reporting, and tighten the guardrails so the same issues do not regress. After this pass lands, the repo should be ready for the next roadmap item: worker-side mesh attachment extraction.
