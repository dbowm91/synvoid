# Worker Mesh Attachment Polish — Iteration 96

## Purpose

Iteration 95 successfully moved worker-side mesh attachment orchestration out of `startup_plan.rs` and into:

```text
src/worker/unified_server/mesh_attachment.rs
```

That created the correct ownership seam. The remaining issue is local structure: `mesh_attachment.rs` now owns the right concern, but `attach_mesh()` is still a dense function containing pipeline creation, required startup, optional startup, support registration, and optional degradation race handling.

This polish pass should split the new module into small internal helpers and tighten guardrails. It should not move ownership again and should not change mesh semantics.

## Current State

The current implementation added:

```text
src/worker/unified_server/mesh_attachment.rs
```

with:

- `WorkerMeshAttachmentInput<'a>`;
- free function `attach_mesh(input) -> Result<Option<MeshStartupState>, BoxError>`;
- supervision pipeline creation;
- required mesh startup path;
- optional mesh startup path;
- support registration one-shot;
- optional startup/degradation select loop;
- return of `MeshStartupState`.

`startup_plan.rs` is now much smaller and delegates mesh attachment behavior to `mesh_attachment::attach_mesh()`.

This is correct directionally, but the new module needs a cleanup pass so future mesh lifecycle work can be reviewed without reading one long function.

## Non-Goals

Do not move `mesh_attachment.rs` into a separate crate.

Do not move `MeshGenerationSupport`, `MeshSupportTasks`, or `stop_mesh_generation_support()` out of `mod.rs` in this pass unless required for a compile fix.

Do not change required/optional mesh semantics.

Do not change readiness timing.

Do not change support task registration ordering.

Do not change shutdown executor behavior from Iteration 94.

Do not change mesh transport internals.

Do not introduce new dependencies.

Do not loosen existing source guards to make the refactor pass.

## Desired End State

After this pass, `attach_mesh()` should be a short orchestration wrapper. Approximate target shape:

```rust
#[cfg(feature = "mesh")]
pub async fn attach_mesh(
    input: WorkerMeshAttachmentInput<'_>,
) -> Result<Option<MeshStartupState>, BoxError> {
    if !input.has_mesh_transport {
        tracing::info!("Mesh disabled — no supervision pipeline created");
        return Ok(None);
    }

    let runtime = create_mesh_pipeline(&input).await?;

    if input.state.mesh_policy.as_ref().is_some_and(|p| p.required) {
        start_required_mesh(RequiredMeshStartInput { input, runtime }).await.map(Some)
    } else {
        start_optional_mesh(OptionalMeshStartInput { input, runtime }).await.map(Some)
    }
}
```

Exact names can differ. The important point is that each helper owns one piece of behavior and returns typed outputs.

## Recommended Internal Types

Add private helper structs in `mesh_attachment.rs`.

### Pipeline Runtime

```rust
#[cfg(feature = "mesh")]
struct MeshPipelineRuntime {
    mesh_transport: Arc<synvoid_mesh::MeshTransport>,
    event_tx: tokio::sync::mpsc::Sender<crate::worker::mesh_supervision::MeshSupervisionEvent>,
    decision_rx: tokio::sync::mpsc::Receiver<crate::worker::mesh_supervision::MeshSupervisorDecision>,
}
```

### Required Startup Input/Output

```rust
#[cfg(feature = "mesh")]
struct RequiredMeshStartInput<'a> {
    worker_id: synvoid_ipc::WorkerId,
    state: &'a UnifiedServerWorkerState,
    readiness: &'a WorkerReadinessPlan,
    mesh_status: std::sync::Arc<tokio::sync::RwLock<crate::worker::mesh_supervision::WorkerMeshStatus>>,
    mesh_transport: Arc<synvoid_mesh::MeshTransport>,
    support_tasks: Option<super::MeshSupportTasks>,
    decision_rx: tokio::sync::mpsc::Receiver<crate::worker::mesh_supervision::MeshSupervisorDecision>,
}

#[cfg(feature = "mesh")]
struct RequiredMeshStartOutput {
    startup_failure: Option<crate::worker::task_registry::WorkerShutdownCause>,
    active_mesh_support: Option<MeshGenerationSupport>,
    decision_rx: tokio::sync::mpsc::Receiver<crate::worker::mesh_supervision::MeshSupervisorDecision>,
}
```

If moving `decision_rx` through a helper is awkward, let the outer `attach_mesh()` own it and pass `&mut` only if that compiles cleanly. Prefer simple ownership over clever lifetimes.

### Optional Startup Input/Output

```rust
#[cfg(feature = "mesh")]
struct OptionalMeshStartInput<'a> {
    state: &'a UnifiedServerWorkerState,
    mesh_status: std::sync::Arc<tokio::sync::RwLock<crate::worker::mesh_supervision::WorkerMeshStatus>>,
    mesh_transport: Arc<synvoid_mesh::MeshTransport>,
    event_tx: tokio::sync::mpsc::Sender<crate::worker::mesh_supervision::MeshSupervisionEvent>,
    decision_rx: tokio::sync::mpsc::Receiver<crate::worker::mesh_supervision::MeshSupervisorDecision>,
    support_tasks: Option<super::MeshSupportTasks>,
}

#[cfg(feature = "mesh")]
struct OptionalMeshStartOutput {
    startup_failure: Option<crate::worker::task_registry::WorkerShutdownCause>,
    active_mesh_support: Option<MeshGenerationSupport>,
    decision_rx: tokio::sync::mpsc::Receiver<crate::worker::mesh_supervision::MeshSupervisorDecision>,
}
```

Do not over-engineer this. The structs only exist to avoid giant function signatures.

## Phase 1 — Extract Pipeline Creation

Move the pipeline creation and critical task registration out of `attach_mesh()` into:

```rust
#[cfg(feature = "mesh")]
async fn create_mesh_pipeline(
    input: &WorkerMeshAttachmentInput<'_>,
) -> Result<MeshPipelineRuntime, BoxError>
```

This helper should:

- clone/unwrap the verified mesh transport;
- create the supervision pipeline;
- register `mesh_supervision_coordinator` as critical;
- register `mesh_exit_observer` as critical;
- return `MeshPipelineRuntime`.

Preserve existing log messages:

```text
Mesh supervision coordinator started (critical)
Mesh exit observer started (critical)
```

Do not move required/optional startup behavior into this helper.

## Phase 2 — Extract Ready Sending Helper

The required mesh path sends ready in two branches: support tasks present and no support tasks. Extract this into a helper so behavior remains identical and deduplicated.

Suggested helper:

```rust
#[cfg(feature = "mesh")]
async fn send_ready_if_deferred(
    state: &UnifiedServerWorkerState,
    worker_id: synvoid_ipc::WorkerId,
    readiness: &WorkerReadinessPlan,
) -> Result<(), BoxError> {
    if let WorkerReadinessPlan::DeferUntilRequiredMeshReady = readiness {
        let mut ipc_guard = state.ipc.lock().await;
        ipc_guard
            .send(&crate::process::Message::UnifiedServerWorkerReady { id: worker_id })
            .await?;
        tracing::info!("Unified Server Worker {} ready (mesh started)", worker_id);
    }
    Ok(())
}
```

Acceptance: there should be only one `UnifiedServerWorkerReady` send in `mesh_attachment.rs` after this extraction.

## Phase 3 — Extract Required Mesh Startup

Move the required branch into:

```rust
#[cfg(feature = "mesh")]
async fn start_required_mesh(
    input: RequiredMeshStartInput<'_>,
) -> Result<RequiredMeshStartOutput, BoxError>
```

This helper must preserve:

- status transition to starting before startup;
- `start_mesh_generation(&mesh_transport, 0).await`;
- generation counter behavior;
- support registration only after mesh startup succeeds;
- status transition to running after support registration succeeds;
- ready send only after startup and support registration succeed;
- support registration failure converted to `MeshFailureCause::StartupFailed(format!("support registration failed: {}", cause))`;
- mesh startup failure converted by `mesh_failure_to_worker_cause(cause)`;
- status transition to failed on both failure paths.

The helper should return `RequiredMeshStartOutput`, and `attach_mesh()` should build `MeshStartupState` from it.

## Phase 4 — Extract Optional Support Registration Spawning

Inside optional startup, isolate the support-registration helper task spawning:

```rust
#[cfg(feature = "mesh")]
async fn spawn_optional_support_registration(
    state: &UnifiedServerWorkerState,
    support_tasks: Option<super::MeshSupportTasks>,
) -> tokio::sync::oneshot::Receiver<Result<Option<MeshGenerationSupport>, WorkerShutdownCause>>
```

The current code converts support registration errors to `String`. Keep `String` if it avoids churn, but prefer preserving the structured `WorkerShutdownCause` until logging/conversion.

The helper should spawn exactly one one-shot task named:

```text
mesh_support_registration
```

Do not start this support registration before optional mesh startup semantics require it. Preserve current ordering from Iteration 95.

## Phase 5 — Extract Optional Mesh Startup Task Spawning

Move the optional mesh transport startup one-shot task into:

```rust
#[cfg(feature = "mesh")]
async fn spawn_optional_mesh_startup(
    state: &UnifiedServerWorkerState,
    mesh_transport: Arc<synvoid_mesh::MeshTransport>,
    event_tx: tokio::sync::mpsc::Sender<crate::worker::mesh_supervision::MeshSupervisionEvent>,
    support_rx: tokio::sync::oneshot::Receiver<Result<Option<MeshGenerationSupport>, String>>,
) -> tokio::sync::oneshot::Receiver<Result<Option<MeshGenerationSupport>, String>>
```

Or keep sender creation outside and pass the sender in if that is closer to the current code.

The helper should spawn exactly one one-shot task named:

```text
mesh_startup
```

Preserve event emission:

- on success: send `MeshSupervisionEvent::Started`;
- on failure: send `MeshSupervisionEvent::StartupFailed(e.to_string())`.

## Phase 6 — Extract Optional Startup Race Loop

Move the optional `tokio::select!` loop into:

```rust
#[cfg(feature = "mesh")]
async fn await_optional_mesh_startup(
    input: OptionalMeshAwaitInput<'_>,
) -> OptionalMeshStartOutput
```

This helper owns:

- `pending_optional_failure`;
- waiting for optional startup result;
- handling `MeshSupervisorDecision::MarkDegraded(reason)` during startup;
- handling `ShutdownWorker(cause)` during startup;
- handling `RestartMesh` as configuration invariant during startup;
- stopping support bundle with `SupportStopContext::OptionalMeshDegraded` if degradation arrived before startup completed;
- transitioning status to running, failed, or degraded as currently implemented.

Acceptance: `attach_mesh()` should no longer contain `tokio::select!`, `pending_optional_failure`, or `MeshSupervisorDecision::RestartMesh` directly.

## Phase 7 — Keep Returned State Shape Stable

At the end of `attach_mesh()`, continue returning:

```rust
Ok(Some(MeshStartupState {
    policy: input.state.mesh_policy.clone().expect("mesh policy present"),
    decision_rx,
    startup_failure,
    active_mesh_support,
}))
```

The exact construction may happen in a helper, but the produced fields must remain the same:

- policy;
- decision receiver;
- required/optional startup failure if one occurred;
- active mesh support bundle if startup succeeded and no degradation consumed it.

## Phase 8 — Tighten Source Guards

Update `tests/unified_worker_composition_root_guard.rs`.

Add guard that `attach_mesh()` remains short enough. Since source parsing is crude, keep threshold practical. Suggested:

```rust
#[test]
fn attach_mesh_remains_a_thin_mesh_orchestration_wrapper() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(repo.join("src/worker/unified_server/mesh_attachment.rs")).unwrap();
    let function = extract_function_body(&source, "pub async fn attach_mesh");
    assert!(function.lines().count() <= 80);
}
```

Add a lightweight helper extractor in the test file if one does not exist. Avoid a brittle full Rust parser.

Add guard that `attach_mesh()` delegates required and optional paths:

```rust
assert!(function.contains("start_required_mesh"));
assert!(function.contains("start_optional_mesh"));
assert!(!function.contains("tokio::select!"));
assert!(!function.contains("pending_optional_failure"));
```

Add guard that `mesh_attachment.rs` still owns the critical moved patterns:

```rust
assert!(source.contains("mesh_support_registration"));
assert!(source.contains("mesh_startup"));
assert!(source.contains("SupportStopContext::OptionalMeshDegraded"));
assert!(source.contains("SupportStopContext::WorkerShutdown") == false);
```

The last guard is intentional: worker-shutdown support cleanup belongs in `shutdown_executor.rs`, not mesh attachment. Optional-degraded cleanup belongs in mesh attachment.

## Phase 9 — Review Existing Guard Changes For Over-Broad Weakening

Inspect these tests after modifications:

```text
tests/worker_mesh_supervision_boundary_guard.rs
tests/worker_supervision_control_flow.rs
tests/data_plane_composition_boundary_guard.rs
tests/background_task_ownership_guard.rs
tests/unified_worker_composition_root_guard.rs
```

Rules:

- Adding `mesh_attachment.rs` as a known composition-root owner is fine.
- Skipping all of `mesh_attachment.rs` in guards is not fine unless the skipped pattern is explicitly owned there.
- If a guard checks that startup plan no longer owns mesh details, it should look for those details in `mesh_attachment.rs` instead of merely removing checks.

## Verification Commands

Minimum:

```bash
cargo fmt
cargo check -p synvoid
cargo test --test unified_worker_composition_root_guard
cargo test --test root_facade_boundary_guard
cargo test --test root_module_ledger_guard
```

Worker/mesh focused:

```bash
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns
cargo test --test worker_supervision_control_flow --features mesh,dns
cargo test --test composition_root_behavioral --features mesh,dns
cargo test --test background_task_ownership_guard
cargo test --test mesh_task_ownership_guard --features mesh,dns
```

Crate checks:

```bash
cargo check -p synvoid-mesh --features mesh
cargo check --no-default-features --features mesh,dns
```

If `cargo check --no-default-features` has a known unrelated failure, document it with exact error text and ensure the mesh/dns feature check still passes.

## Acceptance Criteria

This polish pass is complete when:

- `attach_mesh()` is a short orchestration wrapper.
- Pipeline creation is isolated in a helper.
- Required mesh startup is isolated in a helper.
- Optional mesh startup spawning and optional startup/degradation race handling are isolated in helpers.
- The ready-send path for required mesh is deduplicated.
- Required mesh readiness remains deferred until startup and support registration succeed.
- Optional mesh readiness remains non-blocking.
- Support tasks still register only after mesh startup succeeds.
- Optional degradation cleanup still calls `stop_mesh_generation_support(..., SupportStopContext::OptionalMeshDegraded)`.
- Worker shutdown cleanup remains only in `shutdown_executor.rs`.
- Guard tests fail if mesh attachment logic drifts back into `startup_plan.rs` or if `attach_mesh()` grows back into a dense function.

## Expected Files To Touch

Likely:

```text
src/worker/unified_server/mesh_attachment.rs
tests/unified_worker_composition_root_guard.rs
```

Possibly:

```text
tests/worker_mesh_supervision_boundary_guard.rs
tests/worker_supervision_control_flow.rs
tests/data_plane_composition_boundary_guard.rs
src/worker/AGENTS.override.md
architecture/worker_data_plane_composition_root.md
skills/synvoid_mesh.md
```

Avoid touching unless needed:

```text
src/worker/unified_server/startup_plan.rs
src/worker/unified_server/shutdown_executor.rs
src/worker/unified_server/supervision_loop.rs
crates/synvoid-mesh/**
```

## Handoff Summary

Iteration 95 put worker-side mesh attachment in the right module. Iteration 96 should make that module maintainable: split `attach_mesh()` into typed helper phases, deduplicate readiness signaling, and strengthen source guards around the new ownership boundary. Keep behavior identical.
