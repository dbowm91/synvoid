# Worker Mesh Attachment Extraction — Iteration 95

## Purpose

This plan implements the next roadmap item after the unified worker composition-root decomposition: extract worker-side mesh attachment logic out of `startup_plan.rs` into a focused internal module.

Iteration 93 split the unified worker into startup, supervision, shutdown, and supervisor notification modules. Iteration 94 polished that split by moving shutdown-plan mapping out of the wrapper and restoring explicit active mesh support shutdown. The remaining hotspot is now the mesh block inside `src/worker/unified_server/startup_plan.rs`.

The goal of this pass is to create a worker-owned mesh attachment abstraction that owns mesh startup attachment behavior for the worker process:

- validate mesh runtime inputs;
- create supervision pipeline;
- register mesh supervision coordinator and exit observer;
- start required mesh inline before ready;
- start optional mesh asynchronously;
- register DNS/YARA support tasks only after transport startup succeeds;
- handle optional startup degradation races;
- return a typed result to startup/supervision/shutdown.

This pass should not change mesh semantics. It should make existing semantics easier to review.

## Current State

`src/worker/unified_server/startup_plan.rs` now owns all startup phases. It is much better than the previous monolithic `mod.rs`, but it still includes a dense mesh section:

- disabled-mesh support validation;
- mesh supervision policy construction;
- data-plane builder mesh wiring;
- support task extraction;
- readiness deferral calculation;
- mesh supervision pipeline creation;
- coordinator registration;
- mesh exit observer registration;
- required mesh startup flow;
- optional mesh startup one-shot flow;
- optional support registration helper;
- optional degradation race handling;
- returned `MeshStartupState`.

This is too much for a general startup plan. It should be isolated behind a type such as `WorkerMeshAttachment` or `MeshWorkerAttachment`.

## Non-Goals

Do not move mesh transport implementation out of `synvoid-mesh`.

Do not alter DHT/Raft separation.

Do not change mesh supervision policy behavior.

Do not change required-vs-optional mesh readiness semantics.

Do not change support task registration timing.

Do not change YARA broadcast or DNS verification task internals.

Do not change shutdown executor behavior from Iteration 94.

Do not introduce new dependencies.

Do not rename existing public mesh types unless required by the extraction.

## Desired End State

After this pass, `startup_plan.rs` should delegate worker-side mesh attachment to a new module:

```text
src/worker/unified_server/mesh_attachment.rs
```

The startup plan should read roughly like:

```rust
let mesh_init = init_mesh::init_mesh_and_threat_intel(
    &shared_config,
    &args.config_path,
    &unified_server,
)
.await;

let mesh_attachment = mesh_attachment::WorkerMeshAttachment::prepare(
    mesh_attachment::WorkerMeshAttachmentInput {
        worker_id,
        state: &state,
        shared_config: shared_config.clone(),
        mesh_init,
        support_tasks,
        readiness,
    },
)
.await?;

let mesh_startup = mesh_attachment.mesh_startup;
let readiness = mesh_attachment.readiness;
```

Exact types can differ. The critical point is that startup planning no longer owns the detailed mesh startup/select logic inline.

## Proposed New Module

Create:

```text
src/worker/unified_server/mesh_attachment.rs
```

Add to `src/worker/unified_server/mod.rs`:

```rust
pub mod mesh_attachment;
```

### Suggested Public Types

```rust
#[cfg(feature = "mesh")]
pub struct WorkerMeshAttachmentInput<'a> {
    pub worker_id: synvoid_ipc::WorkerId,
    pub state: &'a super::state::UnifiedServerWorkerState,
    pub shared_config: std::sync::Arc<tokio::sync::RwLock<synvoid_config::ConfigManager>>,
    pub mesh_init: super::init_mesh::MeshInit,
    pub support_tasks: Option<super::MeshSupportTasks>,
    pub readiness: super::startup_plan::WorkerReadinessPlan,
}

#[cfg(feature = "mesh")]
pub struct WorkerMeshAttachmentOutput {
    pub mesh_startup: Option<super::startup_plan::MeshStartupState>,
    pub readiness: super::startup_plan::WorkerReadinessPlan,
}

#[cfg(feature = "mesh")]
pub struct WorkerMeshAttachment;
```

Potential method:

```rust
#[cfg(feature = "mesh")]
impl WorkerMeshAttachment {
    pub async fn attach(
        input: WorkerMeshAttachmentInput<'_>,
    ) -> Result<WorkerMeshAttachmentOutput, Box<dyn std::error::Error + Send + Sync>> {
        // moved logic
    }
}
```

If referencing `startup_plan::WorkerReadinessPlan` creates awkward cycles, move `WorkerReadinessPlan` and `MeshStartupState` into `mesh_attachment.rs` or a tiny neutral module such as `startup_types.rs`. Prefer minimal movement unless the compiler forces it.

## Design Boundary

`mesh_attachment.rs` should own worker-side attachment orchestration, not mesh internals.

It may call:

- `init_mesh::validate_mesh_runtime_inputs()`;
- `crate::worker::mesh_supervision::build_mesh_supervision_policy()`;
- `crate::worker::mesh_supervision::create_supervision_pipeline()`;
- `crate::worker::mesh_supervision::start_mesh_generation()`;
- `crate::worker::mesh_supervision::run_mesh_exit_observer()`;
- `register_mesh_generation_support()`;
- `stop_mesh_generation_support()` for optional degradation cleanup.

It should not own:

- data-plane service building;
- HTTP/WAF request-service wiring;
- generic worker lifecycle loops;
- ordered shutdown;
- supervisor IPC notification mapping.

## Extraction Plan

### Phase 1 — Add Module Skeleton

Create `src/worker/unified_server/mesh_attachment.rs` with module docs:

```rust
// Worker-side mesh attachment orchestration.
//
// Owns mesh supervision pipeline creation, required/optional startup behavior,
// and support-task registration after mesh transport startup succeeds.
//
// This module does not implement mesh transport internals and does not perform
// ordered worker shutdown.
```

Add `pub mod mesh_attachment;` in `mod.rs`.

Keep the module empty enough to compile first.

### Phase 2 — Move Mesh Runtime Input Validation

Move this block from `startup_plan.rs` into `mesh_attachment.rs`:

- read `mesh_enabled` from config;
- clone mesh supervision config;
- call `build_mesh_supervision_policy()`;
- call `validate_mesh_runtime_inputs()`;
- return the policy.

Suggested helper:

```rust
#[cfg(feature = "mesh")]
async fn build_and_validate_mesh_policy(
    shared_config: &Arc<RwLock<ConfigManager>>,
    mesh_init: &super::init_mesh::MeshInit,
) -> Result<crate::worker::mesh_supervision::MeshSupervisionPolicy, BoxError>;
```

This can be the first behavior-preserving extraction.

### Phase 3 — Move Disabled-Mesh Support Validation

Move the debug assertions for disabled mesh into a helper:

```rust
#[cfg(all(feature = "mesh", feature = "dns"))]
async fn debug_assert_disabled_mesh_has_no_support(
    shared_config: &Arc<RwLock<ConfigManager>>,
    mesh_init: &super::init_mesh::MeshInit,
);
```

Preserve exact assertions:

- disabled mesh has empty `dns_verification_registries`;
- disabled mesh has no `yara_broadcast`;
- disabled mesh has no `transport_manager`.

### Phase 4 — Move Mesh Supervision Pipeline Creation

Extract the pipeline creation block:

- determine whether mesh transport exists;
- clone mesh transport;
- create supervision pipeline;
- spawn `mesh_supervision_coordinator` as critical;
- subscribe to mesh exits;
- spawn `mesh_exit_observer` as critical;
- return `decision_rx`, `event_tx`, `mesh_transport`, and status handle.

Suggested helper output:

```rust
#[cfg(feature = "mesh")]
struct MeshPipelineRuntime {
    mesh_transport: std::sync::Arc<synvoid_mesh::MeshTransport>,
    event_tx: tokio::sync::mpsc::Sender<crate::worker::mesh_supervision::MeshSupervisionEvent>,
    decision_rx: tokio::sync::mpsc::Receiver<crate::worker::mesh_supervision::MeshSupervisorDecision>,
}
```

If no mesh transport exists, return `Ok(None)` and log `Mesh disabled — no supervision pipeline created` exactly or equivalently.

### Phase 5 — Move Required Mesh Startup Flow

Extract required mesh behavior:

- transition mesh status to starting;
- call `start_mesh_generation(&mesh_transport, 0).await`;
- increment generation counter on success;
- register support tasks after startup success;
- transition running after support registration succeeds;
- send ready if readiness was deferred;
- on support registration failure, transition failed and return `required_mesh_startup_failure`;
- on mesh startup failure, transition failed and return `required_mesh_startup_failure`.

Suggested helper:

```rust
#[cfg(feature = "mesh")]
async fn start_required_mesh(
    input: RequiredMeshStartInput<'_>,
) -> Result<RequiredMeshStartOutput, BoxError>;
```

Important: do not send ready before both mesh startup and support registration succeed.

### Phase 6 — Move Optional Mesh Startup Flow

Extract optional mesh behavior:

- transition mesh status to starting;
- spawn one-shot `mesh_support_registration` helper;
- spawn one-shot `mesh_startup` task;
- race optional startup completion against mesh decisions;
- if degradation arrives before startup completion, stop support bundle with `SupportStopContext::OptionalMeshDegraded`;
- if startup succeeds and no degradation pending, transition running and set `active_mesh_support`;
- if startup fails, transition failed;
- if `ShutdownWorker` decision arrives during startup, convert failure to worker shutdown cause.

Suggested helper:

```rust
#[cfg(feature = "mesh")]
async fn start_optional_mesh(
    input: OptionalMeshStartInput<'_>,
) -> Result<OptionalMeshStartOutput, BoxError>;
```

Important: optional mesh readiness remains non-blocking. Ready must already be sent before optional startup is awaited or processed.

### Phase 7 — Replace Inline StartupPlan Mesh Block With Attachment Call

After helpers compile, collapse the mesh block in `startup_plan.rs` into a concise call.

The startup plan should still:

- initialize mesh/threat-intel via `init_mesh::init_mesh_and_threat_intel()`;
- wire `DataPlaneServicesBuilder` using `mesh_init` fields;
- extract support tasks;
- compute baseline readiness;
- delegate attachment startup/pipeline behavior.

Avoid moving data-plane builder ownership into `mesh_attachment.rs` in this pass. The attachment should consume only the already-extracted support tasks and runtime state.

### Phase 8 — Add Guardrails

Add or update `tests/unified_worker_composition_root_guard.rs` with mesh-attachment checks.

Suggested tests:

```rust
#[test]
fn startup_plan_delegates_mesh_attachment() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(repo.join("src/worker/unified_server/startup_plan.rs")).unwrap();
    assert!(source.contains("mesh_attachment"));
    assert!(source.contains("WorkerMeshAttachment"));
}

#[test]
fn startup_plan_no_longer_owns_mesh_start_select_loop() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(repo.join("src/worker/unified_server/startup_plan.rs")).unwrap();
    assert!(!source.contains("mesh_support_registration"));
    assert!(!source.contains("pending_optional_failure"));
    assert!(!source.contains("MeshSupervisorDecision::RestartMesh"));
}

#[test]
fn mesh_attachment_owns_optional_degradation_cleanup() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(repo.join("src/worker/unified_server/mesh_attachment.rs")).unwrap();
    assert!(source.contains("SupportStopContext::OptionalMeshDegraded"));
    assert!(source.contains("stop_mesh_generation_support"));
}
```

These are source guards, not substitutes for behavior tests.

## Behavior Invariants

### Readiness

- No mesh transport: no mesh supervision pipeline; ready behavior remains baseline.
- Optional mesh: worker ready is sent without waiting for mesh startup completion.
- Required mesh: worker ready is deferred until mesh startup succeeds and support tasks are registered.
- Required mesh support-registration failure prevents ready and causes worker shutdown.

### Support Task Ordering

- DNS verification loops and YARA broadcast support tasks must be registered only after mesh transport startup succeeds.
- Support tasks must not start for disabled mesh.
- Support tasks must be tied to a generation and cancellable independently.
- Active support bundle must be returned to supervision/shutdown after successful startup.

### Optional Mesh Race Handling

- If degradation arrives during optional startup, the startup result must still be consumed.
- If support registration succeeded but degradation was already pending, stop the support bundle with `SupportStopContext::OptionalMeshDegraded`.
- If optional mesh startup fails, mark status failed/degraded according to existing behavior; do not shut down the worker unless policy emits `ShutdownWorker`.

### Supervision Pipeline

- `mesh_supervision_coordinator` remains critical.
- `mesh_exit_observer` remains critical.
- Mesh decision receiver is returned for the supervision loop.
- `RestartMesh` during startup remains a configuration invariant failure.

### Shutdown

- Do not change Iteration 94 shutdown executor behavior.
- Active mesh support returned by the attachment must still reach `WorkerShutdownContext::from_supervision_result()` and explicit worker-shutdown support cleanup.

## Testing And Verification

Minimum:

```bash
cargo fmt
cargo check -p synvoid
cargo test --test unified_worker_composition_root_guard
cargo test --test root_facade_boundary_guard
cargo test --test root_module_ledger_guard
```

Worker/mesh-specific:

```bash
cargo test --test composition_root_behavioral --features mesh,dns
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns
cargo test --test worker_supervision_control_flow --features mesh,dns
cargo test --test background_task_ownership_guard
cargo test --test mesh_task_ownership_guard --features mesh,dns
```

Crate checks:

```bash
cargo check -p synvoid-mesh --features mesh
cargo check --no-default-features --features mesh,dns
```

If `cargo check --no-default-features` has a known unrelated failure, document the exact error and verify `cargo check --no-default-features --features mesh,dns` if possible.

## Acceptance Criteria

This pass is complete when:

- `src/worker/unified_server/mesh_attachment.rs` exists.
- `startup_plan.rs` delegates mesh attachment/startup/select-loop behavior to `mesh_attachment.rs`.
- `startup_plan.rs` no longer contains the optional mesh startup select loop or support-registration one-shot details inline.
- Required mesh readiness remains deferred until startup and support registration succeed.
- Optional mesh readiness remains non-blocking.
- Support tasks still register only after mesh startup succeeds.
- Optional degradation race handling remains explicit and tested/guarded.
- Composition-root guard tests include mesh attachment ownership checks.
- No shutdown executor regression from Iteration 94.

## Expected Files To Touch

Likely:

```text
src/worker/unified_server/mod.rs
src/worker/unified_server/startup_plan.rs
src/worker/unified_server/mesh_attachment.rs
tests/unified_worker_composition_root_guard.rs
src/worker/AGENTS.override.md
architecture/worker_data_plane_composition_root.md
```

Possibly:

```text
tests/worker_mesh_supervision_boundary_guard.rs
tests/worker_supervision_control_flow.rs
tests/background_task_ownership_guard.rs
```

Avoid touching:

```text
crates/synvoid-mesh/**
src/worker/unified_server/shutdown_executor.rs
src/worker/unified_server/supervision_loop.rs
```

unless required by compile errors or test guard updates.

## Handoff Summary

The previous passes made the unified worker composition root reviewable. This pass should make the worker-side mesh attachment reviewable by moving the dense required/optional mesh startup and support registration logic out of `startup_plan.rs`. Keep behavior identical. The next phase after this should be a polish pass only if the extraction leaves type seams or guardrail rough edges.
