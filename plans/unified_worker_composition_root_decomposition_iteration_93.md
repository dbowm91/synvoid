# Unified Worker Composition Root Decomposition — Iteration 93

## Purpose

This plan implements the next major roadmap item after the root-facade cleanup: decompose the unified worker composition root.

The target function is:

```text
src/worker/unified_server/mod.rs::run_unified_server_worker
```

The current function is semantically organized but still too large. It handles identity, runtime setup, config loading, port validation, TLS passthrough policy validation, bandwidth setup, serverless setup, unified server construction, ACME/Granian startup, WAF setup, mesh/threat-intel initialization, data-plane assembly, request-service wiring, readiness signaling, lifecycle task registration, mesh supervision startup, the main supervision loop, ordered shutdown, supervisor notification, and exit-code selection.

The goal of this pass is to preserve the single worker ownership root while moving large blocks of orchestration into typed internal modules. This is not a crate-extraction pass. This is an internal decomposition pass inside `src/worker/unified_server/`.

## Current State

`src/worker/unified_server/mod.rs` already has useful submodules:

```rust
pub mod init_apps;
pub mod init_config;
pub mod init_mesh;
pub mod init_runtime;
pub mod init_waf;
pub mod lifecycle;
pub mod passthrough_validation;
pub mod services;
pub mod state;
```

It also still owns several substantial concerns directly:

- `MeshGenerationSupport`, `SupportStopContext`, and `MeshSupportStopReport` types;
- YARA broadcast child ownership and teardown helpers;
- `MeshSupportTasks` extraction and registration;
- `stop_mesh_generation_support`;
- all phases inside `run_unified_server_worker()`.

The next step should be to extract orchestration units, not domain logic.

## Non-Goals

Do not change runtime behavior.

Do not change worker readiness semantics.

Do not change mesh required/optional startup behavior.

Do not change support-task registration ordering.

Do not change shutdown ordering.

Do not change exit-code mapping.

Do not change supervisor IPC messages.

Do not move implementation into a new crate.

Do not start the later `WorkerMeshAttachment` extraction in full. It is acceptable to shape types so that future extraction is easier, but this pass should not redesign mesh lifecycle behavior.

Do not introduce new dependencies.

## Desired End State

After this pass, `run_unified_server_worker()` should become a short orchestration skeleton. A rough final shape:

```rust
pub async fn run_unified_server_worker(
    args: UnifiedServerWorkerArgs,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let startup = startup_plan::build_worker_startup(args).await?;
    let supervision = supervision_loop::run_worker_supervision(&startup).await;
    let shutdown = shutdown_executor::execute_worker_shutdown(startup, supervision).await?;

    if shutdown.exit_code != 0 {
        std::process::exit(shutdown.exit_code);
    }

    Ok(())
}
```

Exact names may differ, but the top-level function should delegate to three or four named phases:

1. Startup planning/building.
2. Lifecycle/supervision loop.
3. Ordered shutdown execution.
4. Supervisor notification / exit-code mapping, either inside shutdown or in a small helper.

## Proposed New Modules

Add these files under:

```text
src/worker/unified_server/
```

### `startup_plan.rs`

Owns phases from worker identity through data-plane/service readiness preparation.

Responsibilities:

- worker ID setup;
- CPU affinity;
- log level setup;
- shared heartbeat and health monitor startup;
- IPC setup;
- config setup;
- pre-bind port validation;
- TLS passthrough validation;
- bandwidth tracker configuration;
- drain state and worker metrics construction;
- serverless manager construction;
- `UnifiedServer` construction;
- ACME setup;
- Granian supervisor spawn/wait;
- WAF background setup;
- upload validator setup;
- port honeypot setup;
- mesh/threat-intel initialization;
- disabled-mesh support validation;
- mesh supervision policy construction;
- request initial blocklist;
- `DataPlaneServicesBuilder` construction and cross-wiring;
- `UnifiedServerWorkerState` construction;
- readiness policy calculation;
- lifecycle task preparation, but not necessarily spawning the long-running supervision loop.

Likely public API:

```rust
pub struct WorkerStartupArtifacts {
    pub worker_id: WorkerId,
    pub args: UnifiedServerWorkerArgs,
    pub shared_config: Arc<RwLock<crate::config::MainConfig>>,
    pub ipc: crate::worker::state::WorkerIpc,
    pub unified_server: Arc<UnifiedServer>,
    pub state: UnifiedServerWorkerState,
    pub readiness: WorkerReadinessPlan,
    #[cfg(feature = "mesh")]
    pub mesh_runtime: MeshRuntimeStartupState,
    pub legacy_handles: Vec<tokio::task::JoinHandle<()>>,
}

pub async fn build_worker_startup(
    args: UnifiedServerWorkerArgs,
) -> Result<WorkerStartupArtifacts, Box<dyn std::error::Error + Send + Sync>>;
```

Do not overfit the struct on the first edit. Start by moving a contiguous block out of `run_unified_server_worker()` and compile. Then refine field names.

### `readiness.rs` or local readiness type in `startup_plan.rs`

Optional, only if it reduces complexity. This should encode worker ready signaling rules:

- disabled mesh: ready immediately after baseline startup;
- optional mesh: ready before optional mesh startup completes;
- required mesh: ready only after mesh transport startup and support-task registration succeed.

Possible type:

```rust
pub enum WorkerReadinessPlan {
    SendImmediately,
    DeferUntilRequiredMeshReady,
    AlreadySent,
}
```

Do not change behavior. This type is documentation plus control-flow clarity.

### `supervision_loop.rs`

Owns the main select loop after startup has registered the required lifecycle and mesh supervision tasks.

Responsibilities:

- wait for lifecycle IPC events;
- wait for task registry exits;
- wait for mesh supervisor decisions;
- classify fatal vs non-fatal exits;
- update mesh status/degraded state;
- produce a typed final supervision result.

Likely public API:

```rust
pub struct WorkerSupervisionResult {
    pub cause: crate::worker::task_registry::WorkerShutdownCause,
    #[cfg(feature = "mesh")]
    pub active_mesh_support: Option<MeshGenerationSupport>,
    #[cfg(feature = "mesh")]
    pub mesh_shutdown_state: MeshShutdownStateForExecutor,
}

pub async fn run_worker_supervision(
    startup: &mut WorkerStartupArtifacts,
) -> WorkerSupervisionResult;
```

Whether the function takes `&mut WorkerStartupArtifacts` or consumes a smaller `SupervisionContext` is an implementation choice. Prefer a smaller context if easy, but do not let type design block progress.

Important: `supervision_loop.rs` must not perform ordered teardown. It should choose the cause and return.

### `shutdown_executor.rs`

Owns ordered shutdown after the supervision loop exits.

Responsibilities:

- begin coordinated shutdown;
- set shutdown deadline;
- stop accepting requests;
- drain active work where applicable;
- stop app servers;
- shut down mesh transport and classify clean/forced/incomplete;
- stop active mesh generation support if present;
- clear running flag;
- broadcast registry shutdown;
- join registered tasks;
- abort leftover legacy handles;
- map final cause to supervisor notification;
- derive exit code;
- return a structured shutdown report.

Likely public API:

```rust
pub struct WorkerShutdownReport {
    pub final_cause: crate::worker::task_registry::WorkerShutdownCause,
    pub exit_code: i32,
}

pub async fn execute_worker_shutdown(
    startup: WorkerStartupArtifacts,
    supervision: WorkerSupervisionResult,
) -> Result<WorkerShutdownReport, Box<dyn std::error::Error + Send + Sync>>;
```

### `supervisor_notify.rs`

Small helper module. It may be extracted separately or live inside `shutdown_executor.rs` at first.

Responsibilities:

- map `WorkerShutdownCause` to supervisor IPC messages;
- keep notification behavior exactly identical.

Likely public API:

```rust
pub async fn notify_supervisor_of_shutdown(
    ipc: &crate::worker::state::WorkerIpc,
    worker_id: WorkerId,
    cause: &WorkerShutdownCause,
);

pub fn exit_code_for_shutdown_cause(cause: &WorkerShutdownCause) -> i32;
```

If the existing logic has richer inputs than this, preserve them. The point is to remove the long match block from the top-level worker function.

## Recommended Extraction Order

Use a sequence of small commits or at least small local steps. Each step should compile before moving to the next.

### Step 1 — Add Module Stubs and Re-exports

Create:

```text
src/worker/unified_server/startup_plan.rs
src/worker/unified_server/supervision_loop.rs
src/worker/unified_server/shutdown_executor.rs
src/worker/unified_server/supervisor_notify.rs
```

Update `src/worker/unified_server/mod.rs`:

```rust
pub mod startup_plan;
pub mod supervision_loop;
pub mod shutdown_executor;
pub mod supervisor_notify;
```

At first, the modules may contain only type aliases or placeholder helper functions. Keep the existing behavior in `mod.rs` until the first extraction is ready.

### Step 2 — Extract Supervisor Notification Mapping First

This is the lowest-risk extraction.

Find the shutdown-cause-to-supervisor-message logic currently near the end of `run_unified_server_worker()` and move it to `supervisor_notify.rs`.

The top-level worker function should call:

```rust
supervisor_notify::notify_supervisor_of_shutdown(&ipc, worker_id, &shutdown_cause).await;
```

Also move exit-code mapping if it is currently a separate match:

```rust
let exit_code = supervisor_notify::exit_code_for_shutdown_cause(&shutdown_cause);
```

Verification after this step:

```bash
cargo fmt
cargo check -p synvoid
cargo test --test worker_supervision_control_flow --features mesh,dns
```

If the test is too expensive, at minimum run:

```bash
cargo check -p synvoid
```

### Step 3 — Extract Shutdown Executor

Move the ordered shutdown block into `shutdown_executor.rs`.

This should consume all state needed for teardown. Avoid global lookups if the original code had local handles.

Create an initial `WorkerShutdownContext` if consuming `WorkerStartupArtifacts` is not yet possible:

```rust
pub struct WorkerShutdownContext {
    pub worker_id: WorkerId,
    pub ipc: WorkerIpc,
    pub unified_server: Arc<UnifiedServer>,
    pub drain_state: Arc<WorkerDrainState>,
    pub running: RunningFlag,
    pub task_registry: Arc<TokioMutex<WorkerTaskRegistry>>,
    pub legacy_handles: Vec<tokio::task::JoinHandle<()>>,
    #[cfg(feature = "mesh")]
    pub mesh_transport_manager: Option<Arc<crate::mesh::transport::MeshTransportManager>>,
    #[cfg(feature = "mesh")]
    pub active_mesh_support: Option<MeshGenerationSupport>,
}
```

Use the actual existing types from `UnifiedServerWorkerState`. Do not invent extra state where existing state already owns the handle.

Acceptance for this step:

- shutdown order is textually the same as before;
- logs and metrics remain equivalent;
- incomplete mesh shutdown still merges into final cause;
- leftover legacy handles are still aborted;
- the function returns the same exit code as before.

### Step 4 — Extract Supervision Loop

Move the main `tokio::select!` loop into `supervision_loop.rs`.

Create a context struct to avoid a 20-argument function:

```rust
pub struct WorkerSupervisionContext<'a> {
    pub state: &'a UnifiedServerWorkerState,
    pub worker_id: WorkerId,
    pub lifecycle_rx: ..., // use actual type
    #[cfg(feature = "mesh")]
    pub mesh_decision_rx: Option<...>,
    #[cfg(feature = "mesh")]
    pub active_mesh_support: &'a mut Option<MeshGenerationSupport>,
}
```

If lifetimes become annoying, use owned handles or `Arc` clones. Prefer clarity over minimal cloning.

Behavioral invariants:

- lifecycle IPC stop/restart/shutdown behavior remains identical;
- task registry fatal exits still produce the same `WorkerShutdownCause`;
- one-shot optional mesh startup result handling remains identical;
- required mesh failure still shuts down the worker;
- optional mesh degradation does not shut down the worker unless policy says so;
- pending degradation during optional startup still stops support after startup completes;
- support not-found logging remains contextual.

### Step 5 — Extract Startup Plan

This is the highest-churn extraction. Do it after shutdown and supervision are already isolated.

Move phases 0 through the point where the worker state is ready into `startup_plan.rs`.

Build a `WorkerStartupArtifacts` struct that contains everything needed by supervision and shutdown. Start broad. You can narrow fields later.

Recommended internal split inside `startup_plan.rs`:

```rust
pub async fn build_worker_startup(args: UnifiedServerWorkerArgs) -> Result<WorkerStartupArtifacts, BoxError> {
    let identity = setup_identity(&args)?;
    let runtime = setup_runtime(&args, identity).await?;
    let server = setup_server_stack(&args, &runtime).await?;
    let mesh = setup_mesh_stack(&args, &runtime, &server).await?;
    let data_plane = build_data_plane(&runtime, &server, &mesh).await?;
    let lifecycle = register_lifecycle_tasks(&runtime, &server, &mesh).await?;
    Ok(WorkerStartupArtifacts { ... })
}
```

Do not force this exact structure if it fights the code. The key is to remove contiguous startup phases from `mod.rs` while preserving visible behavior.

### Step 6 — Shorten `run_unified_server_worker()`

After the extractions, reduce the top-level function to the skeleton.

The file `mod.rs` may still own mesh support helper types in this iteration. That is acceptable. The next roadmap item can extract worker-side mesh attachment and support helpers.

Expected final responsibilities for `mod.rs` after this pass:

- module declarations;
- public re-exports;
- mesh support helper types/functions if not yet moved;
- short `run_unified_server_worker()` wrapper.

## Behavior Invariants To Preserve

### Readiness

- Disabled mesh sends ready after baseline startup.
- Optional mesh sends ready without waiting for mesh startup completion.
- Required mesh sends ready only after mesh transport startup succeeds and support tasks are registered.
- Startup failures before ready remain startup failures.

### Mesh Support Tasks

- DNS verification and YARA broadcast support tasks are registered only after mesh startup succeeds.
- DHT routing initialization remains owned by mesh transport transactional startup.
- Optional mesh degradation cancels active generation support without shutting down the worker unless policy requires shutdown.
- Support stop reports include cooperative, aborted, failed, and not-found counts.
- Not-found warnings keep their support-stop context.

### Supervision

- Critical task exits remain fatal.
- Restartable/one-shot behavior remains unchanged.
- Mesh supervisor decisions remain policy-driven.
- Supervisor disconnect behavior remains unchanged.
- Running flag clearing behavior remains unchanged.

### Shutdown

- Stop accepting before drain.
- Drain before app-server stop where applicable.
- Mesh transport shutdown remains ordered and truthfully classified.
- Incomplete mesh shutdown still affects the final shutdown cause.
- Registry shutdown and join semantics remain unchanged.
- Legacy handles are still aborted after registry-managed shutdown.
- Exit code mapping remains identical.
- Supervisor IPC notification remains identical.

## Suggested Type Aliases

To reduce noisy signatures, add local aliases where appropriate:

```rust
type BoxError = Box<dyn std::error::Error + Send + Sync>;
type SharedConfig = Arc<RwLock<crate::config::MainConfig>>;
type SharedUnifiedServer = Arc<UnifiedServer>;
type SharedTaskRegistry = Arc<TokioMutex<crate::worker::task_registry::WorkerTaskRegistry>>;
```

Keep aliases module-local unless they are clearly useful across modules.

## Suggested Tests / Guardrails

### Existing Tests To Preserve

Run relevant existing tests after each major extraction:

```bash
cargo test --test composition_root_behavioral --features mesh,dns
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns
cargo test --test worker_supervision_control_flow --features mesh,dns
cargo test --test background_task_ownership_guard
cargo test --test mesh_task_ownership_guard --features mesh,dns
```

If the full set is too slow, run at least the tests most directly affected by the extracted block.

### New Source Guard

Add a lightweight guard to prevent `run_unified_server_worker()` from growing back into a giant function. Suggested file:

```text
tests/unified_worker_composition_root_guard.rs
```

Guard shape:

```rust
#[test]
fn run_unified_server_worker_remains_a_thin_orchestration_wrapper() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(repo.join("src/worker/unified_server/mod.rs")).unwrap();
    let start = source.find("pub async fn run_unified_server_worker").expect("function exists");
    let body = &source[start..];
    let lines_until_next_item = body
        .lines()
        .take_while(|line| !line.starts_with("pub ") || line.contains("run_unified_server_worker"))
        .count();

    assert!(
        lines_until_next_item <= 80,
        "run_unified_server_worker should stay a thin orchestration wrapper; found {lines_until_next_item} lines"
    );
}
```

This exact parser is crude. Improve it if needed, or skip the guard until the function is fully shortened. Do not let a brittle guard block the core refactor.

### Optional Module Boundary Guard

Add a guard that `shutdown_executor.rs` does not call startup builders and `startup_plan.rs` does not perform shutdown. This can be a simple source scan:

- `startup_plan.rs` must not contain `shutdown_and_join` or `begin_coordinated_shutdown`.
- `supervision_loop.rs` must not contain `shutdown_and_join`.
- `shutdown_executor.rs` may contain shutdown calls.

This is optional.

## Verification Commands

Minimum after final implementation:

```bash
cargo fmt
cargo check -p synvoid
cargo test --test root_facade_boundary_guard
cargo test --test root_module_ledger_guard
```

Recommended worker/mesh validation:

```bash
cargo test --test composition_root_behavioral --features mesh,dns
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns
cargo test --test worker_supervision_control_flow --features mesh,dns
cargo test --test background_task_ownership_guard
cargo test --test mesh_task_ownership_guard --features mesh,dns
```

Recommended crate checks:

```bash
cargo check -p synvoid-http3
cargo check -p synvoid-http
cargo check -p synvoid-waf
cargo check -p synvoid-mesh --features mesh
cargo check --no-default-features --features mesh,dns
```

Known caveat from Iteration 91: `cargo check --no-default-features` may fail on a pre-existing unresolved `stop_mesh_generation_support` import if that has not been fixed separately. Do not treat that as introduced by this pass unless the error changes.

## Review Checklist

The implementation should be rejected if any of the following are true:

- `run_unified_server_worker()` still contains the full startup/supervision/shutdown body.
- Startup order changes without an explicit reason.
- Mesh support tasks can start before mesh transport startup succeeds.
- Optional mesh readiness becomes blocking.
- Required mesh readiness becomes non-blocking.
- Shutdown executor performs readiness or startup work.
- Supervision loop performs ordered teardown.
- Supervisor notification behavior changes.
- Exit code mapping changes.
- New global state is introduced.
- New dependencies are introduced.
- Existing root facade guard or ledger guard is broken.

## Recommended Commit Structure

A smaller model should use this commit sequence if possible:

1. `worker: add composition root module stubs`
2. `worker: extract supervisor shutdown notification mapping`
3. `worker: extract ordered shutdown executor`
4. `worker: extract supervision loop`
5. `worker: extract startup plan artifacts`
6. `worker: reduce unified worker entrypoint to orchestration wrapper`
7. `tests: add unified worker composition root guard`

If doing this in one commit, keep the PR/commit message organized by the same sequence.

## Expected Files To Touch

Likely:

```text
src/worker/unified_server/mod.rs
src/worker/unified_server/startup_plan.rs
src/worker/unified_server/supervision_loop.rs
src/worker/unified_server/shutdown_executor.rs
src/worker/unified_server/supervisor_notify.rs
```

Possibly:

```text
src/worker/unified_server/state.rs
src/worker/unified_server/services.rs
src/worker/unified_server/lifecycle.rs
tests/unified_worker_composition_root_guard.rs
AGENTS.md
```

Avoid touching unrelated domain crates.

## Handoff Summary

This pass should transform the unified worker from a large inline composition function into a short orchestration wrapper backed by typed startup, supervision, shutdown, and supervisor-notification modules. The behavior must remain identical. The payoff is reviewability: once this lands, the next phase can safely extract worker-side mesh attachment without simultaneously reasoning about generic worker startup and shutdown logic.
