# SynVoid Architecture Modularization Roadmap

## Purpose

This roadmap gives a bird's-eye view of the next major actionable improvements for SynVoid's architecture. It is intentionally broader than a single handoff plan. Each section describes a durable direction of travel, the architectural reason for the work, the concrete passes that should be derived from it, and the exit criteria that indicate the area is ready to stop receiving active refactor pressure.

The repository has already moved well beyond the original monolithic shape. The workspace now contains dedicated crates for config, WAF, HTTP, HTTP/3, mesh, TLS, proxy, serverless, static files, block store, IPC, metrics, app server, tunnel, upload, platform, and related domains. Recent work also substantially hardened mesh lifecycle ownership, worker task registration, data-plane service bundling, HTTP/3 WAF decoupling, threat-intel policy composition, and abort/join cleanup.

The remaining architectural problem is not that modularization has failed. The remaining problem is that several transitional roots still act as gravitational centers: the root crate re-exports a wide legacy surface, the unified worker composition root is still very large, and some newly modularized services remain physically located under `src/` while depending on root-owned types. The next phase should therefore prioritize boundary finalization and orchestration extraction rather than broad rewrites.

## Current Architectural Posture

SynVoid is currently in a partially modularized but still root-centered state.

The good parts:

- domain crates exist and are actively used;
- dependency ownership has been migrating out of the root package;
- HTTP/3 no longer needs concrete root-owned `WafCore` coupling for request WAF behavior;
- worker task lifecycle is now structured around `WorkerTaskRegistry`, typed exits, explicit shutdown causes, and bounded teardown;
- mesh startup/shutdown has explicit lifecycle semantics, rollback paths, startup support ownership, and cleanup diagnostics;
- `DataPlaneServicesBuilder` now centralizes cross-wiring of serverless, mesh, threat-intel, YARA, record-store, and request-service handles.

The weak parts:

- `src/lib.rs` remains a broad compatibility facade over many old root modules;
- `run_unified_server_worker()` remains a very large composition function that mixes startup sequencing, validation, service assembly, mesh supervision, lifecycle selection, teardown, and supervisor notification;
- `DataPlaneServices` is still rooted in `src/worker/unified_server/services.rs` and imports root-owned types such as `UnifiedServer`, `PortHoneypotRunner`, and `RequestServices`;
- mesh worker attachment logic is correct-looking but cognitively dense;
- binary command handling still contains inline feature-gated mesh and administrative behavior;
- some legacy modules still exist in `src/` after equivalent domain crates have been introduced.

## Roadmap Sequence

The order below is deliberate. Do not begin by moving every file into crates. First reduce the root composition surfaces into smaller typed orchestration units, then move the units that have stable dependency boundaries.

---

## 1. Root Crate Facade Reduction

### Objective

Shrink the root crate from a broad legacy API surface into either a small application crate or a deliberately deprecated facade. The root should stop being the easiest place for new domain code to import from.

### Rationale

`src/lib.rs` currently exposes a large number of modules and re-exports. This keeps old paths working, but it also weakens the crate-boundary model because new code can accidentally depend on `synvoid::mesh`, `synvoid::http`, `synvoid::waf`, or other root paths instead of depending on the relevant domain crate directly.

### Actionable Passes

1. Classify every `pub mod` in `src/lib.rs` into one of four buckets:
   - pure facade over an existing domain crate;
   - root application/runtime module that genuinely belongs in the app crate;
   - legacy module with a known target crate;
   - legacy module that needs an adapter trait before movement.

2. Add explicit comments for transitional modules explaining the target owner crate and why they remain in root.

3. Convert simple root modules into re-export-only facades where the domain crate already owns the implementation.

4. For new code, forbid imports from `synvoid::<domain>` when an equivalent `synvoid-<domain>` crate exists.

5. Add a lightweight source guard or CI check that detects new root-domain imports in crates that should depend on domain crates directly.

### Exit Criteria

This track is done when `src/lib.rs` mostly contains:

- app/runtime modules that truly require root composition;
- compatibility re-exports with clear deprecation comments;
- no domain implementation modules that already have a dedicated crate owner.

---

## 2. Unified Worker Composition Root Decomposition

### Objective

Split `run_unified_server_worker()` into explicit typed orchestration units without changing runtime semantics.

### Rationale

The current worker composition root is architecturally coherent but too large. It is doing many correct things in one place: config setup, port validation, TLS passthrough validation, bandwidth setup, serverless/app/WAF/mesh initialization, data-plane assembly, lifecycle task registration, mesh supervision, shutdown cause selection, ordered teardown, and supervisor notification.

A composition root is allowed to orchestrate. It should not become a hidden framework. The next pass should preserve the single ownership root while extracting each phase into a testable unit with clear inputs and outputs.

### Actionable Passes

Create these internal modules or structs under `src/worker/unified_server/` first. Move to crates only after boundaries stabilize.

1. `startup_plan.rs`
   - owns phased startup sequencing;
   - returns a `WorkerStartupArtifacts` struct;
   - contains `shared_config`, `ipc`, `unified_server`, `serverless_manager`, `port_honeypot_runner`, `mesh_init`, `data_plane`, and readiness policy.

2. `supervision_loop.rs`
   - owns the `tokio::select!` loop over lifecycle events, registry exits, and mesh supervisor decisions;
   - returns `SupervisionOutcome` and any mutable mesh support state that must survive into shutdown;
   - must not perform teardown.

3. `shutdown_executor.rs`
   - owns ordered shutdown;
   - takes `WorkerShutdownPlan` or equivalent input;
   - handles stop-accepting, drain, app-server stop, mesh shutdown, registry cancellation, legacy handle cleanup, supervisor notification, and exit-code derivation.

4. `supervisor_notify.rs`
   - maps `WorkerShutdownCause` to supervisor IPC messages;
   - removes the long match block from `run_unified_server_worker()`.

5. Keep `run_unified_server_worker()` as a short top-level skeleton:

```rust
pub async fn run_unified_server_worker(args: UnifiedServerWorkerArgs) -> Result<(), BoxError> {
    let startup = startup_plan::build(args).await?;
    let supervision = supervision_loop::run(&startup).await;
    let shutdown = shutdown_executor::execute(startup, supervision).await?;
    if shutdown.exit_code != 0 {
        std::process::exit(shutdown.exit_code);
    }
    Ok(())
}
```

The exact names can differ, but this is the desired shape.

### Exit Criteria

This track is done when `run_unified_server_worker()` is short enough to review in one screen and all startup/supervision/shutdown behavior is covered by module-level tests or existing integration tests.

---

## 3. Worker Mesh Attachment Extraction

### Objective

Move worker-side mesh startup, support-task registration, optional/required readiness behavior, degradation handling, and mesh shutdown integration behind a small worker-facing attachment object.

### Rationale

Mesh transport lifecycle has been hardened heavily, but worker-side attachment remains dense. Required mesh, optional mesh, support generation bundles, pending degradation during startup, mesh supervisor decisions, and shutdown classification are all interwoven with generic worker lifecycle code.

This logic should remain owned by the worker composition root, but it should be encapsulated as a worker mesh adapter rather than inline control flow.

### Actionable Passes

1. Introduce a `WorkerMeshAttachment` or `MeshWorkerAttachment` type.

2. Give it explicit construction inputs:
   - mesh transport manager;
   - mesh supervision policy;
   - mesh status handle;
   - support task descriptors;
   - task registry handle;
   - worker IPC readiness sender or readiness callback.

3. Provide a narrow API:

```rust
impl WorkerMeshAttachment {
    pub async fn start_before_ready_if_required(&mut self) -> Result<ReadyGate, MeshFailureCause>;
    pub async fn start_optional_after_ready(&mut self) -> Option<MeshDecisionReceiver>;
    pub async fn handle_decision(&mut self, decision: MeshSupervisorDecision) -> MeshDecisionAction;
    pub async fn shutdown(&mut self, remaining: Duration) -> MeshShutdownDisposition;
}
```

4. Preserve the current semantics:
   - required mesh defers worker ready until transport startup and support registration both succeed;
   - optional mesh sends worker ready immediately;
   - support tasks are registered only after successful mesh startup;
   - optional mesh degradation stops active support generation;
   - pending degradation during optional startup stops the bundle immediately after startup completes;
   - incomplete mesh shutdown is merged into the final worker shutdown cause.

5. Add regression tests around required readiness, optional degradation during startup, support registration failure, missing support task IDs, and shutdown disposition merging.

### Exit Criteria

This track is done when generic worker supervision code no longer contains low-level mesh startup branches. It should call the mesh attachment object and consume typed actions/results.

---

## 4. Data-Plane Service Boundary Finalization

### Objective

Move `DataPlaneServices`, `RequestServices`, and adjacent request-time service handles toward a stable crate boundary that does not depend on root-owned server types.

### Rationale

`DataPlaneServicesBuilder` is a good intermediate step, but it still lives under `src/worker/unified_server/` and references root-owned objects. The long-term target is that request-time services are built by the worker composition root but consumed by HTTP/WAF/proxy paths through explicit handles from a domain crate.

### Actionable Passes

1. Identify the minimal request-time service set:
   - threat intelligence manager;
   - YARA rules manager;
   - record-store advisory source;
   - serverless manager or serverless request adapter;
   - upload validator if request path requires it;
   - port honeypot reporting sink if request path requires it.

2. Move `RequestServices` into a domain crate if it is not already there. Candidate owner: `synvoid-core` for neutral request context, or a new `synvoid-data-plane` crate if the type is too application-specific.

3. Convert direct root references into traits:

```rust
pub trait PortHoneypotSink: Send + Sync {
    fn record_attempt(&self, ip: IpAddr, port: u16, context: HoneypotContext);
}

pub trait ServerlessDispatch: Send + Sync {
    async fn dispatch(&self, request: ServerlessRequest) -> ServerlessResponse;
}
```

4. Keep root-only cross-wiring in the worker startup module. Move data-plane structs and request-consumed handles out of root.

5. Add compile-time boundary tests or source guards proving `synvoid-http`, `synvoid-http3`, and `synvoid-waf` do not import root `crate::server` or root worker modules.

### Exit Criteria

This track is done when HTTP/WAF/proxy code can receive a `RequestServices` or `DataPlaneServices` handle from a domain crate without importing the root application crate.

---

## 5. HTTP/1 and HTTP/3 Request Pipeline Normalization

### Objective

Make HTTP/1 and HTTP/3 request processing share the same conceptual pipeline where practical, while preserving protocol-specific transport mechanics.

### Rationale

HTTP/3 has made progress by depending on WAF traits instead of concrete root types. Its dispatch path is explicit but still parameter-heavy. HTTP/1 and HTTP/3 should not grow separate copies of routing, WAF, stall, bandwidth, body transform, and upstream semantics unless protocol mechanics force that separation.

### Actionable Passes

1. Introduce request pipeline context structs:

```rust
pub struct RequestPipelineContext<'a> {
    pub start: Instant,
    pub host: &'a str,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub method: &'a Method,
    pub headers: &'a HeaderMap,
    pub client_ip: IpAddr,
    pub route_result: &'a RouteResult,
    pub services: &'a RequestServices,
}
```

2. Split protocol-neutral decisions from protocol-specific IO:
   - route terminal outcome;
   - WAF site/bot-config selection;
   - whether body can stream upstream;
   - stall policy;
   - bandwidth accounting;
   - transform-required checks.

3. Keep stream read/write operations protocol-specific.

4. Add parity tests for:
   - WAF decisions;
   - tarpit/stall handling;
   - body-size limits;
   - streaming upstream eligibility;
   - route terminal behavior;
   - bandwidth counters.

### Exit Criteria

This track is done when HTTP/1 and HTTP/3 share protocol-neutral decision helpers and any divergence is documented as transport-specific rather than accidental copy drift.

---

## 6. CLI and Supervisor Command Dispatch Cleanup

### Objective

Move inline command handling out of `src/main.rs` into typed command handlers, while preserving the binary as a thin entrypoint.

### Rationale

`main.rs` currently handles config testing, OpenAPI export, API spec export, genesis key generation, node info, token hashing, regex checks, status/stop/rehash, threat-feed export, restart, and worker/supervisor mode selection. This is manageable but not clean. As more features become modular, the binary should not be the place where domain behavior accumulates.

### Actionable Passes

1. Add a CLI command dispatch module in `synvoid-cli` or root `src/startup/commands.rs`.

2. Convert flags into an enum-like command plan:

```rust
pub enum StartupCommand {
    ConfigTest,
    ExportOpenApi,
    ExportApiSpec,
    Genesis,
    ShowNodeInfo,
    GenerateToken,
    HashToken,
    CheckRegex,
    Status,
    Stop,
    Rehash,
    ExportThreatFeed,
    RestartThenRun,
    RunWorker(WorkerMode),
    RunSupervisor,
}
```

3. Keep process-exit behavior explicit but local to command dispatch.

4. Move mesh-specific command behavior behind feature-gated command handlers.

5. Add tests for command selection from `Args` without launching server runtime.

### Exit Criteria

This track is done when `main.rs` parses args, asks a dispatcher for a command, and executes it. Domain logic should not be inline in the binary.

---

## 7. Legacy `src/` Module Retirement Plan

### Objective

Systematically retire or relocate legacy root modules whose corresponding domain crates already exist.

### Rationale

The repo has many domain crates and many root modules with overlapping names. Some root modules are legitimate adapters; others are legacy leftovers. Without an explicit retirement ledger, future contributors will not know which path is canonical.

### Actionable Passes

1. Create `architecture/root_module_ledger.md` with columns:
   - root module;
   - current responsibility;
   - target owner crate;
   - status: keep, facade, move, split, delete;
   - blocker;
   - final import path.

2. Start with high-impact modules:
   - `src/http`;
   - `src/http3`;
   - `src/waf`;
   - `src/proxy`;
   - `src/tls`;
   - `src/config`;
   - `src/mesh`;
   - `src/block_store`;
   - `src/serverless`;
   - `src/static_files`.

3. For each root module, decide whether it should become:
   - pure re-export facade;
   - app-layer adapter;
   - moved implementation;
   - deleted stale code.

4. Add `AGENTS.override.md` notes in transitional directories to prevent new implementation from landing in deprecated root locations.

### Exit Criteria

This track is done when every major root module has an owner decision and new implementation has a single canonical location.

---

## 8. Boundary Regression Guardrails

### Objective

Add mechanical checks that prevent architectural drift after cleanup passes land.

### Rationale

SynVoid has already had several boundary cleanup passes. Without source guards, the repo can regress through convenience imports, new globals, or root dependency shortcuts.

### Actionable Passes

1. Add source guards for forbidden imports:
   - domain crates importing the root crate;
   - HTTP/HTTP3 importing root WAF/server concrete types;
   - WAF importing transport/server types;
   - mesh importing worker/supervisor runtime types;
   - data-plane crates importing binary or supervisor code.

2. Add focused compile-time boundary tests where Rust type checking is more reliable than grep.

3. Add lightweight `cargo check` matrix entries:
   - default features;
   - `--no-default-features` where feasible;
   - mesh-only relevant subset;
   - dns/mesh combined subset;
   - HTTP/3 crate directly.

4. Document the allowed dependency direction in `architecture/dependency_boundaries.md`.

### Exit Criteria

This track is done when a new accidental root coupling fails either CI or a local guard test before review.

---

## 9. Global State and Runtime Handle Audit

### Objective

Reduce remaining hidden global state by moving runtime handles into explicit composition-root-owned service bundles.

### Rationale

Several recent improvements moved toward explicit handles: record-store advisory source, data-plane services, task registry, mesh support bundles, canonical snapshots. Continue this pattern. Hidden globals make modularization harder because they create implicit dependencies that do not show up in function signatures.

### Actionable Passes

1. Audit calls matching patterns such as:
   - `get_global_*`;
   - `init_global_*`;
   - `set_*_global`;
   - lazy static managers;
   - module-local singletons.

2. Classify each as:
   - acceptable process-wide singleton;
   - compatibility fallback;
   - should become a field on `DataPlaneServices`;
   - should become a field on worker/supervisor state;
   - should become an injected trait object.

3. Prefer explicit handles for request-time services and mesh policy sources.

4. Leave metrics/tracing process-wide where appropriate; do not over-abstract them without benefit.

### Exit Criteria

This track is done when request handling, threat-intel policy, mesh record-store access, and serverless dispatch use explicit handles rather than global fallback paths, except where compatibility comments identify the remaining global as intentional.

---

## 10. Verification and Test Matrix Consolidation

### Objective

Create a repeatable verification matrix that matches the modular architecture.

### Rationale

The repo has accumulated substantial lifecycle and boundary behavior. Future passes should not rely on ad hoc `cargo check` invocations. The test matrix should map to the boundaries that matter: root app, worker lifecycle, mesh transport, HTTP/3, WAF, data-plane services, and feature combinations.

### Actionable Passes

1. Define a standard local verification script or documented command set:

```bash
cargo check --workspace
cargo check -p synvoid-http3
cargo check -p synvoid-http
cargo check -p synvoid-waf
cargo check -p synvoid-mesh --features mesh
cargo test -p synvoid-mesh --features mesh
cargo test -p synvoid --features mesh,dns -- worker::
```

Adjust commands to match actual feature constraints.

2. Add targeted tests for the most important architecture invariants:
   - HTTP/3 does not require concrete root `WafCore`;
   - task registry never drops an aborted handle without awaiting it;
   - support tasks are registered only after mesh startup success;
   - required mesh gates ready;
   - optional mesh degradation stops support;
   - data-plane builder does not consult global plugin/serverless state;
   - shutdown cause maps to expected exit code and supervisor message.

3. Keep expensive integration tests separate from fast boundary tests.

### Exit Criteria

This track is done when each roadmap area has a small fast regression suite and a documented command sequence for broader validation.

---

## Suggested Next Three Handoff Plans

The next detailed handoff plans should be created in this order.

### Plan A — Unified Worker Composition Root Decomposition

Extract startup plan, supervision loop, shutdown executor, and supervisor notification without changing semantics. This has the best risk/reward ratio because it makes the largest current root function reviewable and unlocks later mesh/data-plane cleanup.

### Plan B — Worker Mesh Attachment Extraction

Once the generic worker skeleton is smaller, isolate worker-side mesh attachment behavior behind a small API. This reduces the chance that future mesh lifecycle changes accidentally perturb generic worker lifecycle behavior.

### Plan C — Root Module Ledger and Facade Reduction

After the worker root is less dense, create the root module ledger and begin shrinking `src/lib.rs`. This should be driven by facts from the codebase rather than a blind move-to-crates pass.

## Stopping Point for This Roadmap Phase

This roadmap phase can be considered complete when:

- the root crate has an explicit ledger and fewer implementation modules;
- `run_unified_server_worker()` is a short orchestration skeleton;
- worker-side mesh attachment is encapsulated;
- data-plane request services have a stable non-root owner or a clearly documented transitional owner;
- boundary source guards prevent new root coupling;
- the verification matrix is documented and runnable.

At that point, SynVoid will have moved from “modularized but root-centered” to “modularized with explicit app-layer composition.” That is the architectural inflection point needed before deeper feature work resumes.
