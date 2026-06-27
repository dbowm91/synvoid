# UnifiedServer Lifecycle Closure Plan

Status: detailed handoff plan.

Scope: focused corrective pass for the residual `UnifiedServer` lifecycle risks identified by `architecture/phase_1_5_verification_report.md`.

This pass should run before Phase 6 of `plans/roadmap.md`. Phases 1, 3, 4, and 5 are substantially closed. The remaining blocker is Phase 2 lifecycle ownership: `UnifiedServerRuntimeHandles` exists but is not integrated; plugin hot-reload ownership is too short-lived; some server tasks are fire-and-forget; and `tokio::select!` shutdown does not join/drain outstanding listener/background tasks.

## Primary Goal

Make `src/server/` lifecycle ownership structurally true rather than documentation/comment based.

By the end of this pass:

- `UnifiedServerRuntimeHandles` is either integrated and useful or deleted/reframed as intentional future work.
- Plugin hot-reload lifecycle remains alive for the full `UnifiedServer::run()` lifetime.
- Protocol listener tasks and server-owned background tasks have explicit owned handles.
- Shutdown broadcasts, joins, aborts on timeout, and reports outcomes.
- Guardrails verify structural ownership, not merely `// reason:` comments.

Preferred outcome: integrate `UnifiedServerRuntimeHandles` and use it as the single owner of server-spawned long-lived tasks.

## Non-Goals

Do not redesign HTTP/1, HTTPS, HTTP/3, TCP, UDP, or DNS request handling.

Do not change worker-side `WorkerTaskRegistry` or supervisor-side `SupervisorTaskRegistry` except for naming consistency if needed.

Do not implement plugin sandbox trust tiers; that belongs to a later plugin hardening phase.

Do not move `UnifiedServer` out of the root crate.

Do not start admin/control-plane authority Phase 6 until this pass is closed.

## Current Known Problems

From the verification report:

1. `UnifiedServerRuntimeHandles` is dead code — defined/exported but not instantiated in `run()`.
2. `PluginRuntimeOwner` is dropped at router creation boundary, so hot-reload watcher lifetime is shorter than intended.
3. `tokio::select!` drops non-completed branch futures without graceful drain on shutdown.
4. Threat-level auto-scale and ACME renewal tasks are fire-and-forget.
5. Lifecycle guard currently verifies `mem::forget` absence and reason comments, not real ownership.
6. Non-mesh HTTP server no-op behavior is undocumented or suspicious and should be verified.

## Target Architecture

`UnifiedServer::run()` should follow a structured lifecycle:

1. Build all request/runtime shared state.
2. Create `UnifiedServerRuntimeHandles`.
3. Create `PluginRuntimeOwner` and store it in a runtime-owned state object.
4. Spawn server-owned listener/background tasks through a registration API.
5. Wait for shutdown signal or critical task exit.
6. Broadcast shutdown.
7. Join all registered tasks within a bounded deadline.
8. Abort and await any task that exceeds the deadline.
9. Emit a `UnifiedServerRuntimeShutdownReport`.
10. Drop plugin/runtime owners only after task shutdown completes.

Preferred public shape:

```rust
pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut runtime = UnifiedServerRuntime::build(self).await?;
    runtime.run_until_shutdown().await
}
```

If introducing `UnifiedServerRuntime` is too large, keep `run()` but create a local `UnifiedServerRuntimeHandles` and `ServerRuntimeOwners` bundle.

## Deliverables

1. Integrated `UnifiedServerRuntimeHandles` used by `UnifiedServer::run()`.
2. `PluginRuntimeOwner` kept alive until after server shutdown.
3. Registered handles for HTTP/1, HTTP/1 IPv6, HTTPS, HTTPS IPv6, HTTP/3, HTTP/3 IPv6, TCP pool, UDP pool, DNS, ACME renewal, and threat-level auto-scale where applicable.
4. Shutdown report emitted/logged from `UnifiedServer::run()`.
5. Lifecycle guard updated to reject unregistered long-lived spawns, not merely missing comments.
6. Tests for handle registration, shutdown timeout, abort-and-await, critical task exit, and plugin owner lifetime.
7. `architecture/unified_server_startup.md` updated to remove “dead code” status and document the real lifecycle.
8. Verification report addendum committed under `architecture/unified_server_lifecycle_closure_report.md`.

## Phase A: Inventory Current Spawns and Lifetimes

Before editing, inventory all server/plugin spawns and lifecycle owners.

Commands:

```bash
rg "tokio::spawn|spawn\(" src/server src/plugin
rg "UnifiedServerRuntimeHandles|NamedRuntimeHandle|RuntimeHandleClass" src/server tests architecture
rg "PluginRuntimeOwner|PluginManagerLifecycle|enable_hot_reload|mem::forget" src/server src/plugin crates/synvoid-plugin-runtime
```

Create or update an inventory table in `architecture/unified_server_startup.md`:

```markdown
| Task / owner | File | Current owner | Target owner | Class | Shutdown behavior |
|--------------|------|---------------|--------------|-------|-------------------|
| HTTP/1 IPv4 | src/server/mod.rs | inline join handle | UnifiedServerRuntimeHandles | CriticalServer | shutdown broadcast + join |
| Threat-level auto-scale | src/server/mod.rs | fire-and-forget | UnifiedServerRuntimeHandles | Maintenance | shutdown watch + join/abort |
| Plugin hot reload | src/server/plugin_runtime.rs | too-short owner | ServerRuntimeOwners | HotReloadWatcher | drop after runtime shutdown |
```

Do not continue until every `tokio::spawn` in `src/server/` is classified.

## Phase B: Normalize Runtime Handle Types

Inspect `src/server/runtime_handles.rs` and make it capable of owning actual server task outputs.

Likely current problem: server tasks may return heterogeneous results such as `Result<(), BoxError>`, while `NamedRuntimeHandle` may expect `JoinHandle<()>`.

Recommended normalization:

```rust
pub type ServerTaskResult = Result<(), String>;

pub struct NamedRuntimeHandle {
    pub name: &'static str,
    pub class: RuntimeHandleClass,
    join: tokio::task::JoinHandle<ServerTaskResult>,
}
```

Add constructor helpers:

```rust
impl NamedRuntimeHandle {
    pub fn new(
        name: &'static str,
        class: RuntimeHandleClass,
        join: tokio::task::JoinHandle<ServerTaskResult>,
    ) -> Self {
        Self { name, class, join }
    }
}
```

If static names are too restrictive, use `Cow<'static, str>` or `String`.

Recommended task classes:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeHandleClass {
    CriticalServer,
    ProtocolListener,
    Maintenance,
    HotReloadWatcher,
    BestEffort,
}
```

Recommended outcome/report types:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeTaskExit {
    Completed,
    Failed(String),
    JoinError(String),
    Aborted,
    TimedOut,
}

#[derive(Debug, Default)]
pub struct UnifiedServerRuntimeShutdownReport {
    pub completed: usize,
    pub failed: usize,
    pub join_errors: usize,
    pub aborted: usize,
    pub timed_out: usize,
    pub critical_failures: usize,
}
```

Add methods:

```rust
impl UnifiedServerRuntimeHandles {
    pub fn new() -> Self;

    pub fn register(&mut self, handle: NamedRuntimeHandle);

    pub fn is_empty(&self) -> bool;

    pub async fn join_next_finished(&mut self) -> Option<(String, RuntimeHandleClass, RuntimeTaskExit)>;

    pub async fn shutdown_and_join(
        &mut self,
        timeout: std::time::Duration,
    ) -> UnifiedServerRuntimeShutdownReport;
}
```

`shutdown_and_join()` must abort and then await timed-out tasks. Do not call `abort()` without awaiting the handle afterward.

## Phase C: Add Spawn Registration Helpers

Create helper functions in `src/server/runtime_handles.rs` or a new `src/server/spawn.rs`.

Recommended API:

```rust
pub fn spawn_registered<F, E>(
    handles: &mut UnifiedServerRuntimeHandles,
    name: &'static str,
    class: RuntimeHandleClass,
    fut: F,
)
where
    F: std::future::Future<Output = Result<(), E>> + Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    let join = tokio::spawn(async move {
        fut.await.map_err(|e| e.to_string())
    });
    handles.register(NamedRuntimeHandle::new(name, class, join));
}

pub fn spawn_registered_unit<F>(
    handles: &mut UnifiedServerRuntimeHandles,
    name: &'static str,
    class: RuntimeHandleClass,
    fut: F,
)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let join = tokio::spawn(async move {
        fut.await;
        Ok(())
    });
    handles.register(NamedRuntimeHandle::new(name, class, join));
}
```

This avoids repeated `tokio::spawn(async move { ... })` conversion code in `mod.rs`.

## Phase D: Keep Plugin Runtime Owner Alive

Inspect current plugin setup in `src/server/mod.rs` and `src/server/plugin_runtime.rs`.

Problem to fix: `PluginRuntimeOwner` is created and dropped before the server runtime exits. This likely terminates hot-reload watcher early.

Target: store plugin owner in a runtime-lifetime owner bundle.

Suggested type:

```rust
struct ServerRuntimeOwners {
    plugin_runtime: Option<PluginRuntimeOwner>,
}
```

or:

```rust
pub struct UnifiedServerRuntimeContext {
    handles: UnifiedServerRuntimeHandles,
    plugin_runtime: Option<PluginRuntimeOwner>,
}
```

Minimum implementation:

```rust
let plugin_runtime_owner = self.build_plugin_runtime_owner().await?;
let _runtime_owners = ServerRuntimeOwners {
    plugin_runtime: plugin_runtime_owner,
};

// `_runtime_owners` must remain in scope until after `handles.shutdown_and_join(...)`.
```

Better implementation:

```rust
let mut runtime = UnifiedServerRuntime {
    handles: UnifiedServerRuntimeHandles::new(),
    owners: ServerRuntimeOwners { plugin_runtime: None },
};
runtime.owners.plugin_runtime = Some(plugin_runtime_owner);
```

Add a test that fails if `PluginRuntimeOwner` is dropped immediately after router creation. This can be indirect:

- add a `PluginRuntimeOwner::is_hot_reload_enabled()` method if cheap,
- or add a drop-observable test-only lifecycle object,
- or test that `ServerRuntimeOwners` stores `Some(plugin_runtime)` for the runtime lifetime.

Do not reintroduce `mem::forget`.

## Phase E: Register Protocol Listener Tasks

In `UnifiedServer::run()`, replace inline spawn handle locals with registered handles.

Target registrations:

- `http_v4`: `CriticalServer`
- `http_v6`: `ProtocolListener`
- `https_v4`: `CriticalServer`
- `https_v6`: `ProtocolListener`
- `http3_v4`: `ProtocolListener`
- `http3_v6`: `ProtocolListener`
- `tcp_pool`: `ProtocolListener`
- `udp_pool`: `ProtocolListener`
- `dns_v4`: `ProtocolListener`
- `dns_v6`: `ProtocolListener` or one DNS task if current code uses one task

Example:

```rust
spawn_registered(
    &mut handles,
    "http_v4",
    RuntimeHandleClass::CriticalServer,
    async move {
        tracing::info!("Starting HTTP server on {}", http_addr);
        Self::run_http_server_inner(state, http_addr, shutdown_rx).await
    },
);
```

For existing tasks returning `Result<(), Box<dyn Error + Send + Sync>>`, ensure `spawn_registered` maps errors to strings.

If some protocol task must be awaited directly because it borrows non-static state, clone/Arc the state so it can be registered. Avoid keeping special inline join paths unless absolutely necessary.

## Phase F: Register Maintenance Tasks

### F1. Threat-Level Auto-Scale

Current risk: loop is fire-and-forget.

Target behavior:

- It receives a shutdown signal.
- It exits on shutdown.
- It is registered as `Maintenance`.

Example:

```rust
let mut shutdown_rx = self.shutdown_tx.subscribe();
spawn_registered_unit(
    &mut handles,
    "threat_level_auto_scale",
    RuntimeHandleClass::Maintenance,
    async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => break,
                _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                    tl_clone.evaluate_and_adjust().await;
                }
            }
        }
    },
);
```

### F2. ACME Renewal

Current risk: ACME init/renewal task is fire-and-forget; cert reload callback may spawn another notification task.

Target behavior:

- Main ACME task is registered as `Maintenance`.
- If ACME manager supports shutdown, wire it. If not, the task must at least exit when shutdown broadcast is received or be abortable through `shutdown_and_join()`.
- Cert reload notification spawn is either short-lived and documented as bounded or registered as `BestEffort` if long-running.

Preferred pattern:

```rust
spawn_registered(
    &mut handles,
    "acme_renewal",
    RuntimeHandleClass::Maintenance,
    async move {
        acme_clone.run_until_shutdown(shutdown_rx).await
            .map_err(|e| e.to_string())
    },
);
```

If `AcmeManager` only has `init().await`, wrap it with shutdown-aware select:

```rust
spawn_registered(
    &mut handles,
    "acme_init_renewal",
    RuntimeHandleClass::Maintenance,
    async move {
        tokio::select! {
            result = acme_clone.init() => result.map_err(|e| e.to_string()),
            _ = shutdown_rx.recv() => Ok(()),
        }
    },
);
```

Add TODO only if ACME internals need later lifecycle improvement. Do not leave the outer task fire-and-forget.

## Phase G: Replace `tokio::select!` Join Logic

Current risk: `tokio::select!` waits on several branch futures and drops non-completed branch futures when one branch completes.

Target behavior:

- `run()` waits for one of:
  - OS shutdown signal,
  - critical task failure,
  - all server tasks unexpectedly complete,
  - explicit internal shutdown request.
- After trigger, it sends shutdown broadcast.
- Then it calls `handles.shutdown_and_join(timeout)`.
- It logs and returns appropriate error if critical task failed.

Recommended loop:

```rust
let shutdown_reason = loop {
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            break UnifiedServerShutdownReason::Signal;
        }
        finished = handles.join_next_finished() => {
            match finished {
                Some((name, class, exit)) => {
                    if class == RuntimeHandleClass::CriticalServer {
                        break UnifiedServerShutdownReason::CriticalTaskExit { name, exit };
                    }
                    tracing::warn!(task = %name, ?class, ?exit, "server task exited");
                }
                None => {
                    break UnifiedServerShutdownReason::AllTasksExited;
                }
            }
        }
    }
};

let _ = self.shutdown_tx.send(());
let report = handles.shutdown_and_join(shutdown_timeout).await;
tracing::info!(?shutdown_reason, ?report, "UnifiedServer shutdown complete");
```

Add a small `UnifiedServerShutdownReason` enum if useful.

Do not rely on dropping branch futures to cancel tasks. Use broadcast, join, abort-on-timeout.

## Phase H: Non-Mesh HTTP Server No-Op Audit

The verification report noted `#[cfg(not(feature = "mesh"))]` HTTP server no-op behavior.

Inspect all `#[cfg(not(feature = "mesh"))]` branches in `src/server/mod.rs`, `src/server/resources.rs`, and relevant HTTP setup code.

Questions:

- Is no-op HTTP server intentional under no-mesh profile?
- Does `cargo check --no-default-features` merely compile a degenerate binary, or should HTTP still serve without mesh?
- Are docs explicit about core/no-mesh runtime behavior?

Corrective options:

1. If no-op is intentional, document it in `architecture/unified_server_startup.md` and `AGENTS.md` profile notes.
2. If not intentional, wire non-mesh HTTP server to use local-only request services and add a basic no-mesh startup test.

Prefer not to fix full no-mesh runtime behavior in this pass unless it is a small wiring error. This pass is about lifecycle ownership, but the no-op should not stay undocumented.

## Phase I: Strengthen Lifecycle Guard

Update `tests/unified_server_lifecycle_ownership_guard.rs`.

Current guard likely checks:

- no `mem::forget`,
- `tokio::spawn` has `// reason:` comment.

New guard should enforce one of these patterns for long-lived server spawns:

- spawned through `spawn_registered` or equivalent,
- immediately registered with `UnifiedServerRuntimeHandles::register`,
- documented short-lived spawn exception with liveness check.

Suggested checks:

1. Reject direct `tokio::spawn` in `src/server/mod.rs` except inside approved helper functions or short-lived bounded callbacks.
2. Require all registered task names in architecture inventory to appear in code.
3. Require every exception to be live.
4. Continue rejecting `mem::forget`.
5. Fail if `UnifiedServerRuntimeHandles` is not instantiated in `src/server/mod.rs` or equivalent runtime module.

Example token checks:

```rust
#[test]
fn unified_server_runtime_handles_are_integrated() {
    let text = read("src/server/mod.rs");
    assert!(
        text.contains("UnifiedServerRuntimeHandles::new()") || text.contains("UnifiedServerRuntime::"),
        "UnifiedServerRuntimeHandles must be integrated into run(), not left as dead code"
    );
}

#[test]
fn server_long_lived_spawns_go_through_registration() {
    let offenders = scan_for_direct_tokio_spawn_outside_allowed_helpers("src/server");
    assert!(offenders.is_empty(), "long-lived server spawns must use spawn_registered/register: {offenders:#?}");
}
```

Do not make the guard impossible for short-lived callback spawns. Instead, require explicit `BoundedShortLived` exceptions with path+token+reason and liveness check.

## Phase J: Tests to Add or Update

### Runtime Handle Tests

In `src/server/runtime_handles.rs` tests:

- `register_tracks_task_count`
- `join_next_finished_returns_completed_task`
- `critical_task_failure_counted_in_report`
- `shutdown_and_join_aborts_timeout_task`
- `shutdown_and_join_awaits_after_abort`
- `maintenance_task_clean_exit_on_shutdown`

### Run-Loop Unit Tests

If `UnifiedServer::run()` is too hard to unit test, extract a testable helper:

```rust
async fn wait_for_shutdown_or_task_exit(
    handles: &mut UnifiedServerRuntimeHandles,
    shutdown_signal: impl Future<Output = ()>,
) -> UnifiedServerShutdownReason
```

Tests:

- signal triggers shutdown reason,
- critical task exit triggers critical reason,
- non-critical maintenance exit logs/continues,
- all tasks exiting returns all-exited reason.

### Plugin Owner Lifetime Tests

Add tests to prove the owner is stored for runtime lifetime. If actual watcher testing is expensive, test the owner bundle structure and drop order with a test-only drop flag.

Example test-only helper:

```rust
#[cfg(test)]
struct DropFlag(Arc<AtomicBool>);

#[cfg(test)]
impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
```

Use this pattern only if it does not pollute production types.

## Phase K: Documentation Updates

Update `architecture/unified_server_startup.md`.

Required changes:

- Remove or replace “dead code” statement for `UnifiedServerRuntimeHandles` after integration.
- Document actual lifecycle flow.
- Document all server task classes and task inventory.
- Document shutdown order and timeout behavior.
- Document plugin owner lifetime.
- Document any remaining short-lived spawn exceptions.
- Document non-mesh HTTP no-op behavior or its fix.

Add `architecture/unified_server_lifecycle_closure_report.md` after implementation.

Suggested report structure:

```markdown
# UnifiedServer Lifecycle Closure Report

Date: YYYY-MM-DD
Base: <commit>
Head: <commit>

## Summary

## Spawns Inventory

## Changes Made

## Tests Run

## Residual Risks

## Final Acceptance Statement
```

## Phase L: Verification Matrix

Run:

```bash
cargo fmt --all -- --check
cargo check
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns

cargo test --test unified_server_lifecycle_ownership_guard
cargo test -p synvoid --lib server::startup_plan
cargo test -p synvoid --lib server::resources
cargo test -p synvoid --lib server::runtime_handles
cargo test -p synvoid --lib server::plugin_runtime

cargo test --test supervisor_task_ownership_guard
cargo test --test request_path_capability_boundary_guard
cargo test --test data_plane_composition_boundary_guard
cargo test --test threat_intel_boundary_guard
cargo test --test threat_intel_consumer_actionability_guard --features mesh,dns
```

Also run any newly added run-loop tests by name.

If a broad command fails for a known pre-existing warning/error unrelated to this pass, record it in the closure report and run the narrow substitute.

## Acceptance Criteria

This pass is complete when:

- `UnifiedServerRuntimeHandles` is instantiated and used by `UnifiedServer::run()` or a replacement runtime struct.
- No architecture doc describes `UnifiedServerRuntimeHandles` as dead code.
- Protocol listener tasks are registered with names and classes.
- Threat-level auto-scale and ACME renewal tasks are registered or explicitly converted to bounded short-lived tasks.
- `PluginRuntimeOwner` remains alive until after registered task shutdown completes.
- Shutdown sends broadcast, joins registered tasks, aborts and awaits timed-out tasks, and emits a report.
- Direct long-lived `tokio::spawn` calls in `src/server/` are rejected by guardrails.
- `mem::forget` remains absent from server/plugin lifecycle code.
- Tests cover handle registration, critical failure, timeout abort, and plugin owner lifetime.
- Non-mesh HTTP no-op behavior is either fixed or explicitly documented.
- `architecture/unified_server_lifecycle_closure_report.md` records commands run and residual risks.

## Suggested Implementation Order

1. Normalize `runtime_handles.rs` to support real task result types.
2. Add spawn registration helpers.
3. Keep `PluginRuntimeOwner` in a runtime-lifetime owner bundle.
4. Register protocol listener tasks.
5. Register maintenance tasks.
6. Replace `tokio::select!` branch-drop shutdown with wait/broadcast/join/abort flow.
7. Strengthen lifecycle guard.
8. Add tests.
9. Update docs and closure report.
10. Run verification matrix.

## Notes for Smaller Models

Do not delete `UnifiedServerRuntimeHandles` unless integration is truly infeasible. The preferred fix is to make it real.

Do not use `mem::forget`, detached tasks, or comment-only ownership as a shortcut.

Do not alter request behavior while restructuring lifecycle. Keep protocol handlers as-is and change only how their tasks are spawned, observed, and shut down.

If compiler lifetime errors appear, clone existing `Arc` state into registered tasks rather than borrowing from `run()`.
