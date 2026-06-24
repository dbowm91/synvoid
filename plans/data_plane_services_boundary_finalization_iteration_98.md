# Data-Plane Services Boundary Finalization — Iteration 98

## Purpose

This phase is the next major roadmap item after the unified worker composition-root and mesh attachment work.

Iterations 93–97 cleaned up the worker composition root:

- Iteration 93 split startup, supervision, shutdown, and supervisor notification out of the old monolithic unified worker entrypoint.
- Iteration 94 corrected wrapper/shutdown details.
- Iteration 95 extracted worker-side mesh attachment into `mesh_attachment.rs`.
- Iteration 96 split mesh attachment into helper phases.
- Iteration 97 restored optional mesh status ordering and cleaned helper input shape.

The next architectural pressure point is the data-plane service boundary. `DataPlaneServices`, `DataPlaneServicesBuilder`, and `RequestServices` are the next root-gravity seam: they connect worker startup, WAF request execution, mesh/threat-intel state, serverless execution, port honeypot, policy context, and request-path dispatch.

This phase should make that seam explicit and stable before any HTTP/1 vs HTTP/3 request-pipeline normalization work.

## Current State

The current boundary is centered around:

```text
src/worker/unified_server/services.rs
src/worker/unified_server/startup_plan.rs
src/worker/unified_server/state.rs
src/worker/context.rs
```

The worker startup plan currently builds and wires concrete services. It likely performs some or all of these responsibilities:

- create/hold `DataPlaneServices`;
- build request services;
- inject request services into WAF/core request path;
- cross-wire mesh transport into serverless manager and port honeypot;
- build or update threat-intel policy context from canonical/advisory sources;
- carry mesh transport manager, threat-intel consumer, record store, and policy context through the worker state.

The shape is much better than when all of this was inline in `run_unified_server_worker()`, but the service boundary still needs a clearer contract.

## Problem Statement

The data-plane service container should not remain an unstructured worker-local wiring bag.

Without tightening this boundary, future HTTP/1 and HTTP/3 request pipeline normalization will be harder because request-path code will continue consuming root/worker-shaped state instead of narrow service handles.

The desired outcome is not a large crate extraction yet. The desired outcome is a stable internal boundary that clearly states:

- which module owns service construction;
- which module owns service cross-wiring;
- which module owns request-path handles;
- which dependencies are allowed to flow from worker startup into request execution;
- which dependencies are forbidden from leaking into request-path code.

## Non-Goals

Do not rewrite HTTP/1 request dispatch.

Do not rewrite HTTP/3 request dispatch.

Do not move `DataPlaneServices` into a new crate in this pass unless the existing code already makes that trivial.

Do not change mesh startup, supervision, or shutdown behavior.

Do not change WAF decision semantics.

Do not change threat-intel policy semantics.

Do not change serverless execution semantics.

Do not change port honeypot behavior.

Do not change public APIs unless the current internal boundary forces it.

Do not introduce new dependencies.

Do not undo Iterations 93–97 worker decomposition.

## Desired End State

After this pass:

- `DataPlaneServices` has a clearly documented ownership contract.
- `DataPlaneServicesBuilder` or its successor owns construction and cross-wiring, not scattered startup code.
- `RequestServices` is treated as the narrow request-path handle, not as a backdoor to worker state.
- `startup_plan.rs` delegates service assembly to a small number of methods and does not manually cross-wire service internals inline.
- Mesh attachment does not know about request services.
- Shutdown executor does not know about request services beyond using worker state.
- HTTP/1 and HTTP/3 request paths remain behaviorally unchanged, but their future normalization path is clearer.
- Guard tests prevent data-plane service code from becoming a broad root composition bucket again.

## Boundary Model

Use three conceptual layers.

### Worker Startup Layer

Owned by:

```text
src/worker/unified_server/startup_plan.rs
```

Allowed responsibilities:

- load config;
- initialize runtime/process-level services;
- call mesh/threat-intel init;
- create high-level application services;
- call a service assembly API;
- install assembled services into `UnifiedServerWorkerState`.

Forbidden responsibilities after this phase:

- manually cross-wiring serverless/mesh/honeypot internals inline;
- manually constructing request-path service handles in multiple places;
- directly mutating threat-intel policy context from scattered locations.

### Data-Plane Assembly Layer

Owned by:

```text
src/worker/unified_server/services.rs
```

or, if the existing code already warrants a split:

```text
src/worker/unified_server/services/mod.rs
src/worker/unified_server/services/builder.rs
src/worker/unified_server/services/request.rs
src/worker/unified_server/services/threat_intel.rs
```

Allowed responsibilities:

- build `DataPlaneServices`;
- build `RequestServices`;
- cross-wire mesh-aware optional services;
- build and apply threat-intel policy context;
- expose narrow typed handles to request path code;
- document which fields are runtime-owned vs request-path-owned.

Forbidden responsibilities:

- mesh startup/shutdown;
- worker supervision;
- supervisor IPC;
- HTTP route dispatch implementation;
- WAF policy decisions beyond handing service handles to WAF code.

### Request Path Layer

Owned by WAF/HTTP/app-server modules.

Allowed responsibilities:

- consume `RequestServices` or a narrow trait/handle derived from it;
- read service handles needed for request decisions;
- avoid worker lifecycle state.

Forbidden responsibilities:

- importing `UnifiedServerWorkerState` for request execution;
- importing broad worker startup modules;
- mutating cross-wiring after startup except through explicit update APIs.

## Phase 1 — Audit Current Service Boundary

Inspect these files first:

```text
src/worker/unified_server/services.rs
src/worker/unified_server/startup_plan.rs
src/worker/unified_server/state.rs
src/worker/context.rs
src/worker/unified_server/mesh_attachment.rs
src/worker/unified_server/shutdown_executor.rs
```

Create a short inline module comment or doc section in `services.rs` capturing current ownership:

```rust
// Data-plane service assembly boundary.
//
// Owns construction and cross-wiring of request-path service handles used by
// the unified worker. Startup code may provide concrete runtime components,
// but request-path modules should consume the narrow RequestServices handle
// rather than UnifiedServerWorkerState or startup modules.
```

Do not add a separate architecture document unless the existing architecture doc already has a data-plane section that should be updated.

## Phase 2 — Clarify `DataPlaneServices` Field Ownership

In `services.rs`, classify each `DataPlaneServices` field with comments or grouped sections.

Suggested grouping:

```rust
pub struct DataPlaneServices {
    // Request-path handle installed into WAF/request dispatch.
    pub request_services: RequestServices,

    // Optional runtime/application services cross-wired at startup.
    pub serverless_manager: Option<...>,
    pub port_honeypot: Option<...>,

    // Mesh/threat-intel data-plane inputs.
    pub mesh_transport_manager: Option<...>,
    pub threat_intel: Option<...>,
    pub threat_intel_policy: Option<...>,
    pub record_store: Option<...>,
}
```

If field names differ, adapt the grouping to the actual code.

Acceptance: a reviewer can tell which fields are request-path handles, optional runtime services, and mesh/threat-intel inputs.

## Phase 3 — Centralize Cross-Wiring In One Builder Method

Find all startup-plan code that manually wires service internals after construction.

Likely examples:

- serverless manager receives mesh transport;
- port honeypot receives mesh transport;
- request services are installed into WAF;
- threat-intel policy context is built from canonical/advisory sources;
- threat-intel context is applied to the data-plane services.

Move this behind one or two explicit methods in `DataPlaneServicesBuilder` or `DataPlaneServices`.

Suggested API:

```rust
impl DataPlaneServicesBuilder {
    pub fn with_mesh_runtime_inputs(
        mut self,
        mesh_transport_manager: Option<Arc<MeshTransportManager>>,
        canonical_reader: Option<Arc<dyn CanonicalThreatSource>>,
        advisory_source: Option<Arc<dyn AdvisoryThreatSource>>,
    ) -> Self {
        // store inputs
    }

    pub fn build_and_cross_wire(self) -> DataPlaneServices {
        let mut services = self.build();
        services.cross_wire_runtime_services();
        services.refresh_threat_intel_policy_context();
        services
    }
}
```

Names can differ. The point is that startup should not know the detailed sequence.

## Phase 4 — Make Threat-Intel Policy Context Ownership Explicit

Threat-intel policy context is a high-risk boundary because it is easy for stale/canonical/advisory semantics to leak into request execution.

Ensure there is one clear owner for:

- building `ThreatIntelPolicyContext` from canonical and advisory sources;
- applying it to request services or WAF policy consumers;
- updating it if sources are refreshed.

Suggested helper names:

```rust
fn build_threat_intel_policy_context(...) -> Option<ThreatIntelPolicyContext>
fn refresh_threat_intel_policy_context(&mut self)
fn apply_threat_intel_policy_context(&self)
```

If these already exist, tighten docs and ensure startup uses them rather than duplicating logic.

Acceptance:

- startup plan does not manually construct `ThreatIntelPolicyContext` inline;
- request path does not pull canonical/advisory sources directly;
- context update/application has one named path.

## Phase 5 — Clarify `RequestServices` As The Narrow Request-Path Handle

Inspect `src/worker/context.rs` or wherever `RequestServices` is defined.

Add doc comments describing what request path code may depend on.

Example:

```rust
/// Narrow service handle for request execution.
///
/// This type is intentionally smaller than `UnifiedServerWorkerState` and must
/// not grow lifecycle/supervision/shutdown dependencies. Add only services that
/// are required while handling a request.
```

If `RequestServices` currently imports broad worker state, isolate that dependency or document it as a follow-up if it cannot be removed safely.

Acceptance:

- request path code can use `RequestServices` without importing worker startup/supervision modules;
- new fields added to `RequestServices` must be request-execution services, not worker lifecycle controls.

## Phase 6 — Reduce Startup Plan Service Wiring Noise

After builder/service methods exist, simplify the data-plane section of `startup_plan.rs`.

Target shape:

```rust
let data_plane = DataPlaneServicesBuilder::new(...)
    .with_serverless_manager(...)
    .with_port_honeypot(...)
    .with_mesh_runtime_inputs(...)
    .with_threat_intel_inputs(...)
    .build_and_cross_wire();

unified_server.install_request_services(data_plane.request_services.clone());
```

or equivalent.

The exact API should follow the existing code style. Avoid creating fluent builder churn if a simple associated function is clearer.

Acceptance:

- `startup_plan.rs` remains the composition root, but not the service internals expert;
- startup plan service assembly is readable in a single short block;
- cross-wiring order is centralized and documented.

## Phase 7 — Add Boundary Guards

Add or update source guards. Prefer extending existing guard tests instead of creating many tiny files.

Likely target:

```text
tests/data_plane_composition_boundary_guard.rs
```

Add checks like:

```rust
#[test]
fn request_services_must_not_import_worker_lifecycle_modules() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(repo.join("src/worker/context.rs")).unwrap();
    assert!(!source.contains("unified_server::startup_plan"));
    assert!(!source.contains("unified_server::supervision_loop"));
    assert!(!source.contains("unified_server::shutdown_executor"));
    assert!(!source.contains("UnifiedServerWorkerState"));
}
```

Add guard that service cross-wiring remains centralized:

```rust
#[test]
fn startup_plan_delegates_data_plane_cross_wiring() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(repo.join("src/worker/unified_server/startup_plan.rs")).unwrap();
    assert!(source.contains("DataPlaneServicesBuilder"));
    assert!(source.contains("build_and_cross_wire") || source.contains("cross_wire"));
    assert!(!source.contains("set_mesh_transport")); // adapt to actual forbidden inline calls
}
```

Use actual current method names. Avoid false positives from comments by stripping comment lines like existing guards do.

Add guard that mesh attachment does not import request services:

```rust
#[test]
fn mesh_attachment_does_not_own_request_services() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(repo.join("src/worker/unified_server/mesh_attachment.rs")).unwrap();
    assert!(!source.contains("RequestServices"));
    assert!(!source.contains("DataPlaneServices"));
}
```

## Phase 8 — Documentation Updates

Update one or more of:

```text
architecture/worker_data_plane_composition_root.md
AGENTS.md
src/worker/AGENTS.override.md
.opencode/skills/synvoid_mesh/SKILL.md
```

Keep docs concise. Do not duplicate the entire plan.

Required doc note:

- `services.rs` is the data-plane assembly boundary;
- `RequestServices` is the narrow request-path handle;
- mesh attachment owns startup attachment only and must not own request services;
- shutdown executor must not own data-plane assembly.

## Verification Commands

Minimum:

```bash
cargo fmt
cargo check -p synvoid
cargo test --test data_plane_composition_boundary_guard
cargo test --test unified_worker_composition_root_guard
cargo test --test root_facade_boundary_guard
cargo test --test root_module_ledger_guard
```

Recommended focused tests:

```bash
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns
cargo test --test worker_supervision_control_flow --features mesh,dns
cargo test --test composition_root_behavioral --features mesh,dns
cargo test --test background_task_ownership_guard
```

Request/data-plane checks, if present:

```bash
cargo test request_services
cargo test data_plane
cargo test threat_intel_policy
```

Package/feature checks:

```bash
cargo check -p synvoid-http
cargo check -p synvoid-http3
cargo check -p synvoid-waf
cargo check -p synvoid-mesh --features mesh
cargo check --no-default-features --features mesh,dns
```

If any check has known unrelated failures, document exact error text and run the narrower targeted tests.

## Acceptance Criteria

This phase is complete when:

- `DataPlaneServices` and `RequestServices` have clear ownership docs.
- Service cross-wiring is centralized in `services.rs` or its submodule, not scattered in startup code.
- Threat-intel policy context build/apply/update path has one clear owner.
- Startup plan delegates service assembly through a narrow API.
- Mesh attachment imports no `RequestServices` or `DataPlaneServices` symbols.
- Request path code does not import `UnifiedServerWorkerState` or startup/supervision/shutdown modules for request execution.
- Boundary guards cover the above constraints.
- Behavior remains unchanged.

## Expected Files To Touch

Likely:

```text
src/worker/unified_server/services.rs
src/worker/unified_server/startup_plan.rs
src/worker/context.rs
tests/data_plane_composition_boundary_guard.rs
architecture/worker_data_plane_composition_root.md
src/worker/AGENTS.override.md
AGENTS.md
```

Possibly:

```text
src/worker/unified_server/state.rs
tests/unified_worker_composition_root_guard.rs
.opencode/skills/synvoid_mesh/SKILL.md
```

Avoid touching unless required:

```text
src/worker/unified_server/mesh_attachment.rs
src/worker/unified_server/shutdown_executor.rs
src/worker/unified_server/supervision_loop.rs
crates/synvoid-mesh/**
crates/synvoid-http/**
crates/synvoid-http3/**
```

## Review Checklist

Reject or revise the implementation if:

- it begins normalizing HTTP/1 and HTTP/3 request pipelines in this phase;
- it moves mesh startup logic back into startup plan;
- it gives mesh attachment knowledge of request services;
- it gives shutdown executor knowledge of service assembly;
- it weakens existing source guards rather than updating them precisely;
- it introduces broad `UnifiedServerWorkerState` dependencies into request path modules;
- it makes threat-intel policy context construction happen in more than one place;
- it changes WAF/request behavior without targeted tests.

## Handoff Summary

The worker composition root and mesh attachment seams are now stable. The next boundary to finalize is the data-plane service container. Keep this phase internal and behavior-preserving: document ownership, centralize service cross-wiring, make `RequestServices` the narrow request-path handle, and add guards so request-path code cannot re-grow dependencies on worker startup/supervision state. HTTP/1 and HTTP/3 pipeline normalization should come after this boundary is stable.
