# Phase 4 Plan: Request-Path Capability Boundary and Concrete Handle Reduction

Status: detailed handoff plan.

Roadmap position: Phase 4 of `plans/roadmap.md`.

Primary goal: ensure HTTP/WAF/proxy request-path code consumes narrow capabilities rather than concrete control-plane, mesh, supervisor, admin, or block-store infrastructure.

## Architectural Context

SynVoid already documents a strong invariant: composition roots own concrete infrastructure; request-path modules consume capabilities. The worker/data-plane architecture identifies request-path modules and forbids them from importing or owning mesh transport, DHT record stores, Raft types, admin handlers, concrete `BlockStore`, concrete `ThreatIntelligenceManager`, supervisor IPC internals, or snapshot/catchup/gossip APIs.

The remaining risk is concrete pass-through handle drift. Some concrete types are currently threaded through request dispatch contexts as pass-through data. That can be acceptable temporarily, but concrete handles tend to become implicit ownership unless narrowed. This phase makes `RequestServices` or narrower traits the normal request-path dependency surface.

## Non-Goals

Do not unify HTTP/1 and HTTP/3 body streaming implementations. Their stream and backpressure semantics differ.

Do not move mesh, DHT, Raft, or block-store concrete implementations into request-path modules.

Do not change enforcement semantics from local-only `BlockStore` reads to remote lookups.

Do not remove all pass-through concrete handles in one patch. Prioritize high-risk handles first.

## Deliverables

1. Updated `RequestServices` boundary that contains only request-execution capabilities.
2. One or more narrow traits for concrete pass-through behavior that is actually consumed by request-path code.
3. Reduced concrete mesh/control-plane handle exposure in HTTP/WAF/proxy dispatch contexts.
4. AST-backed or improved guardrails for request-path forbidden imports.
5. Tests proving HTTP/1 and HTTP/3 request dispatch do not import worker lifecycle modules or control-plane APIs.
6. Updated architecture docs listing remaining exceptions and removal targets.

## Step 1: Inventory Request-Path Concrete Handles

Inventory all concrete handles currently flowing into or through request-path code.

Start with these areas:

```bash
rg "MeshTransportManager|MeshBackendPool|AsyncIpcStream|IpcStream|WorkerId|ServerlessManager|GranianSupervisor|BlockStore|ThreatIntelligenceManager" src/http src/waf src/proxy src/worker/context.rs crates/synvoid-http crates/synvoid-waf crates/synvoid-proxy crates/synvoid-http3
```

Classify each occurrence:

- `construction`: forbidden in request path.
- `import only`: usually forbidden if concrete control-plane type.
- `pass-through`: tolerated only if documented.
- `behavior consumed`: should become a narrow trait.
- `diagnostic/test only`: allow only in test-only files.

Add the inventory to `architecture/request_path_capability_boundary.md` or update `architecture/worker_data_plane_composition_root.md`.

Suggested table:

```markdown
| Concrete type | Current files | Role | Risk | Target |
|---------------|---------------|------|------|--------|
| MeshTransportManager | ... | pass-through/serverless routing | mesh handle in request context | replace with ServerlessDispatch trait or keep scoped exception |
```

## Step 2: Define Capability Traits

Prefer defining traits in the crate that owns the abstraction boundary, not in the root if the trait is reusable.

Candidate trait locations:

- `crates/synvoid-core/src/traits.rs` for generic cross-crate traits.
- `crates/synvoid-waf/src/traits.rs` for WAF-facing enforcement traits.
- `crates/synvoid-http/src/runtime.rs` or similar for HTTP dispatch capabilities.
- `src/worker/context.rs` only for root-local composition handles.

Initial capabilities to consider:

```rust
#[async_trait::async_trait]
pub trait AppDispatch: Send + Sync {
    async fn dispatch_app(
        &self,
        request: AppDispatchRequest,
    ) -> Result<AppDispatchResponse, AppDispatchError>;
}

#[async_trait::async_trait]
pub trait ServerlessDispatch: Send + Sync {
    async fn dispatch_serverless(
        &self,
        request: ServerlessDispatchRequest,
    ) -> Result<ServerlessDispatchResponse, ServerlessDispatchError>;
}

pub trait RequestMetricsSink: Send + Sync {
    fn record_request_start(&self, ctx: &RequestMetricContext);
    fn record_request_end(&self, ctx: &RequestMetricContext, outcome: &RequestOutcomeMetric);
}

pub trait RequestDrainState: Send + Sync {
    fn accepting_requests(&self) -> bool;
    fn connection_started(&self);
    fn connection_finished(&self);
}
```

Do not create traits that simply mirror entire concrete APIs. Narrow them to actual request-path needs.

For blocklist/WAF, prefer existing traits if present. Do not create a trait that exposes mesh/DHT lookup behavior to request code.

## Step 3: Tighten `RequestServices`

Inspect `src/worker/context.rs` and related `RequestServices` construction in `src/worker/unified_server/services.rs`.

Target shape:

```rust
pub struct RequestServices {
    pub waf: Arc<dyn WafProcessor>,
    pub route_resolver: Arc<dyn RouteResolver>,
    pub metrics: Arc<dyn RequestMetricsSink>,
    pub drain: Arc<dyn RequestDrainState>,
    pub app_dispatch: Option<Arc<dyn AppDispatch>>,
    pub serverless_dispatch: Option<Arc<dyn ServerlessDispatch>>,
    // Avoid mesh transport, IPC manager internals, task registry, startup/shutdown handles.
}
```

If existing concrete fields cannot be removed in one pass, wrap them with adapter types at the composition boundary.

Example adapter pattern:

```rust
pub struct RootServerlessDispatch {
    manager: Arc<crate::serverless::manager::ServerlessManager>,
}

#[async_trait::async_trait]
impl ServerlessDispatch for RootServerlessDispatch {
    async fn dispatch_serverless(
        &self,
        request: ServerlessDispatchRequest,
    ) -> Result<ServerlessDispatchResponse, ServerlessDispatchError> {
        // Delegate to manager. Keep concrete manager out of request code.
    }
}
```

Construction belongs in `src/worker/unified_server/services.rs`, not in request handlers.

## Step 4: Replace High-Risk Concrete Imports

Prioritize replacements in this order:

1. Concrete `ThreatIntelligenceManager` imports in request/WAF/proxy/HTTP code. These should already be absent or diagnostic-only; preserve that invariant.
2. Concrete `BlockStore` ownership/construction in request path. Request code may consume a local blocklist trait, not construct/own `BlockStore`.
3. Mesh snapshot/catchup/gossip APIs in request path. These are control-plane only.
4. Admin auth/handler imports in request path.
5. Worker lifecycle/startup/shutdown imports in request path.
6. Concrete app/serverless handles where behavior can be trait-wrapped.

For each replacement:

- Add adapter at composition root.
- Update request-path function signature to consume trait or `RequestServices`.
- Update call sites.
- Add focused test or extend boundary guard.

## Step 5: Improve Boundary Guardrails

Existing guardrails are useful but likely text-based. For high-risk boundaries, add AST-backed import/path scanning where feasible.

Create or update `tests/request_path_capability_boundary_guard.rs`.

Minimum file classification:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoundaryRole {
    RequestPath,
    CompositionRoot,
    ControlPlane,
    Admin,
    SharedTypes,
    TestOnly,
}
```

Request-path scan roots:

- `src/http/`
- `src/waf/`
- `crates/synvoid-http/src/`
- `crates/synvoid-waf/src/`
- `crates/synvoid-proxy/src/`
- `crates/synvoid-http3/src/`

Composition-root exceptions:

- `src/worker/unified_server/services.rs`
- `src/worker/unified_server/startup_plan.rs`
- `src/server/`
- `src/supervisor/`

Forbidden token groups for request path:

```rust
const FORBIDDEN_REQUEST_PATH_TOKENS: &[&str] = &[
    "crate::mesh::transport",
    "crate::mesh::transports",
    "synvoid_mesh::mesh::transport",
    "MeshTransportManager",
    "MeshBackendPool",
    "ThreatIntelligenceManager",
    "crate::block_store::BlockStore",
    "synvoid_block_store::BlockStore",
    "lookup_threat_indicator_in_dht",
    "BlocklistCatchupRequest",
    "BlocklistSnapshotRequest",
    "BlocklistEventGossip",
    "openraft::",
    "crate::supervisor::",
    "verify_admin_token",
    "crate::admin::handlers",
    "UnifiedServerWorkerState",
    "WorkerTaskRegistry",
    "WorkerShutdownCause",
];
```

Prefer AST parsing for `use` items and path expressions if adding `syn` as a dev-dependency is acceptable. If not, keep the existing style but require exception liveness: every exception must correspond to a current occurrence and must include a reason.

## Step 6: Keep Diagnostics Separate from Enforcement

Preserve the threat-intel rule: raw local/DHT lookups are diagnostic/compatibility APIs and must not feed enforcement decisions. Enforcement consumers must use strict policy/actionability wrappers and mutate local enforcement state only through approved paths.

Add guard tokens for raw lookup APIs in enforcement/request files:

```rust
const RAW_THREAT_LOOKUP_TOKENS: &[&str] = &[
    "lookup_local_indicator(",
    "lookup_local_indicator_by_ip(",
    "lookup_threat_indicator_in_dht(",
];
```

Allow diagnostic-prefixed APIs only in admin/diagnostic files:

```rust
"diagnostic_lookup_local_indicator"
```

If a false positive occurs in a comment or test, classify the file as `TestOnly` or improve the scanner. Do not add broad allowlists for request-path files.

## Step 7: HTTP/1 and HTTP/3 Pipeline Boundary Tests

The repo already documents shared stage vocabulary for HTTP/1 and HTTP/3:

1. request metadata normalization,
2. route resolution,
3. body policy,
4. WAF evaluation,
5. terminal response handling,
6. upstream/app dispatch,
7. accounting.

Add or extend tests ensuring:

- HTTP/1 dispatch does not import worker lifecycle modules.
- HTTP/3 dispatch does not import worker lifecycle modules.
- Neither protocol imports mesh snapshot/catchup/gossip APIs.
- Both protocols consume `RequestServices` or narrower handles.
- Protocol-specific body/streaming implementations remain separate.

If a file must import a concrete type as a pass-through, add a scoped exception with:

- file,
- token,
- reason,
- planned replacement,
- liveness check.

## Step 8: Documentation

Update `architecture/worker_data_plane_composition_root.md` or create `architecture/request_path_capability_boundary.md`.

Document:

- Current `RequestServices` fields.
- Capability traits and their concrete adapters.
- Remaining concrete pass-through exceptions.
- Forbidden request-path imports.
- How to add a new request-path capability.
- Rule: request code may read local enforcement state through traits; it may not perform remote mesh/control-plane lookups.

Update `AGENTS.md` with verification commands.

## Verification Commands

Run:

```bash
cargo fmt
cargo test --test request_path_capability_boundary_guard
cargo test --test data_plane_composition_boundary_guard
cargo test --test http_request_pipeline_boundary_guard
cargo test --test threat_intel_consumer_actionability_guard --features mesh,dns
cargo check -p synvoid-waf
cargo check -p synvoid-http
cargo check -p synvoid-http3
cargo check -p synvoid-proxy
cargo check --no-default-features --features mesh,dns
cargo check
```

Adjust test names to existing guard filenames if this work extends current tests rather than adding a new one.

## Acceptance Criteria

This phase is complete when:

- High-risk concrete control-plane/mesh/block-store imports are absent from request-path modules or reduced to documented scoped pass-through exceptions.
- `RequestServices` contains only request-execution capabilities, not startup/supervision/shutdown/task-registry handles.
- New behavior consumed by request code is exposed through narrow traits/adapters.
- Boundary guardrails fail closed for new request-path files or new forbidden imports.
- HTTP/1 and HTTP/3 guardrails pass.
- Threat-intel diagnostic APIs remain separated from enforcement paths.
- Architecture docs list remaining exceptions and next removal targets.

## Handoff Notes for Smaller Models

Do not chase every concrete type at once. Start with the concrete imports that allow request path to reach mesh/control-plane APIs.

Use adapter structs in composition roots. Do not instantiate adapters inside request handlers.

Keep allowlists narrow and live. A broad allowlist is worse than no guardrail.

Do not introduce remote lookups into WAF/request code. The correct model is: control plane populates local state, request path reads local state.
