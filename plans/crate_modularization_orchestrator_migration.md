# SynVoid Orchestrator Migration Plan

> Status: proposed fourth-pass modularization plan.
> Target implementer profile: smaller coding agents such as MiMo 2.5, one narrow task at a time.
> Goal: use the newly introduced trait seams to move remaining orchestration-heavy code out of the root crate without reintroducing concrete root dependencies.

## 0. Current state

The prior modularization passes created a broad workspace and landed the key interface layer:

```text
synvoid-core::request::RequestContext
synvoid-core::routing::{RouteTarget, RouteResolution}
synvoid-core::metrics::MetricsSink
synvoid-core::drain::DrainState
synvoid-waf::traits::WafProcessor
synvoid-waf::traits::{BlockListStore, GeoIpLookup, ChallengeService, WafPersistence}
synvoid-proxy::routing::RouteResolver
synvoid-http::runtime::HttpRuntimeContext
synvoid-app-handlers::dispatch::AppBackendDispatcher
```

Root also now has adapters:

```text
src/waf/adapter.rs      -> RootWafProcessor implements WafProcessor for Arc<WafCore>
src/waf/adapters.rs    -> BlockStore/GeoIp/Challenge/Violation adapters
src/router_adapter.rs  -> expected root Router adapter boundary
```

This is the correct foundation. The next pass should not create many new crates. It should use these traits to finish moving orchestrator code that was previously blocked by concrete root dependencies.

## 1. Primary blockers to remove

The known remaining blockers are:

```text
ProxyServer still lives in root and still stores/accepts Arc<WafCore>.
HTTP server pipeline still lives in root and likely imports WafCore, Router, WorkerMetrics, and drain types.
HTTP/3 server still depends on root-only HTTP/WAF/router/worker state.
WafCore itself still owns concrete AuthManager, BlockStore, ChallengeManager, GeoIpManager, root RequestServices, and root threat trackers.
Worker/Supervisor remain legitimate orchestration owners and should not be extracted yet.
Raft remains fused with mesh transport and should not be split yet.
```

This plan focuses on the first three. It deliberately defers `WafCore` extraction, worker/supervisor extraction, and Raft splitting.

## 2. Hard constraints

1. Do not add dependencies from extracted crates back to root `synvoid`.
2. Do not move worker or supervisor in this pass.
3. Do not split Raft out of mesh in this pass.
4. Do not move `WafCore` into `synvoid-waf` in this pass unless all concrete root dependencies have already been abstracted.
5. Do not move `ProxyServer` while it imports or stores concrete `crate::waf::WafCore`.
6. Do not move the main HTTP pipeline while it imports concrete root `WafCore`, concrete root `Router`, concrete worker metrics, or concrete drain state.
7. Prefer small adapter structs over large trait expansions.
8. If a trait needs more than 5-7 methods, stop and report the boundary problem.
9. Keep `synvoid-core` dependency-light. No Hyper, Axum, Tokio runtime, Quinn, Wasmtime, YARA, OpenRaft, or rusqlite.
10. Preserve behavior. This pass is structural, not semantic.

## 3. Validation matrix

After each task, run the task-specific checks. After each wave, run:

```bash
cargo fmt
cargo check --workspace --all-targets
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo test --lib --no-run
```

If full workspace clippy is too noisy, run narrow clippy:

```bash
cargo clippy -p <touched-crate> --all-targets -- -D warnings
```

## 4. Wave P: finish ProxyServer decoupling and move it

Purpose: make `ProxyServer` a real `synvoid-proxy` type instead of a root type.

Current known problem:

```text
src/proxy/mod.rs
  pub struct ProxyServer<W: WafProcessor = crate::waf::adapter::RootWafProcessor> {
      waf: Arc<W>,
      waf_core: Arc<WafCore>,
      ...
  }
```

The generic WAF processor is present, but concrete `Arc<WafCore>` is still stored and constructor-required. This prevents movement into `synvoid-proxy`.

### Task ORCH-P01: inventory remaining `WafCore` usage inside `ProxyServer`

Do not change behavior yet.

Files touched:

```text
plans/proxyserver_wafcore_usage.md
```

Search in `src/proxy/mod.rs` and related root proxy files for:

```text
waf_core
WafCore
check_request
check_request_full
check_request_body
upstream_error_tracker
challenge_manager
auth_manager
```

Document each direct `WafCore` usage:

```text
Location | Why ProxyServer uses WafCore | Replacement seam | Notes
```

Replacement seam options:

```text
WafProcessor
WafBodyScanner
WafDecisionRenderer
UpstreamErrorReporter
ChallengeRenderer
Remove if duplicate/unused
Keep root-only adapter for now
```

Acceptance:

```bash
cargo check --lib --no-default-features
```

### Task ORCH-P02: introduce additional proxy-facing WAF traits only if needed

Target crate:

```text
crates/synvoid-waf
```

Only do this if ORCH-P01 finds `ProxyServer` needs WAF behavior not covered by `WafProcessor`.

Candidate traits:

```rust
#[async_trait::async_trait]
pub trait WafBodyScanner: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn scan_body_chunk(
        &self,
        ctx: &synvoid_core::request::RequestContext,
        chunk: &[u8],
        phase: synvoid_core::request::BodyScanPhase,
    ) -> Result<Option<crate::primitives::WafDecision>, Self::Error>;
}
```

If upstream error reporting is the only concrete blocker, prefer a tiny trait:

```rust
pub trait UpstreamErrorReporter: Send + Sync + 'static {
    fn record_upstream_error(&self, site_id: &str, upstream: &str, status: Option<u16>);
}
```

Do not create a broad `WafServices` god trait.

Acceptance:

```bash
cargo check -p synvoid-waf
cargo check --lib --no-default-features
```

Stop condition:

If the new trait would expose challenge internals, auth internals, concrete trackers, or root service handles, stop and report. Use a root adapter instead.

### Task ORCH-P03: remove `Arc<WafCore>` from `ProxyServer`

Target crate:

```text
root synvoid crate
```

Files likely touched:

```text
src/proxy/mod.rs
src/http/**
src/worker/**
possibly src/server/**
```

Required changes:

```text
Remove `use crate::waf::WafCore` from src/proxy/mod.rs if only ProxyServer needs it.
Remove `waf_core: Arc<WafCore>` field.
Remove `waf_core: Arc<WafCore>` constructor parameters.
Replace direct WafCore calls with WafProcessor or additional tiny proxy-facing trait from ORCH-P02.
Update all call sites to pass RootWafProcessor or existing WafProcessor value only.
```

Acceptance:

```bash
rg "WafCore|waf_core" src/proxy/mod.rs
# Must return no concrete WafCore field/import/constructor usage.

cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

Allowed exceptions:

Comments in migration notes are acceptable. Code imports/fields/constructor args are not.

### Task ORCH-P04: move `ProxyServer` into `synvoid-proxy`

Depends on: ORCH-P03.

Move the server orchestration code from:

```text
src/proxy/mod.rs
```

to:

```text
crates/synvoid-proxy/src/server.rs
```

Root `src/proxy/mod.rs` should become mostly compatibility re-exports plus any root-only adapters.

Expected changes:

```text
crates/synvoid-proxy/src/lib.rs -> pub mod server; pub use server::ProxyServer;
src/proxy/mod.rs -> pub use synvoid_proxy::* where possible.
```

Dependency rule:

`crates/synvoid-proxy` may depend on:

```text
synvoid-core
synvoid-config
synvoid-http-client
synvoid-upstream
synvoid-proxy-cache
synvoid-waf
synvoid-metrics if needed
```

It must not depend on root `synvoid`.

Acceptance:

```bash
cargo check -p synvoid-proxy
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

Stop condition:

If the moved code tries to import `crate::waf`, `crate::worker`, `crate::router`, `crate::http`, or any root module from inside `crates/synvoid-proxy`, stop and return to ORCH-P02/ORCH-P03.

## 5. Wave H: connect HTTP runtime context to root call sites

Purpose: make root HTTP pipeline use trait-based runtime context before moving it.

The `synvoid-http::runtime::HttpRuntimeContext<W, R, M, D>` type exists. This wave wires it into root, but does not move the main pipeline until imports are clean.

### Task ORCH-H01: inventory concrete dependencies in root HTTP pipeline

Files touched:

```text
plans/http_pipeline_root_dependencies.md
```

Search under:

```text
src/http
src/worker/unified_server
src/http3
src/streaming
src/listener
```

Find imports/usages of:

```text
crate::waf::WafCore
crate::router::Router
crate::worker::*Metrics*
crate::drain::*
crate::proxy::ProxyServer
crate::http_client::UpstreamClientRegistry
```

Document:

```text
Location | Concrete dependency | Trait replacement | Can move now? | Notes
```

Acceptance:

```bash
cargo check --lib --no-default-features
```

### Task ORCH-H02: create root metrics adapter implementing `MetricsSink`

Target crate:

```text
root synvoid crate
```

Files likely touched:

```text
src/metrics/**
src/worker/**
```

Implement `synvoid_core::metrics::MetricsSink` for either:

```text
existing WorkerMetrics type
```

or a new adapter:

```rust
pub struct RootMetricsSink {
    // Arc or clone of existing metrics state
}
```

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

Stop condition:

If existing metrics are global functions only, implement a lightweight adapter that forwards to those functions. Do not redesign metrics.

### Task ORCH-H03: create root drain adapter implementing `DrainState`

Target crate:

```text
root synvoid crate
```

Files likely touched:

```text
src/drain.rs
src/worker/**
src/supervisor/**
```

Implement `synvoid_core::drain::DrainState` for either:

```text
existing drain state type
```

or a new adapter:

```rust
pub struct RootDrainState {
    // Arc or clone of existing drain flag/state
}
```

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

### Task ORCH-H04: complete root router adapter implementing `RouteResolver`

Target crate:

```text
root synvoid crate
```

Files likely touched:

```text
src/router_adapter.rs
src/router.rs
```

Ensure root router adapter implements:

```rust
synvoid_proxy::routing::RouteResolver
```

and returns `synvoid_core::routing::RouteResolution`.

Important:

Do not include backend dispatch in route resolution. Route resolution should answer “what should handle this?” not execute static/plugin/FastCGI/serverless handling.

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

### Task ORCH-H05: construct `HttpRuntimeContext` at root server/worker boundary

Target crate:

```text
root synvoid crate
```

Files likely touched:

```text
src/worker/unified_server/**
src/http/**
src/server/**
```

At the boundary where root currently has concrete WAF/router/metrics/drain objects, construct:

```rust
synvoid_http::runtime::HttpRuntimeContext::new(
    Arc::new(root_waf_processor),
    Arc::new(root_route_resolver),
    Arc::new(root_metrics_sink),
    Arc::new(root_drain_state),
)
```

Do not move the HTTP pipeline yet. Just create and pass the context where possible.

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

Stop condition:

If constructing context requires large lifetime or generic rewrites, create an owned adapter struct with `Arc<dyn ...>` trait objects instead of making the whole worker generic.

## 6. Wave H2: move HTTP server helpers and pipeline incrementally

Purpose: move only code whose imports are already trait-based.

### Task ORCH-H06: move trait-only HTTP helper functions into `synvoid-http`

Move functions from root `src/http/**` into `crates/synvoid-http` only if they do not import root modules.

Allowed dependencies inside `synvoid-http`:

```text
synvoid-core
synvoid-config
synvoid-waf
synvoid-proxy
synvoid-http-client
synvoid-app-handlers
http/http-body/http-body-util/hyper/hyper-util/tokio/tower/bytes/tracing/metrics
```

Forbidden imports inside `crates/synvoid-http`:

```text
synvoid::
crate::waf::WafCore
crate::router::Router
crate::worker
crate::supervisor
crate::server
```

Acceptance:

```bash
cargo check -p synvoid-http
cargo check --lib --no-default-features
```

### Task ORCH-H07: move main HTTP pipeline only when root imports are gone

Before moving, run:

```bash
rg "crate::waf::WafCore|crate::router::Router|WorkerMetrics|WorkerDrain|crate::worker" src/http
```

If concrete root dependencies remain, do not move.

When clean, move the main HTTP server pipeline from root `src/http` into:

```text
crates/synvoid-http/src/server.rs
```

Root `src/http/mod.rs` should become compatibility re-exports.

Acceptance:

```bash
cargo check -p synvoid-http
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

Stop condition:

If the move requires importing root `synvoid`, revert the move and record the remaining dependency in `plans/http_pipeline_root_dependencies.md`.

## 7. Wave Q: HTTP/3 migration after HTTP/1/2 pipeline stabilizes

Purpose: apply the same trait pattern to HTTP/3.

HTTP/3 should remain blocked until the HTTP runtime context pattern is proven in HTTP/1/2.

### Task ORCH-Q01: replace HTTP/3 concrete WAF/router/metrics/drain imports with traits

Target crates:

```text
root synvoid crate
crates/synvoid-http3
```

In root `src/http3`, replace direct concrete dependencies where possible with:

```text
WafProcessor
RouteResolver
MetricsSink
DrainState
```

Acceptance:

```bash
cargo check -p synvoid-http3
cargo check --no-default-features --features mesh,dns
```

Stop condition:

If HTTP/3 depends on root HTTP pipeline internals that are not yet moved, defer until ORCH-H07.

### Task ORCH-Q02: move HTTP/3 server into `synvoid-http3`

Only after ORCH-Q01 and ORCH-H07.

Move:

```text
src/http3/server.rs
```

to:

```text
crates/synvoid-http3/src/server.rs
```

Acceptance:

```bash
cargo check -p synvoid-http3
cargo check --no-default-features --features mesh,dns
```

Forbidden imports inside `crates/synvoid-http3`:

```text
synvoid::
crate::waf::WafCore
crate::router::Router
crate::worker
crate::supervisor
```

## 8. Wave W: WafCore containment and future extraction preparation

Purpose: reduce WafCore concrete field coupling without forcing full extraction yet.

### Task ORCH-W01: inventory concrete fields in `WafCore` and `WafCoreConfig`

Files touched:

```text
plans/wafcore_concrete_dependency_inventory.md
```

Document every concrete root type in:

```text
WafCore
WafCoreConfig
WafCore::new
```

Candidate categories:

```text
Can replace with existing synvoid-waf trait now
Needs new small trait
Should remain root-owned
Should move to synvoid-waf later
Should move to synvoid-threat-intel later
```

Acceptance:

```bash
cargo check --lib --no-default-features
```

### Task ORCH-W02: replace low-risk WafCore fields with trait wrappers

Only do fields that already have traits and adapters:

```text
BlockStore -> ErasedBlockStore or Arc<dyn BlockListStore>
GeoIpManager -> ErasedGeoIp or Arc<dyn GeoIpLookup>
ChallengeManager -> Arc<dyn ChallengeService> only if behavior maps cleanly
Violation persistence -> Arc<dyn WafPersistence> only if behavior maps cleanly
```

Do not force `AuthManager` yet unless there is a small auth trait already obvious.

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
cargo test --lib waf --no-run
```

Stop condition:

If replacing a field causes broad WAF initialization churn, stop and leave a note in the inventory file.

## 9. Wave T: threat tracking seam follow-through

Purpose: stop threat tracking from blocking WAF extraction due to persistence/GeoIP/metrics coupling.

### Task ORCH-T01: create or update threat tracking boundary inventory

Files touched:

```text
plans/threat_tracking_boundary.md
```

Inventory:

```text
src/waf/threat_level.rs
src/waf/violation_tracker.rs
src/waf/probe_tracker.rs
src/waf/asn_tracker.rs
src/waf/ip_feed.rs
src/waf/rule_feed.rs
src/waf/threat_intel.rs
```

For each module, record:

```text
Root dependencies
Persistence dependencies
GeoIP dependencies
Metrics dependencies
Network/background task dependencies
Candidate target crate: synvoid-waf vs synvoid-threat-intel vs root
```

Acceptance:

```bash
cargo check --lib --no-default-features
```

### Task ORCH-T02: decide whether to create `synvoid-threat-intel`

Do not create the crate unless the inventory shows threat tracking is not purely in-memory WAF scoring.

Use this rule:

```text
If modules need feed fetching, persistence, GeoIP enrichment, mesh export, admin serialization, or background tasks, create synvoid-threat-intel.
If modules are pure request-local scoring/tracking, keep them in synvoid-waf.
```

Deliverable:

Update `plans/threat_tracking_boundary.md` with a decision and rationale.

Acceptance:

```bash
cargo check --workspace --all-targets
```

## 10. Wave R: root dependency pruning after orchestrator movement

Purpose: remove root dependencies that become unnecessary after ProxyServer/HTTP movement.

### Task ORCH-R01: update root dependency ownership matrix

Files touched:

```text
plans/root_dependency_ownership.md
```

Reclassify dependencies after the latest moves.

Pay special attention to whether root still directly needs:

```text
hyper
hyper-util
hyper-rustls
tower
tower-http
axum
axum-extra
http-body
http-body-util
tokio-util
quinn
h3
h3-quinn
wasmtime
yara-x
fastcgi-client
maxminddb
metrics-exporter-prometheus
schemars
utoipa
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

### Task ORCH-R02: prune root dependencies in small batches

Remove only dependencies that the ownership matrix marks safe.

Batch size:

```text
3-8 dependencies per commit maximum.
```

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --workspace --all-targets
cargo check --no-default-features --features mesh,dns
```

Stop condition:

If removing a dependency creates broad unrelated failures, restore it and mark it `KEEP_ROOT_FOR_NOW`.

## 11. Things deliberately deferred

### Worker and supervisor extraction

Do not extract worker/supervisor until after:

```text
ProxyServer lives in synvoid-proxy.
Main HTTP pipeline lives in synvoid-http.
HTTP/3 server lives in synvoid-http3 or has trait-only root imports.
WAF/threat tracking concrete fields are reduced.
```

Worker and supervisor are legitimate composition layers. Extracting them too early will create god traits.

### Raft consensus split

Do not split `synvoid-consensus` from `synvoid-mesh` in this pass.

First prove an internal mesh transport trait such as:

```text
ConsensusTransport
```

inside `synvoid-mesh`. Only split after that trait is real and small.

### Full WafCore extraction

Do not move `WafCore` into `synvoid-waf` until:

```text
BlockStore/GeoIP/Challenge/Persistence/Auth/RequestServices are all trait-backed or moved.
Threat tracking target crate is decided.
ProxyServer no longer needs WafCore.
HTTP pipeline no longer imports WafCore.
```

## 12. Recommended task order

Use this sequence:

```text
ORCH-P01  inventory ProxyServer WafCore usage
ORCH-P02  add tiny proxy-facing WAF trait only if needed
ORCH-P03  remove Arc<WafCore> from ProxyServer
ORCH-P04  move ProxyServer into synvoid-proxy
ORCH-H01  inventory HTTP concrete dependencies
ORCH-H02  root MetricsSink adapter
ORCH-H03  root DrainState adapter
ORCH-H04  complete RouteResolver adapter
ORCH-H05  construct HttpRuntimeContext at root boundary
ORCH-H06  move trait-only HTTP helpers
ORCH-H07  move main HTTP pipeline
ORCH-Q01  traitify HTTP/3 server imports
ORCH-Q02  move HTTP/3 server
ORCH-W01  WafCore concrete field inventory
ORCH-W02  replace low-risk WafCore fields with traits
ORCH-T01  threat tracking boundary inventory
ORCH-T02  decide synvoid-threat-intel
ORCH-R01  update root dependency ownership
ORCH-R02  prune root dependencies
```

## 13. Subagent prompt template

Use this prompt for smaller models:

```text
You are implementing SynVoid orchestrator migration task ORCH-XX from plans/crate_modularization_orchestrator_migration.md.
Scope is limited to this task. Preserve behavior. Do not add dependencies from extracted crates back to root synvoid. Do not move worker/supervisor/Raft/WafCore unless explicitly instructed by the task. Prefer tiny traits and root adapters. If a moved file tries to import root synvoid from inside an extracted crate, stop and report the remaining dependency. Run the task acceptance commands and report exact failures.
```

## 14. Success criteria for this pass

This pass is successful when:

1. `ProxyServer` lives in `synvoid-proxy`.
2. `ProxyServer` no longer stores or accepts `Arc<WafCore>`.
3. Root HTTP pipeline constructs or consumes `HttpRuntimeContext`.
4. Trait-only HTTP helpers have moved into `synvoid-http`.
5. The main HTTP pipeline is either moved or has a precise remaining-dependency inventory.
6. HTTP/3 has either moved or has concrete imports reduced to a known minimal set.
7. Root dependency ownership is updated after movement.
8. Root dependency list shrinks in small verified batches.
9. Worker/supervisor remain stable and behavior-preserving.
10. Mesh/Raft is not destabilized.
