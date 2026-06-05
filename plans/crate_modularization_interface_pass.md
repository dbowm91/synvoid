# SynVoid Interface-First Modularization Pass

> Status: proposed third-pass plan.
> Target implementer profile: smaller coding agents such as MiMo 2.5, one narrow task at a time.
> Goal: unblock remaining crate extraction by introducing narrow service traits and adapter layers before moving more orchestration code.

## 0. Why this pass exists

The previous crate modularization passes extracted many useful leaf and mid-level crates:

```text
synvoid-core
synvoid-utils
synvoid-config
synvoid-challenge
synvoid-tarpit
synvoid-waf
synvoid-proxy-cache
synvoid-tls
synvoid-plugin-runtime
synvoid-http-client
synvoid-serverless
synvoid-geoip
synvoid-integrity
synvoid-upstream
synvoid-tunnel
synvoid-proxy
synvoid-http
synvoid-http3
synvoid-dns
synvoid-admin
synvoid-mesh
synvoid-app-handlers
synvoid-platform
synvoid-cli
```

The remaining hard blockers are not primarily file-location problems. They are concrete-type coupling problems.

Observed blockers:

```text
WafCore              -> AuthManager, BlockStore, ChallengeManager, GeoIpManager, persistence, metrics
Threat tracking      -> GeoIpManager, persistence, metrics, feed/network concerns
Router               -> platform, plugin, static_files, app handler implementations
ProxyServer          -> concrete root WafCore
HTTP server pipeline -> concrete WafCore, Router, WorkerMetrics, WorkerDrainState
HTTP/3 server        -> concrete WafCore, Router, WorkerMetrics, WorkerDrainState, UpstreamClientRegistry
Worker/Supervisor    -> orchestration-level coupling to most subsystems
Raft split           -> consensus fused to mesh transport
```

This pass should not try to solve those by moving more files first. It should define narrow traits, adapt root implementations to those traits, then move orchestration code only after the concrete root dependencies have been removed.

## 1. Core principle

Every remaining extraction should follow this order:

```text
1. Identify concrete root dependency.
2. Define a narrow trait or DTO in the lowest appropriate crate.
3. Implement the trait for the existing root type.
4. Change callers to depend on the trait/DTO.
5. Only then move orchestration code into an extracted crate.
```

Do not move `WafCore`, `ProxyServer`, main HTTP pipeline, HTTP/3 server, worker, supervisor, or Raft before their trait seams exist.

## 2. Where traits should live

Use this ownership rule:

```text
synvoid-core
  Dependency-free or near-dependency-free DTOs and traits shared by HTTP, HTTP/3, proxy, worker, and WAF.
  Examples: RequestContext, ResponseIntent, RouteTarget, MetricsSink, DrainState.

synvoid-waf
  WAF-specific decision and processing traits.
  Examples: WafProcessor, WafBodyScanner, BlockListStore, ChallengeService.

synvoid-proxy
  Proxy-specific execution and upstream dispatch traits.
  Examples: ProxyDispatch, UpstreamSelector if not already in synvoid-upstream.

synvoid-app-handlers
  Backend execution traits for static/CGI/FastCGI/PHP/serverless/plugin dispatch.

synvoid-mesh
  Mesh transport traits. Do not split consensus yet.

root synvoid crate
  Temporary adapter implementations for existing concrete root types.
```

Avoid adding traits to `synvoid-core` unless they are truly cross-cutting and can stay small. If a trait risks pulling in WAF/proxy-specific language, keep it in that domain crate.

## 3. Hard constraints for MiMo-sized subagents

1. Implement only one task ID at a time.
2. Do not move a major orchestrator unless the task explicitly says to move it.
3. Do not introduce a dependency from any extracted crate back to root `synvoid`.
4. Do not add a heavy runtime dependency to `synvoid-core`.
5. Prefer `http` crate primitives over `hyper` types in shared traits.
6. Preserve root compatibility shims.
7. Preserve existing feature profiles.
8. Stop and report if a trait would need more than 5-7 methods to satisfy the task; that usually means the boundary is too broad.
9. Stop and report if a proposed trait needs to expose internal locks, channels, task handles, concrete `ArcSwap`, concrete `DashMap`, or concrete Tokio runtime internals.
10. Do not refactor behavior while introducing traits; this pass is structural.

## 4. Always-run validation after each wave

```bash
cargo fmt
cargo check --workspace --all-targets
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo test --lib --no-run
```

For each task, run its narrower acceptance checks first.

## 5. Wave I: request, route, metric, and drain DTOs

Purpose: create tiny shared types that allow HTTP/proxy/WAF/worker code to talk without concrete root structs.

### Task IFACE-I01: define `RequestContext` and request body metadata

Target crate:

```text
crates/synvoid-core
```

Add module:

```text
crates/synvoid-core/src/request.rs
```

Suggested initial shape:

```rust
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub host: Option<String>,
    pub client_ip: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub site_id: Option<String>,
    pub tls_fingerprint: Option<TlsFingerprint>,
}

#[derive(Debug, Clone)]
pub struct TlsFingerprint {
    pub ja3: Option<String>,
    pub ja4: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyScanPhase {
    HeadersOnly,
    StreamingChunk,
    CompleteBody,
}
```

Keep it boring. Do not use `hyper::Request`, `axum`, `http_body`, or root config types.

Acceptance:

```bash
cargo check -p synvoid-core
cargo check -p synvoid-waf
```

### Task IFACE-I02: define `RouteTarget` and `RouteResolution`

Target crate:

```text
crates/synvoid-core
```

Add module:

```text
crates/synvoid-core/src/routing.rs
```

Suggested initial shape:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteTarget {
    ReverseProxy { upstream_id: String },
    Static { location_id: String },
    FastCgi { pool_id: String },
    Cgi { handler_id: String },
    Php { pool_id: String },
    Serverless { function_id: String },
    Plugin { plugin_id: String },
    Tunnel { tunnel_id: String },
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteResolution {
    pub site_id: Option<String>,
    pub target: RouteTarget,
    pub cache_policy_id: Option<String>,
    pub security_policy_id: Option<String>,
}
```

Do not embed concrete backend config structs yet. IDs are enough for the interface pass.

Acceptance:

```bash
cargo check -p synvoid-core
cargo check -p synvoid-proxy
cargo check -p synvoid-http
```

### Task IFACE-I03: define `MetricsSink` and no-op implementation

Target crate:

```text
crates/synvoid-core
```

Add module:

```text
crates/synvoid-core/src/metrics.rs
```

Suggested initial shape:

```rust
use std::time::Duration;

pub trait MetricsSink: Send + Sync + 'static {
    fn record_request_started(&self) {}
    fn record_request_finished(&self, _status: u16, _elapsed: Duration) {}
    fn record_request_body_bytes(&self, _bytes: usize) {}
    fn record_response_body_bytes(&self, _bytes: usize) {}
    fn record_upstream_error(&self, _kind: &str) {}
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NoopMetricsSink;

impl MetricsSink for NoopMetricsSink {}
```

Keep methods optional with default no-op bodies to avoid broad implementations.

Acceptance:

```bash
cargo check -p synvoid-core
cargo check -p synvoid-http
cargo check -p synvoid-http3
```

### Task IFACE-I04: define `DrainState` and no-op implementation

Target crate:

```text
crates/synvoid-core
```

Add module:

```text
crates/synvoid-core/src/drain.rs
```

Suggested initial shape:

```rust
pub trait DrainState: Send + Sync + 'static {
    fn is_draining(&self) -> bool;
    fn should_accept_new_connection(&self) -> bool {
        !self.is_draining()
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AlwaysAcceptDrainState;

impl DrainState for AlwaysAcceptDrainState {
    fn is_draining(&self) -> bool { false }
}
```

Acceptance:

```bash
cargo check -p synvoid-core
cargo check -p synvoid-http
cargo check -p synvoid-http3
```

## 6. Wave W: WAF interface layer

Purpose: allow proxy/HTTP/HTTP3 to depend on WAF behavior without concrete root `WafCore`.

### Task IFACE-W01: define `WafProcessor`

Target crate:

```text
crates/synvoid-waf
```

Add module or extend:

```text
crates/synvoid-waf/src/traits.rs
```

Suggested shape:

```rust
use synvoid_core::request::{BodyScanPhase, RequestContext};
use crate::primitives::WafDecision;

pub trait WafProcessor: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    fn check_request(&self, ctx: &RequestContext) -> Result<WafDecision, Self::Error>;

    fn check_body_chunk(
        &self,
        ctx: &RequestContext,
        chunk: &[u8],
        phase: BodyScanPhase,
    ) -> Result<Option<WafDecision>, Self::Error>;
}
```

If existing WAF APIs are async, use `async-trait` only in `synvoid-waf`, not in `synvoid-core` unless unavoidable.

Acceptance:

```bash
cargo check -p synvoid-waf
cargo check -p synvoid-proxy
cargo check -p synvoid-http
```

Stop condition:

If this trait needs more than request check and body scan functions, split into `WafProcessor` and `WafBodyScanner`.

### Task IFACE-W02: define WAF integration dependency traits

Target crate:

```text
crates/synvoid-waf
```

Add only methods currently needed by `WafCore`. Suggested traits:

```rust
pub trait BlockListStore: Send + Sync + 'static {
    fn is_blocked(&self, ip: std::net::IpAddr) -> bool;
    fn block_ip(&self, ip: std::net::IpAddr, reason: &str);
}

pub trait GeoIpLookup: Send + Sync + 'static {
    fn country_code(&self, ip: std::net::IpAddr) -> Option<String>;
    fn asn(&self, ip: std::net::IpAddr) -> Option<u32>;
}

pub trait ChallengeService: Send + Sync + 'static {
    fn should_issue_challenge(&self, ctx: &synvoid_core::request::RequestContext) -> bool;
    fn build_challenge(&self, ctx: &synvoid_core::request::RequestContext) -> Option<crate::primitives::WafDecision>;
}

pub trait WafPersistence: Send + Sync + 'static {
    fn persist_violation(&self, key: &str, reason: &str);
}
```

Do not try to cover every future method. Let root adapters expose only what current `WafCore` needs.

Acceptance:

```bash
cargo check -p synvoid-waf
cargo check --lib --no-default-features
```

### Task IFACE-W03: implement `WafProcessor` for root `WafCore`

Target crate:

```text
root synvoid crate
```

Files likely touched:

```text
src/waf/mod.rs
possibly src/waf/*.rs
```

Implement the trait by adapting existing `WafCore::check_request*` methods. If no direct mapping exists, add a small adapter struct in root:

```rust
pub struct RootWafProcessor {
    inner: std::sync::Arc<WafCore>,
}
```

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

Stop condition:

If adapting requires changing WAF decision semantics, stop and report. This task must be behavior-preserving.

### Task IFACE-W04: implement integration traits for root dependencies

Target crate:

```text
root synvoid crate
```

Implement the traits from IFACE-W02 for existing root concrete types where possible:

```text
BlockStore -> BlockListStore
GeoIpManager -> GeoIpLookup
ChallengeManager or adapter -> ChallengeService
persistence implementation or adapter -> WafPersistence
```

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

Stop condition:

If a root type cannot implement a trait cleanly, implement a small adapter wrapper rather than modifying the root type deeply.

## 7. Wave R: routing and app dispatch interface layer

Purpose: split route resolution from concrete app/platform/plugin/static execution.

### Task IFACE-R01: define `RouteResolver`

Target crate:

```text
crates/synvoid-proxy
```

Add module:

```text
crates/synvoid-proxy/src/routing.rs
```

Suggested shape:

```rust
use synvoid_core::request::RequestContext;
use synvoid_core::routing::RouteResolution;

pub trait RouteResolver: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    fn resolve(&self, ctx: &RequestContext) -> Result<RouteResolution, Self::Error>;
}
```

Acceptance:

```bash
cargo check -p synvoid-proxy
cargo check --lib --no-default-features
```

### Task IFACE-R02: implement `RouteResolver` for root router or adapter

Target crate:

```text
root synvoid crate
```

If current `Router` directly performs app dispatch, create an adapter that only exposes the resolution portion. Do not move plugin/static/platform dependencies.

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

### Task IFACE-R03: define backend dispatch trait

Target crate:

```text
crates/synvoid-app-handlers
```

Purpose:

Allow HTTP pipeline to call app handlers without knowing whether the concrete handler is static files, CGI, FastCGI, PHP, plugin, or serverless.

Suggested shape:

```rust
pub trait AppBackendDispatcher: Send + Sync + 'static {
    type Request;
    type Response;
    type Error: std::error::Error + Send + Sync + 'static;

    fn dispatch(
        &self,
        target: &synvoid_core::routing::RouteTarget,
        request: Self::Request,
    ) -> Result<Self::Response, Self::Error>;
}
```

Because concrete body types may still be unstable, associated types are acceptable here.

Acceptance:

```bash
cargo check -p synvoid-app-handlers
cargo check -p synvoid-http
```

Stop condition:

If the trait requires concrete Hyper body types, keep it in `synvoid-http` instead of app-handlers.

## 8. Wave M: metrics/drain adapters

Purpose: detach HTTP/HTTP3 from root worker structs.

### Task IFACE-M01: implement `MetricsSink` for root worker metrics adapter

Target crate:

```text
root synvoid crate
```

Files likely touched:

```text
src/worker/**
src/metrics/**
```

Do not move worker metrics. Just implement a small adapter:

```rust
pub struct WorkerMetricsSink {
    // existing root metrics type or Arc
}
```

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

### Task IFACE-M02: implement `DrainState` for root drain state adapter

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

Do not move drain code. Just expose the small adapter.

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

## 9. Wave P: use traits in proxy and move `ProxyServer`

Purpose: complete proxy extraction after WAF/routing traits exist.

### Task IFACE-P01: change proxy execution APIs to accept `WafProcessor`

Target crates:

```text
crates/synvoid-proxy
root synvoid crate
```

Change proxy leaf APIs so they accept `&dyn WafProcessor` or generic `W: WafProcessor`, not concrete root `WafCore`.

Prefer generics for internal helpers and trait objects at orchestration boundaries:

```rust
pub struct ProxyServer<W> {
    waf: std::sync::Arc<W>,
}

impl<W: synvoid_waf::traits::WafProcessor> ProxyServer<W> { ... }
```

If generics cause type proliferation, use trait objects:

```rust
Arc<dyn WafProcessor<Error = RootWafError>>
```

Acceptance:

```bash
cargo check -p synvoid-proxy
cargo check --lib --no-default-features
```

### Task IFACE-P02: move root `ProxyServer` into `synvoid-proxy`

Only after IFACE-P01 passes.

Move the main proxy orchestrator from root `src/proxy/mod.rs` to:

```text
crates/synvoid-proxy/src/server.rs
```

Root `src/proxy/mod.rs` should become re-exports plus adapters.

Acceptance:

```bash
cargo check -p synvoid-proxy
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

Stop condition:

If `ProxyServer` still imports root `crate::waf::WafCore`, stop. Do not move it until that import is gone.

## 10. Wave H: use traits in HTTP server pipeline

Purpose: make the main HTTP/1.1 and HTTP/2 pipeline movable.

### Task IFACE-H01: define `HttpRuntimeContext`

Target crate:

```text
crates/synvoid-http
```

Suggested shape:

```rust
pub struct HttpRuntimeContext<W, R, M, D> {
    pub waf: std::sync::Arc<W>,
    pub router: std::sync::Arc<R>,
    pub metrics: std::sync::Arc<M>,
    pub drain: std::sync::Arc<D>,
}
```

Where:

```text
W: WafProcessor
R: RouteResolver
M: MetricsSink
D: DrainState
```

Acceptance:

```bash
cargo check -p synvoid-http
cargo check --lib --no-default-features
```

### Task IFACE-H02: adapt root HTTP pipeline call sites to construct `HttpRuntimeContext`

Target crate:

```text
root synvoid crate
```

Do not move `src/http/server.rs` yet. Instead, create the runtime context at the boundary where the worker/server currently wires WAF/router/metrics/drain together.

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

### Task IFACE-H03: move HTTP helper functions that now only depend on traits

Target crate:

```text
crates/synvoid-http
```

Move functions from `src/http/server.rs` that no longer import root concrete types.

Acceptance:

```bash
cargo check -p synvoid-http
cargo check --lib --no-default-features
```

### Task IFACE-H04: move main HTTP server pipeline

Only after most imports are trait-based.

Move main server pipeline from root `src/http` into `crates/synvoid-http`.

Acceptance:

```bash
cargo check -p synvoid-http
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

Stop condition:

If moved code still imports root `crate::worker`, `crate::router`, `crate::waf::WafCore`, or `crate::metrics::WorkerMetrics`, stop and return to adapter tasks.

## 11. Wave Q: HTTP/3 extraction after HTTP pipeline stabilizes

Purpose: move HTTP/3 only after the same abstractions used by HTTP are proven.

### Task IFACE-Q01: make HTTP/3 server generic over WAF/router/metrics/drain

Target crates:

```text
root synvoid crate
crates/synvoid-http3
```

Do not move the server first. First change signatures so the HTTP/3 code can accept:

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

### Task IFACE-Q02: move `src/http3/server.rs`

Only after IFACE-Q01 passes and root concrete imports are gone.

Acceptance:

```bash
cargo check -p synvoid-http3
cargo check --no-default-features --features mesh,dns
```

## 12. Wave T: threat tracking and persistence seam

Purpose: unblock WAF threat tracking without dragging GeoIP, persistence, and metrics into the wrong crate.

### Task IFACE-T01: define threat tracking DTOs

Target crate:

```text
crates/synvoid-waf or new crates/synvoid-threat-intel
```

Use a new crate if feed/persistence/network concerns dominate. Use `synvoid-waf` if these are purely in-memory WAF scoring records.

Suggested DTOs:

```rust
pub struct ThreatEntry {
    pub key: String,
    pub reason: String,
    pub severity: u8,
    pub first_seen_unix: u64,
    pub last_seen_unix: u64,
}

pub struct ThreatLookup {
    pub score: u32,
    pub reasons: Vec<String>,
}
```

Acceptance:

```bash
cargo check -p synvoid-waf
```

### Task IFACE-T02: define persistence and metrics traits

Target crate:

```text
crates/synvoid-waf or crates/synvoid-threat-intel
```

Suggested traits:

```rust
pub trait ThreatPersistence: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    fn load_entries(&self) -> Result<Vec<ThreatEntry>, Self::Error>;
    fn save_entry(&self, entry: &ThreatEntry) -> Result<(), Self::Error>;
}

pub trait ThreatMetrics: Send + Sync + 'static {
    fn record_threat_entry(&self, severity: u8) {}
    fn record_feed_update(&self, count: usize) {}
}
```

Acceptance:

```bash
cargo check -p synvoid-waf
cargo check --lib --no-default-features
```

### Task IFACE-T03: adapt root threat tracking to traits

Target crate:

```text
root synvoid crate
```

Implement adapters for existing persistence/metrics/GeoIP dependencies. Do not move threat tracking yet.

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

### Task IFACE-T04: move threat tracking modules

Only after T01-T03.

Move the relevant modules into either:

```text
crates/synvoid-waf
```

or:

```text
crates/synvoid-threat-intel
```

Acceptance:

```bash
cargo check -p synvoid-waf
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

## 13. Wave O: worker/supervisor containment, not extraction

Purpose: prevent premature worker/supervisor extraction.

Do not move worker or supervisor in this pass. Instead, reduce their concrete coupling by making them consume subsystem traits and context structs.

### Task IFACE-O01: create orchestration boundary note

Target file:

```text
plans/worker_supervisor_boundary.md
```

Document:

1. Which concrete subsystems worker constructs.
2. Which concrete subsystems supervisor constructs.
3. Which extracted crates worker should depend on after HTTP/proxy/WAF movement.
4. Which concrete dependencies are legitimate orchestration dependencies and should remain.
5. Which dependencies are accidental and should be replaced by traits.

Acceptance:

```bash
cargo check --workspace --all-targets
```

### Task IFACE-O02: reduce worker imports opportunistically

Only replace direct root imports with extracted-crate imports where the extracted API is already stable.

Do not move worker code.

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

## 14. Wave C: mesh/consensus containment, not Raft split

Purpose: avoid premature consensus extraction.

### Task IFACE-C01: create mesh consensus boundary note

Target file:

```text
plans/mesh_consensus_boundary.md
```

Document:

1. Current coupling between Raft network and mesh transport.
2. Which transport operations Raft actually needs.
3. Candidate future trait, e.g. `ConsensusTransport`.
4. Why `synvoid-consensus` should not be extracted until that trait is proven.

Acceptance:

```bash
cargo check -p synvoid-mesh --features mesh
cargo check --no-default-features --features mesh
```

### Task IFACE-C02: define internal mesh-only `ConsensusTransport` trait if trivial

Target crate:

```text
crates/synvoid-mesh
```

Only do this if the boundary is obvious from C01. Keep it internal to mesh at first.

Acceptance:

```bash
cargo check -p synvoid-mesh --features mesh
```

Do not create `synvoid-consensus` in this pass.

## 15. Recommended task order

Use this order:

```text
IFACE-I01 RequestContext
IFACE-I02 RouteTarget/RouteResolution
IFACE-I03 MetricsSink
IFACE-I04 DrainState
IFACE-W01 WafProcessor
IFACE-W02 WAF integration dependency traits
IFACE-W03 WafProcessor adapter for root WafCore
IFACE-W04 root adapters for BlockStore/GeoIp/Challenge/Persistence
IFACE-R01 RouteResolver
IFACE-R02 root Router adapter
IFACE-R03 AppBackendDispatcher
IFACE-M01 MetricsSink adapter
IFACE-M02 DrainState adapter
IFACE-P01 Proxy APIs use WafProcessor
IFACE-P02 move ProxyServer
IFACE-H01 HttpRuntimeContext
IFACE-H02 root HTTP pipeline constructs context
IFACE-H03 move trait-only HTTP helpers
IFACE-H04 move main HTTP pipeline
IFACE-Q01 make HTTP3 generic over traits
IFACE-Q02 move HTTP3 server
IFACE-T01 threat DTOs
IFACE-T02 threat persistence/metrics traits
IFACE-T03 root threat adapters
IFACE-T04 move threat tracking
IFACE-O01 worker/supervisor boundary note
IFACE-O02 reduce worker imports
IFACE-C01 mesh consensus boundary note
IFACE-C02 internal mesh ConsensusTransport if trivial
```

## 16. Subagent prompt template

Use this exact template for smaller models:

```text
You are implementing SynVoid interface-first modularization task IFACE-XX from plans/crate_modularization_interface_pass.md.
Scope is limited to this task. Do not move major orchestrator files unless this task explicitly says to. Preserve behavior. Do not add dependencies from extracted crates back to root synvoid. Prefer small traits and root adapters. If the trait needs more than 5-7 methods or exposes internal locks/channels/runtime handles, stop and report the boundary problem. Run the task acceptance commands and report exact failures.
```

## 17. Success criteria for this pass

This pass is successful when:

1. Proxy code can depend on `WafProcessor` rather than concrete `WafCore`.
2. HTTP and HTTP/3 code can depend on `RouteResolver`, `MetricsSink`, and `DrainState` rather than concrete root router/worker structs.
3. `ProxyServer` can move into `synvoid-proxy` without importing root `crate::waf::WafCore`.
4. HTTP server pipeline movement becomes mechanical rather than architectural.
5. HTTP/3 server movement becomes mechanical after HTTP pipeline extraction.
6. Threat tracking has persistence/metrics/GeoIP seams and no longer needs to drag root services into WAF.
7. Worker/supervisor remain root orchestration code until subsystem APIs are stable.
8. Raft remains inside mesh until an internal `ConsensusTransport` boundary is proven.

## 18. Things explicitly out of scope

Do not extract worker in this pass.

Do not extract supervisor in this pass.

Do not split Raft into `synvoid-consensus` in this pass.

Do not move the main HTTP pipeline until WAF/router/metrics/drain traits are implemented and used.

Do not move HTTP/3 server until the HTTP pipeline has proven the same trait pattern.

Do not make `synvoid-core` depend on Hyper, Axum, Tokio runtime internals, Wasmtime, YARA, Quinn, OpenRaft, rusqlite, or root `synvoid`.

Do not turn traits into broad service locators. If a trait starts becoming a god object, stop and split it.
