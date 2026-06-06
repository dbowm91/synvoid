# SynVoid Proxy and HTTP Consolidation Handoff Plan

> Status: proposed next-pass handoff.
> Target implementer profile: smaller coding agents such as MiMo 2.5, one task at a time.
> Goal: consolidate the completed `synvoid-proxy::ProxyServer` extraction, remove the duplicate root proxy implementation, then wire HTTP toward trait-based runtime context and prepare HTTP/HTTP3 movement.

## 0. Current state summary

The previous modularization passes successfully introduced the key interface layer and extracted many subsystem crates. The most important recent milestone is that `crates/synvoid-proxy/src/server.rs` now contains a real extracted `ProxyServer<W: WafProcessor>` that no longer stores or accepts concrete `Arc<WafCore>`.

The extracted proxy server now owns/provides:

```text
crates/synvoid-proxy/src/server.rs
  ProxyServer<W: WafProcessor>
  QuicTunnelSender trait
  WAF integration through WafProcessor
  optional ThreatLevelProvider
  optional TarpitService
  optional BlockListStore
  optional UpstreamErrorTracker
  proxy cache integration
  upstream pool integration
```

However, root `src/proxy/mod.rs` still contains an older concrete-root `ProxyServer` implementation that imports and stores concrete `WafCore`:

```text
src/proxy/mod.rs
  use crate::waf::{UpstreamErrorTracker, WafCore};
  pub struct ProxyServer<W: WafProcessor = crate::waf::adapter::RootWafProcessor> {
      waf: Arc<W>,
      waf_core: Arc<WafCore>,
      ...
  }
```

This is now the highest-priority issue. The project has two proxy-server implementations. That should be resolved before any additional crate creation or HTTP movement.

## 1. Pass objective

This pass should produce a single authoritative `ProxyServer` implementation in `synvoid-proxy` and make root `src/proxy` a compatibility shim.

After that, wire root HTTP/server/worker call sites to use the extracted proxy and the already-defined trait interfaces:

```text
synvoid_core::request::RequestContext
synvoid_core::routing::{RouteTarget, RouteResolution}
synvoid_core::metrics::MetricsSink
synvoid_core::drain::DrainState
synvoid_waf::traits::WafProcessor
synvoid_proxy::routing::RouteResolver
synvoid_http::runtime::HttpRuntimeContext
```

Do not extract worker, supervisor, or Raft in this pass.

## 2. Hard constraints

1. Do not add dependencies from extracted crates back to root `synvoid`.
2. Do not create new crates unless explicitly instructed by a task.
3. Do not move worker or supervisor.
4. Do not split Raft/consensus out of mesh.
5. Do not move `WafCore` into `synvoid-waf` in this pass.
6. Do not leave two live `ProxyServer` implementations.
7. Do not move the main HTTP pipeline until it no longer imports concrete root WAF/router/worker types.
8. Prefer root compatibility shims over large call-site rewrites when possible.
9. Preserve behavior. This is a structural consolidation pass.
10. Keep task diffs narrow.

## 3. Validation matrix

Each task has local checks. At the end of each wave run:

```bash
cargo fmt
cargo check --workspace --all-targets
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo test --lib --no-run
```

If full workspace clippy is noisy, run targeted clippy:

```bash
cargo clippy -p <touched-crate> --all-targets -- -D warnings
```

## 4. Wave P: consolidate ProxyServer ownership

### Task PHC-P01: inventory all `ProxyServer` call sites

Do not modify source code except for the plan note.

Create:

```text
plans/proxyserver_callsite_inventory.md
```

Search for:

```bash
rg "ProxyServer" src crates tests examples
rg "crate::proxy::ProxyServer|synvoid_proxy::ProxyServer" src crates tests examples
rg "new_with_tls\(|new_with_pool_config\(|with_upstream_pool\(" src crates tests examples
```

Record each call site:

```text
File | Current ProxyServer path | Constructor used | Has Arc<WafCore>? | Migration action | Notes
```

Migration actions:

```text
SWITCH_TO_SYNVOID_PROXY
KEEP_ROOT_REEXPORT_PATH
NEEDS_ADAPTER
TEST_ONLY_UPDATE
UNKNOWN_INVESTIGATE
```

Acceptance:

```bash
cargo check --lib --no-default-features
```

### Task PHC-P02: verify extracted `synvoid-proxy::ProxyServer` API coverage

Compare root `src/proxy/mod.rs` `ProxyServer` methods against `crates/synvoid-proxy/src/server.rs`.

Create or update:

```text
plans/proxyserver_api_parity.md
```

Record:

```text
Method | Exists in extracted server? | Behavior equivalent? | Missing dependencies | Action
```

At minimum, compare:

```text
new
new_with_tls
new_with_pool_config
with_upstream_pool
with_cache
with_http2
with_proxy_headers_config
with_cache_purge
handle
handle_with_method
handle_with_headers
streaming/body dispatch methods
cache purge path
retry path
error handling path
WAF decision path
QUIC tunnel path
```

Acceptance:

```bash
cargo check -p synvoid-proxy
cargo check --lib --no-default-features
```

Stop condition:

If the extracted server is missing behavior, add the missing method to `crates/synvoid-proxy/src/server.rs`; do not keep the root implementation as a permanent fork.

### Task PHC-P03: add root adapters required by extracted ProxyServer

Target crate:

```text
root synvoid crate
```

Purpose:

Make root call sites able to construct `synvoid_proxy::ProxyServer` without concrete root proxy implementation.

Likely adapters:

```text
RootWafProcessor from src/waf/adapter.rs
BlockStoreAdapter from src/waf/adapters.rs
GeoIp/Threat/Tarpit adapters if required
QuicTunnelSender implementation if QUIC tunnel paths are used
```

If `synvoid-proxy::ProxyServer` requires `ThreatLevelProvider`, `TarpitService`, or `BlockListStore`, construct those from existing root WAF fields or adapters at the call site.

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

Stop condition:

If adapter construction requires exposing many internals from `WafCore`, add a small method on `WafCore` to return the adapter dependency, rather than making fields public or cloning internal state broadly.

### Task PHC-P04: switch call sites to extracted ProxyServer

Target crate:

```text
root synvoid crate
```

Use either direct import:

```rust
use synvoid_proxy::ProxyServer;
```

or temporary root re-export:

```rust
pub use synvoid_proxy::ProxyServer;
```

Update all call sites found in PHC-P01.

Acceptance:

```bash
rg "crate::proxy::ProxyServer" src crates tests examples
# Should return no call sites except compatibility comments, if any.

cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

### Task PHC-P05: replace root `src/proxy/mod.rs` with compatibility shim

Depends on: PHC-P01 through PHC-P04.

Goal:

Root `src/proxy/mod.rs` should no longer define `ProxyServer` or own proxy implementation code. It should re-export `synvoid-proxy` and retain only root-specific adapters if absolutely needed.

Preferred shape:

```rust
//! Compatibility shim for the extracted synvoid-proxy crate.

pub use synvoid_proxy::*;
```

If some root-only adapter must stay:

```rust
pub use synvoid_proxy::*;

pub mod root_adapters;
```

Required removals:

```text
No root ProxyServer struct.
No `waf_core: Arc<WafCore>` field.
No `use crate::waf::{..., WafCore};` inside src/proxy/mod.rs.
No duplicated cache/header/retry modules if they are already exported by synvoid-proxy, unless they are compatibility shims.
```

Acceptance:

```bash
rg "struct ProxyServer|waf_core: Arc<WafCore>|use crate::waf::\{.*WafCore|use crate::waf::WafCore" src/proxy
# Should return no live implementation hits.

cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
cargo check -p synvoid-proxy
```

Stop condition:

If replacing `src/proxy/mod.rs` breaks many imports, first convert submodules one-by-one into re-export shims:

```rust
pub mod headers { pub use synvoid_proxy::headers::*; }
pub mod retry { pub use synvoid_proxy::retry::*; }
```

Then collapse them later.

## 5. Wave H: HTTP boundary wiring, not full movement yet

Purpose:

Prepare HTTP movement by ensuring root HTTP/server/worker code uses extracted proxy and runtime traits.

### Task PHC-H01: update HTTP dependency inventory

Create or update:

```text
plans/http_pipeline_root_dependencies.md
```

Search:

```bash
rg "crate::waf::WafCore|WafCore" src/http src/worker src/server src/http3
rg "crate::router::Router|Router" src/http src/worker src/server src/http3
rg "WorkerMetrics|WorkerDrain|DrainState|drain" src/http src/worker src/server src/http3
rg "crate::proxy::ProxyServer|synvoid_proxy::ProxyServer" src/http src/worker src/server src/http3
```

Record:

```text
File | Concrete root dependency | Existing trait replacement | Can change now? | Notes
```

Acceptance:

```bash
cargo check --lib --no-default-features
```

### Task PHC-H02: ensure root metrics adapter implements `MetricsSink`

Target crate:

```text
root synvoid crate
```

If already implemented, document location in `plans/http_pipeline_root_dependencies.md` and do not rewrite.

If not implemented, create a small adapter:

```rust
pub struct RootMetricsSink { ... }
impl synvoid_core::metrics::MetricsSink for RootMetricsSink { ... }
```

Do not redesign metrics.

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

### Task PHC-H03: ensure root drain adapter implements `DrainState`

Target crate:

```text
root synvoid crate
```

If already implemented, document location and do not rewrite.

If not implemented, create a small adapter:

```rust
pub struct RootDrainState { ... }
impl synvoid_core::drain::DrainState for RootDrainState { ... }
```

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

### Task PHC-H04: ensure root router adapter implements `RouteResolver`

Target crate:

```text
root synvoid crate
```

Verify `src/router_adapter.rs` implements:

```rust
synvoid_proxy::routing::RouteResolver
```

and produces:

```rust
synvoid_core::routing::RouteResolution
```

Do not mix route resolution with backend execution.

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

### Task PHC-H05: construct `HttpRuntimeContext` in root wiring

Target crate:

```text
root synvoid crate
```

Likely files:

```text
src/worker/unified_server/**
src/server/**
src/http/server.rs
src/http/shared_handler.rs
```

Where root already has concrete WAF/router/metrics/drain values, construct:

```rust
synvoid_http::runtime::HttpRuntimeContext::new(
    Arc::new(root_waf_processor),
    Arc::new(root_route_resolver),
    Arc::new(root_metrics_sink),
    Arc::new(root_drain_state),
)
```

If generics become invasive, use boxed trait-object context or a root wrapper. Do not genericize the entire worker if that causes broad churn.

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

## 6. Wave H2: move HTTP code only after imports are clean

### Task PHC-H06: move trait-only HTTP helpers into `synvoid-http`

Move functions/modules from `src/http` only when they do not import root concrete types.

Candidate modules to inspect first:

```text
src/http/body_policy.rs
src/http/challenge_paths.rs
src/http/early_parse.rs
src/http/headers.rs
src/http/request_parse.rs
src/http/response_builder.rs
src/http/response_helpers.rs
src/http/response_transform.rs
src/http/special_request_paths.rs
src/http/upstream_response_transform.rs
src/http/validation_helpers.rs
src/http/waf_decision.rs
```

Allowed dependencies inside `crates/synvoid-http`:

```text
synvoid-core
synvoid-config
synvoid-waf
synvoid-proxy
synvoid-http-client
synvoid-app-handlers
synvoid-metrics
http
http-body
http-body-util
hyper
hyper-util
tokio
tower
bytes
tracing
metrics
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

### Task PHC-H07: defer main HTTP pipeline if concrete imports remain

Before moving `src/http/server.rs` or `src/http/shared_handler.rs`, run:

```bash
rg "crate::waf::WafCore|crate::router::Router|WorkerMetrics|WorkerDrain|crate::worker|crate::supervisor|crate::server" src/http/server.rs src/http/shared_handler.rs
```

If any live concrete imports remain, do not move the main pipeline. Instead update `plans/http_pipeline_root_dependencies.md` with the exact blocker.

Only move main pipeline after that search is clean or all hits are comments/tests.

Acceptance if not moved:

```bash
cargo check --lib --no-default-features
```

Acceptance if moved:

```bash
cargo check -p synvoid-http
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

## 7. Wave Q: HTTP/3 stale-blocker cleanup

Purpose:

The `synvoid-http3` crate still contains an old blocker note. Some of the required traits now exist. Update the inventory and avoid stale documentation.

### Task PHC-Q01: refresh HTTP/3 blocker note

Target file:

```text
crates/synvoid-http3/src/lib.rs
```

Inspect current `src/http3/server.rs` imports. Update the crate-level blocker note to distinguish:

```text
Resolved prerequisites:
  WafProcessor exists
  RouteResolver exists
  MetricsSink exists
  DrainState exists

Remaining blockers:
  exact concrete imports still present in src/http3/server.rs
  dependency on root HTTP pipeline, if any
  dependency on UpstreamClientRegistry, if still root-only
  dependency on StreamingWafDecision, if still root-only
```

Acceptance:

```bash
cargo check -p synvoid-http3
cargo check --no-default-features --features mesh,dns
```

### Task PHC-Q02: do not move HTTP/3 yet unless HTTP/1/2 pipeline has moved

This is a guard task.

If main HTTP pipeline is still root-owned, leave HTTP/3 server in root and record precise blockers.

If main HTTP pipeline has moved and HTTP/3 imports are trait-clean, move:

```text
src/http3/server.rs
```

to:

```text
crates/synvoid-http3/src/server.rs
```

Acceptance if not moved:

```bash
cargo check --no-default-features --features mesh,dns
```

Acceptance if moved:

```bash
cargo check -p synvoid-http3
cargo check --no-default-features --features mesh,dns
```

## 8. Wave R: root dependency ownership cleanup

Purpose:

The root manifest still carries many heavy dependencies. Do not prune randomly. Prune after call sites move.

### Task PHC-R01: update root dependency ownership matrix

Create or update:

```text
plans/root_dependency_ownership.md
```

Classify at least these dependencies:

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
wasmtime
yara-x
rusqlite
rustls
tokio-rustls
quinn
h3
h3-quinn
fastcgi-client
maxminddb
schemars
utoipa
utoipa-swagger-ui
tonic
tonic-reflection
tonic-prost
openraft
openraft-legacy
```

Actions:

```text
KEEP_ROOT_FOR_NOW
REMOVE_FROM_ROOT
MOVE_TO_EXISTING_CRATE
FEATURE_FORWARD_ONLY
UNKNOWN_INVESTIGATE
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

### Task PHC-R02: prune root dependencies in tiny batches

Only remove dependencies marked safe by PHC-R01.

Rules:

```text
3-8 dependencies per commit maximum.
Do not combine dependency pruning with code movement.
If removal causes broad failures, restore and mark KEEP_ROOT_FOR_NOW.
```

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --workspace --all-targets
cargo check --no-default-features --features mesh,dns
```

## 9. Explicitly deferred work

Do not do these in this pass:

```text
Do not extract worker.
Do not extract supervisor.
Do not split Raft/consensus from mesh.
Do not move WafCore into synvoid-waf.
Do not create synvoid-threat-intel unless a later threat-specific plan says to.
Do not rewrite the whole HTTP pipeline before ProxyServer consolidation is complete.
Do not move HTTP/3 before HTTP/1/2 pipeline is trait-clean.
```

## 10. Recommended task order

Use this exact order:

```text
PHC-P01  inventory all ProxyServer call sites
PHC-P02  verify extracted ProxyServer API parity
PHC-P03  add root adapters required by extracted ProxyServer
PHC-P04  switch call sites to extracted ProxyServer
PHC-P05  replace root src/proxy/mod.rs with compatibility shim
PHC-H01  update HTTP dependency inventory
PHC-H02  ensure MetricsSink adapter
PHC-H03  ensure DrainState adapter
PHC-H04  ensure RouteResolver adapter
PHC-H05  construct HttpRuntimeContext in root wiring
PHC-H06  move trait-only HTTP helpers
PHC-H07  defer or move main HTTP pipeline based on import cleanliness
PHC-Q01  refresh HTTP/3 blocker note
PHC-Q02  defer or move HTTP/3 based on HTTP pipeline state
PHC-R01  update root dependency ownership matrix
PHC-R02  prune root dependencies in tiny batches
```

## 11. Subagent prompt template

Use this for smaller agents:

```text
You are implementing SynVoid proxy/HTTP consolidation task PHC-XX from plans/proxy_http_consolidation_handoff.md.
Scope is limited to this task. Preserve behavior. Do not add dependencies from extracted crates back to root synvoid. Do not move worker, supervisor, Raft, WafCore, or HTTP/3 unless the task explicitly says to. Prefer compatibility shims and small root adapters. If an extracted crate tries to import root synvoid, stop and report the remaining dependency. Run the task acceptance commands and report exact failures.
```

## 12. Success criteria

This pass is successful when:

```text
1. There is only one live ProxyServer implementation.
2. The live ProxyServer is synvoid_proxy::ProxyServer.
3. Root src/proxy/mod.rs is a compatibility shim or nearly so.
4. No root ProxyServer stores or accepts Arc<WafCore>.
5. Root HTTP/server/worker wiring can construct/use HttpRuntimeContext.
6. Some trait-only HTTP helper modules move into synvoid-http.
7. HTTP/3 blocker note is accurate and no longer stale.
8. Root dependency ownership matrix reflects the new crate graph.
9. Root dependencies shrink only after verified ownership changes.
10. Worker/supervisor/mesh remain stable.
```
