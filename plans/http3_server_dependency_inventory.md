# HTC-Q01: Inventory `src/http3/server.rs` Concrete Root Dependencies

**File**: `src/http3/server.rs` (292 lines)
**Date**: 2026-06-07

## Summary

`src/http3/server.rs` imports **10 concrete root-owned types** across 8 `crate::` import lines. Two of these (`WafCore`, `WorkerDrainState`) are root-defined structs with no trait seam in extracted crates. The remaining 8 are re-exports from extracted crates (`synvoid-proxy`, `synvoid-waf`, `synvoid-http-client`, `synvoid-metrics`, `synvoid-config`). The `prepare_http3_request_dispatch` and `handle_http3_request_dispatch` functions in `synvoid-http` also take some of these concrete types directly in their signatures.

---

## Concrete Dependency Table

| # | Concrete dependency | Import line | Struct field line | Existing seam | Missing seam | Action | Notes |
|---|---------------------|-------------|-------------------|---------------|--------------|--------|-------|
| 1 | `WafCore` | 14 | 21 | `WafProcessor` (synvoid-waf) | `WafCore` struct has no trait impl for the root-owned fields used here (`connection_limiter`, `is_over_bandwidth_limit`, `streaming`, `as_ref`) | Root-owned — keep as-is for inventory; decoupling requires `WafCore` to impl a local trait or the fields to be accessed via trait methods | `WafCore` is used as `Arc<WafCore>` — the server accesses `.connection_limiter`, `.is_over_bandwidth_limit()`, `.streaming()`, and passes `self.waf.as_ref()` to dispatch. `WafProcessor` trait covers `check_request`/`check_body_chunk` but not connection limiter or bandwidth queries |
| 2 | `FloodProtector` | 14 | 22 | **None** — `FloodProtector` is a struct in `synvoid_waf::flood` | No trait abstraction for `check_tcp_connection()` | Already in extracted crate `synvoid-waf` — no root ownership issue; can be used directly from `synvoid_waf::FloodProtector` | Used at lines 62, 159 (`fp.check_tcp_connection(client_ip)`) |
| 3 | `FloodDecision` | 14 | — (enum variant only) | **None** — enum in `synvoid_waf::flood` | No seam needed — it's a simple value enum | Already in extracted crate — no action needed | Used at lines 160, 164, 168 in match arms |
| 4 | `Router` | 13 | 20 | `RouteResolver` trait (synvoid-proxy) + `RouterRouteResolver` adapter | `prepare_http3_request_dispatch` takes `&Arc<Router>` directly, not `&dyn RouteResolver` | Already in extracted crate `synvoid-proxy` — but `prepare_http3_request_dispatch` still takes concrete `Arc<Router>` | Root re-exports `pub use synvoid_proxy::router::*;` at `src/router.rs:1`. The dispatch function signature in `synvoid-http` would need changing to accept `&dyn RouteResolver` |
| 5 | `HttpClient` | 9 | 23 | **None** — type alias `Client<HttpsConnector<HttpConnector>, Full<Bytes>>` | No trait; it's a `hyper_util` client type alias | Already in extracted crate `synvoid-http-client` — use directly from `synvoid_http_client::HttpClient` | Created via `create_http_client_with_config()` at line 41-42 |
| 6 | `UpstreamClientRegistry` | 12 | 24 | **None** — struct in `synvoid_proxy::client_registry` | No trait abstraction | Already in extracted crate `synvoid-proxy` — can be used directly from `synvoid_proxy::UpstreamClientRegistry` | Created with `UpstreamClientRegistry::new()` at line 53; passed to dispatch at line 272 |
| 7 | `WorkerMetrics` | 11 | 26 | `MetricsSink` trait (synvoid-core) + `WorkerMetricsSink` adapter (synvoid-metrics) | `handle_http3_request_dispatch` takes `Option<&Arc<WorkerMetrics>>` directly | Already in extracted crate `synvoid-metrics` — but dispatch function signature still takes concrete `WorkerMetrics` | Root re-exports from `src/metrics/`. The dispatch function would need changing to accept `Option<&dyn MetricsSink>` |
| 8 | `WorkerDrainState` | 15 | 25 | `DrainState` trait (synvoid-core) + `WorkerDrainStateAdapter` (root) | `WorkerDrainState` is **root-defined** at `src/worker/drain_state.rs:23` — no extracted equivalent | Root-owned struct — keep as-is for inventory; decoupling requires either moving `WorkerDrainState` to a crate or using `DrainState` trait | Stored as `Option<Arc<WorkerDrainState>>` but never used in any method (fields exist, no drain logic in server.rs). Builder method `with_drain_state` exists at line 67 |
| 9 | `Http3Config` / `MainConfig` | 8 | 19, 29 | Both in `synvoid-config` | No trait needed — config structs | Already in extracted crate `synvoid-config` — no action needed | `Http3Config` for server config, `MainConfig` for trusted proxies and passed to dispatch |
| 10 | `create_http_client_with_config` | 9 | — (called in constructor) | **None** — standalone function | No seam needed — factory function | Already in extracted crate `synvoid-http-client` — use directly | Called at line 41-42 |
| 11 | `get_global_bandwidth_tracker_or_log` | 10 | — (called per-request) | **None** — standalone function | No seam needed — utility function | Already in extracted crate `synvoid-metrics` — use directly | Called at line 253, returns `Option<Arc<BandwidthTracker>>` |
| 12 | `bind_udp_reuse` | 100 | — (called in `serve()`) | **None** — platform function | No seam needed — platform utility | Root-owned at `src/platform/socket.rs:381` — keep as-is | Platform-specific UDP socket binding with SO_REUSEPORT |

---

## synvoid-http Dispatch Function Coupling

The `synvoid-http` crate's dispatch functions already take some generic parameters but still couple to concrete types:

### `prepare_http3_request_dispatch` (synvoid-http/src/http3_request_flow.rs:38)

```rust
pub async fn prepare_http3_request_dispatch<R>(
    start: Instant,
    resolver: R,                        // ✅ Generic (Http3RequestResolver)
    remote_addr: SocketAddr,
    trusted_proxies: &[String],
    router: &Arc<Router>,               // ❌ Concrete Router
    connection_limiter: Option<&Arc<ConnectionLimiter>>,  // ❌ Concrete ConnectionLimiter
    over_bandwidth_limit: bool,
) -> Result<Http3RequestDispatchOutcome<R::RequestStream>, R::Error>
```

### `handle_http3_request_dispatch` (synvoid-http/src/http3_request_dispatch.rs:79)

```rust
pub async fn handle_http3_request_dispatch<Waf, S, W>(
    start: Instant,
    route_result: &RouteResult,          // ❌ Concrete (from synvoid-proxy)
    path: &str,
    method: &Method,
    headers: &HeaderMap,
    host: &str,
    query_string: Option<&str>,
    user_agent: Option<&str>,
    client_ip: IpAddr,
    request_stream: &mut W,              // ✅ Generic (Http3RequestStream)
    max_request_size: usize,
    streaming_waf_for_body: Option<S>,   // ✅ Generic (StreamingWafScanner)
    streaming_waf_for_upstream: Option<S>, // ✅ Generic
    connection_guard: Option<&ConnectionTokenGuard>,
    connection_limiter: Option<&Arc<ConnectionLimiter>>,  // ❌ Concrete ConnectionLimiter
    main_config: &Arc<MainConfig>,       // ❌ Concrete MainConfig
    client: &HttpClient,                 // ❌ Concrete HttpClient
    upstream_client_registry: &Arc<UpstreamClientRegistry>, // ❌ Concrete UpstreamClientRegistry
    bandwidth: Option<&Arc<BandwidthTracker>>,  // ❌ Concrete BandwidthTracker
    metrics: Option<&Arc<WorkerMetrics>>,  // ❌ Concrete WorkerMetrics
    waf: &Waf,                           // ✅ Generic (Http3RequestWaf)
) -> Result<(), BoxError>
```

---

## Classification

### Already in extracted crates (no root ownership issue)

These types are defined in extracted crates and merely re-exported by root. They can be imported directly from the extracted crate once `src/http3/server.rs` moves there:

| Type | Crate | Import path |
|------|-------|-------------|
| `Router` | synvoid-proxy | `synvoid_proxy::Router` |
| `FloodProtector` | synvoid-waf | `synvoid_waf::FloodProtector` |
| `FloodDecision` | synvoid-waf | `synvoid_waf::FloodDecision` |
| `HttpClient` | synvoid-http-client | `synvoid_http_client::HttpClient` |
| `UpstreamClientRegistry` | synvoid-proxy | `synvoid_proxy::UpstreamClientRegistry` |
| `WorkerMetrics` | synvoid-metrics | `synvoid_metrics::WorkerMetrics` |
| `Http3Config` | synvoid-config | `synvoid_config::Http3Config` |
| `MainConfig` | synvoid-config | `synvoid_config::MainConfig` |
| `ConnectionLimiter` | synvoid-waf | `synvoid_waf::ConnectionLimiter` |

### Root-owned (need work to decouple)

| Type | Root location | Trait seam in extracted crate | Effort |
|------|---------------|-------------------------------|--------|
| `WafCore` | `src/waf/mod.rs:97` | `WafProcessor` exists but doesn't cover `connection_limiter`, `is_over_bandwidth_limit`, `streaming()` | Medium — need to either extend `WafProcessor` or create a new `WafAccess` trait |
| `WorkerDrainState` | `src/worker/drain_state.rs:23` | `DrainState` trait exists in synvoid-core, `WorkerDrainStateAdapter` wraps it | Low — stored but unused in server.rs methods; just pass `Option<Arc<dyn DrainState>>` |

### Standalone functions (no ownership concern)

| Function | Crate | Notes |
|----------|-------|-------|
| `create_http_client_with_config` | synvoid-http-client | Factory function |
| `get_global_bandwidth_tracker_or_log` | synvoid-metrics | Utility function |
| `bind_udp_reuse` | root (platform) | Platform utility — stays in root |

---

## Acceptance

```bash
cargo check --no-default-features --features mesh,dns
```

**Status**: Inventory complete. No code changes made — this is a read-only inventory task.
