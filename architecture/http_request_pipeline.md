# HTTP Request Pipeline

Internal architecture reference for developers working on request handling in `crates/synvoid-http/`. Both HTTP/1 and HTTP/3 follow the same conceptual stages but use different stream types, body collection strategies, and dispatch modules. This document maps stages to files.

## Overview

Every inbound HTTP request — whether HTTP/1.1 over TCP or HTTP/3 over QUIC — flows through seven conceptual stages: metadata extraction, route resolution, body policy, WAF evaluation, terminal response, backend dispatch, and accounting. The pipelines share the `Router`, `WafDecision`, and `RouteTarget` types from `synvoid-proxy` but diverge in stream ownership, backpressure models, and upstream dispatch (boxed body vs. QUIC stream). Each stage has a dedicated file; stage boundaries are enforced by the composition root boundary guard.

## Shared Stage Vocabulary

| Stage | Description | HTTP/1 File | HTTP/3 File |
|-------|-------------|-------------|-------------|
| **Metadata Normalization** | Extract method, path, host, user_agent, client_ip, headers into a structured context. | `request_preparation.rs` → `extract_request_metadata()` | `http3_request_prelude.rs` → `prepare_http3_request_prelude()` |
| **Route Resolution** | Match normalized request against the routing table. | `request_preparation.rs` → `router.route_with_local_addr()` | `http3_request_prelude.rs` → `router.route()` |
| **Body Policy** | Decide: collect full body, stream through WAF, reject (too large), or tarpit. | `body_policy.rs` → `collect_and_scan_request_body()` | `http3_body.rs` → `collect_http3_request_body()` |
| **WAF Evaluation** | Run WAF checks (early, streaming, buffered) and produce a decision. | `request_parse.rs` → `early_waf_decision()`, `buffered_request_waf_dispatch.rs` → `full_request_waf_decision()` | `http3_request_dispatch.rs` → `waf.check_request_full()`, `http3_waf_dispatch.rs` → `maybe_handle_http3_waf_decision()` |
| **Terminal Response** | Handle terminal decisions (not-found, error, blocked) before upstream dispatch. | `request_frontdoor.rs` → `dispatch_internal_endpoint()` | `http3_terminal.rs` → `maybe_handle_http3_terminal_route_result()` |
| **Backend Dispatch** | Route to the correct backend (upstream, app server, static, serverless, WASM, etc.). | `backend_dispatch.rs` → `handle_pass_backend_dispatch()` | `http3_route_dispatch.rs` → `handle_http3_found_route()` → `http3_buffered_upstream_dispatch.rs` / `http3_streaming_upstream_dispatch.rs` |
| **Accounting** | Record bandwidth, metrics, latency, and request logs. | `http_request_postlude.rs` → `RequestMetricsAdapter` | Inline in dispatch and upstream modules |

## Context Structs

### HTTP/1

```rust
// request_preparation.rs
pub struct PreparedRequest {
    pub on_upgrade: Option<hyper::upgrade::OnUpgrade>,
    pub target: RouteTarget,
    pub parts: http::request::Parts,
    pub method: http::Method,
    pub path: String,
    pub user_agent: Option<String>,
    pub skip_waf: bool,
    pub full_body_arc: Arc<Bytes>,
    pub request_body_size: u64,
    pub body_slice: Option<Arc<Bytes>>,
}
```

`PreparedRequest` is the output of `prepare_request_preflight()` after metadata extraction, early WAF, route resolution, and body collection. It is consumed by `http_request_postlude.rs` which runs the full WAF decision and backend dispatch.

### HTTP/3

`Http3RequestPrelude` is the output of `prepare_http3_request_prelude()` after metadata extraction and route resolution. Iteration 99 adapts that prelude into `Http3RequestMetadata`, which is passed to `handle_http3_request_dispatch()`.

```rust
pub struct Http3RequestMetadata {
    pub start: Instant,
    pub route_result: RouteResult,
    pub path: String,
    pub method: Method,
    pub headers: HeaderMap,
    pub host: String,
    pub query_string: Option<String>,
    pub user_agent: Option<String>,
    pub client_ip: IpAddr,
}
```

HTTP/3 service dependencies are grouped in `Http3DispatchDeps`:

```rust
pub struct Http3DispatchDeps {
    pub max_request_size: usize,
    pub streaming_waf_for_body: Option<Box<dyn StreamingWafScanner>>,
    pub streaming_waf_for_upstream: Option<Box<dyn StreamingWafScanner>>,
    pub connection_limiter: Option<Arc<ConnectionLimiter>>,
    pub main_config: Arc<MainConfig>,
    pub client: HttpClient,
    pub upstream_client_registry: Arc<UpstreamClientRegistry>,
    pub bandwidth: Option<Arc<BandwidthTracker>>,
    pub metrics: Option<Arc<WorkerMetrics>>,
}
```

`handle_http3_request_dispatch()` receives `Http3RequestMetadata`, `Http3DispatchDeps`, the request stream, the optional connection guard, and the WAF backend. This keeps QUIC/server ownership in `synvoid-http3` while the protocol-independent dispatch stages remain in `synvoid-http`.

### RequestServices (worker-level narrow handle)

```rust
// src/worker/context.rs
pub struct RequestServices {
    #[cfg(feature = "mesh")]
    pub threat_intel: Option<Arc<ThreatIntelligenceManager>>,
    pub upload_validator: Option<Arc<UploadValidator>>,
    #[cfg(feature = "mesh")]
    pub yara_rules: Option<Arc<YaraRulesManager>>,
    pub plugin_manager: Option<Arc<GlobalPluginManager>>,
    pub serverless_registry: Option<Arc<ServerlessRegistry>>,
}
```

`RequestServices` is the narrow service handle passed to request dispatch. It must not grow lifecycle/supervision/shutdown dependencies.

## Body/Streaming Semantics

HTTP/1 and HTTP/3 body handling is intentionally **not** unified:

- **HTTP/1** uses `hyper::body::Incoming` — a `Stream<Item = Result<Bytes, Error>>`. Body collection in `body_policy.rs` routes to either `http_body_util::BodyExt::collect()` (small bodies) or `collect_body_with_chunk_waf()` (large bodies with streaming WAF scan). The collected body is wrapped in `Arc<Bytes>` on `PreparedRequest`.

- **HTTP/3** uses a custom `Http3RequestStream` trait with `recv_data() -> Result<Option<Bytes>>`. Body collection in `http3_body.rs` reads from the QUIC stream directly. The collected body is a `Vec<u8>`. Streaming upstream mode bypasses collection entirely when the route target doesn't need body transforms.

The difference is architectural: HTTP/1 bodies flow through hyper's backpressure model; HTTP/3 bodies flow through QUIC stream-level flow control. Unifying them would require abstracting over both backpressure models, which is not worth the complexity.

## Boundary Invariant

Request dispatch consumes `RequestServices` or narrower handles, never `UnifiedServerWorkerState`.

This is enforced by `tests/data_plane_composition_boundary_guard.rs`. The guard classifies each file by role (`CompositionRoot`, `RequestPath`, `SharedTypes`, `Unclassified`) and scans for forbidden tokens:

- `CONSTRUCTION_TOKENS` — constructors of concrete infrastructure types
- `TYPE_IMPORT_TOKENS` — direct imports of `UnifiedServerWorkerState`, `MeshTransport`, `BlockStore`, etc.
- `CONTROL_PLANE_OP_TOKENS` — blocklist/threat-intel mutation operations

Request-path files (`src/waf/`, `src/proxy/`, `crates/synvoid-http/`, `crates/synvoid-waf/`, `crates/synvoid-proxy/`, `crates/synvoid-http3/`) may only import narrow traits and config snapshots. Composition roots (`src/worker/unified_server/`, `src/server/mod.rs`) own concrete infrastructure.

## Guard Tests

| Test | What It Enforces |
|------|------------------|
| `tests/data_plane_composition_boundary_guard.rs` | Request-path modules don't import concrete infrastructure types; files classified by role, exceptions audited |
| `tests/mesh_id_boundary_guard.rs` | Mesh-ID enforcement never called from WAF/request/proxy/HTTP/3 code |
| `tests/threat_intel_boundary_guard.rs` | Enforcement consumers use strict lookup wrappers, not raw lookups |
| `tests/http3_waf_boundary_guard.rs` | HTTP/3 WAF code doesn't leak concrete types into the request path |
| `tests/http_request_pipeline_boundary_guard.rs` | HTTP request dispatch doesn't import worker lifecycle; architecture doc documents `Http3DispatchDeps` and `Http3RequestMetadata`; no stale "no deps struct" wording; dispatch signature uses context structs |

Run all boundary guards:

```bash
cargo test --test data_plane_composition_boundary_guard
cargo test --test mesh_id_boundary_guard
cargo test --test threat_intel_boundary_guard
cargo test --test http3_waf_boundary_guard
cargo test --test http_request_pipeline_boundary_guard
```
