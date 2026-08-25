# HTTP Server Deep Dive

SynVoid's HTTP server crate (`synvoid-http`) implements the 7-stage request pipeline for HTTP/1.1 and HTTP/2, handling all request processing from connection acceptance to backend dispatch.

## 7-Stage Pipeline

### Stage 1: Metadata Normalization (`request_frontdoor.rs`)

```rust
pub async fn prepare_request_frontdoor<D: HttpDrainControl>(
    ctx: RequestFrontdoorContext<D>,
) -> Result<RequestFrontdoorOutcome, hyper::Error> {
    // 1. Sanitize client IP via trusted proxy resolution
    // 2. Extract path, method, host, user-agent
    // 3. Dispatch internal endpoints (/__internal__/health, ready, drain)
    // 4. Handle mesh special paths (key exchange, ACME challenges)
}
```

### Stage 2: Route Resolution (`request_preparation.rs`)

```rust
pub async fn prepare_request_preflight<W, LogFn, DropFn>(
    req: hyper::Request<hyper::body::Incoming>,
    client_ip: IpAddr,
    local_addr: Option<SocketAddr>,
    router: Arc<Router>,
    waf: Arc<W>,
    alt_svc: Option<String>,
    main_config: Arc<MainConfig>,
    on_log: LogFn,
    on_drop: DropFn,
) -> Result<RequestPreflightOutcome, hyper::Error> {
    // 1. Validate WebSocket upgrade
    // 2. Extract metadata
    // 3. Early WAF decision (trust cookie bypass)
    // 4. Resolve route via Router::route_with_local_addr()
    // 5. Return RouteTarget
}
```

### Stage 3: Body Policy (`body_policy.rs`)

```rust
pub async fn collect_and_scan_request_body<W>(
    body: hyper::body::Incoming,
    waf: &W,
    client_ip: IpAddr,
    content_length: Option<usize>,
    max_streaming_body_size: usize,
) -> Result<(Bytes, u64), BodyPolicyError> {
    // For bodies > 256KB: streaming chunk WAF scanning
    // For bodies > 1MB: chunked post-collection scanning (64KB steps)
    // Constants: MAX_WAF_BODY_SIZE = 1MB, CHUNK_WAF_SCAN_SIZE = 64KB
}
```

### Stage 4: WAF Evaluation (`waf_decision.rs`)

```rust
pub async fn resolve_full_request_waf_decision<...>(
    decision: WafDecision,
    client_ip: IpAddr,
    http_config: HttpConfig,
    alt_svc: Option<String>,
    main_config: Arc<MainConfig>,
    on_drop: DropFn,
    on_log: LogFn,
    on_blocked: BlockedFn,
    on_blocked_egress: BlockedEgressFn,
    on_challenged: ChallengedFn,
    elapsed_ms: ElapsedFn,
    render_block_body: BlockRenderFn,
    generate_tarpit_html: TarpitRenderFn,
) -> FullWafDecisionOutcome {
    // 1. Full request WAF check (headers, method, path, query, body, JA4)
    // 2. Map WafDecision variants:
    //    - Drop → 404
    //    - Stall → 408 (with concurrency cap via StallPermit)
    //    - Block → themed HTML error page
    //    - Challenge → HTML challenge page
    //    - Tarpit → streamed slow response
    //    - Pass → continue
}
```

### Stage 5: Terminal Response (`internal_endpoint_dispatch.rs`)

Handles health/ready/drain endpoints and mesh special paths.

### Stage 6: Backend Dispatch (`backend_dispatch.rs`)

WebSocket upgrade is checked first (a separate path in `websocket_upgrade_dispatch.rs`, not a `BackendType` variant). Then the 11 `BackendType` variants are tried in order:

1. Axum dynamic
2. Static files
3. AppServer (mesh-gated, `is_appserver` check)
4. Serverless (mesh-gated)
5. Spin
6. FastCGI/PHP
7. CGI
8. AppServer (general)
9. Mesh backend (mesh-gated)
10. WASM filter
11. Upload validation
12. Upstream proxy (fallback via `upstream_proxy_dispatch.rs`)

### Stage 7: Accounting (`http_request_postlude.rs`)

```rust
pub async fn handle_http_request_postlude(
    context: HttpRequestPostludeContext,
) {
    // 1. Run buffered WAF (if not already run)
    // 2. Backend dispatch
    // 3. Record metrics via RequestMetricsAdapter
    // 4. IPC request logging to supervisor
}
```

## HTTP/1.1 and HTTP/2

- Uses `hyper` 1.x with `http1` and `http2` features
- `EarlyHttpParser` does zero-copy header parsing via `httparse`
- Rejects obs-fold, null bytes, whitespace before header names
- `hyper-util` with `server-auto` and `server-graceful` features

## WebSocket Support

```rust
// Detection (crates/synvoid-http/src/headers.rs)
pub fn is_websocket_upgrade(headers: &http::HeaderMap) -> bool {
    // Case-insensitive check for upgrade=websocket + connection contains "upgrade"
}

// Bidirectional proxy (crates/synvoid-http/src/websocket_dispatch.rs)
pub async fn handle_websocket_tunnel(
    upgraded: hyper::upgrade::OnUpgrade,
    target: RouteTarget,
    path: String,
    waf: Arc<dyn WafCoreBackend>,
    client_ip: IpAddr,
    ws_config: SiteWebSocketConfig,
) {
    // WAF on every message in both directions
    // Supports Block, LogOnly, Allow actions
}
```

## Compression & Response Transform

```rust
pub fn apply_compression(
    body: Bytes,
    accept_encoding: Option<&str>,
    settings: &CompressionSettings,
) -> (Bytes, Option<String>) {
    // Prefer Brotli, fallback to Gzip
    // Configurable levels via CompressionSettings
}

pub fn apply_minification(
    body: Bytes,
    content_type: Option<&str>,
    settings: &MinificationSettings,
) -> Bytes {
    // HTML, CSS, JS minification
}
```

## Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `HttpRuntimeContext` | `crates/synvoid-http/src/runtime.rs` | Bundled runtime deps |
| `FrontdoorRequest` | `crates/synvoid-http/src/request_frontdoor.rs` | Normalized request |
| `RequestPreflight` | `crates/synvoid-http/src/request_preparation.rs` | Route-resolved request |
| `PreparedRequest` | `crates/synvoid-http/src/request_preparation.rs` | Body-collected request |
| `BackendDispatchContext` | `crates/synvoid-http/src/backend_dispatch.rs` | Dispatch context |
| `EarlyHttpRequest` | `crates/synvoid-http/src/early_parse.rs` | Zero-copy early parse |
| `WafStreamedBody` | `crates/synvoid-http/src/shared_handler.rs` | Streaming WAF body wrapper |
