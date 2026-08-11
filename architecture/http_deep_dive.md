# HTTP Server Deep Dive

SynVoid's HTTP server crate (`synvoid-http`) implements the 7-stage request pipeline for HTTP/1.1 and HTTP/2, handling all request processing from connection acceptance to backend dispatch.

## 7-Stage Pipeline

### Stage 1: Metadata Normalization (`request_frontdoor.rs`)

```rust
pub fn prepare_request_frontdoor(
    req: Request<Incoming>,
    conn: ConnectionContext,
) -> FrontdoorRequest {
    // 1. Sanitize client IP via trusted proxy resolution
    // 2. Extract path, method, host, user-agent
    // 3. Dispatch internal endpoints (/__internal__/health, ready, drain)
    // 4. Handle mesh special paths (key exchange, ACME challenges)
}
```

### Stage 2: Route Resolution (`request_preparation.rs`)

```rust
pub async fn prepare_request_preflight(
    frontdoor: FrontdoorRequest,
    router: &Router,
    waf: &WafCore,
) -> Result<RequestPreflight> {
    // 1. Validate WebSocket upgrade
    // 2. Extract metadata
    // 3. Early WAF decision (trust cookie bypass)
    // 4. Resolve route via Router::route_with_local_addr()
    // 5. Return RouteTarget
}
```

### Stage 3: Body Policy (`body_policy.rs`)

```rust
pub async fn collect_and_scan_request_body(
    body: Incoming,
    waf: &RequestBodyWaf,
) -> Result<PreparedRequest> {
    // For bodies > 256KB: streaming chunk WAF scanning
    // For bodies > 1MB: chunked post-collection scanning (64KB steps)
    // Constants: MAX_WAF_BODY_SIZE = 1MB, CHUNK_WAF_SCAN_SIZE = 64KB
}
```

### Stage 4: WAF Evaluation (`waf_decision.rs`)

```rust
pub async fn resolve_full_request_waf_decision(
    prepared: PreparedRequest,
    waf: &WafCore,
) -> WafDecision {
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

12 backend types tried in order:

1. WebSocket upgrade
2. Axum dynamic
3. Static files
4. AppServer (mesh)
5. Serverless (mesh)
6. Spin
7. FastCGI/PHP
8. CGI
9. AppServer (general)
10. Mesh backend (mesh)
11. WASM filter
12. Upload validation
13. Upstream proxy (fallback)

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
// Detection
pub fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    headers.get("upgrade") == Some("websocket")
        && headers.get("connection").map(|v| v.to_str().unwrap().contains("upgrade")) == Some(true)
}

// Bidirectional proxy
async fn handle_websocket_tunnel(
    client: WebSocket,
    upstream: WebSocket,
    waf: &WafCore,
) {
    // WAF on every message in both directions
    // Supports Block, LogOnly, Allow actions
}
```

## Compression & Response Transform

```rust
pub fn apply_compression(
    body: Bytes,
    accept_encoding: &str,
    config: &CompressionSettings,
) -> Bytes {
    // Prefer Brotli, fallback to Gzip
    // Configurable levels via CompressionSettings
}

pub fn apply_minification(
    body: Bytes,
    content_type: &str,
    minifier: &MinifierGenerator,
) -> Bytes {
    // HTML, CSS, JS minification
}
```

## Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `HttpRuntimeContext` | `src/http/runtime.rs` | Bundled runtime deps |
| `FrontdoorRequest` | `src/http/request_frontdoor.rs` | Normalized request |
| `RequestPreflight` | `src/http/request_preparation.rs` | Route-resolved request |
| `PreparedRequest` | `src/http/request_preparation.rs` | Body-collected request |
| `BackendDispatchContext` | `src/http/backend_dispatch.rs` | Dispatch context |
| `EarlyHttpRequest` | `src/http/early_parse.rs` | Zero-copy early parse |
| `WafStreamedBody` | `src/http/shared_handler.rs` | Streaming WAF body wrapper |
