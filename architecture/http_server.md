# HTTP Server Module Architecture

## 1. Purpose and Responsibility

The HTTP Server module (`src/http/`) is the core request handling component of SynVoid. It provides:

- **HTTP/1.1 + HTTP/2 server** using Hyper with protocol validation
- **Request routing** to backends (Static, Upstream, Serverless, FastCGI, PHP, CGI, AppServer, Mesh, AxumDynamic plugins)
- **WAF integration** with early and full request/body scanning
- **WebSocket proxy** with bidirectional tunnel and WAF inspection
- **Response transformation** including compression, minification, and image rights marking
- **Security headers injection** (HSTS, CSP, CORS, etc.)
- **Connection and bandwidth limiting**
- **Static file serving** with caching headers and range support
- **Internal endpoints** for health, drain, and readiness checks

---

## 2. Submodules and Responsibilities

Root `src/http/` is application composition (Phase 20, `keep_app_root`).
Reusable parsing/normalization/dispatch lives canonically in `synvoid-http`;
the full 42-module matrix is `architecture/http_ownership_convergence.md`.
Summary by class:

| Class | Modules |
|-------|---------|
| **Thin facades** (pure re-exports over `synvoid-http`) | `app_server_backend_dispatch`, `early_parse`, `headers`, `internal_endpoint_dispatch`, `internal_handlers`, `mesh_backend_dispatch`, `request_parse`, `response_builder`, `response_helpers`, `response_transform`, `serverless_backend_dispatch`, `shared_handler`, `special_request_paths`, `spin_backend_dispatch`, `static_backend_dispatch`, `streaming_waf_decision`, `upload_validation_dispatch`, `upstream_buffered_dispatch`, `upstream_proxy_dispatch`, `upstream_proxy_dispatch_plan`, `upstream_response_transform`, `upstream_streaming_dispatch`, `validation_helpers`, `waf_decision` |
| **Root adapters** (narrow root services to crate traits) | `axum_dynamic_dispatch`, `body_policy`, `buffered_request_waf_dispatch`, `cgi_backend_dispatch`, `challenge_paths`, `fastcgi_php_backend_dispatch`, `streaming_request_fast_path`, `streaming_waf_upstream_dispatch`, `wasm_filter_dispatch`, `websocket_dispatch`, `websocket_upgrade_dispatch` |
| **Application handlers** (root-owned) | `directory_viewer`, `file_manager`, `file_manager_ui`, `webdav` |
| **Composition root** (root-owned) | `server` (+ `server/`: `accept_loop`, `connection_types`, `observability`) — listener/socket lifecycle, `HttpServerRuntime` service bundle, request task ownership/drain |
| **Other** | `image_rights` (facade over `synvoid-static-files`), `image_poisoning` (deprecated alias, do not use) |

Canonical normalization/policy modules in `synvoid-http`:

| Module | File | Responsibility |
|--------|------|----------------|
| **framing** | `framing.rs` | Fail-closed transfer-framing + authority policy; listener sniff helpers |
| **early_parse** | `early_parse.rs` | Early HTTP request parsing for fast-path routing |
| **headers** | `headers.rs` | Security/CORS header injection, WebSocket key computation, stealth timestamps |
| **request_parse** | `request_parse.rs` | Single metadata extraction, trust-token bypass, internal-endpoint classification |
| **request_frontdoor** | `request_frontdoor.rs` | Trusted-proxy sanitization, internal endpoints, mesh special paths |
| **request_preparation** | `request_preparation.rs` | Preflight (framing validation, routing) + body collection orchestration |
| **body_policy** | `body_policy.rs` | Body collection + chunk WAF scan + size policy |
| **waf_decision** | `waf_decision.rs` | Single WAF-decision→response mapping |
| **response_builder** | `response_builder.rs` | HTTP response construction with alt-svc, cookies, JSON helpers |
| **response_helpers** | `response_helpers.rs` | Security header application, WebSocket handshake responses |
| **response_transform** | `response_transform.rs` | Compression, minification, image rights marking |
| **validation_helpers** | `validation_helpers.rs` | WebSocket upgrade validation |

---

## 3. Key Data Structures and Types

### HttpServer

Root-owned application composition (Phase 20). Long-lived services are
grouped in `HttpServerRuntime` (router, `WafCore`, flood protector, clients,
configs, drain state, metrics, IPC, connection limit, upstream registry,
per-tenant `HttpAppBackends`, mesh handles); `HttpServer` itself holds the
bind address, shutdown channel, and the runtime bundle. Request stages are
delegated to `synvoid-http` (`prepare_http_request_flow`,
`handle_http_request_postlude`); root adapters narrow `WafCore` /
`PluginManager` / supervisor handles to crate traits at the call site.
Full ownership rationale: `architecture/http_ownership_convergence.md` §3.
```rust
pub struct HttpServer {
    addr: SocketAddr,
    shutdown_rx: broadcast::Receiver<()>,
    runtime: HttpServerRuntime,
}
```

### HttpConnection
```rust
struct HttpConnection {
    io: Mutex<Option<TokioIo<ProtocolValidatingStream<tokio::net::TcpStream>>>>,
    drop_requested: RunningFlag,
}
```
Manages the TCP connection lifecycle with protocol validation.

### ConnectionTokenGuard
```rust
struct ConnectionTokenGuard {
    limiter: Arc<ConnectionLimiter>,
    token: Arc<Mutex<Option<ConnectionToken>>>,
}
```
RAII guard for connection limiting with token release-and-acquire for per-site limits.

### RequestMetrics
```rust
struct RequestMetrics {
    site_id: String,
    metrics: Arc<WorkerMetrics>,
}
```
Records per-site request metrics: start, blocked, challenged, proxied, upstream success/failure.

### BodyCollectionProtocol
```rust
pub enum BodyCollectionProtocol {
    Http,
    Https,
}
```
Differentiates metrics counters for HTTP vs HTTPS streaming body events.

### WafStreamedBody<B>
```rust
pub struct WafStreamedBody<B> {
    inner: B,
    streaming_waf: Option<StreamingWafCore>,
    client_ip: IpAddr,
    protocol: BodyCollectionProtocol,
    max_body_size: usize,
    accumulated_len: usize,
}
```
Wrapper `Body` implementation that scans chunks with the streaming WAF.

### RequestContext Trait
```rust
pub trait RequestContext: Send + Sync {
    type Response;
    fn protocol_name(&self) -> &'static str;
    fn build_response(&self, status: u16, body: String, content_type: &str) -> Self::Response;
    fn build_response_with_headers(...);
}
```
Protocol abstraction with `HttpRequestContext` and `HttpsRequestContext` implementations.

---

## 4. Key APIs and Entry Points

### HttpServer::new()
```rust
pub fn new(
    addr: SocketAddr,
    router: Router,
    waf: Arc<WafCore>,
    http_config: HttpConfig,
    shutdown_rx: broadcast::Receiver<()>,
    main_config: MainConfig,
) -> Self
```
Creates a new HTTP server with required components.

### Builder Pattern Methods
```rust
impl HttpServer {
    pub fn with_serverless_manager(self, manager: Arc<ServerlessManager>) -> Self;
    pub fn with_metrics(self, metrics: Arc<WorkerMetrics>) -> Self;
    pub fn with_ipc(self, ipc: Arc<Mutex<IpcStream>>, worker_id: WorkerId) -> Self;
    pub fn with_flood_protector(self, flood_protector: Arc<FloodProtector>) -> Self;
    pub fn with_alt_svc(self, alt_svc: String) -> Self;
    pub fn with_drain_state(self, drain_state: Arc<WorkerDrainState>) -> Self;
    pub fn with_mesh_config(self, mesh_config: Option<Arc<MeshConfig>>) -> Self;
    pub fn with_mesh_transport(self, transport: Option<Arc<MeshTransportManager>>) -> Self;
    pub fn with_app_servers(self, app_servers: Option<Arc<RwLock<HashMap<String, Arc<GranianSupervisor>>>>>) -> Self;
    pub fn with_mesh_backend_pool(self, pool: Option<Arc<MeshBackendPool>>) -> Self;
}
```
Builder pattern for optional components.

### HttpServer::serve()
```rust
#[cfg(feature = "mesh")]
pub async fn serve(mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
```
Main server loop. Only available with `mesh` feature enabled.

### Core Request Handler
```rust
async fn handle_request(
    req: hyper::Request<hyper::body::Incoming>,
    client_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
    router: Arc<Router>,
    waf: Arc<WafCore>,
    // ... 20+ other parameters
) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error>
```
The central request processing function (~4700 lines of processing logic).

---

## 5. Request Handling Flow

### Phase 1: Connection Management
1. Acquire connection limit semaphore
2. Return 503 if semaphore closed

### Phase 2: Listener Protocol Sniffing
`framing::{is_tls_client_hello, is_valid_http_request_start}` (canonical in
`synvoid-http`) reject cross-protocol bytes when `strict_protocol_validation`
is enabled.

### Phase 3: Frontdoor (`prepare_request_frontdoor`)
1. Extract `client_addr` IP; `RequestSanitizer` trusted-proxy handling
2. Internal endpoints (`/__internal__/drain`, `/drain-status`, `/health`, `/ready`)
3. Mesh special paths (key exchange, HTTP-01 challenge)

### Phase 4: Traffic Control
Global connection limiter, per-site limits, bandwidth limit.

### Phase 5: Request Preflight (`prepare_request_preflight`)
1. `extract_request_metadata` — the single method/path/host/UA/cookie
   extraction shared by routing and WAF
2. `framing::validate_request_framing` — ambiguous framing/authority fails
   closed with `400` before routing and WAF
3. Trust-token (`sv_trust` cookie) bypass check
4. `router.route_with_local_addr`

### Phase 6: Streaming Fast Path
For streamable upstream routes: header-only WAF verdict, then streaming
upstream dispatch without full body collection.

### Phase 7: Body Collection (`finalize_request_preparation`)
Framing re-validated via the same canonical helpers, then
`collect_and_scan_request_body` (chunk-WAF scan above 256KB, full scan
above 1MB, `max_streaming_body_size` bound).

### Phase 8: Honeypot & Challenge Assets
```
HONEYPOT_PREFIX/*         -> Deny with 408 (no timed block writes; Phase 19)
/_waf_css_challenge/*     -> CSS challenge page
/_waf_assets/rnd-<name>.png -> CSS asset verification
```

### Phase 9: Full WAF Check + Decision Mapping
`waf.check_request_full()` (unless trust-token/serverless-Off bypass), then
the single canonical mapping in `waf_decision::resolve_full_request_waf_decision`:
```
Drop -> 404 with connection drop
Stall -> sleep to timeout then 408 (concurrency-capped)
Block -> error page with status
Challenge -> 200 with HTML
ChallengeWithCookie -> 200 with Set-Cookie
Tarpit -> streaming tarpit response
Pass -> continue to backend dispatch
```

### Phase 10: Backend Dispatch (`handle_pass_backend_dispatch`)
WebSocket upgrade, AxumDynamic, Static, Serverless, Spin, FastCGI/PHP, CGI,
AppServer, Mesh, WASM filters, upload validation, upstream proxy with
response transforms (minification, compression, image rights marking) and
security headers.

### Phase 11: Request Logging
Log via IPC if verbose logging enabled with rate limiting.

---

## 6. Static File Serving

### Static Response Body Types
```rust
pub enum StaticResponseBody {
    InMemory(Vec<u8>),    // Small files fully loaded
    Buffered(PathBuf),    // Larger files streamed via spawn_blocking
}
```

### Static Handler Flow
1. Check `If-None-Match` / `If-Modified-Since` for 304 responses
2. Parse `Range` header for partial content
3. Serve via `static_handler.serve()`:
   - In-memory: `Full::new(body).boxed()`
   - Buffered: `spawn_blocking` read then `Full::new(body_bytes).boxed()`
4. Apply compression based on `Accept-Encoding`

### Image Rights Marking
```rust
IMAGE_PROTECTION_REGEX = r"\.(?:jpe?g|png|gif|webp|bmp|svg|ico)(?:\?|$)"
```
Applied to images > minimum size, not whitelisted, with caching by site+hash.
This is steganographic rights marking (metadata / watermark signaling), not
adversarial image perturbation.

---

## 7. Feature Gates

| Feature | Purpose |
|---------|---------|
| `mesh` | Required for `HttpServer::serve()`, mesh backends, mesh config, mesh transport |
| `mesh` + `dns` | HTTP-01 ACME challenge serving via `mesh_transport.get_http01_challenge()` |

### Non-Feature-Gated Functionality
- HTTP/1.1 + HTTP/2 server
- WAF early/full checks with body scanning
- WebSocket proxying
- Static file serving
- Response compression/minification
- Security headers injection
- FastCGI, PHP, CGI backends
- AppServer (Granian) backend
- Serverless backend (requires `serverless_manager`)
- Upload validation with YARA
- Trust token fast path

---

## 8. Important Implementation Details

### Protocol Validating Stream
```rust
struct ProtocolValidatingStream<S> {
    stream: S,
    initial_bytes: Option<Vec<u8>>,
}
```
Wraps a stream with initial bytes buffer for protocol validation on first read.

### TLS Detection
Canonical in `synvoid_http::framing::is_tls_client_hello` (Phase 20; both
`src/http/server/` and `src/tls/server.rs` share the one implementation):
```rust
pub fn is_tls_client_hello(bytes: &[u8]) -> bool {
    bytes.len() >= 3 && bytes[0] == 0x16 && bytes[1] == 0x03 && (bytes[2] <= 0x03)
}
```
Rejects TLS on HTTP port when `strict_protocol_validation` is enabled.

### Image Rights Cache
```rust
const IMAGE_RIGHTS_CACHE_MAX_CAPACITY: u64 = 1000;
const IMAGE_RIGHTS_CACHE_TTL_SECS: u64 = 3600;
```
L1 cache with site-prefix invalidation via `invalidate_image_rights_cache_for_site()`.

### Request Log Rate Limiting
```rust
static REQUEST_LOG_RATE_LIMITER: AtomicU32 = AtomicU32::new(0);
static REQUEST_LOG_RATE_LIMITER_RESET: AtomicU64 = AtomicU64::new(0);
```
Per-second rate limiting with atomic compare-exchange for reset synchronization.

### Stealth Timestamp
```rust
pub fn generate_stealth_timestamp(jitter_seconds: u32) -> String {
    // Adds random jitter to Date header to prevent server fingerprinting
}
```
Uses random offset in range `[-jitter_seconds, +jitter_seconds]`.

### WebSocket Accept Key
```rust
pub fn compute_websocket_accept_key(key: &str) -> String {
    // RFC 6455 Section 4.2.2
    const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    // SHA1(sec-websocket-key + GUID) -> base64
}
```

### Bandwidth Tracking
Records ingress/egress via `WorkerMetrics::bandwidth`:
```rust
m.bandwidth.record_egress(body_len, BandwidthProtocol::Http, EgressDirection::Proxied);
m.bandwidth.record_site_egress(&site_id, body_len);
```

---

## 9. Internal Endpoints

| Path | Handler | Access |
|------|---------|--------|
| `GET /__internal__/drain` | `handle_drain_request()` | Localhost only |
| `GET /__internal__/drain-status` | `handle_drain_status_request()` | Localhost only |
| `GET /__internal__/health` | `handle_health_request()` | Any |
| `GET /__internal__/ready` | `handle_ready_request()` | Any |

---

## 10. Response Builder Functions

| Function | Purpose |
|----------|---------|
| `reason_phrase(status: u16) -> &'static str` | HTTP status text |
| `error_body(status: u16) -> &'static [u8]` | Error body bytes |
| `error_response_bytes/status/full/boxed()` | Error response variants |
| `fallback_error_bytes/full/boxed()` | Always 500 responses |
| `bad_gateway_bytes/full()` | 502 responses |
| `build_response_with_alt_svc()` | Response + Alt-Svc header + security headers |
| `build_response_with_cookie()` | Response + Set-Cookie + Alt-Svc |
| `build_json_response()` | JSON response shortcut |

---

## 11. Security Considerations

### Header Filtering
```rust
const FORBIDDEN_RESPONSE_HEADERS: &[&str] = &["server", "x-powered-by", "connection", "keep-alive"];
```
Removed from upstream responses.

### Global Security Headers
```rust
if main_config.security.global_security_headers {
    builder = builder
        .header("Cache-Control", "no-store, no-cache, must-revalidate")
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "DENY");
}
```

### CORS Validation
```rust
if origin == "*" {
    if config.allow_wildcard_cors {
        tracing::warn!("Site CORS allow_origin='*' is insecure...");
    } else {
        tracing::error!("Site CORS allow_origin='*' is rejected for security...");
    }
}
```
Wildcard origin rejected unless `allow_wildcard_cors = true`.

### ConnectionTokenGuard
Automatic release on drop with acquire semantics for per-site upgrades.

---

## 12. Relationship to Other Modules

- **Router**: Site resolution via `router.route_with_local_addr()`
- **WAF Core**: `waf.check_request_full()`, `waf.streaming()` (the former always-`Pass` `check_early` stage was removed in Phase 19; trust-token bypass via `should_skip_waf_from_trust_cookie()`)
- **HTTP Client**: `HttpClient`, `ErasedHttpClient`, upstream request sending
- **Proxy Module**: Headers filtering, forward header building, response size limits
- **Plugin Manager**: WASM filter and response transform application
- **Serverless Manager**: Function dispatch for serverless backends
- **Metrics**: Request metrics, bandwidth tracking, latency recording
- **IPC**: Request logging to supervisor via `IpcStream`
- **Mesh Transport**: Key exchange, HTTP-01 challenges, mesh proxying
