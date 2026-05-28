# HTTP Server Module Architecture

## 1. Purpose and Responsibility

The HTTP Server module (`src/http/`) is the core request handling component of SynVoid. It provides:

- **HTTP/1.1 + HTTP/2 server** using Hyper with protocol validation
- **Request routing** to backends (Static, Upstream, Serverless, FastCGI, PHP, CGI, AppServer, Mesh, AxumDynamic plugins)
- **WAF integration** with early and full request/body scanning
- **WebSocket proxy** with bidirectional tunnel and WAF inspection
- **Response transformation** including compression, minification, and image poisoning
- **Security headers injection** (HSTS, CSP, CORS, etc.)
- **Connection and bandwidth limiting**
- **Static file serving** with caching headers and range support
- **Internal endpoints** for health, drain, and readiness checks

---

## 2. Submodules and Responsibilities

| Module | File | Responsibility |
|--------|------|----------------|
| **server** | `server.rs` (4848 lines) | Core HTTP server, request handling pipeline, connection management |
| **shared_handler** | `shared_handler.rs` | Request context traits, streamed body with WAF, body collection protocol |
| **response_builder** | `response_builder.rs` | HTTP response construction with alt-svc, cookies, JSON helpers |
| **headers** | `headers.rs` | Security/CORS header injection, WebSocket key computation, stealth timestamps |
| **early_parse** | `early_parse.rs` | Early HTTP request parsing for fast-path routing |
| **internal_handlers** | `internal_handlers.rs` | Internal endpoints: `/__internal__/drain`, `/__internal__/health`, etc. |
| **response_helpers** | `response_helpers.rs` | Security header application, response building helpers |
| **response_transform** | `response_transform.rs` | Compression, minification, image poisoning |
| **validation_helpers** | `validation_helpers.rs` | WebSocket upgrade validation |
| **directory_viewer** | `directory_viewer.rs` | Directory listing for static serving |
| **file_manager** | `file_manager.rs` | File management operations |
| **file_manager_ui** | `file_manager_ui.rs` | File manager web UI |
| **webdav** | `webdav.rs` | WebDAV protocol support |

---

## 3. Key Data Structures and Types

### HttpServer
```rust
pub struct HttpServer {
    addr: SocketAddr,
    router: Arc<Router>,
    waf: Arc<WafCore>,
    flood_protector: Option<Arc<FloodProtector>>,
    client: HttpClient,
    shutdown_rx: broadcast::Receiver<()>,
    http_config: HttpConfig,
    alt_svc: Option<String>,
    main_config: Arc<MainConfig>,
    drain_state: Option<Arc<WorkerDrainState>>,
    #[cfg(feature = "mesh")]
    mesh_config: Option<Arc<MeshConfig>>,
    #[cfg(feature = "mesh")]
    mesh_transport: Option<Arc<MeshTransportManager>>,
    metrics: Option<Arc<WorkerMetrics>>,
    ipc: Option<Arc<tokio::sync::Mutex<IpcStream>>>,
    worker_id: Option<WorkerId>,
    serverless_manager: Option<Arc<ServerlessManager>>,
    connection_limit: Arc<Semaphore>,
    app_servers: Option<Arc<RwLock<HashMap<String, Arc<GranianSupervisor>>>>>,
    #[cfg(feature = "mesh")]
    mesh_backend_pool: Option<Arc<MeshBackendPool>>,
    upstream_client_registry: Arc<UpstreamClientRegistry>,
    erased_http_client: ErasedHttpClient,
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

### Phase 1: Connection Management (lines 688-702)
1. Acquire connection limit semaphore
2. Return 503 if semaphore closed

### Phase 2: IP Extraction & Sanitization (lines 704-718)
1. Extract `client_addr` IP
2. Apply `RequestSanitizer` for X-Forwarded-For trusted proxy handling
3. Sanitize request headers

### Phase 3: Internal Endpoints (lines 726-753)
```
/__internal__/drain       -> handle_drain_request() (localhost only)
/__internal__/drain-status -> handle_drain_status_request() (localhost only)
/__internal__/health      -> handle_health_request()
/__internal__/ready       -> handle_ready_request()
```

### Phase 4: Key Exchange Requests (lines 756-777)
Mesh global node key exchange endpoints:
- `/key-request-origin` - POST for key request origin
- `/key-confirm` - POST for key confirmation
- `/health` - GET for health check

### Phase 4.5: Mesh HTTP-01 Challenge (lines 782-808)
```
/.well-known/synvoid-challenge/<token> -> Serve HTTP-01 ACME challenge
```

### Phase 5: Connection Limiting (lines 810-854)
1. Check global connection limiter
2. Per-site connection limits via `try_acquire_with_limits()`
3. ConnectionTokenGuard for automatic release

### Phase 6: Bandwidth Limiting (lines 856-870)
Check global bandwidth limit via `waf.is_over_bandwidth_limit()`.

### Phase 7: WebSocket Detection (lines 872-880)
Parse `Upgrade` and `Connection` headers to detect WebSocket upgrades.

### Phase 8: Request Parsing (lines 882-928)
Extract method, path, query string, host, user-agent, cookies.

### Phase 8.5: Trust Token Fast Path (lines 908-928)
Check for `sv_trust` cookie; if valid, skip WAF checks.

### Phase 9: WAF Early Decision (lines 930-1057)
```
WafDecision::Drop -> Return 404, request connection drop
WafDecision::ChallengeWithCookie -> Return 200 with Set-Cookie
WafDecision::Challenge -> Return 200 with HTML challenge
WafDecision::Block -> Return block status with error page
WafDecision::Pass|Stall|Tarpit -> Continue
```

### Phase 10: Routing & Site Resolution (lines 1062-1174)
```rust
let route = router.route_with_local_addr(&host, &path, local_addr);
```
Apply per-site connection limits after routing.

### Phase 9.5: Upstream Streaming Fast Path (lines 1176-1510)
For `Upstream`/`Serverless` backends with streaming policy:
1. Run WAF full check
2. Dispatch to serverless or forward to upstream with streaming body

### Phase 10: Body Collection (lines 1513-1627)
For non-streaming paths:
1. If body > 256KB: Use `collect_body_with_chunk_waf()` 
2. If body > 1MB: Run WAF full body scan in 64KB chunks

### Phase 11: Honeypot & Challenge Assets (lines 1642-1846)
```
HONEYPOT_PREFIX/*         -> Block IP, return 408
/_waf_css_challenge/*     -> Serve CSS challenge page
/_waf_assets/rnd-<name>.png -> CSS asset verification
```

### Phase 12: Full WAF Check (lines 1860-1892)
Run `waf.check_request_full()` with collected body (unless serverless with `waf_mode=Off`).

### Phase 13: WAF Decision Handling (lines 1894-2113)
```
Drop -> 404 with connection drop
Stall -> Sleep 0-keepalive_timeout then 408
Block -> Error page with status
Challenge -> 200 with HTML
ChallengeWithCookie -> 200 with Set-Cookie
Tarpit -> Streaming tarpit response
Pass -> Continue to backend dispatch
```

### Phase 14: Backend Dispatch (lines 2114-3026)
Supported backend types:
- **WebSocket**: Upgrade tunnel to upstream or AppServer
- **AxumDynamic**: Plugin router via `plugin_manager.get_axum_router()`
- **Static**: `static_handler.serve()` with compression/minification
- **Serverless**: `serverless_manager.handle_serverless_function()`
- **Spin**: `SpinHttpHandler` for WASM apps
- **FastCgi/PHP**: `fastcgi::get_pool().execute()` or PHP client
- **CGI**: `CgiHandler::execute()`
- **AppServer**: `GranianSupervisor.forward_request()`
- **Mesh**: `mesh_backend_pool.select_backend().proxy_request()`

### Phase 15: WASM Filters (lines 3028-3152)
Apply WASM request filters via `plugin_manager.apply_wasm_filters()`.

### Phase 16: Upload Validation (lines 3155-3246)
If content-type is upload, validate with YARA scanning and size limits.

### Phase 17: Upstream Proxy (lines 3247-3844)
- Prepare upstream target with URL/headers/timeouts
- Check body buffering policy for ErasedHttpClient streaming
- Forward request via `send_request_streaming_generic()` or `send_request_with_body_and_timeout()`
- Apply response transforms (minification, compression, image poisoning)
- Inject security headers

### Phase 18: Request Logging (lines 3848-3869)
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

### Image Poisoning
```rust
IMAGE_PROTECTION_REGEX = r"\.(?:jpe?g|png|gif|webp|bmp|svg|ico)(?:\?|$)"
```
Applied to images > minimum size, not whitelisted, with caching by site+hash.

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
```rust
fn is_tls_client_hello(bytes: &[u8]) -> bool {
    bytes.len() >= 3 && bytes[0] == 0x16 && bytes[1] == 0x03 && (bytes[2] <= 0x03)
}
```
Rejects TLS on HTTP port when `strict_protocol_validation` is enabled.

### Image Poison Cache
```rust
const IMAGE_POISON_CACHE_MAX_CAPACITY: u64 = 1000;
const IMAGE_POISON_CACHE_TTL_SECS: u64 = 3600;
```
L1 cache with site-prefix invalidation via `invalidate_image_poison_cache_for_site()`.

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
- **WAF Core**: `waf.check_early()`, `waf.check_request_full()`, `waf.streaming()`
- **HTTP Client**: `HttpClient`, `ErasedHttpClient`, upstream request sending
- **Proxy Module**: Headers filtering, forward header building, response size limits
- **Plugin Manager**: WASM filter and response transform application
- **Serverless Manager**: Function dispatch for serverless backends
- **Metrics**: Request metrics, bandwidth tracking, latency recording
- **IPC**: Request logging to supervisor via `IpcStream`
- **Mesh Transport**: Key exchange, HTTP-01 challenges, mesh proxying
