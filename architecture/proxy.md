# Proxy Module Architecture

## 1. Purpose and Responsibility

> **Location note (2026-06 crate split)**: the proxy implementation lives in
> `crates/synvoid-proxy/src/` (with caching in `crates/synvoid-proxy-cache/`). The
> `src/proxy/*.rs` root paths are thin re-export shims kept for backward compatibility —
> do not add implementation code there.

The proxy subsystem is SynVoid's reverse proxy that handles proxied HTTP/HTTPS requests end-to-end:

| Responsibility | Description |
|----------------|-------------|
| **Upstream Selection** | Load balancing across multiple upstream servers |
| **Header Filtering** | Stripping hop-by-hop and information-leaking headers |
| **Proxy Caching** | Response caching with stale-while-revalidate support |
| **Retry with Backoff** | Automatic retry on upstream failures |
| **Request Buffering** | Body collection and buffering for WAF inspection |
| **Metrics Collection** | Request counts, latency histograms, cache hit/miss |

## 2. Key Submodules

| Module | File | Responsibility |
|--------|------|----------------|
| `dispatch` | `crates/synvoid-proxy/src/dispatch.rs` | Upstream dispatch with load balancing |
| `executor` | `crates/synvoid-proxy/src/executor.rs` | Upstream request building and response handling |
| `cache` | `crates/synvoid-proxy/src/cache.rs` | Proxy cache implementation |
| `headers` | `crates/synvoid-proxy/src/headers.rs` | Header filtering, XFF validation |
| `retry` | `crates/synvoid-proxy/src/retry.rs` | Retry logic with backoff calculation |
| `client_registry` | `crates/synvoid-proxy/src/client_registry.rs` | HTTP client registration |
| `governor` | `crates/synvoid-proxy/src/governor.rs` | Rate limiting for upstream requests |
| `streaming` | `crates/synvoid-proxy/src/streaming.rs` | TeeBody for caching streamed responses |
| `server` | `crates/synvoid-proxy/src/server.rs` | `ProxyServer`, `ProxyResponse`, `QuicTunnelSender`, WAF/caching dispatch |
| `router` | `crates/synvoid-proxy/src/router.rs` | `Router`, `RouteTarget`, `RouteResult`, `BackendType` |
| `routing` / `router_adapter` | `crates/synvoid-proxy/src/{routing,router_adapter}.rs` | Route helpers; `RouterRouteResolver` adapter |
| `location_matcher` | `crates/synvoid-proxy/src/location_matcher.rs` | nginx-style location matching |
| `bidirectional` | `crates/synvoid-proxy/src/bidirectional.rs` | Bidirectional streaming copy with optional WAF scan |
| `protocol/` | `crates/synvoid-proxy/src/protocol/` | Pluggable framed-protocol handlers + `WafAction` adapter |

## 3. Major Data Structures

### ProxyServer
```rust
pub struct ProxyServer<W: WafProcessor> {   // Generic over the WAF bound (composition roots pass WafCore)
    lane_client: Option<EggfetchUpstreamClient>,         // Primary egress lane (Phase 60)
    revalidation_lane: Option<EggfetchUpstreamClient>,   // Separate lane for cache revalidation
    lane_init_error: Option<String>,     // Terminal lane-build failure; fails every request pre-I/O
    upstream_url: String,                // Single upstream URL (fallback)
    waf: Arc<W>,                          // WAF for pre-forwarding checks
    max_response_size: usize,             // Max response size limit
    upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
    site_id: String,
    upstream_pool: Option<Arc<UpstreamPool>>,  // Load-balanced pool
    retry_config: Option<RetryConfig>,
    buffering_config: Option<BufferingConfig>,
    cache: Option<Arc<ProxyCache>>,       // Proxy cache
    cache_key_builder: Option<CacheKeyBuilder>,
    skip_verify: bool,
    cache_purge_token: Option<String>,
    cache_purge_allowed_ips: Arc<HashSet<IpAddr>>,
    pool_max_idle_per_host: usize,        // #[allow(dead_code)] — retained for API compat
    pool_idle_timeout: Duration,          // #[allow(dead_code)] — retained for API compat
    is_http2: bool,                       // Ignored: the eggfetch lane negotiates via ALPN
    proxy_headers_config: Option<Arc<ProxyHeadersConfig>>,  // Custom header overrides
    connection_limiter: Option<Arc<ConnectionLimiter>>,
    threat_level_provider: Option<Arc<dyn ThreatLevelProvider>>,
    tarpit_service: Option<Arc<dyn TarpitService>>,
    block_store: Option<Arc<dyn BlockListStore>>,
    quic_tunnel_sender: Option<Arc<QuicTunnelSender>>,
}
```

### BackendType (from `crates/synvoid-proxy/src/router.rs:66-78`)
```rust
pub enum BackendType {
    Upstream,       // Standard reverse proxy to HTTP/HTTPS upstream
    FastCgi,        // FastCGI process (e.g., PHP-FPM)
    Php,            // PHP via php-cgi executable
    Cgi,            // Generic CGI execution
    AxumDynamic,    // Dynamic axum-based handler for plugin routing
    AppServer,      // Generic application server backend
    Static,         // Internal StaticFileHandler
    QuicTunnel,     // Proxy through QUIC tunnel
    Serverless,     // WASM serverless function execution
    Mesh,           // Routing through WAF Mesh to remote peer
    Spin,           // Fermyon Spin framework WASM execution
}
```

### RetryConfig (from `crates/synvoid-config/src/site/proxy.rs:221`)
```rust
pub struct RetryConfig {
    pub enabled: bool,                    // Default: false
    pub max_retries: u32,                 // Default: 3
    pub timeout_ms: Option<u64>,          // Base backoff timeout (None = no delay)
    pub retry_on_error: bool,             // Default: true (retry on connection errors)
    pub retry_on_timeout: bool,           // Default: true (retry on timeout errors)
    pub retry_on_status: Vec<u16>,        // Default: [502, 503, 504]
    pub retry_non_idempotent: bool,       // Default: false (retry POST/PUT/PATCH)
}
```

## 4. Key APIs and Entry Points

### ProxyServer Construction

```rust
// Basic construction
impl ProxyServer {
    pub fn new(upstream_url: String, waf: Arc<WafCore>, ...) -> Self
    pub fn new_with_tls(...) -> Self
    pub fn new_with_pool_config(...) -> Self
}

// Builder pattern
impl ProxyServer {
    pub fn with_upstream_pool(
        mut self,
        pool: Arc<UpstreamPool>,
        retry_config: Option<RetryConfig>,
        buffering_config: Option<BufferingConfig>,
    ) -> Self
    pub fn with_cache(mut self, cache: Arc<ProxyCache>) -> Self
    pub fn with_http2(mut self, is_http2: bool) -> Self
    pub fn from_config(...) -> Self  // Full configuration from SiteConfig
}

// Request handling
impl ProxyServer {
    pub async fn handle_request(...) -> Result<ProxyResponse, String>
    pub async fn handle_request_with_cache(...) -> Result<ProxyResponse, String>
    pub async fn forward_request_via_tunnel(...) -> Result<ProxyResponse, ...>
}

// Cache management
impl ProxyServer {
    pub fn invalidate_cache(&self, path: &str) -> usize
    pub fn invalidate_cache_by_host(&self, host: &str) -> usize
}
```

### Public Functions

```rust
// From dispatch.rs
pub fn dispatch_to_upstream(...) -> Result<UpstreamResponse, UpstreamDispatchError>

// From headers.rs
pub fn build_forward_headers(...) -> HeaderMap
pub fn filter_response_headers(...) -> Response<Bytes>
pub fn sanitize_request_path(path: &str) -> String
pub fn validate_and_truncate_xff(xff: &str) -> String

// From retry.rs
pub fn calculate_backoff(attempt: u32, base_timeout_ms: u64) -> u64
pub fn should_retry_request(method: &Method, config: &RetryConfig) -> bool
pub fn is_retryable_status(status: u16, config: &RetryConfig) -> bool
```

## 5. Request Dispatch Flow

```
handle_request()
    ↓
[Connection Limiter] ── reject if exceeded
    ↓
[WAF Full Check] ── Drop/Stall/Block/Challenge/Pass
    ↓
forward_request()
    ├── Single upstream: send_single_request()
    └── With pool: forward_with_pool()
                    ├── select_backend() ── LoadBalanceAlgorithm
                    ├── send_single_request()
                    ├── On failure: mark_failed() + retry
                    └── Loop until success or exhausted
```

### forward_with_pool Loop

```rust
loop {
    let backend = pool.select_next_backend(current_backend)...
    backend.increment_connections()
    let result = send_single_request(...)
    backend.record_latency(elapsed)
    backend.decrement_connections()

    if retry_enabled && should_retry && attempt <= max_retries {
        pool.mark_failed(&backend.url)
        sleep(calculate_backoff(attempt, timeout))
        continue
    }
    return result
}
```

## 6. Caching Strategy

### Cache Key Building
```rust
CacheKeyBuilder::new(key_pattern, vary_by)
// Default pattern (crates/synvoid-proxy-cache/src/config.rs:49):
//   "$scheme$request_method$host$site_id$request_uri"
// Placeholders: $scheme, $request_method, $host, $request_uri, $site_id
// Vary-by: selected request headers (for example, Accept-Encoding)
```

### Cache Hit Flow
```
handle_request_with_cache()
    ├── Check method is cacheable (GET by default)
    ├── Build cache key
    ├── Check cache.get()
    │   ├── HIT → build_cached_response()
    │   │         └── If stale-while-revalidate: spawn background revalidation
    │   └── MISS → forward_request()
    │               └── If response is cacheable: TeeBody wraps and stores
```

Shared-cache requests carrying `Authorization`, `Proxy-Authorization`, or
`Cookie` bypass lookup. Responses with `Set-Cookie`, private/no-store cache
directives, or unsupported `Vary` fields are not stored.

### Stale-While-Revalidate
```rust
if is_swr {
    if try_acquire_revalidation(key) {
        tokio::spawn(async {
            revalidate_cache_entry(...).await
        })
    }
}
```

## 7. Retry Logic

### Conditions for Retry
1. Retry enabled in config
2. Method is idempotent (GET, HEAD, OPTIONS, TRACE)
3. Error type matches config (connection error / timeout)
4. Or status code is retryable (502, 503, 504)
5. Attempt count is within the configured retry budget (`max_retries` means
   retries after the initial attempt)

Retries are currently limited to bodyless requests because proxied request
bodies are one-shot streams. This avoids replaying an empty body to a failover
backend. Error retries also honor the configured connection-error and timeout
switches; unrelated transport errors are not retried implicitly.

### Backoff Calculation
```rust
pub fn calculate_backoff(attempt: u32, base_timeout_ms: u64) -> u64 {
    let delay = base_timeout_ms.saturating_mul(2u64.saturating_pow(attempt.min(5)));
    delay.min(30000)  // Cap at 30 seconds
}
```

## 8. WAF Integration

```rust
// Pre-forwarding WAF check
if !skip_waf_check {
    let waf_decision = waf.check_request_full(...).await;

    match waf_decision {
        WafDecision::Drop => return Err("blackholed"),
        WafDecision::Stall => { sleep(30s); pending().await }
        WafDecision::Block(status, msg) => return Block response
        WafDecision::Challenge(type, html) => return Challenge response
        WafDecision::ChallengeWithCookie {...} => return Challenge + Set-Cookie
        WafDecision::Tarpit(path) => return Tarpit stream
        WafDecision::Pass => continue
    }
}
```

Protocol handlers (`crates/synvoid-proxy/src/protocol/`) do not return
`WafDecision` directly: `ProtocolHandler::apply_waf` returns the coarse,
transport-local `WafAction`, which is an explicitly registered adapter over
the canonical enforcement classification
(`enforcement_decision_contract.md`). `WafAction::class()` /
`WafAction::from_class()` are exhaustive and tested; canonical `Drop`
degrades to `Block` at this layer (fail-closed — the framed-protocol layer
cannot silently drop), so the two enums cannot evolve independently.

## 9. Feature Gates

The Proxy module has no feature gates - it is always compiled. However, it integrates with:

| Feature | Integration |
|---------|-------------|
| `mesh` | Threat intelligence announcement on upstream error probing |

Note: `is_http2` is a struct field on `ProxyServer` (set via `with_http2()` builder method),
not a feature gate. It is, however, **inert**: `crates/synvoid-proxy/src/server.rs`
retains it only for API compatibility because the legacy transport used it as a
pool-lookup hint (never for protocol switching). The eggfetch lane negotiates
HTTP/1.1 vs HTTP/2 via ALPN, so the field (and the `proxy.http2` site value
wired through at `src/tls/server.rs`) selects nothing.

## 10. Key Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `MAX_WAF_BODY_SIZE` | 1MB | Body limit for WAF inspection |

Note: Pool configuration values (`pool_max_idle_per_host`, `pool_idle_timeout`) are passed as
constructor parameters, not named constants.

## 11. Dependencies

- `http_client` - Upstream HTTP connections
- `upstream` - Backend pool and health checking
- `waf` - Attack detection before forwarding
- `proxy_cache` - Response caching
- `metrics` - Prometheus metrics

## 12. Implementation Details

### SharedConnectionTable Layout (DOC-H19)

The mmap-based `SharedConnectionTable` in `crates/synvoid-upstream/src/shared_state.rs` uses this layout (Phase 42 v1 header; binding contract: `architecture/shared_memory_atomic_contract.md`):

```
[0..4]:                              magic u32 ("SVCT")
[4..8]:                              version u32 (1)
[8..16]:                             max_workers (u64)
[16..24]:                            max_backends (u64)
[24..32]:                            reserved (u64, zero)
[32..32 + max_workers * 8]:          heartbeats (AtomicU64) [worker_id]
[32 + max_workers * 8 ..]:           connections (AtomicUsize) [worker_id][backend_index]
```

The connections section starts at offset `32 + max_workers * 8`, NOT at `[N+1..]`.
Each worker has `max_backends` connection counters (one per backend).
All offsets derive from the checked `ConnectionTableLayout` value type;
rate-limit offsets likewise live in `RateLimitTableLayout` (no raw mmap
exposure — typed counter slices only).

### CacheKey URI Hashing (DOC-H20)

In `crates/synvoid-proxy-cache/src/key.rs:43-52`, `CacheKey::new()` produces a hash-prefixed URI:

```rust
let mut hasher = AHasher::default();
Hash::hash(&key, &mut hasher);    // key = expanded pattern string
Hash::hash(&vary, &mut hasher);   // vary = header-based vary key
let hash = Hasher::finish(&hasher);

Self {
    uri: format!("{}:{}", hash, uri_str),  // e.g. "1234567890:/api/users"
    // ...
}
```

The `uri` field contains `"<ahash_hex>:<path_and_query>"`, NOT the raw URI.
This ensures cache key uniqueness when the same path has different pattern or vary values.

### Erased Pool Status (DOC-H21, corrected)

`ProxyServer` **no longer constructs an `ErasedHttpClient`**. There is no
`ErasedHttpClient::new(100)` call in `crates/synvoid-proxy/src/server.rs`; egress
runs on the eggfetch lane (`lane_client` / `revalidation_lane`, Phase 60/62), and
the erased pool survives only as a frozen compatibility surface guarded by
`eggfetch_lane_freeze_guard`.

`ErasedHttpClient::new(max_idle_per_host: usize)`
(`crates/synvoid-http-client/src/erased_pool.rs:359`) still accepts a parameter,
but its pool stores `Http1PooledConnection` only — the erased pool is
HTTP/1.1-only. `PoolKey` retains an `is_http2` field that now only partitions
pool entries; it does not select a protocol.

## 13. Related Documentation

- [`upstream.md`](./upstream.md) - Upstream pool and health checking (upstream.rs)
- [`http_shared.md`](./http_shared.md) - HTTP client implementation
- [`waf.md`](./waf.md) - Web Application Firewall
