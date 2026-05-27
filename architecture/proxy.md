# Proxy Module Architecture

## 1. Purpose and Responsibility

The Proxy module (`src/proxy/`) is SynVoid's reverse proxy subsystem that handles proxied HTTP/HTTPS requests end-to-end:

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
| `dispatch` | `dispatch.rs` | Upstream dispatch with load balancing |
| `executor` | `executor.rs` | Upstream request building and response handling |
| `cache` | `cache.rs` | Proxy cache implementation |
| `headers` | `headers.rs` | Header filtering, XFF validation |
| `retry` | `retry.rs` | Retry logic with backoff calculation |
| `client_registry` | `client_registry.rs` | HTTP client registration |
| `governor` | `governor.rs` | Rate limiting for upstream requests |
| `streaming` | `streaming.rs` | TeeBody for caching streamed responses |

## 3. Major Data Structures

### ProxyServer
```rust
pub struct ProxyServer {
    client: HttpClient,                    // Primary upstream client
    revalidation_client: HttpClient,      // Client for cache revalidation
    erased_client: ErasedHttpClient,      // Type-erased client for dynamic dispatch
    upstream_url: String,                // Single upstream URL (fallback)
    waf: Arc<WafCore>,                    // WAF for pre-forwarding checks
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
    pool_max_idle_per_host: usize,
    pool_idle_timeout: Duration,
    is_http2: bool,                       // HTTP/2 enabled flag
}
```

### BackendType (from upstream module)
```rust
pub enum BackendType {
    Single(String),           // Single upstream URL
    Pool(Vec<Backend>),      // Load-balanced pool
    Fallback(Vec<Backend>),  // Fallback chain
    // ... other variants
}
```

### RetryConfig
```rust
pub struct RetryConfig {
    pub enabled: bool,
    pub max_retries: u32,
    pub retry_on_connection_error: bool,
    pub retry_on_timeout: bool,
    pub retry_on_status: Vec<u16>,
    pub timeout_ms: Option<u64>,
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
    pub fn with_upstream_pool(mut self, pool: Arc<UpstreamPool>, ...) -> Self
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

    if retry_enabled && should_retry && attempt < max_retries {
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
// Default pattern: "{scheme}://{host}:{port}{path}"
// Vary-by: cookies, query params, etc.
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
5. Attempt count < max_retries

### Backoff Calculation
```rust
pub fn calculate_backoff(attempt: u32, base_timeout_ms: u64) -> u64 {
    let base = base_timeout_ms.unwrap_or(100);
    let exponential = 2_u64.pow(attempt.min(5));
    let jitter = rand() % 100;
    (base * exponential).saturating_add(jitter)
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

## 9. Feature Gates

The Proxy module has no feature gates - it is always compiled. However, it integrates with:

| Feature | Integration |
|---------|-------------|
| `mesh` | Threat intelligence announcement on upstream error probing |
| `http2` | `is_http2` flag enables HTTP/2 upstream |

## 10. Key Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `MAX_WAF_BODY_SIZE` | 1MB | Body limit for WAF inspection |
| `DEFAULT_POOL_MAX_IDLE` | 100 | Max idle connections per host |
| `DEFAULT_POOL_IDLE_TIMEOUT` | 30s | Idle connection timeout |
| `DEFAULT_UPSTREAM_TIMEOUT` | 30s | Upstream request timeout |

## 11. Dependencies

- `http_client` - Upstream HTTP connections
- `upstream` - Backend pool and health checking
- `waf` - Attack detection before forwarding
- `proxy_cache` - Response caching
- `metrics` - Prometheus metrics

## 12. Related Documentation

- [`upstream.md`](./upstream.md) - Upstream pool and health checking (upstream.rs)
- [`http_shared.md`](./http_shared.md) - HTTP client implementation
- [`waf.md`](./waf.md) - Web Application Firewall
