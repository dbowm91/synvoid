# AGENTS.override.md - HTTP Client Module

## Module Overview

The HTTP client module (`src/http_client/`) provides upstream proxy connections with TLS support, connection pooling, and streaming body handling.

## Key Files

- `src/http_client/mod.rs` - Main client implementation with `HttpClient`, `StreamingWafBody`, and helper functions
- `src/http_client/erased_pool.rs` - Type-erased body traits and connection pooling
- `src/http_client/typed_pool.rs` - TypedConnectionPool for per-host body-typed clients

## Important Patterns

### 1. HttpClient Creation
```rust
pub fn create_http_client() -> HttpClient
pub fn create_http_client_with_config(connect_timeout: Duration, pool_max_idle_per_host: usize, pool_idle_timeout: Duration) -> HttpClient
pub fn create_upstream_client(...) -> HttpClient  // Per-site TLS configuration
```

### 2. StreamingWafBody
Wraps any `hyper::body::Body` and performs WAF scanning on chunks as they pass through:
```rust
pub struct StreamingWafBody<B> {
    inner: B,
    streaming_waf: Option<Arc<crate::waf::attack_detection::StreamingWafCore>>,
    client_ip: IpAddr,
    blocked: bool,
    error_sent: bool,
}
```

### 3. Type-Erased Body (Phase 1) ✅ Complete
```rust
pub trait ErasedBody: Send + Sync + 'static { ... }
pub struct ErasedBodyImpl<B> { inner: B }
pub type BoxErasedBody = Box<dyn ErasedBody>;
```

## True Streaming via Type-Erased Connection Pool

**Status**: ✅ COMPLETE (2026-05-06) - All phases implemented

**Key insight**: Box at connection checkout level, not per-request. Connection checkout happens ~10K-100K times/second (amortized over many requests), vs 1M times/second for per-request boxing.

### Implemented Components

**Http1PooledConnection** (erased_pool.rs):
```rust
pub struct Http1PooledConnection {
    io: Option<TokioIo<tokio::net::TcpStream>>,
    authority: http::uri::Authority,
    sender: Option<http1_client::SendRequest<BoxErasedBody>>,
}
```
- Async constructor takes TcpStream, wraps in TokioIo, performs handshake
- `send_request()` takes ownership, returns type-erased response
- `send_request_and_take_back()` returns connection after request for pool reuse

**ErasedConnectionPool**:
```rust
pub struct ErasedConnectionPool {
    inner: Arc<Mutex<HashMap<PoolKey, VecDeque<Http1PooledConnection>>>>,
    max_idle_per_host: usize,
    connect_timeout: Duration,
}
```
- `checkout()` - creates new connection via `Http1PooledConnection::new()`
- `checkin()` - returns connection to pool for reuse
- `idle_count()` and `total_idle_count()` for monitoring

**ErasedHttpClient**:
```rust
pub struct ErasedHttpClient {
    pool: Arc<ErasedConnectionPool>,
    connector: Arc<dyn ErasedConnector>,
}
```
- Primary interface for type-erased HTTP requests
- `send_request()` with pool checkout/checkin

### Remaining Integration (Phase 9) ⚠️ INCOMPLETE

**Status**: ⚠️ NOT COMPLETED (2026-05-23)

The ErasedHttpClient was implemented but Phase 9 integration into `http/server.rs` proxy path was never completed:
- `ErasedHttpClient` IS added to `HttpServer` struct (`server.rs:357,401`)
- BUT at `server.rs:3302`: `let use_erased_client = false` (hardcoded, never activated)
- The streaming path uses `StreamingHttpClient` from `UpstreamClientRegistry.get_or_create_streaming()` instead
- `ErasedHttpClient` is cloned throughout but never actually called in request path

**To complete Phase 9**:
1. Change line 3302 from `let use_erased_client = false` to proper conditional logic
2. Use `erased_http_client.send_request()` instead of `streaming_client` in the `if use_erased_client` block at line 3329
3. Test with `BodyBufferingPolicy::Streaming` policy

## Verification Commands

```bash
cargo test --lib erased_pool  # Test type-erased body
cargo check --lib             # Verify compilation
```

## Dependencies

- `hyper_util::client::legacy::Client` - HTTP/1.1 and HTTP/2 client
- `hyper_rustls::HttpsConnector` - TLS support
- `moka::sync::Cache` - Connection pooling cache