# AGENTS.override.md - HTTP Client Module

## Module Overview

The HTTP client module (`src/http_client/`) provides upstream proxy connections with TLS support, connection pooling, and streaming body handling.

## Key Files

- `crates/synvoid-http-client/src/lib.rs` — thin facade reexports only
- `crates/synvoid-http-client/src/client.rs`, `tls.rs` (TLS config, UpstreamTlsConfig, upstream_tls_from_site_config, build_tls_config, webpki/native/custom CA, HostnameSkippingVerifier), `pool.rs` (caching, UpstreamClientKey, create_upstream_*), `unix.rs`, `request.rs`, `response.rs`, `erased_pool.rs`, `streaming_waf_body.rs`
- Root: `mod.rs` (shim), `quic_tunnel_dispatch.rs` (root-only, tunnel dep), `streaming_waf_body.rs` (shim)

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

### ErasedHttpClient Integration (Phase 9) ✅ COMPLETED

**Status**: ✅ COMPLETED (2026-05-26)

ErasedHttpClient is now integrated into `http/server.rs`:
- `use_erased_client` at `server.rs:3305` now uses conditional logic based on `body_buffering_policy.should_stream()`
- Uses `target.site_config.proxy.body_buffering_policy.map(|p| p.should_stream(...)).unwrap_or(false)`
- This allows the system to choose between ErasedHttpClient (for streaming) and regular client based on site configuration

### HTTP/2 Configuration (WRK-BUG-1 - FIXED 2026-05-27)

HTTP/2 for upstream connections is now configurable via the `is_http2` parameter in `send_request_erased_streaming()`:

```rust
pub async fn send_request_erased_streaming(
    client: &ErasedHttpClient,
    method: Method,
    url: &str,
    body: BoxErasedBody,
    headers: http::HeaderMap,
    timeout: Option<Duration>,
    is_http2: bool,  // NEW: now configurable
) -> Result<Response<Incoming>>
```

The underlying `ErasedHttpClient::send_request()` already supported `is_http2: bool` via `PoolKey`. The fix simply threads this parameter through to the call site.

## Verification Commands

```bash
cargo test --lib erased_pool  # Test type-erased body
cargo check --lib             # Verify compilation
```

## Iteration 6 Hygiene Split

lib.rs reduced to facade; TLS moved to tls.rs; pooling to pool.rs. Public API unchanged via reexports. Core Module references now point to the crate public API surface (provided via crate lib.rs re-exports); root mod.rs is the shim. Ownership details live in src/http_client/AGENTS.override.md and architecture/http_shared.md.

## Dependencies

- `hyper_util::client::legacy::Client` - HTTP/1.1 and HTTP/2 client
- `hyper_rustls::HttpsConnector` - TLS support
- `moka::sync::Cache` - Connection pooling cache
