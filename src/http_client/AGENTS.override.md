# AGENTS.override.md - HTTP Client Module

## Module Overview

The HTTP client module (`src/http_client/`) provides upstream proxy connections with TLS support, connection pooling, and streaming body handling.

## Key Files

- `src/http_client/mod.rs` - Main client implementation with `HttpClient`, `StreamingWafBody`, and helper functions
- `src/http_client/erased_pool.rs` - Type-erased body traits for connection pooling (Phase 1 complete)

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

### 3. Type-Erased Body (Phase 1)
```rust
pub trait ErasedBody: Send + Sync + 'static { ... }
pub struct ErasedBodyImpl<B> { inner: B }
pub type BoxErasedBody = Box<dyn ErasedBody>;
```

## True Streaming via Type-Erased Connection Pool

**Status**: Phase 1 complete. Phases 2-5 deferred due to hyper type complexity.

**Problem**: `hyper::Client<C, B>` is parametric over body type `B`. You cannot pass `StreamingWafBody<...>` to a client typed for `Full<Bytes>`.

**Solution**: Type-erased connection pool that boxes at connection checkout (10K-100K/sec) not per-request (1M/sec).

**Files to modify when resuming**:
- `src/http_client/erased_pool.rs` - Complete Phases 2-5 (HTTP/1 adapter, connection pool)
- `src/http_client/mod.rs` - Add ErasedHttpClient

## Verification Commands

```bash
cargo test --lib erased_pool  # Test type-erased body
cargo check --lib             # Verify compilation
```

## Dependencies

- `hyper_util::client::legacy::Client` - HTTP/1.1 and HTTP/2 client
- `hyper_rustls::HttpsConnector` - TLS support
- `moka::sync::Cache` - Connection pooling cache