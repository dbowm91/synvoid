# HTTP Client Deep Dive

SynVoid's HTTP client crate provides TLS-configurable HTTP/1.1 and HTTP/2 client with connection pooling, per-site TLS configs, and streaming body support.

## Architecture

### Core Types

```rust
pub type HttpClient = hyper::Client<HttpsConnector<HttpConnector>, Full<Bytes>>;
pub type StreamingHttpClient = hyper::Client<HttpsConnector<HttpConnector>, Body>;

// Type-erased pool for dynamic dispatch
pub trait ErasedConnectionPool: Send + Sync {
    fn get(&self, key: &str) -> Option<PooledClient>;
    fn insert(&self, key: &str, client: PooledClient);
}

pub trait ErasedHttpClient: Send + Sync {
    async fn send(&self, req: Request<Body>) -> Result<Response<Body>>;
}
```

### Connection Pooling

```rust
pub struct ConnectionPool {
    clients: moka::sync::Cache<String, PooledClient>,
    default_ttl: Duration,  // 100s idle, 300s active
}

pub struct PooledClient {
    client: HttpClient,
    tls_config: Option<UpstreamTlsConfig>,
    created_at: Instant,
    last_used: Instant,
}
```

### Per-Site TLS

```rust
pub struct UpstreamTlsConfig {
    pub ca_cert: Option<Vec<u8>>,     // Custom CA certificate
    pub skip_verify: bool,            // Skip server verification
    pub allow_plaintext: bool,        // Allow HTTP (not just HTTPS)
    pub client_cert: Option<(Vec<u8>, Vec<u8>)>,  // mTLS
}
```

### Streaming Body

```rust
pub struct StreamingWafBody {
    inner: Body,
    waf_scanner: Arc<dyn StreamingWafScanner>,
    max_size: usize,
}

impl Stream for StreamingWafBody {
    type Item = Result<Bytes>;
    
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        // Scan each chunk via WAF
        // Enforce max size
    }
}
```

## Integration Points

- Used by HTTP/1, HTTP/3, and proxy layers
- All upstream HTTP connections flow through this crate
- Streaming body support for large uploads/downloads
- Per-site TLS configuration for multi-tenant deployments

## Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `HttpClient` | `crates/synvoid-http-client/src/client.rs` | Standard HTTP client |
| `StreamingHttpClient` | `crates/synvoid-http-client/src/client.rs` | Streaming HTTP client |
| `ConnectionPool` | `crates/synvoid-http-client/src/pool.rs` | Client pooling |
| `UpstreamTlsConfig` | `crates/synvoid-http-client/src/tls.rs` | Per-upstream TLS |
| `StreamingWafBody` | `crates/synvoid-http-client/src/streaming.rs` | WAF-scanning body |
| `ErasedConnectionPool` | `crates/synvoid-http-client/src/erased_pool.rs` | Type-erased pool |
