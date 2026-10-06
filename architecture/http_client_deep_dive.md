# HTTP Client Deep Dive

SynVoid's HTTP client crate provides TLS-configurable HTTP/1.1 and HTTP/2 client with connection pooling, per-site TLS configs, and streaming body support.

## Architecture

### Core Types

```rust
pub type HttpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;
pub type StreamingHttpClient = Client<HttpsConnector<HttpConnector>, BoxErasedBody>;
#[cfg(unix)]
pub type UnixHttpClient = Client<hyperlocal::UnixConnector, Full<Bytes>>;

// Type-erased body for dynamic dispatch
pub trait ErasedBody: Send + Sync + 'static {
    fn poll_frame(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>>;
    fn size_hint(&self) -> SizeHint;
}
pub type BoxErasedBody = Box<dyn ErasedBody>;
```

### Connection Pooling

Per-site clients are cached in static moka caches keyed by `UpstreamClientKey` (TLS config + pool params):

```rust
const MAX_UPSTREAM_CLIENT_CACHE_SIZE: u64 = 100;
const UPSTREAM_CLIENT_CACHE_TTL_SECS: u64 = 300;

static UPSTREAM_CLIENT_CACHE: LazyLock<Cache<UpstreamClientKey, HttpClient>> = ...;
static UPSTREAM_STREAMING_CLIENT_CACHE: LazyLock<Cache<UpstreamClientKey, StreamingHttpClient>> = ...;
```

The erased pool (`ErasedConnectionPool`) manages HTTP/1.1 connections with configurable max idle per host and connect timeout:

```rust
pub struct ErasedConnectionPool {
    inner: Arc<Mutex<HashMap<PoolKey, VecDeque<Http1PooledConnection>>>>,
    max_idle_per_host: usize,
    connect_timeout: Duration,
}
```

### Egress Lanes (Phase 60/62)

Two lanes exist in this crate:

- **Production: the eggfetch lane.** `eggfetch_transport::EggfetchUpstreamClient`
  carries all upstream sends (proxy `ProxyServer`, HTTP/3 upstream dispatch, and
  upstream health checks). `eggfetch_policy` is a private
  `UpstreamTlsConfig` → `eggfetch_core::TlsConfig` translator that keeps a
  single public TLS policy type and preserves the legacy invariants: custom CA
  *augments* the base store rather than replacing it, `skip_verify` disables
  hostname matching only (never chain/signature verification), and the SNI
  override travels per-request.
- **Frozen compatibility surface: the erased pool.** `ErasedConnectionPool` /
  `ErasedHttpClient` still compile and are tested, but production use is blocked
  by `eggfetch_lane_freeze_guard`.

### Per-Site TLS

```rust
pub struct UpstreamTlsConfig {
    pub verify: bool,                    // Verify server certificate
    pub ca_cert_path: Option<String>,    // Custom CA certificate path
    pub server_name: Option<String>,     // Override server name
    pub skip_verify: bool,               // Skip hostname verification
    pub skip_verify_reason: Option<String>, // Audit reason for skip
    pub allow_plaintext: bool,           // Allow HTTP (not just HTTPS)
}
```

### Streaming Body

Phase 34: the WAF-scanning body adapter moved to `synvoid-http`
(`crates/synvoid-http/src/streaming_waf_body.rs`) so the transport core
stays policy-free. Shape (unchanged, new owner):

```rust
pub struct StreamingWafBody<B, S> {
    inner: B,
    streaming_waf: Option<S>,
    client_ip: IpAddr,
    blocked: bool,
    error_sent: bool,
}

impl<B, S> hyper::body::Body for StreamingWafBody<B, S>
where
    B: http_body::Body<Data = Bytes> + Unpin,
    S: StreamingWafScanner + Send + Sync + Unpin + 'static,
{
    type Data = Bytes;
    type Error = std::io::Error;
    
    fn poll_next(...) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        // Scan each chunk via streaming WAF
        // Block on StreamingWafDecision::Block
    }
}
```

## Integration Points

- Used by HTTP/1, HTTP/3, upstream health checks, and the proxy layer
- The proxy, HTTP/3, and `HealthChecker` all send upstream through this crate's
  eggfetch lane, so it owns the shared egress path. Do **not** read this as
  "every connection in the process": in-process lane plumbing also involves
  `synvoid-http-client`'s Unix, QUIC-tunnel, and differential surfaces.
- Streaming body support for large uploads/downloads
- Per-site TLS configuration for multi-tenant deployments

## Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `HttpClient` | `crates/synvoid-http-client/src/client.rs` | Standard HTTP client |
| `StreamingHttpClient` | `crates/synvoid-http-client/src/client.rs` | Streaming HTTP client |
| `UnixHttpClient` | `crates/synvoid-http-client/src/client.rs` | Unix socket HTTP client |
| `UpstreamTlsConfig` | `crates/synvoid-http-client/src/tls.rs` | Per-upstream TLS (neutral policy; site conversion in `synvoid-upstream::tls_adapter`) |
| `StreamingWafBody` | `crates/synvoid-http/src/streaming_waf_body.rs` (Phase 34; was `synvoid-http-client`) | WAF-scanning body |
| `ErasedConnectionPool` | `crates/synvoid-http-client/src/erased_pool.rs` | Type-erased HTTP/1.1 pool |
| `ErasedHttpClient` | `crates/synvoid-http-client/src/erased_pool.rs` | Type-erased HTTP client |
| `ErasedBody` / `BoxErasedBody` | `crates/synvoid-http-client/src/erased_pool.rs` | Type-erased body trait/alias (frozen lane) |
| `EggfetchUpstreamClient` | `crates/synvoid-http-client/src/eggfetch_transport.rs` | Production upstream egress lane |
