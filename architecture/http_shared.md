# HTTP Client Architecture

## Purpose and Responsibility

The HTTP Client module (`src/http_client/`) provides **upstream proxy connections** for SynVoid's reverse proxy architecture. It handles:

1. **HTTP/1.1 and HTTP/2 clients** with TLS support using `hyper` and `hyper-rustls`
2. **Connection pooling** with per-host idle limits and timeouts
3. **Type-erased streaming** for high-performance RPS scales (1M+ RPS target)
4. **Unix socket** connections for local upstream services
5. **QUIC tunnel** support for `quictunnel://` URL schemes
6. **Streaming WAF body scanning** that intercepts chunks mid-body without full buffering

---

## Module Structure

```
src/http_client/
├── mod.rs                  # Root re-export shim for synvoid-http-client crate
├── quic_tunnel_dispatch.rs # QUIC tunnel URL routing
└── streaming_waf_body.rs   # Re-export shim for StreamingWafBody
```

The canonical implementation lives in `crates/synvoid-http-client/`:
```
crates/synvoid-http-client/src/
├── lib.rs              # Thin public facade + re-exports only
├── client.rs           # Public type aliases (HttpClient etc.), high-level create_* entry points, EmptyBody, is_quictunnel_url compat
├── tls.rs              # TLS config, UpstreamTlsConfig, upstream_tls_from_site_config, build_tls_config, webpki/native fallback, custom CA, HostnameSkippingVerifier
├── pool.rs             # UpstreamClientKey, moka client caches, build_upstream_client, create_upstream_* logic
├── unix.rs             # is_unix_socket_url, Unix client and request helpers
├── request.rs          # All send_request_* / streaming / get / post_json / auth helpers
├── response.rs         # HttpResponse + from_hyper conversion
├── erased_pool.rs      # Type-erased connection pool (primary production path)
└── streaming_waf_body.rs # Streaming WAF body scanning
```

### 1. Core Module (`mod.rs`)

(Note: describes the public API surface provided via crate lib.rs re-exports; root `src/http_client/mod.rs` is the thin compatibility shim.)

**Public Types:**
- `HttpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>` — Standard buffered HTTP client
- `StreamingHttpClient = Client<HttpsConnector<HttpConnector>, BoxErasedBody>` — Streaming-capable client
- `UnixHttpClient = Client<UnixConnector, Full<Bytes>>` — Unix domain socket client
- `HttpResponse` — Response wrapper with status, headers, and body
- `UpstreamTlsConfig` — TLS configuration for upstream connections
- `StreamingWafBody<B>` — WAF-scanning body wrapper

**Key Functions:**
- `create_http_client()` / `create_http_client_with_config()` — Creates default HTTPS client
- `create_upstream_client()` / `create_upstream_streaming_client()` — Cached clients by TLS config
- `send_request_*()` family — Variants with/without timeout, body, headers
- `send_request_streaming()` — Raw hyper response with streaming body intact
- `send_unix_request_*()` — Unix socket request helpers
- `send_request_via_quic_tunnel()` — QUIC tunnel tunneling for `quictunnel://` URLs
- `post_json()` / `post_json_with_timeout()` / `post_json_response()` — JSON helpers

---

## Key Submodules and Responsibilities

### `erased_pool.rs` — Type-Erased Connection Pool (Phase 9)

**Purpose:** Avoid per-request boxing overhead at 1M RPS scale. Connection checkout happens ~10K-100K times/second (amortized), while per-request boxing would happen 1M times/second.

**Public Types:**
- `ErasedBody` trait — Type-erased body with `poll_frame()` and `size_hint()`
- `ErasedBodyImpl<B>` — Wraps any `HttpBody<Data=Bytes>` into `Box<dyn ErasedBody>`
- `BoxErasedBody = Box<dyn ErasedBody>` — Alias for boxed trait object
- `ErasedConnectionPool` — HashMap-based pool with `checkout()` / `checkin()` semantics
- `Http1PooledConnection` — Wraps `hyper::client::conn::http1::SendRequest`
- `Http2PooledConnection` — Stub for HTTP/2 (see HTTP/2 Support below)
- `ErasedHttpClient` — High-level client using `ErasedConnectionPool`
- `PoolKey` — `{ authority: String, is_http2: bool }` for pool entry identification

**Pool Semantics:**
```rust
pub struct ErasedConnectionPool {
    inner: Arc<tokio::sync::Mutex<HashMap<PoolKey, VecDeque<Http1PooledConnection>>>>,
    max_idle_per_host: usize,
    connect_timeout: Duration,
}
```

- `checkout(key)` — Pops from pool, or creates new TCP connection + HTTP/1.1 handshake
- `checkin(key, conn)` — Returns connection to pool if `is_connected()` and under `max_idle_per_host`
- Connection is only reused if `sender.is_some()` (handshake completed)

**Error Handling:**
- `InvalidInput` — Malformed authority string or unparseable host:port
- `TimedOut` — TCP connection or handshake exceeded `connect_timeout`
- `Other` — TCP connection failed (includes OS error details)

---

## Major Data Structures

### `UpstreamTlsConfig`

```rust
pub struct UpstreamTlsConfig {
    pub verify: bool,                     // Enable TLS verification (false = skip)
    pub ca_cert_path: Option<String>,     // Custom CA certificate file path
    pub server_name: Option<String>,       // SNI server name override
    pub skip_verify: bool,                 // Bypass hostname verification (chain still validated)
    pub skip_verify_reason: Option<String>, // Documentation why skip_verify is needed
    pub allow_plaintext: bool,             // Allow HTTP (not HTTPS)
}
```

Created from `crate::config::site::UpstreamTlsConfig` via `UpstreamTlsConfig::from_site_config()`.

### `UpstreamClientKey`

```rust
struct UpstreamClientKey {
    tls_config: UpstreamTlsConfigHashable,  // Hashable subset of TLS config
    pool_max_idle: usize,                    // Per-host idle connection limit
    pool_idle_secs: u64,                     // Idle timeout in seconds
}
```

Used as cache key for `UPSTREAM_CLIENT_CACHE` and `UPSTREAM_STREAMING_CLIENT_CACHE` (Moka LRU caches, max 100 entries, 5-minute TTL).

### `StreamingWafBody<B>`

```rust
pub struct StreamingWafBody<B> {
    inner: B,                                            // Original body
    streaming_waf: Option<StreamingWafCore>,             // WAF scanner
    client_ip: IpAddr,                                   // For logging
    blocked: bool,                                       // State: already blocked
    error_sent: bool,                                    // State: error frame sent
}
```

Implements `hyper::body::Body` and scans each chunk via `sw.scan_chunk()`:
- `Block` decision → sets `blocked=true`, returns `PermissionDenied` error
- `Continue` decision → passes frame through

### `HttpResponse`

```rust
pub struct HttpResponse {
    pub status: http::StatusCode,
    pub headers: http::HeaderMap,
    pub body: Bytes,
}
```

Created via `HttpResponse::from_hyper(response, max_size)` which collects the body with optional size limit.

---

## Key APIs and Entry Points

### Client Creation Entry Points

| Function | Purpose |
|----------|---------|
| `create_http_client()` | Default 5s connect timeout, 1000 max idle, 30s idle timeout |
| `create_http_client_with_config(connect_timeout, pool_max_idle, pool_idle_timeout)` | Customized default client |
| `create_upstream_client(timeout, max_idle, idle_timeout, tls_config)` | **Cached** client by TLS config |
| `create_upstream_streaming_client(...)` | **Cached** streaming client by TLS config |
| `create_unix_http_client()` | Unix socket client (100 max idle, 30s idle timeout) |
| `create_simple_http_client(timeout)` | Short-lived simple client |

### Request Sending Entry Points

| Function | Signature |
|----------|-----------|
| `send_request(client, method, url)` | Basic GET/POST |
| `send_request_with_timeout(client, method, url, timeout)` | With timeout |
| `send_request_with_body_and_timeout(client, method, url, body, timeout)` | With body |
| `send_request_with_timeout_and_headers(client, method, url, headers, timeout)` | With headers |
| `send_request_streaming(client, method, url, body, headers, timeout)` | Returns `Response<Incoming>` for streaming |
| `send_request_streaming_generic(client, method, url, body, headers, timeout)` | Generic body type |
| `send_request_erased_streaming(client, method, url, body, headers, timeout, is_http2)` | Uses `ErasedHttpClient` |
| `send_unix_request_with_timeout(client, socket, path, method, timeout)` | Unix socket |
| `send_request_via_quic_tunnel(method, url, headers, body, timeout)` | QUIC tunnel |

### JSON Convenience Functions

| Function | Signature |
|----------|-----------|
| `post_json(client, url, body)` | POST JSON, returns `HttpResponse` |
| `post_json_with_timeout(client, url, body, timeout)` | With timeout |
| `post_json_response<T, R>(client, url, body)` | POST JSON, parse response to `R` |
| `post_json_response_with_timeout<T, R>(client, url, body, timeout)` | With timeout |

---

## Connection Pooling

### Global Client Cache (Moka)

```rust
static UPSTREAM_CLIENT_CACHE: LazyLock<Cache<UpstreamClientKey, HttpClient>> =
    LazyLock::new(|| Cache::builder()
        .max_capacity(100)
        .time_to_live(Duration::from_secs(300))
        .build());

static UPSTREAM_STREAMING_CLIENT_CACHE: LazyLock<Cache<UpstreamClientKey, StreamingHttpClient>> =
    LazyLock::new(|| Cache::builder()
        .max_capacity(100)
        .time_to_live(Duration::from_secs(300))
        .build());
```

Clients are cached by TLS configuration (hashable subset) + pool parameters. This avoids recreating clients for common configurations.

### Per-Client Connection Pool (hyper-util)

```rust
Client::builder(TokioExecutor::new())
    .pool_max_idle_per_host(pool_max_idle_per_host)  // Default: 100
    .pool_idle_timeout(pool_idle_timeout)            // Default: 30s
    .http2_only(false)                               // Both HTTP/1.1 and HTTP/2
    .build(https_connector)
```

- `pool_max_idle_per_host` — Maximum idle connections per host
- `pool_idle_timeout` — Idle connection eviction timeout
- `http2_only(false)` — Negotiates HTTP/1.1 or HTTP/2 via ALPN

### ErasedConnectionPool (Alternative)

For true streaming at scale, `ErasedConnectionPool` provides manual connection management:

1. **Checkout**: `checkout(key)` attempts to pop from `HashMap<PoolKey, VecDeque<Http1PooledConnection>>`
2. **Fallback**: If pool empty, creates new TCP connection + HTTP/1.1 handshake
3. **Checkin**: `checkin(key, conn)` returns connection to pool if under limit and connected

```rust
// Pool checkout flow
let mut pool = inner.lock().await;
if let Some(conns) = pool.get_mut(&key) {
    if let Some(conn) = conns.pop_front() {
        if conn.is_connected() { return Ok(conn); }
    }
}
drop(pool);
// Create new connection with connect_timeout
```

---

## HTTP/2 Support

### ALPN Negotiation

HTTP/2 is enabled via `hyper-rustls` ALPN:
```rust
config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
```

Client negotiates with server — both protocols supported.

### HTTP/2 Configuration Points

1. **`http2_only(false)`** on `Client::builder()` — Allows fallback to HTTP/1.1
2. **`ErasedHttpClient::send_request(..., is_http2)`** — Boolean flag (currently **not wired** for HTTP/2 pooling)

### Known Limitation: HTTP/2 Pooling

From `src/http/AGENTS.override.md`:
> **HTTP2-POOL | ErasedHttpClient HTTP/2 pooling** — hyper http2_client::handshake() API incompatible with current hyper-util

The `Http2PooledConnection` stub exists but `is_available()` always returns `false`:
```rust
impl PooledConnection for Http2PooledConnection {
    fn is_available(&self) -> bool { false }  // Stub - HTTP/2 pooling not implemented
}
```

This is a **deferred item** — HTTP/2 connection pooling requires different API surface.

### Per-Request HTTP/2 Control

`sync void request_erased_streaming()` passes `is_http2` to `ErasedHttpClient::send_request()` but the boolean is stored in `PoolKey` and used for pool lookup, not actual protocol switching on existing connections.

---

## Feature Gates

| Feature | Default | Purpose |
|---------|---------|---------|
| `erased_pool` | **Enabled** | Enables `ErasedConnectionPool`, `ErasedHttpClient`, type-erased body support |
| `buffer` | Off | Enables `synvoid-utils/buffer` (TreiberStack replacement) |
| `rkyv` | Off | Zero-copy serialization alternative to Postcard |
| `post-quantum` | Off | Rustls post-quantum crypto (RUSTSEC-2026-0096 patched) |

### `erased_pool` Feature Impact

When `erased_pool` is **disabled** (not common), the `ErasedConnectionPool` and related types are not compiled. The module still provides standard `HttpClient` via `hyper-util` client.

```toml
# Cargo.toml
erased_pool = []  # Feature gate in [features]
```

---

## TLS Configuration

### TLS Provider

All TLS uses **aws-lc-rs** (Pure Rust):
```rust
use rustls::crypto::aws_lc_rs;
let provider = Arc::new(aws_lc_rs::default_provider());
```

### `build_tls_config()` Flow

1. **Create builder** with aws-lc-rs provider and safe default protocol versions
2. **Skip verification path** (when `skip_verify = true`):
   - Load native certs or fallback to webpki_roots
   - Load custom CA certs from `ca_cert_path` if provided
   - Build `HostnameSkippingVerifier` that bypasses `NotValidForName` errors
   - ALPN: `h2`, `http/1.1`
3. **Normal verification path** (default):
   - Load native certs or fallback to webpki_roots
   - Load custom CA certs from `ca_cert_path` if provided
   - Use `with_root_certificates(root_store)` to build `ClientConfig`
   - ALPN: `h2`, `http/1.1`

### `HostnameSkippingVerifier`

Custom verifier that logs hostname verification bypass but still validates certificate chain:
```rust
impl ServerCertVerifier for HostnameSkippingVerifier {
    fn verify_server_cert(...) -> Result<ServerCertVerified, rustls::Error> {
        match self.inner.verify_server_cert(...) {
            Ok(scv) => Ok(scv),
            Err(rustls::Error::InvalidCertificate(cert_error)) => {
                if let rustls::CertificateError::NotValidForName = cert_error {
                    tracing::warn!(reason = %self.skip_reason, "Skipping hostname verification");
                    Ok(ServerCertVerified::assertion())
                } else { Err(...) }
            }
            Err(e) => Err(e),
        }
    }
}
```

---

## QUIC Tunnel Support

Handles `quictunnel://peer:port/...` URLs via `send_request_via_quic_tunnel()`:

1. Parse URL to extract peer IP and port
2. Get QUIC runtime from `QUIC_TUNNEL_REGISTRY`
3. Open tunnel stream via `runtime.open_tunnel_stream_to_peer()`
4. Send `TunnelMessage::StreamOpen` with protocol `http`
5. Read `StreamOpenAck` response
6. Send raw HTTP/1.1 request over QUIC stream
7. Parse HTTP/1.1 response from stream bytes

This provides a tunneled HTTP proxy over QUIC with TLS passthrough support.

---

## HTTP/3 Server Integration

The HTTP/3 server (`crates/synvoid-http3/src/server.rs`) uses `HttpClient` for upstream requests:

```rust
use crate::http_client::{
    create_http_client_with_config, send_request_streaming,
    send_request_streaming_generic, ErasedBodyImpl, HttpClient,
    StreamingWafBody, UpstreamTlsConfig,
};
```

**Request Flow in HTTP/3:**
1. Client sends HTTP/3 request to QUIC endpoint
2. Server resolves request via `h3::server::RequestResolver`
3. Server calls `send_request_streaming()` or `send_request_streaming_generic()` with `HttpClient`
4. Upstream response is streamed back via `request_stream.send_data()`

**Key HTTP/3 Stats:**
- `synvoid.http3.connections` (gauge) — Active connections
- `synvoid.http3.connections.total` (counter) — Total connections
- `synvoid.http3.connection.errors` (counter) — Connection errors
- `synvoid.http3.request.duration` (histogram) — Request latency
- `synvoid.http3.responses` (counter) — Successful responses

---

## Design Rationale

### Why Type-Erased Pool?

At 1M RPS with millions of tenants, per-request boxing (`Box<dyn Body>`) creates GC pressure. The `ErasedBody` trait + `Box<dyn ErasedBody>` approach moves boxing to connection checkout (10K-100K/second) rather than per-request (1M/second).

### Why Moka for Client Cache?

Moka provides:
- LRU eviction when max capacity (100) exceeded
- TTL-based entry expiration (5 minutes)
- Thread-safe `Arc<Cache<..>>` sharing across async tasks
- Minimal memory footprint vs. `DashMap` or `RwLock<HashMap>`

### Why aws-lc-rs?

Per `AGENTS.md` — Pure Rust crypto, battle-tested, no C bindings. Provides TLS 1.3 and post-quantum (PQ) support when `post-quantum` feature enabled.

---

## File Relationships

| File | Purpose |
|------|---------|
| `src/http_client/mod.rs` | Root re-export shim for `synvoid-http-client` crate |
| `crates/synvoid-http-client/src/lib.rs` | Thin public facade + re-exports; implementation in focused modules |
| `crates/synvoid-http-client/src/client.rs` | Public type aliases (HttpClient etc.), high-level create_* entry points, EmptyBody, is_quictunnel_url compat |
| `crates/synvoid-http-client/src/tls.rs` | TLS config, UpstreamTlsConfig, upstream_tls_from_site_config, build_tls_config, webpki/native fallback, custom CA, HostnameSkippingVerifier |
| `crates/synvoid-http-client/src/pool.rs` | UpstreamClientKey, moka client caches, build_upstream_client, create_upstream_* logic |
| `crates/synvoid-http-client/src/unix.rs` | is_unix_socket_url, Unix client and request helpers |
| `crates/synvoid-http-client/src/request.rs` | All send_request_* / streaming / get / post_json / auth helpers |
| `crates/synvoid-http-client/src/response.rs` | HttpResponse + from_hyper conversion |
| `crates/synvoid-http-client/src/erased_pool.rs` | Type-erased connection pool for streaming |
| `crates/synvoid-http3/src/server.rs` | HTTP/3 server that uses `HttpClient` for upstream |
| `src/proxy/mod.rs` | Uses `http_client` for proxying |
| `src/tunnel/quic/*.rs` | QUIC tunnel infrastructure |
| `crates/synvoid-config/src/site/proxy.rs` + `security.rs` | Site proxy/security config for upstream_tls_from_site_config (no dedicated site/tls.rs) |
