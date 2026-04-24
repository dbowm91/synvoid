# HTTPServer Architecture Skill

## Overview

MaluWAF has two HTTP server implementations:
1. **HttpServer** (`src/http/server.rs`) - handles plain HTTP
2. **HttpsServer** (`src/tls/server.rs`) - handles TLS/SSL

Both share the same request processing logic. The unified handler architecture (`src/server/request_handler.rs`) provides a shared abstraction to eliminate code duplication.

## Unified Handler Architecture

### ConnectionMeta Trait

Both connection types implement the `ConnectionMeta` trait:

```rust
pub trait ConnectionMeta: Send + Sync {
    fn request_drop(&self);
    fn should_drop(&self) -> bool;
    fn get_ja4(&self) -> Option<String>;
    fn supports_websocket(&self) -> bool { true }
    fn protocol(&self) -> &'static str;
    fn tls_context(&self) -> TlsContext;
}
```

### TlsContext

TLS metadata is carried through the request pipeline via `TlsContext`:

```rust
pub struct TlsContext {
    pub ja4_hash: Option<String>,
    pub protocol: &'static str,
}
```

- **HttpConnection**: `get_ja4()` returns `None`, `protocol()` returns `"http"`
- **HttpsConnection**: `get_ja4()` returns the actual JA4 hash, `protocol()` returns `"https"`

## Key Files

| File | Purpose |
|------|---------|
| `src/http/server.rs` | HTTP server (plain connections) |
| `src/tls/server.rs` | HTTPS server (TLS connections) |
| `src/server/request_handler.rs` | Unified handler traits and utilities |
| `src/server/mod.rs` | UnifiedServer orchestration |

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│ UnifiedServer                                                    │
│  └─ run_http_server_inner()  ──► HttpServer                     │
│                                    └─ HttpConnection            │
│  └─ run_https_server_inner() ──► HttpsServer                   │
│                                     └─ HttpsConnection         │
└─────────────────────────────────────────────────────────────────┘

Both connections implement ConnectionMeta:
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│ ConnectionMeta Trait                                           │
│  ├─ HttpConnection  ──► tls_context.protocol = "http"         │
│  └─ HttpsConnection ──► tls_context.protocol = "https"      │
│                            tls_context.ja4_hash = Some(...)     │
└─────────────────────────────────────────────────────────────────┘
```

## Working with the Unified Handler

### Accessing JA4 Hash

```rust
fn process_request<C: ConnectionMeta>(connection: Arc<C>) {
    let tls_context = connection.tls_context();
    if let Some(ja4) = tls_context.ja4_hash {
        tracing::debug!("JA4 fingerprint: {}", ja4);
    }
}
```

### Checking Protocol

```rust
fn process_request<C: ConnectionMeta>(connection: Arc<C>) {
    match connection.protocol() {
        "https" => { /* TLS-specific logic */ }
        "http" => { /* Plain HTTP logic */ }
        _ => {}
    }
}
```

### WebSocket Support

```rust
fn process_request<C: ConnectionMeta>(connection: Arc<C>) {
    if connection.supports_websocket() {
        // Handle WebSocket upgrade
    }
}
```

## JA4 Wiring (O.1)

JA4 fingerprinting is now accessible via `ConnectionMeta`:

1. `HttpsConnection::new()` computes JA4 from TLS ClientHello
2. `connection.get_ja4()` returns the hash
3. Pass to WAF via `check_bot_protection()` to enable JA4-based bot detection

```rust
// In request handler
let ja4_hash = connection.get_ja4();
waf.check_bot_protection_with_ja4(client_ip, path, user_agent, ja4_hash.as_deref());
```

## Connection Structs

### HttpConnection

```rust
struct HttpConnection {
    io: Mutex<Option<TokioIo<tokio::net::TcpStream>>>,
    drop_requested: RunningFlag,
}
```

### HttpsConnection

```rust
struct HttpsConnection {
    io: Mutex<Option<TokioIo<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>>>,
    drop_requested: RunningFlag,
    ja4_hash: Mutex<Option<String>>,
}
```

## Testing

```bash
# Run integration tests
cargo test --test integration_test

# Check compilation
cargo check

# Run clippy
cargo clippy --lib -- -D warnings
```

## Migration Progress

| Step | Status |
|------|--------|
| ConnectionMeta trait | ✅ Complete |
| TlsContext struct | ✅ Complete |
| JA4 accessible via trait | ✅ Complete |
| Migrate request processing | ✅ Complete |
| Remove duplicate code | ✅ Complete |
| Wire JA4 to WAF | ✅ Complete |

## Adding New Connection Types

To add a new connection type (e.g., QUIC):

1. Implement `ConnectionMeta` trait
2. Add impl block in `src/server/request_handler.rs`
3. Ensure `get_ja4()` returns appropriate value

## Common Issues

### WebSocket Not Working on HTTPS

If WebSocket upgrades fail on HTTPS:
1. Check that `supports_websocket()` returns `true`
2. Verify `.with_upgrades()` is called on the HTTP/1 connection builder
3. Ensure `hyper::upgrade::on()` is called before consuming the request body

### JA4 Hash Not Available

JA4 is computed during TLS handshake in `HttpsConnection::new()`. If unavailable:
1. Check that TLS handshake completed successfully
2. Verify `extract_client_hello_bytes_from_stream()` returns `Some`
3. Check that `compute_ja4()` doesn't return `None`
