---
name: httpserver
description: HTTP server architecture with dual-mode implementation for request handling.
---

# HTTPServer Architecture Skill

## Overview

SynVoid has two HTTP server integrations over one canonical pipeline:
1. **HttpServer** (`src/http/server.rs` + `src/http/server/`) - plain HTTP listener + application composition
2. **HttpsServer** (`src/tls/server.rs`) - TLS listener + connection handling

Reusable parsing/normalization/dispatch lives canonically in `synvoid-http`
(`crates/synvoid-http/src/`). Root `src/http/` is application composition
(`keep_app_root`, Phase 20): 24 thin facades, 11 narrow-trait adapters over
root services, 5 application handlers, and the `HttpServer` composition root.
Full matrix: `architecture/http_ownership_convergence.md`.

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
| `src/http/server.rs` + `src/http/server/` | HTTP listener, `HttpServerRuntime` service bundle, accept loop (root composition) |
| `src/tls/server.rs` | HTTPS listener + `HttpsConnection` handling (root integration; core TLS in `synvoid-tls`) |
| `crates/synvoid-http/src/` | Canonical stages: `framing`, `early_parse`, `headers`, `request_parse`, `request_frontdoor`, `request_preparation`, `body_policy`, `waf_decision`, backend dispatches |
| `src/server/request_handler.rs` | Unified handler traits and utilities |
| `src/server/mod.rs` | UnifiedServer orchestration |

Note: `src/server/` is split into focused modules — `startup_plan.rs`, `resources.rs`, `runtime_handles.rs`, `plugin_runtime.rs`, `waf_handler.rs` — with `mod.rs` re-exporting. See `architecture/worker_data_plane_composition_root.md`.

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

## Request Pipeline Normalization (Iteration 99)

HTTP/1 and HTTP/3 pipelines now share the same stage vocabulary documented in `architecture/http_request_pipeline.md`.
HTTP/3 dispatch uses `Http3RequestMetadata` (request fields) and `Http3DispatchDeps` (service handles) context structs
instead of 21 discrete parameters. Both pipelines consume `RequestServices` or narrower handles, never
`UnifiedServerWorkerState`. Guard tests in `tests/http_request_pipeline_boundary_guard.rs` enforce this boundary.

## Canonical Framing Policy (Phase 20)

Transfer-framing and authority validation has one fail-closed implementation:
`crates/synvoid-http/src/framing.rs` (`validate_request_framing`,
`validate_transfer_framing`, `validate_host_authority`, plus the shared
listener sniff helpers `is_tls_client_hello` / `is_valid_http_request_start`).

- Enforced in `prepare_request_preflight` (400 before routing/WAF) and
  re-validated in `finalize_request_preparation` via the same helpers.
- Duplicate `Host` also fails closed on the HTTP/3 prelude; QUIC has no
  transfer-framing ambiguity (explicit frame lengths).
- Do not add parsing/normalization under `src/http` or `src/tls` — extend
  `framing.rs` and cover new ambiguity cases with unit tests there.
- Guard: `cargo test --test http_normalization_ownership_guard`.
- Full module matrix: `architecture/http_ownership_convergence.md`.
