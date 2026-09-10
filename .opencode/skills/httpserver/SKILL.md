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

Both share the same request processing logic (Phase 01 convergence):
`HttpServer::handle_request` and `HttpsServer::handle_request_with_cache`
compose the same canonical `synvoid_http::prepare_http_request_flow` +
`synvoid_http::handle_http_request_postlude` stages. TLS keeps only
connection/transport work (accept, flood protection, handshake, ALPN,
certificate/SNI selection, JA4 extraction, connection lifecycle).

## Converged Request Composition (Phase 01)

Transport differences cross the boundary as narrow values, not traits:

- `ja4_hash: Option<String>` — `HttpsConnection::get_ja4()` on TLS,
  `None` on plaintext; threaded into both the streaming fast-path header
  check (prelude) and the buffered WAF check (postlude).
- `forwarded_protocol: ForwardedProtocol` — `Https` on TLS, `Http` on
  plaintext; only forwarded header that differs (`X-Forwarded-Proto`).
- `alt_svc: None` on TLS (Alt-Svc advertisement stays an HTTP-plane
  concern); `local_addr` captured pre-handshake for vhost routing;
  `mesh_backend_pool: None` on TLS (never wired there).

Do not reintroduce a shared connection trait or `dyn Any` abstraction to
make the servers look identical — the Phase 01 plan rejects that. Guard:
`tls_request_flow_stays_converged` in
`tests/http_normalization_ownership_guard.rs`; parity:
`tests/http_tls_parity.rs`.

## Key Files

| File | Purpose |
|------|---------|
| `src/http/server.rs` + `src/http/server/` | HTTP listener, `HttpServerRuntime` service bundle, accept loop (root composition) |
| `src/tls/server.rs` | HTTPS listener + `HttpsConnection` handling (root integration; core TLS in `synvoid-tls`); request policy via canonical `synvoid-http` stages |
| `crates/synvoid-http/src/` | Canonical stages: `framing`, `early_parse`, `headers`, `request_parse`, `request_frontdoor`, `request_preparation`, `body_policy`, `waf_decision`, backend dispatches |
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

Both compose the same canonical stages:
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│ synvoid-http canonical composition                             │
│  ├─ prepare_http_request_flow (frontdoor/traffic/preflight/    │
│  │   streaming-fast-path/body-policy/challenge)                │
│  └─ handle_http_request_postlude (buffered WAF + dispatch +    │
│      accounting)                                               │
│  boundary: ja4_hash (Some on TLS) + ForwardedProtocol::Https   │
└─────────────────────────────────────────────────────────────────┘
```

## Working with the Converged Handler

### Accessing JA4 Hash

```rust
// In HttpsServer::handle_request_with_cache:
let ja4_hash: Option<String> = http_conn.get_ja4();
// threaded into prepare_http_request_flow + HttpRequestPostludeContext
```

### Checking Protocol

Upstreams observe the downstream scheme via `X-Forwarded-Proto`
(`ForwardedProtocol::Https` on TLS, `Http` on plaintext). Request-path
code must not branch on transport outside this header.

### WebSocket Support

WebSocket upgrades validate via canonical `validate_websocket_upgrade` in
preflight and dispatch via `maybe_handle_websocket_upgrade` in the
postlude on both transports. `.with_upgrades()` stays on each
connection builder.

## JA4 Wiring (Phase 01)

1. `HttpsConnection::new()` computes JA4 from TLS ClientHello
2. `http_conn.get_ja4()` returns the hash per request
3. Passed as `ja4_hash` into `prepare_http_request_flow` (streaming
   fast-path header check) and `HttpRequestPostludeContext::ja4_hash`
   (buffered `check_request_full_owned`) for JA4-based bot detection

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

## Migration Progress (Phase 01 complete)

| Step | Status |
|------|--------|
| Canonical prelude/postlude shared | ✅ Complete |
| JA4 threaded into both WAF checks | ✅ Complete |
| ForwardedProtocol boundary param | ✅ Complete |
| Duplicate HTTPS pipeline removed | ✅ Complete |
| Parity tests + convergence guard | ✅ Complete |

## Adding New Connection Types

To add a new connection type (e.g., QUIC): keep transport work
(handshake, ALPN, fingerprinting) in the transport module and call the
same `prepare_http_request_flow` + `handle_http_request_postlude`
composition with narrow boundary values (`ja4_hash`,
`forwarded_protocol`). Do not add a shared connection trait.

## Common Issues

### WebSocket Not Working on HTTPS

If WebSocket upgrades fail on HTTPS:
1. Verify `.with_upgrades()` is called on the HTTP/1 connection builder
2. Ensure `hyper::upgrade::on()` is called before consuming the request body (canonical preflight does this)
3. Check route target websocket config allows the upgrade

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
