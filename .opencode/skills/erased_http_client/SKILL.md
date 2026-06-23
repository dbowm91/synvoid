---
name: erased_http_client
description: ErasedHttpClient streaming pool patterns and HTTP/2 connection management limitations.
---

# ErasedHttpClient Integration Status

This document tracks the current ErasedHttpClient status and the HTTP/2 pooling limitation.

## Background

The ErasedHttpClient was implemented to provide true streaming via a type-erased connection pool. The design involves:
- `ErasedConnectionPool` - Type-erased connection pooling with checkout/checkin
- `Http1PooledConnection` - Wraps TcpStream in TokioIo with handshake
- `ErasedHttpClient` - Primary interface using the pool

## Current Status (2026-06-23)

Erased client primitives exist, but the HTTP request path currently uses `StreamingHttpClient` for streaming forwards. `ErasedHttpClient` is carried through worker wiring (`src/http/server.rs`) but is not the active streaming send path for proxy requests. The `StreamingHttpClient` type alias is defined in `crates/synvoid-http-client/src/client.rs:17` and used in `crates/synvoid-http/src/upstream_proxy_dispatch_plan.rs`.

### Implemented

1. `ErasedHttpClient` is added to `HttpServer` and passed through request handling.
2. Type-erased body wrappers exist (`ErasedBody`, `ErasedBodyImpl`).
3. Connection pool machinery exists for HTTP/1-style erased bodies.

### Limitation

- Streaming request forwarding still uses `StreamingHttpClient`.
- Full HTTP/2 streaming pooling through the erased path is not the active default and remains a deferred concern.
- Current implementation is acceptable for stable full-body forwarding and existing streaming behavior, but should not be documented as complete erased HTTP/2 pooling.

## If You Choose To Continue This Work

To fully switch the streaming path to erased pooling:

1. Replace the active `StreamingHttpClient` branch with erased-client sending in `src/http/server.rs`.
2. Ensure HTTP/2 connection lifecycle correctness for pooled streaming connections (background task and shutdown semantics).
3. Validate under load with `BodyBufferingPolicy::Streaming`.

## Location Reference

| File | Lines | Purpose |
|------|-------|---------|
| `crates/synvoid-http-client/src/client.rs` | :17 | `StreamingHttpClient` type alias definition |
| `crates/synvoid-http-client/src/erased_pool.rs` | - | `checkout()` with error handling, erased-body + pool primitives |
| `crates/synvoid-http/src/upstream_proxy_dispatch_plan.rs` | :24 | `StreamingHttpClient` used for upstream proxy dispatch |
| `src/http/server.rs` | :98, :146 | `ErasedHttpClient` wired into HttpServer (not the active streaming path) |

## Verification Commands

```bash
# Check compilation
cargo check --lib

# Run erased-pool focused tests
cargo test --lib erased_pool
```

## Related Skills

- `httpserver.md` - HTTP server patterns
