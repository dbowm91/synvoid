# ErasedHttpClient Integration (Phase 9 Incomplete)

This skill documents the ErasedHttpClient implementation and its incomplete Phase 9 integration into the HTTP server.

## Background

The ErasedHttpClient was implemented to provide true streaming via a type-erased connection pool. The design involves:
- `ErasedConnectionPool` - Type-erased connection pooling with checkout/checkin
- `Http1PooledConnection` - Wraps TcpStream in TokioIo with handshake
- `ErasedHttpClient` - Primary interface using the pool

## Phase 9 Status: INCOMPLETE ⚠️

**As of 2026-05-23**: Phase 9 integration into `http/server.rs` was never completed.

### What's Implemented

1. `ErasedHttpClient` is added to `HttpServer` struct (`server.rs:357,401`)
2. The pool and connector are created and cloned throughout

### What's Missing

At `server.rs:3302`:
```rust
let use_erased_client = false;  // Hardcoded to false - never activates!
```

The streaming path uses `StreamingHttpClient` from `UpstreamClientRegistry.get_or_create_streaming()` instead. The `ErasedHttpClient` is cloned throughout but never actually called in the request path.

### The Fix

To complete Phase 9 integration:

1. **Change line 3302** from hardcoded false to conditional logic:
```rust
// Instead of:
let use_erased_client = false;

// Use something like:
let use_erased_client = matches!(buffering_policy, BodyBufferingPolicy::Streaming)
    && self.erased_http_client.is_some();
```

2. **In the if block at line 3329**, use `erased_http_client.send_request()` instead of `streaming_client`:
```rust
if use_erased_client {
    if let Some(client) = &self.erased_http_client {
        response = client.send_request(request, client_ip).await?;
    }
} else {
    // Existing streaming path
}
```

3. **Test with** `BodyBufferingPolicy::Streaming` policy

## Location Reference

| File | Lines | Purpose |
|------|-------|---------|
| `src/http_client/mod.rs` | 34-41 | Moka cache for HTTP clients |
| `src/http_client/erased_pool.rs` | 245-283 | `checkout()` with error handling (NEW-63 added doc comments) |
| `src/http_client/typed_pool.rs` | - | Typed connection pool |
| `src/http/server.rs` | 357,401 | ErasedHttpClient added to HttpServer |
| `src/http/server.rs` | 3302 | `use_erased_client = false` (the bug) |
| `src/http/server.rs` | 3329 | if block that should use ErasedHttpClient |

## Verification Commands

```bash
# Check compilation
cargo check --lib

# Run erased_pool tests
cargo test --lib erased_pool

# Test integration (requires full profile)
cargo test --test integration_test
```

## Related Skills

- `performance_patterns.md` - Connection pooling and buffer management
- `httpserver.md` - HTTP server patterns