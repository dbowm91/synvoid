# Upstream Proxy Module - AGENTS.override.md

Specialized guidance for proxy routing and cache key construction.

## Hot Path

`src/proxy/mod.rs` — Upstream proxy, cookie/cache key construction executes on every request. Critical hot path:
- Every allocation compounds at 1000K rps
- Avoid O(n) operations; prefer O(1) lookups
- Use thread-local buffers and object pools

## Module-Specific Patterns

### Cache Key Construction

- Avoid string concatenation in hot paths
- Use pre-allocated buffers
- Minimize allocations during request processing

### Connection Pooling

- Upstream connections should be pooled and reused
- Connection lifetime management impacts performance

### Retry Policy Honesty

`forward_with_pool()` must check:
1. `config.enabled` - retries must be disabled by default
2. Method safety - only retry GET/HEAD/OPTIONS/TRACE or POST/PATCH when `retry_non_idempotent=true`
3. Use `is_idempotent_method()` and `should_retry_request()` from `retry.rs`

### Header Forwarding

Default behavior forwards all end-to-end headers:
- Strip hop-by-hop headers (Connection, Keep-Alive, TE, Trailer, Upgrade)
- Sanitize spoofable forwarded headers from client (X-Real-IP, X-Forwarded-For, X-Forwarded-Proto)
- Apply `clear`/`hide` config for explicit removals
- Use `set` overrides for header values

### BackendType

The actual `BackendType` enum is at `src/router.rs:65-78` with 11 variants:
`Upstream`, `FastCgi`, `Php`, `Cgi`, `AxumDynamic`, `AppServer`, `Static`, `QuicTunnel`, `Serverless`, `Mesh`, `Spin`

**Note**: `architecture/proxy.md` documents this incorrectly — always verify against source.

### Security: Constant-Time Comparison

Always use `subtle::ConstantTimeEq` for secrets, tokens, and cache purge keys:
```rust
use subtle::ConstantTimeEq;
// For cache purge token comparison:
required_token.as_bytes().ct_eq(token.as_bytes()).into()
```

### FastCGI Concurrency (RESOLVED)

`execute_stream()` at `src/fastcgi/pool.rs:229` — semaphore permit is now held for the full function scope, ensuring concurrency limits are respected.

## Upstream Pool Fixes (2026-05-23)

### Retry Config Now Applied from from_config()

`ProxyServer::from_config()` now properly calls `with_upstream_pool()` to apply retry and buffering configuration. Retries were previously always disabled even when configured.

### TypedConnectionPool plaintext consistency

`TypedConnectionPool` now respects `allow_plaintext` configuration:
- `TypedPoolKey` includes `allow_plaintext: bool`
- `https_only()` used when plaintext disabled
- Security warning logged when plaintext enabled