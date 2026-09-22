# Upstream Proxy Module - AGENTS.override.md

Specialized guidance for proxy routing and cache key construction.

## Hot Path

`crates/synvoid-proxy/src/server.rs` — Canonical upstream proxy implementation, cookie/cache key construction executes on every request. Critical hot path:
- Every allocation compounds at 1000K rps
- Avoid O(n) operations; prefer O(1) lookups
- Use thread-local buffers and object pools

`src/proxy/mod.rs` is now a compatibility shim over `synvoid-proxy`; prefer the extracted crate for new work.

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

The canonical `BackendType` enum is at `crates/synvoid-proxy/src/router.rs:66`
with 11 variants:
`Upstream`, `FastCgi`, `Php`, `Cgi`, `AxumDynamic`, `AppServer`, `Static`, `QuicTunnel`, `Serverless`, `Mesh`, `Spin`.
`src/router.rs` is only a 6-line compat facade (`pub use synvoid_proxy::router::*`)
— import from `synvoid_proxy`, never the root path.

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

### Retry Config Now Applied via `with_upstream_pool()`

`ProxyServer::with_upstream_pool()` is the supported path for applying retry and buffering configuration. Callers should pass the configured pool plus retry/buffering settings before using the proxy server. Retries were previously easy to omit in the root implementation, so keep the explicit wiring in mind when touching call sites.

### TypedConnectionPool plaintext consistency

`TypedConnectionPool` now respects `allow_plaintext` configuration:
- `TypedPoolKey` includes `allow_plaintext: bool`
- `https_only()` used when plaintext disabled
- Security warning logged when plaintext enabled
