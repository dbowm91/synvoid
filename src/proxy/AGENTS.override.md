# Upstream Proxy Module - AGENTS.override.md

Specialized guidance for proxy routing and cache key construction.

## Hot Path

`src/proxy/mod.rs` — Upstream proxy, cookie/cache key construction executes on every request. Critical hot path:
- Every allocation compounds at 500K rps
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