# HTTP/3 Server Module - AGENTS.override.md

Specialized guidance for HTTP/3 QUIC request handling and proxying.

## Hot Path

`crates/synvoid-http3/src/server.rs` — HTTP/3 QUIC request handling and proxying executes on every request. Critical hot path:
- Every allocation compounds at 1000K rps
- Avoid O(n) operations; prefer O(1) lookups
- Use thread-local buffers and object pools

## Module-Specific Patterns

### QUIC Connection Handling

- Connection state management is per-connection
- Stream multiplexing requires careful buffer management

### Architecture Boundary

- `Http3WafBackend` trait is defined in `crates/synvoid-http3/src/lib.rs`
- Server accepts WAF as `Arc<dyn Http3WafBackend>` (trait object)
- Concrete `WafCore` stays in root; only trait objects flow into HTTP/3
- `bind_udp_reuse` comes from `synvoid-platform` crate
- Root re-exports `Http3Server` and `Http3WafBackend` via `src/http3/mod.rs`

## Skills Reference

- `skills/h3_proxy.md` — H3 proxy patterns
