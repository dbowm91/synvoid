# HTTP/3 Server Module - AGENTS.override.md

Specialized guidance for HTTP/3 QUIC request handling and proxying.

## Hot Path

`src/http3/server.rs` — HTTP/3 QUIC request handling and proxying executes on every request. Critical hot path:
- Every allocation compounds at 500K rps
- Avoid O(n) operations; prefer O(1) lookups
- Use thread-local buffers and object pools

## Module-Specific Patterns

### QUIC Connection Handling

- Connection state management is per-connection
- Stream multiplexing requires careful buffer management

## Skills Reference

- `skills/h3_proxy.md` — H3 proxy patterns