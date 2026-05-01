# HTTP Server Module - AGENTS.override.md

Specialized guidance for HTTP request handling and dispatch.

## Hot Path

`src/http/server.rs` — HTTP request handling and dispatch executes on every request. Critical hot path:
- Every allocation compounds at 500K rps
- Avoid O(n) operations; prefer O(1) lookups
- Use thread-local buffers and object pools

## Module-Specific Patterns

### Mesh Backend Pool

`BackendType::Mesh` variant is dispatched via `mesh_backend_pool`. Key files:
- `src/mesh/backend.rs:109-303` — `MeshBackend`/`MeshBackendPool`
- `src/mesh/proxy.rs` — `MeshProxy` for routing

## Known File Path Corrections

| Wrong Path | Correct Path |
|------------|--------------|
| `src/http/client.rs` | `src/http_client/mod.rs` |