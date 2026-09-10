# HTTP Server Module - AGENTS.override.md

Specialized guidance for HTTP request handling and dispatch.

## Ownership (Phase 20)

Root `src/http/` is application composition (`keep_app_root`). Reusable
parsing/normalization/dispatch lives canonically in `synvoid-http`
(`crates/synvoid-http/src/`); the full 42-module matrix is
`architecture/http_ownership_convergence.md`.

- **Thin facades** (24 modules): pure `pub use synvoid_http::…` re-exports.
  Do not add logic; prefer direct canonical imports in new code.
- **Root adapters** (11 modules): narrow root-owned services (`WafCore`,
  `Router`/`PluginManager` downcasts, supervisor maps) to crate traits.
  New capabilities follow the composition-boundary rule: define the narrow
  trait in `synvoid-http`/`synvoid-core`, implement on the root type here.
- **Application handlers** (root-owned): `directory_viewer`,
  `file_manager`, `file_manager_ui`, `webdav`.
- **Composition root** (root-owned): `server.rs` + `server/` (`HttpServer`,
  `HttpServerRuntime`, accept loop). Must not move into `synvoid-http`
  (would pull `WafCore`/drain/flood/plugin services into the domain crate).

Canonical normalization order: listener sniff → frontdoor → traffic control
→ preflight (`extract_request_metadata`, then fail-closed
`framing::validate_request_framing`, trust-token bypass, routing) →
streaming fast path → body policy (`finalize_request_preparation`
re-validates framing) → challenge paths → buffered WAF dispatch (single
decision→response mapping in `waf_decision`) → backend dispatch →
accounting. WAF and routing consume the same `path` from
`extract_request_metadata`; never decode a second path for routing.

Guard: `cargo test --test http_normalization_ownership_guard`.

## TLS Convergence (Phase 01)

`HttpsServer::handle_request_with_cache` (`src/tls/server.rs`) composes the
same canonical stages (`prepare_http_request_flow` +
`handle_http_request_postlude`) with boundary adaptations
(`ForwardedProtocol::Https`, handshake JA4, `alt_svc: None`, pre-handshake
`local_addr`, `mesh_backend_pool: None`). Do not fork routing/body/WAF/
challenge/upstream logic back into `src/tls/server.rs` — the
`tls_request_flow_stays_converged` guard fails on it. Parity:
`cargo test --test http_tls_parity`. Stage matrix:
`architecture/http_request_pipeline.md`.

## Hot Path

`src/http/server.rs` — HTTP request handling and dispatch executes on every request. Critical hot path:
- Every allocation compounds at 1000K rps
- Avoid O(n) operations; prefer O(1) lookups
- Use thread-local buffers and object pools

## Module-Specific Patterns

### Mesh Backend Pool

`BackendType::Mesh` variant is dispatched via `mesh_backend_pool`. Key files:
- `crates/synvoid-mesh/src/mesh/backend.rs` — `MeshBackend`/`MeshBackendPool`
- `crates/synvoid-mesh/src/mesh/proxy.rs` — `MeshProxy` for routing

## Known File Path Corrections

| Wrong Path | Correct Path |
|------------|--------------|
| `src/http/client.rs` | `src/http_client/mod.rs` |
| `src/http/server.rs` (shared logic) | `crates/synvoid-http/src/` (canonical stages) |
| `src/http/shared_handler.rs` | `crates/synvoid-http/src/shared_handler.rs` |
| `src/http/early_parse.rs`, `headers.rs`, `body_policy.rs` (impl) | `crates/synvoid-http/src/` (root paths are facades/adapters) |
| `src/mesh/proxy.rs` | `crates/synvoid-mesh/src/mesh/proxy.rs` |
