# Root Dependency Ownership Matrix

> Status: Created as part of HTC-R01 (HTTP Consolidation)
> Last updated: 2026-06-07
> Scope: Dependencies affected by proxy/http extraction

## Summary

This matrix classifies each dependency from the HTC-R01 scope by its true owner.
Actions: `KEEP_ROOT`, `MOVE_TO_EXISTING_CRATE`, `REMOVE_FROM_ROOT`, `FEATURE_FORWARD_ONLY`, `UNKNOWN_INVESTIGATE`

## Hyper/Tower/Axum Stack

| Dependency | In root Cargo.toml | In synvoid-http | In synvoid-proxy | Root module usage | Action | Notes |
|---|---|---|---|---|---|---|
| hyper | ✅ | ✅ | ✅ | `http/server.rs`, `http/body_policy.rs`, `http/streaming_*`, `http/websocket_*`, `dns/doh.rs`, `tls/server.rs`, `http_client/*` | KEEP_ROOT | 45 uses in root; server pipeline, DNS-over-HTTPS, TLS, HTTP client |
| hyper-util | ✅ | ✅ | ❌ | `http_client/typed_pool.rs`, `http_client/erased_pool.rs`, `http/server/connection_types.rs`, `dns/doh.rs`, `tls/server.rs` | KEEP_ROOT | 9 uses in root; HTTP client pooling, server connections |
| hyper-rustls | ✅ | ❌ (in synvoid-http-client) | ❌ | `http_client/typed_pool.rs` only (3 uses) | REMOVE_FROM_ROOT | 3 uses; synvoid-http-client already owns this dep |
| tower | ✅ | ✅ | ❌ | 32 files in `admin/handlers/*`, `admin/middleware.rs`, `admin/mod.rs`, `admin/ws/*`, `http/directory_viewer.rs`, `http/file_manager*.rs`, `http/webdav.rs`, `plugin/*`, `bin/server.rs` | KEEP_ROOT | 9 uses; middleware framework for admin API, file serving, plugin loader |
| tower-http | ✅ | ❌ | ❌ | `admin/mod.rs` only (1 use: `CorsLayer`, `ServeDir`) | KEEP_ROOT | 1 use; CORS + static file serving in admin server |
| axum | ✅ | ✅ | ❌ | 32 files: all `admin/handlers/*`, `admin/middleware.rs`, `admin/mod.rs`, `admin/openapi.rs`, `admin/ws/*`, `http/directory_viewer.rs`, `http/file_manager*.rs`, `http/webdav.rs`, `plugin/axum_loader.rs`, `plugin/mod.rs`, `bin/server.rs` | KEEP_ROOT | 135 uses; admin API framework, static file UI, plugin loader |
| axum-extra | ✅ | ❌ | ❌ | `admin/handlers/common.rs` only (1 use) | KEEP_ROOT | 1 use; typed headers in admin handlers |
| http-body | ✅ | ✅ | ✅ | `http/body_policy.rs`, `http_client/erased_pool.rs`, `http_client/typed_pool.rs`, `tls/server.rs` | KEEP_ROOT | 26 uses across root; body trait used everywhere |
| http-body-util | ✅ | ✅ | ✅ | `tls/server.rs`, `honeypot_port/responders/ai.rs`, `server/waf_handler.rs`, `http/*_dispatch.rs`, `http/challenge_paths.rs`, `http_client/*`, `dns/doh.rs` | KEEP_ROOT | Body utilities used in many root dispatch modules |
| tokio-util | ✅ | ❌ | ❌ | **0 uses in root** | REMOVE_FROM_ROOT | 0 direct imports; no root module uses it |

## WAF/Detection/Scanning

| Dependency | In root Cargo.toml | In synvoid-http | In synvoid-proxy | Root module usage | Action | Notes |
|---|---|---|---|---|---|---|
| yara-x | ✅ | ❌ | ❌ | `upload/yara_scanner.rs` only (9 uses) | KEEP_ROOT | Root upload module uses directly for YARA scanning |
| infer | ✅ | ❌ | ❌ (in synvoid-app-handlers) | **0 uses in root** | REMOVE_FROM_ROOT | 0 uses; synvoid-app-handlers owns this dep |
| wasmtime | ✅ (via `[patch.crates-io]`) | ❌ | ❌ | **0 uses in root** | REMOVE_FROM_ROOT | 0 uses; synvoid-plugin-runtime owns this dep; root has comment "wasmtime moved to synvoid-plugin-runtime" |

## Minification/Compression/Static Files

| Dependency | In root Cargo.toml | In synvoid-http | In synvoid-proxy | Root module usage | Action | Notes |
|---|---|---|---|---|---|---|
| lightningcss | ✅ | ❌ | ❌ | **0 uses in root** | REMOVE_FROM_ROOT | 0 uses; synvoid-static-files owns this dep |
| minify-html | ✅ | ❌ | ❌ | **0 uses in root** | REMOVE_FROM_ROOT | 0 uses; synvoid-static-files owns this dep |
| minify-js | ✅ | ❌ | ❌ | **0 uses in root** | REMOVE_FROM_ROOT | 0 uses; synvoid-static-files owns this dep |
| brotli | ✅ | ❌ | ❌ | **0 direct uses in root** (only string refs "br" in worker/config) | REMOVE_FROM_ROOT | 0 uses; synvoid-static-files owns this dep |
| walkdir | ✅ | ❌ | ❌ | `static_files/file_manager.rs` (1 use) | KEEP_ROOT | 1 use; root static_files module uses directly |
| fastcgi-client | ✅ | ❌ | ❌ (in synvoid-app-handlers) | **0 uses in root** (root fastcgi/ is pure re-export from synvoid-app-handlers) | REMOVE_FROM_ROOT | 0 uses; root fastcgi/mod.rs is `pub use synvoid_app_handlers::fastcgi::*` |

## Database/GeoIP

| Dependency | In root Cargo.toml | In synvoid-http | In synvoid-proxy | Root module usage | Action | Notes |
|---|---|---|---|---|---|---|
| rusqlite | ✅ | ❌ | ❌ | `dns/store.rs`, `dns/trust_anchor.rs`, `honeypot_port/storage.rs`, `waf/threat_level/persistence/sqlite.rs` | KEEP_ROOT | 4 root modules use directly |
| maxminddb | ✅ | ❌ | ❌ | **0 uses in root** | REMOVE_FROM_ROOT | 0 uses; synvoid-geoip owns this dep |

## Observability/Admin/Schema

| Dependency | In root Cargo.toml | In synvoid-http | In synvoid-proxy | Root module usage | Action | Notes |
|---|---|---|---|---|---|---|
| metrics-exporter-prometheus | ✅ | ❌ | ❌ | `admin/prometheus_exporter.rs` only (1 use) | KEEP_ROOT | 1 use; root admin module uses directly |
| schemars | ✅ | ❌ | ❌ (in synvoid-proxy) | `admin/handlers/config.rs`, `main.rs` (2 uses) | KEEP_ROOT | 2 uses; root main.rs generates JSON schema |
| utoipa | ✅ | ❌ | ❌ | 23 files in `admin/handlers/*`, `admin/openapi.rs`, `admin/schema.rs`, `admin/state.rs`, `admin/mod.rs` | KEEP_ROOT | 258 uses; core admin API OpenAPI annotations |
| utoipa-swagger-ui | ✅ | ❌ | ❌ | Feature-gated (`swagger-ui` feature), only in root | FEATURE_FORWARD_ONLY | Optional dep; root feature-gate only |

## HTTP/3 + QUIC

| Dependency | In root Cargo.toml | In synvoid-http | In synvoid-proxy | Root module usage | Action | Notes |
|---|---|---|---|---|---|---|
| quinn | ✅ | ❌ (in synvoid-http3) | ❌ | `dns/doq.rs`, `http3/server.rs`, `tcp/listener.rs` | KEEP_ROOT | 3 root modules use directly |
| h3 | ✅ | ✅ | ❌ | `http3/server.rs` only (1 use) | KEEP_ROOT | 1 use; root http3 server uses directly |
| h3-quinn | ✅ | ❌ | ❌ | `http3/server.rs` only (1 use) | KEEP_ROOT | 1 use; root http3 server uses directly |

## Recommended Removals (No Root Usage)

### Removed (HTC-R02 Batch 1 — 2026-06-07)

| Dependency | Reason | Already in extracted crate |
|---|---|---|
| `tokio-util` | 0 uses in root | synvoid-static-files |
| `infer` | 0 uses in root | synvoid-app-handlers |
| `maxminddb` | 0 uses in root | synvoid-geoip |
| `lightningcss` | 0 uses in root | synvoid-static-files |
| `minify-html` | 0 uses in root | synvoid-static-files |
| `minify-js` | 0 uses in root | synvoid-static-files |
| `brotli` | Test-only use removed; prod logic in synvoid-static-files | synvoid-static-files |

### Not Removed — KEEP_ROOT_FOR_NOW

| Dependency | Reason |
|---|---|
| `hyper-rustls` | 3 direct uses in root `src/http_client/typed_pool.rs` — cannot remove until http_client/ is consolidated |
| `fastcgi-client` | Not in root Cargo.toml (already removed) |
| `wasmtime` | Only in `[patch.crates-io]` (transitive dep fix); `bench_wasm.rs` needs it but was pre-existing broken |

## Recommended Moves (To Existing Crate)

| Dependency | Move to | Reason |
|---|---|---|
| `hyper-rustls` | synvoid-http-client | Already owns TLS HTTP connector; only 3 root uses in http_client/ which is being consolidated |

## Verification

```bash
# After removing the above deps, verify compilation:
cargo check --workspace --all-targets

# Verify no broken imports:
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
```
