# HTC-H05: Simplify root `src/http/mod.rs` — Investigation & Findings

## Goal

Make root `src/http/mod.rs` look more like root `src/proxy/mod.rs` — a compatibility shim over `synvoid-http`.

## Why `pub use synvoid_http::*` Cannot Be Used

The plan's preferred shape (`pub use synvoid_http::*;` + only root-only modules) is **blocked by 11 adapter shim modules** that wrap root concrete types to match synvoid-http's trait-based API.

**Conflict example:** `synvoid-http` re-exports `body_policy::collect_and_scan_request_body` with a trait-based signature. Root `src/http/body_policy.rs` defines its own `collect_and_scan_request_body` that accepts `Arc<WafCore>` and adapts it. Both names would be exported, causing a collision.

**The 11 adapter shim modules that prevent wildcard re-export:**

| Module | Root concrete type adapted |
|--------|---------------------------|
| axum_dynamic_dispatch | `Arc<Router>` → `&dyn AxumDynamicRouterLookup` |
| body_policy | `Arc<WafCore>` → `&WafCore` |
| buffered_request_waf_dispatch | WafCore callbacks (check_request_full, error_page_manager, tarpit) |
| cgi_backend_dispatch | WafCore error_page_manager callback |
| challenge_paths | `Arc<WafCore>` → deref + config access |
| fastcgi_php_backend_dispatch | WafCore error_page_manager + image_poisoning callback |
| streaming_request_fast_path | WafCore callbacks + UpstreamClientRegistry |
| streaming_waf_upstream_dispatch | `Arc<WafCore>` → streaming + error_page_manager |
| wasm_filter_dispatch | `Arc<Router>` → PluginManager → dyn WasmFilterBackend |
| websocket_dispatch | `Arc<WafCore>` → dyn WafCoreBackend |
| websocket_upgrade_dispatch | app_server socket path + WafCore adaptation |

These modules MUST remain as explicit `pub mod` declarations. They cannot be replaced by re-exports from synvoid-http because they provide different function signatures.

## What Can Be Simplified: Redundant Convenience Re-exports

The 7 `pub use` lines at the bottom of `mod.rs` are convenience re-exports. Most are **unused** via the short path:

| Re-export | Used via short path? | Location |
|-----------|---------------------|----------|
| `early_parse::{EarlyHttpParser, EarlyHttpRequest}` | **No** | Only referenced in mod.rs itself |
| `headers::{inject_cors_headers, inject_security_headers}` | **No** | `inject_security_headers` used via `crate::http::headers::` path |
| `image_poisoning::{apply_image_poisoning, invalidate_image_poison_cache_for_site}` | **Yes** | `src/http/server.rs:361`, `src/http/fastcgi_php_backend_dispatch.rs:9`, `src/admin/state.rs:613` |
| `response_builder::{bad_gateway_bytes, error_body, error_response_bytes, fallback_error_boxed, fallback_error_bytes, fallback_error_full, reason_phrase}` | **Partially** | Only `fallback_error_boxed` used: `src/tls/server.rs:832` |
| `response_transform::{apply_compression, apply_minification, ResponseTransformConfig}` | **No** | Only referenced in mod.rs itself |
| `server::HttpServer` | **Yes** | `src/server/mod.rs:9` |
| `shared_handler::SharedRequestHandler` | **No** | Used via `crate::http::shared_handler::` path |

**4 items are actually used via short path:**
- `HttpServer` — `src/server/mod.rs:9`
- `apply_image_poisoning` — `src/http/server.rs:361`, `src/http/fastcgi_php_backend_dispatch.rs:9`
- `invalidate_image_poison_cache_for_site` — `src/admin/state.rs:613`
- `fallback_error_boxed` — `src/tls/server.rs:832`

## Recommended Change

Remove the 3 fully-unused convenience re-exports (`early_parse`, `headers`, `response_transform`). Trim `response_builder` to only the used item (`fallback_error_boxed`). Keep the 3 re-exports from root-only modules (`image_poisoning`, `server`, `shared_handler`) since those are the authoritative source.

### Before (52 lines)

```rust
pub mod app_server_backend_dispatch;
pub mod axum_dynamic_dispatch;
pub mod body_policy;
// ... 38 more module declarations ...

pub use early_parse::{EarlyHttpParser, EarlyHttpRequest};
pub use headers::{inject_cors_headers, inject_security_headers};
pub use image_poisoning::{apply_image_poisoning, invalidate_image_poison_cache_for_site};
pub use response_builder::{
    bad_gateway_bytes, error_body, error_response_bytes, fallback_error_boxed,
    fallback_error_bytes, fallback_error_full, reason_phrase,
};
pub use response_transform::{apply_compression, apply_minification, ResponseTransformConfig};
pub use server::HttpServer;
pub use shared_handler::SharedRequestHandler;
```

### After (48 lines)

```rust
pub mod app_server_backend_dispatch;
pub mod axum_dynamic_dispatch;
pub mod body_policy;
// ... 38 more module declarations (unchanged) ...

pub use image_poisoning::{apply_image_poisoning, invalidate_image_poison_cache_for_site};
pub use response_builder::fallback_error_boxed;
pub use server::HttpServer;
pub use shared_handler::SharedRequestHandler;
```

**Net change:** Remove 3 unused re-export lines, trim `response_builder` from 4 lines to 1. Module declarations unchanged.

## Why Further Simplification Is Blocked

1. **Adapter shims cannot be collapsed** — they provide different function signatures wrapping root concrete types (WafCore, Router, etc.)
2. **Root-only modules must stay** — server, directory_viewer, file_manager, file_manager_ui, image_poisoning, webdav depend on root-only state
3. **`pub use synvoid_http::*` is not feasible** — would collide with adapter shim definitions
4. **Pure shim modules are already minimal** — each is 1-2 lines (`pub use synvoid_http::module::*`); removing them would break module-path access used by other root files (e.g., `crate::http::response_builder::build_response_with_alt_svc`)

## Acceptance

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

Both must pass after the change.
