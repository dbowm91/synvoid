# HTTP Module Overlap Matrix

Generated for HTC-H00. Compares root `src/http/mod.rs` modules vs extracted `crates/synvoid-http/src/lib.rs` modules.

## Legend

| Action | Meaning |
|--------|---------|
| `REEXPORT_SHIM_NOW` | Root file is already a pure 1-2 line `pub use synvoid_http::*` shim; safe to delete later |
| `KEEP_ROOT_ONLY` | Root file adapts root-only concrete types (WafCore, Router, etc.) to trait-based synvoid-http API; must stay in root |
| `KEEP_ROOT_ONLY` | Module only exists in root; depends on root-only state; out of scope for extraction |
| `MOVE_TO_SYNVOID_HTTP` | Module only in root but could move (low root dependencies) |
| `DELETE_ROOT_DUPLICATE` | Root file can be deleted (pure shim with no extra content) |
| `UNKNOWN_INVESTIGATE` | Need more investigation |

## Modules

| Module | In root? | In synvoid-http? | Root imports concrete root state? | Action | Notes |
|--------|----------|-------------------|-----------------------------------|--------|-------|
| app_server_backend_dispatch | ✅ | ✅ | No | `REEXPORT_SHIM_NOW` | Root is 2-line `pub use synvoid_http::app_server_backend_dispatch::*` |
| axum_dynamic_dispatch | ✅ | ✅ | Yes — `crate::config::MainConfig`, `crate::router::{RouteTarget, Router}` | `KEEP_ROOT_ONLY` | Root shim adapts `Arc<Router>` → `&dyn AxumDynamicRouterLookup` |
| body_policy | ✅ | ✅ | Yes — `crate::waf::WafCore` | `KEEP_ROOT_ONLY` | Root shim adapts `Arc<WafCore>` → `&WafCore` (deref) |
| buffered_request_waf_dispatch | ✅ | ✅ | Yes — `crate::config::{HttpConfig, MainConfig}`, `crate::router::RouteTarget`, `crate::waf::WafCore` | `KEEP_ROOT_ONLY` | Root shim passes WafCore callbacks (check_request_full, error_page_manager, tarpit) to trait-based synvoid-http |
| cgi_backend_dispatch | ✅ | ✅ | Yes — `crate::config::MainConfig`, `crate::router::RouteTarget`, `crate::waf::WafCore` | `KEEP_ROOT_ONLY` | Root shim passes WafCore error_page_manager callback |
| challenge_paths | ✅ | ✅ | Yes — `crate::config::MainConfig`, `crate::waf::WafCore` | `KEEP_ROOT_ONLY` | Root shim adapts Arc<WafCore> → deref + config access |
| directory_viewer | ✅ | ❌ | Yes — `crate::config::ConfigManager`, `crate::admin`, `crate::static_files`, `crate::theme` | `KEEP_ROOT_ONLY` | Full implementation (222 lines); depends on admin auth, config, theme, static_files |
| early_parse | ✅ | ✅ | No | `REEXPORT_SHIM_NOW` | Root is 2-line `pub use synvoid_http::early_parse::*` |
| fastcgi_php_backend_dispatch | ✅ | ✅ | Yes — `crate::config::MainConfig`, `crate::http::apply_image_poisoning`, `crate::router::{RouteTarget, Router}`, `crate::waf::WafCore` | `KEEP_ROOT_ONLY` | Root shim passes WafCore error_page_manager + image_poisoning callback |
| file_manager | ✅ | ❌ | Yes — `crate::config::ConfigManager`, `crate::admin`, `crate::static_files` | `KEEP_ROOT_ONLY` | Full implementation (394 lines); depends on admin auth, config, static_files |
| file_manager_ui | ✅ | ❌ | Yes — `crate::config::ConfigManager`, `crate::admin`, `crate::theme` | `KEEP_ROOT_ONLY` | Full implementation (363 lines); depends on admin auth, config, theme |
| headers | ✅ | ✅ | No | `REEXPORT_SHIM_NOW` | Root is 2-line `pub use synvoid_http::headers::*` |
| image_poisoning | ✅ | ❌ | Yes — `crate::config::site::SiteImagePoisonConfig` | `KEEP_ROOT_ONLY` | Full implementation (98 lines); standalone cache logic, but depends on config type |
| internal_endpoint_dispatch | ✅ | ✅ | No | `REEXPORT_SHIM_NOW` | Root is 2-line `pub use synvoid_http::internal_endpoint_dispatch::*` |
| internal_handlers | ✅ | ✅ | No | `REEXPORT_SHIM_NOW` | Root is 2-line `pub use synvoid_http::internal_handlers::*` |
| mesh_backend_dispatch | ✅ | ✅ | No | `REEXPORT_SHIM_NOW` | Root is 2-line `pub use synvoid_http::mesh_backend_dispatch::*` (cfg mesh) |
| request_parse | ✅ | ✅ | No | `REEXPORT_SHIM_NOW` | Root is 2-line `pub use synvoid_http::request_parse::*` |
| response_builder | ✅ | ✅ | No | `REEXPORT_SHIM_NOW` | Root is 2-line `pub use synvoid_http::response_builder::*` |
| response_helpers | ✅ | ✅ | No | `REEXPORT_SHIM_NOW` | Root is 2-line `pub use synvoid_http::response_helpers::*` |
| response_transform | ✅ | ✅ | No | `REEXPORT_SHIM_NOW` | Root is 2-line `pub use synvoid_http::response_transform::*` |
| server | ✅ | ❌ | Yes — `crate::config::{HttpConfig, MainConfig}`, `crate::router::Router`, `crate::worker::drain_state::WorkerDrainState`, `crate::http_client::ErasedHttpClient` | `KEEP_ROOT_ONLY` | Full implementation (494+428 lines in sub-modules); core HTTP server lifecycle |
| serverless_backend_dispatch | ✅ | ✅ | No | `REEXPORT_SHIM_NOW` | Root is 2-line `pub use synvoid_http::serverless_backend_dispatch::*` (cfg mesh) |
| shared_handler | ✅ | ✅ | No | `REEXPORT_SHIM_NOW` | Root is 2-line `pub use synvoid_http::shared_handler::*` |
| special_request_paths | ✅ | ✅ | No | `REEXPORT_SHIM_NOW` | Root is 3-line `pub use synvoid_http::special_request_paths::*` (cfg mesh) |
| spin_backend_dispatch | ✅ | ✅ | No | `REEXPORT_SHIM_NOW` | Root is 1-line `pub use synvoid_http::spin_backend_dispatch::*` |
| static_backend_dispatch | ✅ | ✅ | No | `REEXPORT_SHIM_NOW` | Root is 1-line `pub use synvoid_http::maybe_handle_static_backend` |
| streaming_request_fast_path | ✅ | ✅ | Yes — `crate::config::MainConfig`, `crate::proxy::client_registry::UpstreamClientRegistry`, `crate::proxy::WafDecision`, `crate::router::{RouteTarget, Router}`, `crate::waf::WafCore` | `KEEP_ROOT_ONLY` | Root shim passes WafCore callbacks + UpstreamClientRegistry |
| streaming_waf_decision | ✅ | ✅ | No | `REEXPORT_SHIM_NOW` | Root is 1-line `pub use synvoid_http::streaming_waf_decision::*` |
| streaming_waf_upstream_dispatch | ✅ | ✅ | Yes — `crate::config::MainConfig`, `crate::proxy::client_registry::UpstreamClientRegistry`, `crate::router::RouteTarget`, `crate::waf::WafCore` | `KEEP_ROOT_ONLY` | Root shim adapts Arc<WafCore> → streaming + error_page_manager |
| upload_validation_dispatch | ✅ | ✅ | No | `REEXPORT_SHIM_NOW` | Root is 1-line `pub use synvoid_http::upload_validation_dispatch::*` |
| upstream_buffered_dispatch | ✅ | ✅ | No | `REEXPORT_SHIM_NOW` | Root is 2-line `pub use synvoid_http::upstream_buffered_dispatch::*` |
| upstream_proxy_dispatch | ✅ | ✅ | No | `REEXPORT_SHIM_NOW` | Root is 2-line `pub use synvoid_http::upstream_proxy_dispatch::*` |
| upstream_proxy_dispatch_plan | ✅ | ✅ | No | `REEXPORT_SHIM_NOW` | Root is 2-line `pub use synvoid_http::upstream_proxy_dispatch_plan::*` |
| upstream_response_transform | ✅ | ✅ | No | `REEXPORT_SHIM_NOW` | Root is 2-line `pub use synvoid_http::upstream_response_transform::*` |
| upstream_streaming_dispatch | ✅ | ✅ | No | `REEXPORT_SHIM_NOW` | Root is 2-line `pub use synvoid_http::upstream_streaming_dispatch::*` |
| validation_helpers | ✅ | ✅ | No | `REEXPORT_SHIM_NOW` | Root is 1-line `pub use synvoid_http::validation_helpers::*` |
| waf_decision | ✅ | ✅ | No | `REEXPORT_SHIM_NOW` | Root is 1-line `pub use synvoid_http::waf_decision::*` |
| wasm_filter_dispatch | ✅ | ✅ | Yes — `crate::config::MainConfig`, `crate::router::{RouteTarget, Router}`, `crate::waf::WafCore` | `KEEP_ROOT_ONLY` | Root shim adapts Arc<Router> → PluginManager → dyn WasmFilterBackend |
| webdav | ✅ | ❌ | Yes — `crate::config::ConfigManager` | `KEEP_ROOT_ONLY` | Full implementation (773 lines); depends on config, axum routing |
| websocket_dispatch | ✅ | ✅ | Yes — `crate::config::site::SiteWebSocketConfig`, `crate::router::RouteTarget`, `crate::waf::WafCore` | `KEEP_ROOT_ONLY` | Root shim adapts Arc<WafCore> → dyn WafCoreBackend |
| websocket_upgrade_dispatch | ✅ | ✅ | Yes — `crate::config::site::SiteWebSocketConfig`, `crate::router::{BackendType, RouteTarget}`, `crate::waf::WafCore` | `KEEP_ROOT_ONLY` | Root shim resolves app_server socket path + adapts WafCore |

## Modules Only in synvoid-http (not in root)

| Module | In root? | In synvoid-http? | Notes |
|--------|----------|-------------------|-------|
| backend_dispatch | ❌ | ✅ | New extraction target |
| http_request_flow | ❌ | ✅ | New extraction target |
| http_request_postlude | ❌ | ✅ | New extraction target |
| http3_body | ❌ | ✅ | HTTP/3 body collection |
| http3_buffered_upstream_dispatch | ❌ | ✅ | HTTP/3 upstream |
| http3_request_dispatch | ❌ | ✅ | HTTP/3 request dispatch |
| http3_request_flow | ❌ | ✅ | HTTP/3 request flow |
| http3_request_prelude | ❌ | ✅ | HTTP/3 prelude |
| http3_route_dispatch | ❌ | ✅ | HTTP/3 route dispatch |
| http3_streaming_upstream_dispatch | ❌ | ✅ | HTTP/3 streaming upstream |
| http3_terminal | ❌ | ✅ | HTTP/3 terminal |
| http3_waf_dispatch | ❌ | ✅ | HTTP/3 WAF dispatch |
| listener | ❌ | ✅ | TCP listener abstraction |
| request_frontdoor | ❌ | ✅ | Request frontdoor preparation |
| request_preparation | ❌ | ✅ | Request preflight/preparation |
| runtime | ❌ | ✅ | Runtime utilities |
| streaming_request_pass | ❌ | ✅ | Streaming request pass |
| traffic_control | ❌ | ✅ | Connection/rate limiting |

## Summary

| Category | Count | Description |
|----------|-------|-------------|
| `REEXPORT_SHIM_NOW` | 24 | Pure shims; can be deleted once root callers migrated to `synvoid_http::` directly |
| `KEEP_ROOT_ONLY` (shim with state) | 11 | Adapt root concrete types → synvoid-http traits; must stay in root |
| `KEEP_ROOT_ONLY` (root-only module) | 6 | Full implementations only in root; out of scope for extraction |
| **Total root modules** | **41** | |
| synvoid-http-only modules | 18 | New modules only in extracted crate |

### Root-only state types requiring shims

| Type | Used by shim modules |
|------|---------------------|
| `crate::waf::WafCore` | body_policy, buffered_request_waf_dispatch, cgi_backend_dispatch, challenge_paths, fastcgi_php_backend_dispatch, streaming_request_fast_path, streaming_waf_upstream_dispatch, wasm_filter_dispatch, websocket_dispatch, websocket_upgrade_dispatch |
| `crate::router::Router` | axum_dynamic_dispatch, fastcgi_php_backend_dispatch, streaming_request_fast_path, wasm_filter_dispatch |
| `crate::router::RouteTarget` | axum_dynamic_dispatch, buffered_request_waf_dispatch, cgi_backend_dispatch, fastcgi_php_backend_dispatch, streaming_waf_upstream_dispatch, wasm_filter_dispatch, websocket_dispatch, websocket_upgrade_dispatch |
| `crate::config::MainConfig` | axum_dynamic_dispatch, buffered_request_waf_dispatch, cgi_backend_dispatch, challenge_paths, fastcgi_php_backend_dispatch, streaming_request_fast_path, streaming_waf_upstream_dispatch, wasm_filter_dispatch |
| `crate::config::HttpConfig` | buffered_request_waf_dispatch |
| `crate::config::site::*` | websocket_dispatch, websocket_upgrade_dispatch (SiteWebSocketConfig) |
| `crate::proxy::client_registry::UpstreamClientRegistry` | streaming_request_fast_path, streaming_waf_upstream_dispatch |
| `crate::worker::drain_state::WorkerDrainState` | server (root-only module) |
