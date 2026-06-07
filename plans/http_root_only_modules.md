# Root-Only HTTP Module Inventory

> Generated for HTC-H06. Classifies remaining root `src/http` modules that have no extracted equivalent in `synvoid-http`.

## Summary

Five modules remain root-only. All share a common pattern: they depend on root-concrete types (`ConfigManager`, `verify_admin_token`, `Router`, `WafCore`, etc.) that are not available in extracted crates. `image_poisoning.rs` was extracted in HWS-S02 — its canonical implementation now lives in `synvoid-static-files` and the root file is a compatibility shim. Three modules (`directory_viewer`, `file_manager`, `webdav`) follow an identical dependency pattern and could move to `synvoid-static-files` once a shared auth seam exists.

## Classification Table

| Module | Why root-owned | Root dependencies | Candidate target crate | Next seam needed | Priority |
|--------|---------------|-------------------|----------------------|------------------|----------|
| `server.rs` (494 lines) | Core HTTP server lifecycle; wires all root concrete types together | `crate::config::{HttpConfig, MainConfig}`, `crate::router::Router`, `crate::waf::{FloodDecision, FloodProtector, WafCore}`, `crate::worker::drain_state::WorkerDrainState`, `crate::http_client::{ErasedHttpClient, HttpClient, create_http_client_with_config}`, `crate::metrics::WorkerMetrics`, `crate::proxy::client_registry::UpstreamClientRegistry`, `crate::process::ipc_transport::IpcStream`, `crate::process::ipc::WorkerId`, `crate::serverless::manager::ServerlessManager`, `crate::app_server::GranianSupervisor`, `crate::mesh::{config::MeshConfig, transports::MeshTransportManager, MeshBackendPool}`, `crate::http::shared_handler::SharedRequestHandler`, `crate::http::headers`, `crate::http::response_transform::path_looks_like_image`, `crate::mesh::proxy::get_cached_regex` | `root-only for now` | Trait-based `ServerBackend` abstraction for Router/WafCore/WorkerDrainState; process-level state (IPC, serverless, mesh, app_servers) passed via builder traits | Low |
| `directory_viewer.rs` (222 lines) | Depends on admin auth, ConfigManager, static_files directory rendering, theme | `crate::admin::verify_admin_token`, `crate::config::ConfigManager`, `crate::static_files::directory::{render_directory_listing, DirectoryListingParams}`, `crate::theme::ThemeConfig` | `synvoid-static-files` | `AdminAuth` trait (shared with file_manager, webdav); `ConfigManager` access via `Arc<dyn ConfigAccessor>` | Medium |
| `file_manager.rs` (394 lines) | Depends on admin auth, ConfigManager, FileManager from static_files, MIME registry | `crate::admin::verify_admin_token`, `crate::config::ConfigManager`, `crate::static_files::file_manager::FileManager`, `crate::mime::MIME_REGISTRY`, `crate::static_files::file_manager::FileManagerConfig`, `crate::upload::rate_limit::RateLimitConfig` | `synvoid-static-files` | Same `AdminAuth` trait; MIME registry access via trait or static import | Medium |
| `file_manager_ui.rs` (363 lines) | Depends on admin auth, ConfigManager, theme rendering | `crate::admin::verify_admin_token`, `crate::config::ConfigManager`, `crate::theme::{ThemeConfig, ThemeRenderer}` | `synvoid-theme` | Same `AdminAuth` trait; theme rendering is already in `synvoid-theme` | Medium |
| `image_poisoning.rs` | **Extracted (HWS-S02)** — root file is now a `pub use synvoid_static_files::image_poisoning::*;` shim | — | `synvoid-static-files` | Done | Done |
| `webdav.rs` (773 lines) | Depends on admin auth, ConfigManager, FileManager from static_files | `crate::admin::verify_admin_token`, `crate::config::ConfigManager`, `crate::static_files::file_manager::FileManager` | `synvoid-static-files` | Same `AdminAuth` trait as directory_viewer/file_manager | Medium |

## Dependency Pattern Analysis

### Shared Pattern: Admin Auth + ConfigManager + static_files

Three modules (`directory_viewer`, `file_manager`, `webdav`) follow an identical dependency pattern:

```
crate::admin::verify_admin_token  → admin auth check
crate::config::ConfigManager      → configuration access
crate::static_files::*            → core file operations
```

All three also duplicate identical `require_auth()` functions and `unsafe impl Send/Sync` blocks. This suggests a shared extraction seam:

1. Define `AdminAuth` trait: `fn verify(token: &str, hash: &str) -> bool`
2. Define `ConfigAccessor` trait or pass `Arc<ConfigManager>` as a generic parameter
3. Move all three modules to `synvoid-static-files` behind the trait boundary

### `server.rs` Entanglement

`server.rs` is the most entangled module. It directly wires:
- **Process-level state**: IPC transport, WorkerId, ServerlessManager, GranianSupervisor
- **Feature-gated state**: MeshConfig, MeshTransportManager, MeshBackendPool (all `#[cfg(feature = "mesh")]`)
- **Core infrastructure**: Router, WafCore, FloodProtector, WorkerDrainState, UpstreamClientRegistry, ErasedHttpClient, WorkerMetrics

This module cannot be extracted without first defining trait abstractions for all of the above. It should remain root-only until the HTTP server lifecycle is redesigned around traits.

### `image_poisoning.rs` Standalone Potential

`image_poisoning.rs` is the smallest and most self-contained module (98 lines). Its only root dependency is `SiteImagePoisonConfig` (a config struct) and `PoisonImageClient` (already in `static_files`). This is the highest-priority extraction candidate — it could move to `synvoid-static-files` with minimal seam work.

## Extraction Priority Order

1. ~~**`image_poisoning.rs`** → `synvoid-static-files`~~ **Done (HWS-S02)**
2. **`directory_viewer.rs`** → `synvoid-static-files` (shared auth pattern, small module)
3. **`file_manager_ui.rs`** → `synvoid-theme` (UI-only, theme is primary dep)
4. **`file_manager.rs`** → `synvoid-static-files` (larger but follows same pattern as directory_viewer)
5. **`webdav.rs`** → `synvoid-static-files` (largest file_manager-style module, same auth seam)
6. **`server.rs`** → `root-only for now` (core infrastructure, requires trait redesign)

## Ownership Decisions (HTC-H07)

### image_poisoning.rs (DONE — HWS-S02)

| Field | Decision |
|-------|----------|
| **Module** | `image_poisoning.rs` (98 lines) |
| **Status** | **Extracted.** Canonical implementation now in `crates/synvoid-static-files/src/image_poisoning.rs`. Root file is a `pub use` compatibility shim. |
| **Result** | `synvoid-static-files` gained `moka`, `sha2`, `hex` deps. No cycle introduced. Root `src/http/mod.rs` path preserved. |

### file_manager.rs + file_manager_ui.rs

| Field | Decision |
|-------|----------|
| **Modules** | `file_manager.rs` (394 lines) + `file_manager_ui.rs` (363 lines) |
| **Target crate** | **Root-only for now** |
| **Reasoning** | Both modules depend on `crate::static_files::file_manager::FileManager` — a 1362-line root-owned type that wraps filesystem operations with upload scanning (`MalwareScanner`, `YaraScanner`), archive extraction, and rate limiting from `crate::upload`. The `FileManager` struct itself depends on `crate::config::ConfigManager` and `crate::upload::*` types. Extracting these HTTP handlers without extracting `FileManager` first would require introducing an `Arc<dyn FileManagerBackend>` trait — significant effort for two modules that form a cohesive admin surface. Additionally, `file_manager_ui.rs` depends on `ThemeRenderer` for HTML generation. |
| **Required seams** | (1) Extract `FileManager` to `synvoid-static-files` with a trait boundary for upload/scanner dependencies, OR (2) define `FileManagerBackend` trait in root and pass it via `State`. `ConfigManager` access requires `Arc<dyn ConfigAccessor>` trait. Auth already re-exported from `synvoid-admin`. |
| **Estimated effort** | **large** — requires `FileManager` extraction (1362 lines + upload dependencies) or trait abstraction before HTTP handlers can move. |
| **Dependencies that must move first** | `FileManager` (root `src/static_files/file_manager.rs`) must move to `synvoid-static-files` or be trait-abstracted. `MalwareScanner`/`YaraScanner` from `crate::upload` would also need trait boundaries. `ConfigManager` access requires a new trait seam. |

### directory_viewer.rs

| Field | Decision |
|-------|----------|
| **Module** | `directory_viewer.rs` (222 lines) |
| **Target crate** | **Root-only for now** (cohesive with file_manager group) |
| **Reasoning** | Same dependency pattern as `file_manager.rs`: depends on `ConfigManager` and admin auth. However, its core rendering logic (`render_directory_listing`) is already extracted in `synvoid-static-files::directory`. The root module adds auth checking, config access, path security (hidden file blocking), and the Axum router. While it *could* extract if `ConfigManager` were trait-abstracted, keeping it root-owned alongside `file_manager` maintains a cohesive admin file-browsing surface. Extracting one without the other would split a related feature across crates. |
| **Required seams** | Same `ConfigAccessor` trait as `file_manager`. Auth already available. `ThemeConfig` already in `synvoid-theme`. |
| **Estimated effort** | **medium** — small module, but gated by the same `ConfigManager` seam needed for `file_manager`. |
| **Dependencies that must move first** | `ConfigManager` trait abstraction (shared with `file_manager`). Should extract as a group with `file_manager`/`webdav`. |

### webdav.rs

| Field | Decision |
|-------|----------|
| **Module** | `webdav.rs` (773 lines) |
| **Target crate** | **Root-only for now** (cohesive with file_manager group) |
| **Reasoning** | Identical dependency pattern to `file_manager.rs`: `ConfigManager`, admin auth, and `FileManager`. WebDAV is a protocol extension over the same file operations that `FileManager` provides (PROPFIND, MKCOL, MOVE, COPY all delegate to `FileManager::list_directory`, `create_directory`, `rename`, etc.). Extracting WebDAV without `FileManager` would require the same trait abstraction. The XML generation (`generate_propfind_response`) is self-contained but the handler dispatch (`webdav_handler`) routes to methods that call `FileManager` directly. |
| **Required seams** | Same `ConfigAccessor` trait and `FileManager` abstraction as `file_manager`. |
| **Estimated effort** | **medium** — largest of the file-management group (773 lines), but structurally identical to `file_manager.rs`. |
| **Dependencies that must move first** | `FileManager` extraction or trait abstraction (shared with `file_manager`). Should extract as a group. |

### Summary: The file-management cluster

`file_manager.rs`, `file_manager_ui.rs`, `directory_viewer.rs`, and `webdav.rs` form a **cohesive admin file-management surface** with identical dependency patterns:

```
verify_admin_token  ← already in synvoid-admin
ConfigManager       ← root-only, needs trait abstraction
FileManager         ← root-only, needs extraction or trait abstraction
ThemeConfig/Renderer ← already in synvoid-theme
MIME_REGISTRY       ← already in synvoid-app-handlers
```

**Recommended extraction path (future pass):**
1. Define `trait FileManagerBackend` with the methods used by all four modules (`list_directory`, `read_file`, `write_file`, `delete`, `rename`, `create_directory`, etc.)
2. Define `trait ConfigAccessor` for the limited config reads these modules perform
3. Move all four modules as a group to `synvoid-static-files` behind these trait boundaries
4. Root passes concrete `FileManager` and `ConfigManager` implementations via `State`

This is **not** the current pass — these modules stay root-only until the trait seams exist.
