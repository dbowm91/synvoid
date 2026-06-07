# HTC-H08: `src/http/server.rs` Concrete Dependency Inventory

> Generated from `src/http/server.rs` (491 lines) and submodules
> `server/accept_loop.rs` (193 lines), `server/connection_types.rs` (142 lines),
> `server/observability.rs` (93 lines).
>
> Updated 2026-06-07: MDM-H01 — refreshed concrete dependency inventory; MDM-H02 import
> replacements applied; MDM-H03 ownership policy decision.

## Summary

The `HttpServer` struct and its submodules depend on **15 distinct concrete root dependencies**
from outside `synvoid-http`. Of these, **5 already have trait seams** in external crates that
are already wired through the generic type parameters of `prepare_http_request_flow` and
`handle_http_request_postlude`. The remaining **10 are direct concrete usages** without
existing trait seams.

## Concrete Dependency Table

| # | Concrete Dependency | Location (line) | Existing Trait/Seam | Can Replace Now? | Required Adapter | Notes |
|---|---------------------|-----------------|---------------------|------------------|------------------|-------|
| 1 | `crate::router::Router` | `server.rs:50` | `synvoid_proxy::routing::RouteResolver` / `RouterRouteResolver` | **Partially** — synvoid-http already uses `synvoid_proxy::Router` directly as a concrete type in its function signatures. Server.rs re-exports the same concrete type via `crate::router::Router` (which is `pub use synvoid_proxy::router::*`). | None needed — already the same type | `Router` is a concrete struct, not behind a trait. The `RouteResolver` trait exists but is not used by synvoid-http's flow/postlude functions. |
| 2 | `crate::waf::WafCore` | `server.rs:51` | `synvoid_http::BufferedRequestWaf`, `RequestBodyWaf`, `UploadValidationWaf`, `WafErrorPageRenderer`, `synvoid_proxy::protocol::trait_def::WafCoreBackend` | **Yes** — already generic `W` in `prepare_http_request_flow<W>` and `handle_http_request_postlude<W>`. Server.rs passes `Arc<WafCore>` which satisfies all trait bounds. | None — already wired | `WafCore` implements all 5 required traits. The generic bounds are: `W: BufferedRequestWaf + RequestBodyWaf<StreamingScanner=S>`, and postlude: `W: BufferedRequestWaf + WafCoreBackend + UploadValidationWaf + WafErrorPageRenderer`. |
| 3 | `crate::waf::FloodProtector` | `server.rs:51` | **None** | **No** — no trait seam exists. Used directly in `accept_loop.rs:50-62` via `fp.check_tcp_connection(client_ip)`. | Would need a `FloodChecker` trait | Called only in the accept loop for per-connection flood decisions. Low coupling surface. |
| 4 | `crate::waf::FloodDecision` | `server.rs:51` | **None** | **No** — enum used directly in accept_loop. | None if FloodProtector gets a trait | Simple enum (`Blackholed`, `RateLimited`, `Allowed`). |
| 5 | `crate::metrics::WorkerMetrics` | `server.rs:48` | `synvoid_core::metrics::MetricsSink` | **No** — `MetricsSink` has 5 basic methods but `WorkerMetrics` has 20+ additional methods (e.g., `record_request_queue_time_ms`, `record_site_request_start`, `record_inline_cpu_phase_time_ms`). The `MetricsSink` trait is too narrow. | Would need a much broader `WorkerMetrics` trait or extend `MetricsSink` significantly | synvoid-http's flow/postlude also use `WorkerMetrics` directly as a concrete type (`&Option<Arc<WorkerMetrics>>`). Not behind a generic. |
| 6 | `crate::worker::drain_state::WorkerDrainState` | `server.rs:52` | `synvoid_http::HttpDrainControl` | **Yes** — already generic `D` in `prepare_http_request_flow<D>` and `handle_http_request_postlude`. `WorkerDrainState` implements `HttpDrainControl` at `worker/drain_state.rs:260`. | None — already wired | `DrainGuard` in `connection_types.rs:123-141` also uses `WorkerDrainState` directly (calls `increment_active`/`decrement_active`). |
| 7 | `crate::http_client::HttpClient` | `server.rs:41` | **None** | **No** — concrete struct used as `client: HttpClient` field and passed to postlude. | Would need an `HttpClient` trait | Created via `create_http_client_with_config()` at `server.rs:91`. |
| 8 | `crate::http_client::ErasedHttpClient` | `server.rs:25` | **None** | **No** — concrete struct stored as field and passed through. | Would need an `ErasedHttpClient` trait | Already type-erased internally (uses `Box<dyn ...>` inside). |
| 9 | `crate::proxy::client_registry::UpstreamClientRegistry` | `server.rs:49` | **None** | **No** — concrete struct used directly. | Would need a trait | Created as `UpstreamClientRegistry::new()` at `server.rs:122`. Passed to postlude. |
| 10 | `crate::config::HttpConfig` | `server.rs:36` | **None** | **No** — config struct used directly. | None expected — config types are typically concrete | Used for `max_connections`, `header_read_timeout_secs`, `max_headers`, `max_request_size`, `strict_protocol_validation`. |
| 11 | `crate::config::MainConfig` | `server.rs:37` | **None** | **No** — config struct used directly. | None expected — config types are typically concrete | Passed through to flow/postlude functions. |
| 12 | `crate::mesh::config::MeshConfig` | `server.rs:43` | **None** | **No** — cfg-gated (`#[cfg(feature = "mesh")]`). | None expected | Only used when `mesh` feature is enabled. synvoid-http uses `synvoid_mesh::MeshConfig` directly. |
| 13 | `crate::mesh::transports::MeshTransportManager` | `server.rs:45` | **None** | **No** — cfg-gated. | None expected | synvoid-http uses `synvoid_mesh::transports::MeshTransportManager` directly. |
| 14 | `crate::mesh::MeshBackendPool` | `server.rs:47` | **None** | **No** — cfg-gated. | None expected | synvoid-http uses `synvoid_mesh::MeshBackendPool` directly. |
| 15 | `crate::serverless::manager::ServerlessManager` | `server.rs:73` | **None** | **No** — concrete struct used directly. | None expected | synvoid-http uses `synvoid_serverless::ServerlessManager` directly. |
| 16 | `crate::app_server::GranianSupervisor` | `server.rs:75` | **None** | **No** — concrete struct in `HashMap<String, Arc<GranianSupervisor>>`. | None expected | synvoid-http uses `synvoid_app_server::GranianSupervisor` directly. |
| 17 | `crate::plugin::PluginManager` | `server.rs:312` | `synvoid_http::WasmFilterBackend`, `synvoid_http::AxumDynamicRouterLookup` | **Yes** — used via `downcast_ref` and cast to trait objects. Already behind trait objects. | None — already wired | Obtained from `Router::plugin_manager()` which returns `Option<Arc<dyn Any + Send + Sync>>`. |
| 18 | `crate::platform::socket::bind_tcp_reuse` | `accept_loop.rs:26` | **None** | **No** — platform-specific function. | None expected | Platform socket binding is inherently concrete. |

## Internal Module Dependencies (within `src/http/`)

These are dependencies on sibling modules within the same crate — not root dependencies, but relevant for cohesion analysis.

| Dependency | Location (line) | Module | Notes |
|------------|-----------------|--------|-------|
| `crate::http::shared_handler::SharedRequestHandler` | `server.rs:24` | `shared_handler` | `#[allow(unused_imports)]` — not actually used in server.rs |
| `crate::http::headers` | `server.rs:39` | `headers` | `#[allow(unused_imports)]` — not actually used in server.rs |
| `crate::http::response_builder::build_response_with_alt_svc` | `server.rs:256` | `response_builder` | Used in error path (503 response) |
| `crate::http::apply_image_poisoning` | `server.rs:361` | `image_poisoning` | Passed as closure to postlude |
| `crate::http::response_transform::path_looks_like_image` | `server.rs:373` | `response_transform` | Test-only import |
| `crate::http_client::create_http_client_with_config` | `server.rs:41` | `http_client` | Creates the `HttpClient` instance |
| `crate::http_client::send_request_via_quic_tunnel` | `server.rs:350` | `http_client` | Passed as closure to postlude |

## IPC/Process Dependencies

| Dependency | Location (line) | Notes |
|------------|-----------------|-------|
| `crate::process::ipc_transport::IpcStream` | `server.rs:71`, `accept_loop.rs:17`, `observability.rs:11` | Concrete IPC stream type. synvoid-http uses `synvoid_ipc::AsyncIpcStream`. |
| `crate::process::ipc::WorkerId` | `server.rs:72`, `accept_loop.rs:18`, `observability.rs:10` | Concrete worker ID type. synvoid-http uses `synvoid_ipc::WorkerId`. |
| `crate::process::Message::WorkerRequestLog` | `observability.rs:87` | IPC message variant |
| `crate::process::current_timestamp` | `observability.rs:9` | Timestamp utility |
| `crate::utils::safe_unix_timestamp` | `observability.rs:51` | Timestamp utility |
| `crate::metrics::RequestLogPayload` | `observability.rs:8` | Request log payload struct |
| `crate::RunningFlag` | `connection_types.rs:7` | Utility for connection drop tracking |

## Observations

1. **synvoid-http already uses generics for WAF and drain control.** The `prepare_http_request_flow<W, D, S>` and `handle_http_request_postlude<W>` functions accept generic type parameters bounded by traits (`BufferedRequestWaf`, `HttpDrainControl`, etc.). `server.rs` satisfies these with concrete types (`WafCore`, `WorkerDrainState`).

2. **synvoid-http does NOT use generics for metrics, router, HTTP client, or config.** These are passed as concrete types (`&Arc<Router>`, `&Option<Arc<WorkerMetrics>>`, `HttpClient`, `HttpConfig`, `MainConfig`). This means `server.rs` must depend on these concrete types even though they come from external crates.

3. **The `FloodProtector` is the only WAF-related dependency without a trait seam.** It is only used in the accept loop for per-connection decisions, making it a small coupling surface.

4. **`HttpClient` is used both as a concrete field and passed by value.** The postlude takes it by reference (`&client`), but it is cloned per-connection in the accept loop.

5. **`ErasedHttpClient` is already type-erased internally** but is still a concrete struct in `server.rs`. It is passed to the postlude but not used there (prefixed with `_`).

6. **Mesh dependencies are cleanly cfg-gated** and follow the same pattern as their non-mesh counterparts.

7. **`SharedRequestHandler` and `headers` imports are unused** (`#[allow(unused_imports)]`). These are dead imports that should be cleaned up.

## Replacement Candidates (by priority)

| Priority | Dependency | Action | Effort |
|----------|------------|--------|--------|
| Low | `SharedRequestHandler`, `headers` | Remove unused imports | Trivial |
| Low | `FloodProtector` | Create `FloodChecker` trait in `synvoid-waf` or `synvoid-core` | Small |
| Medium | `WorkerMetrics` | Extend `MetricsSink` trait or create `WorkerMetricsSink` trait | Medium — 20+ methods to abstract |
| Medium | `HttpClient` | Create `HttpClientBackend` trait | Medium — used by-value and by-ref |
| High | Already wired: `WafCore`, `WorkerDrainState`, `PluginManager` | No action needed | None |

## Files Analyzed

- `src/http/server.rs` (494 lines) — main `HttpServer` struct and `handle_request`
- `src/http/server/accept_loop.rs` (193 lines) — TCP accept loop
- `src/http/server/connection_types.rs` (142 lines) — connection protocol validation and drain guard
- `src/http/server/observability.rs` (93 lines) — request log rate limiting and IPC dispatch

## Decision: KEEP_ROOT_UNTIL_WORKER_CONTEXT_REWORK

Rationale: server.rs has 14 concrete root dependencies without trait seams.
The existing trait seams (WafCore→WafProcessor, WorkerDrainState→DrainState) are
already wired through generics. The remaining dependencies (Router, WorkerMetrics,
HttpClient, FloodProtector, config types, IPC/process, mesh, serverless, app_server)
would require broad trait redesigns that should be part of a dedicated server-runtime
context pass.

Recommended next steps:
1. Create FloodChecker trait in synvoid-waf (small, low coupling)
2. Extend MetricsSink or create WorkerMetricsSink trait (medium, 20+ methods)
3. Create HttpClientBackend trait (medium, used by-value and by-ref)
4. Move config types to synvoid-config or create ConfigAccessor trait
5. Define ServerBackend trait for process-level state (IPC, serverless, mesh, app_server)

---

# MDM-H01: Refreshed Concrete Dependency Inventory (2026-06-07)

> Wave H, Task H01. Refreshed inventory for `src/http/server.rs` and its three
> submodules (`accept_loop.rs`, `connection_types.rs`, `observability.rs`).
> Counts all distinct concrete dependencies and classifies whether each can
> already be replaced by an extracted-crate import without behaviour change.

## Count summary

| Class | Count |
|-------|-------|
| Total distinct concrete dependencies (across `src/http/server.rs` and its 3 submodules) | 30 |
| Already in extracted crate (clean root → crate import possible) | 23 |
| Not clean (function depends on root-only types) | 1 (`send_request_via_quic_tunnel`) |
| Still root-owned (cannot replace without trait reworks) | 4 (`WafCore`, `WorkerDrainState`, `PluginManager`, `bind_tcp_reuse`) |
| Trivially already canonical (`synvoid_http::*`) | 2 (`synvoid_http::response_builder::build_response_with_alt_svc`, `synvoid_http::response_transform::path_looks_like_image`) |

The 4 still-root-only items are the structural blockers for moving `src/http/server.rs`
into a crate:

- `WafCore` — root struct in `src/waf/mod.rs`; `Http3RequestWaf::check_request_full`
  body lives there. Plan §2 defers WafCore extraction.
- `WorkerDrainState` — root struct in `src/worker/drain_state.rs`. `DrainGuard` calls
  `increment_active` / `decrement_active` directly on the struct. Plan §2 defers
  worker movement.
- `PluginManager` — root struct in `src/plugin/mod.rs`. `synvoid_plugin_runtime` has
  a same-named struct but it is not publicly re-exported.
- `bind_tcp_reuse` — root platform utility (thin shim over `synvoid_platform`).

Every other `crate::...` import (e.g. `crate::config::*`, `crate::http_client::*`,
`crate::metrics::*`, `crate::router::*`, `crate::mesh::*`, `crate::serverless::*`,
`crate::app_server::*`, `crate::process::ipc*`, `crate::utils::*`,
`crate::RunningFlag`, `crate::http::apply_image_rights_marking`,
`crate::http::response_builder::*`, `crate::metrics::record_http_request_latency`)
is a thin re-export of an already-extracted crate and was successfully replaced
during the MDM-H02 pass below.

## Refreshed Concrete Dependency Table

| # | Concrete dependency | Location (line) | Existing seam | Remaining blocker | Move impact | Notes |
|---|---------------------|-----------------|---------------|-------------------|-------------|-------|
| 1 | `crate::waf::WafCore` | server.rs:47, 55, 83, 99, 196, 227, 278, 321 | `BufferedRequestWaf` + `RequestBodyWaf` + `UploadValidationWaf` + `WafErrorPageRenderer` + `WafCoreBackend` + `Http3RequestWaf` (all 6 implemented in root) | **Root-owned concrete.** `Http3RequestWaf::check_request_full` body lives in `src/waf/mod.rs`. | Cannot move without extracting `WafCore` itself (deferred by plan §2). | All 5 WAF traits are bound through `HttpServer`'s call sites; root stays the owner. |
| 2 | `crate::waf::FloodProtector` | server.rs:47, 56, 100, 147, 198; accept_loop.rs:9, 50–62 | None | None — **clean** | Replace with `synvoid_waf::FloodProtector` (root shim at `src/waf/flood/mod.rs` already does `pub use synvoid_waf::flood::*`). | Re-export is mechanically clean. |
| 3 | `crate::waf::FloodDecision` | server.rs:47; accept_loop.rs:52, 56, 60 | None | None — **clean** | Replace with `synvoid_waf::FloodDecision`. | Value enum in synvoid-waf. |
| 4 | `crate::router::Router` | server.rs:46, 54, 82, 98, 195, 226, 277, 307, 311, 320 | `RouteResolver` trait exists in synvoid-proxy but `synvoid-http`'s flow/postlude still take `&Arc<Router>` concretely | None — **clean** for the import itself; concrete `&Arc<Router>` stays | Replace with `synvoid_proxy::Router` (root shim at `src/router.rs` is just `pub use synvoid_proxy::router::*`). | The `RouteResolver` decoupling is a separate, broader refactor. |
| 5 | `crate::metrics::WorkerMetrics` | server.rs:45, 67, 132, 235, 263, 326 | `MetricsSink` trait in synvoid-core (5 methods) | `WorkerMetrics` exposes 20+ methods; the `MetricsSink` trait is too narrow | Replace with `synvoid_metrics::WorkerMetrics` (root re-exports `pub use synvoid_metrics::*`). | `record_request_queue_time_ms` is called at server.rs:264. |
| 6 | `crate::worker::drain_state::WorkerDrainState` | server.rs:48, 62, 106, 157, 202, 231, 306; connection_types.rs:6, 124, 128, 137 | `HttpDrainControl` trait in synvoid-http (already wired) | **Root-owned concrete.** `DrainGuard` calls `increment_active` / `decrement_active` directly on the struct. | Cannot move without extracting `WorkerDrainState` itself. | `D: HttpDrainControl` already covers the flow/postlude code paths. |
| 7 | `crate::http_client::HttpClient` | server.rs:38, 57, 88, 101, 197, 228, 322 | None | None — **clean** | Replace with `synvoid_http_client::HttpClient`. | Root shim `src/http_client/mod.rs` is `pub use synvoid_http_client::*`. |
| 8 | `crate::http_client::create_http_client_with_config` | server.rs:38, 88 | None | None — **clean** | Replace with `synvoid_http_client::create_http_client_with_config`. | Same shim. |
| 9 | `crate::http_client::ErasedHttpClient` | server.rs:23, 76, 120, 246 | None | None — **clean** | Replace with `synvoid_http_client::ErasedHttpClient`. | Same shim. |
| 10 | `crate::config::HttpConfig` | server.rs:34, 59, 84, 103, 199, 232, 281, 325 | None | None — **clean** | Replace with `synvoid_config::http::HttpConfig`. | Root shim `src/config/mod.rs` re-exports `pub use synvoid_config::*`. |
| 11 | `crate::config::MainConfig` | server.rs:35, 61, 86, 105, 201, 230, 280, 324; observability.rs:7 | None | None — **clean** | Replace with `synvoid_config::MainConfig`. | Same shim. |
| 12 | `crate::mesh::config::MeshConfig` | server.rs:40, 64, 108, 163, 204, 233, 289 | None | None — **clean** | Replace with `synvoid_mesh::MeshConfig`. | Root shim `src/mesh/mod.rs` is `pub use synvoid_mesh::mesh::*`. |
| 13 | `crate::mesh::transports::MeshTransportManager` | server.rs:42, 66, 110, 169, 206, 234, 291 | None | None — **clean** | Replace with `synvoid_mesh::transports::MeshTransportManager`. | Same shim. |
| 14 | `crate::mesh::MeshBackendPool` | server.rs:44, 74, 118, 185, 214, 244, 341 | None | None — **clean** | Replace with `synvoid_mesh::MeshBackendPool`. | Same shim. |
| 15 | `crate::serverless::manager::ServerlessManager` | server.rs:70, 126, 211, 239, 293, 337 | None | None — **clean** | Replace with `synvoid_serverless::ServerlessManager`. | Root re-exports `pub use synvoid_serverless::*`. |
| 16 | `crate::app_server::GranianSupervisor` | server.rs:72, 177, 212, 242 | None | None — **clean** | Replace with `synvoid_app_server::GranianSupervisor`. | Root re-exports `pub use synvoid_app_server::*`. |
| 17 | `crate::plugin::PluginManager` | server.rs:309, 313 (downcast) | `WasmFilterBackend` + `AxumDynamicRouterLookup` trait objects (cast at use site) | **Root-owned concrete** (`pub struct PluginManager` in `src/plugin/mod.rs`). `synvoid_plugin_runtime` has a same-named struct but it is *not* re-exported by `synvoid_plugin_runtime::lib.rs`. | Cannot move without extracting `PluginManager` itself. | The cast is already trait-based; only the downcast target is concrete. |
| 18 | `crate::http::apply_image_rights_marking` | server.rs:358 (inline call) | None | None — **clean** | Replace inline call with `synvoid_static_files::image_rights::apply_image_rights_marking` (root re-exports via `src/http/image_rights.rs` → `synvoid_static_files::image_rights::*`). | |
| 19 | `crate::http_client::send_request_via_quic_tunnel` | server.rs:347 (inline closure) | None | **Not clean** — the function lives in root's `src/http_client/quic_tunnel_dispatch.rs` and depends on `crate::tunnel::quic` (root-owned). The extracted crate `synvoid_http_client` does not have it. | Cannot move without extracting the QUIC tunnel module first (separate task). | Stop condition hit during H02; reverted and left as `crate::http_client::send_request_via_quic_tunnel`. |
| 20 | `crate::metrics::record_http_request_latency` | server.rs:361 (inline) | None | None — **clean** | Replace with `synvoid_metrics::record_http_request_latency`. | |
| 21 | `crate::http::response_builder::build_response_with_alt_svc` | server.rs:253 (inline) | None | None — **clean** | Replace with `synvoid_http::response_builder::build_response_with_alt_svc`. | Already canonical in synvoid-http. |
| 22 | `crate::http::response_transform::path_looks_like_image` | server.rs:371 (test) | None | None — **clean** | Replace with `synvoid_http::response_transform::path_looks_like_image`. | Already canonical in synvoid-http. |
| 23 | `crate::process::ipc_transport::IpcStream` | server.rs:68, 138, 209, 237; observability.rs:11 | None | None — **clean** | Replace with `synvoid_ipc::AsyncIpcStream`. | Root re-exports `pub use synvoid_ipc::*`. |
| 24 | `crate::process::ipc::WorkerId` | server.rs:69, 140, 209, 238; observability.rs:10 | None | None — **clean** | Replace with `synvoid_ipc::WorkerId`. | Root re-exports `pub use synvoid_ipc::*`. |
| 25 | `crate::metrics::RequestLogPayload` | observability.rs:8 | None | None — **clean** | Replace with `synvoid_metrics::RequestLogPayload`. | Root re-exports `pub use synvoid_metrics::*`. |
| 26 | `crate::process::current_timestamp` | observability.rs:9 | None | None — **clean** | Replace with `synvoid_utils::current_timestamp` (or equivalent in synvoid-utils / synvoid-mesh). | Used at observability.rs:72. |
| 27 | `crate::utils::safe_unix_timestamp` | observability.rs:51 | None | None — **clean** | Replace with `synvoid_utils::safe_unix_timestamp` (`synvoid_mesh` re-exports it). | |
| 28 | `crate::platform::socket::bind_tcp_reuse` | accept_loop.rs:26 | None | **Root platform utility** | Cannot move without extracting `synvoid-platform`'s socket module (already done — the function lives at `src/platform/socket.rs:381` which is a thin shim over `synvoid_platform`). | The shim itself could be deleted; this is a root-side cleanup, not a server-blocker. |
| 29 | `crate::RunningFlag` | connection_types.rs:7 | None | None — **clean** | Replace with `synvoid_utils::RunningFlag` (verify export). | Small util re-export. |
| 30 | `crate::mesh::proxy::get_cached_regex` | server.rs:370 (test) | None | None — **clean** | Replace with `synvoid_mesh::proxy::get_cached_regex` (root re-exports `pub use synvoid_mesh::mesh::*`). | Test-only. |

**Summary by class:**
- **Root-only (4):** `WafCore`, `WorkerDrainState`, `PluginManager`, `bind_tcp_reuse`.
- **Not clean (1):** `send_request_via_quic_tunnel` (function lives in root's
  `src/http_client/quic_tunnel_dispatch.rs` and depends on root's
  `crate::tunnel::quic`).
- **Clean (23):** every other `crate::...` import inside `src/http/server.rs`
  and its submodules is a thin re-export of an already-extracted crate and was
  successfully replaced during the MDM-H02 pass.

---

# MDM-H02: Import Replacements (2026-06-07)

> Wave H, Task H02. Replaced obvious root → extracted-crate imports in
> `src/http/server.rs`, `src/http/server/observability.rs`, and
> `src/http/server/connection_types.rs`. Submodule `accept_loop.rs` was left
> unchanged because it only references `super::*` plus one root platform call
> (`crate::platform::socket::bind_tcp_reuse`).

## Replacement list (before → after)

| File:line | Before | After |
|-----------|--------|-------|
| `src/http/server.rs:23` | `use crate::http_client::ErasedHttpClient;` | `use synvoid_http_client::ErasedHttpClient;` |
| `src/http/server.rs:34` | `use crate::config::HttpConfig;` | `use synvoid_config::http::HttpConfig;` |
| `src/http/server.rs:35` | `use crate::config::MainConfig;` | `use synvoid_config::MainConfig;` |
| `src/http/server.rs:38` | `use crate::http_client::{create_http_client_with_config, HttpClient};` | `use synvoid_http_client::{create_http_client_with_config, HttpClient};` |
| `src/http/server.rs:40` | `use crate::mesh::config::MeshConfig;` | `use synvoid_mesh::config::MeshConfig;` |
| `src/http/server.rs:42` | `use crate::mesh::transports::MeshTransportManager;` | `use synvoid_mesh::transports::MeshTransportManager;` |
| `src/http/server.rs:44` | `use crate::mesh::MeshBackendPool;` | `use synvoid_mesh::MeshBackendPool;` |
| `src/http/server.rs:45` | `use crate::metrics::WorkerMetrics;` | `use synvoid_metrics::WorkerMetrics;` |
| `src/http/server.rs:46` | `use crate::router::Router;` | `use synvoid_proxy::Router;` |
| `src/http/server.rs:47` | `use crate::waf::{FloodDecision, FloodProtector, WafCore};` | `use synvoid_waf::{FloodDecision, FloodProtector};` (then `use crate::waf::WafCore;` on a new line — see below) |
| `src/http/server.rs:47` (split) | n/a | `use crate::waf::WafCore;` (root-owned, stays) |
| `src/http/server.rs:48` | `use crate::worker::drain_state::WorkerDrainState;` | **unchanged** (root-owned) |
| `src/http/server.rs:49` | `use synvoid_proxy::UpstreamClientRegistry;` | **unchanged** (already canonical) |
| `src/http/server.rs:253` | `synvoid_http::response_builder::build_response_with_alt_svc(...)` (already canonical) | **unchanged** |
| `src/http/server.rs:309, 313` | `pm.downcast_ref::<crate::plugin::PluginManager>()` | **unchanged** (root-owned `PluginManager`) |
| `src/http/server.rs:347` | `crate::http_client::send_request_via_quic_tunnel(...)` | **unchanged** (see Stop Conditions) — the function is defined in `src/http_client/quic_tunnel_dispatch.rs` and depends on `crate::tunnel::quic`, so it is not a clean extracted-crate replacement. |
| `src/http/server.rs:358` | `crate::http::apply_image_rights_marking(...)` | `synvoid_static_files::image_rights::apply_image_rights_marking(...)` |
| `src/http/server.rs:361` | `crate::metrics::record_http_request_latency` | `synvoid_metrics::record_http_request_latency` |
| `src/http/server.rs:370` | `use crate::mesh::proxy::get_cached_regex;` (test) | `use synvoid_mesh::proxy::get_cached_regex;` (test) |
| `src/http/server.rs:371` | `use synvoid_http::response_transform::path_looks_like_image;` (test, already canonical) | **unchanged** |
| `src/http/server/observability.rs:7` | `use crate::config::MainConfig;` | `use synvoid_config::MainConfig;` |
| `src/http/server/observability.rs:8` | `use crate::metrics::RequestLogPayload;` | `use synvoid_metrics::RequestLogPayload;` |
| `src/http/server/observability.rs:9` | `use crate::process::current_timestamp;` | `use synvoid_utils::current_timestamp;` |
| `src/http/server/observability.rs:10` | `use crate::process::ipc::WorkerId;` | `use synvoid_ipc::WorkerId;` |
| `src/http/server/observability.rs:11` | `use crate::process::ipc_transport::IpcStream;` | `use synvoid_ipc::AsyncIpcStream as IpcStream;` |
| `src/http/server/observability.rs:51` | `crate::utils::safe_unix_timestamp()` (inline) | `synvoid_utils::safe_unix_timestamp()` (inline) |
| `src/http/server/observability.rs:72` | `crate::process::current_timestamp` (inline) | `synvoid_utils::current_timestamp` (inline) |
| `src/http/server/observability.rs:87` | `crate::process::Message::WorkerRequestLog` (inline) | `synvoid_ipc::Message::WorkerRequestLog` (inline) |
| `src/http/server/connection_types.rs:7` | `use crate::RunningFlag;` | `use synvoid_utils::RunningFlag;` |

## Stop conditions hit

One stop condition was hit: the `crate::http_client::send_request_via_quic_tunnel`
inline call (server.rs:347) is **not** a clean extracted-crate replacement. The
function is defined in `src/http_client/quic_tunnel_dispatch.rs` and depends on
`crate::tunnel::quic` (root-owned). `synvoid_http_client` does not export it.
That call site was reverted to `crate::http_client::send_request_via_quic_tunnel`
and documented in the dependency table as "not clean".

All other replacements passed `cargo check --lib --no-default-features` and
`cargo check --no-default-features --features mesh,dns`.

The hard rules in the plan §2 explicitly forbid:
- Changing `HttpServer` generics (none touched),
- Modifying worker construction flow (none touched),
- Moving `src/http/server.rs` (file location unchanged),
- Refactoring unrelated code (no refactors; only imports + 3 inline call sites).

The `HttpServer` struct continues to take `Arc<Router>`, `Arc<WafCore>`, `HttpClient`,
`Arc<UpstreamClientRegistry>`, `Arc<WorkerDrainState>`, etc. by concrete type — none
of those types changed, only the import paths.

## Validation commands run

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

Both pass. See "Validation" section at the bottom of this file for results.

---

# MDM-H03: HTTP Server Ownership Policy (2026-06-07)

## Decision: `KEEP_ROOT_AS_COMPOSITION_LAYER`

### Justification

- **No measured hot-edit data:** The plan §6 explicitly defers a move of
  `src/http/server.rs` until compile-time measurements and dependency-inventory
  work show a frequent hot-edit path. This task is the inventory pass; no
  `cargo build --timings` data is available yet for `src/http/server.rs`
  specifically, so the default `KEEP_ROOT_AS_COMPOSITION_LAYER` applies.
- **Concrete deps already reduced (23 of 30 are clean, 1 not clean, 4 root-only):**
  After H02, every type in `src/http/server.rs` (and its submodules) that is
  *not* root-owned is now imported directly from its extracted crate (23 of
  30). The four remaining root-only blockers (`WafCore`, `WorkerDrainState`,
  `PluginManager`, `bind_tcp_reuse`) are all explicitly deferred by plan §2:
  WafCore may not be moved; WorkerDrainState is part of worker (also off-limits);
  `PluginManager` is a root struct in `src/plugin/mod.rs`; `bind_tcp_reuse` is
  a thin shim over `synvoid_platform`. One further item (`send_request_via_quic_tunnel`)
  is not a clean replacement because it depends on root's `crate::tunnel::quic`.
- **Composition-layer status:** `HttpServer::new` (and its `with_*` builder
  methods) is the single place in the workspace that wires together
  WAF, router, HTTP client, IPC, drain state, mesh, serverless, app-server,
  plugin manager and metrics. That wiring is *intentionally* a composition
  concern, and the worker (which is the next orchestrator layer up) needs
  to keep `HttpServer` close to its own code because `WorkerDrainState`,
  `WorkerMetrics`, and `IpcStream` are all worker-owned.
- **`HttpServer` generics unchanged:** The hard rule "do not change `HttpServer`
  generics" was honoured. None of the call sites that change during H02 alter
  the public type signature of `HttpServer::new`, `with_*`, or `handle_request`.

### Conditions that would change this decision

- A measured compile-time regression on `src/http/server.rs` showing it is on
  a hot rebuild path *and* the four root-only blockers are removed. (Currently
  the file is 491 lines plus 428 lines of submodules — not particularly hot
  relative to e.g. `src/worker/unified_server/` at 4+ modules.)
- Completion of a separate WorkerContext / ServerBackend trait pass that
  abstracts `WafCore`, `WorkerDrainState`, and `PluginManager` behind traits
  such that `HttpServer` can be parameterised on those traits instead of
  holding concrete types. Until then, moving `server.rs` to its own crate
  would only relocate the dependencies, not remove them.

### Recommended follow-up tasks

1. Run the Wave M compile-timing script (`scripts/measure_compile_paths.sh`,
   MDM-M01) and capture the rebuild cost of editing `src/http/server.rs`.
2. Defer the actual movement of `server.rs` to a follow-up "ServerBackend
   trait" task that abstracts `WafCore`, `WorkerDrainState`, and
   `PluginManager`.
3. If measurements show the file is a hot edit path even after trait
   abstractions, re-evaluate as `MOVE_NOW_NOT_RECOMMENDED` → `MOVE_LATER_AFTER_RUNTIME_CONTEXT`.

### Validation

```bash
cargo check --workspace --all-targets   # final validation per plan §6
```

Results captured at the bottom of this file.

