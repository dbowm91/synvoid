# HTC-H08: `src/http/server.rs` Concrete Dependency Inventory

> Generated from `src/http/server.rs` (494 lines) and submodules
> `server/accept_loop.rs` (193 lines), `server/connection_types.rs` (142 lines),
> `server/observability.rs` (93 lines).

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
