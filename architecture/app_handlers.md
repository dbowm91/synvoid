# Application Handlers

SynVoid provides built-in, optimized handlers for various application types, allowing it to serve content directly or interface efficiently with specialized backends.

## 1. Static File Handler

> **Scope note:** static-file serving is canonically owned by `synvoid-static-files`
> (`crates/synvoid-static-files/src/lib.rs:44`); this section describes how app-handler
> dispatch reaches it. See [`static_files.md`](./static_files.md) for the full deep dive.

The `StaticFileHandler` (`crates/synvoid-static-files/src/lib.rs:44`) is a high-performance engine for serving static assets. It includes features typically found in standalone web servers:

- **Directory Listings:** Automatically generates index pages for directories with configurable themes.
- **Path Normalization:** Protects against path traversal attacks by resolving and validating paths before access.
- **MIME Type Mapping:** Automatic content-type detection based on file extensions.
- **Caching & Compression:** Supports `gzip` and `brotli` pre-compression and integrates with the internal proxy cache.
- **IPC Delegation:** Heavy operations (CSS/JS minification, image compression) are delegated to CPU offload workers via IPC for background processing. The legacy `StaticWorker` IPC names remain as compatibility aliases.

## 2. FastCGI & PHP-FPM

SynVoid handles dynamic PHP applications by interfacing directly with PHP-FPM (or any FastCGI-compliant backend).

- **Unix Socket & TCP Support:** Can connect to PHP-FPM via local Unix domain sockets for maximum performance or over TCP for remote backends.
- **Environment Management:** Automatically populates FastCGI environment variables (e.g., `SCRIPT_FILENAME`, `QUERY_STRING`) required for PHP execution.
- **Response Streaming:** Efficiently streams responses from the FastCGI backend via `crates/synvoid-app-handlers/src/fastcgi/streaming.rs`.
- **PHP specialization:** FPM socket auto-detection, INI forwarding, and location config merging live in
  `crates/synvoid-app-handlers/src/php/` — see [`php.md`](./php.md) for the full deep dive.

## 3. Python (Granian)

SynVoid includes built-in support for Python ASGI/WSGI applications using the **Granian** application server (`crates/synvoid-app-server/src/granian.rs`).

- **GranianSupervisor:** Full process management struct that spawns and monitors Granian instances as child processes (`GranianSupervisor`).
- **GranianConfig:** Runtime configuration struct for Granian deployment settings (defined at `crates/synvoid-app-server/src/granian.rs`). Note: This is distinct from `AppServerConfig` in `crates/synvoid-config/src/app_server.rs` which is the TOML-parsed configuration; GranianConfig is the resolved runtime type.
- **Auto-install Support:** Granian can be automatically installed if not present.
- **Admin API Endpoints:** Granian instances are manageable via the Admin API.
- **Unix Socket IPC:** Communication between the Worker and Granian happens over local Unix sockets, bypassing the overhead of the network stack.
- **Simplified Deployment:** Allows deploying Django, Flask, or FastAPI applications with a single configuration file.

Verification: `rg "granian" src/` returns 70+ matches across the codebase.

## 4. Serverless WASM (Edge Functions)

For high-performance, sandboxed edge computing, SynVoid integrates a WebAssembly (WASM) runtime.

- **Wasmtime Integration:** Uses the industry-standard `wasmtime` engine for executing WASM modules.
- **Instance Pooling:** Maintains a pool of pre-initialized WASM instances to eliminate cold start latency. (Note: Instance pooling is supported for WAF plugins; the Spin runtime does not use instance pooling.)

**Serverless InstancePool (APP-3):**
The `InstancePool` at `crates/synvoid-serverless/src/instance_pool.rs:11` provides sophisticated pooling:
- Per-function instance pools with `min_instances` / `max_instances` bounds
- Idle timeout eviction (default 5 minutes)
- Autoscaling based on utilization thresholds (10s tick)
- Pre-warm on startup via `initialize()` method
- Cold start tracking and metrics
- **Resource Isolation:** Enforces strict limits on CPU time, memory usage, and syscall access for every WASM execution.
- **Mesh Distribution:** (Mesh mode only) WASM modules can be distributed globally across the mesh for the serverless WASM backend. Generic WASM distribution is not implemented.

## 5. Spin Application Support

SynVoid also supports the **Fermyon Spin** framework, allowing for the execution of Spin-based microservices.

- **Metadata Parsing:** Automatically parses Spin application manifests (`spin.toml`) to determine routes and configurations.
- **Request Mapping:** Maps incoming HTTP requests to specific Spin components and triggers their execution.

### Spin vs Generic WASM Edge Functions

Spin is **not** the same as the generic WASM edge functions described above. Key distinctions:

| Aspect | Generic WASM Edge Functions | Spin |
|--------|---------------------------|------|
| **Runtime** | Wasmtime with custom resource limits | Custom Spin Runtime (`SpinRuntime`) |
| **Routing** | Longest-prefix-match on configured routes | Spin manifest (`spin.toml`) with built-in trigger system |
| **Manifest** | Configuration-driven routes | `spin.toml` parsed via `crates/synvoid-plugin-runtime/src/spin/manifest.rs` |
| **Registration** | Part of site configuration | Manual registration via Admin API |
| **Components** | Single WASM module per route | Multiple named components in manifest |
| **HTTP Dispatch** | `ServerlessRoute` (generic WASM) in server pipeline at `crates/synvoid-serverless/src/routing.rs` | `SpinHttpHandler` at `crates/synvoid-plugin-runtime/src/spin/handler.rs`, dispatched via canonical `crates/synvoid-http/src/*dispatch.rs` |

Spin applications are registered using `SpinAppsManager::register()` and handled via `SpinHttpHandler` which wraps the `SpinRuntime`. The Spin runtime parses its manifest at startup to determine component routes and trigger configurations.

**Integration Point:** When `BackendType::Spin` is configured, the HTTP server creates a `SpinHttpHandler` that routes requests through the Spin runtime to the appropriate component based on the Spin manifest.

## 6. BackendType Mapping (APP-5)

The `BackendType` enum at `crates/synvoid-proxy/src/router.rs` defines all backend variants (Upstream, FastCgi, Php, Cgi, AxumDynamic, AppServer, Static, QuicTunnel, Serverless, Mesh, Spin). Dispatch lives in canonical `crates/synvoid-http/src/*dispatch.rs` (not `src/http/server.rs`):

| BackendType | Dispatch | Purpose |
|-------------|----------|---------|
| `Upstream` | `backend_dispatch.rs` / `upstream_proxy_dispatch.rs` | HTTP proxy to external upstream |
| `FastCgi` / `Php` | `fastcgi_php_backend_dispatch.rs` | FastCGI proxy / PHP-FPM |
| `Cgi` | `cgi_backend_dispatch.rs` | Generic CGI execution |
| `AxumDynamic` | `axum_dynamic_dispatch.rs` | Dynamic Axum routes |
| `AppServer` | `app_server_backend_dispatch.rs` | Granian Python ASGI/WSGI |
| `Static` | `static_backend_dispatch.rs` | Static file serving |
| `QuicTunnel` | tunnel dispatch | QUIC tunnel proxy |
| `Serverless` | `backend_dispatch.rs` (+ mesh/serverless dispatch) | WASM serverless functions (mesh-gated) |
| `Mesh` | `mesh_backend_dispatch.rs` | Mesh routing backend |
| `Spin` | `spin_backend_dispatch.rs` | Spin framework WASM |

### Mesh Distribution for WASM (APP-6) ✅

Serverless WASM functions can be distributed across the mesh:
- Enabled via `mesh` feature flag
- `ServerlessManager` registers functions in DHT via `RecordStoreManager::store_and_announce()`
- Announces via `MeshTransport::announce_serverless()`
- Hierarchical routing as `serverless_function:{name}`
- Implementation: `crates/synvoid-serverless/src/manager.rs:117` + mesh integration at `crates/synvoid-mesh/src/mesh/`
