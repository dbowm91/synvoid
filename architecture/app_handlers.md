# Application Handlers

SynVoid provides built-in, optimized handlers for various application types, allowing it to serve content directly or interface efficiently with specialized backends.

## 1. Static File Handler

The `StaticFileHandler` (`src/static_files/mod.rs:42`) is a high-performance engine for serving static assets. It includes features typically found in standalone web servers:

- **Directory Listings:** Automatically generates index pages for directories with configurable themes.
- **Path Normalization:** Protects against path traversal attacks by resolving and validating paths before access.
- **MIME Type Mapping:** Automatic content-type detection based on file extensions.
- **Caching & Compression:** Supports `gzip` and `brotli` pre-compression and integrates with the internal proxy cache.
- **IPC Delegation:** Heavy operations (CSS/JS minification, image compression) are delegated to CPU offload workers via IPC for background processing. The legacy `StaticWorker` IPC names remain as compatibility aliases.

## 2. FastCGI & PHP-FPM

SynVoid handles dynamic PHP applications by interfacing directly with PHP-FPM (or any FastCGI-compliant backend).

- **Unix Socket & TCP Support:** Can connect to PHP-FPM via local Unix domain sockets for maximum performance or over TCP for remote backends.
- **Environment Management:** Automatically populates FastCGI environment variables (e.g., `SCRIPT_FILENAME`, `QUERY_STRING`) required for PHP execution.
- **Response Streaming:** Efficiently streams responses from the FastCGI backend via `src/fastcgi/streaming.rs`.

## 3. Python (Granian)

SynVoid includes built-in support for Python ASGI/WSGI applications using the **Granian** application server (`src/app_server/granian.rs` - 1047 lines).

- **GranianSupervisor:** Full process management struct that spawns and monitors Granian instances as child processes (`GranianSupervisor`).
- **GranianConfig:** Runtime configuration struct for Granian deployment settings (defined at `src/app_server/granian.rs:165`). Note: This is distinct from `AppServerConfig` in `crates/synvoid-config/src/app_server.rs` which is the TOML-parsed configuration; GranianConfig is the resolved runtime type.
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
The `InstancePool` at `src/serverless/instance_pool.rs:11` provides sophisticated pooling:
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
| **Manifest** | Configuration-driven routes | `spin.toml` parsed via `src/spin/manifest.rs` |
| **Registration** | Part of site configuration | Manual registration via Admin API |
| **Components** | Single WASM module per route | Multiple named components in manifest |
| **HTTP Dispatch** | `ServerlessRoute` (generic WASM) in server pipeline at `src/serverless/routing.rs:112` | `SpinHttpHandler` at `src/spin/handler.rs:117`, handler creation at `src/http/server.rs:2378` |

Spin applications are registered using `SpinAppsManager::register()` and handled via `SpinHttpHandler` which wraps the `SpinRuntime`. The Spin runtime parses its manifest at startup to determine component routes and trigger configurations.

**Integration Point:** When `BackendType::Spin` is configured, the HTTP server creates a `SpinHttpHandler` that routes requests through the Spin runtime to the appropriate component based on the Spin manifest.

## 6. BackendType Mapping (APP-5)

The `BackendType` enum at `src/router.rs:66-78` defines all backend variants:

| BackendType | Handler Location | Purpose |
|-------------|------------------|---------|
| `Upstream` | `src/http/server.rs:1190` | HTTP proxy to external upstream |
| `FastCgi` | `src/http/server.rs:2508` | FastCGI proxy (PHP, Python, etc.) |
| `Php` | `src/http/server.rs:2513` | PHP-FPM via unix socket or TCP |
| `Cgi` | `src/http/server.rs:2747` | Generic CGI execution |
| `AxumDynamic` | `src/http/server.rs:2172` | Dynamic Axum routes |
| `AppServer` | `src/http/server.rs:2821` | Granian Python ASGI/WSGI |
| `Static` | `src/http/server.rs:2213` | Static file serving |
| `QuicTunnel` | `src/upstream/address.rs:27` | QUIC tunnel proxy |
| `Serverless` | `src/http/server.rs:1238` | WASM serverless functions (mesh-gated) |
| `Mesh` | `src/http/server.rs:2872` | Mesh routing backend |
| `Spin` | `src/http/server.rs:2421` | Spin framework WASM |

### Mesh Distribution for WASM (APP-6) ✅

Serverless WASM functions can be distributed across the mesh:
- Enabled via `mesh` feature flag
- `ServerlessManager` registers functions in DHT via `RecordStoreManager::store_and_announce()`
- Announces via `MeshTransport::announce_serverless()`
- Hierarchical routing as `serverless_function:{name}`
- Implementation: `src/serverless/manager.rs:117` + mesh integration at `src/mesh/transport.rs:1464`
