# Worker/Data-Plane Composition Root Ownership

**Established**: Iteration 58
**Guardrail**: `tests/data_plane_composition_boundary_guard.rs`

## Invariant

> Composition roots own concrete infrastructure; request-path modules consume capabilities.

## Composition Root Files

These files construct and wire concrete infrastructure:

| File | Role |
|------|------|
| `src/worker/unified_server/mod.rs` | Primary composition root for UnifiedServerWorker |
| `src/worker/unified_server/init_mesh.rs` | Mesh transport, threat intelligence, YARA init |
| `src/worker/unified_server/init_waf.rs` | WAF background tasks, upload validation |
| `src/worker/unified_server/init_apps.rs` | Granian app servers, serverless manager |
| `src/worker/unified_server/services.rs` | DataPlaneServicesBuilder |
| `src/worker/unified_server/lifecycle.rs` | IPC message loop, canonical trust snapshot |
| `src/worker/unified_server/state.rs` | IPC connection, config loading |
| `src/worker/connection.rs` | Legacy worker WAF init |
| `src/worker/cpu_task/mod.rs` | CPU offload worker composition |
| `src/supervisor/process.rs` | Supervisor process composition |
| `src/supervisor/mesh.rs` | Mesh agent composition |
| `src/server/mod.rs` | UnifiedServer struct (holds block_store) |
| `src/main.rs` | Process dispatcher |

## Request-Path Modules

These modules handle live HTTP/HTTPS requests and must consume narrow traits:

| Directory | Purpose |
|-----------|---------|
| `src/waf/` | WAF request evaluation (uses `BlockListStore` trait) |
| `src/proxy/` | Proxy re-export shim (clean) |
| `src/http/` | HTTP server request handling |
| `src/http3/` | HTTP/3 re-export shim (clean) |
| `crates/synvoid-waf/` | WAF engine (clean, uses trait abstractions) |
| `crates/synvoid-proxy/` | Proxy engine (clean, uses trait abstractions) |
| `crates/synvoid-http3/` | HTTP/3 engine (clean, uses trait abstractions) |
| `crates/synvoid-http-client/` | HTTP client (clean, uses trait abstractions) |
| `crates/synvoid-http/` | HTTP request dispatch (some concrete types pass through) |

## Dependency Rules

### Composition Roots May Own

- Concrete `BlockStore`
- Concrete `ThreatIntelligenceManager`
- Mesh transport / DHT / Raft handles
- IPC manager/client/server handles
- Metrics providers, config objects
- WAF engine implementation
- HTTP/3 adapter implementation
- Supervisor/worker synchronization channels

### Request Path Must Consume

- `Arc<dyn BlockListStore>` / `Arc<dyn WafProcessor>` / trait objects
- Immutable config snapshots
- Local blocklist query capability traits
- Request context objects populated at the boundary
- Telemetry emitter traits

### Request Path Must Not Import/Own

- Mesh transport concrete types (`MeshTransportManager`, `MeshBackendPool`)
- DHT record store types (`RecordStoreManager`)
- Raft client/state-machine types
- Admin handlers (`verify_admin_token`)
- Concrete `BlockStore` or `ThreatIntelligenceManager`
- Supervisor IPC manager internals
- Snapshot/catchup/gossip APIs

## Concrete Type Threading

Some concrete types (mesh transport, IPC stream, serverless manager) are threaded through request-path dispatch contexts (`HttpServerRuntime`, `BackendDispatchContext`, `HttpRequestPostludeContext`) as pass-through data from the composition root. This is architecturally acceptable — the types are received, not constructed or owned.

## Known Pass-Through Types

These concrete types flow through request-path dispatch but are owned by the composition root:

| Type | Origin | Usage |
|------|--------|-------|
| `MeshTransportManager` | Mesh init | Threaded for serverless routing |
| `MeshBackendPool` | Mesh init | Threaded for backend routing |
| `MeshConfig` | Config | Threaded for mesh features |
| `AsyncIpcStream` | IPC init | Threaded for request logging |
| `WorkerId` | IPC init | Threaded for request logging |
| `ServerlessManager` | App init | Threaded for WASM dispatch |
| `GranianSupervisor` | App init | Threaded for app-server dispatch |

## Adding New Capabilities

To add a new capability to the request path:

1. Define a narrow trait in `crates/synvoid-waf/src/traits.rs` or `crates/synvoid-core/`
2. Implement the trait on a concrete type in a composition root
3. Pass `Arc<dyn YourTrait>` to request-path modules
4. Never pass the concrete type directly to request-path code

## Guardrail

`tests/data_plane_composition_boundary_guard.rs` scans request-path directories for forbidden concrete infrastructure tokens and panics if violations are found.
