# Worker/Data-Plane Composition Root Ownership

**Established**: Iteration 58
**Updated**: Iteration 60
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
| `src/worker/unified_server/init_runtime.rs` | Re-exports of state.rs runtime helpers |
| `src/worker/unified_server/init_config.rs` | Re-exports of state.rs config helpers |
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
- Concrete `ThreatIntelligenceManager` (removed from WAF in Iteration 59)
- Raft/DHT module imports (`crate::raft::`, `openraft::`, `crate::dht::`)
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

## WAF Blocklist No-Op Shims (Iteration 59)

The following `WafCore` methods are **API-compatibility shims** — they do not mutate block store state:

| Method | Behavior |
|--------|----------|
| `check_early()` | Always returns `WafDecision::Pass` |
| `block_ip_for_honeypot()` | No-op (empty body) |
| `block_ip_with_threat_intel()` | No-op (empty body) |

These methods are retained only for trait compatibility (`EarlyWafHooks`, `ChallengePathWaf`, `UploadValidationWaf`). Blocklist writes occur via dedicated local/control-plane enforcement paths, not through the WAF request path.

`check_dht_threat_lookup()` and `get_threat_intel()` were removed in Iteration 59 — they were dead code referencing concrete `ThreatIntelligenceManager` on the request path.

## Guardrail (Iteration 60)

`tests/data_plane_composition_boundary_guard.rs` enforces the composition boundary with role-based file classification and three token groups:

- **`BoundaryRole` enum**: Classifies files as `CompositionRoot`, `RequestPath`, `ControlPlane`, `Admin`, `SharedTypes`, `TestOnly`, or `Unclassified`. Each file under `src/worker/unified_server/` is classified individually. Unknown files under mixed-role directories fail closed as `Unclassified`.
- **`boundary_scan_roots()`**: Mixed-role scan roots that include `src/worker/unified_server/` alongside pure request-path directories. Every `.rs` file in these roots is traversed and classified.
- **`CONSTRUCTION_TOKENS`**: Catches concrete infrastructure construction (`BlockStore::new`, `ThreatIntelligenceManager::new`, etc.)
- **`TYPE_IMPORT_TOKENS`**: Catches concrete type imports (`crate::block_store::BlockStore`, `crate::raft::`, etc.)
- **`CONTROL_PLANE_OP_TOKENS`**: Catches control-plane operations (`export_blocklist_snapshot`, `lookup_threat_indicator_in_dht`, etc.)

Pass-through types in HTTP dispatch (`MeshTransportManager`, `MeshBackendPool`) have scoped `BoundaryException` entries with documented reasons. The guardrail also runs focused tests for BlockStore types, ThreatIntelligenceManager types, and Raft/DHT imports specifically.

**Exception liveness**: Every `BoundaryException` must correspond to a current, audited source occurrence. A liveness test verifies each exception token is present in at least one matching file, preventing stale exceptions from silently authorizing regressions.

**Fail-closed classification**: New files added under mixed-role directories (e.g., `src/worker/unified_server/`) must receive an explicit `BoundaryRole` classification. The default for unknown unified-server files is `Unclassified`, which causes the guardrail test to fail with instructions to classify the file explicitly.
