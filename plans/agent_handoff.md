# Wave 21: Deep Process Isolation and Business Logic Migration

The following tasks focus on moving the actual business logic into the isolated processes created in Wave 20 and further decomposing the workspace.

## 1. Migrate Mesh Control Plane Logic
- **REMOVED**: The stub process was removed. Mesh logic (DHT/Raft) remains in UnifiedServerWorker where it was designed to run. See `plans/control_plane_boundaries.md` for rationale.

## 2. Migrate Plugin/Serverless Execution Logic
- **REMOVED**: The stub process was removed. WASM plugins run in UnifiedServerWorker via Wasmtime sandboxing. See `plans/plugin_isolation.md` for rationale.

## 3. Deep Workspace Decomposition
- **Goal**: Extract `maluwaf-mesh` and `maluwaf-proxy` into the `crates/` directory.
- **Tasks**:
  - Create `crates/maluwaf-mesh` and move mesh submodules.
  - Create `crates/maluwaf-proxy` and move proxy/http_client submodules.
  - Resolve cyclic dependencies using traits in `maluwaf-utils`.
- **Status**: WAF extraction was attempted and failed - WAF module has too many cross-dependencies on main crate modules. See `plans/todo_deferred.md` for details.

## 4. Complete Config Schema Modernization
- **Goal**: Add remaining V2 aliases and verify backward compatibility.
- **Tasks**:
  - Add aliases to `ThreatLevelConfig` fields in `src/config/protection.rs`.
  - Verify all aliases with unit tests in `maluwaf-config`.

---

# Completed (Wave 20 Stabilization + Recent Work)
- [x] Raft Metrics & Axum API Fixes
- [x] Test Concurrency & Global State Deadlocks
  - [x] DashMap deadlock fixed - replaced with RwLock<HashMap>
  - [x] TokenBucket mockable clock implemented
- [x] Initial Process Isolation Scaffolding
- [x] `maluwaf-config` Extraction
- [x] Zero-Copy Proxying Validation (findings documented)
  - Streaming proxy correctly uses BufferPool
  - Static files Buffered variant reads into memory (needs deeper refactoring)
- [x] **Removed unused stubs**: MeshControlPlane and PluginExecution stubs deleted

---

# Notes for Next Agent

## Completed Fixes (2026-05-02)
| Branch | Status |
|--------|--------|
| `fix/raft-metrics-api` | Merged - Fixed raft metrics endpoints |
| `fix/test-concurrency` | Merged - Fixed DashMap deadlock in SlidingWindowLimiter |
| `fix/token-bucket-mockable-clock` | Merged - Added mockable clock for TokenBucket tests |
| `feature/zero-copy-validation` | Merged - Documented zero-copy implementation |
| `chore/remove-unused-stubs` | Merged - Removed MeshControlPlane and PluginExecution stubs |

## Deferred Items
See `plans/todo_deferred.md` for detailed list:
- WAF module extraction - **FAILED** (too many cross-dependencies)
- Static file sendfile - needs deeper HTTP response handling refactoring
- Workspace decomposition - only `maluwaf-config` and `maluwaf-utils` extracted so far