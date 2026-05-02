# Wave 21: Deep Process Isolation and Business Logic Migration

The following tasks focus on moving the actual business logic into the isolated processes created in Wave 20 and further decomposing the workspace.

## 1. Migrate Mesh Control Plane Logic
- **Goal**: Move DHT and Raft management to the `--mesh-control-plane` process.
- **Tasks**:
  - Implement the IPC listener in `src/mesh/control_plane.rs`.
  - Move initialization of `RoutingTable`, `RecordStoreManager`, and `RaftInstance` into the isolated process.
  - Implement an `IpcMeshClient` in the main process to forward mesh operations over IPC.

## 2. Migrate Plugin/Serverless Execution Logic
- **Goal**: Move WASM execution to the `--plugin-execution` process.
- **Tasks**:
  - Implement the IPC listener in `src/plugin/execution.rs`.
  - Implement a "Plugin Host Proxy" for callbacks (logging, metrics) from the isolated process.
  - Update the WAF/HTTP worker to delegate WASM execution via IPC.

## 3. Deep Workspace Decomposition
- **Goal**: Extract `maluwaf-mesh` and `maluwaf-proxy` into the `crates/` directory.
- **Tasks**:
  - Create `crates/maluwaf-mesh` and move mesh submodules.
  - Create `crates/maluwaf-proxy` and move proxy/http_client submodules.
  - Resolve cyclic dependencies using traits in `maluwaf-utils`.

## 4. Complete Config Schema Modernization
- **Goal**: Add remaining V2 aliases and verify backward compatibility.
- **Tasks**:
  - Add aliases to `ThreatLevelConfig` fields in `src/config/protection.rs`.
  - Verify all aliases with unit tests in `maluwaf-config`.

---

# Completed (Wave 20 Stabilization)
- [x] Raft Metrics & Axum API Fixes
- [x] Test Concurrency & Global State Deadlocks
- [x] Initial Process Isolation Scaffolding
- [x] `maluwaf-config` Extraction
