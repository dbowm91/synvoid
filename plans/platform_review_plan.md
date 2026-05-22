# Platform Architecture Review - Improvement Plan

**Date**: 2026-05-22
**Reviewer**: Architecture Review Agent
**Scope**: Platform module (`src/platform/`), Process module (`src/process/`), Supervisor module (`src/supervisor/`), Startup module (`src/startup/`), and Overseer module (`src/overseer/`)

---

## Executive Summary

The Platform architecture documentation is **partially accurate** but has several discrepancies between what's documented and what's actually implemented. Most critically, the documentation describes a simplified two-tier "Supervisor → Worker" architecture, while the actual codebase implements a **three-tier hierarchy** (Overseer → Master → Worker) with the Supervisor being a newer consolidation layer.

---

## 1. Documented vs Implemented Comparison

### 1.1 Process Hierarchy

| Documented | Actual Implementation | Status |
|------------|---------------------|--------|
| Supervisor (default mode, consolidated overseer+master) | Supervisor runs as `--supervisor` mode (main.rs:529-536), spawns workers and gRPC API | IMPLEMENTED |
| Master (`--master` flag) | `run_master_mode()` in `src/startup/master.rs:23` | EXISTS |
| Overseer (legacy) | `src/overseer/` module with `OverseerProcess` in `src/overseer/process.rs` | EXISTS (LEGACY) |
| UnifiedServerWorker (`--unified-server-worker`) | `run_unified_server_worker()` in `src/worker/unified_server.rs` | IMPLEMENTED |
| StaticWorker (`--static-worker`) | `run_static_worker()` in `src/startup/worker.rs` | IMPLEMENTED |
| BaseWorkerProcess (`--worker`) | Legacy, no HTTP handler (per AGENTS.md:136-140) | DEPRECATED |

### 1.2 Key Files - Documentation vs Reality

| Documented Path | Actual Location | Notes |
|----------------|-----------------|-------|
| `src/http/shared_handler.rs` (WAF pipeline) | `src/http/server.rs:4530-4537` | AGENTS.md:79 correction applies |
| `src/mesh/raft/state_machine.rs` (quorum verification) | `src/mesh/dht/signed.rs:860-934` | AGENTS.md:81 correction applies |
| `src/mesh/dht/quorum.rs:339-386` (race condition) | FIXED per AGENTS.md:83 | FIXED |

### 1.3 IPC Architecture

**Documentation** (`platform_deep_dive.md:109-127`):
- 4-byte length prefix framing
- HMAC-SHA3-256 signed messages
- 60-second replay window
- MAX_MESSAGE_SIZE: 1 MiB
- SCM_Rights FD passing (max 254 FDs)

**Actual Implementation** - Verified in:
- `src/process/ipc_signed.rs:49-53` (constants)
- `src/process/ipc_signed.rs:70` (REPLAY_WINDOW_SECS = 60)
- `src/process/ipc_framing.rs` (length prefix)
- `src/platform/unix.rs:16` (MAX_FDS_PER_MESSAGE = 254)
- HMAC verification uses `subtle::ConstantTimeEq` in `ipc_signed.rs:225-226`

---

## 2. Discrepancies Identified

### 2.1 CRITICAL: Three-Tier vs Two-Tier Hierarchy

**Documentation Claims** (`process_lifecycle.md:3-17`):
```
Supervisor (Control Plane)
├── Process Management
├── Zero-Downtime Upgrades
├── Control Plane API
└── Configuration
```

**Reality**: The codebase has **three tiers**:

```
Overseer (legacy, still active)
├── Spawns Master
├── Spawns Mesh Agent
├── Health monitoring
├── Upgrade orchestration
└── Handles recovery

Master (src/startup/master.rs:205-797)
├── ProcessManager (spawns workers)
├── Admin API
├── BlockStore
├── RuleFeedManager
├── IPC listener
└── Broadcasts to workers

Supervisor (src/supervisor/process.rs:187-291)
├── NEW consolidated mode (2026-05-22)
├── Replaces Overseer+Master for simpler deployments
├── Spawns UnifiedServerWorkers directly
└── gRPC control API

Worker (UnifiedServerWorker/StaticWorker)
├── Request handling
├── WAF pipeline
└── Mesh transport
```

**Location of Evidence**:
- `src/startup/master.rs:89-203` - `run_overseer_mode()` still exists
- `src/overseer/process.rs:51-106` - `OverseerProcess` with `master_child`, `mesh_agent_child`
- `src/main.rs:518-521` - Mesh agent mode
- `src/supervisor/process.rs:27-45` - `SupervisorProcess::new()` creates ProcessManager directly

**Impact**: Documentation needs update to reflect the three-tier architecture with Overseer still being the parent of Master in legacy deployments.

### 2.2 gRPC Server No TLS

**Documentation** (`platform_deep_dive.md:181`):
> **Security note**: gRPC binds to `localhost` only - TLS not required for local IPC.

**Actual Code** (`src/supervisor/api.rs:114-129`):
```rust
pub async fn start_grpc_server(
    addr: std::net::SocketAddr,
    process_manager: Arc<ProcessManager>,
    state: SupervisorState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let service = ControlPlaneService::new(process_manager, state);
    tonic::transport::Server::builder()
        .add_service(ControlPlaneServer::new(service))
        .serve(addr)
        .await?;
    Ok(())
}
```

**Status**: Accurate - TLS is intentionally omitted for localhost IPC (per AGENTS.md:177).

### 2.3 Missing `control_plane/` Module Reference

**Documentation** (`process_lifecycle.md:16`):
> Key Logic: `src/supervisor/`, `src/control_plane/`.

**Reality**: `src/control_plane/` does not exist. The gRPC service is in `src/supervisor/api.rs`.

**Fix Required**: Remove reference to non-existent `src/control_plane/` from documentation.

### 2.4 Startup Flow Discrepancy

**Documentation** (`platform_deep_dive.md:201-217`) shows 11 steps for `run_master_mode()`.

**Actual Code** (`src/startup/master.rs:205-797`):
The actual flow has 15+ distinct phases including:
1. Post-quantum TLS initialization (lines 210-246)
2. Site discovery and loading (lines 258-268)
3. CRITICAL REQUIREMENT comment about Master NOT running UnifiedServer inline (lines 278-307)
4. BlockStore creation (lines 308-314)
5. Threat feed client initialization (lines 529-592)
6. IPC endpoint binding (lines 607-650)
7. Worker spawning (lines 652-667)
8. Static worker spawning (lines 658-667)
9. Signal handlers (line 669)
10. Health monitor (lines 671-675)
11. Blocklist persist interval (lines 677-687)
12. Admin server (lines 693-726)
13. UnifiedServerWorker spawning (lines 728-736)

**Impact**: Documentation significantly underspecifies the Master startup flow.

---

## 3. Specific Bugs and Issues

### 3.1 BaseWorkerProcess Never Used for HTTP

**Location**: `src/main.rs:36` (`--worker` flag)

**Issue**: Per AGENTS.md:136-140, BaseWorkerProcess is legacy and has no HTTP handler. The code path exists but is never invoked for HTTP traffic.

### 3.2 OverseerProcess.mesh_agent_child Spawns During Shutdown

**Location**: `src/overseer/process.rs:395-409`

```rust
if let Some(ref mut child) = self.mesh_agent_child {
    match child.try_wait() {
        Ok(Some(status)) => {
            tracing::warn!("Mesh Agent process exited...");
            let _ = self.spawn_mesh_agent();
        }
        Ok(None) => {}
        Err(e) => { ... }
    }
} else {
    let _ = self.spawn_mesh_agent();  // Always spawns if None - BUG
}
```

**Issue**: The `else` branch at line 408 unconditionally spawns a mesh agent even during shutdown. Should check `if self.running.is_running()` before spawning.

### 3.3 SupervisorProcess.handle_connection() References Non-Existent Function

**Location**: `src/supervisor/process.rs:153-170`

```rust
async fn handle_connection(mut ipc: IpcStream, pm: Arc<ProcessManager>, state: SupervisorState) {
    match ipc.recv_with_timeout::<Message>(1000).await {
        Ok(Some(msg)) => {
            crate::master::handle_worker_connection_single(ipc, pm, msg).await;  // DOESN'T EXIST
        }
        _ => {
            Self::handle_admin_command(ipc, pm, state).await;
        }
    }
}
```

**Issue**: `crate::master::handle_worker_connection_single` does not appear to exist. This would cause a compile error if Supervisor mode is used.

**Action Required**: Verify this function exists or replace with correct handler.

### 3.4 Windows Socket FD Passing Error Message Inaccurate

**Location**: `src/platform/windows_impl.rs:87-99`

```rust
fn send_sockets(&self, _handles: &[Self::Handle]) -> Result<(), SocketHandoffError> {
    Err(SocketHandoffError::NotSupported(
        "Socket FD passing requires WSADuplicateSocket. Use port-swap upgrade mode instead."
            .into(),
    ))
}
```

**Issue**: The error message suggests port-swap as an alternative, but there's no actual port-swap implementation in the Windows path for socket handoff.

---

## 4. Recommended Improvements

### 4.1 Documentation Corrections

| File | Line(s) | Issue | Recommendation |
|------|---------|-------|----------------|
| `architecture/process_lifecycle.md` | 16 | Reference to non-existent `src/control_plane/` | Remove reference |
| `architecture/process_lifecycle.md` | 5-27 | Describes 2-tier hierarchy | Update to reflect 3-tier with Overseer→Master→Worker |
| `architecture/platform_deep_dive.md` | 201-217 | Startup flow incomplete | Add missing steps from `src/startup/master.rs` |
| `architecture/platform_deep_dive.md` | 113-121 | Process hierarchy table incomplete | Add Overseer row |

### 4.2 Code Fixes

| Issue | Location | Severity | Fix |
|-------|----------|----------|-----|
| Mesh agent spawns during shutdown | `src/overseer/process.rs:408` | Medium | Add `if self.running.is_running()` check before unconditional spawn |
| Non-existent function reference | `src/supervisor/process.rs:161` | High | Verify `handle_worker_connection_single` exists or replace with correct handler |
| Windows socket FD passing error message | `src/platform/windows_impl.rs:89` | Low | Update message to be accurate about limitations |

### 4.3 Architecture Diagram Corrections

The architecture diagram in `platform_deep_dive.md:234-278` shows a direct Supervisor→Master→Worker hierarchy. **Recommended Update**: Add the Overseer layer for legacy deployments, and clarify that Supervisor mode is a newer consolidated approach that replaces Overseer+Master for simpler deployments.

---

## 5. Verified Implementation Details

### 5.1 Platform Module (`src/platform/`)

| File | Claims | Verified |
|------|--------|----------|
| `mod.rs` | Platform enum detection | Lines 20-30 |
| `ipc.rs` | IPC trait abstraction | Traits at lines 6-28 |
| `sandbox.rs` | Multi-backend sandboxing | Landlock, Capsicum, Pledge, Seatbelt, Job Objects all present |
| `socket.rs` | Socket creation, FD passing | `MAX_FDS_PER_MESSAGE` = 254 at line 16 |
| `process.rs` | Signal handling | UnixProcessControl, WindowsProcessControl |
| `unix.rs` | Unix domain sockets | `UnixIpcListener`, `UnixIpcStream` |
| `windows_impl.rs` | Windows named pipes | `WindowsIpcListener`, `WindowsIpcStream` |

### 5.2 Process Module (`src/process/`)

| File | Claims | Verified |
|------|--------|----------|
| `ipc.rs` | 60+ message variants | 150+ variants in Message enum |
| `ipc_framing.rs` | Length-prefixed framing | 4-byte BE length header |
| `ipc_signed.rs` | HMAC-SHA3-256, replay protection | DashMap nonce cache, 60s window at line 70 |
| `ipc_transport.rs` | Async IPC transport | `IpcStream` with `send/recv` |
| `manager.rs` | ProcessManager | `spawn_unified_server_workers()` |

### 5.3 Supervisor Module (`src/supervisor/`)

| File | Claims | Verified |
|------|--------|----------|
| `process.rs` | SupervisorProcess struct | Lines 19-25 |
| `api.rs` | gRPC control plane | No TLS (intentional per AGENTS.md) |
| `state.rs` | SupervisorState with trackers | BlockStore, ConfigManager |
| `mesh.rs` | Mesh agent mode | `run_mesh_agent_mode()` |
| `commands.rs` | Command handling | `handle_supervisor_command()` |

---

## 6. Summary of Required Actions

### High Priority
1. **Update architecture docs** to reflect three-tier hierarchy (Overseer→Master→Worker)
2. **Fix or remove** dead code in `src/supervisor/process.rs:161` referencing non-existent function `handle_worker_connection_single`
3. **Update process_lifecycle.md** to remove non-existent `src/control_plane/` reference

### Medium Priority
4. **Fix mesh agent spawn during shutdown** in `src/overseer/process.rs:408` - add running check
5. **Expand startup flow documentation** in `platform_deep_dive.md` to match actual complexity
6. **Add Overseer row** to process hierarchy table in `platform_deep_dive.md:113-121`

### Low Priority
7. **Clarify Windows FD passing limitations** in error messages
8. **Update BaseWorkerProcess documentation** to note it's deprecated and unused for HTTP

---

## 7. Files to Update

| File | Changes |
|------|---------|
| `architecture/process_lifecycle.md` | Add Overseer layer, fix control_plane reference |
| `architecture/platform_deep_dive.md` | Expand startup flow, add Overseer to hierarchy table |
| `src/supervisor/process.rs:161` | Fix dead code reference or remove |
| `src/overseer/process.rs:408` | Add running check before mesh agent spawn |

---

*End of Plan*