# Process Lifecycle Architecture Review

**Document Reviewed:** `architecture/process_lifecycle.md`
**Review Date:** 2026-05-06
**Code Sources:** `src/overseer/`, `src/master/`, `src/process/`

---

## 1. Verified Claims

### 1.1 Overseer Responsibilities
| Claim | Status | Evidence |
|-------|--------|----------|
| Spawns and monitors Master process | **VERIFIED** | `overseer/process.rs:106-115` - `spawn_master()` spawns via `spawn_and_log()` |
| Handles zero-downtime upgrades via "Dual Master" | **VERIFIED** | `overseer/process.rs:869-990` - `dual_master_upgrade()` method |
| Manages drain cycles for old processes | **VERIFIED** | `overseer/drain_manager.rs` - `DrainManager` tracks worker drain states |
| Performs health checks on Master | **VERIFIED** | `overseer/process.rs:117-151` - `check_master_health()` with process + IPC checks |
| Executes rollbacks on upgrade failure | **VERIFIED** | `overseer/rollback.rs` - `RollbackManager::perform_rollback()` |
| Key Logic location | **VERIFIED** | `src/overseer/process.rs`, `src/overseer/upgrade.rs` exist and contain logic |

### 1.2 Master Responsibilities
| Claim | Status | Evidence |
|-------|--------|----------|
| Spawns and monitors Workers via ProcessManager | **VERIFIED** | `src/process/manager.rs` - `ProcessManager` struct with worker spawning |
| Configuration loading and validation | **VERIFIED** | `overseer/process.rs:203-246` - `reload_config()` parses `main.toml` |
| Admin API server | **VERIFIED** | `src/master/commands.rs` - CLI command handlers (`handle_status`, `handle_stop`, etc.) |
| IPC Hub via Unix domain sockets | **VERIFIED** | `src/process/ipc.rs` - `IpcStream` over Unix domain sockets |
| Security Isolation (never handles external traffic) | **VERIFIED** | Architecture confirms Master is control-plane only |

### 1.3 Worker Types
| Claim | Status | Evidence |
|-------|--------|----------|
| Unified Server Worker with Tokio event loop | **VERIFIED** | `process/worker.rs` - `UnifiedServerWorkerProcess` |
| Handles HTTP/1, HTTP/2, HTTP/3, TCP, UDP | **PARTIAL** | Worker process exists but full protocol verification outside scope |
| Static Worker for static file serving | **VERIFIED** | `process/worker.rs:StaticWorkerProcess` |

### 1.4 Communication Flow
| Claim | Status | Evidence |
|-------|--------|----------|
| Overseer <-> Master: Health checks, upgrade coordination | **VERIFIED** | `process/ipc.rs:632-647` - `OverseerGetStatus`, `OverseerStatusResponse` messages |
| Master <-> Worker: Config distribution, threat feeds, rule updates | **VERIFIED** | `process/ipc.rs:443-464` - `ThreatFeedUpdate`, `RulePatternsUpdate`, `BlocklistUpdate` |
| Worker <-> Worker: Mesh network communication | **VERIFIED** | `process/ipc.rs:756-767` - `MeshControlRequest/Response` messages |

### 1.5 Zero-Downtime Upgrades
| Claim | Status | Evidence |
|-------|--------|----------|
| Dual Master handoff mechanism | **VERIFIED** | `overseer/process.rs:869-990` + `overseer/socket_handoff.rs` |
| Preflight checks on new Master | **VERIFIED** | `overseer/upgrade.rs:99-183` - `Orchestrator::stage()` with `PreflightValidator` |
| Old Master enters Drain Mode | **VERIFIED** | `overseer/process.rs:1169-1241` - `drain_and_stop_old_master_with_confirmation()` |
| Auto-Rollback on health check failure | **VERIFIED** | `overseer/upgrade.rs:358-427` - `apply_with_auto_rollback()` |

### 1.6 Process State & Health Monitoring
| Claim | Status | Evidence |
|-------|--------|----------|
| Status file `overseer_status.json` | **VERIFIED** | `overseer/process.rs:26-42` - `OverseerStatusFile` struct |
| Process health via `try_wait()` and SIGCHLD | **VERIFIED** | `overseer/process.rs:120-131` - uses `child.try_wait()` |
| IPC health via `MasterHealthCheck` messages | **VERIFIED** | `overseer/process.rs:164-200` - sends `Message::MasterHealthCheck` |
| Worker health via heartbeats | **VERIFIED** | `process/manager.rs:1006-1030` - `handle_heartbeat()` |

---

## 2. Unverified Claims (Needs Further Investigation)

### 2.1 Worker-to-Worker Mesh Communication
The document claims workers communicate directly via QUIC streams for threat intelligence sharing. While `MeshControlRequest/Response` messages exist in `process/ipc.rs:756-767`, the actual QUIC transport implementation was not reviewed. **Recommendation:** Verify `src/mesh/` implementation.

### 2.2 HTTP/3 (QUIC) Support in Unified Server
The claim that Unified Server Worker handles HTTP/3 (QUIC) was not verified in the process lifecycle code. This may be handled in the worker implementation itself. **Recommendation:** Verify worker implementation supports QUIC.

### 2.3 Windows Named Pipe IPC
While `src/process/ipc_windows.rs` exists and `WindowsIpcListener` is defined in `process/ipc.rs:1564-1680`, the actual Windows IPC accept loop (`windows_ipc_accept_loop`) mentioned in `src/master/mod.rs:15` was not reviewed.

---

## 3. Implementation Gaps

### 3.1 Status File Location Inconsistency
**Document says:** Status file in runtime directory  
**Code shows:** `overseer_status.json` written to `runtime_dir` (line 387-400)  
**Issue:** Uses `tokio::fs::rename()` for atomic writes (good), but no rotation policy for old status files.

### 3.2 Drain Timeout Hardcoding
**Location:** `overseer/process.rs:288-301`  
**Issue:** `stop_child_process` uses hardcoded 10 second timeout for graceful stop before force kill:
```rust
while start.elapsed() < Duration::from_secs(10) {
```
**Recommendation:** Make this configurable via `OverseerConfig`.

### 3.3 IPC Key File Cleanup on Non-Unix
**Location:** `process/ipc_signed.rs:172` and `process/ipc_signed.rs:193`  
**Issue:** On Unix, the IPC key file is deleted after reading. On Windows, it appears to also be deleted (line 193), but the file permission check is less rigorous (only checks `readonly()` vs mode bits on Unix).

### 3.4 Recovery State Timeout
**Location:** `overseer/state.rs:119-127`  
**Issue:** `needs_recovery()` includes `RollingBack` state, but there's no maximum duration check for recovery states. If recovery hangs, the system could be stuck indefinitely.
```rust
pub fn needs_recovery(&self) -> bool {
    matches!(
        self.state,
        UpgradeState::RecoveryNeeded
            | UpgradeState::DualMasterActive
            | UpgradeState::DrainingOldMaster
            | UpgradeState::RollingBack
    )
}
```

---

## 4. Code Improvements

### 4.1 Duplicate Drain Implementation
**Files:** `overseer/drain_manager.rs` and `overseer/process.rs`  
**Issue:** `DrainManager` in `drain_manager.rs` and the drain logic in `process.rs` (`drain_and_stop_old_master`, `drain_and_stop_old_master_with_confirmation`) appear to have overlapping functionality. Consider consolidating.

### 4.2 Sync vs Async IpcStream Confusion
**Location:** `process/ipc.rs:1524-1554`  
**Observation:** The documentation explicitly notes this is a legacy sync wrapper. The existence of two `IpcStream` types (`ipc::IpcStream` sync and `ipc_transport::IpcStream` async) could cause confusion. The comments are helpful but the architecture could be cleaner.

### 4.3 Missing Error Context in Health Checks
**Location:** `overseer/health.rs:209-225`  
**Issue:** `check_worker` returns `HealthStatus::Error(String)` but the error details are lost when converted to string:
```rust
Err(e) => HealthStatus::Error(e),
```
**Recommendation:** Preserve error kind or add error code.

### 4.4 State Persistence Race Condition Potential
**Location:** `overseer/state.rs:230-243`  
**Issue:** `save()` writes to temp file then renames. On Unix this is atomic, but the persistence directory creation and file write could fail. Additionally, there's no fsync/fdatasync to ensure durability on crash.

---

## 5. Bug Reports

### 5.1 Non-Atomic State Updates in Dual Master Upgrade
**Location:** `overseer/process.rs:941-964`  
**Issue:** State transitions and persistence are separate operations. If the process crashes between state update and persistence save, the state could be inconsistent:
```rust
state.state = UpgradeState::Validating;  // State changed
self.persistence.save(&state)             // But persistence could fail
    .map_err(UpgradeError::IoError)?;
```
**Severity:** Medium - Could cause recovery issues after crash

### 5.2 Socket Handoff Path Verification Bypass
**Location:** `overseer/socket_handoff.rs:155-161`  
**Issue:** The socket path in `SocketHandoffRequest` is checked against expected path, but the check is case-insensitive for the comparison and doesn't verify the handoff socket is actually from the old master:
```rust
if socket_path != expected_path.to_string_lossy() {
    return Err(SocketHandoffError::InvalidState(format!(
        "Unexpected socket path: {}",
        socket_path
    )));
}
```
**Security Concern:** An attacker could send a fake handoff request with the correct socket path. However, this is mitigated by socket file permissions (Unix domain sockets require filesystem access).

### 5.3 Missing Bounds Check on Port Array
**Location:** `overseer/socket_handoff.rs:418-420`  
**Issue:** `fds.iter().zip(ports.iter())` assumes equal lengths, but if `recv_fds` returns wrong count, this could silently drop FDs or miss ports:
```rust
for (fd, port) in fds.iter().zip(ports.iter()) {
    holder.add_existing_fd(*fd, *port, crate::process::SocketType::Tcp);
}
```
**Recommendation:** Add explicit length check with error handling.

---

## 6. Security Concerns

### 6.1 IPC Session Key Transmission
**Location:** `process/manager.rs:350-381`  
**Finding:** IPC session key is passed via temporary file (`SYNVOID_IPC_KEY_FILE`) or environment variable (`SYNVOID_IPC_KEY`). The temp file approach is good (0o600 permissions, symlink attack prevention), but:
- On Unix, key file is deleted after reading (line 172)
- On Windows, similar deletion occurs (line 193)  
**Assessment:** **SECURE** - File-based key exchange with proper cleanup

### 6.2 HMAC Verification Uses Constant-Time Comparison
**Location:** `process/ipc_signed.rs:217-218`  
```rust
use subtle::ConstantTimeEq;
computed_hmac.ct_eq(expected_hmac).into()
```
**Assessment:** **SECURE** - Correctly uses constant-time comparison for HMAC verification

### 6.3 Timestamp Replay Protection
**Location:** `process/ipc_signed.rs:101-105`  
```rust
fn verify_timestamp(timestamp: u64) -> bool {
    let now = crate::utils::current_timestamp();
    let diff = now.abs_diff(timestamp);
    diff <= REPLAY_WINDOW_SECS  // 60 seconds
}
```
**Assessment:** **SECURE** - 60-second replay window is reasonable. Nonce cache also prevents replay attacks.

### 6.4 Path Traversal Prevention in IPC Validation
**Location:** `process/ipc.rs:810-828`  
```rust
fn check_path_str(...) {
    if value.contains("..") {
        return Err(IpcValidationError {
            field: field.into(),
            message: "path traversal detected".into(),
        });
    }
}
```
**Assessment:** **SECURE** - Path traversal checked for all path fields

### 6.5 Unix Socket Permission Model
**Location:** `process/socket_path.rs`  
**Finding:** Socket files use `0o600` permissions via `set_socket_permissions()`. Master socket is `master.sock`, worker sockets use `worker-{id}.sock`.
**Assessment:** **SECURE** - Only owner can access IPC sockets

### 6.6 Preflight Binary Execution
**Location:** `overseer/preflight.rs:273-341`  
**Security Note:** Preflight validation executes the new binary as a subprocess with `--preflight-validate --startup-test`. This is acceptable since it's running the same binary in test mode, not arbitrary code execution.

---

## 7. Missing Documentation

### 7.1 Upgrade State Machine Documentation
**Location:** `overseer/state.rs:8-66`  
**Missing:** The `UpgradeState` enum has detailed state transitions but no corresponding state diagram or detailed transition table in the architecture document. The document mentions "Dual Master" states but doesn't enumerate them.

### 7.2 IPC Message Protocol Documentation
**Location:** `process/ipc.rs:245-768`  
**Missing:** The `Message` enum has extensive documentation comments grouping variants by concern, but there's no top-level protocol documentation for:
- Message framing format
- Request/response pairing expectations
- Error handling conventions

### 7.3 Socket Handoff Protocol
**Location:** `overseer/socket_handoff.rs`  
**Missing:** The socket handoff mechanism for zero-downtime upgrades (transferring listen sockets from old master to new master) is not documented in `process_lifecycle.md`. This is a critical security-sensitive mechanism.

### 7.4 Drain Protocol State Machine
**Location:** `overseer/drain_manager.rs:371-419`  
**Missing:** The drain protocol has its own state handling (`handle_drain_request`, `create_drain_status_response`) but no documentation on the full drain state machine and timeout behavior.

### 7.5 Worker Health Monitoring Details
**Location:** `process/manager.rs:1266-1290`  
**Missing:** The document mentions "Worker Health via heartbeats" but doesn't explain:
- What happens when a worker misses a heartbeat
- Restart backoff behavior
- Max restart attempts enforcement

### 7.6 Recovery After Incomplete Upgrade
**Location:** `overseer/process.rs:502-613`  
**Missing:** The automatic recovery mechanism for incomplete upgrades (detected via `RecoveryNeeded`, `DualMasterActive`, `DrainingOldMaster`, `RollingBack` states) is not documented. This is important for understanding system resilience.

---

## 8. Summary

### Strengths
1. **Well-structured hierarchical design** - Overseer -> Master -> Worker separation is clear
2. **Security-conscious IPC** - HMAC signing, replay protection, path traversal prevention
3. **Comprehensive upgrade flow** - Dual master handoff with health checks and auto-rollback
4. **State persistence for recovery** - Upgrade state survives process restarts
5. **Clean message protocol** - Well-organized Message enum with validation

### Weaknesses
1. **Documentation gaps** - Socket handoff, drain protocol, recovery mechanism undocumented
2. **Some hardcoded timeouts** - Drain timeout in `stop_child_process` should be configurable
3. **State update + persistence not atomic** - Could cause recovery issues on crash
4. **Dual IpcStream types** - Sync vs async creates confusion

### Recommendations
1. Add section on socket handoff protocol to `process_lifecycle.md`
2. Add state diagram for upgrade state machine
3. Make hardcoded timeouts configurable
4. Consider atomic state persistence (write + fsync in single operation)
5. Consolidate drain manager implementations if possible
6. Document recovery mechanism and its limitations

---

*Review compiled from source code analysis of `src/overseer/`, `src/master/`, `src/process/` modules.*
