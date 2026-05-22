# Process Lifecycle Architecture Review

**Document:** `architecture/process_lifecycle.md`
**Review Date:** 2026-05-22
**Reviewed Modules:** `src/overseer/`, `src/master/`, `src/process/`

---

## 1. Verified Claims

### 1.1 Supervisor/Master Two-Tier Pattern

| Claim | Status | Evidence |
|-------|--------|----------|
| Supervisor merges Overseer and Master | **VERIFIED** | `src/overseer/process.rs:51-70` defines `OverseerProcess` which spawns and monitors `master_child`. The overseer directly manages the master lifecycle. |
| Process Management: spawning/monitoring | **VERIFIED** | `src/overseer/process.rs:108-117` (`spawn_master`), `src/overseer/process.rs:119-153` (`check_master_health`). Worker spawning in `src/process/manager.rs:497-552`. |
| Zero-Downtime Upgrades | **VERIFIED** | `src/overseer/upgrade.rs:185-326` (`apply` method with staged binary, validation, drain sequence). UpgradeState machine in `src/overseer/state.rs:8-22`. |
| gRPC API for Control Plane | **PARTIAL** | The document mentions `proto/control.proto` gRPC API. Actual implementation appears to use Unix socket IPC (`Message::OverseerGetStatus`, `Message::OverseerStatusResponse` in `src/process/ipc.rs`). No gRPC server found in overseer/master. |
| Supervisor key logic: `src/supervisor/` | **NOT FOUND** | `src/supervisor/` directory does not exist. Code is in `src/overseer/`. Document references non-existent path. |

### 1.2 Worker Shared-Nothing Architecture

| Claim | Status | Evidence |
|-------|--------|----------|
| Each worker process is completely independent | **VERIFIED** | `src/process/worker.rs:47-154` - `WorkerProcess` and variants contain only `Child` handle, no shared state. Workers communicate via IPC only. |
| Kernel Load Balancing via SO_REUSEPORT | **VERIFIED** | `src/process/socket_fd.rs:268-272` - `create_listening_socket` with `ReusePort` option. `src/overseer/mode.rs:29-37` - `detect_upgrade_mode()` auto-detects reuseport support. |
| CPU Pinning via sched_setaffinity | **NOT IMPLEMENTED** | No `sched_setaffinity` call found in codebase. `src/process/manager.rs:666-668` passes `--cpu-affinity` argument but no actual affinity setting in spawn logic. This is a gap. |
| Workers receive config via IPC | **VERIFIED** | `src/process/manager.rs:353-401` - `build_worker_command` passes config path. IPC session key mechanism in `src/process/ipc_signed.rs`. |

### 1.3 Communication Flow

| Claim | Status | Evidence |
|-------|--------|----------|
| External Management (gRPC) | **NOT FOUND** | No gRPC implementation found. Unix domain socket IPC used (`src/master/ipc.rs`, `src/process/ipc_transport.rs`). Document appears to describe aspirational design. |
| Internal Coordination (IPC) | **VERIFIED** | Full IPC implementation in `src/process/ipc.rs` (Message enum with 80+ variants), `src/process/ipc_framing.rs`, `src/process/ipc_signed.rs`. Unix sockets on Unix, named pipes on Windows. |
| Mesh Network (QUIC) | **VERIFIED** | `src/mesh/` exists with mesh protocol. `src/master/commands.rs:368-455` exports `handle_export_threat_feed` with mesh signing. |

### 1.4 Zero-Downtime Upgrade Flow

| Claim | Status | Evidence |
|-------|--------|----------|
| Stage new binary | **VERIFIED** | `src/overseer/upgrade.rs:99-183` - `stage()` downloads, validates checksum, runs preflight checks. |
| New Supervisor takes over gRPC | **NOT IMPLEMENTED** | No gRPC. The overseer uses Unix socket IPC for upgrade coordination via `Message::OverseerUpgradePrepare`. |
| Workers rotated with SO_REUSEPORT | **VERIFIED** | `src/overseer/upgrade.rs:811-826` - `spawn_upgraded_workers` with `reuse_port` flag. `src/overseer/mode.rs:11-20` - `UpgradeMode::ReusePort` variant. |
| Old workers drain | **VERIFIED** | `src/overseer/upgrade.rs:838-969` - `drain_old_workers` with HTTP drain protocol. `src/overseer/drain_manager.rs` - `DrainManager` tracks drain state. |

### 1.5 Self-Healing Worker Restart

| Claim | Status | Evidence |
|-------|--------|----------|
| Immediate spawn replacement | **VERIFIED** | `src/process/manager.rs:1386-1417` - `handle_failure_restarts` with exponential backoff. `src/process/manager.rs:1396-1417` - respects `max_restart_attempts`. |
| Pin to correct core | **NOT IMPLEMENTED** | CPU affinity not actually set despite `--cpu-affinity` flag being passed. See gap below. |

---

## 2. Unverified Claims (Needs Investigation)

| Claim | Source | Required Verification |
|-------|--------|----------------------|
| gRPC API (`proto/control.proto`) | Document line 15 | Search for `control.proto`, verify gRPC server exists |
| `src/supervisor/` directory | Document line 16 | Confirm if this is renamed or non-existent |
| CPU pinning actually works | Document line 24 | Test on Linux whether `sched_setaffinity` is called |
| Tokio runtime per worker | Document line 46 | Verify each worker gets dedicated Tokio runtime |

---

## 3. Implementation Gaps

### 3.1 CPU Affinity Not Actually Set (HIGH PRIORITY)

**Location:** `src/process/manager.rs:666-668`

The code passes `--cpu-affinity` flag to worker command:
```rust
let core = id.as_usize() % self.cpu_count;
cmd.arg("--cpu-affinity").arg(core.to_string());
```

However, no actual `sched_setaffinity` call exists in the codebase. The flag is passed but never acted upon in the worker process startup. This means:
- Workers are NOT actually pinned to specific cores
- Cache thrashing and jitter may occur as documented architecture claims

**Fix Required:** Worker main.rs must parse `--cpu-affinity` and call `nix::sched::sched_setaffinity()` or equivalent.

### 3.2 gRPC Control Plane Not Implemented

**Location:** Document claims gRPC API at `proto/control.proto`

The actual implementation uses Unix socket IPC. No gRPC server found in:
- `src/overseer/` - No gRPC server
- `src/master/` - No gRPC server
- `src/admin/` - May have REST API but not gRPC

The document describes aspirational architecture that doesn't match implementation.

### 3.3 Non-existent `src/supervisor/` Path

**Location:** Document line 16 references `src/supervisor/`, `src/control_plane/`

Actual structure:
- Supervisor logic is in `src/overseer/`
- No `src/control_plane/` directory exists

### 3.4 IPC Signing Verification is Mocked

**Location:** `src/master/ipc.rs:350-354`

```rust
static VERIFIED_WITH_ASYNC: std::sync::OnceLock<()> = std::sync::OnceLock::new();
VERIFIED_WITH_ASYNC.get_or_init(|| {
    tracing::debug!("IPC signing verified with async transport");
});
```

This is a no-op placeholder. The `OnceLock` doesn't actually verify anything - it just logs a message once. Real verification should check cryptographic signatures on messages.

### 3.5 Missing Permission Restriction on IPC Key Temp File

**Location:** `src/process/manager.rs:403-462`

The `write_ipc_key_to_tempfile` creates a temp file with `0o600` permissions on Unix. However:
1. The temp file is NOT cleaned up on process exit (no `auto-cleanup` on drop)
2. If the process crashes, the key file persists in `/tmp/` with the IPC key
3. Only 10,000 workers tracked max in rate limiter (`src/process/ipc_rate_limit.rs:27`)

---

## 4. Code Improvements

### 4.1 IPC Rate Limiter - Worker ID Collision Possible

**Location:** `src/process/ipc_rate_limit.rs:69-107`

The per-worker rate limit uses `worker_id: u64` directly without namespace separation between worker types:
- Base workers use `WorkerId` (0-based index)
- Static workers use `usize` worker_id directly in some messages
- Unified server workers use `WorkerId`

This could cause collision if worker_id overflow or reuse across worker types. Recommendation: Use separate rate limit namespaces per worker type.

### 4.2 Process Manager Lock Contention

**Location:** `src/process/manager.rs:524-543`

```rust
let mut workers = self.workers.write();
let worker_process = WorkerProcess::new_placeholder(id, port, restart_count);
workers.insert(id.as_usize(), worker_process);
drop(workers);

let child = match cmd.spawn() {
    // blocking I/O while holding lock briefly
```

This pattern is acceptable but could be improved with a spawn queue to avoid thundering herd on restart.

### 4.3 Health Check Timeout Hardcoded

**Location:** `src/master/ipc.rs:371`

```rust
ipc.recv_with_timeout::<Message>(5000).await
```

Timeout is 5000ms hardcoded. Should be configurable or adaptive based on system load.

### 4.4 Missing Request Log Eviction Strategy

**Location:** `src/process/manager.rs:1068-1078`

```rust
if logs.len() >= Self::MAX_REQUEST_LOGS {
    logs.pop_front();
}
```

Using `VecDeque` with `pop_front()` is O(n) due to memory shift. Should use a proper ring buffer or check if `VecDeque::pop_front` is O(1) (it should be for VecDeque). Verified: VecDeque::pop_front is O(1) amortized.

### 4.5 Heartbeat Timeout Uses Blocking Operations in Async Context

**Location:** `src/process/manager.rs:695-722`

```rust
let mut unified_server_workers = self.unified_server_workers.write();  // blocking
if let Some(worker) = unified_server_workers.get_mut(&worker_id.as_usize()) {
    *worker.last_heartbeat_mut() = Instant::now();
```

This uses `parking_lot::RwLock` which can block async executor if lock is contended. Consider using `tokio::sync::RwLock` for async-compatible locking.

---

## 5. Bug Reports

### BUG-1: CPU Affinity Flag Not Honored

**Severity:** Medium
**Component:** Worker spawn / process management

Workers receive `--cpu-affinity N` but the worker main.rs does not parse or apply this to `sched_setaffinity()`. Workers run on any core despite the argument.

**Reproduction:**
1. Start synvoid with multiple workers
2. Observe worker PIDs in `/proc/<pid>/status` - `Cpus_allowed:` shows all CPUs, not single core

**Expected:** Workers pinned to specific cores
**Actual:** No pinning occurs

### BUG-2: IPC Key Temp File Not Cleaned Up

**Severity:** Medium
**Security:** Leak of IPC session key material

**Location:** `src/process/manager.rs:403-462`

Temp file `synvoid_ipc_key_<pid>` written to `/tmp/` but:
1. Not deleted on process normal exit
2. Not deleted on process crash
3. Stale files from dead processes only cleaned on retry (line 429-451)

**Impact:** IPC session key visible to other local users until PID recycled

**Fix:** Use `tempfile` crate with `auto_unlink_on_drop` or register cleanup handler.

### BUG-3: LockGuard Can Deadlock on Drop

**Severity:** Low (Unix-only)
**Location:** `src/overseer/state.rs:331-335`

```rust
impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_file);
    }
}
```

If `drop()` panics, the mutex state may be corrupted. Should use `std::panic::catch_unwind` or note this in docs.

### BUG-4: Retry Logic After Cleanup May Fail

**Severity:** Low
**Location:** `src/process/manager.rs:427-451`

```rust
Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
    if let Some(stale_pid) = Self::parse_ipc_key_pid(&file_path) {
        if !Self::is_pid_alive(stale_pid) {
            // Delete and retry
```

Race condition: PID could become alive between `is_pid_alive` check and `remove_file`. Another process could claim same PID before file deletion completes.

---

## 6. Security Concerns

### SEC-1: IPC Signing Verification is Ineffective

**Location:** `src/master/ipc.rs:350-354`

The `VERIFIED_WITH_ASYNC` OnceLock doesn't actually verify signatures - it just logs. Real HMAC/signature verification using `IpcSigner` exists but is not invoked for the initial connection handshake.

**Recommendation:** Actually verify signatures in the message handler loop, not just during initial connection.

### SEC-2: PID Spoofing Detection Has Race Window

**Location:** `src/master/ipc.rs:405-438`

```rust
if is_startup_message {
    if let Some(actual_pid) = peer_pid {
        if let Some(claimed_pid) = claimed_pid_for_startup {
            if claimed_pid != actual_pid {
                // REJECT
            }
        }
        // Bind worker to PID
        bindings.insert(wid, actual_pid);
    }
}
```

After startup, subsequent messages check against `bindings`. However, between startup message and binding insertion, there's a window where worker could send messages with different PID. This is a TOCTOU race.

### SEC-3: No Rate Limit on Per-Worker Messages After Binding

**Location:** `src/process/ipc_rate_limit.rs:69-107`

After `check_worker` passes, there's no per-message rate limiting. A compromised worker could flood the master with messages up to the global limit (1000/sec default) without any per-worker quota.

### SEC-4: Config Token Stored in Plaintext

**Location:** `src/master/commands.rs:343-362`

When generating new token:
```rust
std::fs::write(&main_config_path, &updated_content)?;
// Later: set permissions to 0o600
```

If process crashes between write and permission change, token is world-readable. Should use atomic write (temp file + rename) or set permissions before write.

---

## 7. Missing Documentation

| Item | Location | Gap |
|------|----------|-----|
| Worker startup flags | `src/process/manager.rs:517-521` | `--worker`, `--worker-id`, `--port`, `--cpu-affinity`, `--total-workers` not documented in process_lifecycle.md |
| SO_REUSEPORT detection logic | `src/overseer/mode.rs:29-37` | `detect_upgrade_mode()` not explained |
| IPC session key mechanism | `src/process/ipc_signed.rs` | How key exchange works, fallback behavior |
| Drain protocol states | `src/overseer/drain_manager.rs:371-398` | `handle_drain_request` state machine not documented |
| Upgrade state machine | `src/overseer/state.rs:8-66` | `UpgradeState`, `is_terminal()`, `is_transition()`, `max_duration_secs()` not explained |
| Preflight validation | `src/overseer/preflight.rs` | What checks are performed, what failures are retryable |
| Mesh agent lifecycle | `src/overseer/process.rs:324-340` | Mesh agent spawn/restart logic not documented |

---

## 8. Architecture Issues Summary

| Issue | Severity | Fix Complexity |
|-------|----------|----------------|
| CPU pinning not implemented | Medium | Low (need to parse flag and call sched_setaffinity) |
| gRPC control plane not built | High | High (significant implementation work) |
| IPC signing verification is fake | High | Medium (implement real signature verification) |
| Temp file cleanup missing | Medium | Low |
| Wrong path references in doc | Low | Low (doc update) |

---

## 9. Recommendations

### Immediate (Do Now)

1. **Fix CPU affinity**: Worker main.rs must call `nix::sched::sched_setaffinity()` when `--cpu-affinity` is specified
2. **Clean up temp IPC key files**: Use `auto_unlink_on_drop` pattern
3. **Fix IPC signing verification**: Actually verify HMAC signatures, don't just log

### Short Term (This Sprint)

4. **Update `process_lifecycle.md`** to reflect actual implementation:
   - Remove references to `src/supervisor/` (use `src/overseer/`)
   - Remove gRPC references (use Unix socket IPC)
   - Document actual IPC message types
   - Document drain protocol

5. **Add rate limit per worker type**: Separate namespaces for base workers, static workers, unified server workers

### Long Term (Next Release)

6. **Implement gRPC control plane** if required, or update document to match Unix socket reality
7. **Add CPU affinity integration tests** that verify workers actually run on assigned cores
8. **Consider replacing `parking_lot` with `tokio::sync` primitives** in async contexts

---

## Appendix: Key File References

| File | Purpose | Key Functions |
|------|---------|---------------|
| `src/overseer/process.rs` | OverseerProcess manages master lifecycle | `spawn_master()`, `check_master_health()`, `run()` |
| `src/overseer/upgrade.rs` | Orchestrator handles zero-downtime upgrades | `stage()`, `apply()`, `rollback()`, `apply_with_auto_rollback()` |
| `src/overseer/state.rs` | UpgradeState machine and persistence | `UpgradeState`, `OverseerState`, `Persistence` |
| `src/overseer/drain_manager.rs` | Worker drain coordination | `DrainManager`, `DrainProtocol` |
| `src/process/manager.rs` | ProcessManager spawns/monitors workers | `spawn_worker()`, `handle_heartbeat()`, `check_workers_health()` |
| `src/process/ipc.rs` | IPC message definitions | `Message` enum (80+ variants) |
| `src/process/ipc_signed.rs` | IPC message signing | `IpcSigner`, `generate_session_key()` |
| `src/master/ipc.rs` | Master IPC connection handler | `handle_worker_connection_internal()` |
| `src/process/socket_fd.rs` | Socket creation with SO_REUSEPORT | `create_listening_socket()`, `SocketHolder` |
| `src/overseer/mode.rs` | Upgrade mode detection | `detect_upgrade_mode()`, `probe_reuseport_support()` |
