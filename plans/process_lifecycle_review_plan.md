# Process Lifecycle Architecture Review - Improvement Plan

## Executive Summary

The architecture document `architecture/process_lifecycle.md` is generally accurate but contains several stale references, incorrect line numbers, and missing features. The most significant issues are related to outdated Overseer terminology, incorrect file references for SO_REUSEPORT, incorrect CLI flag descriptions, and an incomplete drain coordination implementation in the Supervisor.

---

## 1. Discrepancies Found

### 1.1 Stale Overseer Terminology (Lines 7-15, 17-25)

**Document says:**
- "Overseer (Legacy - Parent Process)" at lines 7-15
- "Master (Legacy - Mid-tier Process)" at lines 17-25
- "Key Logic: `src/overseer/`" and "`src/startup/master.rs`, `src/master/`"

**Actual State:**
- Overseer and Master still exist as runnable code paths (not truly "legacy")
- `--master` flag IS available in CLI (`src/main.rs:35`) and invokes `run_master_mode()`
- `run_overseer_mode()` IS importable and invokable via `--master` if `mesh` feature is enabled
- Overseer code exists at `src/overseer/` and is fully functional

**Verification:**
```rust
// main.rs:19
use synvoid::startup::master::{run_master_mode, run_overseer_mode};

// main.rs:529-531
} else if args.master {
    init_logging_simple();
    run_master_mode(args.config_path, args.log_level);
```

**Line:** `architecture/process_lifecycle.md:7-15`, `architecture/process_lifecycle.md:17-25`

**Severity:** Medium - Documentation claims modes are unreachable but they are reachable

---

### 1.2 Incorrect SO_REUSEPORT File Reference (Line 50)

**Document says:**
> "See `src/overseer/spawn.rs:43`"

**Actual Code:**
- `src/overseer/spawn.rs:43` is a blank line within `SpawnConfig::for_current_binary()`
- The `reuse_port: false` default is at line 43 in the implementation, but the file is `src/startup/worker.rs` that actually passes `reuse_port: false` to worker args
- The claim mixes up contexts between Overseer spawn config and worker startup args

**Actual Location for SO_REUSEPORT in worker spawning:**
- `src/startup/worker.rs:42` - `reuse_port: false` in `build_unified_server_worker_args()`
- `src/process/manager.rs:583-585` - passes `--reuse-port` flag to worker process when `reuse_port: true`

**Correct Reference:** `src/startup/worker.rs:42` for initial worker spawn with `reuse_port: false`

**Severity:** Low - Minor inaccuracy in file reference

---

### 1.3 CPU Affinity Documentation Incomplete (Line 51)

**Document says:**
> "On Linux, workers are automatically assigned CPU affinity based on worker ID via `sched_setaffinity`. Not supported on macOS/BSD (logs warning)."

**Actual Implementation (`src/worker/unified_server.rs:183-194`):**
```rust
if let Some(core) = args.cpu_affinity {
    #[cfg(target_os = "linux")]
    {
        use nix::sched::{sched_setaffinity, CpuSet};
        let pid = std::process::id();
        let mut cpuset = CpuBitmask::new();
        cpuset.set(core);
        if let Err(e) = sched_setaffinity(pid, &cpuset) {
            tracing::warn!("Failed to set CPU affinity: {}", e);
        }
    }
}
```

**Issues Found:**
1. **Linux-only condition is correct** - but the code doesn't log a warning on macOS/BSD when `cpu_affinity` is passed
2. **CPU affinity is NOT automatic** - it must be explicitly passed via `--cpu-affinity` flag
3. The Supervisor does pass CPU affinity when spawning unified workers (`src/process/manager.rs:667-668`)

**Actual Behavior:**
- Supervisor assigns CPU affinity based on `worker_id % cpu_count` (`src/process/manager.rs:667`)
- Only when spawning unified server workers via `spawn_unified_server_worker_with_id()`
- Regular `--worker` mode does NOT automatically get CPU affinity

**Severity:** Medium - Documentation implies automatic CPU pinning for all workers

---

### 1.4 Missing Drain Coordination in Supervisor

**Document says (Lines 88-93):**
> "The Supervisor provides a unified view of the system health... Self-Healing: If a worker fails, the Supervisor immediately spawns a replacement and pins it to the correct core."

**Actual State:**
- Supervisor's `ProcessManager` does handle worker restart via `reap_zombies()` and `handle_failure_restarts()`
- **No drain coordination in Supervisor** - drain is only implemented in:
  - `src/process/manager.rs:833-862` (`drain_unified_server_worker_async`)
  - `src/process/manager.rs:997-1021` (`drain_static_worker_async`)
- Supervisor process does NOT invoke drain during normal operations
- Drain protocol exists (`Message::UnifiedServerWorkerDrain`, `Message::StaticWorkerDrain`) but is not triggered by supervisor during upgrades

**Severity:** High - Drain coordination during upgrades is missing from Supervisor

---

### 1.5 Supervisor Missing gRPC API Implementation

**Document says (Lines 36-38):**
> "- **gRPC API:** Hosts the formal Control Plane API (`proto/control.proto`) for remote management."

**Actual State:**
- gRPC server IS started in `src/supervisor/process.rs:127-134`
- BUT the `ControlPlaneService` implementation in `src/supervisor/api.rs` only implements:
  - `get_status` - basic status
  - `reload_config` - simple reload
  - `stop` - shutdown signal
  - `block_ip` / `unblock_ip` - IP blocking
- **Missing critical APIs** that exist in Master/Overseer:
  - No drain coordination
  - No rolling restart
  - No upgrade orchestration
  - No worker scaling

**Severity:** High - Supervisor is missing key control plane APIs described in documentation

---

### 1.6 Legacy Overseer Still Imported and Usable

**Document says (Lines 31-32):**
> "Consolidated Mode (default)... THIS IS THE ONLY FUNCTIONAL MODE - no CLI flag exists to select Legacy Mode."

**Actual State:**
- `--master` flag EXISTS (`src/main.rs:35`) and invokes `run_master_mode()`
- `run_overseer_mode()` is imported from `src/startup/master.rs` (line 19)
- The entire Overseer module exists at `src/overseer/` and is fully functional
- It is NOT truly legacy/unreachable code

**Severity:** Medium - Documentation claim about reachability is incorrect

---

## 2. Bugs and Security Issues

### 2.1 BUG-PL-1 Status Update Needed

**AGENTS.md says:**
> "BUG-PL-1 Master mode CLI flag (`src/main.rs:27` - --master flag now functional)"

**But documentation at `architecture/process_lifecycle.md:31-32` says:**
> "Legacy Mode (code only, not selectable): ... there's no CLI flag to enable it"

**Resolution Needed:** Either:
1. Update documentation to reflect that `--master` flag IS functional
2. OR disable the `--master` flag in CLI to match documentation

**Severity:** Documentation inconsistency with actual code behavior

---

### 2.2 No Actual Drain Protocol in Supervisor Context

The Supervisor has NO drain message handling. When examining `src/supervisor/process.rs`:
- `handle_connection()` at line 168 only handles worker messages and admin commands
- No drain-specific message handlers exist
- The drain methods in `ProcessManager` exist but are not called from supervisor context

**This is NOT a bug in process_lifecycle.md** - it's a gap between documented architecture and implementation.

**Severity:** Feature gap - drain coordination needs to be added to supervisor

---

## 3. Concrete Improvements Suggested

### 3.1 Update Process Hierarchy Documentation

**Current (Lines 5-41):**
```
### 1. Overseer (Legacy - Parent Process)
### 2. Master (Legacy - Mid-tier Process)
### 3. Supervisor (Consolidated Control Plane)
```

**Suggested Revision:**
```
### 1. Supervisor Process (Default - Primary Mode)
   - Default mode when no flags specified
   - Spawns UnifiedServerWorkers directly
   - Handles control plane via gRPC API

### 2. Master Process (--master flag)
   - Legacy mode, child of Overseer
   - Invoked via: `synvoid --master`
   - Handles worker management, admin API, block store, IPC

### 3. Overseer Process (run_overseer_mode)
   - Top-level orchestrator (parent of Master)
   - Handles health monitoring, recovery, upgrades
   - Invoked via: `synvoid --mesh --overseer` (or similar)
```

**Files to Reference:**
- `src/main.rs:531` - `run_master_mode()` invocation
- `src/startup/master.rs:23` - `run_master_mode()` definition
- `src/startup/master.rs:89` - `run_overseer_mode()` definition
- `src/supervisor/process.rs:212` - `run_supervisor_mode()` definition

---

### 3.2 Fix SO_REUSEPORT Reference

**Current (Line 50):**
> "See `src/overseer/spawn.rs:43`"

**Should be:**
> "Initial workers use `reuse_port: false`. During upgrades, `spawn_upgrade_worker()` passes `--reuse-port` flag. See `src/startup/worker.rs:42` and `src/process/manager.rs:558-612`."

---

### 3.3 Clarify CPU Affinity Behavior

**Current (Line 51):**
> "On Linux, workers are automatically assigned CPU affinity based on worker ID via `sched_setaffinity`."

**Should be:**
> "On Linux, unified server workers are assigned CPU affinity based on `worker_id % cpu_count`. CPU affinity must be explicitly passed via CLI (`--cpu-affinity`) or assigned by the Supervisor during worker spawning (see `src/process/manager.rs:667-668`).

---

### 3.4 Add Drain Coordination to Supervisor

**Missing from Supervisor:**
1. Drain message types (`Message::UnifiedServerWorkerDrain`)
2. Drain state tracking
3. Rolling restart with drain
4. Upgrade handoff with drain

**Suggested Implementation:**
- Add `DrainManager` integration to `SupervisorProcess`
- Implement `handle_drain_request()` in supervisor
- Add drain-related gRPC APIs

---

### 3.5 Document Actual Worker Types Accurately

**Current (Lines 45-47):**
> "- **UnifiedServerWorker:** Primary worker..."
> "- **StaticWorker:** Dedicated worker..."
> "- **Legacy Worker (BaseWorkerProcess):** Deprecated raw TCP/UDP proxy worker..."

**Should Clarifty:**
- `UnifiedServerWorkerProcess` - managed by `ProcessManager` in `src/process/worker.rs:185-216`
- `StaticWorkerProcess` - managed by `ProcessManager` in `src/process/worker.rs:158-183`
- `WorkerProcess` - legacy pool workers in `src/process/worker.rs:93-156`
- BaseWorkerProcess is NOT deprecated - it's the base type for all workers

---

### 3.6 Update SO_REUSEPORT Section (Lines 72-73, 84)

**Current:**
> "Independent Listeners: Each worker opens its own set of listeners using `SO_REUSEPORT`."
> "SO_REUSEPORT allows both old and new workers to coexist during the transition..."

**Should Add:**
- Initial workers use `reuse_port: false` (bound once, no sharing)
- Upgrade workers use `reuse_port: true` (can share port with old workers)
- Actual implementation in:
  - `src/tcp/listener.rs:115-124`
  - `src/process/socket_fd.rs:268`
  - `src/platform/socket.rs:371-394`

---

## 4. File Reference Corrections

| Document Line | Document Reference | Actual Location | Notes |
|---------------|---------------------|-----------------|-------|
| 15 | `src/overseer/` | `src/overseer/` | Correct - but Overseer is still functional |
| 25 | `src/startup/master.rs`, `src/master/` | `src/startup/master.rs:23` | Only `run_master_mode` in startup, `src/master/` contains handlers |
| 39 | `src/supervisor/` | `src/supervisor/` | Correct |
| 43 | `src/worker/` | `src/worker/` | Correct |
| 50 | `src/overseer/spawn.rs:43` | `src/startup/worker.rs:42` | Wrong file reference |
| 72 | SO_REUSEPORT claim | `src/tcp/listener.rs:115` | Accurate but no file ref given |

---

## 5. Priority Recommendations

### P0 - Critical (Documentation is Incorrect)
1. **Update reachability claims** - either disable `--master` flag or update docs to reflect it IS functional
2. **Add drain coordination to Supervisor** - implement missing upgrade handling

### P1 - High Priority
3. **Fix SO_REUSEPORT file reference** - accuracy matters for debugging
4. **Clarify CPU affinity** - "automatic" is misleading

### P2 - Medium Priority
5. **Update process hierarchy description** - reflect actual 3-tier hierarchy more accurately
6. **Document worker types correctly** - BaseWorkerProcess is NOT deprecated

### P3 - Low Priority
7. **Add actual file references** - where not currently provided
8. **Cross-link related docs** - e.g., `docs/PROCESS_MANAGEMENT.md` for SO_REUSEPORT details

---

## 6. Verification Commands

```bash
# Verify Overseer module exists and is imported
grep -r "run_overseer_mode" src/ --include="*.rs"

# Verify --master flag exists
grep -A2 "long.*master" src/main.rs

# Verify SO_REUSEPORT implementation
rg "reuse_port" src/process/manager.rs | head -20

# Verify CPU affinity in supervisor
rg "cpu_affinity" src/process/manager.rs

# Verify drain methods exist
rg "drain.*worker.*async" src/process/manager.rs
```
