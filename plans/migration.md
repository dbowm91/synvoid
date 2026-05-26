# Supervisor Migration Plan: Eradicate Legacy Overseer/Master Paradigm

**Generated:** 2026-05-26
**Status:** PLANNED (not started)
**Architecture:** Supervisor-Worker Model (Single Process Type)

---

## Executive Summary

Consolidate all process management into a single **Supervisor-Worker** architecture with full zero-downtime upgrade capability. Remove all legacy Overseer/Master complexity while preserving health validation, staged rolling restarts, and crash recovery.

### Goals

1. **Single process architecture**: Supervisor is the ONLY management process
2. **Zero-downtime upgrades**: Rolling restarts with drain coordination and health validation
3. **Crash recovery**: Upgrade state survives Supervisor crashes
4. **Clean erasure**: Full removal of `overseer/` and `master.rs` (1915+ lines)

### What We're Building

A simplified but complete upgrade system for Supervisor that providing:

| Capability | Implementation |
|------------|----------------|
| Binary staging | Preflight validation with checksum verification |
| Rolling restart | One-at-a-time worker spawn with SO_REUSEPORT |
| Health validation | HTTP health checks against worker ports |
| Drain coordination | Worker drain endpoint + confirmation polling |
| Auto-rollback | Health failure triggers rollback to previous workers |
| State persistence | Atomic JSON file write for crash recovery |
| CLI + gRPC API | Both command-line and gRPC control for upgrade operations |

---

## Before: Legacy Architecture (Overseer → Master → Workers)

```
synvoid (no args) → run_supervisor_mode()     [NEW - 2026]
synvoid --master      → run_master_mode()       [LEGACY]
synvoid --overseer    → run_overseer_mode()     [LEGACY - unused]

Overseer Process (zero-downtime upgrade coordinator)
├── Manages Master lifecycle
├── Dual-master socket handoff
├── Complex 11-state upgrade state machine
├── Socket handoff via SCM_RIGHTS
└── State persisted to overseer-state.json

Master Process (worker orchestrator)
├── Spawns UnifiedServerWorker processes
├── Owns admin API + gRPC control
├── IPC listener for worker commands
└── ProcessManager (spawn, monitor, restart)

Workers (UnifiedServerWorker)
├── HTTP/HTTPS/HTTP3 listeners [SO_REUSEPORT]
├── WAF processing
└── Upstream proxy
```

### Legacy Removal Targets

| File/Module | Lines | Reason |
|-------------|-------|--------|
| `src/startup/master.rs` | ~1031 | Functionality migrated to supervisor |
| `src/overseer/` module | ~1915 | Completely unused in current flow |
| `src/startup/mod.rs` MasterState | ~100 | Replaced by SupervisorState |
| `OVerseerConfig`, `OverseerProcess` | N/A | Never instantiated |
| `--master` CLI flag | N/A | Legacy entry point |

---

## After: Unified Supervisor Architecture

```
synvoid (no args) → run_supervisor_mode() [ONLY MODE]

Supervisor Process (unified management)
├── Simple 5-state upgrade machine
├── Orchestrates rolling worker restarts
├── Owns admin API + gRPC control
├── IPC listener for worker commands
├── State persisted to supervisor-state.json
└── ProcessManager (spawn, monitor, restart, drain)

Workers (UnifiedServerWorker)
├── HTTP/HTTPS/HTTP3 listeners [SO_REUSEPORT]
├── WAF processing
├── Upstream proxy
└── Drain endpoint (/__internal__/drain, /__internal__/drain-status)
```

---

## Phase 1: Extract Required Capabilities from Overseer

### 1.1 Move Health Checking to Supervisor

**Source:** `src/overseer/health.rs`
**Target:** `src/supervisor/health.rs`
**Lines:** ~700

| Method | Status | Notes |
|--------|--------|-------|
| `HealthChecker::new()` | Keep | Port range + config |
| `validate_all()` | Keep | Basic HTTP health check |
| `validate_with_metrics()` | Keep | Returns success rate |
| `enhanced_health_check_with_baseline()` | Keep | Latency comparison |
| `comprehensive_validation()` | Simplify | Single pass, no A/B |
| `shadow_traffic_test()` | **DELETE** | Overkill for simple rollout |
| `enhanced_health_result()` | Keep | For auto-rollback decisions |
| `retry_with_timeout()` | Keep | Utility function |
| `wait_for_condition()` | Keep | Utility function |

**Why keep:** Health validation is essential for safe upgrades. We want to know if new workers are healthy before routing traffic to them.

### 1.2 Keep Drain Protocol in ProcessManager

**Source:** `src/overseer/drain_manager.rs`
**Status:** Already implemented in `ProcessManager::drain_unified_server_worker_async()`

| Method | Status | Notes |
|--------|--------|--------|
| Drain endpoint | Keep | `/__internal__/drain` |
| Drain status endpoint | Keep | `/__internal__/drain-status` |
| IPC drain message | Keep | Already wired |
| Connection tracking | Keep | Already functional |

**Why keep:** Workers need drain endpoint to gracefully stop accepting new connections while processing existing requests.

### 1.3 Extract Preflight Validation

**Source:** `src/overseer/preflight.rs`
**Target:** `src/supervisor/preflight.rs`
**Lines:** ~300

| Method | Status | Notes |
|--------|--------|-------|
| `PreflightConfig` | Keep | Timeout, startup time bounds |
| `PreflightValidator` | Keep | Binary + config validation |
| `PreflightResult` | Keep | Success/failure with reasons |
| `PreflightError` | Keep | Enum of validation failures |

**Why keep:** Preflight catches obviously broken binaries before wasting time on rolling restart.

### 1.4 Simplified State Machine

**Source:** `src/overseer/state.rs`
**Target:** `src/supervisor/upgrade_state.rs`
**Lines:** ~250 → ~100

**OLD: 11 States**
```rust
enum UpgradeState {
    Idle,
    Staging,
    Spawning,
    Validating,
    Draining,
    Committed,
    RollingBack,
    Failed,
    RecoveryNeeded,
    DualMasterActive,      // REMOVE
    DrainingOldMaster,     // REMOVE
}
```

**NEW: 5 States**
```rust
enum UpgradeState {
    Idle,                    // No upgrade in progress
    Staging(String),         // Binary staged with path + checksum
    Validating(usize),      // N workers being health checked
    Committing(usize),     // N workers left to upgrade
    RollingBack(String),    // Upgrade failed, rolling back: reason
}
```

**Why simplify:** Dual-master states are irrelevant for Supervisor.
Single-master rolling restarts don't need concurrent old+new master tracking.

### 1.5 What to DELETE from Overseer

| File | Lines | Reason |
|------|-------|--------|
| `src/overseer/socket_handoff.rs` | ~790 | Dual-master only, uses SCM_RIGHTS |
| `src/overseer/process.rs` | ~1915 | Full module removal |
| `src/overseer/upgrade.rs` | ~700 | Replace with simpler supervisor/upgrade.rs |
| `src/overseer/spawn.rs` | ~250 | Duplicate spawn logic in ProcessManager |
| `src/overseer/drain_manager.rs` | ~457 | Drain already in ProcessManager |
| `src/overseer/health.rs` | ~700 | Move to supervisor/ |
| `src/overseer/preflight.rs` | ~300 | Move to supervisor/ |
| `src/overseer/state.rs` | ~250 | Simplify and move |
| `src/overseer/mode.rs` | ~76 | Keep for SO_REUSEPORT detection |
| `src/overseer/cli.rs` | ~200 | Legacy CLI, won't be needed |
| `src/overseer/constants.rs` | ~50 | Cleanup constants |
| `src/overseer/checksum.rs` | ~100 | Move to supervisor/ |
| `src/overseer/rollback.rs` | ~200 | Simplified into supervisor/upgrade.rs |
| `src/overseer/ipc_client.rs` | ~300 | IPC already in ProcessManager |
| `src/overseer/connection_tracker.rs` | ~200 | Connection tracking already in ProcessManager |
| `src/overseer/upgrade.rs` complex | ~700 | Delete after extraction |

**Total deletion:** ~1915 lines of overseer code

---

## Phase 2: Create Supervisor Upgrade Orchestrator

### 2.1 New File: `src/supervisor/upgrade.rs`

```rust
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::RwLock;

pub struct UpgradeOrchestrator {
    state: RwLock<UpgradeState>,
    config: UpgradeConfig,
    process_manager: Arc<ProcessManager>,
    health_checker: Arc<HealthChecker>,
    state_persistence: UpgradeStatePersistence,
}

#[derive(Clone)]
pub enum UpgradeState {
    Idle,
    Staging(StagedBinary),
    Validating { new_workers: Vec<WorkerId> },
    Committing { upgraded: usize, remaining: usize },
    RollingBack { reason: String },
}

pub struct StagedBinary {
    pub path: PathBuf,
    pub checksum: [u8; 32],
    pub staged_at: u64,
}

pub struct UpgradeConfig {
    pub rolling_window_size: usize,      // Default: 1 (one at a time)
    pub health_check_timeout_secs: u64,  // Default: 30
    pub drain_timeout_secs: u64,        // Default: 60
    pub max_retries: u32,               // Default: 3
    pub rollback_on_health_failure: bool, // Default: true
}
```

### 2.2 Key Methods

```rust
impl UpgradeOrchestrator {
    /// Stage a binary for upgrade: validate + persist state
    pub async fn stage(&self, binary_path: PathBuf) -> Result<StagedBinary, UpgradeError>;

    /// Apply the staged binary: rolling restart
    pub async fn apply(&self) -> Result<UpgradeResult, UpgradeError>;

    /// Rollback to previous state
    pub async fn rollback(&self) -> Result<(), UpgradeError>;

    /// Get current upgrade state
    pub async fn get_state(&self) -> UpgradeState;

    /// Recover from crashed upgrade state
    pub async fn recover_from_crash(&self) -> Result<(), UpgradeError>;
}
```

### 2.3 Rolling Restart Flow (apply method)

```
1. Validate staged binary exists and checksum matches
2. For each worker in current pool (one at a time):
   a. Spawn new worker with same port + SO_REUSEPORT
   b. Health check new worker (poll /__internal__/health)
   c. If healthy:
      - Send drain signal to OLD worker
      - Wait for drain confirmation (/__internal__/drain-status)
      - Stop old worker gracefully
   d. If unhealthy:
      - Stop new worker
      - Rollback all previously upgraded workers
      - Return error
3. Mark upgrade as committed
4. Clean up old upgrade state file
```

### 2.4 State Persistence

**File:** `$RUNTIME_DIR/synvoid/supervisor-upgrade-state.json`

```json
{
  "version": 1,
  "state": "Staging|Validating|Committing|RollingBack",
  "staged_binary": {
    "path": "/path/to/binary",
    "checksum": "sha256:...",
    "staged_at": 1748250600
  },
  "new_workers": [3, 4, 5, 6],
  "original_workers": [1, 2],
  "upgraded_count": 2,
  "remaining_count": 4,
  "rollback_reason": null,
  "last_updated": 1748250900
}
```

**Persistence rules:**
- Write atomically using temp file + rename
- Load on Supervisor startup
- If state is non-Idle, attempt recovery (rollback or continue)

### 2.5 Auto-Rollback Triggers

```rust
// Rollback triggers:
// 1. Health check fails for new worker (N consecutive failures)
// 2. Drain times out for old worker
// 3. New worker crashes during upgrade
// 4. Supervisor receives shutdown signal during upgrade

// Rollback action:
// 1. Mark state as RollingBack
// 2. Stop any new workers spawned
// 3. Kill any workers that are in draining state
// 4. Kill any workers in Validating state
// 5. Restart original workers if they were stopped
// 6. Mark state as Idle
```

---

## Phase 3: ProcessManager Upgrade Path

### 3.1 Already Existing

The following already exist in `src/process/manager.rs`:

| Method | Status | Notes |
|--------|--------|-------|
| `spawn_upgrade_worker()` | ✅ Exists | Uses `--reuse-port` flag |
| `drain_unified_server_worker_async()` | ✅ Exists | Drain protocol implemented |
| `get_workerHealth()` | ✅ Exists | Health status via IPC |
| `spawn_unified_server_workers()` | ✅ Exists | Base spawn method |

### 3.2 Changes Needed

1. **Add upgrade spawn config to `ProcessManagerConfig`:**
```rust
pub struct ProcessManagerConfig {
    // ... existing fields ...
    pub upgrade_mode: bool,
    pub reuse_port: bool,
}
```

2. **Expose upgrade spawning to ProcessManager public API:**
```rust
impl ProcessManager {
    pub async fn spawn_worker_for_upgrade(&self, port: u16) -> Result<WorkerId, ProcessError>;
    pub async fn drain_and_stop_worker(&self, id: WorkerId) -> Result<(), ProcessError>;
}
```

3. **Add health check that respects upgrade state:**
- Worker health check should query `/__internal__/health`
- Return `WorkerHealth::Healthy` only if HTTP 200

---

## Phase 4: CLI + gRPC API

### 4.1 CLI Flags (main.rs)

**Add to Args struct:**
```rust
#[arg(long, help = "Stage a binary for upgrade")]
stage_upgrade: Option<PathBuf>,

#[arg(long, help = "Apply staged upgrade (rolling restart)")]
apply_upgrade: bool,

#[arg(long, help = "Rollback in-progress upgrade")]
rollback_upgrade: bool,

#[arg(long, help = "Show upgrade status")]
upgrade_status: bool,
```

**Add handlers:**
```rust
if let Some(path) = args.stage_upgrade {
    handle_stage_upgrade(path)?;
}
if args.apply_upgrade {
    handle_apply_upgrade()?;
}
if args.rollback_upgrade {
    handle_rollback_upgrade()?;
}
if args.upgrade_status {
    handle_upgrade_status()?;
}
```

### 4.2 gRPC API Extensions

**File:** `src/supervisor/api.rs`

```protobuf
service ControlPlane {
    // ... existing methods ...
    rpc StageUpgrade(StageUpgradeRequest) returns (StageUpgradeResponse);
    rpc ApplyUpgrade(ApplyUpgradeRequest) returns (ApplyUpgradeResponse);
    rpc RollbackUpgrade(RollbackUpgradeRequest) returns (RollbackUpgradeResponse);
    rpc GetUpgradeStatus(GetUpgradeStatusRequest) returns (UpgradeStatus);
}
```

**Request/Response types:**
```rust
message StageUpgradeRequest {
    string binary_path = 1;
}
message StageUpgradeResponse {
    bool success = 1;
    string checksum = 2;
    string error = 3;
}

message ApplyUpgradeRequest {
    // Uses staged binary from previous call
}
message ApplyUpgradeResponse {
    bool success = 1;
    uint64 workers_upgraded = 2;
    uint64 workers_remaining = 3;
    string error = 4;
}

message RollbackUpgradeRequest {}
message RollbackUpgradeResponse {
    bool success = 1;
    string reason = 2;
}

message GetUpgradeStatusRequest {
    // Can be empty - uses current state
}
message UpgradeStatus {
    string state = 1;        // "Idle", "Staging", etc.
    string staged_path = 2;
    string staged_checksum = 3;
    uint64 staged_at = 4;
    uint64 upgraded_count = 5;
    uint64 remaining_count = 6;
    string rollback_reason = 7;
}
```

---

## Phase 5: Remove Legacy Code

### 5.1 Delete Files

| File | Command | Notes |
|------|---------|-------|
| `src/startup/master.rs` | DELETE | Fully replaced by supervisor |
| `src/overseer/` entire module | DELETE | 1915+ lines removed |

### 5.2 Update `src/startup/mod.rs`

**Remove:**
```rust
pub mod master;  // DELETE THIS
pub struct MasterState { ... }  // DELETE THIS
pub struct MasterStateTrackers { ... }  // DELETE THIS
```

**Keep:**
```rust
pub mod bootstrap;
pub mod daemon;
pub mod worker;
```

### 5.3 Update `src/main.rs`

**Remove imports:**
```rust
// DELETE:
#[cfg(feature = "mesh")]
use synvoid::master::handle_export_threat_feed;
use synvoid::master::{
    handle_configtest, handle_generatenewtoken, handle_generatetoken, handle_rehash, handle_status,
    handle_stop,
};
// Keep:
use synvoid::worker::{
    run_static_worker, run_unified_server_worker, setup_unified_server_panic_handler,
    setup_worker_panic_handler,
};
#[cfg(feature = "mesh")]
use synvoid::startup::master::{run_master_mode, run_overseer_mode};  // DELETE
use synvoid::startup::worker::{build_static_worker_args, build_unified_server_worker_args};
use synvoid::supervisor::run_supervisor_mode;
```

**Remove `--master` flag:**
```rust
struct Args {
    // REMOVE:
    #[arg(long, help = "Run as master process (legacy mode - managed by Overseer)")]
    master: bool,
    // ... keep everything else ...
}
```

**Simplify main() routing:**
```rust
// BEFORE:
if args.static_worker { ... }
else if args.unified_server_worker { ... }
else if args.mesh_agent { ... }
else if args.master { run_master_mode(...) }
else if args.wasm_jail { ... }
else if args.yara_jail { ... }
else { run_supervisor_mode(...) }

// AFTER:
if args.static_worker { ... }
еlse if args.unified_server_worker { ... }
else if args.mesh_agent { ... }
else if args.wasm_jail { ... }
else if args.yara_jail { ... }
else { run_supervisor_mode(...) }  // Supervisor is ONLY management process
```

### 5.4 Update AGENTS.md

**Remove from Known Deferred Items:**
- SUP-1 is Intentional (localhost IPC) - keep as is

**Update process architecture documentation:**
- Remove references to Overseer/Master hierarchy
- Update Process Hierarchy table to show Supervisor as only management process
- Remove "Requires investigation for BaseWorkerProcess" since we've unified

**Remove stale bug entries:**
- BUG-PL-1 (--master flag) - this is no longer relevant since we're removing --master

---

## Phase 6: Testing

### 6.1 Integration Tests Required

**Test file:** `tests/upgrade_test.rs`

| Test | Description |
|------|-------------|
| `test_stage_upgrade_checksum_mismatch` | Stage with invalid checksum |
| `test_stage_upgrade_binary_not_found` | Stage non-existent binary |
| `test_apply_upgrade_rolling_restart` | Full rolling restart of 4 workers |
| `test_apply_upgrade_health_failure_rollback` | Rollback when health check fails |
| `test_apply_upgrade_drain_timeout_rollback` | Rollback when drain times out |
| `test_rollback_after_partial_upgrade` | Rollback after upgrading 2 of 4 workers |
| `test_crash_recovery_on_startup` | Verify state recovery from persisted file |
| `test_concurrent_upgrade_rejected` | Can't stage while upgrade in progress |
| `test_upgrade_status_cli` | CLI `--upgrade-status` output |
| `test_upgrade_status_grpc` | gRPC `GetUpgradeStatus` response |

### 6.2 Verification Commands

```bash
# After migration, run:
cargo check --no-default-features --features mesh,dns
cargo test --lib --no-run
cargo test --test upgrade_test

# Verify no references to run_master_mode or run_overseer_mode:
grep -r "run_master_mode\|run_overseer_mode" src/  # Should return empty
grep -r "overseer::" src/  # Should return empty
```

---

## Detailed Wave Execution

### Wave 1: Extract Health, Preflight, State (Day 1)

1. Move `src/overseer/health.rs` to `src/supervisor/health.rs`
   - Remove shadow traffic test methods
   - Keep core health check methods
2. Move `src/overseer/preflight.rs` to `src/supervisor/preflight.rs`
3. Create simplified `src/supervisor/upgrade_state.rs`
4. Create `src/supervisor/upgrade.rs` skeleton with state machine
5. Implement state persistence (load/save upgrade state)

**Verify:** Supervisor builds, health checks work

### Wave 2: Implement Rolling Restart (Day 2-3)

1. Implement `stage()` method with preflight validation
2. Implement `apply()` method with rolling restart loop
3. Wire ProcessManager drain + upgrade spawn
4. Wire health checker to rolling restart
5. Implement `rollback()` method

**Verify:** `cargo test --lib rolling_restart` passes

### Wave 3: Auto-Rollback + Recovery (Day 4)

1. Implement auto-rollback triggers
2. Implement crash recovery on startup
3. Add gRPC upgrade methods
4. Add upgrade state persistence

**Verify:** Crash recovery test passes

### Wave 4: CLI Integration (Day 5)

1. Add `--stage-upgrade`, `--apply-upgrade`, `--rollback-upgrade`, `--upgrade-status` flags
2. Implement CLI handlers in main.rs
3. Update gRPC control API

**Verify:** CLI upgrade commands work end-to-end

### Wave 5: Remove Legacy Code (Day 6-7)

1. Delete `src/startup/master.rs`
2. Delete `src/overseer/` module
3. Update `src/startup/mod.rs`
4. Update `src/main.rs`
5. Update AGENTS.md

**Verify:** 
- `cargo check --lib` passes
- No references to `run_master_mode` or `overseer::`
- All profiles compile

### Wave 6: Integration Testing (Day 8)

1. Write comprehensive upgrade tests
2. Run full test suite
3. Fix any issues found

**Verify:** Full test suite passes

---

## Files Modified/Created Summary

### New Files

| File | Lines | Purpose |
|------|-------|---------|
| `src/supervisor/health.rs` | ~600 | Health checking (from overseer) |
| `src/supervisor/preflight.rs` | ~250 | Preflight validation (from overseer) |
| `src/supervisor/upgrade_state.rs` | ~100 | Simplified state machine |
| `src/supervisor/upgrade.rs` | ~400 | Upgrade orchestrator |
| `tests/upgrade_test.rs` | ~400 | Integration tests |

### Deleted Files

| File | Lines | Reason |
|------|-------|--------|
| `src/startup/master.rs` | ~1031 | Replaced by supervisor |
| `src/overseer/` entire module | ~1915 | Unused legacy code |

### Modified Files

| File | Changes |
|------|---------|
| `src/startup/mod.rs` | Remove MasterState, master module |
| `src/main.rs` | Remove --master flag, add upgrade flags |
| `src/supervisor/process.rs` | Add upgrade orchestrator integration |
| `src/process/manager.rs` | Add upgrade spawn methods |
| `src/supervisor/api.rs` | Add upgrade RPC methods |
| `AGENTS.md` | Update architecture docs, remove stale entries |

### Lines Removed (Net)

| Category | Lines |
|----------|-------|
| Overseer module | -1915 |
| Master module | -1031 |
| Legacy cleanup | ~-300 |
| **Total Removed** | **~-3246** |

### Lines Added

| Category | Lines |
|----------|-------|
| Supervisor health | +600 |
| Supervisor preflight | +250 |
| Supervisor upgrade state | +100 |
| Supervisor upgrade orchestrator | +400 |
| Upgrade tests | +400 |
| **Total Added** | **+1750** |

**Net Result:** ~1500 lines removed overall

---

## Risk Mitigation

| Risk | Mitigation | Fallback |
|------|------------|----------|
| Upgrade state corruption on crash | Atomic file rename pattern | Manual restart with --force |
| Health check false positives | Multiple checks with timeout | Indefinite wait for stable health |
| Worker drain timeout | Configurable drain timeout | Wait longer configured |
| Binary checksum doesn't match | Preflight SHA256 check | Reject staging |
| gRPC/CLI state mismatch | Both use same UpgradeOrchestrator | CLI overrides gRPC |

---

## Dependencies

No new external dependencies. Uses existing:
- `tokio` for async runtime
- `serde` for JSON serialization
- `sha2` for checksum verification
- `std::fs` for atomic file operations

---

## Open Questions (Answered)

| Question | Answer |
|----------|--------|
| State persistence | Yes - survives Supervisor crashes |
| Binary staging | Single binary swap (simpler than multi-version) |
| API | Both CLI and gRPC |
| Testing | Integration tests required |

---

## Success Criteria

1. **Single process model**: `synvoid` with no args runs Supervisor only
2. **Zero legacy references**: No `run_master_mode`, `run_overseer_mode`, `overseer::` imports
3. **Zero-downtime verified**: Rolling restart test passes
4. **Crash recovery verified**: State persistence test passes
5. **All profiles compile**: Core, Mesh, DNS, Full profiles
6. **Integration tests pass**: Full upgrade flow test suite
