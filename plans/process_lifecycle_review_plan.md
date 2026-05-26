# Process Lifecycle Architecture Review Plan

## Executive Summary

The architecture document `architecture/process_lifecycle.md` contains **significant inaccuracies** regarding the process hierarchy, worker spawning, and CPU affinity configuration. The document describes a legacy Overseer->Master->Worker hierarchy that is **not functional** due to a missing `--master` CLI flag, and the actual default behavior differs from what is documented.

---

## Stale Items Identified

| Item | Document Claim | Actual Code | Impact |
|------|---------------|-------------|--------|
| **Overseer hierarchy** | Overseer is "top-level orchestrator" that spawns Master | Overseer code exists but cannot spawn Master because `--master` flag is missing from `main.rs` | **Critical** - Legacy mode is broken |
| **Master key logic** | `src/startup/master.rs`, `src/master/` | `run_master_mode()` is defined but never called from main.rs | **Critical** - Master never runs |
| **Default mode** | "Supervisor Consolidated Mode (default)" with Legacy Mode as fallback | Only `run_supervisor_mode()` is the default; no CLI flag exists to select Legacy Mode | **Medium** - Document implies choice exists |
| **CPU affinity** | "Must be explicitly configured via `cpu_affinity` parameter - not automatic" | CPU affinity is **automatically** set based on worker ID in `spawn_unified_server_worker_with_id` (line 666-668) | **High** - Document is wrong |
| **reuse_port reference** | Line 46: "Initial workers use `reuse_port: false`. See `src/overseer/upgrade.rs:748`" | Line 748 is `reuse_port: matches!(mode, UpgradeMode::ReusePort)` - not about initial workers | **Medium** - Wrong line reference |
| **Worker types** | Single "Worker" type mentioned | Three worker types exist: `Worker` (legacy), `StaticWorker`, `UnifiedServerWorker` | **Low** - Incomplete documentation |

---

## Claims Verified / Issues Found

### 1. Overseer Cannot Spawn Master (CRITICAL BUG)

**Document Claim:** Overseer spawns Master process at line 8-11

**Code Verification:**
- `src/overseer/spawn.rs:83-84` adds `--master` flag when spawning Master:
  ```rust
  ProcessMode::Master => {
      cmd.arg("--master");
  }
  ```
- `src/main.rs:21-192` - The `Args` struct has **NO** `--master` flag defined

**Impact:** When Overseer attempts to spawn Master, the child process will fail immediately with "unrecognized argument --master"

**Code Location:** `src/overseer/spawn.rs:84`, `src/main.rs:21-192`

---

### 2. CPU Affinity is AUTOMATIC, Not Manual

**Document Claim:** Line 47: "Must be explicitly configured via `cpu_affinity` parameter - not automatic"

**Code Verification:**
- `src/process/manager.rs:666-668`:
  ```rust
  // Assign CPU affinity based on worker ID
  let core = id.as_usize() % self.cpu_count;
  cmd.arg("--cpu-affinity").arg(core.to_string());
  ```

**Impact:** CPU affinity is automatically assigned based on worker ID. The document incorrectly states it must be explicit.

**Code Location:** `src/process/manager.rs:666-668`

---

### 3. Supervisor Mode is ONLY Mode (No Legacy Mode Selection)

**Document Claim:** Line 30-32: Supervisor has "Consolidated Mode (default)" and "Legacy Mode"

**Code Verification:**
- `src/main.rs:527-536`:
  ```rust
  } else {
      // Default: Run as Supervisor (manager of Workers)
      // This replaces the legacy Overseer -> Master hierarchy.
      run_supervisor_mode(...)
  }
  ```
- No CLI flag exists to select between Supervisor and Overseer modes
- `run_overseer_mode()` is defined in `src/startup/master.rs:89` but is **never called**

**Impact:** The "Legacy Mode" option does not exist as a runtime selectable option. The Overseer->Master hierarchy is code that exists but cannot be invoked.

**Code Location:** `src/main.rs:527-536`

---

### 4. Supervisor Spawns UnifiedServerWorkers Directly

**Document Claim:** Line 33-34: Supervisor "Spawning and monitoring Worker processes"

**Code Verification:**
- `src/supervisor/process.rs:79-89`:
  ```rust
  // Spawn initial unified workers (data plane)
  tracing::info!("Spawning {} unified server workers", config.unified_server_workers);
  if let Err(e) = self.process_manager.spawn_unified_server_workers(config.unified_server_workers) {
  ```

**Status:** Verified - Supervisor spawns UnifiedServerWorkers directly

**Code Location:** `src/supervisor/process.rs:79-89`

---

### 5. Block Store Exists in Both Supervisor and Master

**Document Claim:** Line 23: Master "Manages persistent IP blocklists"

**Code Verification:**
- Supervisor: `src/supervisor/process.rs:236` - BlockStore created
- Master: `src/startup/master.rs:310` - BlockStore created

**Status:** Verified - BlockStore exists in both

**Code Location:** `src/supervisor/process.rs:236`, `src/startup/master.rs:310`

---

### 6. Worker Drain Implementation

**Document Claim:** Line 79: Workers are "signaled to drain"

**Code Verification:**
- `src/overseer/drain_manager.rs` - Full drain manager implementation
- `src/worker/drain_state.rs` - Worker-side drain state handling
- Drain protocol sends `DrainRequest`, `StopAccepting`, polls `DrainStatusResponse`

**Status:** Verified - Comprehensive drain system exists

**Code Location:** `src/overseer/drain_manager.rs`, `src/worker/drain_state.rs`

---

### 7. reuse_port Behavior

**Document Claim:** Line 46: "Initial workers use `reuse_port: false`"

**Code Verification:**
- `src/overseer/spawn.rs:43`: Default SpawnConfig has `reuse_port: false`
- `src/process/manager.rs:583-585`: Only set when `reuse_port: true` passed
- `src/overseer/upgrade.rs:748`: `reuse_port: matches!(mode, UpgradeMode::ReusePort)`

**Status:** Partially correct - Initial workers do use `reuse_port: false` by default, but the reference to line 748 is wrong

**Code Location:** `src/overseer/spawn.rs:43`

---

## Improvement Plan

### High Priority

| ID | Issue | Action | Files |
|----|-------|--------|-------|
| **IMP-1** | Missing `--master` CLI flag breaks Overseer->Master hierarchy | Add `--master` flag to Args struct in main.rs and handle it by calling `run_master_mode()` | `src/main.rs` |
| **IMP-2** | Legacy Overseer mode cannot be selected | Either remove legacy mode documentation OR add CLI flag to enable it | `src/main.rs`, `architecture/process_lifecycle.md` |

### Medium Priority

| ID | Issue | Action | Files |
|----|-------|--------|-------|
| **IMP-3** | CPU affinity documentation is wrong | Update line 47 to state CPU affinity is automatic | `architecture/process_lifecycle.md` |
| **IMP-4** | Wrong line reference for reuse_port | Update line 46 to reference correct location | `architecture/process_lifecycle.md` |
| **IMP-5** | Worker types undocumented | Add section describing UnifiedServerWorker, StaticWorker, and legacy Worker | `architecture/process_lifecycle.md` |

### Low Priority

| ID | Issue | Action | Files |
|----|-------|--------|-------|
| **IMP-6** | Document mentions Mesh Agent but no details | Add Mesh Agent section or reference | `architecture/process_lifecycle.md` |

---

## Bug Report

### Critical

| Bug ID | Description | Location | Impact |
|--------|-------------|----------|--------|
| **BUG-PL-1** | Overseer cannot spawn Master because `--master` flag missing from CLI | `src/main.rs:21-192`, `src/overseer/spawn.rs:84` | Legacy Overseer->Master hierarchy is completely non-functional |

### Minor

| Bug ID | Description | Location | Impact |
|--------|-------------|----------|--------|
| **MINOR-PL-1** | Document incorrectly states CPU affinity must be explicit | `architecture/process_lifecycle.md:47` | Misleading documentation |
| **MINOR-PL-2** | Document references wrong line for reuse_port behavior | `architecture/process_lifecycle.md:46` | Incorrect reference |

---

## Recommendations

1. **Immediate**: Add `--master` flag to main.rs to fix the broken legacy hierarchy, OR update documentation to accurately reflect that only Supervisor mode is functional

2. **Short-term**: Update `architecture/process_lifecycle.md` to:
   - Correct CPU affinity description
   - Fix reuse_port line reference
   - Document UnifiedServerWorker as the primary worker type
   - Clarify that Legacy Mode is code-only and not selectable

3. **Long-term**: Consider removing legacy Overseer->Master code paths if they are not intended to be functional

---

## Verification Commands

```bash
# Verify compilation
cargo check --no-default-features --features mesh

# Verify Supervisor mode is default
grep -n "run_supervisor_mode\|run_overseer_mode" src/main.rs

# Verify missing --master flag
grep -n '"master"' src/main.rs

# Verify CPU affinity is automatic
grep -n "cpu_affinity" src/process/manager.rs
```
