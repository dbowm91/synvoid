# Process Lifecycle Architecture Review

> **Review Date**: 2026-05-27
> **Reviewer**: Analysis of `architecture/process_lifecycle.md` vs actual implementation

---

## Verified Correct Items

| Item | Doc Location | Actual Location | Status |
|------|-------------|----------------|--------|
| Overseer `run_overseer_mode()` exists | `src/startup/master.rs:89` | `src/startup/master.rs:89` | ✅ |
| Supervisor uses `DrainManager` | `src/overseer/drain_manager.rs` | `src/supervisor/process.rs:48` | ✅ |
| `DrainManager` struct | `src/overseer/drain_manager.rs:20` | `src/overseer/drain_manager.rs:20` | ✅ |
| `UpgradeMode` enum | `src/overseer/mode.rs` | `src/overseer/mode.rs:4-8` | ✅ |
| `detect_upgrade_mode()` | `src/overseer/mode.rs` | `src/overseer/mode.rs:29-37` | ✅ |
| Default entry point uses Supervisor | `src/main.rs:541-546` | `src/main.rs:539-547` | ✅ |
| `--master` flag calls `run_master_mode()` | `src/main.rs:531` | `src/main.rs:531` | ✅ |
| `spawn_unified_server_worker_with_id()` | `src/process/manager.rs:653` | `src/process/manager.rs:653-693` | ✅ |
| `spawn_upgrade_worker()` | `src/process/manager.rs:558-612` | `src/process/manager.rs:558-612` | ✅ |
| `spawn_static_worker()` | `src/process/manager.rs:614-648` | `src/process/manager.rs:614-648` | ✅ |
| gRPC control plane proto | `proto/control.proto` | `proto/control.proto` | ✅ |
| `BaseWorkerProcess` struct | `src/process/worker.rs:48` | `src/process/worker.rs:48` | ✅ |
| CPU affinity via `sched_setaffinity` | `src/worker/unified_server.rs:186` | `src/worker/unified_server.rs:183-196` | ✅ |
| Platform CPU warning (macOS/BSD) | Platform module | `src/platform/mod.rs:114` | ✅ |

---

## Discrepancies Found

### 1. Supervisor Drain Coordination — OUTDATED DOCUMENTATION

**Doc says** (line 36):
> "the Supervisor does not currently implement drain coordination. Workers are restarted directly without the staged draining that Overseer provides."

**Actual** (`src/supervisor/process.rs:186-260`):
> `drain_aware_shutdown()` is fully implemented. Supervisor HAS drain coordination via ported `DrainManager`.

**Severity**: P3 — Documentation is stale. PL-5 was completed (plan.md:111).

---

### 2. Worker Types — Minor Mismatch

**Doc says** (line 47-51):
> Three worker types: UnifiedServerWorker, StaticWorker, Legacy Worker (BaseWorkerProcess)

**Actual**:
- `BaseWorkerProcess` is the base struct for all worker process types (not a separate worker) — see `src/process/worker.rs:48-91`
- Legacy raw TCP/UDP "BaseWorkerProcess" is the same struct used by unified and static workers

**Severity**: P3 — The documentation conflates `BaseWorkerProcess` (base struct) with "Legacy Worker" (process mode). Clarification needed.

---

### 3. Initial Workers `reuse_port: false` — Verified

**Doc says** (line 54):
> "Initial workers use `reuse_port: false` (default)"

**Actual** (`src/startup/worker.rs:42`):
```rust
reuse_port: false,
```

This is correct for initial workers. `SO_REUSEPORT` is enabled for upgrade workers via `spawn_upgrade_worker()`.

**Severity**: None — Document is accurate.

---

## Bugs Identified

### BUG-PL-4: Supervisor Lacks PortSwap Upgrade Mode (P2)

**Severity**: P2 — Medium

**Location**: `src/supervisor/process.rs` lacks `UpgradeMode` / `PortSwap` support

**Issue**: The documentation correctly states that Supervisor uses `SO_REUSEPORT` directly but lacks `PortSwap` fallback. However, this is marked as "See PL-4" but PL-4 is not documented in plan.md — only referenced.

**Impact**: On systems where `SO_REUSEPORT` fails, Supervisor cannot gracefully rotate workers via port swap.

**Recommendation**: Either document PL-4 in plan.md or implement PortSwap support in Supervisor.

---

### BUG-DOC-1: Spurious PL-5 Reference (P3)

**Severity**: P3 — Low

**Location**: `architecture/process_lifecycle.md:36`

**Issue**: The statement "See PL-5 in `plans/plan.md` for planned improvements" is incorrect — PL-5 is already completed.

**Fix**: Update doc to reflect PL-5 is complete, or remove reference.

---

## Suggested Improvements

### IMPROVE-1: Document PL-4 or Remove Reference (P2)

The reference to PL-4 in the architecture doc creates confusion. Either:
1. Add PL-4 to plan.md with implementation details, or
2. Update architecture doc to remove the PL-4 reference and phrase it as a known limitation

### IMPROVE-2: Clarify BaseWorkerProcess vs Legacy Worker (P3)

The documentation conflates the `BaseWorkerProcess` struct (a base type for all worker processes) with "Legacy Worker (BaseWorkerProcess)" (a mode for raw TCP/UDP proxy). Consider:
- Rename to avoid confusion (`BaseWorkerProcess` → `WorkerProcessBase` or document the trait better)
- Clarify that "BaseWorkerProcess" is a base struct, not a process implementation

### IMPROVE-3: Add Supervisor Upgrade Flow Diagram (P3)

The existing doc describes Overseer upgrade flow implicitly, but doesn't describe how Supervisor handles zero-downtime upgrades. Consider adding a section on Supervisor upgrade flow.

### IMPROVE-4: Cross-Reference Master Mode Spawns (P3)

The Master mode documentation (`src/startup/master.rs:23`) shows it spawns workers via `process_manager.spawn_worker()` (line 653) for legacy workers, and `spawn_unified_server_workers()` (line 733). The architecture doc should note this distinction.

---

## Summary

| Category | Count |
|----------|-------|
| Verified Correct | 14 |
| Discrepancies | 1 (outdated drain coordination info) |
| Bugs | 2 (1 P2, 1 P3) |
| Improvements | 4 (1 P2, 3 P3) |

**Overall Assessment**: The architecture document is mostly accurate. The main issue is stale documentation about Supervisor drain coordination (PL-5 is complete). The primary bug is the undocumented PL-4 limitation regarding PortSwap upgrade mode.

---

*Last Updated: 2026-05-27*
