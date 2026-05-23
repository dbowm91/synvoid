# Platform Architecture Review - Improvement Plan

**Review Date:** 2026-05-23
**Documents Reviewed:**
- `architecture/platform_deep_dive.md`
- `architecture/process_lifecycle.md`
- `architecture/worker_architecture.md`
- `AGENTS.md` (root)
- `src/platform/AGENTS.override.md`

---

## Verified Correct Items

### Process Hierarchy (Verified ✅)

| Claim | Source | Status |
|-------|--------|--------|
| Supervisor consolidates Overseer + Master | AGENTS.md:117, process_lifecycle.md:28-39 | ✅ Verified |
| Overseer exists at `src/overseer/` | overseer/mod.rs | ✅ Verified |
| Process types in `src/process/worker.rs` | BaseWorkerProcess, WorkerProcess, StaticWorkerProcess, UnifiedServerWorkerProcess | ✅ Verified |
| `src/startup/master.rs` contains `run_master_mode()` | startup/master.rs:23 | ✅ Verified |
| `src/supervisor/process.rs` contains `run_supervisor_mode()` | supervisor/process.rs:212 | ✅ Verified |

### File Paths (Verified ✅)

| Claim | Source | Status |
|-------|--------|--------|
| Platform files at `src/platform/*.rs` | unix.rs, windows_impl.rs, sandbox.rs, ipc.rs | ✅ Verified |
| Process files at `src/process/*.rs` | ipc.rs, manager.rs, worker.rs, socket_fd.rs | ✅ Verified |
| Supervisor files at `src/supervisor/*.rs` | process.rs, api.rs, state.rs, commands.rs | ✅ Verified |
| `src/overseer/process.rs` exists | OverseerProcess struct | ✅ Verified |

### Key Implementation Details (Verified ✅)

| Claim | Source | Status |
|-------|--------|--------|
| SO_REUSEPORT for kernel load balancing | src/process/socket_fd.rs, src/tcp/listener.rs:115-124 | ✅ Verified |
| CPU affinity pinning via sched_setaffinity (Linux only) | src/worker/unified_server.rs:183-213 | ✅ Verified |
| gRPC server binds to localhost only | src/supervisor/api.rs:129-144, AGENTS.md:85 | ✅ Verified |
| HMAC-SHA3-256 with 60s replay window | src/process/ipc_signed.rs | ✅ Verified |
| Tokio runtime per worker | src/worker/unified_server.rs (async fn run_unified_server_worker) | ✅ Verified |
| Message enum with 17+ categories | src/process/ipc.rs:252-598 (documented at lines 246-298) | ✅ Verified |

---

## Discrepancies Found

### 1. Process Hierarchy Diagram Inconsistency

**Issue:** `platform_deep_dive.md:246-269` shows three-tier hierarchy:
```
Supervisor → Master → Workers
```

**But AGENTS.md:175-178 states Supervisor replaces Overseer + Master in consolidated mode:
```
Consolidated (recommended): Supervisor → Workers directly
Traditional (legacy): Overseer → Master → Workers
```

**Actual Code:** `src/supervisor/process.rs:79-89` spawns workers directly:
```rust
if let Err(e) = self.process_manager.spawn_unified_server_workers(config.unified_server_workers)
```

**Priority:** High
**File:Line:** platform_deep_dive.md:246-269

---

### 2. Master "MUST NOT run UnifiedServer" Not Documented

**Issue:** `platform_deep_dive.md` architecture diagram shows Master with "Admin Server" but does NOT document the critical constraint that Master MUST NOT run UnifiedServer inline.

**Actual Code:** `src/startup/master.rs:279-302` contains explicit CRITICAL comment:
```rust
// CRITICAL ARCHITECTURAL REQUIREMENT: Master process must NEVER run UnifiedServer inline.
//
// The Master process must ONLY:
// - Run the admin panel API
// - Orchestrate threat intelligence
// - Manage worker processes
// - Handle IPC communications
//
// The Master MUST NOT:
// - Run UnifiedServer inline for request handling
// - Accept HTTP/TCP/UDP/QUIC/WebSocket requests directly
```

**Priority:** High
**File:Line:** platform_deep_dive.md:223 (missing critical note), src/startup/master.rs:279-302

---

### 3. CPU Affinity Not Automatic

**Issue:** `process_lifecycle.md:47` claims "On Linux, workers are automatically pinned to specific CPU cores".

**Actual Code:** `src/startup/worker.rs:32` shows `cpu_affinity: Option<usize>` is an **optional parameter**, not automatic. It must be explicitly provided:
```rust
pub fn build_unified_server_worker_args(...) -> UnifiedServerWorkerArgs {
    UnifiedServerWorkerArgs {
        ...
        cpu_affinity,  // Must be passed explicitly
        ...
    }
}
```

**Priority:** Medium
**File:Line:** process_lifecycle.md:47

---

### 4. gRPC Default Port 50051 Not Accurate

**Issue:** `platform_deep_dive.md:167` claims "gRPC control API on `localhost` (port 50051 default)".

**Actual Code:** `src/supervisor/process.rs:115-123` uses configurable `control_api_addr`:
```rust
let grpc_addr = self
    .state
    .config
    .read()
    .await
    .main
    .supervisor
    .control_api_addr
    .parse();
```

The default port is in `MainConfig`, not hardcoded to 50051.

**Priority:** Medium
**File:Line:** platform_deep_dive.md:167

---

### 5. SO_REUSEPORT for Workers Not Automatic

**Issue:** `process_lifecycle.md:68` and `platform_deep_dive.md:242` imply workers automatically use SO_REUSEPORT.

**Actual Code:** `src/startup/worker.rs:42` shows:
```rust
reuse_port: false,  // Initial workers do NOT use SO_REUSEPORT
```

SO_REUSEPORT is used during **upgrades** (`src/overseer/upgrade.rs:748`) but not for initial worker spawn.

**Priority:** Medium
**File:Line:** process_lifecycle.md:68, platform_deep_dive.md:242

---

### 6. Message Categories Count Mismatch

**Issue:** `platform_deep_dive.md:91-107` lists "15 categories" but the actual IPC Message enum has more.

**Actual Code:** `src/process/ipc.rs:252-298` documents groupings but actual enum has ~17 groups:
- Worker Lifecycle ✅
- Master Commands (includes additional variants like MasterSupervisorConfigReload)
- Static Worker (includes additional variants like StaticWorkerBackgroundTasksDone)
- Threat Intel (includes ThreatIndicatorFromMesh)
- Blocklist & Rules
- Static Content
- App Server (NOT in doc)
- Unified Server ✅
- Worker Drain
- Upgrade
- Overseer
- Master Drain
- Drain Protocol
- Socket Handoff
- Worker Restart (NOT in doc)
- Plugin ✅
- Mesh Control (NOT in doc - lines 113-144)

**Priority:** Low
**File:Line:** platform_deep_dive.md:91-107

---

### 7. Startup Flow Missing Key Steps

**Issue:** `platform_deep_dive.md:203-220` shows startup flow missing critical items.

**Actual Code:** `src/startup/master.rs:205-797` shows additional steps:
- Post-quantum TLS initialization (lines 210-242)
- MIME type loading (lines 258-268)
- BlockStore initialization (lines 308-314)
- RuleFeedManager initialization (lines 319-329)
- Shared state initialization (IPC listener lines 607-650)
- Worker spawning loop (lines 652-667)
- Health monitor spawn (lines 672-675)
- Admin server spawn (lines 693-726)
- **NOT in doc:** Blocklist persistence loop (lines 678-687)

**Priority:** Low
**File:Line:** platform_deep_dive.md:203-220

---

### 8. Sandbox Backend Platform Availability

**Issue:** `platform_deep_dive.md:62` says "macOS Seatbelt... (requires `macos-sandbox` feature)".

**Actual Code:** `src/platform/sandbox.rs` and platform AGENTS.override.md:116 show:
```rust
- macOS Seatbelt: Requires `macos-sandbox` feature flag to actually enforce
```

But there is NO actual `macos-sandbox` feature gate in the codebase - the AGENTS doc may be documenting planned behavior.

**Priority:** Medium
**File:Line:** platform_deep_dive.md:62, src/platform/AGENTS.override.md:116

---

### 9. macOS CPU Affinity Not Automatic

**Issue:** `process_lifecycle.md:47` implies CPU pinning works on all platforms automatically.

**Actual Code:** `src/worker/unified_server.rs:205-208`:
```rust
#[cfg(all(unix, not(target_os = "linux")))]
{
    tracing::info!("CPU affinity pinning requested for core {}, but not supported on this Unix platform", core);
}
```

CPU affinity is **Linux-only** despite being labeled as automatic in docs.

**Priority:** Medium
**File:Line:** process_lifecycle.md:47

---

### 10. IPC Rate Limiting Table Structure

**Issue:** `platform_deep_dive.md:82-83` implies per-worker isolation:
```
IPC Rate Limiting: Token bucket + per-worker isolation
```

**Actual Code:** `src/process/ipc_rate_limit.rs` has global + per-worker configuration but the **per-worker isolation is per-connection**, not per-worker-process as the doc implies.

**Priority:** Low
**File:Line:** platform_deep_dive.md:82-83

---

## Bugs Identified

### BUG-1: Documentation References Wrong Process for Admin Server

**File:Line:** platform_deep_dive.md:249-251
```
│  ┌─────────────────┐  ┌──────────────────────┐  │
│  │ ProcessManager   │  │ Admin Server         │  │
│  │ (shared w/ sup)  │  │ (port from config)   │  │
│  └─────────────────┘  └──────────────────────┘  │
```

**Problem:** This shows Admin Server running in Master, but in **consolidated Supervisor mode**, the Admin Server runs in Supervisor via `src/startup/master.rs:693-726`.

In traditional mode, Master runs Admin Server. In consolidated mode, Supervisor runs gRPC Control API (different from Admin API).

**Fix:** Split the diagram to show:
- **Consolidated mode:** Supervisor (ProcessManager + gRPC Control API) → Workers
- **Traditional mode:** Master (ProcessManager + Admin API) → Workers

---

## Improvement Suggestions

### Suggestion 1: Document the Two Deployment Modes

Add explicit documentation of the two deployment models in `platform_deep_dive.md`:

```markdown
## Deployment Models

### Consolidated Mode (Recommended)
Supervisor → Workers directly
- Simpler deployment
- Supervisor runs both ProcessManager and gRPC Control API
- Single process to monitor

### Traditional Mode (Legacy)
Overseer → Master → Workers
- Overseer handles upgrades and recovery
- Master runs Admin API
- Master runs ProcessManager
```

**Priority:** High

---

### Suggestion 2: Add CPU Affinity Configuration Note

Update `process_lifecycle.md:47` to clarify:
```markdown
- **CPU Pinning:** On Linux, workers can be pinned to specific CPU cores via `sched_setaffinity`, eliminating jitter and cache thrashing. **Must be explicitly configured via `cpu_affinity` parameter** - not automatic.
```

**Priority:** Medium

---

### Suggestion 3: Clarify SO_REUSEPORT Usage

Update `process_lifecycle.md:68` and `platform_deep_dive.md:242`:
```markdown
- **SO_REUSEPORT:** Used during worker upgrades (via upgrade mode) and for Socket Handoff. Initial worker spawn uses `reuse_port: false` by default.
```

**Priority:** Medium

---

### Suggestion 4: Document "CRITICAL ARCHITECTURAL REQUIREMENT"

Add a prominent note in `platform_deep_dive.md` section 4 (or create new section):
```markdown
## Critical Security Constraint: Master Must NOT Handle Requests

The Master process (in traditional mode) or Supervisor process (in consolidated mode) **MUST NOT**:
- Run UnifiedServer inline for request handling
- Accept external HTTP/TCP/UDP/QUIC/WebSocket traffic
- Handle any untrusted client requests

This separation is CRITICAL for security isolation. Workers handle untrusted input; Master/Supervisor handles sensitive operations (config, workers, intelligence).

**See:** `src/startup/master.rs:279-302` for the authoritative comment.
```

**Priority:** High

---

### Suggestion 5: Fix Platform Availability for Seatbelt

If `macos-sandbox` feature is planned but not implemented, either:
1. Add the feature gate to `src/platform/sandbox.rs`
2. Update `src/platform/AGENTS.override.md:116` to reflect actual behavior

**Priority:** Medium

---

### Suggestion 6: Update Message Category Count

Update `platform_deep_dive.md:91` to say "**17+ categories**" and add the missing categories:
- App Server
- Worker Restart
- Mesh Control

**Priority:** Low

---

### Suggestion 7: Add SO_REUSEPORT Upgrade Behavior

Document in `worker_architecture.md` or `process_lifecycle.md`:
```markdown
## Zero-Downtime Upgrades with SO_REUSEPORT

During worker upgrades, the upgrade mode sets `reuse_port: true` on new workers, allowing:
1. New workers to share the port with old workers
2. Kernel to distribute connections across both old and new workers
3. Old workers to drain while new workers accept new connections
```

**Priority:** Medium

---

## Summary

| Priority | Count | Items |
|----------|-------|-------|
| **High** | 3 | Process hierarchy diagram, Master constraint doc, Critical security constraint |
| **Medium** | 6 | CPU affinity auto claim, gRPC port, SO_REUSEPORT, Seatbelt feature, macOS CPU affinity, Deployment modes |
| **Low** | 4 | Message categories, Startup flow, IPC rate limiting, SO_REUSEPORT upgrade behavior |

**Key Files Needing Updates:**
- `architecture/platform_deep_dive.md` - Multiple sections
- `architecture/process_lifecycle.md` - CPU affinity, SO_REUSEPORT claims
- `architecture/worker_architecture.md` - Missing SO_REUSEPORT upgrade documentation
- `src/platform/AGENTS.override.md` - Seatbelt feature gate