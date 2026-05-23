# Process Lifecycle Review Plan

## Document Reviewed
`architecture/process_lifecycle.md` - Process Lifecycle & Execution Model

---

## Claims Verification Status

### 1. Three-Tier Hierarchy (Overseer → Master → Workers)

| Claim | Status | Code Location |
|-------|--------|----------------|
| Overseer spawns Master and Mesh Agent | ✅ VERIFIED | `src/overseer/process.rs:365-366` |
| Overseer handles health monitoring | ✅ VERIFIED | `src/overseer/process.rs:377-414` |
| Overseer handles recovery | ✅ VERIFIED | `src/overseer/process.rs:355-363` |
| Master spawns Workers via ProcessManager | ✅ VERIFIED | `src/startup/master.rs:653,733` |
| Master hosts Admin API | ✅ VERIFIED | `src/startup/master.rs` (uses MasterState) |
| Master manages Block Store | ✅ VERIFIED | `src/startup/master.rs:310-317` |

### 2. Supervisor (Consolidated Mode)

| Claim | Status | Code Location |
|-------|--------|----------------|
| Supervisor merges Overseer + Master | ✅ VERIFIED | `src/supervisor/mod.rs:1-6` |
| Runs workers directly | ✅ VERIFIED | `src/supervisor/process.rs:79-89` |
| Has gRPC API | ✅ VERIFIED | `src/supervisor/api.rs:129-144` |
| Uses ProcessManager | ✅ VERIFIED | `src/supervisor/process.rs:21,33` |

**Note:** Supervisor has its OWN BlockStore (`src/supervisor/state.rs:29`) separate from Master. This is correct for consolidated mode but the document should clarify this.

### 3. Worker Data Plane

| Claim | Status | Code Location |
|-------|--------|----------------|
| Workers use SO_REUSEPORT during upgrades | ✅ VERIFIED | `src/overseer/upgrade.rs:748` |
| Initial workers use reuse_port: false | ✅ VERIFIED | `src/startup/worker.rs:42` |
| CPU affinity requires explicit config | ✅ VERIFIED | `src/worker/unified_server.rs:183-184` |
| CPU affinity only works on Linux | ✅ VERIFIED | `src/worker/unified_server.rs:184-212` |
| CPU affinity uses sched_setaffinity | ✅ VERIFIED | `src/worker/unified_server.rs:186,194` |

### 4. Communication Flow

| Claim | Status | Code Location |
|-------|--------|----------------|
| CLI uses CommandClient | ✅ VERIFIED | `src/process/command.rs:14-389` |
| CommandClient supports gRPC | ✅ VERIFIED | `src/process/command.rs:68-112` |
| CommandClient supports Unix Socket | ✅ VERIFIED | `src/process/command.rs:114-148` |
| CommandClient supports Signals | ✅ VERIFIED | `src/process/command.rs:193-222` |
| Internal IPC over Unix domain sockets | ✅ VERIFIED | `src/process/ipc.rs` |
| Mesh transport for Supervisor-to-Supervisor | ✅ VERIFIED | `src/supervisor/mesh.rs` |

### 5. Shared-Nothing Architecture

| Claim | Status | Code Location |
|-------|--------|----------------|
| No shared memory for request handling | ✅ VERIFIED | Each worker has own listener |
| Independent listeners with SO_REUSEPORT | ✅ VERIFIED | `src/tcp/listener.rs:115-124` |
| Each worker runs dedicated Tokio runtime | ✅ VERIFIED | `src/startup/worker.rs` |

**Document Gap:** The document does NOT mention `SharedConnectionTable` (shared memory for distributed load balancing) or `SharedRateLimitTable`. This is a significant omission since workers DO share some state via SHM.

### 6. Zero-Downtime Upgrades

| Claim | Status | Code Location |
|-------|--------|----------------|
| SO_REUSEPORT allows old+new workers to coexist | ✅ VERIFIED | `src/overseer/upgrade.rs:748` |
| Workers rotated during upgrade | ✅ VERIFIED | `src/overseer/upgrade.rs` |
| New Supervisor takes over gRPC | ⚠️ PARTIAL | gRPC address is same, not takeover mechanism described |

### 7. Process State & Health Monitoring

| Claim | Status | Code Location |
|-------|--------|----------------|
| Supervisor monitors worker exits | ✅ VERIFIED | `src/process/manager.rs:1309-1314` |
| Supervisor monitors heartbeats | ✅ VERIFIED | `src/process/manager.rs:1283-1307` |
| Self-healing: spawns replacement on failure | ✅ VERIFIED | `src/process/manager.rs:1386-1425` |
| Replacement pinned to correct core | ⚠️ PARTIAL | CPU affinity auto-assigned, not from config (`src/process/manager.rs:667`) |

**Note:** The claim "pins it to the correct core" is misleading. ProcessManager auto-assigns cores based on worker ID % cpu_count, not from per-worker config.

---

## Bug Reports

### Critical Bugs

| Bug | Location | Description |
|-----|----------|-------------|
| gRPC uptime_secs hardcoded to 0 | `src/supervisor/api.rs:55` | `uptime_secs: 0` is hardcoded in StatusResponse. Should track actual start time. |

### Minor Bugs

| Bug | Location | Description |
|-----|----------|-------------|
| Missing SharedConnectionTable documentation | `architecture/process_lifecycle.md` | Workers actually share state via SHM for load balancing; document claims "shared-nothing" which is misleading for cross-worker coordination |
| BlockStore dual ownership unclear | `src/supervisor/state.rs:29` vs `src/startup/master.rs:310` | Supervisor and Master each have their own BlockStore. Document doesn't clarify this or explain data synchronization |

---

## Improvement Plan

### High Priority

| Item | Issue | Recommendation |
|------|-------|----------------|
| Document SharedConnectionTable | Workers use SHM-based SharedConnectionTable for load balancing | Add section explaining cross-worker shared state for load balancing |
| Fix gRPC uptime_secs | `src/supervisor/api.rs:55` | Store start time in SupervisorState and return actual uptime |
| Clarify BlockStore ownership | Both Supervisor and Master have BlockStore | Document which BlockStore is authoritative and how they sync |

### Medium Priority

| Item | Issue | Recommendation |
|------|-------|----------------|
| CPU affinity pinning description | Claims "correct core" from config, actually auto-assigned | Update document to reflect auto-assignment: `core = worker_id % cpu_count` |
| Clarify health check intervals | 5-second interval hardcoded in supervisor main loop | Document actual health check behavior |
| Add Mesh Agent modes documentation | Mesh Agent runs standalone OR within Supervisor | Clarify the two deployment modes for Mesh Agent |

### Low Priority

| Item | Issue | Recommendation |
|------|-------|----------------|
| CommandClient method fallback | `src/process/command.rs:20-49` | Document the fallback chain: gRPC → Unix Socket → Signal |
| Upgrade coordination details | `src/overseer/upgrade.rs` | Add sequence diagram for upgrade handoff |
| drain_state documentation | `src/worker/drain_state.rs` | Worker drain states not documented in arch doc |

---

## Summary

The `architecture/process_lifecycle.md` document is largely accurate in describing the process hierarchy and lifecycle management. Key strengths:

1. ✅ Three-tier hierarchy is correctly described
2. ✅ Supervisor consolidated mode is accurate
3. ✅ SO_REUSEPORT upgrade mechanism is documented correctly
4. ✅ Worker isolation and CPU affinity details are accurate

Key gaps/improvements needed:

1. **SharedConnectionTable omission** - The document claims "shared-nothing" but workers actually share connection state via SHM
2. **gRPC uptime_secs bug** - Hardcoded to 0, should track actual start time
3. **BlockStore dual ownership** - Both Supervisor and Master have BlockStore; document should clarify
4. **CPU affinity description** - Implies per-worker config, but actually auto-assigned

The implementation generally follows the documented architecture, with the main issues being documentation gaps rather than implementation bugs.
