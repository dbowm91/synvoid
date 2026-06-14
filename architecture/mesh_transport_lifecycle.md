# Mesh Transport Lifecycle Inventory — Iteration 71

## Purpose

This document is the **canonical inventory** of every task spawned by `MeshTransport`, `MeshDiscovery`, `DhtRoutingManager`, and `ThreatIntelligenceManager` during the mesh runtime lifecycle. It classifies each task, documents its current cancellation/join behavior, and defines the target lifecycle state machine, startup ordering, and shutdown ordering.

## Task Classification Definitions

| Class | Definition |
|-------|-----------|
| **CriticalService** | Long-lived loop that must remain running for the mesh to function. Loss causes degraded or broken connectivity. Requires crash-loop restart and coordinated shutdown. |
| **RestartableBackground** | Periodic or long-lived task that supports the mesh but is not individually fatal on loss. Can be restarted independently. May be skipped during shutdown if already finished. |
| **BoundedChild** | Short-lived task spawned in response to a specific event (e.g., peer connection, sync request). Completes naturally. Parent drains or aborts these during shutdown. |
| **OneShotStartup** | Task that runs once during initialization and then completes. Dropped after completion. Not restarted. |

## Task Inventory

### MeshTransport Tasks

Spowned by `MeshTransport::start()` in `transport.rs:2006-2240`.

| # | Task Name | File:Line | Class | Owner | Current Cancellation | Current Join | Startup Dependency | Failure Policy | Drains Children | Mutates State |
|---|-----------|-----------|-------|-------|---------------------|-------------|-------------------|---------------|----------------|--------------|
| 1 | `global_self_attestation` | transport.rs:2023 | OneShotStartup | MeshTransport | None (fire-and-forget) | None (dropped) | None | Ignore | No | Yes (DHT writes) |
| 2 | `pow_nonce_refresh` | transport.rs:2049 | RestartableBackground | MeshTransport | None (no shutdown signal) | None (dropped) | None | Ignore | No | Yes (config cache) |
| 3 | `mlkem_key_rotation` | transport.rs:2079 | RestartableBackground | MeshTransport | None (no shutdown signal) | None (dropped) | None | Ignore | No | Yes (session state) |
| 4 | `mesh_maintenance_loop` | transport.rs:2124 | CriticalService | MeshTransport | `broadcast::Receiver` | None (dropped) | None | Crash loop | No | Yes (peer cleanup) |
| 5 | `datagram_listener_loop` | transport.rs:2130 | CriticalService | MeshTransport | `broadcast::Receiver` | None (dropped) | None | Crash loop | No | No (read-only) |
| 6 | `connection_maintenance` | transport.rs:2154 | RestartableBackground | MeshTransport | None (no shutdown signal) | None (dropped) | `min_peer_connections > 0` | Ignore | No | Yes (connections) |
| 7 | `peer_health_check` | transport.rs:2165 | RestartableBackground | MeshTransport | None (no shutdown signal) | None (dropped) | `min_peer_connections > 0` | Ignore | No | No (read-only) |
| 8 | `proactive_cache_warming` | transport.rs:2183 | RestartableBackground | MeshTransport | None (no shutdown signal) | None (dropped) | `min_peer_connections > 0` | Ignore | No | No (read-only) |
| 9 | `dht_cache_resync` | transport.rs:2194 | RestartableBackground | MeshTransport | None (no shutdown signal) | None (dropped) | `min_peer_connections > 0` | Ignore | No | Yes (DHT cache) |
| 10 | `load_reporter` | transport.rs:2205 | RestartableBackground | MeshTransport | None (no shutdown signal) | None (dropped) | `min_peer_connections > 0` | Ignore | No | No (read-only) |
| 11 | `global_node_heartbeat` | transport.rs:2217 | RestartableBackground | MeshTransport | None (no shutdown signal) | None (dropped) | `min_peer_connections > 0` | Ignore | No | Yes (DHT heartbeat) |
| 12 | `mesh_accept_loop` | transport.rs:2233 | CriticalService | MeshTransport | `broadcast::Receiver` | None (dropped) | QUIC runtime | Crash loop | Yes (per-peer) | No (accepts only) |
| 13 | `incoming_peer_connection` | transport.rs:2252 | BoundedChild | `mesh_accept_loop` | None | None (dropped) | `mesh_accept_loop` | Ignore | No | Yes (peer map) |

### MeshDiscovery Tasks

Spawned by `MeshDiscovery` in `discovery.rs`.

| # | Task Name | File:Line | Class | Owner | Current Cancellation | Current Join | Startup Dependency | Failure Policy | Drains Children | Mutates State |
|---|-----------|-----------|-------|-------|---------------------|-------------|-------------------|---------------|----------------|--------------|
| 14 | `discovery_maintenance` | discovery.rs:64 | RestartableBackground | MeshDiscovery | `mpsc::Receiver` | None (dropped) | None | Ignore | No | Yes (connections) |

### DhtRoutingManager Tasks

Spawned by `DhtRoutingManager` in `dht/routing/manager.rs`.

| # | Task Name | File:Line | Class | Owner | Current Cancellation | Current Join | Startup Dependency | Failure Policy | Drains Children | Mutates State |
|---|-----------|-----------|-------|-------|---------------------|-------------|-------------------|---------------|----------------|--------------|
| 15 | `dht_bucket_stats` | routing/manager.rs:176 | RestartableBackground | DhtRoutingManager | `watch::Sender` | JoinHandle (tracked) | DhtRoutingManager | Graceful | No | No |
| 16 | `dht_bucket_refresh` | routing/manager.rs:176 | RestartableBackground | DhtRoutingManager | `watch::Sender` | JoinHandle (tracked) | DhtRoutingManager | Graceful | No | Yes (DHT) |
| 17 | `dht_peer_ping` | routing/manager.rs:176 | RestartableBackground | DhtRoutingManager | `watch::Sender` | JoinHandle (tracked) | DhtRoutingManager | Graceful | No | No |

### ThreatIntelligenceManager Background Tasks

Spawned from `threat_intel.rs`.

| # | Task Name | File:Line | Class | Owner | Current Cancellation | Current Join | Startup Dependency | Failure Policy | Drains Children | Mutates State |
|---|-----------|-----------|-------|-------|---------------------|-------------|-------------------|---------------|----------------|--------------|
| 18 | `threat_sync_operation` | threat_intel.rs:2682 | BoundedChild | ThreatIntelligenceManager | None | None (dropped) | ThreatIntelligenceManager | Ignore | No | Yes (indicators) |
| 19 | `threat_sync_operation` | threat_intel.rs:2767 | BoundedChild | ThreatIntelligenceManager | None | None (dropped) | ThreatIntelligenceManager | Ignore | No | Yes (indicators) |
| 20 | `threat_sync_operation` | threat_intel.rs:2801 | BoundedChild | ThreatIntelligenceManager | None | None (dropped) | ThreatIntelligenceManager | Ignore | No | Yes (indicators) |

## Lifecycle State Machine

```
┌──────────┐
│ Stopped  │
└────┬─────┘
     │ start()
     ▼
┌──────────┐
│ Starting │
└──┬───┬───┘
   │   │
   │   │ startup failed
   │   ▼
   │ ┌──────────────────────────┐
   │ │ rollback_failed?         │
   │ │  clean  → Stopped        │
   │ │  errors → Failed ──────┐ │
   │ └────────────────────────┘ │
   │                             │
   │ startup complete            │ (Failed requires manual recovery)
   ▼                             │
┌──────────┐                     │
│ Running  │                     │
└──┬───────┘                     │
   │                             │
   │ stop() or fatal error       │
   ▼                             │
┌──────────┐     rollback        │
│ Stopping │────────────────→┌───┘
└──────────┘                 │
                             ▼
                      ┌──────────┐
                      │ Stopped  │ (if rollback clean)
                      └──────────┘
```

### State Descriptions

| State | Description |
|-------|-------------|
| **Stopped** | No tasks running. Initial state and terminal state after clean shutdown/rollback. |
| **Starting** | Bootstrap in progress: configuration validated, runtime created, peers connecting. |
| **Running** | All required tasks active. Accepting peer connections. Processing DHT traffic. |
| **Stopping** | Shutdown initiated. No new peers accepted. Existing peers draining. |
| **Failed** | Rollback itself had errors. Requires manual recovery. Can transition to `Starting` via `can_start()`. |

## Startup Ordering

`start_with_policy()` is the primary startup entry point. The legacy `start()` is a convenience wrapper that uses `MeshStartupPolicy::default()` (all-optional). Both acquire the **lifecycle operation lock** (`lifecycle_op: tokio::sync::Mutex<()>`) before proceeding, serializing concurrent start/stop transitions.

The following startup phases execute sequentially. Each phase must complete before the next begins.

| Phase | Description | Required |
|-------|-------------|----------|
| 1 | Acquire lifecycle operation lock. Acquire lifecycle state lock. Verify `can_start()` (allows `Stopped` or `Failed`). Transition to `Starting`. | Yes |
| 2 | Create `MeshStartupStage` with a fresh `MeshTaskGroup` (using stable exit sender + global ID generator). Reset `shutdown_started` flag. | Yes |
| 3 | Start critical transport loops: `mesh_maintenance_loop`, `datagram_listener_loop`. | Yes |
| 4 | Seed bootstrap (one-shot self-attestation). Degraded if policy allows; fatal if `require_seed_connectivity`. | No |
| 5 | Connect configured peers. Degraded if policy allows; fatal if `require_configured_peers`. | No |
| 6 | DHT bootstrap. Degraded if policy allows; fatal if `require_dht_bootstrap`. | No |
| 7 | Start periodic background loops: `connection_maintenance`, `peer_health_check`, `proactive_cache_warming`, `dht_cache_resync`, `load_reporter`, `global_node_heartbeat`, `discovery_maintenance`, `dht_bucket_stats`, `dht_bucket_refresh`, `dht_peer_ping`. | No |
| 8 | Start `mesh_accept_loop` with QUIC runtime. | Yes |
| 9 | Transfer staged task group into transport ownership. Transition lifecycle state to `Running`. Set `running_projection = true`. Mark stage as committed. | Yes |

**Note:** Tasks gated on `min_peer_connections > 0` are skipped during startup if no peer connections are configured.

### Lifecycle Operation Lock

A `tokio::sync::Mutex<()>` field (`lifecycle_op`) on `MeshTransport` serializes start and stop transitions. Both `start_with_policy()` and `shutdown_with_timeout()` acquire this lock as their first operation, preventing concurrent lifecycle mutations. This ensures:
- No overlapping start attempts
- No start during shutdown
- No overlapping shutdown calls
- State transitions are always observable in a consistent order

## Shutdown Ordering

`shutdown_with_timeout(timeout)` is the primary shutdown entry point. All shutdown phases share **one deadline** derived from the caller's timeout — no phase applies a fresh fixed timeout.

The following shutdown phases execute sequentially. Each phase must complete before the next begins.

| Phase | Description | Required |
|-------|-------------|----------|
| 1 | Acquire lifecycle operation lock. Verify `can_stop()` (allows `Running` only). Transition to `Stopping`. Clear `running_projection`. | Yes |
| 2 | Set `shutdown_started` flag. Signal shutdown to task group via `begin_shutdown()`. Also send on legacy broadcast channel. | Yes |
| 3 | Close all QUIC connections. Capture `peers_at_shutdown_start`. Clear peer connection map. | Yes |
| 4 | Join all tasks with shared deadline (`remaining(deadline)`). | Yes |
| 5 | Drain peer sessions with shared deadline. Abort and drain if deadline expires mid-wait. | Yes |
| 6 | Clear lifecycle state (task group, shutdown signal, startup guard). | Yes |
| 7 | Transition lifecycle to `Stopped`. | Yes |

## Rollback Behavior (Iterations 70–71)

If any startup phase fails after the first task spawn, `rollback_and_return()` is called:

1. **Record the startup error** — preserve the original error for the caller.
2. **Begin cancellation** — signal shutdown to all tasks started during the failed attempt via `stage.task_group.begin_shutdown()`.
3. **Close attempt-created connections** — close and remove QUIC connections for peers connected during this attempt. Rollback uses `session_id` (not `node_id`) for `peer_connections` DashMap removal.
4. **Join/abort all tasks** — await graceful completion with a bounded timeout, then abort.
5. **Restore topology entries** — remove topology entries that were created during the failed startup (entries that did not exist before).
6. **Clean up peer sessions** — cooperative drain → abort all → brief wait.
7. **Stop the QUIC runtime** (if started).
8. **Verify rollback completeness** — `verify_rollback_complete()` checks post-rollback invariants.
9. **Classify rollback outcome** — `RollbackReport` indicates whether cleanup was clean or had errors.

### StagedPeerResource

Each peer mutation during startup is tracked with `StagedPeerResource`:

| Field | Meaning |
|-------|---------|
| `session_id` | Session identifier for the peer connection |
| `node_id` | Node identifier for the peer |
| `topology_existed_before` | Whether a topology entry existed before this startup attempt |
| `connection_inserted` | Whether the connection was inserted into the connection map |
| `session_task_created` | Whether a session task was spawned |

This enables precise rollback: connections are removed by `session_id`, topology entries are only removed if they were created during this attempt, and session tasks are selectively aborted.

### rollback_and_return()

`rollback_and_return<T>(stage, startup_error)` centralizes rollback error propagation:

1. Calls `rollback_startup()` to perform cleanup.
2. Calls `verify_rollback_complete()` to check post-rollback invariants.
3. Calls `finish_failed_startup()` to handle lifecycle state transition.
4. If rollback was clean and verification passed, returns the original startup error.
5. If rollback had errors or verification found issues, returns `StartupRollbackFailed` with both the original error and the rollback/verification errors.

This ensures callers always receive a meaningful error, even when rollback itself fails.

### Rollback Report

`RollbackReport` tracks rollback outcome with expanded fields:

| Field | Meaning |
|-------|---------|
| `clean` | Whether the rollback completed without errors |
| `errors` | Errors encountered during rollback (may be partial) |
| `tasks_joined` | Number of staged tasks that completed during rollback |
| `tasks_aborted` | Number of staged tasks still active after join timeout |
| `peer_connections_closed` | Number of peer connections closed during rollback |
| `topology_entries_restored` | Number of topology entries restored (best-effort) |
| `peer_sessions_cleaned` | Number of peer sessions cleaned up |
| `runtime_stopped` | Whether the QUIC runtime was stopped |

### Shared Rollback Deadline

All rollback phases share a single deadline governed by `startup_rollback_timeout_secs` (default 15s). This ensures bounded rollback regardless of how many resources were created. The same timeout governs task joining, session cleanup, and topology restoration.

### Rollback Outcome → Lifecycle Transition

| Rollback Outcome | Lifecycle Transition | Recovery |
|------------------|---------------------|----------|
| **Clean** (`RollbackReport.clean = true`) | `Starting → Stopped` | Safe to retry `start_with_policy()` immediately |
| **Errors** (`RollbackReport.clean = false`) | `Starting → Failed` | Requires manual recovery; `can_start()` allows retry from `Failed` |

### Rollback Guarantees

- After clean rollback, the `MeshTransport` is in `Stopped` state and can be restarted.
- After error rollback, the `MeshTransport` is in `Failed` state; `can_start()` permits a subsequent attempt.
- `rollback_and_return()` constructs `StartupRollbackFailed` when cleanup is incomplete, preserving both the original error and rollback errors.
- `verify_rollback_complete()` checks post-rollback invariants (e.g., no remaining connections, no orphaned topology entries) and reports issues.
- Partially completed DHT writes from `global_self_attestation` are idempotent and safe to retry.
- No leaked tasks remain after rollback (all joined or aborted).
- `DhtRoutingManager` tasks are gracefully cancelled via `watch::Sender` and joined via tracked `JoinHandle`.
- The stage is never dropped without explicit rollback or commit (ownership is guaranteed).

## Staged Startup/Rollback (Iterations 69–71)

`MeshStartupStage` owns every task and resource from a single startup attempt. It collects all spawned task handles into a single staging area.

### MeshStartupStage

- Every task spawned during startup is registered with the stage via `stage.track(handle)`.
- Peer resources created during startup (connections, topology entries, sessions) are recorded via `stage.record_peer(StagedPeerResource)` with exact mutation metadata.
- On success, `commit_startup()` transfers ownership in this order: (1) install staged task group into transport, (2) transition lifecycle state to `Running`, (3) set `running_projection = true`, (4) mark stage as committed.
- On failure, `rollback_startup()` cancels and joins all staged tasks, closes attempt-created connections, restores topology entries, cleans up peer sessions, and stops the runtime — no task group is dropped without cancellation and join.
- The stage ensures atomic cleanup: either all resources from an attempt survive or none do.
- `MeshStartupStage` tracks: `created_peers: Vec<StagedPeerResource>` (exact peer mutations), `runtime_started` (whether QUIC runtime was started), and `committed` (whether the stage has been committed).

### Lifecycle Transitions

```
Stopped → Starting → Running
                   ↓ (post-spawn error, rollback clean)
                 Stopped (safe to retry)

Stopped → Starting → Running
                   ↓ (post-spawn error, rollback had errors)
                 Failed (requires recovery, can_start() allows retry)
```

`rollback_startup()` is called on any post-spawn error. It signals shutdown to all staged tasks, joins with bounded timeout (5s), aborts stragglers, and clears the startup guard. The transport returns to `Stopped` (clean rollback) or `Failed` (incomplete rollback) and is ready for a subsequent attempt.

## Required vs Optional Bootstrap Policy (Iteration 69)

`MeshStartupPolicy` controls whether bootstrap failures are fatal or degraded.

### MeshStartupPolicy

```rust
pub struct MeshStartupPolicy {
    pub require_seed_connectivity: bool,   // default: false
    pub require_configured_peers: bool,   // default: false
    pub require_dht_bootstrap: bool,      // default: false
}
```

Default policy is all-optional (degraded startup allowed). A transport can start with zero peers connected and enter a degraded mode. When a bootstrap requirement is `true`, failure triggers `rollback_startup()` — the transport cannot enter `Running` without satisfying the policy.

### MeshStartupReport

Returned after startup to communicate the actual bootstrap outcome:

| Field | Meaning |
|-------|---------|
| `bootstrap_degraded` | Whether startup succeeded despite missing optional bootstrap targets |
| `peers_connected` | Number of peers connected during startup |
| `dht_bootstrap_ok` | Whether DHT bootstrap completed |
| `seed_attestation_ok` | Whether seed self-attestation completed |

## Stable Exit Subscription (Iteration 69)

### Problem

Previous implementations created the broadcast exit sender inside the task group. When the task group was replaced during shutdown/rollback, the exit sender was dropped and subscribers got `RecvError::Closed`.

### Solution

`mesh_exit_tx: broadcast::Sender<MeshTaskExit>` lives on `MeshTransport` itself, surviving task group replacement. Task groups are created with `MeshTaskGroup::new_with_forward(exit_tx)` which forwards their internal exit events to the stable sender.

### Invariants

- `subscribe_exits()` is synchronous and valid before `start()` — no task group needed.
- Broadcast delivery is for **runtime observation only** — not authoritative for shutdown reports.
- Join-returned exit is the authoritative source for `MeshShutdownReport`.
- No duplicate accounting between broadcast and join — each task reports exactly once.

## Task ID/Dedup Semantics (Iterations 69–70)

### MeshTaskIdGenerator

`MeshTaskIdGenerator` owns a monotonically increasing `AtomicU64` counter. Each `MeshTransport` owns one `Arc<MeshTaskIdGenerator>` and passes it into every new `MeshTaskGroup` via `new_with_forward_and_id_gen()`. This ensures **globally unique task IDs across task-group generations** — no two exit-channel events share the same ID during process lifetime.

### MeshTaskId

`MeshTaskId(u64)` is assigned at spawn time by `MeshTaskGroup`. IDs are unique within the process when allocated via `MeshTaskIdGenerator`.

### Semantics

- **Broadcast delivery**: Tasks forwarded to the stable exit sender carry their `MeshTaskId` for runtime observation (monitoring, metrics, logging).
- **Join-returned exit**: When `join_all()` collects exits, each carries the same `MeshTaskId`. This is the **authoritative** source for shutdown reports and metrics.
- **No duplicate accounting**: If a task's exit is observed via both broadcast and join, the metrics system deduplicates via `MeshTaskId`. The `MeshShutdownReport` uses only join-returned exits.

## Handshake/Session Ownership Split (Iteration 69)

### Handshake Children

- Bounded, short-lived, semaphore-limited.
- Live in `mesh_accept_loop`'s `JoinSet<HandshakeResult>`.
- `max_concurrent_handshakes` (default 32) bounds concurrency via `OwnedSemaphorePermit`.
- On connection complete or error, the handshake entry is removed from the `JoinSet`.
- Shutdown drains with bounded timeout, then aborts.

### Peer Sessions

- Long-lived connections stored in `peer_sessions: Arc<Mutex<JoinSet<()>>>`.
- Created after successful handshake; removed on disconnect.
- Shutdown drains peer sessions **after** closing all QUIC connections.
- Each session handle is `.await`ed with bounded timeout.

### Ordering

```
Shutdown → close connections → drain peer sessions → drain handshake children → abort remnants
```

## Truthful Shutdown Report (Iterations 69–71)

`MeshShutdownReport` fields reflect the actual state observed during shutdown:

| Field | Source | Meaning |
|-------|--------|---------|
| `clean_tasks` | Join results | Count of tasks that exited cleanly |
| `failed_tasks` | Join results | Tasks that exited with an error (non-fatal) |
| `aborted_tasks` | Join results | Tasks that were forcibly aborted |
| `drained_peer_children` | Accept loop report | Number of bounded peer children that drained cleanly during accept-loop shutdown |
| `aborted_peer_children` | Accept loop report | Number of bounded peer children that were aborted after timeout during accept-loop shutdown |
| `peers_at_shutdown_start` | Captured at shutdown begin | Peer count before teardown |
| `remaining_peers` | Measured after connection close/drain | Peers still active after drain |
| `drained_peer_sessions` | Session drain result | Number of peer sessions drained cleanly |
| `aborted_peer_sessions` | Session drain result | Number of peer sessions aborted |

### MeshAcceptLoopReport

The `MeshAcceptLoopReport` struct (`lifecycle.rs:325`) is wired into the mesh accept loop. When the accept loop shuts down, it tracks `drained_handshakes` (cooperatively exited children) and `aborted_handshakes` (forcibly aborted after timeout). The report is stored in `MeshTransport::accept_loop_report` and read by `shutdown_with_timeout()` to populate `MeshShutdownReport.drained_peer_children` / `aborted_peer_children`.

The `rejected_at_capacity` field remains untracked (always zero) — it would require incrementing a counter in the accept loop's semaphore rejection path.

### Invariants

- `remaining_peers` is measured **after** connections are closed and sessions are drained, not before.
- `peers_at_shutdown_start` is captured at the beginning of shutdown for comparison.
- Handshake child counts propagate into the report from the accept loop's `JoinSet`.
- The report is truthful — it reflects what actually happened, not what was requested.
- `drained_peer_children` and `aborted_peer_children` in `MeshShutdownReport` are now populated from the accept loop report (Iteration 71).

## Worker Integration (Iterations 69–70)

### ManagedMeshService Updates

| Method | Behavior |
|--------|----------|
| `subscribe_critical_exits()` | Delegates to stable `subscribe_exits()` — valid before `start()`, survives task group replacement |
| `is_running()` | Reads `running_projection: Arc<AtomicBool>` — set `true` on `commit_startup()`, set `false` on `shutdown_with_timeout()` entry. No Tokio lock contention, no blocking. |
| `start()` | Compatibility wrapper calling `MeshTransport::start()` (uses default policy) |
| `start_with_policy(policy)` | Primary API — staged transactional startup via `MeshStartupStage` |
| `shutdown(timeout)` | Calls `MeshTransport::shutdown_with_timeout()` |

### `running_projection` (AtomicBool)

`is_running()` reads from an `AtomicBool` projection (`running_projection`) rather than locking the lifecycle state mutex. This avoids Tokio mutex contention in hot observation paths. The projection is set:
- `true` in `commit_startup()` after transitioning to `Running`
- `false` at the entry of `shutdown_with_timeout()` after transitioning to `Stopping`

### MeshServiceExit Variant

`WorkerShutdownCause` gains a `MeshServiceExit(MeshTaskExit)` variant for mesh task failures:

```rust
pub enum WorkerShutdownCause {
    // ... existing variants ...
    MeshServiceExit(MeshTaskExit),  // Mesh task failed
}
```

This variant is fatal when the mesh task is a `CriticalService` with `Error`, `Panic`, or `UnexpectedCompletion` (following the same fatality policy as other critical services).

### Mesh Supervision (Explicitly Deferred — Outcome B)

Worker mesh supervision consumption is **explicitly deferred** (Outcome B from Iteration 70). The `MeshServiceExit` variant exists in `WorkerShutdownCause` but is **not wired** in the production worker supervision loop. `ManagedMeshService` trait and `MeshFailureCause` types are staged infrastructure for future integration.

The supervision loop would observe exits from the stable subscription and map them to `MeshServiceExit` using the same `is_fatal_exit()` classification when integration is implemented.

## Failure Injection Hooks (Iteration 69 — Phase 20)

`MeshTransport` supports test-only failure injection for deterministic startup testing. The hooks are compiled only in `#[cfg(test)]` builds.

### StartupFailurePoint Enum

```rust
#[cfg(test)]
pub enum StartupFailurePoint {
    AfterCriticalTasks,      // After mesh_maintenance and datagram_listener spawned
    DuringSeedBootstrap,     // Before seed bootstrap phase
    DuringPeerConnect,       // Before configured peer connection phase
    DuringDhtBootstrap,      // Before DHT bootstrap phase
    DuringRuntimeStart,      // Before QUIC runtime start_server()
    BeforeLifecycleCommit,   // Before lifecycle state transitions to Running (renamed from AfterLifecycleCommit)
}
```

### Hook API

```rust
impl MeshTransport {
    /// Set a failure injection hook for testing.
    pub fn set_startup_failure_hook(
        &self,
        hook: impl Fn(StartupFailurePoint) -> Result<(), String> + Send + 'static,
    );

    /// Clear the failure injection hook.
    pub fn clear_startup_failure_hook(&self);

    /// Check if a hook is currently installed.
    pub fn has_startup_failure_hook(&self) -> bool;
}
```

### Hook Behavior

When a hook is installed, `start()` checks it at each phase. If the hook returns `Err(msg)`:
- Phases 3-6 (pre-accept): Error propagated via `?`, no rollback needed (no runtime tasks started).
- Phases 9-10 (post-accept): `rollback_startup()` called before returning error.

When the hook returns `Ok(())`, startup continues normally.

### Test Coverage

`tests/mesh_startup_rollback.rs` (11 tests):
- Hook lifecycle (set, clear, replace)
- `StartupFailurePoint` enum properties
- Retry from Failed state
- Lifecycle not stuck at Starting after failure
- Transport construction with minimal defaults
- Hook API integration

## Changelog

| Iteration | Changes |
|-----------|---------|
| 70 | Initial lifecycle state machine, staged startup/rollback, task groups, truthful shutdown report, failure injection hooks, worker integration |
| 71 | Commit ordering: task group install → lifecycle transition → running projection. `rollback_and_return()` centralizes rollback error propagation, constructing `StartupRollbackFailed` when cleanup is incomplete. `StagedPeerResource` tracks exact peer mutations. Rollback uses `session_id` for `peer_connections` removal. Topology entries created during failed startup removed on rollback. `RollbackReport` expanded with `tasks_joined`, `tasks_aborted`, `peer_connections_closed`, `topology_entries_restored`, `peer_sessions_cleaned`, `runtime_stopped`. `verify_rollback_complete()` checks post-rollback invariants. Shared rollback deadline (`startup_rollback_timeout_secs`, default 15s). Peer session cleanup: cooperative drain → abort all → brief wait. `QuicRuntime::stop_server()` provides active endpoint cleanup during rollback. `MeshAcceptLoopReport` wired — accept loop tracks drained/aborted handshake children and publishes report; `MeshShutdownReport.drained_peer_children` and `aborted_peer_children` populated from accept loop report. |
