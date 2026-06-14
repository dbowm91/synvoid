# Mesh Transport Lifecycle Inventory — Iteration 69

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
   │ ┌────────┐
   │ │ Failed │──────────┐
   │ └────────┘          │ rollback complete
   │                     ▼
   │              ┌──────────┐
   │              │ Stopped  │
   │              └──────────┘
   │
   │ startup complete
   ▼
┌──────────┐
│ Running  │
└──┬───────┘
   │
   │ stop() or fatal error
   ▼
┌──────────┐     rollback    ┌──────────┐
│ Stopping │────────────────→│ Stopped  │
└──────────┘                 └──────────┘
```

### State Descriptions

| State | Description |
|-------|-------------|
| **Stopped** | No tasks running. Initial state and terminal state after shutdown/rollback. |
| **Starting** | Bootstrap in progress: configuration validated, runtime created, peers connecting. |
| **Running** | All required tasks active. Accepting peer connections. Processing DHT traffic. |
| **Stopping** | Shutdown initiated. No new peers accepted. Existing peers draining. |
| **Failed** | Startup failed or runtime encountered a fatal error. Rollback in progress. |

## Startup Ordering

The following startup phases execute sequentially. Each phase must complete before the next begins.

| Phase | Description | Required |
|-------|-------------|----------|
| 1 | Acquire startup guard. Verify not already running. | Yes |
| 2 | Validate configuration and required runtime handles. | Yes |
| 3 | Create fresh task group and shutdown state. | Yes |
| 4 | Start minimum listener/runtime for bootstrap (QUIC socket). | Yes |
| 5 | Seed bootstrap (one-shot self-attestation). | No |
| 6 | Connect configured peers. | No |
| 7 | DHT bootstrap. | No |
| 8 | Start critical transport loops: `mesh_maintenance_loop`, `datagram_listener_loop`, `mesh_accept_loop`. | Yes |
| 9 | Start periodic background loops: `pow_nonce_refresh`, `mlkem_key_rotation`, `connection_maintenance`, `peer_health_check`, `proactive_cache_warming`, `dht_cache_resync`, `load_reporter`, `global_node_heartbeat`, `discovery_maintenance`, `dht_bucket_stats`, `dht_bucket_refresh`, `dht_peer_ping`. | No |
| 10 | Start one-shot self-attestation (`global_self_attestation`) if applicable. | No |
| 11 | Commit lifecycle state to `Running`. | Yes |
| 12 | Set `running = true` only after required startup succeeds. | Yes |

**Note:** Tasks gated on `min_peer_connections > 0` are skipped during startup if no peer connections are configured.

## Shutdown Ordering

The following shutdown phases execute sequentially. Each phase must complete before the next begins.

| Phase | Description | Required |
|-------|-------------|----------|
| 1 | Mark shutdown intent (`Stopping`). | Yes |
| 2 | Stop accepting new peers (close accept loop). | Yes |
| 3 | Signal periodic/maintenance tasks (broadcast cancel). | Yes |
| 4 | Stop datagram/listener loops. | Yes |
| 5 | Drain peer children (in-flight `incoming_peer_connection` tasks). | Yes |
| 6 | Close active peer connections. | Yes |
| 7 | Await critical tasks (`mesh_maintenance_loop`, `datagram_listener_loop`, `mesh_accept_loop`). | Yes |
| 8 | Await background tasks (`pow_nonce_refresh`, `mlkem_key_rotation`, etc.). | No (best-effort) |
| 9 | Abort and await remnants (any tasks that did not finish gracefully). | Yes |
| 10 | Clear lifecycle state (task group, shutdown signal, startup guard). | Yes |
| 11 | Set `running = false`. | Yes |

## Rollback Behavior

If any startup phase fails:

1. **Record the startup error** — preserve the original error for the caller.
2. **Begin cancellation** — signal shutdown to all tasks started during the failed attempt.
3. **Join/abort all tasks** — await graceful completion with a bounded timeout, then abort.
4. **Close listener/runtime resources** — release QUIC socket and associated state.
5. **Clear shutdown/task-group state** — reset internal state to allow a subsequent startup attempt.
6. **Ensure `running = false`** — guarantee the lifecycle reflects the stopped state.
7. **Return diagnostics** — return the original startup error plus any rollback diagnostics (e.g., which tasks were started, how many joined vs. aborted).

### Rollback Guarantees

- After rollback, the `MeshTransport` is in `Stopped` state and can be restarted.
- Partially completed DHT writes from `global_self_attestation` are idempotent and safe to retry.
- No leaked tasks remain after rollback (all joined or aborted).
- `DhtRoutingManager` tasks are gracefully cancelled via `watch::Sender` and joined via tracked `JoinHandle`.

## Staged Startup/Rollback (Iteration 69)

`MeshStartupStage` owns every task and resource from a single startup attempt. It collects all spawned task handles into a single staging area.

### MeshStartupStage

- Every task spawned during startup is registered with the stage via `stage.track(handle)`.
- On success, the stage hands off ownership to the running task group.
- On failure, `stage.rollback()` cancels and joins all staged tasks — no task group is dropped without cancellation and join.
- The stage ensures atomic cleanup: either all tasks from an attempt survive or none do.

### Lifecycle Transitions

```
Stopped → Starting → Running
                  ↓ (post-spawn error)
                Failed → rollback → Stopped
```

`rollback_startup()` is called on any post-spawn error. It signals shutdown to all staged tasks, joins with bounded timeout, aborts stragglers, and clears the startup guard. The transport returns to `Stopped` and is ready for a subsequent attempt.

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

## Task ID/Dedup Semantics (Iteration 69)

### MeshTaskId

`MeshTaskId(u64)` is assigned at spawn time by `MeshTaskGroup`. The ID is monotonically increasing and unique within the process.

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

## Truthful Shutdown Report (Iteration 69)

`MeshShutdownReport` fields reflect the actual state observed during shutdown:

| Field | Source | Meaning |
|-------|--------|---------|
| `total_tasks` | Task group count | Total tasks that were spawned |
| `clean_shutdown` | Join results | All tasks exited cleanly |
| `tasks_clean` | Join results | Count of tasks with `CleanCompletion` |
| `tasks_failed` | Join results | Count of tasks with `Error` |
| `tasks_aborted` | Join results | Count of tasks that had to be aborted |
| `peers_at_shutdown_start` | Captured at shutdown begin | Peer count before teardown |
| `remaining_peers` | Measured after connection close/drain | Peers still active after drain |
| `drained_peer_sessions` | Session drain result | Number of peer sessions drained cleanly |
| `aborted_peer_sessions` | Session drain result | Number of peer sessions aborted |
| `drained_handshake_children` | Handshake drain result | Number of handshake children drained |
| `aborted_handshake_children` | Handshake drain result | Number of handshake children aborted |

### Invariants

- `remaining_peers` is measured **after** connections are closed and sessions are drained, not before.
- `peers_at_shutdown_start` is captured at the beginning of shutdown for comparison.
- Handshake child counts propagate into the report from the accept loop's `JoinSet`.
- The report is truthful — it reflects what actually happened, not what was requested.

## Worker Integration (Iteration 69)

### ManagedMeshService Updates

| Method | Behavior |
|--------|----------|
| `subscribe_critical_exits()` | Delegates to stable `subscribe_exits()` — valid before `start()`, survives task group replacement |
| `is_running()` | Derives from `MeshLifecycleState` (not a legacy `AtomicBool`) |
| `start()` | Calls `MeshTransport::start()` with staged startup |
| `shutdown(timeout)` | Calls `MeshTransport::shutdown_with_timeout()` |

### MeshServiceExit Variant

`WorkerShutdownCause` gains a `MeshServiceExit(MeshTaskExit)` variant for mesh task failures:

```rust
pub enum WorkerShutdownCause {
    // ... existing variants ...
    MeshServiceExit(MeshTaskExit),  // Mesh task failed
}
```

This variant is fatal when the mesh task is a `CriticalService` with `Error`, `Panic`, or `UnexpectedCompletion` (following the same fatality policy as other critical services).

### Mesh Supervision

When the control plane is re-enabled in workers, the mesh supervision loop observes exits from the stable subscription and maps them to `MeshServiceExit` using the same `is_fatal_exit()` classification. The supervision loop is wired into the worker's `WorkerTaskRegistry` supervision select.
