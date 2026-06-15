# Mesh Transport Lifecycle Inventory — Iteration 77

## Purpose

This document is the **canonical inventory** of every task spawned by `MeshTransport`, `MeshDiscovery`, `DhtRoutingManager`, and `ThreatIntelligenceManager` during the mesh runtime lifecycle. It classifies each task, documents its current cancellation/join behavior, and defines the target lifecycle state machine, startup ordering, and shutdown ordering.

## Iteration 76 — Forced-Cleanup Corrective Pass

Iteration 76 corrects three classes of bugs that survived Iteration 75 and adds
mechanical guardrails to prevent regression:

### Part A — Always finalize `MeshTaskGroup`

`rollback_startup()` and `recover_failed_state()` now **always** call
`MeshTaskGroup::join_all(remaining(deadline))`. The pre-fix call site did
`if task_remaining.is_zero() { Vec::new() }`, which left tasks orphaned in the
registry without exit reporting. The contract is:

> A zero remaining budget changes cleanup from drain to forced abort — it
> never permits skipping ownership finalization.

`join_all(Duration::ZERO)` itself takes the zero-budget branch internally
(`handle.abort()` + `handle.await` + synthetic `Aborted` exit). The single
call site is now `let exits = stage.task_group.join_all(remaining(deadline))`.

### Part B — Cooperative peer-session cancellation

`PeerSessionTask` gains a `shutdown_tx: watch::Sender<bool>` field. The
session's `peer_message_loop` selects on the cooperative signal via:

```rust
tokio::select! {
    biased;
    _ = shutdown_rx.changed() => { /* cooperative drain */ }
    stream = accept_bi() => { ... }
}
```

The `biased` keyword ensures the cancel branch wins the race against a
steady stream of incoming events. A shared `stop_peer_session_task()` helper
classifies cleanup as `PeerSessionStopOutcome::{Drained, ForcedParentAbort,
Failed}` so rollback/recovery/shutdown can distinguish cooperative drain
from forced parent abort (which cannot prove the child stream-handler
`JoinSet` was drained through the normal path).

`stop_staged_peer_activity()` always sends the cooperative signal **before**
delegating to the helper:

```rust
let _ = task.shutdown_tx.send(true);
let outcome = Self::stop_peer_session_task(task.handle, left, Some(report)).await;
```

### Part C — Safe DHT force restoration

`KBucket::force_replace` signature changed from `Option<PeerContact>` to
`Result<Option<PeerContact>, ForceRestoreError>`. A full bucket with an
absent target now fails closed with `BucketFullTargetAbsent` rather than
silently evicting an unrelated contact. The new error type is propagated
through `RoutingTable::force_restore_contact` as
`Result<PeerContact, ForceRestoreContactError>`, which is then translated
to `String` in `DhtRoutingManager::restore_peer` for the report.

### Part D — DHT snapshot boundary

`DhtPeerSnapshot` is documented as a **logical** snapshot. The
`last_seen` field is intentionally refreshed to `now()` during restore
because rolling the clock backwards on a contact that may have legitimately
been seen again would be incorrect. Callers that need recency must use the
freshly-snapshotted `PeerContact` (which is restored verbatim), not
`DhtPeerSnapshot.last_seen`.

### Part E — Refined stream timeout semantics

Two independent timeout fields replace the single per-message read timeout:

| Field | Default | Scope | Use case |
|-------|---------|-------|----------|
| `peer_message_timeout_secs` | 30s | Per-message read/framing | Bounds I/O stall on a single message |
| `peer_stream_total_timeout_secs` | 0 (disabled) | Total stream lifetime | Optional cap for long-lived streams |

The split prevents long-lived proxy streams from being killed by the
short per-message framing timeout. In Iteration 77, `apply_read_timeouts`
was removed — per-message read timeouts are now applied directly at
`read_exact_with_timeout()` / `read_to_end_with_timeout()` call sites
in `peer_message_loop`, not via a wrapper around the full handler future.

### Guardrails

- **`tests/mesh_forced_cleanup.rs`** (new): 8 integration tests covering Parts A/B/C/D.
- **`tests/mesh_task_ownership_guard.rs`**: 9 new `iter76_*` assertions.
- **`tests/mesh_startup_rollback.rs`**: 8 new behavioral assertions.
- **`tests/mesh_lifecycle_tests.rs`**: 1 cooperative-cancellation test.

## Iteration 77 — Nested-Cleanup Corrective Pass

Iteration 77 addresses four classes of issues from Iteration 76:

### Part A — Deadline-aware stream drain

`drain_peer_stream_handlers()` now uses `tokio::time::timeout(left, handlers.join_next()).await`
so no cooperative wait exceeds the supplied timeout. A hung stream handler can no longer block
session finalization indefinitely.

### Part B — Remove `apply_read_timeouts`

The `apply_read_timeouts()` wrapper around the full `handle_peer_message()` future was removed.
The configured read/framing timeout was misleadingly a total handler lifetime timeout when
applied at the future level. Per-message reads now use `read_exact_with_timeout()` and
`read_to_end_with_timeout()` directly, applying the timeout to the actual I/O operation.

### Part C — Forced abort classification

`stop_peer_session_task()` zero-budget branch now correctly returns `ForcedParentAbort`
instead of `Failed("parent cancelled")`. A new `force_abort_peer_session()` helper wraps
the cooperative abort + await pattern for callers that need to forcibly terminate a session.

### Part D — Rollback error accounting

Rollback and recovery now record `ForcedParentAbort` and `Failed` outcomes as incomplete
cleanup errors, preventing false clean lifecycle transitions.

### Part E — Datagram handler ownership

`start_datagram_handler()` now owns incoming datagram handlers in a bounded `JoinSet`
(`max_concurrent_datagram_handlers`, default 32) instead of bare `tokio::spawn()`. This
closes the last visible detached mesh task path. The `JoinSet` is drained on shutdown.

### New Config Fields

| Field | Default | Description |
|-------|---------|-------------|
| `peer_stream_drain_timeout_secs` | 5 | Timeout for draining per-stream handlers before forced abort |
| `max_concurrent_datagram_handlers` | 32 | Bounded concurrency for datagram handler tasks |

### New Helpers

- `force_abort_peer_session()` — cooperative abort + await for forcibly terminating a session
- `classify_stream_join()` / `classify_forced_stream_join()` — classify join results for stream handlers
- `read_exact_with_timeout()` / `read_to_end_with_timeout()` — deadline-aware reads replacing the removed `apply_read_timeouts` wrapper

### Guardrails

- **`tests/mesh_forced_cleanup.rs`**: new `iter77_*` behavioral tests
- **`tests/mesh_task_ownership_guard.rs`**: new `iter77_*` guardrails

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
   │ startup complete            │ (Failed requires recovery)
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

   Failed ─── recover_failed_state() ──→ Stopped
   (can_start() does NOT allow Failed)
```

### State Descriptions

| State | Description |
|-------|-------------|
| **Stopped** | No tasks running. Initial state and terminal state after clean shutdown/rollback. Safe to restart. |
| **Starting** | Bootstrap in progress: configuration validated, runtime created, peers connecting. |
| **Running** | All required tasks active. Accepting peer connections. Processing DHT traffic. |
| **Stopping** | Shutdown initiated. No new peers accepted. Existing peers draining. |
| **Failed** | Rollback itself had errors. **Not safe to restart.** Requires explicit recovery via `recover_failed_state()`. `can_start()` does NOT allow `Failed` — attempting to start from `Failed` state panics. |

### Failed State Recovery (Iterations 72, 74, 75)

`Failed` indicates incomplete rollback — some resources may still be owned. `can_start()` only allows `Stopped`, not `Failed`. The transport must recover before it can restart.

```rust
pub async fn recover_failed_state(
    &self,
    timeout: Duration,
) -> Result<(), MeshTransportError>
```

`recover_failed_state(timeout)` performs:

1. **Acquire lifecycle operation lock** — prevents concurrent start/stop.
2. **Transition from `Failed` to `Starting`** — allows cleanup to proceed.
3. **Re-run cleanup** — re-executes the same rollback steps (signal shutdown, close connections, join/abort tasks, restore topology, clean sessions, stop runtime).
4. **Apply retained residue before clearing** — `FailedStartupResidue` from the previous incomplete rollback is applied via `restore_and_verify_peer_logical_state()` (Iteration 75) which combines restoration and verification in one call. Successfully restored peers have their connections closed and removed. Partially restored peers retain residue for a subsequent attempt (Iteration 74, Phase 2–3).
5. **Verify no owned resources remain** — checks connection map is empty, topology entries are clean, task group is drained. **Iteration 77**: `session_errors` from peer session drain are merged into `issues` so they appear in recovery diagnostics rather than being silently discarded.
6. **Transition to `Stopped`** — marks transport as clean and safe to restart.

If recovery fails (timeout or verification issues), the transport transitions back to `Failed`. Multiple recovery attempts are safe.

## Startup Ordering

`start_with_policy()` is the primary startup entry point. The legacy `start()` is a convenience wrapper that uses `MeshStartupPolicy::default()` (all-optional). Both acquire the **lifecycle operation lock** (`lifecycle_op: tokio::sync::Mutex<()>`) before proceeding, serializing concurrent start/stop transitions.

The following startup phases execute sequentially. Each phase must complete before the next begins.

| Phase | Description | Required |
|-------|-------------|----------|
| 1 | Acquire lifecycle operation lock. Acquire lifecycle state lock. Verify `can_start()` (allows `Stopped` only). Transition to `Starting`. | Yes |
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

## Rollback Behavior (Iterations 70–75)

If any startup phase fails after the first task spawn, `rollback_and_return()` is called:

1. **Record the startup error** — preserve the original error for the caller.
2. **Begin cancellation** — signal shutdown to all tasks started during the failed attempt via `stage.task_group.begin_shutdown()`.
3. **Close attempt-created connections** — close and remove QUIC connections for peers connected during this attempt. Rollback uses `session_id` (not `node_id`) for `peer_connections` DashMap removal.
4. **Join/abort all tasks** — await graceful completion with a bounded timeout, then abort. `tasks_aborted` is derived from `MeshTaskExitReason::Aborted` exit metadata, not from `active_count()`.
5. **Stop all peer sessions and auxiliary tasks** (Iteration 75) — ensures no late writes can invalidate restored state.
6. **Restore topology and DHT entries** — use `restore_and_verify_peer_logical_state()` (Iteration 75) which combines restoration and verification in one call. Topology restored via `restore_peer_state()` (native `PeerState`, not lossy conversion) with bidirectional `global_nodes` secondary-index update. DHT restored via `restore_peer()` using force-replacement (`force_restore_contact()`). For new peers (no prior state), topology entry is removed and DHT routing entry is removed when `DhtPeerMutation::Created`.
7. **Clean up peer sessions** — selective abort of only the staged sessions (keyed by `session_id` in the peer session registry).
8. **Stop the QUIC runtime** (if started).
9. **Merge verification into report** — `verify_rollback_complete()` checks post-rollback invariants; issues are merged into `RollbackReport` before `finish_failed_startup()`.
10. **Classify rollback outcome** — `RollbackReport` indicates whether cleanup was clean or had errors. Only **unresolved** peers (not all staged peers) are retained in `FailedStartupResidue`.

### StagedPeerResource

Each peer mutation during startup is tracked with `StagedPeerResource`:

| Field | Meaning |
|-------|---------|
| `session_id` | Session identifier for the peer connection |
| `node_id` | Node identifier for the peer |
| `topology_existed_before` | Whether a topology entry existed before this startup attempt |
| `connection_inserted` | Whether the connection was inserted into the connection map |
| `session_task_created` | Whether a session task was spawned |
| `dht_registration_created` | Whether DHT routing entries were created for this peer (Iteration 72) |

This enables precise rollback: connections are removed by `session_id`, topology entries are restored via snapshot, DHT entries are removed when `dht_registration_created` is true, and session tasks are selectively aborted from the keyed registry.

### StagedTopologySnapshot (Iterations 72, 74)

Topology snapshots capture the exact native prior state before modification:

| Field | Meaning |
|-------|---------|
| `peer_state` | Native `PeerState` for the peer (Iteration 74 — replaces lossy `MeshPeerInfo` + `PeerStatus` conversion) |

Rollback restores the exact prior state for existing peers (where `topology_existed_before = true`) via `restore_peer_state()` and removes new peers (where `topology_existed_before = false`). This avoids the ambiguity of "best-effort" restoration. The `restore_peer_logical_state()` shared helper (Iteration 74) is used by both `rollback_startup()` and `recover_failed_state()` to avoid duplicated restoration logic.

### rollback_and_return()

`rollback_and_return<T>(stage, startup_error)` centralizes rollback error propagation:

1. Calls `rollback_startup()` to perform cleanup.
2. Calls `verify_rollback_complete()` to check post-rollback invariants.
3. Calls `finish_failed_startup()` to handle lifecycle state transition.
4. If rollback was clean and verification passed, returns the original startup error.
5. If rollback had errors or verification found issues, stores **only unresolved peers** (not all staged peers) in `FailedStartupResidue` and returns `StartupRollbackFailed` with both the original error and the rollback/verification errors.

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
| `topology_entries_restored` | Number of topology entries restored |
| `peer_sessions_cleaned` | Number of peer sessions cleaned up |
| `unresolved_peers` | Number of peers that could not be restored, retained in `FailedStartupResidue` for retry (Iteration 75) |
| `runtime_stopped` | Whether the QUIC runtime was stopped |

### Shared Rollback Deadline

All rollback phases share a single deadline governed by `startup_rollback_timeout_secs` (default 15s). This ensures bounded rollback regardless of how many resources were created. The same timeout governs task joining, session cleanup, and topology restoration.

### Rollback Outcome → Lifecycle Transition

| Rollback Outcome | Lifecycle Transition | Recovery |
|------------------|---------------------|----------|
| **Clean** (`RollbackReport.clean = true`) | `Starting → Stopped` | Safe to retry `start_with_policy()` immediately |
| **Errors** (`RollbackReport.clean = false`) | `Starting → Failed` | **Not safe to restart.** Requires `recover_failed_state(timeout)` to transition to `Stopped` |

### Rollback Guarantees

- After clean rollback, the `MeshTransport` is in `Stopped` state and can be restarted.
- After error rollback, the `MeshTransport` is in `Failed` state; `can_start()` does NOT allow `Failed`. Use `recover_failed_state()` to recover.
- `rollback_and_return()` merges verification issues into `RollbackReport` before `finish_failed_startup()` — callers see the complete picture.
- `verify_rollback_complete()` checks post-rollback invariants (e.g., no remaining connections, no orphaned topology entries) and merges issues into the report.
- `tasks_aborted` is derived from `MeshTaskExitReason::Aborted` in exit metadata, not from `active_count()` — authoritative accounting.
- Topology entries are restored via `restore_peer_logical_state()` using native `PeerState` — exact prior state, not lossy conversion (Iteration 74). `restore_peer_state()` bidirectionally updates `global_nodes` (inserts when global, removes when non-global) (Iteration 75).
- DHT routing entries are restored from `DhtPeerSnapshot` via `restore_peer()` using force-replacement (`RoutingTable::force_restore_contact()`), which unconditionally replaces existing contacts without silent failures on full buckets (Iteration 75).
- `rollback_startup()` stops all peer sessions and auxiliary tasks **before** logical restoration (Iteration 75), preventing late writes from invalidating restored state.
- `restore_and_verify_peer_logical_state()` combines restoration and verification in one call (Iteration 75), ensuring atomicity.
- Only **unresolved** peers (not all staged peers) are retained in `FailedStartupResidue` on incomplete rollback (Iteration 75).
- Peer session tasks are selectively aborted from the keyed registry (not a global `JoinSet`).
- Partially completed DHT writes from `global_self_attestation` are idempotent and safe to retry.
- No leaked tasks remain after rollback (all joined or aborted).
- `DhtRoutingManager` tasks are gracefully cancelled via `watch::Sender` and joined via tracked `JoinHandle`.
- The stage is never dropped without explicit rollback or commit (ownership is guaranteed).
- A `commit_startup()` warning is logged when replacing a non-empty old task group (non-empty guard).

## Staged Startup/Rollback (Iterations 69–72)

`MeshStartupStage` owns every task and resource from a single startup attempt. It collects all spawned task handles into a single staging area.

### MeshStartupStage

- Every task spawned during startup is registered with the stage via `stage.track(handle)`.
- Peer resources created during startup (connections, topology entries, sessions) are recorded via `stage.record_peer(StagedPeerResource)` with exact mutation metadata (including `dht_registration_created`).
- Topology snapshots (`StagedTopologySnapshot`) capture `MeshPeerInfo` + `PeerStatus` before modification.
- On success, `commit_startup()` transfers ownership in this order: (1) install staged task group into transport, (2) transition lifecycle state to `Running`, (3) set `running_projection = true`, (4) mark stage as committed. **Warning logged if replacing non-empty old task group** (Iteration 72).
- On failure, `rollback_startup()` cancels and joins all staged tasks, closes attempt-created connections, restores topology entries (via snapshots), removes DHT entries, cleans up peer sessions (selective), and stops the runtime — no task group is dropped without cancellation and join.
- The stage ensures atomic cleanup: either all resources from an attempt survive or none do.
- `MeshStartupStage` tracks: `created_peers: Vec<StagedPeerResource>` (exact peer mutations), `topology_snapshots: Vec<StagedTopologySnapshot>` (prior topology state), `runtime_started` (whether QUIC runtime was started), and `committed` (whether the stage has been committed).

### Preflight Peer Routes (Iteration 72)

During startup, `preflight_peer_routes` runs as a **bounded child** in the staged task group. During steady-state (after commit), it runs detached (best-effort). This ensures preflight work is tracked during startup rollback but doesn't block steady-state operation.

### Lifecycle Transitions

```
Stopped → Starting → Running
                   ↓ (post-spawn error, rollback clean)
                 Stopped (safe to retry)

Stopped → Starting → Running
                   ↓ (post-spawn error, rollback had errors)
                 Failed (requires recover_failed_state())

Failed ──→ recover_failed_state() ──→ Stopped (safe to retry)
```

`rollback_startup()` is called on any post-spawn error. It signals shutdown to all staged tasks, joins with bounded timeout (5s), aborts stragglers, and clears the startup guard. The transport returns to `Stopped` (clean rollback) or `Failed` (incomplete rollback). From `Failed`, `recover_failed_state()` is the only path back to `Stopped`.

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

## Handshake/Session Ownership Split (Iterations 69, 72)

### Handshake Children

- Bounded, short-lived, semaphore-limited.
- Live in `mesh_accept_loop`'s `JoinSet<HandshakeResult>`.
- `max_concurrent_handshakes` (default 32) bounds concurrency via `OwnedSemaphorePermit`.
- On connection complete or error, the handshake entry is removed from the `JoinSet`.
- Shutdown drains with bounded timeout, then aborts.

### Peer Sessions (Iteration 72 — Selective Ownership)

Peer sessions now use a **keyed HashMap** (`HashMap<String, PeerSessionTask>`) instead of a global `JoinSet<()>`. Each session is keyed by `session_id`, allowing rollback to target only the sessions created during a specific startup attempt.

| Field | Meaning |
|-------|---------|
| `session_id` | Session identifier (same as `StagedPeerResource.session_id`) |
| `task_handle` | `JoinHandle<()>` for the session task |
| `node_id` | Node identifier for the peer (for logging) |
| `generation: u64` | Generation counter wired from `stage.next_session_generation()` (Phase 18); prevents stale completions from removing newer entries |

**Rollback behavior**: `rollback_startup()` iterates `created_peers` and aborts only the matching `PeerSessionTask` entries by `session_id`. Existing sessions from prior startups are untouched.

**Generation wiring (Phase 18)**: When a peer session is created during startup, `next_session_generation()` is called on the stage before spawning the session task. The same generation value is used for both the `PeerSessionTask.generation` field and the `StagedPeerResource.session_generation` field, ensuring the session reaper and rollback share the same generation for consistency.

**One global session-generation domain (Iteration 74, Phase 25)**: All sessions — both outbound (startup-created) and inbound (accept-loop) — now use a single `session_generation: Arc<AtomicU64>` counter on `MeshTransport`. This replaces the previous split where outbound sessions used the stage counter and inbound sessions used a separate zero-based counter. The unified domain ensures generation values are globally unique across all session origins and prevents any ambiguity in the session reaper's generation matching.

**Steady-state behavior**: New connections add entries to the map; disconnections remove them. The map is protected by `tokio::sync::Mutex`.

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
| `accept_loop_report` | Accept loop report | `Option<MeshAcceptLoopReport>` — `None` when stale or no prior startup (Iteration 74); `Some` when from current generation |
| `peers_at_shutdown_start` | Captured at shutdown begin | Peer count before teardown |
| `remaining_peers` | Measured after connection close/drain | Peers still active after drain |
| `drained_peer_sessions` | Session drain result | Number of peer sessions drained cleanly |
| `aborted_peer_sessions` | Session drain result | Number of peer sessions aborted |
| `failed_peer_sessions` | Session drain result | Number of peer sessions that failed (panic/error, Iteration 73) |

### MeshAcceptLoopReport (Iteration 72 — Generation Tracking)

The `MeshAcceptLoopReport` struct (`lifecycle.rs:325`) is wired into the mesh accept loop. When the accept loop shuts down, it tracks `drained_handshakes` (cooperatively exited children) and `aborted_handshakes` (forcibly aborted after timeout). The report is stored in `MeshTransport::accept_loop_report` and read by `shutdown_with_timeout()` to populate `MeshShutdownReport.accept_loop_report: Option<MeshAcceptLoopReport>`. Stale reports (generation mismatch) are `None` (Iteration 74).

| Field | Meaning |
|-------|---------|
| `drained_handshakes` | Number of handshake children that exited cleanly |
| `aborted_handshakes` | Number of handshake children that were forcibly aborted |
| `rejected_at_capacity` | Always zero (untracked) |
| `generation: u64` | Distinguishes reports across startup cycles; reset at each `start_with_policy()` |

The `generation` field (Iteration 72) ensures that a stale report from a previous startup cycle is not misattributed to the current cycle. Each call to `start_with_policy()` increments the generation counter, and the accept loop tags its report with the current generation.

### Accept-Loop Generation Verification (Phases 19, Iteration 74)

`MeshTransport` carries a `startup_generation: Arc<AtomicU64>` field (initialized to 0). Each call to `start_with_policy()` increments it via `fetch_add(1, SeqCst) + 1` before any startup phases run. The new generation is also written into the accept-loop report (`report.generation = gen`), resetting its handshake counters.

At shutdown, `shutdown_with_timeout()` loads the current generation and compares it against the accept-loop report's generation. **Iteration 74 (Phase 29–30)**: stale reports are now **suppressed** — when the generation does not match (or no startup has occurred), `accept_loop_report` in `MeshShutdownReport` is set to `None` instead of reporting potentially stale counts. The `MeshShutdownReport` type now carries `accept_loop_report: Option<MeshAcceptLoopReport>` (was separate `drained_peer_children` / `aborted_peer_children` fields).

```rust
// transport.rs:3958-3986
let accept_report = self.accept_loop_report.lock().await.clone();
let current_gen = self.startup_generation.load(Ordering::SeqCst);
let report_is_fresh = if current_gen == 0 {
    false  // No startup yet; report not meaningful
} else if accept_report.generation == current_gen {
    true
} else {
    tracing::warn!(
        "Accept-loop report generation mismatch: report={}, current={}; counts suppressed",
        accept_report.generation,
        current_gen
    );
    false
};
report.accept_loop_report = if report_is_fresh {
    Some(accept_report.clone())
} else {
    None
};
```

A mismatch or `current_gen == 0` indicates the accept-loop report is from a prior startup cycle or no startup has occurred. The `None` value prevents misattributing stale handshake counts to the current shutdown.

### Invariants

- `remaining_peers` is measured **after** connections are closed and sessions are drained, not before.
- `peers_at_shutdown_start` is captured at the beginning of shutdown for comparison.
- Handshake child counts propagate into the report from the accept loop's `JoinSet`.
- The report is truthful — it reflects what actually happened, not what was requested.
- `accept_loop_report` in `MeshShutdownReport` is `None` when the report is stale (generation mismatch) or no startup has occurred (Iteration 74). This prevents misattributing prior-cycle accept-loop data to the current shutdown.

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

## Hard Rejection of Non-Empty Task Group Replacement (Iteration 73)

`commit_startup()` now **hard-rejects** replacement when the old task group is non-empty:

```rust
let old_task_group = {
    let mut tg = self.task_group.lock().await;
    let (c, b, ch) = tg.active_count();
    if c + b + ch > 0 {
        return Err(MeshTransportError::LifecycleConflict(format!(
            "cannot commit startup over non-empty task group: {c} critical, {b} background, {ch} children"
        )));
    }
    std::mem::replace(&mut *tg, std::mem::take(&mut stage.task_group))
};
```

This is a hard error, not a warning — replacing a non-empty task group would orphan running tasks. The guard runs **before** `std::mem::replace`.

## Pre-Mutation Topology and DHT Snapshots (Iterations 73, 74)

The outbound `connect_to_peer` path now captures state **before** mutation:

1. **Topology snapshot**: `self.topology.get_peer(&node_id).await` is called **before** `self.topology.add_peer(...)`. Stores the native `PeerState` directly (Iteration 74 — no lossy `MeshPeerInfo` conversion).
2. **DHT snapshot**: `rm.snapshot_peer(&peer_node_id).await` is called **before** `self.dht_on_peer_connected(...)`. Stores all `PeerContact` fields (Iteration 74 — geo, latency, trust, PoW nonce, public key).

These snapshots feed into `StagedPeerResource` for rollback:
- `previous_topology: Option<StagedTopologySnapshot>` — restored on rollback via `restore_peer_state()` (native type)
- `dht_mutation: DhtPeerMutation` — derived from pre-mutation snapshot comparison (not from `rm.is_enabled()` alone)

### DhtPeerSnapshot (Iteration 74 expanded, Iteration 75 — complete PeerContact)

`DhtPeerSnapshot` stores a clone of the native `PeerContact` (Iteration 75), replacing the previous individual-field representation. This eliminates field drift — any future `PeerContact` additions are automatically captured in snapshots without requiring `DhtPeerSnapshot` schema updates.

| Field | Meaning |
|-------|---------|
| `contact: PeerContact` | Complete native `PeerContact` clone for exact lossless restoration |

The `peer_matches_snapshot()` method on `DhtRoutingManager` verifies that the current routing entry matches a snapshot, used by rollback/recovery verification to prove exact logical restoration (Phase 11).

### DhtPeerMutation (Iteration 74 simplified)

`DhtPeerMutation` is an enum tracking what DHT state was created or modified:

| Variant | Meaning |
|---------|---------|
| `None` | No DHT mutation (routing disabled or no snapshot) |
| `Created` | New DHT peer entry created (no prior snapshot) |
| `Previous(DhtPeerSnapshot)` | Prior DHT state existed and was replaced or updated in place; snapshot captures the complete prior state for lossless restoration (Iteration 74) |

The mutation is derived from the pre-mutation snapshot comparison, **not** from `rm.is_enabled()` directly. This ensures rollback can accurately restore the prior DHT state.

Iteration 74 collapsed the previous `Replaced` and `UpdatedInPlace` variants into a single `Previous` variant — both cases carry the same prior-state snapshot for restoration. The `restore_peer()` method on `DhtRoutingManager` re-inserts the contact with all fields from the snapshot, refreshing `last_seen` to `Instant::now()` since the peer was recently connected.

## Retained Failed-Startup Residue (Iterations 73, 74)

When rollback is incomplete, `rollback_and_return()` now stores a `FailedStartupResidue` on the transport:

```rust
pub struct FailedStartupResidue {
    pub peers: Vec<StagedPeerResource>,
    pub generation: u64,
    pub runtime_started: bool,
    pub rollback_errors: Vec<String>,
}
```

This residue is consumed by `recover_failed_state()` during recovery. **Iteration 74**: recovery now applies the residue **before** clearing it — `restore_peer_logical_state()` is called for each peer in the residue to restore topology and DHT entries. Successfully restored peers have their connections closed and removed. Partially restored peers are retained in the residue for a subsequent attempt. The residue is cleared only when all peers are restored or all restoration attempts are exhausted.

## Full Recovery Ownership Guarantees (Iterations 73, 74, 75)

`recover_failed_state(timeout)` now performs residue application before comprehensive verification:

| Phase | Description |
|-------|-------------|
| Phase 7 | Apply retained `FailedStartupResidue` via `restore_and_verify_peer_logical_state()` (Iteration 75) — restore topology and DHT entries for each peer, close and remove connections, verify restoration. Partially restored peers retain residue. |
| Phase 8 | Clear auxiliary tasks (abort and await all) |
| Phase 9 | Clear accept-loop report counts |
| Phase 10a | Task group `active_count()` must be `(0, 0, 0)` |
| Phase 10b | `peer_sessions` must be empty |
| Phase 10c | `peer_connections` must be empty |
| Phase 10d | `auxiliary_tasks` must be empty |
| Phase 10e | `failed_startup_residue` must be `None` |

Recovery outcomes are tracked via `RecoveryReport` (Iteration 74, Phase 35):

```rust
pub struct RecoveryReport {
    pub tasks_joined: usize,
    pub sessions_joined: usize,
    pub auxiliary_joined: usize,
    pub topology_restored: usize,
    pub dht_restored: usize,
    pub errors: Vec<String>,
}
```

If any check fails, the issues are collected and the transport transitions back to `Failed` with a detailed error message.

## Cooperative Deadline vs. Forced Abort-and-Await (Iteration 73)

All abort paths now follow the **abort-and-await** pattern:

```rust
handle.abort();
let _ = handle.await;
```

This ensures the task's resources are fully released before proceeding. The pattern applies to:
- Peer session drain (shutdown + recovery)
- Auxiliary task cleanup (shutdown + recovery)
- Handshake child drain (accept loop)

The `remaining(deadline)` helper computes the remaining budget. If the budget is exhausted before cooperative completion, tasks are forcibly aborted and immediately awaited.

## Owned Auxiliary/Preflight Tasks (Iteration 73)

Preflight tasks (`preflight_peer_routes`) now have explicit ownership:

| Phase | Ownership | Registry |
|-------|-----------|----------|
| **Startup** | Bounded child in staged task group | `stage.task_group.spawn_child(...)` |
| **Steady-state** | Transport-owned auxiliary task | `auxiliary_tasks: HashMap<MeshTaskId, AuxiliaryTask>` |

During startup, preflight runs as a bounded child — it participates in rollback cancellation. During steady-state, it runs detached but is tracked in the `auxiliary_tasks` registry. On shutdown, all auxiliary tasks are aborted and awaited.

### Session Binding and Rollback Cancellation (Phase 14)

Auxiliary tasks are bound to peer sessions via the `session_id` field on `AuxiliaryTask`. During rollback, `rollback_startup()` collects the `session_id` values from staged peers and calls `cancel_auxiliary_tasks_for_sessions(&session_ids)`:

```rust
// Phase 6b: Cancel auxiliary tasks associated with staged sessions (Phase 14)
let session_ids: Vec<String> = stage
    .created_peers
    .iter()
    .filter_map(|p| p.session_task_id.as_ref().cloned())
    .collect();
self.cancel_auxiliary_tasks_for_sessions(&session_ids).await;
```

`cancel_auxiliary_tasks_for_sessions()` filters `auxiliary_tasks` by matching `task.session_id` against the staged session IDs, then aborts and awaits each matching task. This ensures preflight queries do not outlive the peer sessions they were spawned for.

```rust
pub struct AuxiliaryTask {
    pub task_id: MeshTaskId,
    pub session_id: Option<String>,
    pub kind: AuxiliaryTaskKind,
    pub handle: JoinHandle<MeshTaskExit>,
}

pub enum AuxiliaryTaskKind {
    PreflightRoute,
}
```

## Peer-Session Completion Reaping and Exit Classification (Iteration 73)

Peer sessions now report structured exit metadata:

```rust
pub struct PeerSessionExit {
    pub session_id: String,
    pub node_id: String,
    pub reason: PeerSessionExitReason,
    pub generation: u64,
}

pub enum PeerSessionExitReason {
    Clean,
    ConnectionClosed,
    Cancelled,
    Error(String),
    Panic(String),
    Aborted,
}
```

The `generation` counter prevents stale completions from removing newer entries. Shutdown uses `PeerSessionExitReason` to classify session outcomes into `drained_peer_sessions`, `aborted_peer_sessions`, and `failed_peer_sessions` in `MeshShutdownReport`.

### Session Reaper (Phases 15–18, Iteration 74 hardening)

The session reaper is a critical background task spawned after lifecycle commit. It watches for `PeerSessionExit` events via the `session_exit_tx` channel and removes entries from the `peer_sessions` registry:

- **Channel**: `session_exit_tx: broadcast::Sender<PeerSessionExit>` on `MeshTransport`, cloned into each session task's `tokio::spawn` closure
- **Subscription**: reaper subscribes via `self.session_exit_tx.subscribe()` during `spawn_session_reaper()` (called from `commit_startup()`)
- **Generation check**: removes entry only when `task.generation == exit.generation` (or exit generation is 0 for legacy/startup paths)
- **Stale skip**: when generation mismatches, the reaper logs a debug message and leaves the entry untouched
- **Exit on channel close**: reaper exits cleanly when the broadcast channel closes (transport dropped)
- **Cancellation-aware** (Iteration 74, Phase 14): uses `tokio::select!` on both the exit receiver and a `session_reaper_shutdown: watch::Sender<bool>` signal, ensuring the reaper exits cleanly during shutdown
- **Handle awaiting outside lock** (Iteration 74, Phase 15): after removing an entry from the registry, the `JoinHandle` is awaited **outside** the `peer_sessions` lock to avoid holding it during join
- **Broadcast lag recovery** (Iteration 74, Phase 17): when `RecvError::Lagged` is received, the reaper scans `peer_sessions` for `is_finished()` handles and removes/joins them outside the lock

```rust
// transport.rs:2675-2749
async fn spawn_session_reaper(&self) {
    let mut exit_rx = self.session_exit_tx.subscribe();
    let mut shutdown_rx = self.session_reaper_shutdown.subscribe();
    group.spawn_critical("session_reaper", async move {
        loop {
            tokio::select! {
                event = exit_rx.recv() => {
                    match event {
                        Ok(exit) => {
                            let removed = {
                                let mut sessions = transport.peer_sessions.lock().await;
                                match sessions.get(&exit.session_id) {
                                    Some(task) if task.generation == exit.generation => {
                                        sessions.remove(&exit.session_id)
                                    }
                                    Some(task) => { /* stale skip */ None }
                                    None => None,
                                }
                            };
                            // Await outside lock (Iteration 74, Phase 15)
                            if let Some(task) = removed {
                                let _ = task.handle.await;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            transport.reap_finished_peer_sessions().await;
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { break; }
                }
            }
        }
    });
}
```

### Auxiliary Task Reaper (Iteration 74, Phase 20–21)

A new `spawn_auxiliary_reaper()` runs as a critical background task after lifecycle commit, mirroring the session reaper's design:

- **Channel**: `auxiliary_exit_tx: broadcast::Sender<AuxiliaryTaskExit>` on `MeshTransport`, used by auxiliary tasks to signal completion
- **Subscription**: reaper subscribes via `self.auxiliary_exit_tx.subscribe()`
- **Removal**: on receiving an `AuxiliaryTaskExit`, removes the entry from `auxiliary_tasks` and awaits the handle **outside** the lock
- **Cancellation-aware**: uses `tokio::select!` with the same `session_reaper_shutdown` signal for clean shutdown exit
- **Broadcast lag recovery**: on `RecvError::Lagged`, scans for `is_finished()` handles and joins them outside the lock

```rust
// transport.rs:2801-2859
async fn spawn_auxiliary_reaper(&self) {
    let mut exit_rx = self.auxiliary_exit_tx.subscribe();
    let mut shutdown_rx = self.session_reaper_shutdown.subscribe();
    group.spawn_critical("auxiliary_reaper", async move {
        loop {
            tokio::select! {
                event = exit_rx.recv() => {
                    match event {
                        Ok(exit) => {
                            let removed = {
                                let mut aux = transport.auxiliary_tasks.lock().await;
                                aux.remove(&exit.task_id)
                            };
                            if let Some(task) = removed {
                                let _ = task.handle.await;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            transport.reap_finished_auxiliary_tasks().await;
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { break; }
                }
            }
        }
    });
}
```

The `AuxiliaryTaskExit` type is a new exit event published by auxiliary tasks on completion:

```rust
pub struct AuxiliaryTaskExit {
    pub task_id: MeshTaskId,
    pub session_id: Option<String>,
    pub reason: MeshTaskExitReason,
}
```

### MeshShutdownReport Extension

`MeshShutdownReport` now includes `failed_peer_sessions: usize` — sessions that exited with a panic or unexpected error (distinct from `aborted_peer_sessions` which are deadline-forced).

## Worker Mesh Supervision Remains Deferred (Iteration 73)

Worker mesh supervision consumption remains **explicitly deferred** (Outcome B from Iteration 70). The `MeshServiceExit` variant exists in `WorkerShutdownCause` but is **not wired** in the production worker supervision loop. `ManagedMeshService` trait and `MeshFailureCause` types are staged infrastructure for future integration.

## DHT Force-Replacement Restoration (Iteration 75)

`DhtRoutingManager::restore_peer()` now uses `RoutingTable::force_restore_contact()` which unconditionally replaces existing contacts. Previous behavior could silently fail when the target bucket was full — the restored contact was simply dropped. Force-replacement ensures DHT state is always restored exactly during rollback and recovery, regardless of routing table capacity.

**Before (Iteration 74)**: `restore_peer()` called `RoutingTable::insert_contact()` which respected bucket capacity limits. A full bucket caused the restoration to fail silently.

**After (Iteration 75)**: `restore_peer()` calls `RoutingTable::force_restore_contact()` which bypasses capacity checks and replaces the existing entry. The restored contact has all fields from the snapshot, with `last_seen` refreshed to `Instant::now()` since the peer was recently connected.

## Topology Secondary-Index Restoration (Iteration 75)

`restore_peer_state()` now bidirectionally updates the `global_nodes` secondary index:

- When restoring a global node: inserts into `global_nodes`
- When restoring a non-global node: removes from `global_nodes`

`remove_peer()` also clears `global_nodes` to prevent stale entries from accumulating in the secondary index after rollback removes topology entries.

## Teardown-Before-Restoration Ordering (Iteration 75)

`rollback_startup()` now stops all peer sessions and auxiliary tasks **before** performing logical restoration (topology/DHT). This ordering prevents late writes from peer sessions or auxiliary tasks from invalidating restored state:

```
Previous order:  restore topology → stop sessions → stop auxiliary tasks
Iteration 75:    stop sessions → stop auxiliary tasks → restore topology
```

## Combined Restore-and-Verify (Iteration 75)

`restore_and_verify_peer_logical_state()` combines restoration and verification in a single call, ensuring atomicity. Previously, restoration and verification were separate steps which could observe intermediate states. The combined method:

1. Restores topology via `restore_peer_state()` (bidirectional `global_nodes` update)
2. Restores DHT via `restore_peer()` (force-replacement)
3. Verifies restoration via `peer_matches_snapshot()`

Used by both `rollback_startup()` and `recover_failed_state()`.

## Residue Retention Through Verification Failure (Iteration 75)

Failed peers are retained in `FailedStartupResidue` for retry. `rollback_and_return()` stores only **unresolved** peers (not all staged peers) in the residue. This ensures:

- Successfully restored peers do not pollute the residue
- Only peers that actually need retry are retained
- `recover_failed_state()` can focus cleanup effort on the remaining unresolved peers

## Session-Local Stream Handler Ownership (Iteration 75)

`peer_message_loop()` now uses a `JoinSet` for per-stream handlers:

- Each incoming stream from a peer is handled by a dedicated task in the `JoinSet`
- Handlers are reaped during the session (not leaked on session close)
- Concurrency is limited by `max_concurrent_peer_streams` config (default 32)
- Each handler is timeout-wrapped via `peer_message_timeout_secs` (default 30s)
- The `JoinSet` is drained before session exit

### PeerStreamDrainReport (Iteration 75)

New type tracking stream drain statistics when a peer session exits:

```rust
pub struct PeerStreamDrainReport {
    pub drained_streams: usize,
    pub aborted_streams: usize,
    pub timed_out_streams: usize,
}
```

## Worker Mesh Supervision Remains Deferred (Iteration 75)

Worker mesh supervision consumption remains **explicitly deferred** (Outcome B from Iteration 70). The `MeshServiceExit` variant exists in `WorkerShutdownCause` but is **not wired** in the production worker supervision loop. `ManagedMeshService` trait and `MeshFailureCause` types are staged infrastructure for future integration.

## Restoration Accuracy Guarantees (Iteration 75)

The DHT and topology restoration paths now have well-defined accuracy guarantees:

| Layer | Accuracy | Method |
|-------|----------|--------|
| **DHT** | Exact (complete `PeerContact` stored) | `restore_peer()` uses `force_restore_contact()` with all fields from `DhtPeerSnapshot.contact` |
| **Topology (primary fields)** | Exact | `restore_peer_state()` restores native `PeerState` — node_id, address, port, role, status |
| **Topology (secondary metrics)** | Intentionally excluded | `PeerScore`, connection failure counts, latency stats are not captured in snapshots; they repopulate naturally through steady-state observation |

Secondary metrics (scores, failures, latency) are intentionally excluded from snapshots because they are ephemeral observations that naturally repopulate through normal peer interaction. Capturing them would add complexity without improving rollback correctness — a restored peer's metrics will converge back to accurate values within minutes of steady-state operation.

## Changelog

| Iteration | Changes |
|-----------|---------|
| 70 | Initial lifecycle state machine, staged startup/rollback, task groups, truthful shutdown report, failure injection hooks, worker integration |
| 71 | Commit ordering: task group install → lifecycle transition → running projection. `rollback_and_return()` centralizes rollback error propagation, constructing `StartupRollbackFailed` when cleanup is incomplete. `StagedPeerResource` tracks exact peer mutations. Rollback uses `session_id` for `peer_connections` removal. Topology entries created during failed startup removed on rollback. `RollbackReport` expanded with `tasks_joined`, `tasks_aborted`, `peer_connections_closed`, `topology_entries_restored`, `peer_sessions_cleaned`, `runtime_stopped`. `verify_rollback_complete()` checks post-rollback invariants. Shared rollback deadline (`startup_rollback_timeout_secs`, default 15s). Peer session cleanup: cooperative drain → abort all → brief wait. `QuicRuntime::stop_server()` provides active endpoint cleanup during rollback. `MeshAcceptLoopReport` wired — accept loop tracks drained/aborted handshake children and publishes report; `MeshShutdownReport.drained_peer_children` and `aborted_peer_children` populated from accept loop report. |
| 72 | **Failed state recovery**: `recover_failed_state(timeout)` acquires lifecycle lock, re-runs cleanup, verifies no owned resources remain, transitions to `Stopped`. `can_start()` now only allows `Stopped` (not `Failed`). **Selective peer-session ownership**: `HashMap<String, PeerSessionTask>` keyed registry replaces global `JoinSet<()>`. Rollback targets only staged sessions. **Topology snapshots**: `StagedTopologySnapshot` captures `MeshPeerInfo` + `PeerStatus` before modification; rollback restores exact prior state for existing peers, removes new peers. **DHT mutation tracking**: `dht_registration_created: bool` on `StagedPeerResource`; rollback removes DHT routing entries via `remove_peer()`. **Owned preflight tasks**: `preflight_peer_routes` runs as bounded child during startup, detached during steady-state. **Accept-loop report generation**: `generation: u64` field distinguishes reports across startup cycles; reset at each `start_with_policy()`. **Authoritative abort accounting**: `tasks_aborted` derived from `MeshTaskExitReason::Aborted` exit metadata, not `active_count()`. **Verification merged before lifecycle selection**: `rollback_and_return()` merges verification issues into `RollbackReport` before `finish_failed_startup()`. **Non-empty task group guard**: `commit_startup()` logs warning when replacing non-empty old task group. |
| 73 | **Hard rejection of non-empty task group replacement**: `commit_startup()` returns `LifecycleConflict` error if old task group is non-empty (checked before `std::mem::replace`). **Pre-mutation snapshots**: `get_peer()` (topology) and `snapshot_peer()` (DHT) captured before `add_peer()` and `dht_on_peer_connected()` in outbound connection path. **DhtPeerMutation enum**: `Created`, `Replaced(snapshot)`, `UpdatedInPlace(snapshot)`, `None` — derived from pre-mutation snapshot comparison, not `rm.is_enabled()` alone. **FailedStartupResidue**: retained on transport when rollback is incomplete; consumed and cleared by `recover_failed_state()`. **Full recovery verification**: `recover_failed_state()` verifies task group empty, peer sessions empty, auxiliary tasks empty, connections empty, residue cleared. **Abort-and-await pattern**: all `.abort()` calls followed by `.await` to reap task resources. **Auxiliary task ownership**: preflight tracked in `auxiliary_tasks: HashMap<MeshTaskId, AuxiliaryTask>` during steady-state; `AuxiliaryTaskKind::PreflightRoute` variant. **Peer-session exit classification**: `PeerSessionExitReason` enum (Clean/ConnectionClosed/Cancelled/Error/Panic/Aborted), `PeerSessionExit` struct with generation counter. **MeshShutdownReport.failed_peer_sessions**: new field for panic/error session exits. **Worker mesh supervision**: remains deferred (Outcome B from Iteration 70). |
| 74 | **Residue application during recovery**: `recover_failed_state()` now applies `FailedStartupResidue` via `restore_peer_logical_state()` before clearing — restores topology and DHT entries for each peer, closes connections. Partially restored peers retain residue for subsequent attempts. **Native topology restoration**: `StagedTopologySnapshot` stores native `PeerState` (not lossy `MeshPeerInfo` + `PeerStatus`); rollback uses `restore_peer_state()` for exact prior state. **Native DHT restoration**: `DhtPeerSnapshot` expanded to capture all `PeerContact` fields (geo, latency, trust, PoW nonce, public key); `restore_peer()` re-inserts contact with all fields; `peer_matches_snapshot()` verification method added. **DhtPeerMutation simplified**: `Replaced` and `UpdatedInPlace` collapsed into single `Previous(DhtPeerSnapshot)` variant. **Session reaper cancellation-awareness**: uses `tokio::select!` with `session_reaper_shutdown` watch signal; handles await outside the lock; broadcast lag recovery scans for finished handles. **Auxiliary task reaper**: `spawn_auxiliary_reaper()` as critical background task; `AuxiliaryTaskExit` type for exit events; same `select!` + lag-recovery pattern. **One global session-generation domain**: `session_generation: Arc<AtomicU64>` on `MeshTransport` used by both outbound and inbound sessions (replaces split stage/zero counters). **Accept-loop report freshness**: `MeshShutdownReport.accept_loop_report` is now `Option<MeshAcceptLoopReport>`; stale reports are `None` instead of potentially misattributed counts. **RecoveryReport**: internal accounting struct for structured recovery outcomes. **Shared `restore_peer_logical_state()`**: used by both `rollback_startup()` and `recover_failed_state()` for deduplication. **Worker mesh supervision**: remains deferred (Outcome B from Iteration 70). |
| 75 | **Force-replacement DHT restoration**: `restore_peer()` uses `force_restore_contact()` which unconditionally replaces existing contacts, eliminating silent failures on full buckets. **Complete PeerContact snapshot**: `DhtPeerSnapshot` stores a clone of the native `PeerContact` instead of individual fields, eliminating field drift. **Topology secondary-index restoration**: `restore_peer_state()` bidirectionally updates `global_nodes` (inserts when global, removes when non-global); `remove_peer()` also clears `global_nodes`. **Teardown-before-restoration ordering**: `rollback_startup()` stops all peer sessions and auxiliary tasks before logical restoration. **Combined restore-and-verify**: `restore_and_verify_peer_logical_state()` combines restoration and verification in one call. **Residue retention**: `rollback_and_return()` stores only unresolved peers in `FailedStartupResidue`. **Session-local stream handlers**: `peer_message_loop()` uses a `JoinSet` for per-stream handlers with capacity limiting, timeout wrapping, and drain-before-exit. **`PeerStreamDrainReport`**: new type tracking stream drain statistics. **Worker mesh supervision**: remains deferred (Outcome B from Iteration 70). |
| 76 | **Forced-cleanup corrective pass**. **Part A — Zero-budget finalization**: `rollback_startup()` and `recover_failed_state()` now always call `MeshTaskGroup::join_all(remaining(deadline))` — never skip on zero budget. The pre-fix call site did `if task_remaining.is_zero() { Vec::new() }`, leaving tasks orphaned in the registry without exit reporting. `join_all(Duration::ZERO)` itself aborts and awaits each task with synthetic `Aborted` exits, so the contract is preserved. **Part B — Cooperative session cancellation**: `PeerSessionTask` gains a `shutdown_tx: watch::Sender<bool>` field. `peer_message_loop` selects on the cooperative signal via `tokio::select! { biased; ... }` so the cancel branch wins the race against incoming events. The shared `stop_peer_session_task()` helper classifies cleanup as `PeerSessionStopOutcome::{Drained, ForcedParentAbort, Failed}` so callers can distinguish cooperative drain from forced parent abort. `stop_staged_peer_activity()` always sends the cooperative signal before delegating to the helper. **Part C — Safe DHT force restoration**: `KBucket::force_replace` returns `Result<Option<PeerContact>, ForceRestoreError>` instead of `Option<PeerContact>`. A full bucket with an absent target now fails closed with `BucketFullTargetAbsent` rather than silently evicting an unrelated contact. `RoutingTable::force_restore_contact` returns `Result<PeerContact, ForceRestoreContactError>` and propagates the bucket-level error. **Part D — DHT snapshot boundary**: `DhtPeerSnapshot` is documented as a *logical* snapshot; `last_seen` is intentionally refreshed to `now()` during restore and must not be relied on for byte-for-byte restoration. **Part E — Refined stream timeout**: per-message read timeout (`peer_message_timeout_secs`) is now distinct from the optional total stream lifetime timeout (`peer_stream_total_timeout_secs`, default 0 = disabled). The split prevents long-lived proxy streams from being killed by the short framing timeout. `apply_read_timeouts` helper wraps each per-message read with `tokio::time::timeout`. **Guardrails**: `tests/mesh_forced_cleanup.rs` (8 integration tests), `tests/mesh_task_ownership_guard.rs` (9 new `iter76_*` assertions), `tests/mesh_startup_rollback.rs` (8 new behavioral assertions), `tests/mesh_lifecycle_tests.rs` (1 cooperative-cancellation test). **Worker mesh supervision**: remains deferred (Outcome B from Iteration 70). |
| 77 | **Nested-cleanup corrective pass**. **Part A — Deadline-aware stream drain**: `drain_peer_stream_handlers()` uses `tokio::time::timeout(left, handlers.join_next()).await` so no cooperative wait exceeds the supplied timeout. **Part B — Remove `apply_read_timeouts`**: The wrapper was misleadingly a total handler lifetime timeout; per-message reads now use `read_exact_with_timeout()` / `read_to_end_with_timeout()` directly at I/O sites. **Part C — Forced abort classification**: `stop_peer_session_task()` zero-budget branch returns `ForcedParentAbort` (was `Failed`). New `force_abort_peer_session()` helper wraps cooperative abort + await. **Part D — Rollback error accounting**: `ForcedParentAbort` and `Failed` outcomes recorded as incomplete cleanup errors, preventing false clean transitions. **Part E — Datagram handler ownership**: `start_datagram_handler()` owns handlers in a bounded `JoinSet` (`max_concurrent_datagram_handlers`, default 32) instead of bare `tokio::spawn()`. New config: `peer_stream_drain_timeout_secs` (default 5), `max_concurrent_datagram_handlers` (default 32). |
