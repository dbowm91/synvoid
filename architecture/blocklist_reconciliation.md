# Blocklist Offline-Peer Reconciliation

## Overview

This document describes the offline-peer catchup mechanism for blocklist events, implemented in Iteration 48. It complements `blocklist_remove_consistency.md` (which covers online gossip and local application semantics).

## Problem

When a peer is disconnected during `BlocklistEventGossip` emission, it misses the event and retains stale block state until TTL expiry, manual correction, or restart. Iteration 48 adds bounded reconciliation so peers can converge after missed gossip.

## Architecture

### Event Log

Each node maintains a bounded in-memory `BlocklistEventLog` (default 10,000 events) that records blocklist events after they are accepted for propagation/application.

- **Location**: `BlockStore.event_log` (mesh) and `ProcessManager.blocklist_event_log` (IPC)
- **Capacity**: Configurable, default 10,000 for mesh, 1,000 for IPC
- **Eviction**: FIFO — oldest events evicted one-by-one when at capacity
- **Dedup**: Events with duplicate `event_id` are not inserted twice
- **Persistence**: In-memory only; restart loses retained events

### Cursor / Watermark

Each event log entry is assigned a monotonically increasing local sequence number. Replaying peers specify a cursor:

```rust
struct BlocklistEventCursor {
    since_sequence: Option<u64>,  // None = from oldest retained; Some(n) = events > n
    max_events: u32,              // Maximum events per response
}
```

The cursor is source-local, not globally comparable. Each node's sequence starts at 0 and increments with each appended event. `since_sequence: None` replays from the oldest retained event (not necessarily from genesis). `since_sequence: Some(n)` returns events with sequence `> n` (exclusive cursor).

### Catchup Messages

Two new mesh message variants (proto fields 179/180):

- `BlocklistCatchupRequest`: requesting node, `since_sequence` (optional — `None` means from start), since_timestamp, max_events
- `BlocklistCatchupResponse`: events, history_complete, latest_sequence, latest_timestamp, snapshot_required

### Catchup Flow

1. Peer connects/reconnects → `dht_on_peer_connected()` sends `BlocklistCatchupRequest` with `since_sequence: None` (from start — replay all retained events)
2. Remote node queries its `BlocklistEventLog` via `BlockStore::query_blocklist_catchup()`
3. Remote responds with `BlocklistCatchupResponse` containing matching events
4. Receiver applies each event via `BlockStore::apply_blocklist_event()`
5. If `snapshot_required: true`, the requesting peer should request a full snapshot (admin/manual)

### Supervisor/Worker IPC

The supervisor retains a separate bounded event log (1,000 events) for IPC replay:

- Events are recorded when `broadcast_blocklist_event()` is called
- On worker ready, supervisor replays recent events via `BlocklistEventUpdate` IPC
- Workers apply replayed events through the same `apply_blocklist_event()` pipeline

## Guarantees

| Property | Status |
|----------|--------|
| Online peers receive best-effort gossip | ✅ Existing |
| Reconnecting peers can request recent events | ✅ Iteration 48 |
| Events apply through `apply_blocklist_event()` | ✅ Iteration 48 |
| History gaps detected and surfaced | ✅ Iteration 48 |
| Snapshot fallback documented | ✅ Iteration 48 |
| From-start catchup replays first retained event | ✅ Iteration 49 |
| Exclusive since_sequence cursor remains available | ✅ Iteration 49 |
| Per-target stale suppression survives restarts | ✅ Iteration 52 |
| Request/WAF paths remain local-only | ✅ Invariant |
| Mesh-ID blocks are control-plane only | ✅ Invariant (Iteration 51) |
| Raft remains out of operational blocklist | ✅ Invariant |

## What Is NOT Guaranteed

- No guaranteed delivery while offline (best-effort gossip)
- No permanent event log (in-memory only, restart loses)
- No exact convergence if offline longer than retention window
- No request-path remote checks
- No mesh-ID enforcement on the request path (control-plane only; Iteration 51)
- No acknowledged delivery for individual events

**Note (Iteration 52):** Per-target stale suppression (`TargetStateCache`) is now persisted to `blocklist_target_state.json` and survives restarts. Persisted records preserve origin `source_node` and `provenance` metadata (Iteration 53). However, the *event log* (`BlocklistEventLog`) remains in-memory only — catchup gaps can still occur if a peer misses events during an extended offline period.

## Retention Window

- Mesh event log: 10,000 events (configurable)
- IPC event log: 1,000 events
- At typical event rates, this covers hours to days of operation
- Events beyond the retention window require snapshot/admin retry

## History Gap Detection

When a peer requests events since a sequence that has been evicted from the log:

1. `BlocklistCatchupResult.history_complete` is `false`
2. `BlocklistCatchupResult.snapshot_required` is `true`
3. The requesting peer logs a warning
4. Operator intervention (admin snapshot or manual sync) is needed

## Diagnostics

Admin endpoint: `GET /mesh/blocklist/catchup-stats`

Returns:
- Mesh event log count, oldest/newest timestamps, next sequence
- IPC event log count, oldest/newest timestamps, next sequence

## Implementation Details

### Types

- `BlocklistEventLog`: bounded VecDeque + HashSet in `synvoid-block-store`
- `BlocklistEventCursor`: query cursor with `since_sequence: Option<u64>` + max_events. `None` = from oldest retained; `Some(n)` = exclusive after n.
- `BlocklistCatchupResult`: query result with events, history_complete, snapshot_required
- `BlocklistEventData`: wire-format event data in `synvoid-mesh`

### File Locations

| Component | File |
|-----------|------|
| Event log | `crates/synvoid-block-store/src/lib.rs` |
| Catchup messages | `crates/synvoid-mesh/src/mesh/proto/mesh.proto` (fields 179/180) |
| Catchup handler | `crates/synvoid-mesh/src/mesh/transport_peer.rs` |
| Peer connect hook | `crates/synvoid-mesh/src/mesh/transport_connection.rs` |
| IPC event log | `crates/synvoid-ipc/src/manager.rs` |
| Admin diagnostics | `src/admin/handlers/mesh_admin.rs` |
