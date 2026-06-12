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
5. If `snapshot_required: true`, the requesting peer automatically requests a paged snapshot (Iteration 56)

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
| Paged snapshot fallback for history gaps | ✅ Iteration 56 |
| Snapshot preserves provenance metadata | ✅ Iteration 56 |
| Snapshot respects LWW/stale suppression | ✅ Iteration 56 |
| Request/WAF paths remain local-only | ✅ Invariant |
| Mesh-ID blocks are control-plane only | ✅ Invariant (Iteration 51) |
| Raft remains out of operational blocklist | ✅ Invariant |

## What Is NOT Guaranteed

- No guaranteed delivery while offline (best-effort gossip)
- No permanent event log (in-memory only, restart loses)
- No request-path remote checks
- No mesh-ID enforcement on the request path (control-plane only; Iteration 51)
- No acknowledged delivery for individual events
- Snapshot is not globally linearizable (convergence, not consensus)
- Snapshot is not Raft-backed

**Note (Iteration 52):** Per-target stale suppression (`TargetStateCache`) is now persisted to `blocklist_target_state.json` and survives restarts. Persisted records preserve origin `source_node` and `provenance` metadata (Iteration 53). However, the *event log* (`BlocklistEventLog`) remains in-memory only — catchup gaps can still occur if a peer misses events during an extended offline period. **Iteration 56 adds paged snapshot fallback** to handle gaps beyond event-log retention.

## Retention Window

- Mesh event log: 10,000 events (configurable)
- IPC event log: 1,000 events
- At typical event rates, this covers hours to days of operation
- Events beyond the retention window require snapshot/admin retry

## History Gap Detection

When a peer requests events since a sequence that has been evicted from the log:

1. `BlocklistCatchupResult.history_complete` is `false`
2. `BlocklistCatchupResult.snapshot_required` is `true`
3. The requesting peer automatically sends a `BlocklistSnapshotRequest` (Iteration 56)
4. The responding peer returns paged `BlocklistSnapshotResponse` chunks
5. The requesting peer applies each chunk via `BlockStore::apply_blocklist_snapshot()`

## Snapshot Fallback (Iteration 56)

When event replay cannot cover the full history (gap exceeds retention window), a paged snapshot transfer converges the peer's local BlockStore.

### Snapshot Semantics

- **Control-plane reconciliation payload**: current known local state from the responding peer
- **Not globally linearizable**: each peer's snapshot is a point-in-time view
- **Not Raft-backed**: no consensus involved
- **Not request-path dependent**: mesh control plane only
- **Bounded and pageable**: configurable `max_items` (default 500) with cursor-based pagination
- **Provenance-preserving**: all entries carry `BlockProvenance` metadata
- **Carries target-state/tombstones**: includes `BlocklistTargetStateRecord` entries for LWW ordering

### Wire Messages

Two new mesh message variants (proto fields 181/182):

- `BlocklistSnapshotRequest`: requesting_node, request_id, include_ip_blocks, include_mesh_id_blocks, include_target_state, site_scope (optional), page_token, max_items
- `BlocklistSnapshotResponse`: request_id, source_node, timestamp, ip_blocks, mesh_blocks, target_state_records, next_page_token, has_more, snapshot_complete, truncated_reason, error

### Snapshot Flow

1. Peer reconnects → sends `BlocklistCatchupRequest`
2. Remote returns `BlocklistCatchupResponse` with `snapshot_required: true`
3. Requesting peer sends `BlocklistSnapshotRequest`
4. Remote calls `BlockStore::export_blocklist_snapshot()` → returns paged `BlocklistSnapshotResponse`
5. Requesting peer calls `BlockStore::apply_blocklist_snapshot()` for each page
6. If `has_more: true`, requesting peer sends next page request with `page_token`
7. Convergence complete when `has_more: false` or max page limit reached

### Snapshot Apply Rules

- Validates IP addresses before applying IP entries
- Validates mesh-ID identifiers are non-empty
- Does not apply expired block entries
- Does not apply expired target-state records
- Uses existing per-target LWW semantics when target-state records exist
- Snapshot block entries do not override newer local unblock tombstones
- Snapshot unblock tombstones do not remove newer local blocks
- Provenance is preserved from snapshot entries
- Does not emit mesh gossip (converges local state only)

### Export Rules

- Collects current IP blocks and mesh blocks from shards
- Collects target-state records from `TargetStateCache`
- Filters expired entries
- Sorts by `(target_kind, site_scope, identifier)` for stable pagination
- Respects `site_scope` filter if requested
- Uses numeric page tokens (offset-based pagination)

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
| Snapshot export/apply | `crates/synvoid-block-store/src/lib.rs` |
| Catchup messages | `crates/synvoid-mesh/src/mesh/proto/mesh.proto` (fields 179/180) |
| Snapshot messages | `crates/synvoid-mesh/src/mesh/proto/mesh.proto` (fields 181/182) |
| Catchup/snapshot handler | `crates/synvoid-mesh/src/mesh/transport_peer.rs` |
| Peer connect hook | `crates/synvoid-mesh/src/mesh/transport_connection.rs` |
| IPC event log | `crates/synvoid-ipc/src/manager.rs` |
| Admin diagnostics | `src/admin/handlers/mesh_admin.rs` |
