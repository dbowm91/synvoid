# Phase 5 Plan: Blocklist Convergence, Replay, and Ordering Hardening

Status: detailed handoff plan.

Roadmap position: Phase 5 of `plans/roadmap.md`.

Primary goal: strengthen blocklist/event convergence across peer disconnects and process restarts without converting operational blocklists into a Raft/consensus subsystem.

## Architectural Context

SynVoid's operational blocklist model is intentionally eventual-consistency based. Admin/control-plane operations mutate local `BlockStore`, emit `BlocklistEvent` updates, gossip to mesh peers, and replicate to local workers through IPC. Request/WAF paths remain local-only and read local enforcement state.

The current architecture already includes:

- block/unblock event gossip,
- event IDs for idempotency,
- bounded FIFO dedupe,
- per-target LWW stale suppression,
- persisted target-state/tombstones,
- provenance-preserving event application,
- offline-peer catchup from bounded in-memory event logs,
- paged snapshot fallback for history gaps,
- stable snapshot pagination,
- local-only request-path enforcement.

Remaining hardening targets:

- event logs are in-memory only,
- per-peer catchup cursors are not durable,
- ordering still depends heavily on timestamps and is sensitive to clock skew,
- snapshot fallback handles gaps but is heavier than replay for routine restarts,
- acknowledged delivery is still absent for critical removes.

This phase improves durability and ordering while preserving the non-Raft operational model.

## Non-Goals

Do not make operational blocklist updates Raft-backed.

Do not add request-path remote checks.

Do not enforce mesh-ID blocks on external HTTP request paths.

Do not require globally linearizable snapshots.

Do not remove existing snapshot fallback.

## Deliverables

1. Persisted per-peer blocklist catchup cursors.
2. Optional compact durable event-log window for recent blocklist events, if feasible in this phase.
3. Source-scoped monotonic sequence or hybrid logical clock metadata for better ordering under skew.
4. Updated `BlocklistEvent` apply semantics preserving backward compatibility.
5. Tests for restart-safe cursor hydration, stale replay suppression, snapshot fallback interaction, and clock-skew-resistant ordering.
6. Updated architecture docs for blocklist convergence, limitations, and remaining non-guarantees.

## Step 1: Inventory Current Blocklist Event Types and Paths

Inspect these files before editing:

```bash
rg "BlocklistEvent|BlocklistEventLog|BlocklistCatchup|BlocklistSnapshot|TargetStateCache|SeenEventCache|apply_blocklist_event|export_blocklist_snapshot|apply_blocklist_snapshot" crates/synvoid-block-store crates/synvoid-mesh crates/synvoid-ipc src/supervisor src/admin tests architecture
```

Expected areas:

- `crates/synvoid-block-store/src/lib.rs`: event log, block store apply/export/snapshot logic.
- `crates/synvoid-mesh/src/mesh/transport_peer.rs`: catchup/snapshot message handling.
- `crates/synvoid-mesh/src/mesh/transport_connection.rs`: peer connect catchup hook.
- `crates/synvoid-ipc/src/manager.rs`: supervisor/worker IPC event replay.
- `src/admin/handlers/mesh_admin.rs`: catchup diagnostics.
- `architecture/blocklist_reconciliation.md`.
- `architecture/blocklist_remove_consistency.md`.

Do not begin implementation until the current type names and file locations are confirmed.

## Step 2: Add Per-Peer Cursor Types

Add cursor persistence types to `synvoid-block-store` or `synvoid-mesh` depending on existing ownership. Prefer `synvoid-block-store` if the cursor is part of local blocklist convergence state; prefer `synvoid-mesh` if it is strictly transport-peer state. A good compromise is storage primitives in block-store and transport-specific application in mesh.

Suggested type:

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlocklistPeerCursorRecord {
    pub peer_id: String,
    pub source_node: String,
    pub last_sequence: Option<u64>,
    pub last_timestamp: u64,
    pub last_event_id: Option<String>,
    pub updated_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct BlocklistPeerCursorStoreSnapshot {
    pub version: u32,
    pub records: Vec<BlocklistPeerCursorRecord>,
}
```

Clarify terminology:

- `peer_id`: local identity for the remote peer connection, if stable.
- `source_node`: event source node whose sequence this cursor tracks.
- `last_sequence`: last applied source-local sequence from that peer/source.
- `last_timestamp`: wall-clock timestamp for diagnostics and fallback.
- `last_event_id`: optional tie-back for debugging and duplicate repair.

If the existing sequence is producer-local but not stable across restart, document that cursor is best-effort and must fall back to snapshot when the remote event log cannot satisfy it.

## Step 3: Persist Cursor Store

Add persistence to the same data directory used for blocklist target-state persistence.

Suggested file:

```text
blocklist_peer_cursors.json
```

Persistence rules:

- Hydrate on `BlockStore::new()` or mesh convergence manager startup.
- Filter expired records on load.
- Persist on orderly shutdown.
- Persist opportunistically after cursor updates, but avoid per-event synchronous writes on hot paths.
- If there is already a background persistence task for target state, piggyback cursor persistence there.

Write strategy:

- Keep in-memory cursor map as authoritative during runtime.
- Mark dirty on update.
- Flush on interval or shutdown.
- Use atomic write pattern: write temp file, fsync if existing persistence code does this, rename.

Suggested API:

```rust
impl BlockStore {
    pub fn get_blocklist_peer_cursor(&self, peer_id: &str, source_node: &str) -> Option<BlocklistPeerCursorRecord>;

    pub fn update_blocklist_peer_cursor(&self, record: BlocklistPeerCursorRecord) -> Result<(), BlockStoreError>;

    pub fn persist_blocklist_peer_cursors(&self) -> Result<(), BlockStoreError>;

    pub fn hydrate_blocklist_peer_cursors(&self) -> Result<(), BlockStoreError>;
}
```

If `BlockStore` internals are already large, add a dedicated submodule:

```text
crates/synvoid-block-store/src/blocklist_cursors.rs
```

and re-export through `lib.rs`.

## Step 4: Use Cursors in Mesh Catchup

On peer connect/reconnect, current catchup behavior may request from oldest retained event. Update it to:

1. Look up persisted cursor for that peer/source.
2. If present, send `BlocklistCatchupRequest` with `since_sequence = Some(last_sequence)`.
3. If absent, send `since_sequence = None` to request oldest retained events.
4. On catchup response apply success, update cursor to latest applied sequence/timestamp/event ID.
5. If response says `snapshot_required = true`, request paged snapshot and update cursor only after snapshot completion or keep a separate snapshot watermark.

Important: do not skip sequence 0. The existing architecture notes that `None` means from oldest retained and `Some(n)` means events with sequence `> n`.

Failure behavior:

- If cursor points before retained history and remote returns `snapshot_required`, use snapshot fallback.
- If snapshot fails, leave old cursor unchanged and log/metric failure.
- If some events apply and then later event fails, update cursor only through last successfully applied event.
- If event is duplicate, cursor can advance if the event sequence is newer and target application result is idempotent.
- If event is stale due to local newer target state, cursor can advance because the event was observed and intentionally ignored.

## Step 5: Optional Durable Recent Event Log

If this phase has capacity, persist a compact recent event log window.

Do not make it unbounded.

Suggested config:

```toml
[mesh.blocklist_event_log]
persist_recent = false
max_persisted_events = 10000
persist_interval_secs = 30
```

Default can remain disabled in the first pass if write amplification is a concern. If enabled, persist only compact event data needed for replay/catchup, not redundant full snapshots.

Rules:

- Bounded FIFO retention.
- Dedup by event ID.
- Persist asynchronously or on interval.
- Hydrate on startup before serving catchup requests.
- If persistence file is corrupt, log warning and start with empty event log; do not block startup unless configured fail-closed.

This is optional because persisted per-peer cursors plus snapshot fallback already improves routine behavior. Durable event log is a further optimization.

## Step 6: Add Source-Scoped Ordering Metadata

Current LWW ordering uses version when present, then timestamp. Add stronger source-scoped ordering without breaking old events.

Suggested additions to event data:

```rust
pub struct BlocklistEventOrdering {
    pub source_node: String,
    pub source_sequence: Option<u64>,
    pub hybrid_logical_time: Option<u64>,
    pub wall_time: u64,
}
```

If changing wire types directly is difficult, add optional fields to existing event data:

- `source_sequence: Option<u64>`
- `hlc: Option<u64>` or `logical_time: Option<u64>`

Ordering comparison proposal:

1. If both events have explicit `version`, higher version wins.
2. Else if both events are from same `source_node` and both have `source_sequence`, higher sequence wins.
3. Else if both have HLC/logical time, higher HLC wins.
4. Else use timestamp as backward-compatible fallback.
5. If equal, use deterministic tie-breaker: `(source_node, event_id)` lexicographic or a documented stable order.
6. Equal timestamp with no deterministic tie-break should remain stale/no-op as current behavior does.

Do not allow older blocks to resurrect newer unblocks.

Do not allow older unblocks to remove newer blocks.

Preserve existing persisted target-state records. Add optional ordering fields to target-state persistence if needed:

```rust
pub source_sequence: Option<u64>,
pub logical_time: Option<u64>,
```

Migration behavior:

- Missing fields from old files deserialize as `None`.
- Existing timestamp ordering remains valid.
- New events populate source sequence where source can maintain a counter.

## Step 7: Source Sequence Generation

Add a local monotonic sequence generator for blocklist events.

Possible owner:

- `BlockStore`: if it emits/applies local events.
- supervisor/admin emission path: if event creation is centralized there.
- mesh transport manager: if sequence is transport-scoped.

Prefer the authority that creates local `BlocklistEvent`s.

Persistence:

- Persist last local source sequence if possible so restarts do not reset to zero for the same node ID.
- If persistence is not available in first pass, include boot ID or node startup epoch in ordering metadata to avoid confusing source sequences across restart.

Suggested file:

```text
blocklist_local_sequence.json
```

Simpler first pass:

```rust
pub struct BlocklistLocalSequence {
    source_node: String,
    boot_id: String,
    next_sequence: AtomicU64,
}
```

Event ID should include enough entropy to remain unique even if source sequence restarts. Existing event ID format may already include timestamp and identifier hash; preserve that.

## Step 8: Tests

Add unit and integration-style tests around these behaviors.

Cursor persistence tests:

- `peer_cursor_persists_and_hydrates`.
- `expired_peer_cursor_is_filtered_on_load`.
- `cursor_updates_after_applied_catchup_event`.
- `cursor_does_not_advance_past_failed_event`.
- `duplicate_event_can_advance_cursor_when_sequence_observed`.
- `stale_event_can_advance_cursor_without_mutating_target`.

Snapshot interaction tests:

- `cursor_gap_triggers_snapshot_fallback`.
- `snapshot_failure_does_not_overwrite_cursor`.
- `snapshot_completion_records_reconciliation_watermark` if implemented.

Ordering tests:

- `same_source_sequence_orders_despite_clock_skew`.
- `higher_version_still_wins_over_sequence`.
- `older_block_does_not_resurrect_after_newer_unblock_with_sequence`.
- `older_unblock_does_not_remove_newer_block_with_sequence`.
- `legacy_timestamp_only_events_remain_supported`.
- `deterministic_tie_breaker_is_stable`.

Durable event log tests, if implemented:

- `persisted_event_log_hydrates_on_startup`.
- `persisted_event_log_respects_capacity`.
- `corrupt_persisted_event_log_falls_back_to_empty_with_warning`.

## Step 9: Metrics and Diagnostics

Add metrics where the code already emits blocklist/catchup metrics or use the root metrics crate if appropriate.

Suggested metrics:

- `blocklist_peer_cursor_loaded_total`
- `blocklist_peer_cursor_persist_failed_total`
- `blocklist_peer_cursor_updated_total`
- `blocklist_catchup_cursor_used_total`
- `blocklist_catchup_snapshot_fallback_total`
- `blocklist_event_ordering_source_sequence_total`
- `blocklist_event_ordering_timestamp_fallback_total`
- `blocklist_event_stale_replay_ignored_total`

Update admin diagnostics endpoint `GET /mesh/blocklist/catchup-stats` or equivalent to include:

- number of persisted peer cursors,
- oldest/newest cursor update time,
- cursor persistence status,
- durable event log status if implemented,
- snapshot fallback counts if available.

Do not expose sensitive identifiers unnecessarily. Mesh IDs may be control-plane identifiers; sanitize or summarize if needed.

## Step 10: Documentation Updates

Update:

- `architecture/blocklist_reconciliation.md`
- `architecture/blocklist_remove_consistency.md`
- `AGENTS.md` if verification commands change
- any skill docs that mention blocklist event log limitations

Documentation must clearly state:

- operational blocklists remain eventually consistent,
- event log persistence is bounded if implemented,
- snapshots are convergence repair, not globally linearizable state,
- request path remains local-only,
- per-peer cursors are convergence metadata, not delivery acknowledgements,
- ordering is stronger than timestamp-only when source sequence/HLC metadata is present,
- legacy timestamp-only events remain supported.

## Verification Commands

Run targeted tests first:

```bash
cargo fmt
cargo test -p synvoid-block-store blocklist
cargo test -p synvoid-mesh --features mesh blocklist
cargo test --test mesh_id_boundary_guard
cargo test --test threat_intel_consumer_actionability_guard --features mesh,dns
cargo check -p synvoid-block-store --features mesh
cargo check -p synvoid-mesh --features mesh
cargo check --no-default-features --features mesh
cargo check --no-default-features --features mesh,dns
cargo check
```

If specific test names differ, use `cargo test ... cursor`, `cargo test ... snapshot`, and `cargo test ... stale` against the relevant crates.

## Acceptance Criteria

This phase is complete when:

- Per-peer blocklist cursor state can persist and hydrate across restart.
- Catchup uses persisted cursors when available and safely falls back to oldest retained or snapshot repair when not.
- Cursor advancement is correct for applied, duplicate, stale, and failed events.
- Ordering semantics are improved with source-scoped sequence or HLC metadata while preserving legacy timestamp-only behavior.
- Older blocks cannot resurrect newer unblocks under the new ordering tests.
- Older unblocks cannot remove newer blocks under the new ordering tests.
- Snapshot fallback remains functional and provenance-preserving.
- Request/WAF path remains local-only and mesh-ID control-plane boundary tests still pass.
- Architecture docs accurately describe guarantees and non-guarantees.

## Handoff Notes for Smaller Models

Do not introduce Raft. The correct model is still eventual convergence plus local enforcement.

Do not put catchup or snapshot checks on the request path.

Be conservative with persistence writes. Avoid synchronous disk writes per blocklist event on hot paths.

Prefer adding optional fields with backward-compatible defaults over replacing existing event formats.

If durable event-log persistence becomes too large, complete persisted peer cursors and source-sequence ordering first; leave durable log as a follow-up.
