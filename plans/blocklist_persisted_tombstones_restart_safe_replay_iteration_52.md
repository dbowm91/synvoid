# Blocklist Persisted Tombstones and Restart-Safe Stale Replay Protection — Iteration 52

## Purpose

The blocklist plane now has first-class target-aware events, FIFO dedupe, per-target stale suppression, offline-peer catchup, cursor semantics, provenance preservation, and a formal mesh-ID request-path boundary. The remaining hardening gap is restart safety.

Today, stale replay protection depends on in-memory `TargetStateCache` and event dedupe state. After process restart, a node can lose the knowledge that a newer unblock already superseded an older block event. If an old event is replayed after restart and no retained target state exists, it can incorrectly resurrect stale block state.

This pass should persist bounded per-target tombstones / last-applied event state so stale blocklist replay protection survives process restart.

## Current Known State

Recent iterations established:

- `BlocklistEvent` with event ID, source node, timestamp, target kind, site scope, identifier, operation, provenance, TTL, and optional version.
- `BlockStore::apply_blocklist_event()` with duplicate detection and per-target stale suppression.
- `TargetStateCache` tracks last-applied event metadata per `(target_kind, site_scope, identifier)` in memory.
- `SeenEventCache` tracks recently seen event IDs in memory.
- `BlocklistEventLog` retains recent events in memory for catchup.
- Offline catchup can replay missed events within retention.
- Cursor semantics are unambiguous.
- Docs explicitly state restart loses stale replay protection.

This pass should replace or augment that limitation with persisted tombstones/target state.

## Non-Goals

Do not persist the entire blocklist event log unless needed.

Do not build a full append-only event store.

Do not introduce Raft for operational blocklist state.

Do not add request-path network lookups.

Do not change mesh-ID request-path scope.

Do not redesign block/unblock propagation.

Do not change admin auth/authz.

Do not remove in-memory caches; persistent state should hydrate them or supplement them.

## Phase 1 — Audit Existing Persistence Surfaces

Inspect current BlockStore persistence structure and shutdown/flush behavior.

Likely files:

- `crates/synvoid-block-store/src/lib.rs`
- `crates/synvoid-core/src/block_store.rs`
- architecture docs for BlockStore persistence
- tests around `blocks.json`, `mesh_blocks.json`, migration, shutdown flush

Questions to answer:

- Where are `blocks.json` and `mesh_blocks.json` written?
- Is persistence async/debounced or immediate?
- How does `shutdown().await` flush state?
- Can a third persistence file be added cleanly?
- Are there existing atomic-write helpers?
- Are tests using temp dirs or in-memory stores?

Recommended persistence file:

```text
blocklist_tombstones.json
```

or:

```text
blocklist_target_state.json
```

Prefer `blocklist_tombstones.json` if the state is meant to prevent stale resurrection after unblocks.

Prefer `blocklist_target_state.json` if both last block and last unblock state are persisted.

## Phase 2 — Define Persistent State Model

Use a compact per-target last-applied state record.

Suggested core type:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistTargetStateRecord {
    pub target_kind: BlockTargetKind,
    pub site_scope: String,
    pub identifier: String,
    pub last_operation: BlocklistOperation,
    pub timestamp: u64,
    pub version: Option<u64>,
    pub event_id: Option<String>,
    pub source_node: Option<String>,
    pub provenance: BlockProvenance,
    pub recorded_at: u64,
    pub expires_at: Option<u64>,
}
```

Rationale:

- `last_operation=Unblock` prevents older block replay from resurrecting a target.
- `last_operation=Block` prevents older unblock replay from removing a newer block.
- `timestamp`/`version` preserve existing LWW semantics.
- `provenance` preserves audit context.
- `expires_at` bounds storage lifetime.

## Phase 3 — Retention Policy

Persistent tombstones must be bounded.

Recommended defaults:

- Keep target-state records for at least the maximum blocklist event replay horizon.
- Default TTL: 7 days or configurable.
- Maximum records: 100,000 or configurable.
- Evict expired records on load and periodically on persist.

Config options if existing config surface is available:

```toml
blocklist.target_state_persist = true
blocklist.target_state_max_records = 100000
blocklist.target_state_ttl_secs = 604800
```

If config plumbing is too large, use constants first and document them.

Important:

- Do not let tombstones grow unbounded.
- Expired tombstones must not block legitimate future admin actions indefinitely.
- If a live block entry exists, target state should reflect its last block operation.

## Phase 4 — Hydrate TargetStateCache on Startup

On `BlockStore::new`, after loading IP blocks, mesh-ID blocks, and legacy migration, load persisted target-state/tombstone records.

Process:

1. Read `blocklist_target_state.json` / `blocklist_tombstones.json` if present.
2. Deserialize records with backward-compatible defaults.
3. Drop expired records.
4. Rebuild `TargetStateCache` from records.
5. Optionally persist compacted records if expired entries were removed.
6. Log count loaded / expired / invalid.

Hydration must not mutate request-path behavior except stale replay protection.

## Phase 5 — Persist on Apply

Update `apply_blocklist_event()` so successful or intentional no-op applications persist target-state records.

Current intended no-op example:

- unblock of already-missing target still records target state to prevent older block resurrection.

Required behavior:

- On `Applied`, update in-memory `TargetStateCache` and persistent target-state store.
- On `IgnoredStale`, do not overwrite target state.
- On `InvalidTarget`, do not record anything.
- On `StoreDisabled`, do not record anything.
- On `NoopDuplicate`, do not need to rewrite unless target state is missing and can be safely recovered from event metadata. Prefer no rewrite.

Use existing persistence triggering pattern rather than writing synchronously on every request if possible.

## Phase 6 — Integrate with Existing Block/Unblock APIs

Stale replay protection currently focuses on event application. Manual/admin direct block/unblock APIs also define target state.

Update target-state recording for:

- `block_ip_with_provenance`
- `unblock_ip`
- `block_mesh_id_with_provenance`
- `unblock_mesh_id`
- any direct `add_block` compatibility path if it represents a block event

Decide whether direct APIs should create synthetic target-state records with source `local_api` or rely on their surrounding admin/event path.

Recommended:

- For direct BlockStore mutation APIs, update target-state with a local timestamp if the operation succeeds.
- If the caller later emits a `BlocklistEvent`, ensure timestamp/version ordering does not conflict.
- Avoid double-recording if direct APIs are only called through `apply_blocklist_event()` by adding an internal helper or flag.

Safer implementation shape:

- Keep `apply_blocklist_event()` as the canonical distributed apply path.
- Add an internal `record_target_state_from_event()` helper.
- For direct admin paths, ensure the emitted event is applied/recorded exactly once or explicitly call record helper after successful local mutation.

## Phase 7 — Persistent Dedupe: Decide Scope

Primary problem is stale replay, not duplicate replay.

Do not persist the entire `SeenEventCache` unless needed.

Recommended:

- Persist target-state records only.
- Duplicate event replay after restart may re-run as no-op/stale depending on target state.
- If exact duplicate event has same timestamp/version, target-state stale check should reject it as `IgnoredStale` or no-op.

Document that event-ID dedupe remains in-memory, while target-state stale protection is persisted.

## Phase 8 — Reconciliation / Catchup Interaction

Ensure offline catchup works correctly after restart.

Scenarios:

1. Node restarts after applying unblock tombstone; later receives older block via catchup. Expected: `IgnoredStale`.
2. Node restarts with persisted block target state; later receives older unblock. Expected: `IgnoredStale`.
3. Node restarts with no retained event log. Expected: catchup may be needed, but persisted target-state still prevents older stale replay if replay arrives.
4. Node receives from-start catchup with sequence 0 after restart. Expected: apply ordering respects persisted target state.

## Phase 9 — Mesh-ID and IP Coverage

Persistent target state must cover both target kinds:

- `BlockTargetKind::Ip`
- `BlockTargetKind::MeshId`

Site scope must be part of the target key.

Global fallback behavior for mesh IDs must be tested explicitly if applicable.

## Phase 10 — Tests

Add focused tests with temp dirs and restart simulation.

### Persistence load/save tests

- target-state record serializes/deserializes.
- expired records are ignored on load.
- invalid records do not panic load.
- compaction removes expired records.

### Restart stale replay tests

- apply newer IP unblock, shutdown/reload, replay older IP block -> `IgnoredStale`, IP remains unblocked.
- apply newer mesh-ID unblock, shutdown/reload, replay older mesh-ID block -> `IgnoredStale`, mesh ID remains unblocked.
- apply newer IP block, shutdown/reload, replay older IP unblock -> `IgnoredStale`, IP remains blocked.
- apply newer mesh-ID block, shutdown/reload, replay older mesh-ID unblock -> `IgnoredStale`, mesh ID remains blocked.

### Direct API tests

- admin/direct unblock records persisted target state.
- admin/direct block records persisted target state if applicable.
- missing-target unblock still persists tombstone.

### Retention tests

- expired tombstone no longer suppresses newer legitimate block.
- capacity eviction is deterministic.
- persisted file does not grow unbounded under repeated operations.

### Catchup tests

- replay after restart uses persisted target state.
- from-start catchup does not resurrect stale state.

## Phase 11 — Documentation

Update:

- `architecture/blocklist_remove_consistency.md`
- `architecture/blocklist_reconciliation.md`
- `architecture/block_store.md`
- `architecture/blockstore_admin_observability.md`
- `AGENTS.md`

Docs must state:

- target-state stale replay protection is persisted;
- event-ID dedupe remains in-memory unless changed;
- retention/TTL/capacity semantics;
- restart behavior;
- file name and migration/backward-compat behavior;
- request/WAF path remains local-only;
- mesh-ID request-path scope remains control-plane-only.

## Phase 12 — Verification Commands

Run focused tests:

```bash
cargo test -p synvoid-core blocklist
cargo test -p synvoid-block-store tombstone
cargo test -p synvoid-block-store target_state
cargo test -p synvoid-block-store restart
cargo test -p synvoid-block-store stale
cargo test -p synvoid-block-store catchup
cargo test -p synvoid-mesh blocklist_event
cargo test --test mesh_id_boundary_guard
cargo test --test manual_enforcement_provenance_guard
cargo test --test threat_intel_boundary_guard
cargo test --lib --no-run
```

If persistence format or config changes affect workspace compilation:

```bash
cargo test --workspace --no-run
```

Adjust filters to actual test names.

## Acceptance Criteria

This pass is complete when:

1. A persisted per-target blocklist state/tombstone file exists.
2. `BlockStore::new` hydrates target stale-suppression state from disk.
3. Successful block/unblock event applications update persisted target state.
4. Missing-target unblocks persist tombstones to prevent stale resurrection.
5. Restart tests prove older block events cannot resurrect a target after newer unblock.
6. Restart tests prove older unblock events cannot remove newer block.
7. Both IP and mesh-ID target kinds are covered.
8. Site scope is part of persisted target identity.
9. Retention/TTL/capacity are bounded and documented.
10. Event-ID dedupe vs persisted target-state responsibilities are documented.
11. Request/WAF paths remain unchanged.
12. Existing boundary/provenance/reconciliation guardrails still pass.

## Notes for the Implementer

This is a persistence hardening pass, not a consensus redesign.

The invariant is:

> A node restart must not erase the fact that a newer blocklist operation superseded an older event for the same target.
