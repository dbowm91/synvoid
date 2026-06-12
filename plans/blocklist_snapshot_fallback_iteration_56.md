# Blocklist Snapshot Fallback for Catchup History Gaps — Iteration 56

## Purpose

The blocklist plane now has target-aware events, stale replay suppression, offline catchup within event-log retention, provenance preservation, mesh-ID request-path boundaries, persisted target state, and restart-safe stale replay protection.

The remaining convergence gap is what happens when a peer misses more blocklist history than the bounded event log can replay. The system already detects this with `snapshot_required`, but that signal is not yet actionable.

This pass should add a control-plane-only blocklist snapshot fallback so a reconnecting peer can converge after the event-log retention window has been exceeded.

## Current Known State

Recent iterations established:

- `BlocklistEventLog` stores recent blocklist events in memory.
- `BlocklistCatchupRequest` / `BlocklistCatchupResponse` allow peers to request recent events.
- `BlocklistCatchupResult` includes `history_complete` and `snapshot_required`.
- Cursor semantics are explicit: `None` means from oldest retained event, `Some(n)` means exclusive sequence.
- Target-state records are persisted in `blocklist_target_state.json`.
- IP and mesh-ID block entries preserve provenance.
- Request/WAF path remains local-only.
- Mesh-ID blocks remain control-plane/admin scoped only.
- Raft remains out of operational blocklist propagation.

This pass should connect the `snapshot_required` signal to an actual paged snapshot transfer/apply path.

## Non-Goals

Do not build a linearizable global blocklist.

Do not introduce Raft for operational blocklist state.

Do not add request-path mesh/DHT/Raft lookups.

Do not change WAF request-path semantics.

Do not change mesh-ID request-path scope.

Do not persist the full event log unless needed.

Do not remove event replay/catchup; snapshot is a fallback, not replacement.

Do not require one unbounded message for all blocklist state.

## Phase 1 — Define Snapshot Semantics

Document snapshot semantics before coding.

A blocklist snapshot is:

- a control-plane reconciliation payload;
- current known local state from the responding peer;
- not a globally linearizable truth;
- not Raft-backed;
- not request-path dependent;
- bounded and pageable;
- provenance-preserving;
- capable of carrying target-state/tombstone records.

Snapshot apply should be conservative:

- add/update current IP blocks from snapshot;
- add/update current mesh-ID blocks from snapshot;
- hydrate target-state records/tombstones from snapshot;
- avoid resurrecting stale state over newer local target-state records;
- preserve provenance;
- report conflicts/ignored stale records.

Important: snapshot does not mean “delete every local entry not present in peer snapshot” unless explicitly implementing full-authoritative reconciliation. Prefer additive/merge semantics first.

## Phase 2 — Wire/API Model

Add wire-level snapshot messages.

Suggested protobuf/message types:

```text
BlocklistSnapshotRequest
BlocklistSnapshotResponse
```

Request fields:

- `request_id`
- `site_scope` or optional filter
- `include_ip_blocks: bool`
- `include_mesh_id_blocks: bool`
- `include_target_state: bool`
- `page_token` / `cursor`
- `max_items`
- `requesting_node`

Response fields:

- `request_id`
- `source_node`
- `timestamp`
- `ip_blocks`
- `mesh_blocks`
- `target_state_records`
- `next_page_token`
- `has_more`
- `snapshot_complete`
- `truncated_reason`
- `error`

Existing likely data models to reuse/convert:

- `BlockEntryData` or `BlockEntry`
- `MeshBlockEntryData` or `MeshBlockEntry`
- `BlocklistTargetStateRecord`

Keep field numbers append-only; do not renumber existing protobuf fields.

## Phase 3 — BlockStore Snapshot Export API

Add a BlockStore export API that can produce paged snapshot chunks.

Suggested types:

```rust
pub struct BlocklistSnapshotCursor { ... }
pub struct BlocklistSnapshotChunk { ... }
pub struct BlocklistSnapshotOptions { ... }
```

Required contents:

- IP block records, including site scope and provenance.
- Mesh-ID block records, including site scope and provenance.
- Persisted/current target-state records, including operation, timestamp, version, provenance, source node, expiry.
- Snapshot cursor/next page token.

Implementation constraints:

- no request-path use;
- avoid holding all shard locks for too long;
- deterministic ordering if possible for stable pagination;
- bound page size;
- do not expose expired entries;
- filter by site scope if requested.

Potential implementation shape:

1. Collect current `BlockRecord`/entries from shards into vectors.
2. Collect target-state records from `TargetStateCache`.
3. Sort by `(target_kind, site_scope, identifier)`.
4. Slice by cursor and `max_items`.
5. Return chunk with `next_page_token`.

If full sorting is expensive, start with simple vector sorting and document that this is control-plane-only. Optimize later if needed.

## Phase 4 — Snapshot Apply API

Add a local apply API.

Suggested method:

```rust
pub fn apply_blocklist_snapshot(&self, snapshot: BlocklistSnapshotChunk) -> BlocklistSnapshotApplyResult
```

Apply result should include:

- IP blocks applied/updated;
- mesh-ID blocks applied/updated;
- target-state records applied;
- stale records ignored;
- invalid records ignored;
- conflicts;
- errors.

Rules:

- Validate IP addresses before applying IP entries.
- Validate mesh-ID identifiers are non-empty.
- Do not apply expired block entries.
- Do not apply expired target-state records.
- Use existing per-target LWW semantics when target-state records exist.
- Snapshot block entries should not override a newer local unblock tombstone.
- Snapshot unblock tombstones should not remove a newer local block.
- Provenance must be preserved from snapshot entries.

Prefer using existing internal helpers where possible:

- `block_ip_with_provenance` / lower-level insert helper
- `block_mesh_id_with_provenance` / lower-level insert helper
- target-state insertion helper

Avoid emitting new mesh gossip while applying a snapshot unless intentionally configured. Snapshot apply should converge local state, not re-broadcast every record by default.

## Phase 5 — Catchup Integration

Connect `snapshot_required` to snapshot fallback.

Flow:

1. Peer reconnects.
2. Local node sends `BlocklistCatchupRequest`.
3. Remote node returns `BlocklistCatchupResponse` with `snapshot_required=true` or `history_complete=false`.
4. Local node sends `BlocklistSnapshotRequest`.
5. Remote node returns one or more `BlocklistSnapshotResponse` pages.
6. Local node applies each page locally.
7. Local node logs summary and metrics.

Retries/errors:

- If snapshot page fails, log and retry bounded times or surface diagnostic.
- If `has_more=true`, request next page until complete or failure.
- Use a max page limit to avoid infinite loops.
- Include request IDs for correlation.

## Phase 6 — Supervisor/Worker Scope

Decide whether snapshot fallback applies only mesh peer-to-peer first, or also supervisor/worker IPC.

Recommended first pass:

- Mesh peer snapshot fallback first.
- Supervisor/worker can already receive initial blocklist state via IPC bootstrap; do not expand unless low effort.

If adding worker support:

- reuse same snapshot DTOs or conversions;
- preserve provenance;
- keep worker request path unaffected.

## Phase 7 — Target-State / Tombstone Transfer

Target-state/tombstones are important for stale replay safety.

Snapshot should optionally include `BlocklistTargetStateRecord` records.

Rules:

- Include only non-expired target-state records.
- Apply target-state records using the same version/timestamp ordering rules as `TargetStateCache`.
- Do not overwrite newer local target state with older remote target state.
- If snapshot block entry conflicts with newer local tombstone, ignore block entry and count as stale/ignored.
- If snapshot tombstone conflicts with newer local block, ignore tombstone and count as stale/ignored.

This prevents snapshot fallback from undoing restart-safe stale replay protections.

## Phase 8 — Observability

Add diagnostics and metrics if existing surfaces are available.

Suggested counters/log fields:

- snapshot requests sent;
- snapshot responses received;
- snapshot pages applied;
- snapshot apply errors;
- IP blocks applied;
- mesh-ID blocks applied;
- target-state records applied;
- stale snapshot records ignored;
- invalid snapshot records ignored;
- snapshot bytes/items transferred;
- `source_node`, `request_id`, `page_count`.

Admin/debug endpoint optional:

- expose snapshot fallback stats next to catchup stats if cheap.

## Phase 9 — Tests

Add focused tests.

### BlockStore snapshot export tests

- exports IP blocks with provenance.
- exports mesh-ID blocks with provenance.
- exports target-state records with provenance/source.
- respects page size.
- produces stable next page token.
- filters expired block entries.
- filters expired target-state records.

### Snapshot apply tests

- applies IP block entry.
- applies mesh-ID block entry.
- applies target-state tombstone.
- preserves provenance.
- ignores invalid IP records.
- ignores expired records.
- does not overwrite newer local unblock with older snapshot block.
- does not overwrite newer local block with older snapshot unblock tombstone.
- site scope is respected.

### Catchup integration tests

- catchup history gap sets `snapshot_required`.
- snapshot request follows gap.
- paged snapshot converges local BlockStore.
- missing event log after restart can still converge via snapshot.
- target-state records prevent stale resurrection after snapshot.

### Wire/protobuf tests

- encode/decode snapshot request.
- encode/decode snapshot response.
- unknown/missing optional fields handled safely.

### Regression tests

- request/WAF paths unchanged.
- mesh-ID boundary guard still passes.
- blocklist provenance guard still passes.
- threat-intel actionability guard still passes.

## Phase 10 — Documentation

Update:

- `architecture/blocklist_reconciliation.md`
- `architecture/blocklist_remove_consistency.md`
- `architecture/block_store.md`
- `architecture/blockstore_admin_observability.md`
- `AGENTS.md`

Docs must explain:

- event replay vs snapshot fallback;
- when `snapshot_required` is emitted;
- snapshot is control-plane-only;
- snapshot is not Raft/global-linearizable;
- snapshot is paged/bounded;
- snapshot preserves provenance;
- snapshot carries target-state/tombstones;
- snapshot apply is merge/conservative, not necessarily delete-absent authoritative sync unless implemented;
- remaining limitations.

## Phase 11 — Verification Commands

Run focused checks:

```bash
cargo test -p synvoid-block-store snapshot
cargo test -p synvoid-block-store blocklist
cargo test -p synvoid-block-store target_state
cargo test -p synvoid-mesh snapshot
cargo test -p synvoid-mesh catchup
cargo test -p synvoid-core blocklist
cargo test --test mesh_id_boundary_guard
cargo test --test manual_enforcement_provenance_guard
cargo test --test threat_intel_boundary_guard
cargo test --test threat_intel_consumer_actionability_guard
cargo test --lib --no-run
```

If protobuf or IPC schemas change:

```bash
cargo test --workspace --no-run
```

Adjust filters to actual test names.

## Acceptance Criteria

This pass is complete when:

1. `snapshot_required` can trigger a concrete snapshot fallback flow.
2. Snapshot request/response wire types exist and are tested.
3. Snapshot transfer is paged/bounded.
4. Snapshot export includes IP blocks, mesh-ID blocks, and target-state/tombstone records.
5. Snapshot apply preserves provenance.
6. Snapshot apply respects target-state LWW/stale suppression.
7. Snapshot apply does not resurrect stale blocks over newer unblocks.
8. Snapshot apply does not remove newer blocks with older tombstones.
9. Catchup history gap integration is tested end-to-end or with close unit/integration coverage.
10. No request/WAF path changes are introduced.
11. Mesh-ID request-path scope remains control-plane-only.
12. Raft remains out of operational blocklist snapshots.
13. Docs clearly distinguish replay, snapshot fallback, and remaining non-goals.

## Notes for the Implementer

This is convergence repair for missed control-plane history, not a consensus system.

The invariant is:

> Event replay repairs recent gaps; snapshot fallback repairs gaps beyond retention. Neither path creates request-path remote dependency or global linearizability.
