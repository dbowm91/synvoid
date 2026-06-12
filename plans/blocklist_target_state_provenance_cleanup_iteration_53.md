# Blocklist Target-State Provenance Cleanup — Iteration 53

## Purpose

Iteration 52 added persisted per-target blocklist state in `blocklist_target_state.json`, allowing stale replay protection to survive process restarts. The core restart-safety objective is implemented, but the persisted target-state records currently lose some audit metadata when serialized.

This cleanup pass should preserve `source_node` and `BlockProvenance` in persisted target-state records and align comments/docs with the new restart-safe behavior.

The goal is small and surgical: keep the restart-safe target-state model, but stop writing default provenance/source values into a record type that is explicitly capable of carrying origin metadata.

## Current Known State

From Iteration 52:

- `BlocklistTargetStateRecord` exists in `synvoid-core`.
- `blocklist_target_state.json` is loaded by `BlockStore::new()`.
- `shutdown()` persists target state before normal block persistence shutdown.
- `TargetStateCache` is hydrated from persisted records.
- Restart replay tests exist for IP and mesh-ID stale suppression.
- Direct APIs record target state through `record_target_state_from_direct_op()`.
- The persisted record type includes `source_node` and `provenance` fields.

Known cleanup issue:

- `persist_target_state_to_disk()` serializes `source_node: None` and `provenance: BlockProvenance::default()` for every record.
- This does not break stale replay ordering, but it loses audit context and conflicts with the provenance-preservation work from Iteration 50.
- Local `TargetStateCache` comments still say restart loses stale replay protection, despite persistence now hydrating it on startup.

## Non-Goals

Do not redesign target-state persistence.

Do not persist the full event log.

Do not introduce Raft or durable consensus.

Do not change request/WAF path behavior.

Do not change mesh-ID control-plane-only scope.

Do not change stale replay comparison semantics unless required to carry metadata.

Do not expand into acknowledged delivery or full snapshot fallback.

## Phase 1 — Audit Target-State Metadata Flow

Inspect all target-state construction and persistence paths.

Search terms:

- `BlocklistTargetStateRecord`
- `LastAppliedBlocklistEvent`
- `record_target_state_from_direct_op`
- `record_target_state`
- `persist_target_state_to_disk`
- `target_state.write()`
- `target_state_persist`
- `source_node: None`
- `BlockProvenance::default()`

Determine:

- where event-origin provenance is available;
- where direct-operation provenance is available;
- whether `LastAppliedBlocklistEvent` currently stores enough metadata;
- whether persisted records can be reconstructed without defaulting metadata.

## Phase 2 — Extend In-Memory Last-Applied State

If `LastAppliedBlocklistEvent` does not carry source/provenance, extend it.

Suggested shape:

```rust
struct LastAppliedBlocklistEvent {
    timestamp: u64,
    version: Option<u64>,
    event_id: Option<String>,
    operation: BlocklistOperation,
    source_node: Option<String>,
    provenance: BlockProvenance,
}
```

Requirements:

- preserve existing stale comparison behavior;
- use source/provenance only for persistence/audit, not ordering;
- hydrate these fields from `BlocklistTargetStateRecord` on startup;
- default only for legacy records that genuinely lack provenance.

## Phase 3 — Preserve Metadata From Event Apply Path

Update `apply_blocklist_event()` target-state recording so it stores:

- `event.source_node.clone()`;
- `event.provenance.clone()`;
- `event.event_id.clone()`;
- operation/timestamp/version as today.

Required behavior:

- `Applied` records full metadata.
- missing-target unblock that records target state also records full event provenance/source.
- `IgnoredStale` does not overwrite existing metadata.
- `InvalidTarget` does not record metadata.
- `NoopDuplicate` should not rewrite existing metadata unless target-state is missing and that recovery is explicitly implemented.

## Phase 4 — Preserve Metadata From Direct Operations

Update `record_target_state_from_direct_op()` or equivalent direct-operation helper so direct writes carry origin provenance.

For direct APIs:

- `block_ip_with_provenance` should record provided provenance.
- `block_mesh_id_with_provenance` should record provided provenance.
- `add_block` should use available provenance or documented compatibility default.
- `unblock_ip` and `unblock_mesh_id` may lack explicit provenance today; if caller context is unavailable, use a documented local/direct default rather than `LegacyUnknown` if a better variant exists.

Preferred options for direct unblocks:

1. Add provenance-aware unblock variants, such as `unblock_ip_with_provenance()` and `unblock_mesh_id_with_provenance()`, and route admin/event paths through them.
2. Keep existing signatures but record a conservative compatibility provenance for direct unblocks, documenting the limitation.

Recommended: implement provenance-aware unblock helpers if small; otherwise document direct unblock provenance defaults clearly and leave a follow-up.

## Phase 5 — Fix Persistence Serialization

Update `persist_target_state_to_disk()` to serialize actual metadata from `LastAppliedBlocklistEvent`.

Current lossy pattern to remove:

```rust
source_node: None,
provenance: BlockProvenance::default(),
```

Replacement:

```rust
source_node: state.source_node.clone(),
provenance: state.provenance.clone(),
```

Also ensure `recorded_at` and `expires_at` behavior remains unchanged.

## Phase 6 — Fix Startup Hydration

Update hydration from `BlocklistTargetStateRecord` so `TargetStateCache` receives:

- timestamp;
- version;
- event ID;
- operation;
- source node;
- provenance.

Legacy/default behavior:

- Existing persisted records without fields should deserialize safely.
- If provenance is missing in older files, default according to serde/default behavior and document.
- Do not panic on malformed target-state files.

## Phase 7 — Comment and Documentation Cleanup

Fix stale local comments and docs.

Known stale comment:

- `TargetStateCache` comment still says process restart loses stale replay protection.

Replace with language like:

```rust
/// Bounded in-memory cache of per-target last-applied event state.
/// Hydrated from persisted target-state records on startup when enabled.
/// Runtime capacity remains bounded; persistence provides restart-safe warm start.
```

Update docs if needed:

- `architecture/blocklist_remove_consistency.md`
- `architecture/blocklist_reconciliation.md`
- `architecture/block_store.md`
- `architecture/blockstore_admin_observability.md`
- `architecture/blocklist_provenance_preservation.md`
- `AGENTS.md`

Docs must state:

- persisted target-state records preserve origin provenance when available;
- event-ID dedupe remains in-memory only;
- direct API provenance defaults if some direct unblock paths cannot carry caller provenance;
- target-state persistence is for restart-safe replay ordering, not full audit-log durability.

## Phase 8 — Tests

Add focused tests.

### Serialization tests

- `BlocklistTargetStateRecord` roundtrip preserves `source_node`.
- `BlocklistTargetStateRecord` roundtrip preserves `provenance.kind` and `provenance.source`.

### Event apply persistence tests

- apply block event with `source_node` and `AdminManual` provenance, persist/reload, verify target-state record/hydrated state carries source/provenance.
- apply unblock event with source/provenance, persist/reload, verify metadata persists.
- missing-target unblock still persists event provenance.

### Direct API tests

- `block_ip_with_provenance` persists provided provenance in target state.
- `block_mesh_id_with_provenance` persists provided provenance in target state.
- direct unblock provenance behavior is tested according to chosen implementation.

### Stale replay regression tests

- existing restart stale-replay tests still pass.
- stale rejected event does not overwrite stored provenance/source.

### Comment/docs guard, optional

- Source scan ensuring `TargetStateCache` comments no longer claim restart loses stale replay protection.

## Phase 9 — Verification Commands

Run focused checks:

```bash
cargo test -p synvoid-core target_state
cargo test -p synvoid-core provenance
cargo test -p synvoid-block-store target_state
cargo test -p synvoid-block-store tombstone
cargo test -p synvoid-block-store provenance
cargo test -p synvoid-block-store restart
cargo test -p synvoid-block-store stale
cargo test --test mesh_id_boundary_guard
cargo test --test manual_enforcement_provenance_guard
cargo test --test threat_intel_boundary_guard
cargo test --lib --no-run
```

If signatures change for provenance-aware unblocks:

```bash
cargo test --workspace --no-run
```

Adjust filters to actual test names.

## Acceptance Criteria

This cleanup is complete when:

1. Persisted target-state records no longer force `source_node: None`.
2. Persisted target-state records no longer force `BlockProvenance::default()`.
3. Event-applied target state preserves event provenance/source through persist/reload.
4. Direct block APIs preserve provided provenance through target-state persistence.
5. Direct unblock provenance behavior is either provenance-aware or explicitly documented/tested as a compatibility default.
6. Startup hydration restores provenance/source metadata into in-memory target state.
7. Existing restart stale-replay protection still works for IP and mesh-ID targets.
8. Stale events do not overwrite newer target-state provenance/source.
9. Comments/docs no longer claim restart loses stale replay protection.
10. Existing boundary/provenance/mesh-ID guardrails still pass.

## Notes for the Implementer

This is cleanup, not a new architecture track.

The invariant is:

> Persisted target state exists to preserve replay-ordering safety across restart, but when it carries metadata, that metadata must not be silently replaced with defaults.
