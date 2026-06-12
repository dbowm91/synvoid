# Blocklist IPC Provenance Preservation — Iteration 50

## Purpose

The blocklist consistency track is now mature enough to move on. The next known gap is auditability: some supervisor/worker and IPC blocklist sync paths may reassign provenance to `SupervisorSync` and lose the original source/cause of a block or unblock.

This pass should preserve original provenance across blocklist IPC and sync boundaries while still recording that the supervisor/worker path relayed the event.

The goal is not to change enforcement semantics. The goal is to make audit records, admin list output, diagnostics, and worker-local BlockStore state retain the true origin of a blocklist decision.

## Current Known State

Recent work established:

- `BlockProvenance` and `BlockProvenanceKind` exist.
- `BlockEntry` and `MeshBlockEntry` carry provenance.
- `BlockRecord` exposes provenance for admin listing.
- `BlocklistEvent` carries provenance.
- `BlocklistEventGossip` and `BlocklistEventUpdate` propagate target-aware block/unblock events.
- `BlockStore::apply_blocklist_event()` applies events with the event's provenance.
- Some older IPC/snapshot/blocklist sync paths may still use `SupervisorSync` as a replacement provenance rather than preserving original provenance.
- Existing docs mention an IPC provenance-loss gap.

## Non-Goals

Do not redesign blocklist propagation.

Do not alter request/WAF enforcement behavior.

Do not change block/unblock semantics.

Do not introduce Raft for blocklist provenance.

Do not remove `SupervisorSync` as a provenance kind; it is still useful as a relay/apply context.

Do not build a full audit-log subsystem.

Do not change admin auth/authz.

Do not break wire compatibility without a migration/default strategy.

## Phase 1 — Audit All Blocklist IPC/Sync Provenance Paths

Search for every path that converts, syncs, or reconstructs blocklist state.

Search terms:

- `BlockProvenanceKind::SupervisorSync`
- `SupervisorSync`
- `BlockEntryData`
- `MeshBlockEntryData`
- `BlocklistUpdate`
- `BlocklistResponse`
- `BlocklistEventUpdate`
- `BlocklistEventData`
- `block_ip_with_provenance`
- `block_mesh_id_with_provenance`
- `apply_blocklist_event`
- `provenance_source`
- `admin_ban_ip`
- `admin_ban_mesh_id`
- `announce_local_block`
- `broadcast_blocklist_event`

Likely files:

- `crates/synvoid-core/src/block_store.rs`
- `crates/synvoid-block-store/src/lib.rs`
- `crates/synvoid-ipc/**`
- `crates/synvoid-mesh/**`
- `src/supervisor/**`
- `src/worker/unified_server/lifecycle.rs`
- `src/admin/handlers/mesh_admin.rs`
- `architecture/manual_enforcement_ownership.md`
- `architecture/blockstore_admin_observability.md`
- `architecture/blocklist_remove_consistency.md`
- `architecture/blocklist_reconciliation.md`

Produce/update an inventory section in `architecture/manual_enforcement_ownership.md` or a new `architecture/blocklist_provenance_preservation.md`.

Classify each path:

- preserves original provenance;
- overwrites provenance;
- has no provenance field;
- reconstructs provenance from lossy data;
- intentionally marks relay context.

## Phase 2 — Define Provenance Semantics

Separate **origin provenance** from **relay/apply context**.

Recommended model:

### Origin provenance

The actor/system that originally caused the blocklist state change.

Examples:

- `AdminManual` / `admin_ban_ip`
- `AdminManual` / `admin_ban_mesh_id`
- `ThreatIntelPolicy` or existing equivalent
- `SupervisorSync` only if supervisor itself was the originator
- `LegacyUnknown` for old data without source

### Relay context

The transport path that delivered the operation to this node/worker.

Examples:

- `mesh_gossip`
- `supervisor_ipc`
- `worker_replay`
- `catchup_replay`

Do not overwrite origin provenance with relay context. If relay information is needed, add a separate field or log/metric label.

If adding a new struct is too invasive, preserve `BlockProvenance` as origin and use tracing fields for relay context.

## Phase 3 — Extend Wire Types Where Provenance Is Missing

Audit current wire/IPC types and add provenance fields where missing.

Likely candidates:

- `BlockEntryData`
- `MeshBlockEntryData`
- `BlocklistUpdate`
- `BlocklistResponse`
- worker IPC representations
- supervisor retained/replay event representations

Preferred fields:

```rust
provenance_kind: Option<String>
provenance_source: Option<String>
```

or strongly typed equivalents if the existing wire layer supports them.

Requirements:

- backwards compatible defaults;
- missing provenance maps to `LegacyUnknown` or `SupervisorSync` only when the supervisor truly originated it;
- old messages still deserialize;
- new messages preserve original `BlockProvenance` end-to-end.

If protobuf is involved:

- add optional fields with new field numbers;
- do not renumber existing fields;
- update conversion helpers;
- add encode/decode tests.

## Phase 4 — Fix Positive Snapshot Sync Provenance

The event path likely preserves provenance through `BlocklistEvent`, but positive snapshot sync may still be lossy.

Audit and fix:

- supervisor blocklist snapshot to worker;
- worker startup sync;
- `BlocklistResponse` handling;
- any conversion from `BlockEntryData` into `BlockEntry`;
- any conversion from `MeshBlockEntryData` into `MeshBlockEntry`.

Required behavior:

- if snapshot entry has origin provenance, worker BlockStore stores that provenance;
- if snapshot entry lacks provenance, use `LegacyUnknown` or compatibility default and document;
- relay path may be logged separately as `relay="supervisor_sync"`.

Do not blanket assign `SupervisorSync` to all entries unless the supervisor itself created the block.

## Phase 5 — Fix Event Replay / Catchup Provenance If Needed

Validate:

- `BlocklistEventData::from_event` preserves provenance;
- `BlocklistEventData::to_event` preserves provenance;
- `BlocklistEventGossip` receive path applies event provenance unchanged;
- catchup response/replay preserves provenance;
- supervisor `BlocklistEventUpdate` preserves provenance.

If any path currently reconstructs provenance as `SupervisorSync`, replace that with the event's origin provenance.

Use relay context only in logs/metrics:

```rust
tracing::debug!(
    provenance_kind = ?event.provenance.kind,
    provenance_source = ?event.provenance.source,
    relay = "catchup_replay",
    ...
);
```

## Phase 6 — Admin Listing / Diagnostics

Ensure admin-visible state exposes the preserved origin.

Check:

- `GET /mesh/bans`
- catchup diagnostics if relevant;
- debug dump/admin blocklist stats;
- logs emitted on worker apply;
- tests for provenance in `BanRecord`.

Required behavior:

- a worker-applied block originally created by admin still lists as `AdminManual` / `admin_ban_*`, not `SupervisorSync`;
- mesh catchup replay does not change origin;
- legacy unknown data is explicitly shown as unknown/legacy if surfaced.

## Phase 7 — Tests

Add focused tests.

### Wire/IPC conversion tests

- `BlockEntry -> BlockEntryData -> BlockEntry` preserves provenance.
- `MeshBlockEntry -> MeshBlockEntryData -> MeshBlockEntry` preserves provenance.
- old data missing provenance defaults correctly.
- protobuf encode/decode preserves provenance fields.

### Worker/supervisor sync tests

- supervisor sends admin-origin IP block; worker stores `AdminManual` provenance.
- supervisor sends admin-origin mesh-ID block; worker stores `AdminManual` provenance.
- supervisor-origin block stores `SupervisorSync` only when origin is supervisor.
- worker replay from retained event log preserves origin provenance.

### Event/catchup tests

- `BlocklistEventGossip` preserves provenance through receive/apply.
- `BlocklistCatchupResponse` preserves provenance for replayed events.
- duplicate/no-op event does not overwrite existing provenance incorrectly.
- stale event does not overwrite newer provenance.

### Admin tests

- list bans returns original provenance after sync/replay.
- legacy/missing provenance returns documented default.

### Guardrail tests

- source scan or unit test to catch unconditional `BlockProvenanceKind::SupervisorSync` assignment in worker blocklist ingestion paths.

## Phase 8 — Documentation

Update:

- `architecture/manual_enforcement_ownership.md`
- `architecture/blockstore_admin_observability.md`
- `architecture/blocklist_remove_consistency.md`
- `architecture/blocklist_reconciliation.md`
- `architecture/block_store.md`
- `docs/THREAT_INTEL.md` if threat-intel-origin blocks are involved
- `AGENTS.md`

Docs must state:

- origin provenance is preserved end-to-end;
- relay/apply context must not overwrite origin provenance;
- `SupervisorSync` means supervisor-originated or compatibility-only, not merely supervisor-relayed;
- default behavior for legacy messages without provenance;
- which wire messages carry provenance;
- remaining limitations.

## Phase 9 — Verification Commands

Run focused tests:

```bash
cargo test -p synvoid-core provenance
cargo test -p synvoid-block-store provenance
cargo test -p synvoid-mesh provenance
cargo test -p synvoid-ipc provenance
cargo test --lib blocklist
cargo test --lib supervisor
cargo test --lib mesh_admin
cargo test --test manual_enforcement_provenance_guard
cargo test --test threat_intel_boundary_guard
cargo test --lib --no-run
```

If protobuf/wire messages change:

```bash
cargo test --workspace --no-run
```

Adjust filters to actual test names.

## Acceptance Criteria

This pass is complete when:

1. Every blocklist IPC/sync path has been inventoried for provenance behavior.
2. Origin provenance and relay/apply context are explicitly separated.
3. Positive snapshot sync preserves original block provenance.
4. Event gossip/catchup/replay preserves original blocklist event provenance.
5. Worker BlockStore entries retain original provenance after supervisor relay.
6. `SupervisorSync` is not used as a blanket replacement for origin provenance.
7. Legacy/missing provenance defaults are documented and tested.
8. Admin listing exposes preserved origin provenance after sync/replay.
9. Guardrails prevent reintroducing unconditional provenance overwrite in worker ingestion paths.
10. Request/WAF enforcement semantics remain unchanged.

## Notes for the Implementer

This is an auditability pass. Keep it narrow.

The invariant is:

> Transport may explain how a blocklist event arrived, but it must not erase why the blocklist event exists.
