# BlockStore Counter Correctness, Migration Verification, and Unblock Event Staging — Iteration 45

## Purpose

Iteration 44 replaced the sentinel `0.0.0.0` mesh-ID ban model with first-class mesh-ID block entries. The model is now materially cleaner: multiple mesh IDs can be blocked concurrently, admin paths call mesh-specific APIs, listings are unified through `BlockRecord`, and legacy sentinel migration exists.

Before adding distributed unblock propagation, do one focused hardening pass over the new state model:

1. Fix/verify BlockStore count correctness for overwrites and removals.
2. Verify legacy sentinel migration is actually invoked during initialization and persisted correctly.
3. Add invariants/tests around IP and mesh-ID counters, persistence, and unified records.
4. Stage a local, target-aware `BlocklistEvent` model for future unblock propagation without wiring a full gossip/DHT protocol yet.

The goal is to make the state model reliable before adding distributed removal semantics.

## Current Known State

Implemented in Iteration 44:

- `MeshBlockEntry`, `BlockTargetKind`, and `BlockRecord` exist in `synvoid-core`.
- `BlockStore` now has separate `shards` for IP entries and `mesh_shards` for mesh-ID entries.
- `mesh_blocks.json` stores mesh-ID blocks separately from `blocks.json`.
- Admin `ban_mesh_id` calls `block_mesh_id_with_provenance`.
- Admin `unban` with `ban_type="mesh_id"` calls `unblock_mesh_id`.
- `list_bans` calls `get_all_block_records` and exposes both IP and mesh-ID blocks.
- `migrate_legacy_sentinel_entries()` exists and converts `0.0.0.0` entries with `mesh_id_ban:` reasons into first-class mesh entries.
- Unblock propagation is intentionally local-only and documented as future work.

Observed follow-up concerns:

- `block_ip` / `block_ip_with_provenance` appear to increment `total_entries` unconditionally after insert; this can drift on overwrite.
- `block_mesh_id_with_provenance` already increments `total_mesh_entries` only when the key is new.
- Need to verify `migrate_legacy_sentinel_entries()` is actually called on initialization/load, not merely defined.
- Need to verify migration removes the legacy IP entry, increments/decrements counts correctly, and persists both files.
- Need a local target-aware event type before designing full mesh unblock propagation.

## Non-Goals

Do not implement full mesh gossip/DHT unblock propagation in this pass.

Do not redesign threat-intel policy gates.

Do not change WAF request-path behavior.

Do not add request-path network lookups.

Do not redesign BlockStore persistence format beyond targeted count/migration fixes.

Do not remove legacy IP block APIs.

Do not remove legacy sentinel compatibility until migration is proven.

Do not introduce broad admin UI/API expansion.

## Phase 1 — Fix IP Counter Drift on Overwrite

Update `crates/synvoid-block-store/src/lib.rs`.

Audit these methods:

- `block_ip`
- `block_ip_with_provenance`
- `add_block`
- any helper that inserts into `self.shards`

Required behavior:

- increment `total_entries` only when inserting a new key;
- do not increment count when overwriting an existing `(site_scope, ip)` entry;
- still update/persist the entry on overwrite;
- capacity eviction should account for overwrite correctly.

Suggested pattern:

```rust
let mut store = self.shards[idx].write();
let is_new = !store.contains_key(&key);
if is_new && self.total_entries.load(Ordering::Relaxed) >= max_entries {
    // evict before insert
}
store.insert(key, entry);
if is_new {
    self.total_entries.fetch_add(1, Ordering::Relaxed);
}
```

Be careful with capacity checks:

- overwriting an existing key should not trigger eviction;
- inserting a new key at capacity should evict one entry first;
- if the evicted key is the same key being inserted, avoid double-decrement/double-increment oddities if that can happen.

Mirror the already-correct `block_mesh_id_with_provenance` behavior where practical.

## Phase 2 — Verify Mesh-ID Counter Semantics

Audit mesh-specific methods:

- `block_mesh_id_with_provenance`
- `unblock_mesh_id`
- `is_mesh_id_blocked` expiration path
- `get_mesh_stats`
- `get_all_mesh_entries`
- `get_all_block_records`

Required behavior:

- new mesh ID increments `total_mesh_entries` once;
- overwriting the same `(site_scope, mesh_id)` does not increment count;
- unblocking existing mesh ID decrements once;
- unblocking missing mesh ID returns false and does not decrement;
- expiration path decrements once;
- unified record count equals live IP entries plus live mesh-ID entries.

Add or strengthen tests rather than just relying on code review.

## Phase 3 — Verify Legacy Sentinel Migration Is Called

Find where `BlockStore::new` or surrounding initialization should call `migrate_legacy_sentinel_entries()`.

Acceptance requirement:

- if `blocks.json` contains a legacy sentinel entry, creating/loading `BlockStore` results in a first-class `MeshBlockEntry` being available through `is_mesh_id_blocked` / `get_all_mesh_entries` / `get_all_block_records`.

Implementation options:

### Preferred

Call `migrate_legacy_sentinel_entries()` during `BlockStore::new` after both IP and mesh files are loaded and before returning `Self`.

Potential shape:

```rust
let store = Self { ... };
let migrated = store.migrate_legacy_sentinel_entries();
if migrated > 0 { ... }
store
```

Ensure this is safe with persistence task setup.

### Alternative

If migration must be explicit, expose/document a required initialization call and ensure all production constructors call it. This is less preferred because it is easier to forget.

## Phase 4 — Migration Persistence and Compatibility Tests

Add tests with temporary directories and real JSON files.

Required tests:

1. load `blocks.json` containing one sentinel mesh-ID entry;
2. after `BlockStore::new`, `get_all_entries()` no longer contains sentinel IP entry;
3. `get_all_mesh_entries()` contains the migrated mesh ID;
4. `total_entries` decremented and `total_mesh_entries` incremented correctly;
5. persistence writes migrated state to `mesh_blocks.json`;
6. old `blocks.json` without provenance still deserializes and defaults to `LegacyUnknown`;
7. malformed/non-mesh `0.0.0.0` entries are not migrated incorrectly.

If persistence is asynchronous, use shutdown/flush or deterministic persist helpers instead of sleeps where possible.

## Phase 5 — Unified Block Record Invariants

Add tests for `get_all_block_records`.

Required assertions:

- IP records have `target_kind == Ip` and identifier is IP string;
- mesh records have `target_kind == MeshId` and identifier is mesh ID;
- records preserve provenance kind/source;
- records sort by `blocked_at` descending if that is the intended API guarantee;
- legacy sentinel migration records appear as mesh records, not IP records.

If sorting is not intended as a stable guarantee, document that instead of testing strict order.

## Phase 6 — Admin Response Regression Tests

Add handler/service-level tests where feasible.

Required behavior:

- two distinct mesh IDs can be banned and both appear in `GET /mesh/bans`;
- unbanning one mesh ID removes only that record;
- unbanning a missing mesh ID returns 404;
- IP ban/unban behavior is unchanged;
- response text remains local-only and does not imply mesh-wide unblock propagation.

If full Axum handler tests are too heavy, add lower-level tests against the block-store-backed service/helper layer and keep admin response mapping small.

## Phase 7 — Stage a Local Target-Aware Blocklist Event Type

Do not implement full mesh propagation yet. Define the local model needed for future propagation.

Possible type location:

- `synvoid-core::block_store`
- or a mesh/control-plane module if that avoids unwanted dependencies.

Suggested shape:

```rust
pub enum BlocklistOperation {
    Block,
    Unblock,
}

pub struct BlocklistEvent {
    pub operation: BlocklistOperation,
    pub target_kind: BlockTargetKind,
    pub identifier: String,
    pub site_scope: String,
    pub reason: Option<String>,
    pub provenance: BlockProvenance,
    pub timestamp: u64,
    pub source_node: Option<String>,
    pub event_id: Option<String>,
}
```

Requirements:

- serializable/deserializable;
- target-aware (`Ip` / `MeshId`);
- provenance-bearing;
- able to express unblock without reason;
- idempotency-friendly fields exist or are explicitly deferred.

Keep this as a data model and local helper only. Do not wire it into gossip/DHT unless trivial and already supported.

## Phase 8 — Add Local Event Emission Hooks Without Distributed Claims

If a clean local hook exists, have admin unban/block create or log a `BlocklistEvent` internally.

Possible outcomes:

### Minimal acceptable

- Type exists.
- Docs explain it is staged for future propagation.
- Admin responses remain local-only.

### Better if low-risk

- Admin block/unblock paths construct a local `BlocklistEvent` and emit a structured log.
- No mesh transmission occurs.

Do not add misleading fields to responses like `propagated: true`.

If adding event hooks would create churn, leave it as a model-only type and make propagation the next plan.

## Phase 9 — Documentation

Update:

- `architecture/blockstore_admin_observability.md`
- `architecture/manual_enforcement_ownership.md`
- `architecture/block_store.md`
- `docs/THREAT_INTEL.md` if sync semantics changed
- `AGENTS.md` if new implementation rules are durable

Documentation must state:

- IP overwrite count behavior;
- mesh-ID overwrite count behavior;
- legacy sentinel migration call path;
- local-only unblock semantics;
- whether a local `BlocklistEvent` model exists and whether it is transmitted;
- that full distributed unblock propagation remains future work unless implemented.

## Phase 10 — Verification Commands

Run focused tests:

```bash
cargo test -p synvoid-block-store counter
cargo test -p synvoid-block-store mesh_id
cargo test -p synvoid-block-store migration
cargo test -p synvoid-block-store block_record
cargo test --lib mesh_admin
cargo test --test manual_enforcement_provenance_guard
cargo test --lib --no-run
```

If a core event model is added:

```bash
cargo test -p synvoid-core blocklist_event
```

If supervisor/worker sync touched:

```bash
cargo test --lib blocklist
cargo test --lib supervisor
```

Adjust filters to actual test names.

## Acceptance Criteria

This pass is complete when:

1. IP block counters do not drift on overwrite.
2. Mesh-ID counters do not drift on overwrite, unblock, expiration, or migration.
3. `BlockStore::new` or equivalent production initialization invokes legacy sentinel migration automatically.
4. Legacy sentinel migration is tested with real persisted data.
5. Unified `BlockRecord` listings preserve target kind, identifier, provenance, and expected ordering semantics.
6. Admin ban/unban/list tests cover multiple concurrent mesh-ID bans and targeted mesh-ID unban.
7. Admin response wording remains local-only for unblock operations.
8. A target-aware local `BlocklistEvent` model is either added and documented, or explicitly deferred to the next propagation pass.
9. No full distributed unblock propagation is claimed unless actually implemented.
10. Existing WAF/threat-intel boundary guardrails still pass.

## Notes for the Implementer

Keep this as a state-model hardening pass. The next architectural layer is distributed unblock propagation, but it should be built on reliable counters, deterministic migration, and explicit target-aware event semantics.

The invariant is:

> BlockStore counts and admin-visible records must reflect live state exactly. Legacy sentinel entries must be migrated deterministically. Unblock events must be target-aware before they become distributed.
