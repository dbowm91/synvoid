# Blocklist Remove Consistency Ordering and Dedupe Cleanup — Iteration 47

## Purpose

Iteration 46 implemented mesh-wide blocklist remove propagation using `BlocklistEvent`, `BlocklistEventGossip`, and supervisor/worker `BlocklistEventUpdate`. The propagation path is now present, but the documented consistency model must be tightened so implementation and guarantees match precisely.

This pass should resolve two specific issues:

1. The docs describe timestamp-based last-writer-wins and `IgnoredStale`, but the current apply path appears to enforce event-ID dedupe only.
2. The docs describe oldest/FIFO dedupe eviction, but the current bounded `HashSet` behavior clears the whole set at capacity.

The goal is to make blocklist remove propagation semantics honest, deterministic, and tested.

## Current Known State

From Iteration 46:

- `BlocklistEvent` supports distributed fields: `event_id`, `source_node`, `ttl_secs`, and `version`.
- `BlocklistEventData` and `BlocklistEventGossip` exist on the protobuf/wire path.
- `MeshMessage::BlocklistEventGossip` exists.
- `announce_local_unblock()` gossips unblock events.
- Supervisor pushes `BlocklistEventUpdate` IPC to workers.
- `BlockStore::apply_blocklist_event()` dispatches block/unblock events locally.
- `BlocklistApplyResult` includes `Applied`, `NoopDuplicate`, `IgnoredStale`, `InvalidTarget`, and `StoreDisabled`.
- Current dedupe is an in-memory `HashSet<String>` capped at 10,000 events.
- Current docs state last-writer-wins by timestamp and FIFO-ish dedupe eviction.

Open concern:

- If there is no per-target last-applied timestamp/version state, stale events are not actually suppressed.
- If capacity handling clears the full seen-event set, dedupe behavior is not FIFO/LRU.

## Non-Goals

Do not redesign the whole propagation stack.

Do not add Raft to operational blocklist removals.

Do not add request-path network lookups.

Do not change WAF request-path behavior.

Do not add acknowledged delivery in this pass.

Do not build full durable event sourcing.

Do not change admin auth/authz.

Do not remove the existing protobuf/wire message unless incompatible.

## Phase 1 — Confirm Actual Runtime Semantics

Inspect and document the current code paths:

- `BlockStore::apply_blocklist_event()`
- `seen_events` storage and eviction logic
- `BlocklistApplyResult::IgnoredStale` usage
- `BlocklistEvent::version` usage
- `BlocklistEvent::timestamp` usage
- `announce_local_unblock()`
- `BlocklistEventGossip` receive/apply path
- `BlocklistEventUpdate` worker apply path
- architecture docs referencing ordering/dedupe

Outcome of this phase:

- Identify whether stale suppression exists anywhere.
- Identify whether dedupe eviction is full-clear, FIFO, LRU, or undefined.
- Decide whether this pass implements stronger semantics or downgrades docs.

## Phase 2 — Choose Consistency Semantics

Choose one of two explicit options.

### Option A — Implement stronger last-writer-wins semantics

Add per-target applied-event metadata.

Target key:

```rust
(target_kind, site_scope, identifier)
```

State per target:

```rust
last_timestamp: u64
last_version: Option<u64>
last_event_id: Option<String>
last_operation: BlocklistOperation
```

Rules:

- If both events have `version`, higher version wins.
- If only timestamps are available, higher timestamp wins.
- Equal timestamp/version duplicate or older event is a no-op.
- Older block must not resurrect a target after newer unblock.
- Older unblock must not remove a newer block.
- Return `IgnoredStale` when rejecting older per-target event.

This gives the docs a real implementation.

### Option B — Downgrade docs to dedupe-only semantics

Keep implementation simple.

Rules:

- `event_id` dedupe prevents exact duplicate replays only.
- There is no stale-event suppression.
- Received events apply in arrival order.
- Timestamp/version are carried for observability and future ordering only.
- Remove or explain `IgnoredStale` as currently reserved/future-only.

This is acceptable only if operational risk is tolerable and docs are explicit.

Recommended: **Option A** if small enough. Mesh-wide remove consistency matters now, so stale replay protection is worth adding.

## Phase 3 — Implement Target State for Stale Suppression

If choosing Option A, add a bounded in-memory per-target event state cache to `BlockStore` or an adjacent helper.

Suggested structures:

```rust
struct BlocklistTargetKey {
    target_kind: BlockTargetKind,
    site_scope: String,
    identifier: String,
}

struct LastAppliedBlocklistEvent {
    timestamp: u64,
    version: Option<u64>,
    event_id: Option<String>,
    operation: BlocklistOperation,
}
```

Requirements:

- No network I/O.
- In-memory is acceptable for this pass.
- Bounded capacity to avoid unbounded growth.
- Does not block request/WAF paths.
- Used only in `apply_blocklist_event()` or its local helper.

Potential capacity:

- 10,000 seen event IDs.
- 10,000 per-target last-applied entries.

If a target-state cache is full, evict oldest target metadata or document full-clear fallback.

## Phase 4 — Fix Dedupe Eviction Semantics

Replace full-set clear with deterministic bounded eviction, or update docs to say full clear.

Preferred implementation:

- Use `HashSet<String>` plus `VecDeque<String>` insertion order.
- On insert:
  - if new, push event ID into queue and set;
  - while queue len > max, pop front and remove from set.
- Duplicate event IDs return `NoopDuplicate`.

Suggested fields:

```rust
seen_events: RwLock<HashSet<String>>,
seen_event_order: RwLock<VecDeque<String>>,
```

Or wrap both in one lock:

```rust
seen_events: RwLock<SeenEventCache>
```

Preferred wrapper avoids lock-order bugs.

```rust
struct SeenEventCache {
    set: HashSet<String>,
    order: VecDeque<String>,
}
```

Behavior:

- Do not clear entire cache at capacity.
- Evict oldest event IDs one-by-one.
- Tests must prove oldest event can be replayed after eviction while recent event remains deduped.

## Phase 5 — Apply Ordering Rules Before Mutation

If implementing Option A, apply stale checks before mutating BlockStore state.

Order inside `apply_blocklist_event()` should be:

1. Validate target.
2. Check duplicate event ID.
3. Build target key.
4. Check target last-applied timestamp/version.
5. If stale, record/dedupe if appropriate and return `IgnoredStale` without mutation.
6. Mutate BlockStore.
7. Record event ID and last-applied target state only after a successful or intentional no-op application.

Important subtlety:

- A valid unblock for an already-missing target may still need to record target last-applied state, otherwise an older block could replay and resurrect the target.
- A duplicate should return `NoopDuplicate` before target stale logic.
- Invalid target should not be recorded.

Recommended result mapping:

- Duplicate event ID -> `NoopDuplicate`.
- Older target timestamp/version -> `IgnoredStale`.
- Unblock missing target but event is newest -> `Applied` or `NoopDuplicate`? Prefer a new result would be clearer, but avoid enum churn unless needed. If retaining existing enum, document as `Applied` because the event’s desired state is now represented.
- Store disabled -> `StoreDisabled`.

## Phase 6 — Decide Whether to Persist Tombstones

In-memory target-state cache protects against stale replays only while the node is alive.

For this pass, in-memory may be acceptable, but document the limitation.

If cheap, add short-lived persisted tombstones for unblocks:

```rust
BlocklistTombstone {
    target_kind,
    site_scope,
    identifier,
    timestamp,
    version,
    event_id,
    expires_at,
}
```

This is likely larger than needed for Iteration 47.

Recommended:

- keep in-memory per-target state now;
- document that process restart loses stale replay protection;
- create future follow-up only if needed.

## Phase 7 — Tests

Add focused tests.

### Dedupe cache tests

- duplicate event ID returns `NoopDuplicate`.
- cache capacity evicts oldest event only, not entire set.
- recently seen events remain deduped after capacity eviction.
- missing `event_id` events are not deduped, or are handled according to documented policy.

### Stale suppression tests, if Option A

- newer unblock prevents older block from resurrecting IP.
- newer unblock prevents older block from resurrecting mesh ID.
- newer block prevents older unblock from removing IP.
- newer block prevents older unblock from removing mesh ID.
- equal timestamp/event with different ID behavior is defined and tested.
- version ordering beats timestamp if both versions are present.
- `IgnoredStale` is returned for stale events.

### Apply semantics tests

- unblock missing target with newest event records target state.
- invalid IP event does not record dedupe/target state.
- duplicate invalid event behavior is defined.
- event without ID still applies but is not deduped, or is rejected if you choose event ID required for distributed path.

### Documentation regression tests if source-scan guard is practical

- no docs claim FIFO/LRU if implementation is full-clear.
- no docs claim timestamp LWW if `IgnoredStale` is not implemented.

Prefer real behavior tests over source-scan tests.

## Phase 8 — Documentation Updates

Update:

- `architecture/blocklist_remove_consistency.md`
- `architecture/blockstore_admin_observability.md`
- `architecture/manual_enforcement_ownership.md`
- `architecture/block_store.md`
- `AGENTS.md`

Docs must state exactly:

- duplicate event semantics;
- stale event semantics;
- whether timestamp/version ordering is enforced or reserved;
- whether target-state/tombstones are in-memory or persisted;
- dedupe cache eviction behavior;
- restart limitations;
- no request-path network lookups;
- Raft remains intentionally unused for operational blocklist removals.

## Phase 9 — Verification Commands

Run focused tests:

```bash
cargo test -p synvoid-core blocklist_event
cargo test -p synvoid-block-store blocklist_event
cargo test -p synvoid-block-store dedupe
cargo test -p synvoid-block-store stale
cargo test -p synvoid-block-store apply_blocklist_event
cargo test --lib mesh_admin
cargo test --lib blocklist
cargo test --test manual_enforcement_provenance_guard
cargo test --test threat_intel_boundary_guard
cargo test --lib --no-run
```

If protobuf/wire docs or conversions changed:

```bash
cargo test -p synvoid-mesh blocklist_event
cargo test --workspace --no-run
```

Adjust filters to actual test names.

## Acceptance Criteria

This pass is complete when:

1. Dedupe cache behavior matches docs.
2. The cache does not full-clear while docs claim FIFO/LRU eviction.
3. `IgnoredStale` is either implemented and tested or documented as reserved/future-only.
4. If LWW semantics are documented, stale block/unblock events are actually suppressed per target.
5. Older block events cannot resurrect a target after a newer unblock, if Option A is chosen.
6. Older unblock events cannot remove a newer block, if Option A is chosen.
7. Missing-target unblocks have clear semantics and tests.
8. Restart limitations are documented if target-state/tombstones are in-memory only.
9. Request/WAF paths remain local-only.
10. Raft boundary remains documented and unchanged.

## Notes for the Implementer

This is a semantics alignment pass. Do not expand the transport surface unless necessary.

The invariant is:

> The remove-consistency documentation must describe exactly what the node enforces. If the node claims duplicate protection, stale suppression, or last-writer-wins ordering, those properties must be implemented and tested at the local apply boundary.
