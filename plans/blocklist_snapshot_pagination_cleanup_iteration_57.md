# Blocklist Snapshot Pagination Cleanup — Iteration 57

## Purpose

Iteration 56 added concrete snapshot fallback for blocklist catchup history gaps. The core convergence path is now present: `snapshot_required` triggers `BlocklistSnapshotRequest`, peers return snapshot responses, and receivers apply IP blocks, mesh-ID blocks, and target-state records.

The remaining cleanup is snapshot pagination semantics.

Current review notes suggest:

- block entries are paged, but target-state records may be included wholesale on every page;
- `snapshot_complete` may be false whenever target-state records are non-empty, even on the final page;
- applying snapshot block records through direct block APIs may record target-state timestamps as local apply time rather than original snapshot `blocked_at`, which needs explicit testing/behavioral confirmation.

This pass should make snapshot pagination unambiguous, efficient, and covered by regression tests.

## Current Known State

Iteration 56 added:

- `BlocklistSnapshotOptions`
- `BlocklistSnapshotCursor`
- `BlocklistSnapshotChunk`
- `BlocklistSnapshotApplyResult`
- `BlockStore::export_blocklist_snapshot()`
- `BlockStore::apply_blocklist_snapshot()`
- `BlocklistSnapshotRequest` / `BlocklistSnapshotResponse` wire messages
- snapshot request on catchup `snapshot_required=true`
- snapshot response apply and next-page request when `has_more=true`

Known cleanup targets:

1. Target-state records need clear pagination semantics.
2. `snapshot_complete` needs correct final-page semantics.
3. Snapshot block application should not accidentally distort future LWW ordering by recording local apply timestamp where original snapshot timestamp should be used.

## Non-Goals

Do not redesign the full snapshot architecture.

Do not add Raft or global linearizability.

Do not add request-path remote lookups.

Do not change WAF request-path behavior.

Do not change mesh-ID request-path scope.

Do not remove event replay/catchup.

Do not make snapshot delete-absent authoritative unless explicitly required later.

## Phase 1 — Confirm Existing Semantics With Tests

Before changing behavior, add or inspect tests that reproduce the current suspected issues.

Scenarios:

- multi-page snapshot with IP blocks and non-empty target-state records;
- final page with non-empty target-state records;
- multi-page snapshot response where target-state records appear on every page;
- receiver applies repeated target-state records across pages;
- snapshot block apply writes target state with local apply timestamp instead of snapshot timestamp.

If current tests already cover these, verify expected assertions. If not, add failing tests first.

## Phase 2 — Choose Target-State Pagination Strategy

Pick one explicit strategy.

### Option A — Unified Pagination Across All Snapshot Items

Treat IP blocks, mesh-ID blocks, and target-state records as one sorted item stream.

Pros:

- `max_items` applies to the entire response.
- No duplicate target-state transfer across pages.
- `has_more` and `snapshot_complete` are simple.

Cons:

- Requires a typed snapshot item enum for all three item types.
- Wire response still separates fields, so export must split page items back into lists.

Recommended if implementation is manageable.

### Option B — Separate Sections With Section-Aware Cursor

Cursor encodes both section and offset:

```text
ip:<offset>
mesh:<offset>
target_state:<offset>
done
```

Pros:

- Clear and efficient.
- Avoids one large combined vector if desired.

Cons:

- More cursor logic.
- Needs robust parsing/defaulting.

### Option C — Send Target-State Only On First Or Final Page

Keep paging block entries, but send target-state records only once.

Pros:

- Minimal change.
- Avoids duplicate target-state transfer.

Cons:

- `max_items` does not strictly bound total message size if target-state is large.
- Does not solve large target-state snapshots well.

Recommendation: **Option A** if simple enough; otherwise **Option B**. Avoid Option C unless target-state is known to be small and bounded enough for one message.

## Phase 3 — Fix `snapshot_complete`

Define fields precisely:

- `has_more`: true if additional page requests are needed.
- `next_page_token`: token for the next page if and only if `has_more=true`.
- `snapshot_complete`: true if this response completes the requested snapshot and no further pages are needed.

Required invariant:

```rust
snapshot_complete == !has_more && error.is_none()
```

or for `BlocklistSnapshotChunk` without error:

```rust
snapshot_complete == !has_more
```

Do not make `snapshot_complete` depend on whether `target_state_records` is empty.

Add tests:

- first page of multi-page snapshot: `has_more=true`, `snapshot_complete=false`, `next_page_token=Some(_)`.
- final page with target-state records: `has_more=false`, `snapshot_complete=true`, `next_page_token=None`.
- single-page snapshot with target-state records: `has_more=false`, `snapshot_complete=true`.

## Phase 4 — Bound Response Size Correctly

Ensure `max_items` bounds response payload according to chosen strategy.

If using unified pagination:

- `ip_blocks.len() + mesh_blocks.len() + target_state_records.len() <= max_items`.

If using section-aware pagination:

- each page should include at most `max_items` records from the active section(s), or define separate per-section limits.

If preserving separate block-entry pagination and target-state-once behavior:

- document that target-state records are separately bounded by `target_state_max_records` and can appear on one page;
- add an explicit cap or truncation reason if target-state is too large.

Preferred acceptance: `max_items` bounds the total record count in each snapshot response.

## Phase 5 — Avoid Duplicate Target-State Transfer Across Pages

Ensure each target-state record is sent at most once per snapshot sequence.

Tests:

- create snapshot with `N` target-state records and page size smaller than total items;
- collect all pages;
- assert no duplicate `(target_kind, site_scope, identifier)` target-state records across pages;
- assert all expected target-state records eventually appear.

This matters for bandwidth and for avoiding repeated stale/no-op apply noise.

## Phase 6 — Snapshot Block Apply and Target-State Timestamp Semantics

Review `apply_blocklist_snapshot()` path for block records.

Current concern:

- Applying a snapshot block via `block_ip_with_provenance()` or `block_mesh_id_with_provenance()` may record direct target state with `safe_unix_timestamp()`.
- That can make remote snapshot block state look newer than it really is.
- Future LWW comparisons may then reject legitimate older-but-authoritative target-state records or unblocks depending on ordering.

Preferred behavior:

- Snapshot block entry target-state should be recorded using `record.blocked_at` as timestamp, not local apply time.
- If a snapshot includes an explicit target-state record for the same target, that record should be authoritative for ordering metadata and applied after/with the block.
- If no target-state record exists, the block record can synthesize target state from `blocked_at`.

Possible implementation:

- Add internal helper to insert snapshot block entries without recording target state with local time.
- Or after applying via direct API, overwrite target state with a snapshot-derived `LastAppliedBlocklistEvent` timestamped at `record.blocked_at`, subject to LWW rules.
- Ensure this does not break direct admin/manual block semantics.

Tests:

- snapshot block with `blocked_at=T` results in target-state timestamp `T`, not apply time.
- newer local unblock at `T+10` prevents applying snapshot block at `T`.
- snapshot target-state at `T+20` can update after snapshot block at `T`.

## Phase 7 — Transport Flow Safety

Review `transport_peer.rs` snapshot response handling.

Ensure:

- next-page requests use returned `next_page_token` only when `has_more=true`;
- completion logs use `has_more=false`, not `snapshot_complete` if `snapshot_complete` can be stale during transition;
- after fixing `snapshot_complete`, completion logging can use either consistently;
- request ID is preserved across pages;
- no infinite loop if `has_more=true` but `next_page_token=None`;
- add a warning and stop if that invalid state appears.

Add guard:

```rust
if has_more && next_page_token.is_none() {
    warn!(...);
    return;
}
```

## Phase 8 — Docs Cleanup

Update:

- `architecture/blocklist_reconciliation.md`
- `architecture/blocklist_remove_consistency.md`
- `architecture/block_store.md` if present/relevant
- `AGENTS.md`

Docs must state:

- how snapshot pagination works;
- whether `max_items` applies to all records or only a section;
- what `snapshot_complete` means;
- target-state records are not duplicated across pages;
- snapshot block target-state timestamp semantics;
- snapshot remains control-plane-only, non-Raft, non-request-path.

## Phase 9 — Verification Commands

Run focused checks:

```bash
cargo test -p synvoid-block-store snapshot
cargo test -p synvoid-block-store target_state
cargo test -p synvoid-block-store stale
cargo test -p synvoid-mesh snapshot
cargo test -p synvoid-mesh catchup
cargo test -p synvoid-core blocklist
cargo test --test mesh_id_boundary_guard
cargo test --test manual_enforcement_provenance_guard
cargo test --test threat_intel_boundary_guard
cargo test --test threat_intel_consumer_actionability_guard
cargo test --lib --no-run
```

If wire/proto or cursor format changes:

```bash
cargo test --workspace --no-run
```

Adjust filters to actual test names.

## Acceptance Criteria

This cleanup is complete when:

1. Snapshot pagination covers IP blocks, mesh-ID blocks, and target-state records with explicit semantics.
2. `max_items` bounds the total response record count, or docs/tests clearly state and cap any exception.
3. Target-state records are not resent on every block-entry page.
4. `snapshot_complete` is true on the final page even when target-state records are present.
5. `has_more`, `next_page_token`, and `snapshot_complete` obey documented invariants.
6. Transport handles invalid pagination states safely.
7. Snapshot block apply does not record local apply time as ordering timestamp unless explicitly intended and tested.
8. Snapshot apply still preserves provenance.
9. Snapshot apply still respects newer local tombstones/blocks.
10. Existing catchup, blocklist, provenance, mesh-ID, and threat-intel guard tests still pass.

## Notes for the Implementer

This is a cleanup of a working feature. Do not expand scope into consensus, delete-absent reconciliation, or full persistent event logs.

The invariant is:

> Snapshot pagination must be complete, bounded, and non-duplicative; snapshot application must preserve the original ordering semantics of the records it transfers.
