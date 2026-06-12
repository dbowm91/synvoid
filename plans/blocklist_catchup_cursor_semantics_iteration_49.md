# Blocklist Catchup Cursor Semantics — Iteration 49

## Purpose

Iteration 48 added bounded blocklist event replay for offline-peer catchup. The event log and catchup architecture are sound, but there is a small cursor-semantics edge case that should be closed before treating the reconciliation path as mature.

Current documentation says reconnect catchup uses `since_sequence: 0` for “full catchup on connect,” while `BlocklistEventCursor` semantics say events with `sequence > since_sequence` are returned. If the first event has sequence `0`, a request with `since_sequence: 0` will skip that first event.

This pass should define an unambiguous “from beginning” cursor, update the wire/API semantics, add tests for first-event replay, and align docs.

## Current Known State

From Iteration 48:

- `BlocklistEventLog` assigns local monotonically increasing sequence numbers starting at `0`.
- `BlocklistEventCursor { since_sequence, max_events }` returns events with sequence greater than `since_sequence`.
- `query_since()` infers `oldest_seq` from `next_sequence - events.len()`.
- Docs say peer reconnect sends `since_sequence: 0` for full catchup.
- This can skip event sequence `0` if “full catchup” is intended.
- `snapshot_required` is used when requested history has already been evicted.

## Non-Goals

Do not redesign offline-peer reconciliation.

Do not add persistent cursors.

Do not add full snapshot fallback.

Do not change request/WAF path behavior.

Do not add Raft or acknowledged delivery.

Do not change event log retention policy except as needed for cursor semantics.

## Phase 1 — Choose Explicit Cursor Semantics

Pick one clear model.

### Recommended Option A — Optional Cursor / FromStart Variant

Represent “from beginning” explicitly.

Possible Rust shape:

```rust
pub enum BlocklistEventCursor {
    FromStart { max_events: u32 },
    AfterSequence { since_sequence: u64, max_events: u32 },
}
```

or:

```rust
pub struct BlocklistEventCursor {
    pub since_sequence: Option<u64>,
    pub max_events: u32,
}
```

Semantics:

- `since_sequence: None` means from the oldest retained event.
- `since_sequence: Some(n)` means return events with sequence `> n`.

This is the cleanest API.

### Acceptable Option B — Sentinel Value

Use `since_sequence = u64::MAX` or similar as “from beginning.”

This avoids protobuf optional changes but is less readable. Use only if wire compatibility strongly favors it.

### Acceptable Option C — Start Sequence at 1

Make first event sequence `1`, so `since_sequence: 0` means from beginning.

This is simple but requires careful update to `oldest_seq` math and docs.

Recommended: **Option A** if protobuf/serde compatibility allows optional fields; otherwise Option C.

## Phase 2 — Update Wire Contract

Update `BlocklistCatchupRequest` to express from-start cleanly.

If using Option A:

- make `since_sequence` optional;
- absent `since_sequence` means from beginning;
- present `since_sequence` means exclusive cursor.

If protobuf syntax already supports `optional uint64`, use it. If not, add:

```proto
bool from_start = ...;
uint64 since_sequence = ...;
```

Rules:

- `from_start=true` ignores `since_sequence`.
- `from_start=false` uses `since_sequence` as exclusive cursor.

Avoid ambiguous `0` semantics.

## Phase 3 — Update `BlocklistEventLog::query_since`

Make the query implementation match the chosen semantics.

Required tests:

- log has sequence `0`; from-start returns event `0`;
- `AfterSequence(0)` returns sequence `1+` only;
- empty log from-start returns empty complete result;
- history gap detection still works for an evicted cursor;
- max event limit still applies.

Implementation considerations:

- If cursor is from-start, `first_idx = 0`.
- If cursor is after sequence, current `sequence > since_sequence` logic is correct.
- `latest_sequence` should continue to report the newest retained/appended sequence.
- `snapshot_required` should be false for from-start unless the log had already evicted history and the caller expected complete from genesis; document this carefully.

For from-start after retention has already evicted early events, decide whether `history_complete` should be true or false.

Recommended:

- `from_start` means “from the oldest retained event,” not “from genesis.”
- If caller needs genesis-complete history, it must use a separate snapshot/digest path.
- Docs must say this explicitly.

## Phase 4 — Update Peer Reconnect Catchup

Update peer reconnect logic to use the new from-start form.

Current doc says:

```text
since_sequence: 0 (full catchup on connect)
```

Replace with:

```text
from_start=true
```

or:

```text
since_sequence=None
```

depending on implementation.

Ensure any conversion helpers map the request correctly across protobuf/Rust types.

## Phase 5 — Update Supervisor/Worker Replay If Needed

If worker replay uses the same cursor type, update it too.

Required behavior:

- worker replay from beginning of supervisor retained log includes supervisor event sequence `0`;
- replay after known cursor remains exclusive;
- existing worker-ready replay tests updated.

## Phase 6 — Documentation

Update:

- `architecture/blocklist_reconciliation.md`
- `architecture/blocklist_remove_consistency.md` if it mentions catchup cursor behavior
- `AGENTS.md` if cursor semantics are included there
- protobuf comments / generated docs if present

Docs must state:

- sequence numbers are source-local;
- from-start means from oldest retained event, not necessarily from genesis;
- after-sequence cursor is exclusive;
- reconnect catchup uses from-start only when no prior cursor exists;
- if a retained-history gap is detected, `snapshot_required=true`;
- request/WAF path remains local-only.

## Phase 7 — Tests

Add focused tests.

### Event log cursor tests

- `from_start_includes_sequence_zero`.
- `after_sequence_zero_skips_sequence_zero`.
- `from_start_empty_log_complete`.
- `after_evicted_sequence_sets_snapshot_required`.
- `max_events_limits_from_start`.
- `latest_sequence_reports_newest_sequence`.

### Wire conversion tests

- protobuf request with from-start maps to from-start cursor.
- protobuf request with since sequence maps to exclusive cursor.
- response encode/decode still preserves latest sequence, timestamp, snapshot flag.

### Peer/worker tests, if existing harness permits

- reconnect request uses from-start when no cursor is available.
- worker replay from start includes first retained event.

## Verification Commands

Run focused checks:

```bash
cargo test -p synvoid-block-store catchup
cargo test -p synvoid-block-store cursor
cargo test -p synvoid-mesh catchup
cargo test -p synvoid-mesh blocklist_event
cargo test --lib supervisor
cargo test --lib blocklist
cargo test --test manual_enforcement_provenance_guard
cargo test --test threat_intel_boundary_guard
cargo test --lib --no-run
```

If protobuf changed:

```bash
cargo test --workspace --no-run
```

Adjust filters to actual test names.

## Acceptance Criteria

This pass is complete when:

1. “From start” catchup semantics are explicit and unambiguous.
2. A reconnect catchup with no prior cursor replays sequence `0` if it is still retained.
3. Exclusive `since_sequence` behavior remains available and tested.
4. Wire/protobuf request fields no longer rely on ambiguous `since_sequence: 0` semantics.
5. History gap and `snapshot_required` behavior remain correct.
6. Supervisor/worker replay, if affected, uses the same semantics.
7. Docs accurately describe retained-history replay, not genesis-complete replay.
8. Request/WAF paths remain untouched.

## Notes for the Implementer

This is a narrow semantic cleanup. Do not expand it into persistent cursors, full snapshot fallback, or acknowledged delivery.

The invariant is:

> A catchup cursor must never silently skip the first retained event when the caller asks to replay from the beginning.
