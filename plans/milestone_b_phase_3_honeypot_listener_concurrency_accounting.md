# Milestone B Phase 3: Honeypot Listener Concurrency and Accounting

## Purpose

Harden the honeypot listener runtime so it behaves predictably under scanner bursts, connection floods, malformed clients, and slow clients. This phase targets listener correctness, connection admission, per-IP accounting, payload capture limits, timeout semantics, and connection record accuracy.

The honeypot should remain low/medium interaction, but it must not become an easy memory, task, or file-descriptor exhaustion target.

## Current issues to address

1. Global active connection limiting can race because the active counter is checked before spawned tasks increment it. A burst of accepted sockets can exceed the configured max.
2. Per-IP connection counts are decremented but zero-count entries may remain, allowing the map to grow with unique scanner IPs.
3. `max_payload_size` is not strictly enforced; payload capture is limited by a small number of reads rather than the configured maximum.
4. Initial read appears to use `connection_timeout_ms`; subsequent read uses `read_timeout_ms`, but semantics need to be explicit and tested.
5. Accounting records only the first read size in some paths rather than total bytes received.
6. Bytes sent may not include all response bytes.
7. Service/protocol identification and banner selection may pass display service names where normalized protocol names are expected; this is primarily Phase 4 but the listener should pass normalized fields.
8. Shutdown behavior should not leak permits, per-IP counts, or tasks.

## Non-goals

- Do not redesign the honeypot storage backend in this phase, except for accounting fields needed by listener correctness.
- Do not add AI responder safety work here. That belongs to later Milestone C work.
- Do not implement threat-intel scoring changes here. That belongs to later deception/actionability work.
- Do not expand the protocol detector here beyond normalizing caller/callee boundaries needed by the listener.

## Implementation plan

### 1. Replace active counter admission with a semaphore

Use a `tokio::sync::Semaphore` or equivalent admission guard for global active connections.

Expected flow:

1. Accept socket.
2. Acquire global connection permit before spawning handler.
3. If no permit is available, drop/close socket and record a rejection metric.
4. Acquire/update per-IP permit/count.
5. Spawn handler with owned permit guards.
6. Permit guards release automatically on handler exit, timeout, error, or shutdown.

Avoid check-then-increment races. The permit must be acquired before the task is considered admitted.

### 2. Add per-IP bounded admission with cleanup

Preferred option:

- Use per-IP semaphores with a bounded/TTL map.
- Remove entries when the count reaches zero.
- Optionally cap total tracked IP entries to prevent map growth from random-source scans.

Low-churn option:

- Keep the existing map but remove IP entries when count reaches zero.
- Ensure all early-return paths release/decrement through guard types.

Add an RAII guard for per-IP accounting if using manual counts.

### 3. Enforce payload capture limits

Revise `handle_connection` read loop:

- Read until EOF, timeout, or `max_payload_size` reached.
- Never allocate beyond `max_payload_size`.
- If incoming data exceeds `max_payload_size`, truncate capture and set a `payload_truncated` flag in metadata/record if available.
- Continue or close according to configured behavior; default can close after max capture.
- Avoid unbounded `Vec` growth.

If storage schema cannot add `payload_truncated` now, include it in metadata JSON or a follow-up note.

### 4. Clarify timeout semantics

Define and document:

- `connection_timeout_ms`: time allowed for first meaningful client data or total idle connect setup.
- `read_timeout_ms`: idle timeout between subsequent reads.
- optional `max_connection_duration_ms`: total cap if needed; otherwise document absence.

Tests should prove:

- idle client is closed after initial timeout
- slow client is closed after read timeout
- active client can send multiple chunks up to max payload size
- handler exits and releases permits after timeout

### 5. Correct byte accounting

Record:

- total bytes received across all reads, capped at payload capture limit or actual received if tracked separately
- total bytes sent across banner + generated response writes
- duration in milliseconds with saturating cast if storage uses `u32`
- whether payload was truncated, if schema/metadata supports it

Do not report only the first read as total bytes received.

### 6. Normalize protocol/service handoff

Listener should pass normalized protocol identifiers to banner/responder selection. Avoid passing display labels like `HTTP` to functions expecting `http`.

This can be fully completed in Phase 4, but Phase 3 should stop making the mismatch worse:

- Store both display service and normalized protocol if available.
- Use normalized protocol for banner lookup.
- Use display/service name for logs/UI only.

### 7. Add metrics/logging

Add or confirm counters for:

- accepted connections
- rejected due to global limit
- rejected due to per-IP limit
- timed out waiting for first data
- timed out during read
- payload truncated
- handler errors
- storage insert failures

Logs should include remote IP, local port, detected protocol, bytes received, bytes sent, duration, and rejection reason where appropriate. Avoid logging raw payload by default.

### 8. Tests

Add unit/integration tests using local loopback sockets where possible.

Required tests:

- global limit: with max concurrent set to 1, second simultaneous client is rejected or held according to chosen semantics.
- burst admission: many simultaneous connects never exceed max active permits.
- per-IP limit: max per IP is enforced.
- per-IP cleanup: after connections close, map entries are removed or count returns to zero without retaining empty entries.
- payload limit: data larger than `max_payload_size` is truncated and does not allocate beyond limit.
- multi-read accounting: two or more reads record total bytes, not first read only.
- bytes sent accounting: banner + response sizes are included.
- initial timeout releases permits.
- read timeout releases permits.
- shutdown releases permits and exits listener loop.

If full listener tests are hard because of port binding/races, factor the admission/accounting logic into smaller testable units and add one end-to-end smoke test.

## Storage compatibility

Avoid breaking existing SQLite schema unless needed. Prefer metadata additions for new fields such as `payload_truncated`. If schema changes are required, include migration logic and tests.

## Local validation commands

Minimum:

```bash
cargo fmt --all -- --check
cargo clippy -p synvoid-honeypot --all-targets -- -D warnings
cargo test -p synvoid-honeypot --all-targets
```

Preferred:

```bash
cargo test -p synvoid-honeypot --features mesh --all-targets
cargo test -p synvoid-honeypot --all-features --all-targets
cargo test --workspace -p synvoid-honeypot -p synvoid-upload
```

If port-binding tests are flaky locally, mark only the loopback stress variants as ignored and provide deterministic unit tests for the core admission guards. Do not ignore all listener correctness coverage.

## Success criteria

- Global max concurrent connections is enforced race-free.
- Per-IP limit is enforced and does not leak zero-count entries.
- Payload capture never exceeds `max_payload_size`.
- Byte accounting records total received/sent bytes.
- Timeouts release all permits/counts.
- Shutdown does not leak tasks or admission state.
- Listener passes normalized protocol identifiers to banner/responder lookup.
- Tests cover admission, timeout, accounting, and cleanup behavior.

## Handoff notes

This phase sets up Phase 4 by giving protocol detection a clean caller boundary. If protocol detection remains imperfect after Phase 3, listener records should still carry enough normalized/contextual data for Phase 4 to fix detection without another listener refactor.
