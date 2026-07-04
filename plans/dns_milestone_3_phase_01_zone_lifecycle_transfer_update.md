# DNS Milestone 3 Phase 1: Zone Lifecycle, Transfer, Update, and NOTIFY Correctness

## Objective

Harden authoritative zone lifecycle behavior beyond the Milestone 1/2 query-serving foundation. This phase focuses on zone load/store/reload, serial semantics, dynamic update, NOTIFY, AXFR, IXFR, TSIG policy, cache invalidation, and safe operational behavior around zone mutation.

## Context

Milestone 1 established core authoritative response correctness. Milestone 2 established runtime/config/cache/coalescing safety. Milestone 3 begins advanced DNS feature trustworthiness. Zone mutation and transfer are high-risk because they can corrupt authoritative data, leak zones, or leave stale cache entries.

## Non-goals

Do not implement full DNSSEC signing lifecycle in this phase except where zone mutation must trigger DNSSEC cache invalidation or signing hooks. Do not expand recursive resolver behavior. Do not add new transport protocols.

## Primary files

- `crates/synvoid-dns/src/server/zone.rs`
- `crates/synvoid-dns/src/server/mod.rs`
- `crates/synvoid-dns/src/update.rs`
- `crates/synvoid-dns/src/notify.rs`
- `crates/synvoid-dns/src/transfer.rs`
- `crates/synvoid-dns/src/zone_file.rs`
- `crates/synvoid-dns/src/store.rs`
- `crates/synvoid-dns/src/cache.rs`
- `crates/synvoid-dns/src/metrics.rs`
- `crates/synvoid-config/src/dns/*`
- DNS architecture docs and config matrix

## Workstream 1: Zone lifecycle state model

Tasks:

- Define explicit zone states: loading, active, reloading, disabled, failed, deleting.
- Ensure failed zone load cannot leave a half-active zone.
- Ensure reload is atomic from query-handler perspective.
- Preserve old active zone on failed reload unless configuration says fail-closed.
- Add per-zone health/error metadata: last load time, last error, serial, record count, DNSSEC state.
- Ensure zone origin normalization is consistent.

Tests:

- invalid zone load fails without replacing valid zone.
- reload success swaps atomically.
- reload failure preserves previous zone or fails closed according to policy.
- origin normalization handles trailing dot consistently.

Acceptance criteria:

- query path never sees half-loaded zone data.
- operator can identify zone load failures.

## Workstream 2: SOA and serial correctness

Tasks:

- Audit SOA parsing, validation, and emission.
- Enforce one apex SOA per authoritative zone unless multi-SOA policy is explicitly supported.
- Ensure serial arithmetic follows RFC 1982 comparison semantics.
- Ensure dynamic update and transfer apply bump or preserve serial according to DNS semantics.
- Ensure serial monotonicity policy is documented.
- Add helper for comparing serials safely across wraparound.

Tests:

- missing SOA rejected.
- multiple SOA rejected or deterministic policy tested.
- serial increment across wraparound.
- IXFR serial comparison uses RFC 1982 semantics.
- dynamic update serial policy tested.

Acceptance criteria:

- SOA and serial behavior is deterministic and protocol-aware.

## Workstream 3: Dynamic UPDATE policy

Tasks:

- Verify UPDATE is disabled by default.
- Enforce allowlists, TSIG requirements, zone existence, record-type policy, and maximum update size.
- Ensure prerequisites are evaluated correctly before mutation.
- Make update application atomic.
- Invalidate cache entries for affected names and negative entries.
- Emit metrics for accepted, refused, failed, malformed, and unauthorized updates.
- Add audit logs without leaking sensitive TSIG material.

Tests:

- UPDATE disabled returns configured error.
- unauthorized client refused.
- missing/invalid TSIG refused when required.
- prerequisite failure does not mutate zone.
- successful add/delete mutates zone atomically.
- cache invalidation after add/delete.
- malformed update fails without partial mutation.

Acceptance criteria:

- UPDATE cannot partially mutate zone or bypass authorization.

## Workstream 4: NOTIFY handling

Tasks:

- Verify NOTIFY is disabled unless configured.
- Enforce source allowlist and optional TSIG.
- Decide master/secondary behavior for this project.
- If acting as secondary, validate SOA serial before transfer.
- Rate-limit NOTIFY to prevent transfer storms.
- Ensure NOTIFY does not trigger transfer for unknown zones unless explicitly allowed.
- Emit metrics/logs for accepted/refused/ignored NOTIFY.

Tests:

- NOTIFY disabled policy response.
- unknown-zone NOTIFY refused/ignored.
- unauthorized source refused.
- stale serial does not trigger transfer.
- newer serial triggers transfer scheduling if secondary behavior exists.

Acceptance criteria:

- NOTIFY cannot create unbounded transfer work or unauthorized zone changes.

## Workstream 5: AXFR hardening

Tasks:

- Ensure AXFR is disabled by default unless explicitly allowed.
- Enforce allowlists and TSIG consistently.
- Verify multi-message framing and SOA bracketing.
- Ensure TCP-only behavior.
- Apply response-size and connection limits appropriately for transfers.
- Avoid coalescing and ordinary cache handling for AXFR.
- Add transfer metrics.

Tests:

- AXFR over UDP refused/not supported.
- AXFR denied without allowlist match.
- AXFR denied without TSIG when required.
- AXFR emits opening and closing SOA.
- AXFR message order deterministic.
- AXFR does not enter ordinary cache/coalescing path.

Acceptance criteria:

- AXFR cannot leak zones without explicit authorization.

## Workstream 6: IXFR correctness

Tasks:

- Verify IXFR disabled/enabled config behavior.
- Define history retention policy and memory/storage limits.
- Use RFC 1982 serial comparison.
- Fallback to AXFR only when configured and authorized.
- Ensure deltas are complete and ordered.
- Ensure transfer apply invalidates cache variants.

Tests:

- IXFR denied when disabled.
- IXFR from current serial returns no-op response.
- IXFR from older serial returns ordered deltas.
- IXFR too old falls back or refuses based on config.
- malformed IXFR request refused.

Acceptance criteria:

- IXFR behavior is deterministic and bounded.

## Workstream 7: Store persistence and recovery

Tasks:

- Audit zone store save/load error propagation.
- Ensure zone writes are atomic or journaled.
- Ensure startup handles corrupt store records deterministically.
- Add backup/rollback strategy for zone mutation if store write fails.
- Ensure dynamic update does not acknowledge success before durable write if durability is required.

Tests:

- store save failure causes update failure or documented degraded mode.
- corrupt stored zone rejected.
- restart reloads last committed zone.
- failed store write does not mutate active in-memory zone unless policy allows volatile mode.

Acceptance criteria:

- zone persistence cannot silently lose or corrupt authoritative data.

## Workstream 8: Cache invalidation and DNSSEC hooks

Tasks:

- On every accepted zone mutation, invalidate all affected authoritative cache variants.
- Invalidate DNSSEC-shaped records when DNSSEC keys/signatures/proofs are affected.
- For zone-wide transfer/reload, invalidate entire zone.
- Add invalidation metrics by reason.
- Add signing hook placeholders if DNSSEC phase needs re-sign scheduling.

Tests:

- update add invalidates previous NXDOMAIN.
- update delete invalidates previous positive response.
- AXFR apply invalidates zone.
- IXFR apply invalidates affected names.
- DNSSEC key/signature change invalidates signed answers.

Acceptance criteria:

- stale authoritative answers cannot survive zone mutation.

## Workstream 9: Documentation and operator guidance

Update:

- `architecture/dns.md`
- `architecture/dns_config_runtime_matrix.md`
- DNS ops docs if present

Document:

- safe authoritative primary profile;
- safe secondary profile;
- transfer/update defaults;
- TSIG requirements;
- serial policy;
- cache invalidation behavior;
- deferred limitations.

## Verification commands

```bash
cargo fmt --all --check
cargo test -p synvoid-dns update
cargo test -p synvoid-dns notify
cargo test -p synvoid-dns transfer
cargo test -p synvoid-dns zone
cargo test -p synvoid-dns cache
cargo check -p synvoid-dns --all-features
cargo check --workspace
```

## Completion criteria

Phase 1 is complete when zone lifecycle is atomic, dynamic update/NOTIFY/AXFR/IXFR enforce config and authorization, store failures are handled deterministically, mutation invalidates cache variants, and docs accurately describe safe operation.
