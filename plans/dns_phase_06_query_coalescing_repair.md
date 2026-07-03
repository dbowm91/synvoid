# DNS Phase 6: Query Coalescing Repair and Hardening

## Objective

Make DNS query coalescing safe, measurable, and production-usable. Query coalescing should reduce duplicate concurrent work for equivalent DNS questions without creating stale responses, privacy leaks, DNSSEC shape mismatches, or timeout latency.

Milestone 1 introduced parsed-query keys and owner broadcast behavior. Phase 6 verifies and hardens the complete lifecycle.

## Current concerns

- The corrective pass added `QueryKey::from_parsed` and broadcast-on-owner, but concurrency behavior needs dedicated tests.
- Coalescing key dimensions must reflect all output-affecting inputs: qname, qtype, qclass, DO bit, EDNS response-size class if relevant, client IP/ECS/view, transport, and policy dimensions.
- Waiter timeout and owner cancellation semantics must clean up in-flight entries.
- Negative responses should coalesce when safe.
- Coalescing must not leak one client's policy-shaped answer to another client.

## Primary files

- `crates/synvoid-dns/src/query_coalesce.rs`
- `crates/synvoid-dns/src/server/startup.rs`
- `crates/synvoid-dns/src/server/query.rs`
- `crates/synvoid-dns/src/parsed_query.rs`
- `crates/synvoid-dns/src/cache.rs`
- `crates/synvoid-dns/src/metrics.rs`
- `crates/synvoid-config/src/dns/dns_settings.rs`
- DNS coalescing tests

## Required invariants

1. Only semantically equivalent queries coalesce.
2. First query becomes owner; later equivalent queries wait.
3. Owner success broadcasts exact response to waiters.
4. Owner failure cancels the in-flight key and waiters do not hang indefinitely.
5. Timeouts remove or expire in-flight entries deterministically.
6. DNSSEC DO and EDNS-affecting differences do not share responses incorrectly.
7. Client-policy-shaped answers do not cross client/view boundaries.
8. Coalescing disabled means no coalescing overhead.

## Workstream 1: Key dimension audit

Tasks:

- Define a `QueryKeyPolicy` or document fixed key dimensions.
- Include at least:
  - canonical qname
  - qtype
  - qclass
  - DO bit
  - client IP or ECS scope when geo/view/firewall/DNS64/policy can affect answer
  - transport if response shape differs by UDP/TCP
  - EDNS UDP payload bucket if truncation behavior can differ
- Decide whether RD/CD bits affect authoritative answer shape. If not, document why they are excluded.
- Ensure case folding follows DNS semantics while preserving response question echo elsewhere.
- Add unit tests for every key dimension.

Acceptance criteria:

- Key equivalence is explicit and tested.
- Queries that can produce different response bytes do not coalesce accidentally.

## Workstream 2: Owner/waiter lifecycle tests

Tasks:

- Add async tests using Tokio for `QueryCoalescer` directly.
- Test first caller receives `NewQuery`.
- Test second identical caller waits and receives broadcast response.
- Test multiple waiters all receive response.
- Test owner cancellation wakes or times out waiters according to policy.
- Test cleanup removes in-flight state after broadcast.
- Test repeated query after broadcast becomes a new owner unless served by cache.

Acceptance criteria:

- Coalescing behavior is deterministic under concurrency tests.
- No normal success path leaves waiters to timeout.

## Workstream 3: Failure and timeout semantics

Tasks:

- Define behavior when owner returns `None`, panics inside task, or produces validation/firewall drop.
- Ensure `cancel_in_flight` removes entry and notifies waiters if possible.
- Add bounded waiter timeout and metric for timeout.
- Ensure owner cannot leave permanent in-flight entries.
- Add cleanup interval tests using short durations.

Tests:

- Owner returns no response -> waiters complete with miss/cancel outcome.
- Owner times out -> in-flight removed.
- Cleanup task removes stale entries.
- Late broadcast after cleanup is ignored safely.

Acceptance criteria:

- Coalescer cannot wedge a key indefinitely.
- Timeout behavior is observable in metrics/logs.

## Workstream 4: Server integration

Tasks:

- Review UDP and TCP integration to ensure owner path always broadcasts success or cancels failure.
- Ensure cache hits bypass owner creation where possible, or document if cache sits behind coalescing.
- Confirm negative responses broadcast safely.
- Ensure zone transfer, UPDATE, NOTIFY, malformed queries, and firewall drops are excluded from coalescing unless explicitly safe.
- Ensure coalescing does not apply to AXFR/IXFR multi-message responses.

Tests:

- Two concurrent identical UDP-style queries share work.
- Positive response coalesces.
- NODATA coalesces.
- NXDOMAIN coalesces.
- REFUSED no-zone behavior either coalesces safely or is excluded by policy.
- AXFR/IXFR are not coalesced.
- UPDATE/NOTIFY are not coalesced.

Acceptance criteria:

- Server paths use coalescing only for safe single-response query classes.

## Workstream 5: Metrics and observability

Tasks:

- Add or wire metrics:
  - coalescing enabled gauge
  - owner count
  - waiter hit count
  - broadcast count
  - cancel count
  - timeout count
  - cleanup stale count
  - in-flight current count
- Add structured logs with qname redaction if qname privacy is enabled.
- Ensure metrics labels avoid high-cardinality qname by default.

Acceptance criteria:

- Operators can tell whether coalescing is helping or causing latency.
- No high-cardinality metrics are emitted by default.

## Workstream 6: Configuration and defaults

Tasks:

- Verify coalescing is disabled/enabled by config only.
- Confirm default max wait and cleanup interval are safe.
- Add config validation for nonsensical intervals.
- Document recommended settings for authoritative mode and recursive mode.

Acceptance criteria:

- Coalescing config is safe by default and test-covered.

## Verification commands

```bash
cargo fmt --all --check
cargo test -p synvoid-dns query_coalesce
cargo test -p synvoid-dns coalescing
cargo test -p synvoid-dns
cargo check -p synvoid-dns --all-features
cargo check --workspace
```

## Completion criteria

Phase 6 is complete when query coalescing has explicit key semantics, deterministic owner/waiter behavior, safe cancellation/timeout cleanup, server integration tests, metrics, and config-driven enablement with no unsafe sharing across policy-affecting dimensions.
