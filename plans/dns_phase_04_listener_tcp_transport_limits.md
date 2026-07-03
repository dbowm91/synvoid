# DNS Phase 4: Listener Binding, TCP Lifecycle, and Transport Limits

## Objective

Make DNS listener startup and transport handling production-safe and testable. This phase closes the runtime boundary around UDP/TCP binding, TCP connection lifecycle, response-size limits, idle/read timeouts, graceful shutdown, and transport-specific behavior.

Milestone 1 already fixed the most visible issues: `dns.bind_address` is honored, DNS64 is passed into standard contexts, and TCP connection guards are held inside spawned tasks. Phase 4 turns those corrective fixes into a complete transport boundary.

## Current concerns

- UDP and TCP bind together to one configured address/port, but bind behavior, failure handling, and IPv4/IPv6 behavior need tests.
- Invalid bind address currently appears to fall back in startup logic instead of failing fast, even though config validation exists.
- TCP appears to process a single length-prefixed query and then return; this may be intentional, but it should be documented as one-query TCP or upgraded to persistent DNS-over-TCP semantics.
- TCP response-size validation logs oversize responses but may still send them.
- UDP/TCP shutdown is partially wired with oneshot channels; background cleanup tasks need shutdown policy clarity.
- DoT/DoH/DoQ adapters are outside this phase, but their shared DNS server clone/startup behavior should not regress.

## Primary files

- `crates/synvoid-dns/src/server/startup.rs`
- `crates/synvoid-dns/src/server/query.rs`
- `crates/synvoid-dns/src/limits.rs`
- `crates/synvoid-dns/src/query_validator.rs`
- `crates/synvoid-dns/src/server/response.rs`
- `crates/synvoid-config/src/dns/*`
- DNS runtime tests under `crates/synvoid-dns/tests/`

## Design requirements

Transport handling must have these invariants:

1. Listener bind address and port come from validated config.
2. Invalid config fails before socket bind; no silent fallback in production startup.
3. TCP connection limit guards live for the full connection-processing lifetime.
4. TCP behavior is explicitly one-query or persistent; implementation and docs agree.
5. UDP truncates by negotiated packet size; TCP does not apply UDP truncation semantics unless a TCP response exceeds configured hard limits.
6. Response-size validation is enforceable, not only logging.
7. Shutdown should stop UDP, TCP accept loop, and associated per-transport tasks without orphaned loops.

## Workstream 1: Bind-address policy

Tasks:

- Replace any startup fallback from invalid `bind_address` to `0.0.0.0` with fail-fast behavior.
- Rely on `DnsConfig::validate` where available, but keep startup robust when called directly.
- Add helper function if useful:

```rust
fn configured_bind_addr(config: &DnsConfig) -> Result<SocketAddr, String>
```

- Test IPv4 explicit bind address construction.
- Test IPv6 explicit bind address construction.
- Test invalid bind address errors.
- Test port zero behavior through config validation, not runtime fallback.

Acceptance criteria:

- No production startup path silently changes a configured bind address.
- Bind-address behavior is unit-tested without requiring privileged port 53.

## Workstream 2: UDP receive/send boundary

Tasks:

- Ensure UDP buffer size comes from config and is bounded by sane min/max values.
- Verify queries larger than configured UDP buffer are handled as truncation or validation failure according to policy.
- Ensure UDP responses honor EDNS UDP payload size, default 512 fallback, and max configured response size.
- Ensure RRL/rate-limit decisions happen before expensive work where possible.
- Ensure firewall and validator errors emit deterministic responses or drops according to policy.
- Add tracing fields for transport=`udp`, client IP, qname if parsed, qtype, response length, and decision class.

Tests:

- UDP buffer-size helper tests.
- Oversized UDP positive response sets TC.
- EDNS 4096 response avoids TC when under 4096.
- RRL drop path does not send response.
- Firewall block path drops or REFUSEDs exactly as configured.

Acceptance criteria:

- UDP behavior is deterministic and packet-size aware.
- UDP path has sufficient logs for debugging drops versus responses.

## Workstream 3: TCP lifecycle policy

Tasks:

- Decide whether TCP is intentionally one-query-per-connection or persistent DNS-over-TCP.
- If one-query: document this limitation and name the handler accordingly, for example `handle_single_tcp_query`.
- If persistent: implement read loop with idle timeout, maximum queries per connection, response writes per query, and clean close.
- Keep connection guard live across the full loop/task lifetime.
- Ensure per-query validation, firewall, RRL, cache, coalescing, and zone transfer dispatch remain correct.
- For AXFR/IXFR, ensure multi-message responses use TCP only and bypass ordinary single-message response size assumptions.

Tests:

- TCP guard is retained during query processing.
- TCP idle timeout closes quiet connection.
- TCP malformed length prefix fails deterministically.
- TCP response includes two-byte length prefix.
- TCP AXFR/IXFR path uses parsed query question end for TSIG.
- If persistent mode is selected, multiple queries on one connection work.

Acceptance criteria:

- TCP lifecycle is intentional, tested, and documented.
- Connection limits are enforced by active lifetime, not accept-time only.

## Workstream 4: Transport response-size limits

Tasks:

- Separate UDP payload-size truncation from hard response-size safety limits.
- Define behavior for TCP response above `max_tcp_response_size`: REFUSED, SERVFAIL, close connection, or stream zone-transfer chunks where appropriate.
- Make `ConnectionLimits::validate_response_size` result actionable instead of only warning.
- Add metrics for response-too-large by transport.
- Ensure TC is not used incorrectly as a substitute for TCP hard-limit errors.

Tests:

- UDP oversize -> TC.
- TCP ordinary oversize -> configured hard-limit behavior.
- AXFR multi-message can exceed ordinary response size through chunking only when allowed.
- Hard-limit error does not write malformed partial response.

Acceptance criteria:

- Response-size handling is explicit per transport.
- Oversize TCP responses are not silently sent after warning.

## Workstream 5: Shutdown and background task hygiene

Tasks:

- Review UDP task, TCP task, coalescer cleanup task, key rotation task, and recursive server task shutdown behavior.
- Add cancellation token or structured task handle if oneshot does not cover all tasks.
- Ensure `DnsServer::shutdown` signals all runtime loops and waits or exposes handles where feasible.
- Ensure cloned `DnsServer` instances used by DoT/DoH/DoQ do not hold stale shutdown channels or untracked handles.

Tests:

- Startup then shutdown releases UDP/TCP ports in a test using ephemeral port.
- Coalescer cleanup task stops or is explicitly documented as process-lifetime.
- Multiple shutdown calls are idempotent.

Acceptance criteria:

- Runtime tasks do not leak under normal start/stop integration tests.
- Ports are reusable after shutdown.

## Workstream 6: Documentation

Update DNS architecture docs with:

- Bind-address fail-fast policy.
- UDP truncation policy.
- TCP lifecycle mode.
- Transport response-size behavior.
- Shutdown limitations if any remain.

## Verification commands

```bash
cargo fmt --all --check
cargo test -p synvoid-dns transport
cargo test -p synvoid-dns limits
cargo test -p synvoid-dns
cargo check -p synvoid-dns --all-features
cargo check --workspace
```

## Completion criteria

Phase 4 is complete when transport startup is deterministic, bind behavior is fail-fast and tested, TCP lifecycle policy is explicit, connection limits hold across task lifetime, UDP/TCP response-size behavior is enforceable, and start/stop does not leave orphaned listener tasks in normal tests.
