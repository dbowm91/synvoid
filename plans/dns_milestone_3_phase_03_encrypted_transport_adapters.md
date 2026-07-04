# DNS Milestone 3 Phase 3: DoT, DoH, and DoQ Adapter Correctness

## Objective

Harden encrypted DNS transport adapters so DoT, DoH, and DoQ faithfully preserve the DNS core semantics established in Milestones 1 and 2. This phase focuses on adapter boundaries: framing, TLS/QUIC configuration, HTTP semantics, transport-class propagation, limits, shutdown, observability, and conformance smoke tests.

## Context

The core UDP/TCP authoritative path is now substantially stronger. Encrypted transports must not reintroduce bypasses around parsing, cache keys, response flags, truncation policy, coalescing exclusions, rate limits, firewall checks, DNS64/ECS policy, or shutdown behavior.

## Non-goals

Do not redesign the core DNS query handler. Do not expand DNSSEC correctness except where encrypted transport affects DO/EDNS handling. Do not add recursive resolver features except safe adapter routing.

## Primary files

- `crates/synvoid-dns/src/dot.rs`
- `crates/synvoid-dns/src/doh.rs`
- `crates/synvoid-dns/src/doq.rs`
- `crates/synvoid-dns/src/server/startup.rs`
- `crates/synvoid-dns/src/server/query.rs`
- `crates/synvoid-dns/src/cache.rs`
- `crates/synvoid-dns/src/query_coalesce.rs`
- `crates/synvoid-dns/src/limits.rs`
- `crates/synvoid-dns/src/metrics.rs`
- `crates/synvoid-config/src/dns/*`
- encrypted transport tests

## Workstream 1: Shared adapter contract

Tasks:

- Define a shared internal contract for all DNS transports:
  - parse once;
  - validate/firewall before expensive work;
  - pass accurate transport class;
  - preserve client identity policy;
  - route cache/coalescing consistently;
  - enforce transport limits;
  - emit structured metrics.
- Ensure DoT/DoH/DoQ call the same parsed-query cache path or document why not.
- Ensure adapter behavior does not duplicate stale parsing/response logic.

Acceptance criteria:

- encrypted adapters are thin wrappers over the core query engine.
- core DNS semantics are not forked per transport.

## Workstream 2: DoT correctness

Tasks:

- Verify TLS listener config, certificate loading, key permissions, and reload policy.
- Verify DNS-over-TCP framing over TLS: two-byte length prefix, complete reads, bounded message size.
- Decide one-query versus persistent DoT policy; align with TCP policy.
- Enforce idle timeout and connection limits.
- Use `TransportClass::Tcp` or a distinct DoT class if response shape differs.
- Ensure DoT does not set RA/AD incorrectly.
- Ensure shutdown drains listener and active tasks.

Tests:

- valid DoT query receives length-prefixed DNS response.
- malformed length prefix rejected.
- oversized query rejected.
- invalid certificate config fails startup.
- idle timeout closes connection.
- cache key uses encrypted transport policy.

Acceptance criteria:

- DoT adapter preserves TCP DNS semantics and TLS config is fail-fast.

## Workstream 3: DoH correctness

Tasks:

- Verify DoH route and methods: GET and POST policy.
- Enforce `application/dns-message` content type for POST.
- Decode GET `dns=` parameter safely if supported.
- Enforce HTTP body size limits.
- Return correct HTTP status codes for malformed HTTP versus DNS FORMERR semantics.
- Preserve DNS response wire bytes exactly in body.
- Set appropriate headers: content type, cache-control policy, length where feasible.
- Use `TransportClass::Http`.
- Ensure client identity extraction respects proxy headers only when trusted.

Tests:

- POST valid DNS message returns DNS wire body.
- POST wrong content type rejected.
- GET valid base64url query works if supported.
- malformed DNS request returns valid error policy.
- response content type correct.
- oversized body rejected.
- untrusted forwarded-for ignored.

Acceptance criteria:

- DoH follows expected HTTP semantics without weakening DNS policy.

## Workstream 4: DoQ correctness

Tasks:

- Verify QUIC listener config, certificate loading, ALPN policy, and port defaults.
- Map QUIC streams/datagrams to DNS query processing according to intended support.
- Enforce per-stream message size and connection limits.
- Use `TransportClass::Quic`.
- Ensure shutdown closes QUIC endpoint and active connections.
- Document unsupported DoQ features explicitly.

Tests:

- valid DoQ stream receives DNS response.
- malformed query rejected.
- oversized message rejected.
- invalid TLS/ALPN config fails.
- shutdown releases endpoint.

Acceptance criteria:

- DoQ support is either correctly bounded and tested or clearly marked experimental/deferred.

## Workstream 5: Transport class and cache/coalescing integration

Tasks:

- Ensure DoT/DoH/DoQ pass appropriate `TransportClass` into cache path.
- Decide whether DoT should share `Tcp` cache namespace or have its own class.
- Ensure coalescing keys include encrypted transport class when adapters use coalescing.
- Ensure AXFR/IXFR/UPDATE/NOTIFY exclusions apply identically.
- Add tests proving HTTP/QUIC/TCP/UDP cache/coalescing isolation where response shape differs.

Acceptance criteria:

- encrypted transport responses cannot poison or reuse wrong UDP/TCP cache shapes.

## Workstream 6: Limits, rate limiting, firewall, and client identity

Tasks:

- Verify rate limiting by client IP for encrypted transports.
- Define trusted proxy behavior for DoH.
- Ensure firewall sees parsed query and client identity consistently.
- Apply connection and request limits per transport.
- Add metrics for accepted/refused/malformed/oversized by transport.

Tests:

- rate limit applies to DoT/DoH/DoQ.
- firewall block applies to DoT/DoH/DoQ.
- trusted proxy headers honored only when configured.
- request limits enforced.

Acceptance criteria:

- encrypted transports cannot bypass operational controls.

## Workstream 7: Observability

Tasks:

- Add per-transport metrics for queries, responses, errors, latency, active connections, and bytes.
- Avoid high-cardinality qname labels.
- Add debug logs for transport-level errors without leaking secrets.
- Ensure TLS/QUIC config errors are actionable.

Acceptance criteria:

- operators can distinguish UDP/TCP/DoT/DoH/DoQ behavior.

## Workstream 8: Documentation and examples

Update:

- `architecture/dns.md`
- config matrix
- DoT/DoH/DoQ docs if present
- example configs

Document:

- supported encrypted transports;
- certificate config;
- trusted proxy policy;
- per-transport limits;
- cache/coalescing transport-class behavior;
- known deferrals.

## Verification commands

```bash
cargo fmt --all --check
cargo test -p synvoid-dns dot
cargo test -p synvoid-dns doh
cargo test -p synvoid-dns doq
cargo test -p synvoid-dns transport
cargo check -p synvoid-dns --all-features
cargo check --workspace
```

Optional external smoke tests:

```bash
kdig +tls @127.0.0.1 -p <dot-port> example.test A
curl -H 'content-type: application/dns-message' --data-binary @query.bin https://127.0.0.1:<doh-port>/dns-query
```

## Completion criteria

Phase 3 is complete when DoT, DoH, and DoQ adapters preserve core DNS semantics, enforce transport-specific limits and identity policy, integrate with cache/coalescing safely, shut down cleanly, and have accurate docs/tests. Unsupported encrypted transport behavior must be explicitly deferred rather than implied.
