# DNS Production Readiness Roadmap

## Context

The Synvoid DNS subsystem has the right broad architecture for an integrated authoritative DNS service: zone storage, trie-based zone lookup, cache support, DNSSEC scaffolding, transfer/update/notify modules, encrypted transport modules, DNS64, RPZ, firewalling, rate limiting, and recursive resolver support. The current production risk is not lack of ambition; it is that several foundational DNS behaviors are still implemented through ad hoc packet construction and partially wired runtime paths.

This roadmap is intended as a handoff plan to bring `crates/synvoid-dns` closer to production readiness. It prioritizes correctness of DNS wire output first, then runtime safety, then advanced feature fidelity, then observability and operations.

The hard production gate is: valid DNS wire output across supported RR types, correct truncation and TCP fallback behavior, correct authoritative NODATA/NXDOMAIN behavior, no open-recursive default, honored listener bind address, effective TCP limits, reliable cache invalidation, and CI-backed interoperability tests.

## Milestone 1: Protocol correctness foundation

Milestone 1 must make the authoritative DNS core produce valid, semantically correct DNS messages. This milestone is intentionally narrow and should be completed before optimization or feature expansion.

### Phase 1: Wire-format response encoder closure

Replace ad hoc response byte appending with a typed response encoder boundary. Each RR encoder must validate input and return a complete encoded record before packet assembly mutates the output buffer. Packet section counts must be derived from successfully emitted records only. Fix truncation to preserve query ID and set TC correctly rather than producing a random-ID SERVFAIL-like response.

Primary files likely touched:

- `crates/synvoid-dns/src/server/response.rs`
- `crates/synvoid-dns/src/wire.rs`
- `crates/synvoid-dns/src/server/query.rs`
- `crates/synvoid-dns/src/server/dnssec_impl.rs`
- tests under `crates/synvoid-dns/tests/` or module-level tests

Exit criteria:

- A, AAAA, CNAME, NS, SOA, MX, TXT, PTR, CAA, TLSA, SVCB, HTTPS, NAPTR, SSHFP, DNSKEY, DS, RRSIG, NSEC, and NSEC3 responses parse cleanly through the project parser and a Hickory parser.
- Unsupported or malformed zone records never leave partial RR bytes in the response.
- `ANCOUNT`, `NSCOUNT`, and `ARCOUNT` match exactly emitted records.
- UDP responses that exceed advertised payload size preserve query ID, set TC, avoid fabricated SERVFAIL, and remain parseable.

### Phase 2: Canonical query parser and flag semantics hardening

Unify query parsing behind a single canonical parsed-query object. The server currently has multiple independent parsers for cache keys, firewall handling, query handling, transfer detection, and negative responses. Replace these with one checked parser that validates bounds, label length, qname length, qclass, qtype, opcode, EDNS metadata, DNSSEC DO bit, and DNS cookie material.

Also fix response flag semantics. Authoritative responses should set AA, preserve RD from the query if desired, set RA only when recursion is genuinely available to that client, and avoid setting AD merely because an authoritative signature was attached.

Primary files likely touched:

- `crates/synvoid-dns/src/server/query.rs`
- `crates/synvoid-dns/src/query_coalesce.rs`
- `crates/synvoid-dns/src/query_validator.rs`
- `crates/synvoid-dns/src/firewall.rs`
- `crates/synvoid-dns/src/edns.rs`
- `crates/synvoid-dns/src/wire.rs`

Exit criteria:

- Query parser fuzz tests cover short packets, overlong labels, pointer abuse, invalid qnames, invalid EDNS, multi-question packets, unsupported classes, and malformed OPT records.
- Cache, firewall, RRL, coalescing, transfer, update, notify, and ordinary lookup paths consume the same parsed query structure.
- Response flags are derived from parsed query state and server mode, not hard-coded constants.
- Invalid queries generate deterministic FORMERR/REFUSED/NOTIMP responses where appropriate instead of panics or silent drops.

### Phase 3: Authoritative negative responses and miss semantics

Implement correct authoritative miss behavior. The server should not silently return `None` for ordinary misses inside an authoritative zone. It must distinguish no matching zone, matching zone with nonexistent name, matching name with requested type absent, refused/non-authoritative behavior, and DNSSEC-authenticated denial.

Unsigned NODATA and NXDOMAIN responses should include SOA in the authority section. Signed zones should include NSEC or NSEC3 denial records and signatures where configured. Remove or test-only-gate the special `.example` shortcut that constructs synthetic NXDOMAIN responses with root-label SOA data.

Primary files likely touched:

- `crates/synvoid-dns/src/server/query.rs`
- `crates/synvoid-dns/src/server/response.rs`
- `crates/synvoid-dns/src/server/dnssec_impl.rs`
- `crates/synvoid-dns/src/server/zone.rs`
- `crates/synvoid-dns/src/zone_file.rs`

Exit criteria:

- Existing-zone missing-name queries receive authoritative NXDOMAIN with SOA.
- Existing-name missing-type queries receive authoritative NODATA with SOA.
- No-zone queries follow the configured policy: REFUSED, SERVFAIL, or recursion path if explicitly enabled and allowed.
- Signed NODATA and NXDOMAIN responses validate with DNSSEC-aware clients once the project signing layer is enabled.
- Negative cache TTL behavior is deterministic and documented.

## Milestone 2: Runtime safety and configuration fidelity

Milestone 2 makes configured behavior real and removes deployment footguns.

### Phase 4: Listener binding, TCP lifecycle, and transport limits

Honor `dns.bind_address` for UDP and TCP sockets. Keep TCP connection limit guards alive for the full spawned task lifetime rather than dropping them immediately after accept. Decide whether DNS-over-TCP supports one query per connection or bounded persistent connections, then document and test that behavior.

Exit criteria:

- Binding to `127.0.0.1`, `0.0.0.0`, `::1`, and `::` works as configured.
- TCP connection limit tests prove concurrent sessions are bounded.
- Idle and query timeouts are enforced.
- UDP truncation followed by TCP retry works with `dig`.

### Phase 5: Config-to-runtime audit

Create a matrix for every DNS config field. Classify each field as active, partially active, planned, deprecated, or invalid. Wire high-value partially active settings and explicitly mark unsupported settings.

Known items to address:

- Pass `dns64_translator` into UDP/TCP contexts instead of `None`.
- Use `DnsCache::with_serve_stale` when `settings.serve_stale.enabled` is configured.
- Apply qname privacy to logs.
- Implement or remove DNS padding from production config.
- Implement or remove prefetch from production config.

Exit criteria:

- Every DNS config field has either a runtime test or documentation stating unsupported/experimental status.
- Enabling DNS64, serve-stale, qname privacy, and padding changes observable behavior if the fields remain in production config.

### Phase 6: Query coalescing repair

Wire `broadcast_response` so the owner of a coalesced request publishes successful and negative responses to waiters. Clean up entries on success, timeout, cancellation, and malformed input. Revisit the key shape for geo/ECS/view-aware authoritative responses.

Exit criteria:

- Concurrent identical queries result in one underlying response build.
- Waiters receive responses before timeout.
- Metrics show hits, misses, timeouts, evictions, and in-flight count accurately.
- Enabling coalescing does not worsen normal p95 latency.

### Phase 7: Cache semantics and invalidation correctness

Separate authoritative cache assumptions from recursive cache assumptions. Do not reject legitimate authoritative response variation as poisoning. Fix record invalidation so per-client/per-subnet cache keys are invalidated for a qname/qtype regardless of client dimension.

Exit criteria:

- Record updates invalidate all cached variants.
- Dynamic update tests prove stale records are not served.
- Authoritative geo/DNSSEC/round-robin variants are not rejected by full-packet fingerprint heuristics.

## Milestone 3: Advanced DNS feature trustworthiness

Milestone 3 completes features that are expected from a production authority and prevents dangerous default exposure.

### Phase 8: Zone lifecycle, serials, IXFR, AXFR, and NOTIFY

Route all zone mutations through a `ZoneMutation` boundary that increments serials, records IXFR history, invalidates cache, rebuilds indexes if needed, schedules NOTIFY, and persists when a backing store is configured.

Exit criteria:

- Add/update/delete operations increment SOA serial.
- IXFR returns bounded history where available and falls back to AXFR according to config.
- NOTIFY emits to configured secondaries.
- TSIG-required transfer/update paths fail closed.

### Phase 9: DNSSEC correctness and key lifecycle

Validate authoritative signing behavior against real DNSSEC clients. Separate authoritative signing from recursive validation semantics. Do not set AD as a substitute for validation. Verify DNSKEY, DS, CDS, CDNSKEY, RRSIG, NSEC, and NSEC3 behavior.

Exit criteria:

- Signed positive, NODATA, and NXDOMAIN responses validate with `delv` or equivalent.
- KSK/ZSK rotation does not break the chain.
- HSM initialization failure has explicit fail-open/fail-closed policy.

### Phase 10: DoT, DoH, and DoQ adapters

Make encrypted transports thin adapters over the same canonical parser and response builder. Verify transport-specific limits, certificate resolution, request mapping, and error handling.

Exit criteria:

- UDP, TCP, DoT, DoH, and DoQ return equivalent DNS messages for the same query.
- Transport metrics are split by protocol.
- Malformed DoH/DoT/DoQ requests fail safely without diverging DNS semantics.

### Phase 11: Recursive mode isolation

Prevent accidental open resolver behavior. Define authoritative-only, recursive-only, forwarding-recursive, and mixed modes with explicit client allow policy.

Exit criteria:

- Recursion is disabled by default.
- Recursive mode requires explicit allowlist or restricted listener binding.
- RA flag reflects actual recursion availability to the client.
- Authoritative cache and recursive cache are separate.

## Milestone 4: Operability, performance, and release readiness

Milestone 4 makes the DNS system observable, benchmarked, documented, and continuously verifiable.

### Phase 12: Metrics, logs, and diagnostics

Add metrics for query count by transport/qtype/rcode, latency, truncation, TCP fallback, cache hit/miss/stale, zone serial, transfer attempts, TSIG failures, DNSSEC signing failures, malformed queries, firewall decisions, RRL drops, and coalescer behavior. Apply qname privacy consistently.

Exit criteria:

- Operators can inspect loaded zones, serials, key status, cache stats, listener bindings, and enabled transports.
- QNAME privacy mode changes log output.
- Metrics avoid unbounded label cardinality.

### Phase 13: Performance and load testing

Benchmark static authority, many-zone hosting, DNSSEC-heavy zones, NXDOMAIN floods, large responses, ACME TXT bursts, TCP fallback, and mixed UDP/TCP traffic. Optimize after correctness gates are stable.

Exit criteria:

- p50/p95/p99 latency baselines exist.
- Throughput baselines exist for UDP and TCP.
- Memory remains bounded under malformed floods.
- No global lock dominates query hot path.

### Phase 14: Interoperability and conformance suite

Build CI tests that launch the server on ephemeral ports and query it with project parsers, Hickory, `dig`, `drill`, and DNSSEC-aware tooling where available.

Exit criteria:

- Golden packet tests cover all supported RR types and negative responses.
- Fuzz tests cover parser boundaries.
- Every fixed DNS protocol bug receives a regression test.
- Tests run without privileged port 53 or public DNS dependencies.

### Phase 15: Production profile and documentation

Document production-supported modes and explicitly mark experimental features. Provide configs for authoritative-only public DNS, internal authority, signed zones, ACME DNS-01, TSIG-secured transfers, DoT/DoH, and private recursion.

Exit criteria:

- Minimal authoritative deployment works from docs.
- Default config is safe.
- Unsupported features are not advertised as production-ready.
- The duplicate `src/dns` versus `crates/synvoid-dns` layout is resolved or documented as a compatibility shim.

## Recommended execution order

1. Finish Milestone 1 completely before optimizing hot paths.
2. Merge Milestone 2 before enabling DNS broadly in integration environments.
3. Treat Milestone 3 as feature trustworthiness hardening; advanced features should remain experimental until their phase gates pass.
4. Treat Milestone 4 as the release-readiness gate.

The most important first implementation rule is to add tests before or alongside fixes. DNS protocol regressions are easy to reintroduce when response construction is byte-oriented, so the encoder and parser should become test-dense before feature work resumes.
