# DNS Milestone 2 Phase 3: Cache Integration Closure

## Objective

Complete the transition from a simple qname/qtype cache to a production-safe DNS cache integrated with parsed query state, transport state, authoritative/recursive namespaces, invalidation hooks, TTL policy, and observability.

The first Milestone 2 pass redesigned `CacheKey` and added cache metrics and serve-stale behavior. This phase ensures the server actually uses those new dimensions correctly.

## Current state

Already improved:

- `CacheKey` includes qname, qtype, qclass, dnssec_ok, client_subnet, transport_class, and namespace.
- `TransportClass` separates UDP512, UDP EDNS, TCP, HTTP, and QUIC shapes.
- `CacheNamespace` separates authoritative and recursive cache entries.
- cache metrics were added.
- serve-stale behavior has direct tests.
- fingerprinting no longer keys by qname alone.

Still requiring closure:

- server cache lookup/insertion path must construct full keys from parsed query and runtime context;
- TTL parser must be compression-safe;
- mutation paths must invalidate all cache variants;
- recursive and authoritative caches must not collide;
- SERVFAIL/REFUSED caching policy must be explicit.

## Primary files

- `crates/synvoid-dns/src/cache.rs`
- `crates/synvoid-dns/src/server/query.rs`
- `crates/synvoid-dns/src/server/startup.rs`
- `crates/synvoid-dns/src/server/zone.rs`
- `crates/synvoid-dns/src/update.rs`
- `crates/synvoid-dns/src/transfer.rs`
- `crates/synvoid-dns/src/recursive_cache.rs`
- `crates/synvoid-dns/tests/dns_config_fidelity.rs`
- `crates/synvoid-dns/tests/dns_recursive_isolation.rs`

## Workstream 1: Cache key construction API

Tasks:

- Add canonical constructors:

```rust
CacheKey::from_parsed_authoritative(
    parsed: &ParsedDnsQuery,
    client_subnet: Option<IpAddr>,
    transport_class: TransportClass,
) -> CacheKey

CacheKey::from_parsed_recursive(
    parsed: &ParsedDnsQuery,
    client_subnet: Option<IpAddr>,
    transport_class: TransportClass,
) -> CacheKey
```

- Canonicalize qname inside constructors.
- Set qclass from parsed query.
- Set dnssec_ok from parsed DO bit.
- Set namespace explicitly.
- Add optional ECS-derived subnet support if ECS is parsed.
- Add tests for every dimension.

Acceptance criteria:

- server code no longer hand-mutates partial cache keys for qname/qtype only.

## Workstream 2: Server path integration

Tasks:

- UDP path: construct authoritative cache key from parsed query and UDP transport class.
- TCP path: construct authoritative cache key from parsed query and TCP transport class.
- DoH/DoQ/DoT paths: either construct appropriate transport class or document deferred integration.
- Recursive path: construct recursive namespace key.
- Remove default `CacheKey::new(String::new(), NULL, ...)` placeholders from active paths.
- Ensure cache hit uses the same key dimensions as cache insert.

Tests:

- UDP 512 cached TC response does not satisfy TCP query.
- UDP EDNS 4096 response does not collide with UDP512 query if response shape differs.
- DO=true response does not satisfy DO=false query.
- qclass differs -> miss.
- recursive namespace entry does not satisfy authoritative lookup.

Acceptance criteria:

- production cache path uses full cache key dimensions.

## Workstream 3: TTL extraction hardening

Tasks:

- Add compression-aware DNS name skipping helper.
- Parse the question section safely.
- Parse all answer RRs and use minimum positive TTL.
- Parse authority SOA for negative TTL.
- Reject malformed packets from cache insertion.
- Do not cache SERVFAIL by default.
- Do not cache REFUSED by default unless explicit config exists.

Tests:

- answer owner compression pointer works.
- multiple answer TTL chooses minimum.
- malformed pointer does not cache.
- NODATA SOA TTL extraction works.
- NXDOMAIN SOA TTL extraction works.
- SERVFAIL returns TTL 0.
- REFUSED returns TTL 0 by default.

Acceptance criteria:

- TTL extraction is safe enough for arbitrary wire packets produced by the server.

## Workstream 4: Invalidation hooks

Tasks:

- Audit mutation paths:
  - config zone load;
  - store zone load;
  - `add_record`;
  - dynamic update;
  - transfer apply;
  - IXFR apply;
  - DNSSEC key rollover;
  - zone delete if present.
- Invalidate all qname/client/transport/DNSSEC variants.
- Invalidate negative entries when adding positive records.
- Clear composite fingerprint entries on invalidation.
- Add reason-coded invalidation metrics.

Tests:

- adding A invalidates NXDOMAIN for that qname.
- adding MX invalidates NODATA for existing owner.
- zone reload invalidates all names under origin.
- dynamic update invalidates all variants.
- DNSSEC key change invalidates signed response entries.

Acceptance criteria:

- authoritative zone mutation cannot leave stale cached response variants.

## Workstream 5: Recursive cache separation

Tasks:

- Verify `recursive_cache.rs` and `cache.rs` namespace semantics align.
- Decide whether recursive cache remains separate implementation or converges on shared `CacheKey` namespace.
- Ensure validation state and trust anchor status are part of recursive cache metadata where needed.
- Add tests that authoritative and recursive entries cannot collide.

Acceptance criteria:

- recursive data cannot satisfy authoritative responses and vice versa.

## Workstream 6: Metrics and docs

Tasks:

- Wire cache metrics into existing DNS metrics export path.
- Add invalidation reason metrics.
- Avoid high-cardinality qname labels.
- Document cache key dimensions and TTL policy in `architecture/dns.md` and the config matrix.

## Verification commands

```bash
cargo fmt --all --check
cargo test -p synvoid-dns cache
cargo test -p synvoid-dns dns_config_fidelity
cargo test -p synvoid-dns dns_recursive_isolation
cargo test -p synvoid-dns authoritative_negative
cargo check -p synvoid-dns --all-features
cargo check --workspace
```

## Completion criteria

Phase 3 is complete when server cache paths use full parsed-query/context key construction, TTL parsing is compression-safe, mutation invalidation covers all variants, authoritative/recursive cache data cannot collide, and cache metrics/docs reflect actual behavior.
