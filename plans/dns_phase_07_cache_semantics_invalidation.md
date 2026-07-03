# DNS Phase 7: Cache Semantics and Invalidation Correctness

## Objective

Make DNS caching correct, safe, observable, and aligned with authoritative versus recursive semantics. DNS cache bugs can create stale records, poison false positives, wrong client-specific answers, broken DNSSEC shape, and incorrect negative caching. This phase hardens cache keys, TTL policy, invalidation, serve-stale behavior, and authoritative/recursive separation.

## Current concerns

- `DnsCache` appears to use a weighted capacity model while config names may imply entry count.
- Cache keys include qname, qtype, and optional client subnet, but response shape can also depend on DO bit, ECS, DNS64, transport, recursion policy, view/policy, and EDNS size/truncation behavior.
- Negative cache TTL extraction is basic and should derive from SOA/minimum policy where possible.
- Invalidation by qname/zone must remove all client-subnet/view variants.
- Authoritative and recursive cache semantics should be distinct.
- Serve-stale config exists but must be fully wired and tested.
- The current fingerprint/poisoning heuristic may be too coarse if keyed only by qname.

## Primary files

- `crates/synvoid-dns/src/cache.rs`
- `crates/synvoid-dns/src/recursive_cache.rs`
- `crates/synvoid-dns/src/server/query.rs`
- `crates/synvoid-dns/src/server/zone.rs`
- `crates/synvoid-dns/src/update.rs`
- `crates/synvoid-dns/src/transfer.rs`
- `crates/synvoid-dns/src/edns.rs`
- `crates/synvoid-dns/src/dns64.rs`
- `crates/synvoid-dns/src/metrics.rs`
- `crates/synvoid-config/src/dns/dns_settings.rs`
- DNS cache tests

## Required invariants

1. Cache key dimensions cover all output-affecting inputs.
2. Authoritative cache entries are invalidated on zone updates, loads, deletes, dynamic updates, and transfer apply.
3. Recursive cache entries are isolated from authoritative zone state.
4. Negative responses are cached according to DNS negative caching policy and local config.
5. Serve-stale is explicit, bounded, observable, and disabled by default unless configured.
6. Cache poisoning heuristics do not reject legitimate authoritative variance or allow unsafe mutation.
7. Cache size and TTL config are accurately documented and tested.

## Workstream 1: Cache key redesign

Tasks:

- Define a `DnsCacheKey` that includes all relevant dimensions:
  - canonical qname
  - qtype
  - qclass
  - DO bit / DNSSEC response-shape bit
  - client subnet or view key when ECS/geo/DNS64/policy affects answer
  - transport or response-size class if TC/EDNS shape can differ
  - authoritative versus recursive namespace
- Preserve a compact key for cases where dimensions are irrelevant.
- Add helper constructors from `ParsedDnsQuery` and runtime context.
- Avoid storing raw client IP when privacy config requires subnet truncation or redaction.

Tests:

- Same qname/qtype but DO bit differs -> key differs when DNSSEC output differs.
- Same qname/qtype but client policy differs -> key differs.
- Same qname/qtype but qclass differs -> key differs.
- Authoritative and recursive entries cannot collide.
- Case-insensitive qname canonicalization works.

Acceptance criteria:

- Cache key equivalence is explicit and tested.
- No known response-shape dimension is missing from the key.

## Workstream 2: TTL and negative caching policy

Tasks:

- Rework TTL extraction to parse DNS names with compression pointers safely.
- For positive answers, use minimum answer TTL unless config min/max TTL clamps apply.
- For NODATA/NXDOMAIN, derive TTL from authority SOA TTL and SOA MINIMUM according to the chosen RFC 2308 policy, then clamp with config.
- Avoid caching malformed responses.
- Ensure SERVFAIL is not cached unless explicitly configured for a very short failure cache.
- Ensure REFUSED is either not cached or cached only under explicit policy.

Tests:

- Positive A response TTL extraction.
- Multi-answer TTL uses minimum answer TTL.
- NODATA negative TTL derives from SOA.
- NXDOMAIN negative TTL derives from SOA.
- Malformed response not cached.
- SERVFAIL not cached by default.
- REFUSED not cached by default or follows explicit policy.

Acceptance criteria:

- Cache TTL policy is protocol-aware and tested.

## Workstream 3: Invalidation correctness

Tasks:

- Audit every zone mutation path:
  - config zone load
  - store zone load
  - `add_record`
  - dynamic update
  - transfer apply
  - IXFR apply
  - zone delete if present
  - DNSSEC key rollover affecting DNSKEY/DS/RRSIG/NSEC/NSEC3 records
- Ensure invalidation removes all variants for affected qname/qtype and all client-subnet/view entries.
- Add zone-wide invalidation for zone reload and transfer apply.
- Add RRset-specific invalidation for dynamic updates where feasible.
- Ensure negative cache entries for affected names are invalidated when new records are added.
- Ensure CNAME target changes invalidate both CNAME owner and dependent cached lookups if dependency tracking exists; if not, prefer zone-wide invalidation.

Tests:

- Add A record invalidates prior NXDOMAIN for that name.
- Add MX record invalidates prior NODATA for existing name.
- Update A record invalidates all client-specific cache entries.
- Zone reload invalidates all records under origin.
- DNSSEC key change invalidates DNSSEC-shaped answers.

Acceptance criteria:

- Zone changes cannot leave stale authoritative answers in cache.
- Invalidation covers client-subnet and DNSSEC variants.

## Workstream 4: Authoritative versus recursive cache separation

Tasks:

- Decide whether authoritative and recursive caches are separate structs or separate namespaces in a shared cache.
- Ensure recursive cache respects upstream TTL, validation state, bailiwick policy, and trust-anchor state.
- Ensure authoritative cache is invalidated by local zone changes and does not accept external upstream data.
- Ensure AD/CD/DO recursive response shape is separated from authoritative response shape.
- Add clear docs for cache ownership.

Tests:

- Recursive cache entry cannot satisfy authoritative query for same qname/qtype.
- Authoritative zone update does not mutate recursive cache except through explicit namespace invalidation if intended.
- Recursive validation state is part of recursive cache metadata.

Acceptance criteria:

- No cross-contamination between authoritative and recursive cache data.

## Workstream 5: Serve-stale behavior

Tasks:

- Wire serve-stale config into cache constructor and runtime get path.
- Define stale eligibility:
  - maximum stale age
  - serve only on upstream/zone lookup failure or always while refresh pending
  - whether stale negative responses are allowed
  - whether DNSSEC signed stale data is allowed after signature expiry
- Add stale response metadata/logging.
- Expose stale hit metrics.
- Ensure authoritative local zone changes invalidate stale entries immediately.

Tests:

- Serve-stale disabled returns miss after TTL expiry.
- Serve-stale enabled returns stale within max stale window.
- Stale beyond max window returns miss.
- Zone update invalidates stale authoritative entry.
- Stale hit increments metric.

Acceptance criteria:

- Serve-stale behavior is bounded, explicit, and test-covered.

## Workstream 6: Cache poisoning/fingerprint policy

Tasks:

- Review current response fingerprinting logic.
- Avoid qname-only fingerprinting that rejects legitimate qtype/client/DNSSEC/view variance.
- If poisoning protection is kept, key fingerprint by the same dimensions as cache key or by RRset identity.
- Add structured warnings for suspicious mutation rather than dropping legitimate authoritative changes after zone update.
- Ensure local authoritative updates reset fingerprint state.

Tests:

- A and AAAA for same qname do not conflict.
- DNSSEC and non-DNSSEC response shapes do not conflict.
- Different client-specific answers do not conflict when policy allows them.
- Legitimate zone update does not trigger poisoning rejection after invalidation.

Acceptance criteria:

- Poisoning heuristics do not create false positives for legitimate server behavior.

## Workstream 7: Metrics and diagnostics

Tasks:

Add metrics for:

- cache hits/misses by namespace
- stale hits
- negative-cache hits
- invalidations by reason
- dropped malformed cache inserts
- cache insert size
- eviction count if available
- poisoning/fingerprint warnings

Add logs with safe labels. Avoid raw qname labels in metrics unless explicitly configured for debug.

Acceptance criteria:

- Operators can diagnose stale/missing/incorrect cache behavior without high-cardinality metrics.

## Workstream 8: Documentation

Update docs with:

- Cache key dimensions.
- TTL policy.
- Negative caching policy.
- Serve-stale policy.
- Authoritative vs recursive cache separation.
- Invalidation triggers.
- Configuration examples.

## Verification commands

```bash
cargo fmt --all --check
cargo test -p synvoid-dns cache
cargo test -p synvoid-dns recursive_cache
cargo test -p synvoid-dns authoritative_negative
cargo test -p synvoid-dns
cargo check -p synvoid-dns --all-features
cargo check --workspace
```

## Completion criteria

Phase 7 is complete when cache key dimensions are correct, TTL and negative caching are protocol-aware, zone mutation invalidation is comprehensive, authoritative and recursive cache data cannot collide, serve-stale is fully wired and bounded, poisoning heuristics are dimensionally correct, and cache behavior is covered by tests and docs.
