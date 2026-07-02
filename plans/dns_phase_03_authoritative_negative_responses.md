# DNS Phase 3: Authoritative Negative Responses and Miss Semantics

## Objective

Implement correct authoritative behavior for misses. The DNS server should produce explicit, parseable, authoritative NODATA and NXDOMAIN responses for zones it serves, and should apply a clear no-zone policy instead of silently returning no response for ordinary misses.

This phase completes Milestone 1 by making the authoritative server semantically usable, not merely wire-valid for positive answers.

## Current problem summary

The current query path can return `None` for common miss cases. A matching zone with no matching name, or a matching name with a missing requested type, should not normally result in no response. For an authoritative DNS server, those cases should produce NXDOMAIN or NODATA with SOA in the authority section. Signed zones should additionally provide authenticated denial through NSEC or NSEC3 where configured.

There is also a special-case `.example` path that builds a synthetic NXDOMAIN response with root-label SOA fields and zero serial. That behavior should not exist in production lookup logic. It should be removed, feature-gated for tests, or replaced with normal zone-derived negative response generation.

## Primary files and modules

Likely implementation targets:

- `crates/synvoid-dns/src/server/query.rs`
- `crates/synvoid-dns/src/server/response.rs`
- `crates/synvoid-dns/src/server/dnssec_impl.rs`
- `crates/synvoid-dns/src/server/zone.rs`
- `crates/synvoid-dns/src/zone_file.rs`
- `crates/synvoid-dns/src/zone_trie.rs`
- `crates/synvoid-dns/tests/`

## Required response taxonomy

Define an explicit lookup outcome enum before building responses. Suggested shape:

```rust
enum AuthoritativeLookupOutcome {
    Positive {
        origin: String,
        qname: String,
        qtype: u16,
        records: Vec<DnsZoneRecord>,
    },
    Cname {
        origin: String,
        qname: String,
        cname_chain: Vec<DnsZoneRecord>,
        terminal_records: Vec<DnsZoneRecord>,
    },
    NoData {
        origin: String,
        qname: String,
        qtype: u16,
        soa: DnsZoneRecord,
        denial: Option<DenialProof>,
    },
    NxDomain {
        origin: String,
        qname: String,
        qtype: u16,
        soa: DnsZoneRecord,
        denial: Option<DenialProof>,
    },
    NoAuthoritativeZone {
        qname: String,
        qtype: u16,
    },
    Refused,
    NotImplemented,
}
```

The exact shape can differ, but the response builder should know whether it is building positive, NODATA, NXDOMAIN, no-zone REFUSED/SERVFAIL, or recursive fallback. Avoid using `None` as a catch-all result.

## Name existence and type existence rules

Implement helpers that answer these questions within the best matching zone:

1. Does the qname fall under an authoritative zone origin?
2. Does the exact owner name exist in the zone?
3. Does the owner name have the requested qtype?
4. Does the owner name have a CNAME?
5. Does a wildcard owner apply?
6. Is the query for apex metadata such as SOA, NS, DNSKEY, DS, CDS, CDNSKEY, NSEC3PARAM?
7. Is the request type ANY, and if so, what local policy applies?

Expected behavior:

- Matching owner and requested type -> positive answer.
- Matching owner and no requested type -> NODATA with SOA.
- Missing owner under served zone -> NXDOMAIN with SOA unless wildcard policy supplies an answer.
- CNAME owner queried for non-CNAME type -> return CNAME, and optionally terminal answer if in-zone and implemented.
- No served zone -> configured no-zone policy.

## SOA requirements

Every authoritative NODATA and NXDOMAIN response must include the zone SOA in the authority section unless the zone is malformed and has no SOA. If no SOA exists, choose a fail-safe policy:

- Prefer rejecting the zone at load time unless explicitly allowed for test/minimal zones.
- If a zone without SOA is allowed, negative responses should use a deterministic SERVFAIL or REFUSED rather than constructing synthetic root SOA data.

The SOA encoder should be the typed encoder from Phase 1. Negative cache TTL should be derived from SOA MINIMUM or a documented configured override.

## DNSSEC denial requirements

For signed zones:

- NODATA should include appropriate NSEC or NSEC3 proof for name-exists/type-absent.
- NXDOMAIN should include appropriate NSEC or NSEC3 proof for nonexistence and closest encloser behavior where implemented.
- Denial records should be signed with the zone signing key if signing is enabled.
- Unsigned zones should not fabricate DNSSEC denial records.

If full RFC-complete NSEC3 closest-encloser handling is too large for this phase, implement a conservative subset and document the limitation in the phase PR. Do not claim full DNSSEC denial conformance unless validated by DNSSEC-aware clients.

## No-zone policy

Add or identify an explicit policy for queries outside served zones:

- Authoritative-only public server should normally return REFUSED for names it is not authoritative for.
- Mixed recursive mode may recurse only if recursion is enabled and allowed for that client.
- SERVFAIL should be reserved for internal failure, not ordinary no-zone behavior.
- Silent drop should be reserved for malformed packets or firewall/RRL policy, not ordinary valid queries.

The policy should be implemented in one place and covered by tests.

## Remove special-case `.example` logic

The current shortcut that returns simple NXDOMAIN for `.example` should be removed from production query handling. If existing tests depend on it, replace them with a loaded `example` test zone and assert standard negative behavior. Synthetic negative builders can remain as low-level helpers only if they are clearly named and not used for normal authoritative lookup.

## Wildcard behavior

Assess current wildcard support. If wildcard records are supported, include them in lookup outcome tests. If not supported, document that wildcard expansion is out of scope and ensure the server's negative behavior is deterministic.

Minimum expected tests:

- Exact owner exists and qtype exists -> positive.
- Exact owner exists and qtype absent -> NODATA.
- Owner absent under zone -> NXDOMAIN.
- Apex SOA query -> positive SOA.
- Apex NS query -> positive NS.
- CNAME owner queried for A -> CNAME response.
- Wildcard positive or documented unsupported behavior.

## Test plan

Add integration-style tests with a small test zone:

```text
$ORIGIN example.test.
@ 300 IN SOA ns1.example.test. hostmaster.example.test. 2026070201 3600 600 604800 300
@ 300 IN NS ns1.example.test.
ns1 300 IN A 192.0.2.53
www 300 IN A 192.0.2.10
alias 300 IN CNAME www.example.test.
_txt 300 IN TXT "hello"
```

Test cases:

- `www.example.test A` returns NOERROR with A.
- `www.example.test AAAA` returns NOERROR/NODATA with SOA in authority.
- `missing.example.test A` returns NXDOMAIN with SOA in authority.
- `example.test SOA` returns SOA.
- `example.test NS` returns NS.
- `alias.example.test A` returns CNAME and does not produce malformed data.
- `outside.test A` returns REFUSED or configured no-zone outcome.
- Negative response `NSCOUNT` equals authority record count.
- Negative response TTL follows documented negative TTL policy.
- Negative responses parse with project parser and Hickory.

Add signed-zone tests if the existing DNSSEC machinery can generate deterministic test keys. If deterministic signing is not available, add structural tests for NSEC/NSEC3 inclusion and defer full validation to Phase 9.

## Acceptance criteria

- `cargo test -p synvoid-dns` passes.
- Ordinary authoritative misses no longer return `None` from the top-level query path.
- NODATA and NXDOMAIN responses include zone SOA in authority.
- No-zone queries follow an explicit policy.
- The `.example` synthetic shortcut is removed from production query flow or clearly test-gated.
- Signed denial responses include appropriate denial records where DNSSEC is enabled, within documented scope.
- Negative response packets parse cleanly and have correct section counts.

## Non-goals

This phase does not need to complete production-grade NSEC3 closest-encloser coverage if the current DNSSEC implementation is not ready. It also does not need to complete recursive fallback policy beyond ensuring no-zone behavior is explicit and safe.

## Implementation sequence

1. Add test zones and failing tests for NODATA, NXDOMAIN, no-zone, CNAME miss, and SOA authority inclusion.
2. Introduce explicit lookup outcome type.
3. Refactor positive lookup to return `Positive`/`Cname` outcomes.
4. Add owner/type existence helpers.
5. Add unsigned NODATA and NXDOMAIN builders using Phase 1 typed encoder.
6. Route signed zones through existing NSEC/NSEC3 helpers with corrected section placement.
7. Remove or test-gate `.example` shortcut.
8. Add no-zone policy tests.
9. Verify negative cache TTL extraction behavior.

## Handoff notes

Keep negative response generation explicit. Avoid small helper shortcuts that obscure whether the response is NXDOMAIN, NODATA, REFUSED, or SERVFAIL. DNS clients and recursive resolvers behave differently for each case, and production correctness depends on preserving those distinctions.
