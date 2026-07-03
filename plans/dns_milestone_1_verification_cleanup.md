# DNS Milestone 1 Verification and Cleanup Pass

## Context

The DNS Milestone 1 corrective implementation has moved the subsystem substantially closer to a production-adjacent authoritative DNS core. The current tree now has a typed response encoder, `EncodeReport`, byte-size truncation, parsed-query-aware handler paths, parsed-query-derived coalescing keys, unsigned authoritative NODATA/NXDOMAIN response generation, no-zone REFUSED behavior, bind-address honoring, DNS64 context propagation, and TCP connection guard lifetime cleanup.

This verification/cleanup pass is intended to close the remaining Milestone 1 correctness gaps before moving to broader Milestone 2 runtime/config fidelity work. The focus is narrow: prove the current implementation compiles and behaves correctly, remove remaining authoritative flag mistakes, clean up signed negative response construction, enforce SOA invariants for authoritative zones, and document any intentionally deferred DNSSEC limitations.

## Current risk summary

The remaining issues are concentrated in four areas:

1. Authoritative DNSSEC responses can still set AD because positive response construction passes `records_signed` as `authentic_data`, and signed NODATA/NXDOMAIN builders manually set AD when proof records are present.
2. Unsigned NODATA/NXDOMAIN is now much better, but zones without SOA can still yield negative responses without authority SOA unless load-time policy rejects those zones.
3. Older signed NODATA/NXDOMAIN response builders still manually assemble packets and appear to have wire-format and section-count risks, especially around SOA RDATA and EDNS/ARCOUNT.
4. The implementation has grown quickly and needs a hard compile/test/conformance pass before treating Milestone 1 as closed.

## Scope

Primary files likely touched:

- `crates/synvoid-dns/src/server/response.rs`
- `crates/synvoid-dns/src/server/response_encoder.rs`
- `crates/synvoid-dns/src/server/query.rs`
- `crates/synvoid-dns/src/server/mod.rs`
- `crates/synvoid-dns/src/server/zone.rs`
- `crates/synvoid-dns/src/zone_file.rs`
- `crates/synvoid-dns/src/parsed_query.rs`
- `crates/synvoid-dns/tests/authoritative_negative.rs`
- additional DNS tests under `crates/synvoid-dns/tests/`
- DNS architecture docs only where behavior is intentionally documented

Do not broaden this pass into DoT/DoH/DoQ conformance, full recursive resolver policy, full NSEC3 closest-encloser correctness, performance optimization, or full config-to-runtime matrix work.

## Phase 1: Compile and baseline verification

Before making more changes, establish the real state of the tree.

Run:

```bash
cargo fmt --all --check
cargo test -p synvoid-dns
cargo test -p synvoid-config dns
cargo check -p synvoid-dns --all-features
cargo check --workspace
```

If any command fails, fix compile/test failures first before changing behavior further. Record failures in the implementing PR or commit notes so later reviewers know whether the pass started from a broken tree.

If fuzz tooling is available and configured:

```bash
cargo fuzz run parsed_query_parse -- -max_total_time=30
```

Acceptance criteria:

- The repository has a known baseline: pass/fail status for every command above.
- Any compile errors introduced by the corrective implementation are fixed before protocol cleanup proceeds.
- Formatting is stable.

## Phase 2: Remove AD from authoritative response paths

### Problem

Authoritative servers should not set AD merely because they generated signatures or denial proofs. AD is a recursive validation signal. The current positive response path still derives `authentic_data` from `records_signed`, and signed negative builders still set AD when NSEC/NSEC3 records are present.

### Implementation tasks

- In `build_response`, stop passing `records_signed` as `authentic_data` to `build_response_flags`.
- Set `authentic_data=false` for all authoritative-only positive responses.
- In `build_nxdomain_response` and `build_nodata_response`, remove manual `flags |= 0x0020` behavior for signed denial records.
- Audit all calls to `build_response_flags`, `build_response_flags_full`, and any direct `0x0020` bit manipulation.
- If recursive validated data eventually needs AD, introduce a separate explicit `ValidatedRecursiveResponse` path later. Do not overload authoritative signing state.

### Tests

Add tests for:

- Signed authoritative positive response includes RRSIG but does not set AD.
- Signed NODATA with NSEC/NSEC3 proof does not set AD.
- Signed NXDOMAIN with NSEC/NSEC3 proof does not set AD.
- Unsigned authoritative positive/NODATA/NXDOMAIN responses do not set AD.
- Existing RD echo behavior still works.
- RA remains false in authoritative-only mode.

Add helper functions to `authoritative_negative.rs` or a new flag-focused test file:

```rust
fn response_ad(resp: &[u8]) -> bool { response_flags(resp) & 0x0020 != 0 }
fn response_ra(resp: &[u8]) -> bool { response_flags(resp) & 0x0080 != 0 }
fn response_rd(resp: &[u8]) -> bool { response_flags(resp) & 0x0100 != 0 }
```

Acceptance criteria:

- No authoritative path sets AD from signing or denial proof presence.
- Tests fail if AD is reintroduced into authoritative responses.

## Phase 3: Enforce SOA invariants for authoritative zones

### Problem

Unsigned NODATA/NXDOMAIN now includes SOA when available, but authoritative zones should not normally be served without SOA. The current zone loader validates SOA format when present but should also ensure production zones have an SOA before being accepted, unless a deliberate test-only/minimal-zone path is used.

### Implementation tasks

- Decide production policy: authoritative zones loaded through config must contain at least one SOA record.
- Add validation after records are loaded for each `DnsZoneEntry`:
  - Reject zone if no SOA exists.
  - Reject zone if multiple SOAs exist unless there is an explicit documented merge policy.
  - Reject zone if SOA owner is not apex or equivalent apex representation.
- Keep direct test construction of `Zone` available for unit tests, but ensure integration tests that mimic config loading include SOA.
- In `build_unsigned_nodata` and `build_unsigned_nxdomain`, if `soa` is `None`, return SERVFAIL or REFUSED according to policy. Prefer SERVFAIL for malformed served zone because the zone is authoritative but internally invalid.
- Add structured log/metric for missing SOA negative-response fallback if runtime invalid state is encountered.

### Tests

Add tests for:

- Config zone without SOA is rejected by `load_zones`.
- Config zone with malformed SOA is rejected.
- Config zone with SOA at non-apex owner is rejected or normalized according to explicit policy.
- Runtime `build_unsigned_nodata(..., soa=None)` returns SERVFAIL.
- Runtime `build_unsigned_nxdomain(..., soa=None)` returns SERVFAIL.

Acceptance criteria:

- No served authoritative zone from config can lack SOA.
- Negative responses from malformed in-memory state fail closed instead of claiming NODATA/NXDOMAIN without SOA.

## Phase 4: Move signed negative responses onto typed encoder or mark deferred

### Problem

The new unsigned negative builders use `ResponseEnvelope` and `encode_rr` for SOA authority records. The older signed NODATA/NXDOMAIN builders still manually assemble wire packets. In particular, the signed NODATA path appears to append textual SOA value bytes as RDATA instead of encoded SOA wire format and has section-count risks around authority/additional counts.

### Implementation tasks

Preferred path:

- Rewrite `build_nxdomain_response` and `build_nodata_response` to use `ResponseEnvelope`, `encode_rr`, and `assemble_packet`.
- Add SOA records to `authority_records`, not manual bytes.
- Add NSEC/NSEC3 proof records to `authority_records` using `encode_rr`.
- Add RRSIG records for denial proof RRsets through `encode_rr`.
- Add OPT through `build_opt_encoded_record` so ARCOUNT is correct.
- Derive all counts from envelope vectors.
- Use the same flag policy as unsigned negative responses: AA true, RD echoed, RA false, AD false, RCODE set explicitly.

Fallback path if full signed denial rewrite is too large:

- Remove signed negative response assertions from production-readiness claims.
- Add an explicit `TODO`/doc note that signed denial proof response construction remains non-production and will be completed in DNSSEC milestone work.
- Ensure manual builders do not corrupt packets for the existing test cases.
- At minimum fix textual SOA RDATA emission and ARCOUNT/NSCOUNT drift.

### Tests

Add tests for signed negative packet structure with deterministic/dummy records:

- Signed NODATA has QDCOUNT=1, ANCOUNT=0, NSCOUNT >= SOA + denial proof count, ARCOUNT includes OPT only when present.
- Signed NXDOMAIN has QDCOUNT=1, ANCOUNT=0, NSCOUNT >= SOA/proof count, ARCOUNT correct.
- SOA in signed negative response is encoded as DNS SOA wire RDATA, not text bytes.
- NSEC/NSEC3 records have correct type and RDLENGTH.
- RRSIG records, if generated, increment NSCOUNT.
- AD remains false.

Acceptance criteria:

- Signed negative response builders no longer hand-maintain inconsistent section counts, or the limitation is explicitly documented and tests cover the remaining manual behavior.

## Phase 5: Tighten authoritative lookup semantics

### Problem

The new `AuthoritativeLookupOutcome` is useful, but the query path still has separate positive/CNAME/ANY/DNSSEC special-case logic before falling back to `zone.lookup_authoritative`. This is acceptable for now but needs tests to ensure the outcome model agrees with production behavior and does not create conflicting miss semantics.

### Implementation tasks

- Add unit tests directly for `Zone::lookup_authoritative`:
  - Positive exact type.
  - CNAME owner queried for A.
  - Existing owner missing type -> NoData.
  - Missing owner -> NxDomain.
  - Apex SOA lookup.
  - Apex NS lookup.
- Verify owner normalization between `@`, apex origin, relative names, and trailing-dot qnames.
- Confirm `RecordType::ANY` policy is tested separately from exact type lookup.
- Ensure CNAME loop handling returns an explicit response consistently, not `None`.

Acceptance criteria:

- The lookup outcome helper is tested independently from packet construction.
- Query-path negative behavior and outcome-helper behavior are consistent.

## Phase 6: Verify truncation and response-size behavior

### Problem

Byte-size truncation is now implemented, but it needs regression tests across normal, EDNS, DNSSEC, and ACME/TXT paths.

### Implementation tasks

- Add tests for oversized positive response with no EDNS: must return TC and fit within 512 bytes.
- Add tests for oversized positive response with EDNS 4096: should not truncate if under 4096.
- Add tests for oversized TXT/ACME response path; the current ACME helper calls `build_truncated_response` with `rd=false`, so verify whether RD should be echoed and fix if needed.
- Ensure truncated responses preserve query ID, QDCOUNT, question, RD, AA, and RA=false.
- Ensure truncated responses include OPT only when appropriate and ARCOUNT matches.

Acceptance criteria:

- Tests fail if truncation regresses to count-based checks.
- TC response is parseable and policy-consistent.

## Phase 7: Coalescing and parsed-query propagation verification

### Problem

The corrective pass added `from_parsed`, broadcast-on-owner, and cancel-on-failure behavior. It now needs concurrency tests to prove waiters receive responses rather than timing out.

### Implementation tasks

- Add async unit tests for `QueryCoalescer`:
  - First caller receives `NewQuery`.
  - Second identical caller waits.
  - Owner broadcasts response.
  - Waiter receives identical response.
  - Owner cancellation removes in-flight entry.
  - Timeout removes or leaves clean state according to policy.
- Add key-dimension tests:
  - qname/qtype/qclass differ -> key differs.
  - DO bit differs -> key differs if output can differ.
  - client IP differs -> key differs when client dimension is included.
- Ensure UDP and TCP paths use `from_parsed` in the common case.

Acceptance criteria:

- Query coalescing can be enabled without normal waiters timing out after successful owner computation.
- Coalescing key dimensions are tested.

## Phase 8: Runtime smoke tests for already-fixed Milestone 2-adjacent items

### Problem

The corrective pass fixed bind-address usage, DNS64 propagation, and TCP connection guard lifetime. These were not the core of Milestone 1, but they should not regress.

### Implementation tasks

- Add tests or small helper tests for bind-address parsing where practical.
- Add test proving standard-mode handler state receives DNS64 translator when configured. If starting sockets in tests is brittle, test the `query_context()` or handler state construction path.
- Add test for TCP connection guard lifetime if `ConnectionLimits` exposes active-count observability. If not, add a TODO to expose test-only active count later.
- Confirm invalid bind address behavior. Current implementation falls back to `0.0.0.0` on parse failure. Consider changing to fail fast because `DnsConfig::validate` already treats bind address as meaningful configuration. If fallback is retained, document why.

Acceptance criteria:

- Bind-address behavior is explicit and tested or documented.
- DNS64 context propagation has at least one regression test.
- TCP connection guard lifetime has either a test or a documented instrumentation gap.

## Phase 9: External interoperability smoke checks

If local tools are available, run against an ephemeral server loaded with a test zone:

```bash
dig @127.0.0.1 -p <port> www.test.local A +noall +answer +comments
dig @127.0.0.1 -p <port> www.test.local MX +noall +authority +comments
dig @127.0.0.1 -p <port> missing.test.local A +noall +authority +comments
dig @127.0.0.1 -p <port> outside.example A +noall +comments
dig @127.0.0.1 -p <port> large.test.local TXT +bufsize=512 +ignore
dig @127.0.0.1 -p <port> large.test.local TXT +tcp
```

If `drill` or `delv` are available:

```bash
drill @127.0.0.1 -p <port> www.test.local A
drill @127.0.0.1 -p <port> missing.test.local A
delv @127.0.0.1 -p <port> www.test.local A
```

Do not block the pass solely on local tool availability, but record whether these checks were run. If not run, leave an explicit note in docs or commit message.

## Phase 10: Documentation cleanup

Update DNS architecture docs only after behavior is verified.

Required docs updates:

- Milestone 1 status: positive RR encoding, parsed query handling, unsigned negative responses, truncation, and no-zone REFUSED behavior.
- Explicit DNSSEC limitation if signed NODATA/NXDOMAIN is not fully production-clean.
- SOA requirement for authoritative zones.
- AD/RA policy: authoritative-only responses do not set RA; authoritative signing does not set AD.
- Verification command output summary if not captured elsewhere.

Acceptance criteria:

- Docs do not overclaim DNSSEC production readiness.
- Docs clearly distinguish Milestone 1 closed behavior from deferred Milestone 3 DNSSEC hardening.

## Final acceptance checklist

Milestone 1 verification/cleanup is complete when all of the following are true:

- `cargo fmt --all --check` passes.
- `cargo test -p synvoid-dns` passes.
- `cargo test -p synvoid-config dns` passes or any unrelated failure is documented.
- `cargo check -p synvoid-dns --all-features` passes.
- `cargo check --workspace` passes or any unrelated failure is documented.
- Authoritative positive responses do not set RA.
- Authoritative positive responses do not set AD merely because RRSIGs were emitted.
- Signed and unsigned NODATA/NXDOMAIN responses do not set AD.
- Unsigned NODATA includes SOA and returns NOERROR.
- Unsigned NXDOMAIN includes SOA and returns NXDOMAIN.
- Served authoritative zones loaded from config require valid SOA.
- Missing SOA runtime state fails closed for negative responses.
- Truncation is byte-size based and preserves query ID.
- Coalescing waiters receive owner-broadcast responses.
- The `.example` shortcut remains test-only or is removed entirely.
- Signed negative response builders are either typed-encoder-backed or explicitly documented as deferred DNSSEC hardening work.

## Out of scope

This pass must not turn into the full DNSSEC milestone. Defer these unless a small fix is required to keep current tests valid:

- Full NSEC3 closest-encloser implementation.
- RFC 5011 trust-anchor rollover semantics.
- HSM-backed signing failure policy.
- DoT/DoH/DoQ conformance matrix.
- Recursive resolver client allow policy.
- Full config-to-runtime audit.
- Performance/load benchmarking.

## Recommended commit structure

Use small commits if possible:

1. `dns: verify milestone 1 baseline`
2. `dns: remove AD from authoritative responses`
3. `dns: enforce authoritative SOA invariants`
4. `dns: route signed negative responses through encoder`
5. `dns: add truncation and coalescing regressions`
6. `docs: update DNS milestone 1 status`

A single implementation commit is acceptable if the agent workflow prefers it, but keep the PR/commit message explicit about which acceptance criteria were satisfied and which DNSSEC items remain deferred.
