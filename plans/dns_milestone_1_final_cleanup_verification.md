# DNS Milestone 1 Final Cleanup and Verification Plan

## Context

DNS Milestone 1 is now close to closure. The authoritative unsigned path has a typed encoder, parser-driven query flow, byte-size truncation, SOA-backed NODATA/NXDOMAIN, no-zone REFUSED behavior, improved flag semantics, and broad regression tests. The remaining work should be a narrow closure pass, not another feature phase.

The current residual risks are concentrated around signed NXDOMAIN SOA inclusion, compile/test evidence, duplicate DNS source trees, and final documentation accuracy.

## Goal

Close DNS Milestone 1 with a clear verification record and no known protocol correctness gaps in the core authoritative path.

## Non-goals

Do not implement full DNSSEC production readiness, full recursive resolver policy, DoT/DoH/DoQ hardening, RPZ, performance benchmarking, or the full config-to-runtime matrix in this pass. Those belong to later milestones.

## Scope

Primary files:

- `crates/synvoid-dns/src/server/query.rs`
- `crates/synvoid-dns/src/server/response.rs`
- `crates/synvoid-dns/src/server/response_encoder.rs`
- `crates/synvoid-dns/src/server/zone.rs`
- `crates/synvoid-dns/tests/authoritative_negative.rs`
- `architecture/dns.md`
- duplicate legacy DNS files under `src/dns/` if still present

## Workstream 1: Establish verification baseline

Run and record:

```bash
cargo fmt --all --check
cargo test -p synvoid-dns
cargo test -p synvoid-config dns
cargo check -p synvoid-dns --all-features
cargo check --workspace
```

If any command fails, fix the failure before proceeding unless the failure is demonstrably unrelated to DNS. Any unrelated failure must be documented with exact crate, command, and error class.

Optional, if tooling is available:

```bash
cargo fuzz run parsed_query_parse -- -max_total_time=30
```

Acceptance criteria:

- The pass leaves a known command-result record in commit notes or docs.
- `synvoid-dns` test and all-feature check pass.
- Workspace status is either passing or has explicitly documented unrelated failures.

## Workstream 2: Signed NXDOMAIN SOA closure

Problem: signed NODATA now accepts an SOA and routes through the typed encoder, but signed NXDOMAIN appears to emit denial proof records without including SOA in the authority section.

Tasks:

- Change `build_nxdomain_response` to accept `soa_record: Option<&DnsZoneRecord>` or a compact negative-response context.
- Thread the zone SOA into the signed NXDOMAIN call site in `handle_parsed_query`.
- Add the SOA to `ResponseEnvelope.authority_records` before NSEC/NSEC3 proof records.
- Encode SOA through `encode_rr`; do not hand-write SOA bytes.
- If the SOA is missing or fails encoding, return SERVFAIL or a deterministic fail-closed response rather than a bare NXDOMAIN.
- Ensure AD remains false.
- Ensure ARCOUNT is derived from `additional_records`, not manually patched.

Tests:

- Signed NXDOMAIN includes SOA in authority.
- Signed NXDOMAIN includes NSEC or NSEC3 proof records when configured.
- Signed NXDOMAIN has AD=false and RA=false.
- Signed NXDOMAIN NSCOUNT equals the actual number of authority records on the wire.
- Missing SOA in signed NXDOMAIN path fails closed.

Acceptance criteria:

- Unsigned and signed NXDOMAIN both include SOA for served zones.
- No signed negative path emits textual SOA RDATA.
- No signed negative path manually patches inconsistent section counts.

## Workstream 3: Duplicate DNS tree decision

Problem: both `crates/synvoid-dns/...` and `src/dns/...` paths exist and were touched during recent cleanup. This is a long-term maintenance hazard because fixes can diverge.

Tasks:

- Determine whether `src/dns` is still compiled, used by another crate, or stale legacy code.
- If stale, remove the duplicate DNS implementation or reduce it to compatibility shims that re-export the crate implementation.
- If retained intentionally, add a top-of-file note explaining ownership and synchronization rules.
- Search for imports from `src::dns`, `crate::dns`, and path-module inclusions that reference the duplicate tree.
- Update docs to make the canonical implementation path explicit: `crates/synvoid-dns`.

Acceptance criteria:

- There is one canonical DNS implementation path.
- Any retained duplicate/shim path is documented and cannot silently drift.
- Future agents know where to apply DNS changes.

## Workstream 4: Runtime invalid SOA fail-closed behavior

Config and store loading now reject zones without SOA, but direct in-memory test construction and dynamic mutation can still create malformed zone state.

Tasks:

- Ensure `build_unsigned_nodata` and `build_unsigned_nxdomain` return SERVFAIL when `soa=None`.
- Ensure signed NODATA and signed NXDOMAIN return SERVFAIL when SOA is required but unavailable.
- Add metrics/logging for missing-SOA runtime state.
- Consider making `Zone::lookup_authoritative` return a structured internal-invalid variant when SOA is required but missing.

Tests:

- In-memory zone with no SOA returns SERVFAIL for NODATA.
- In-memory zone with no SOA returns SERVFAIL for NXDOMAIN.
- Config-load zone without SOA remains rejected.
- Store-load zone without SOA remains rejected.

Acceptance criteria:

- Served-zone negative responses never claim NODATA/NXDOMAIN without SOA.
- Malformed in-memory zone state fails closed.

## Workstream 5: Final authoritative flag regression tests

The flag policy is now mostly correct. Lock it down with tests.

Tests to add or confirm:

- Positive authoritative response: AA=true, RD echoes query, RA=false, AD=false.
- Positive signed authoritative response: RRSIG present where expected, AD=false.
- Unsigned NODATA: AA=true, RA=false, AD=false.
- Unsigned NXDOMAIN: AA=true, RA=false, AD=false.
- Signed NODATA: AA=true, RA=false, AD=false.
- Signed NXDOMAIN: AA=true, RA=false, AD=false.
- REFUSED no-zone: RA=false, AD=false.
- TC response: TC=true, AA=true, RD echoed, RA=false, AD=false.

Acceptance criteria:

- A future reintroduction of AD or RA into authoritative-only responses fails tests.

## Workstream 6: Documentation closure

Update `architecture/dns.md` only after verification passes.

Document:

- Milestone 1 closed behavior.
- Exact verification commands and results.
- Canonical implementation path.
- DNSSEC limitation boundaries, especially if full NSEC3 closest-encloser semantics remain deferred.
- Explicit AD/RA policy.
- Authoritative-zone SOA requirement.

Acceptance criteria:

- Docs do not overclaim full DNSSEC production readiness.
- Docs make clear that Milestone 1 is authoritative wire/query correctness, not full DNSSEC/recursive transport hardening.

## Final checklist

Milestone 1 can be marked closed when:

- `cargo test -p synvoid-dns` passes.
- `cargo check -p synvoid-dns --all-features` passes.
- Core authoritative responses are parseable and count-correct.
- Signed and unsigned NXDOMAIN include SOA.
- AD is never set by authoritative signing.
- RA is false for authoritative-only responses.
- Truncation is byte-size based and tested.
- Duplicate DNS tree status is resolved.
- Docs state the exact remaining DNSSEC deferrals.
