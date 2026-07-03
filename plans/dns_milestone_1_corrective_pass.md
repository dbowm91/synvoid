# DNS Milestone 1 Corrective Pass

## Completion Summary

**All phases (A–G) are complete.** The DNS module now has:

- **Response flags (Phase A):** `ResponsePolicy` struct and `build_response_flags_with_policy()` centralized in `parsed_query.rs`. All authoritative responses use RA=false and echo RD from query.
- **Byte-size truncation (Phase B):** `build_response` assembles full packet and checks `packet.len() > max_size`. Added `EncodedRecord::wire_len()` and `ResponseEnvelope::total_wire_len()`. Added `build_truncated_tc_response` helper.
- **Parser propagation (Phase C):** `QueryKey::from_parsed()`, `handle_parsed_query()`, `handle_parsed_query_with_cache()`. TCP/UDP paths parse once and pass `ParsedDnsQuery` downward.
- **Authoritative NODATA/NXDOMAIN (Phase D):** `Zone::lookup_authoritative()` returning `AuthoritativeLookupOutcome`. Unsigned negative responses use SOA from zone. `.example` shortcut removed from production flow.
- **Encoder strictness (Phase E):** `SkippedRecord`/`EncodeReport` types. MX priority > u16::MAX rejected. CAA tag > 255 rejected. TLSA validation hardened. SOA encode failure → SERVFAIL. `encode_failures` metric added.
- **Query coalescing (Phase F):** Owner broadcasts response after compute. `cancel_in_flight()` on failure. Negative responses coalesce.
- **Runtime correctness (Phase G):** Bind address from config honored. DNS64 translator passed through. TCP guard inside spawn closure.

See `architecture/dns.md` and `.opencode/skills/dns_dnssec/SKILL.md` for updated architectural details.

## Context

This plan follows the first implementation pass after the DNS production-readiness roadmap and Milestone 1 phase plans. The repository has moved in the correct direction: `crates/synvoid-dns/src/server/response_encoder.rs` now provides a typed response encoder, `crates/synvoid-dns/src/parsed_query.rs` now provides a canonical parser and response flag helpers, and the query path has begun moving away from direct byte slicing.

The remaining issues are not architectural disagreement; they are closure gaps. This corrective pass should convert the new scaffolding into consistent production-adjacent behavior by fixing flag semantics, byte-size truncation, parser propagation, ordinary authoritative negative responses, and a small set of visible runtime regressions that will otherwise obscure Milestone 1 verification.

## Scope

This is a focused corrective pass for DNS Milestone 1. It should not broaden into the full Milestone 2 runtime/config audit except where an already-visible defect blocks Milestone 1 verification or causes misleading tests.

Primary target files:

- `crates/synvoid-dns/src/server/response.rs`
- `crates/synvoid-dns/src/server/response_encoder.rs`
- `crates/synvoid-dns/src/server/query.rs`
- `crates/synvoid-dns/src/parsed_query.rs`
- `crates/synvoid-dns/src/query_coalesce.rs`
- `crates/synvoid-dns/src/query_validator.rs`
- `crates/synvoid-dns/src/server/startup.rs`
- `crates/synvoid-dns/src/firewall.rs`
- `crates/synvoid-dns/src/transfer.rs`
- DNS tests and fuzz targets

## Corrective goals

1. All normal response builders must derive flags from parsed query policy rather than hard-coded RD/RA/AD values.
2. Truncation must trigger from byte size, not record count.
3. Signed authoritative answers must not set AD merely because RRSIGs were emitted.
4. Parser output must become the dominant query state through handler/cache/coalescing/transfer paths.
5. Ordinary unsigned authoritative NODATA/NXDOMAIN must produce SOA-bearing negative responses instead of returning `None`.
6. The special `.example` synthetic NXDOMAIN path must leave production query flow.
7. New encoder behavior must not silently hide malformed zone data without tests, metrics, or explicit policy.
8. Tests must prove the corrected semantics at packet, handler, and integration boundary levels.

## Phase A: Response flag semantics closure

### Problem

The new `parsed_query` module includes canonical response flag constructors, including `build_response_flags_from_query`, but `DnsServer::build_response` still uses hard-coded values equivalent to authoritative, RD=true, RA=true, AD=`records_signed`. That preserves two prior problems: authoritative-only responses can advertise recursion availability, and signed authoritative responses can incorrectly assert AD.

### Implementation tasks

- Add a response policy struct or parameters that carry the original parsed query flags into response construction. Suggested shape:

```rust
pub(crate) struct ResponsePolicy {
    pub authoritative: bool,
    pub recursion_available: bool,
    pub authentic_data: bool,
    pub checking_disabled_allowed: bool,
}
```

- Add variants of `build_response`, `build_truncated_response`, `build_nodata_response`, `build_nxdomain_response`, and ACME TXT response construction that accept either `&ParsedDnsQuery` or a lightweight `ResponseQuestion`/`ResponsePolicy` object.
- Keep compatibility wrappers only if necessary, but ensure production query flow calls the parsed-query-aware versions.
- Set RA false for authoritative-only answers.
- Preserve RD from the parsed query.
- Preserve opcode where applicable for NOTIFY/UPDATE response helpers.
- Do not set AD for authoritative signing alone. Reserve AD for validated recursive data when recursive validation is explicitly implemented.
- Audit every remaining call to `build_response_flags(true, ..., true, true, ...)` or `build_response_flags_full(..., recursion_available=true, authentic_data=true, ...)` and justify or replace it.

### Tests

Add or update tests proving:

- Authoritative answer with RD=false returns RD=false and RA=false.
- Authoritative answer with RD=true returns RD=true and RA=false.
- DNSSEC-signed authoritative answer includes RRSIG but AD remains false.
- Truncated authoritative answer sets TC and preserves RD but not RA.
- NXDOMAIN and NODATA responses follow the same flag policy.

### Acceptance criteria

- No production authoritative response path hard-codes RA=true.
- No production authoritative signing path sets AD solely because records were signed.
- Flag policy is centralized enough that future transport adapters can reuse it.

## Phase B: Byte-size truncation correctness

### Problem

The current `build_response` truncation decision compares `envelope.answer_records.len()` to `max_response_size`. That is a record-count versus byte-size mismatch and will usually fail to trigger truncation for oversized UDP responses.

### Implementation tasks

- Add `ResponseEnvelope::wire_len_with_question(qname, qtype, qclass)` or equivalent helper that estimates/constructs exact packet length before final assembly.
- Prefer exact byte length over heuristic length. If exact assembly is inexpensive, assemble once, check length, and rebuild a minimal TC response if over limit.
- Ensure EDNS OPT additional record size is included in the size calculation.
- Ensure DNSSEC RRSIG sizes are included.
- Decide and implement truncation policy:
  - Minimal TC response with question and optional OPT only, or
  - Partial answer truncation with only complete records.
- Preserve transaction ID and question section.
- Set TC and leave RCODE as NOERROR for normal truncation.
- Add a regression test for a large TXT or many-record response with `udp_payload_size=512` that triggers TC.

### Tests

Add tests for:

- Oversized response triggers TC.
- Non-oversized response does not trigger TC.
- Truncated response preserves ID.
- Truncated response has valid section counts.
- Truncated response parses through the project parser/Hickory if available.
- TCP-sized response path can still emit full answer where test harness supports it.

### Acceptance criteria

- No truncation condition compares record count to byte size.
- Large UDP responses reliably set TC.
- Truncation tests fail on the previous count-vs-byte bug.

## Phase C: Parser propagation and duplicate parsing cleanup

### Problem

`ParsedDnsQuery` exists, but the query path still reparses packet bytes multiple times. TCP parses once for firewall, then coalescing builds a key from raw bytes, transfer handling parses again, `handle_query_with_cache` parses, and `handle_query` parses again.

### Implementation tasks

- Introduce parsed-query-aware handler variants:

```rust
handle_parsed_query(ctx, parsed, client_ip)
handle_parsed_query_with_cache(ctx, parsed, cache, cache_key, client_ip)
```

- Convert UDP startup to parse once and pass `&ParsedDnsQuery` downward.
- Convert TCP query handling to parse once and pass `&ParsedDnsQuery` downward.
- Convert `QueryKey::from_query` to either:
  - `QueryKey::from_parsed(parsed, client_ip, policy_dimensions)`, or
  - a thin wrapper that parses only for callers that genuinely lack parsed state.
- Convert transfer detection to use `parsed.is_axfr()` and `parsed.is_ixfr()` from the same parsed object.
- Convert TSIG parse offsets to use `parsed.question_end`.
- Remove or mark raw-byte parsing helpers as test-only if replaced.
- Keep raw packet bytes available for TSIG, UPDATE, NOTIFY, and wire echoing through `parsed.raw`.

### Tests

Add tests around:

- Cache key generation from parsed query.
- Coalescing key generation from parsed query.
- AXFR and IXFR dispatch using parsed query state.
- Malformed query produces one parser error path and no downstream panics.

### Acceptance criteria

- Main UDP/TCP production paths parse each query once before dispatch.
- Cache, firewall, coalescing, transfer, update, notify, ACME TXT, and ordinary lookup use parsed state where available.
- Raw parsing remains only inside `ParsedDnsQuery::parse`, TSIG-specific parsing, or explicitly documented test helpers.

## Phase D: Authoritative unsigned NODATA/NXDOMAIN closure

### Problem

The query path still returns `None` for ordinary no-zone and unsigned miss cases. DNSSEC-enabled NSEC/NSEC3 paths exist, but ordinary authoritative negative behavior remains incomplete. The special `.example` shortcut still exists in production flow and emits synthetic root-label SOA data.

### Implementation tasks

- Introduce an explicit lookup outcome enum for authoritative query results. Suggested minimum:

```rust
enum AuthoritativeLookupOutcome {
    Positive(Vec<DnsZoneRecord>),
    Cname(Vec<DnsZoneRecord>),
    NoData { soa: DnsZoneRecord },
    NxDomain { soa: DnsZoneRecord },
    NoAuthoritativeZone,
}
```

- Add helper functions:
  - `zone_owner_exists(zone, lookup_name) -> bool`
  - `zone_get_soa(zone) -> Option<DnsZoneRecord>`
  - `lookup_authoritative(zone, lookup_name, qtype) -> AuthoritativeLookupOutcome`
- For matching zone and owner exists but qtype absent, return NODATA with SOA in authority.
- For matching zone and owner absent, return NXDOMAIN with SOA in authority.
- For no matching zone, return REFUSED by default in authoritative-only mode unless recursion policy explicitly says otherwise.
- Remove `.example` shortcut from production flow. If needed, move it into a test helper or replace tests with a loaded `example` zone.
- Ensure negative response builders use the typed encoder for SOA authority records.
- Keep signed denial paths, but route unsigned negative behavior independently so DNSSEC is not required for correct negative responses.

### Tests

Create a small authoritative test zone with SOA, NS, A, TXT, and CNAME. Test:

- Existing owner, existing type -> NOERROR with answer.
- Existing owner, missing type -> NOERROR/NODATA with SOA in authority.
- Missing owner under served zone -> NXDOMAIN with SOA in authority.
- No served zone -> REFUSED or configured no-zone result.
- CNAME owner queried for A -> CNAME behavior remains sane.
- Negative response section counts match emitted authority records.
- Negative response TTL policy is deterministic.
- `.example` no longer receives synthetic special treatment unless a test zone is loaded.

### Acceptance criteria

- Ordinary authoritative misses do not return `None`.
- NODATA and NXDOMAIN include zone SOA for served zones.
- `.example` shortcut is removed or gated out of production flow.
- Negative responses use the same flag policy as positive authoritative responses.

## Phase E: Encoder strictness and malformed zone data policy

### Problem

The new encoder avoids malformed packets by ignoring `encode_rr` failures in `build_response`. This prevents wire corruption, but it can silently produce incomplete NOERROR responses if a zone contains malformed data.

### Implementation tasks

- Decide policy for malformed zone records:
  - Prefer validation at zone load for all supported RR types.
  - If runtime encode failure still occurs, emit structured warning/metric and omit the record only when at least one valid RR remains.
  - If all records for a positive answer fail encoding, return SERVFAIL rather than NOERROR/NODATA unless policy says otherwise.
- Add `EncodeReport` or similar to report skipped records from `build_response`.
- Add metrics/log hooks if the project metrics layer is available in this crate.
- Validate SOA format at zone load for production zones, because negative responses depend on SOA.
- Validate MX priority fits `u16`; currently `u32` priority is cast to `u16`, which can silently wrap/truncate. Reject out-of-range MX priority.
- Validate CAA tag length, SVCB parameter length/order constraints, SSHFP algorithm/fingerprint constraints, and TLSA numeric fields as strictly as feasible.

### Tests

Add tests for:

- Invalid A in zone load is rejected or runtime returns SERVFAIL according to chosen policy.
- MX priority greater than `u16::MAX` is rejected.
- Malformed SOA prevents zone load or causes deterministic SERVFAIL for negative responses.
- Mixed valid/invalid records do not corrupt packets and produce visible diagnostics.

### Acceptance criteria

- No malformed zone record can silently produce a false-success response without diagnostics.
- SOA-dependent negative response tests cannot pass with malformed SOA.
- MX priority overflow/truncation is fixed.

## Phase F: Query coalescing closure at the Milestone 1 boundary

### Problem

Coalescing still appears to create waiters via `get_or_wait`, but the UDP/TCP paths do not visibly broadcast the computed response to those waiters after the owner computes it. That means enabling coalescing can add timeout latency instead of reducing duplicate work.

This is formally Milestone 2 in the broader roadmap, but because the current startup path already exercises coalescing in the Milestone 1 query flow, it should either be fixed or disabled by default with clear tests.

### Implementation tasks

- Add parsed-query-based `QueryKey::from_parsed` as described in Phase C.
- When `get_or_wait` returns `NewQuery`, compute response and call `broadcast_response(key, response.clone())` before returning it to the owner.
- On malformed query, timeout, or handler failure, remove/cleanup the in-flight entry.
- Decide whether negative responses are broadcast. Prefer yes: identical NXDOMAIN/NODATA responses should coalesce if key dimensions match.
- Include DNSSEC DO bit, qclass, qtype, qname, and relevant client dimension in the coalescing key.

### Tests

Add async tests for:

- Two identical in-flight queries result in one owner and one waiter.
- Owner broadcasts positive response.
- Owner broadcasts negative response.
- Timeout cleans up in-flight entry.
- Coalescing key differs when DO bit differs.

### Acceptance criteria

- Coalescing does not create waiters that can only time out under normal success.
- Coalescer metrics reflect hit/miss behavior after response broadcast.

## Phase G: Minimal runtime correctness cleanup needed for verification

### Problem

A few non-Milestone-1 runtime defects remain visible in the same files and can invalidate integration tests: standard mode ignores `dns.bind_address`, standard UDP/TCP contexts pass `dns64_translator: None`, and TCP connection guard is dropped before the spawned task lifetime.

### Implementation tasks

- Honor `self.config.bind_address` when constructing UDP/TCP bind addresses.
- Pass `self.dns64_translator` through `DnsHandlerState` and into UDP/TCP `QueryContext` instead of `None`.
- Hold the TCP connection limit guard for the lifetime of the spawned task. Move the guard into the `tokio::spawn` closure and bind it to a named variable there.
- Add smoke tests where practical, or at minimum unit tests for bind address parsing if direct socket tests are brittle.

### Tests

Add tests for:

- Bind address parsing accepts configured IPv4 and IPv6 bind addresses.
- DNS64 translator present in `query_context()` and standard handler state where config enables it.
- TCP guard lifetime behavior is covered if `ConnectionLimits` exposes observable active count; otherwise add a targeted unit test around guard scoping.

### Acceptance criteria

- Standard listener no longer ignores `dns.bind_address`.
- DNS64 config is not silently inert in standard mode.
- TCP connection limits hold slots during query processing.

## Phase H: Verification pass

### Required commands

Run at least:

```bash
cargo fmt --all
cargo test -p synvoid-dns
cargo test -p synvoid-config dns
cargo check -p synvoid-dns --all-features
cargo check --workspace
```

If fuzz tooling is configured and cheap enough:

```bash
cargo fuzz run parsed_query_parse -- -max_total_time=30
```

If external DNS tools are available locally, run manual interoperability checks against an ephemeral test server:

```bash
dig @127.0.0.1 -p <port> www.example.test A +noall +answer +comments
dig @127.0.0.1 -p <port> www.example.test AAAA +noall +authority +comments
dig @127.0.0.1 -p <port> missing.example.test A +noall +authority +comments
dig @127.0.0.1 -p <port> outside.test A +noall +comments
dig @127.0.0.1 -p <port> large.example.test TXT +bufsize=512 +ignore
dig @127.0.0.1 -p <port> large.example.test TXT +tcp
```

### Regression checklist

- Positive A response parses and has correct counts.
- Positive MX response parses and has correct RDLENGTH.
- Positive TXT response parses and has correct RDLENGTH.
- Positive DNSSEC-signed response does not set AD in authoritative-only mode.
- Oversized UDP response sets TC by byte size.
- NODATA includes SOA.
- NXDOMAIN includes SOA.
- No-zone behavior is explicit.
- `.example` synthetic behavior is gone from production path.
- Coalescing owner broadcasts response or coalescing is disabled and documented.
- Standard bind address is honored.
- TCP connection limit guard is held across spawned task lifetime.

## Out of scope

Do not attempt to complete full DNSSEC NSEC3 closest-encloser correctness, production recursive resolver policy, DoT/DoH/DoQ conformance, RPZ, full config-to-runtime matrix, or performance optimization in this corrective pass. Those are subsequent roadmap phases.

## Completion definition

This corrective pass is complete when Milestone 1 can be summarized as:

- The response encoder emits structurally valid packets for supported positive RRsets.
- Response flags are policy-derived and do not advertise recursion or AD incorrectly in authoritative-only mode.
- Truncation works by byte size and preserves query identity.
- The main query path uses parsed query state rather than repeated raw parsing.
- Authoritative unsigned negative responses are explicit and SOA-bearing.
- The special `.example` shortcut no longer affects production behavior.
- Tests exist for each corrected bug class.
