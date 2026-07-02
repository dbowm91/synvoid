# DNS Phase 1: Wire-Format Response Encoder Closure

## Objective

Replace the current ad hoc DNS response byte construction with a safe, typed response encoder boundary. The phase is complete when supported RR types produce parseable DNS packets, section counts match emitted records, malformed zone data cannot corrupt a response, and UDP truncation preserves query identity while setting the correct DNS semantics.

This is the first Milestone 1 phase because the server cannot be treated as production-adjacent until its wire output is deterministic and valid.

## Current problem summary

The existing `build_response` path appends owner/type/class/TTL before RR-specific encoding has succeeded. Several RR branches either omit `RDLENGTH`, compute it incorrectly, or can skip unsupported records after partial RR headers have already been appended. `ANCOUNT` is patched from input `records.len()` rather than successfully encoded records. This creates malformed DNS messages under ordinary record types and especially under invalid zone data.

The truncation path also generates a fresh random response ID and emits SERVFAIL-like flags instead of preserving the request ID and setting TC on a valid response envelope.

## Primary files and modules

Likely implementation targets:

- `crates/synvoid-dns/src/server/response.rs`
- `crates/synvoid-dns/src/server/query.rs`
- `crates/synvoid-dns/src/server/dnssec_impl.rs`
- `crates/synvoid-dns/src/wire.rs`
- `crates/synvoid-dns/src/zone_file.rs`
- `crates/synvoid-dns/tests/` for integration tests if available

Do not spread new packet-writing helpers across unrelated modules. Prefer a compact `wire` or `response` submodule with one explicit encoder boundary.

## Required design

Introduce typed intermediate structures for response assembly. Suggested shapes:

```rust
struct EncodedRecord {
    section: DnsSection,
    record_type: RecordType,
    ttl: u32,
    bytes: Vec<u8>,
}

enum DnsSection {
    Answer,
    Authority,
    Additional,
}

struct ResponseEnvelope<'a> {
    query_id: u16,
    qname: &'a str,
    qtype: u16,
    qclass: u16,
    flags: ResponseFlags,
    edns: Option<&'a EdnsOptions>,
}
```

The exact names may differ, but the invariant must not: a record encoder must return a complete record byte vector or an error before packet assembly mutates the response buffer. Packet assembly then appends only complete records and derives counts from the vectors it actually appends.

Keep encoding errors structured enough for tests and logs. Avoid returning `None` for malformed record data when a concrete error can explain the failure.

## RR encoding requirements

Implement or repair at least these record encoders:

- A: validate IPv4, RDLENGTH 4.
- AAAA: validate IPv6, RDLENGTH 16.
- CNAME, NS, PTR: encode target domain with root terminator and correct RDLENGTH.
- SOA: encode MNAME, RNAME, SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM in wire format. Do not treat SOA as opaque text in production response paths.
- MX: encode 16-bit preference plus exchange name; RDLENGTH must include both.
- TXT: split into <=255-byte character strings, but RDLENGTH must equal total TXT payload length.
- CAA: encode flags, tag length, tag, and value with strict length checks.
- TLSA: encode usage, selector, matching type, and cert association bytes.
- SVCB and HTTPS: preserve priority, target name, sorted parameters, and valid parameter lengths.
- NAPTR: encode order, preference, flags, services, regexp, and replacement.
- SSHFP: encode algorithm, fingerprint type, and decoded fingerprint bytes.
- DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM: keep existing logic if structurally valid, but route through the same complete-record boundary.

Unsupported RR types must fail before any bytes are appended. Invalid record values must either be rejected at zone load or omitted with a structured encoding error. Do not let invalid A, invalid AAAA, invalid MX, or malformed TXT produce partial packets.

## Packet assembly requirements

The response builder must:

1. Preserve query ID.
2. Echo exactly one validated question unless the parsed query policy rejects the packet elsewhere.
3. Append answer, authority, and additional records from pre-encoded vectors only.
4. Patch or write `QDCOUNT`, `ANCOUNT`, `NSCOUNT`, and `ARCOUNT` from actual emitted section lengths.
5. Apply EDNS OPT records through the same additional-section count path.
6. Apply DNSSEC RRSIG records only after the covered RRset is known to have encoded successfully.
7. Avoid setting AD merely because signatures were emitted; flag semantics will be completed in Phase 2, but Phase 1 must not further entrench incorrect semantics.
8. Ensure generated packets parse under the project parser and Hickory.

## Truncation requirements

Replace the current truncation builder with a function that receives at least query ID, question, qtype, qclass, and desired flags. The truncation response must:

- Preserve the original query ID.
- Set QR.
- Set TC.
- Preserve AA for authoritative responses.
- Preserve RD if the project policy preserves it.
- Set RA only if recursion is available to this client and mode.
- Avoid fabricating SERVFAIL solely because the response is too large.
- Include a valid question section.
- Prefer zero answers for minimal truncation unless a carefully bounded partial answer policy is implemented and tested.

Do not generate random transaction IDs in truncation paths.

## Test plan

Add unit tests for every individual record encoder. These tests should verify exact RDLENGTH and parseability.

Add response-level tests for:

- Single A response.
- Multiple A/AAAA records.
- CNAME response.
- MX response with non-default priority.
- TXT values under and over 255 bytes.
- PTR response.
- SOA response.
- CAA response.
- TLSA response.
- SVCB and HTTPS response.
- NAPTR response.
- SSHFP response.
- DNSKEY and DS response.
- Response containing RRSIG when DNSSEC is enabled.
- Unsupported record type does not corrupt packet.
- Invalid A/AAAA/MX/TXT-like data does not corrupt packet.
- EDNS OPT additional record increments ARCOUNT correctly.
- Truncation preserves query ID and sets TC.

Add parser round-trip tests using Hickory if already available as a dependency. If Hickory is not available in the test dependency graph, add the smallest acceptable dev-dependency or use the existing project DNS parser as a first gate and note Hickory interoperability as a follow-up task.

## Integration checks

Where feasible, add a local integration test that starts the DNS server on an ephemeral UDP/TCP port, loads a test zone, and queries it with a Rust client. External CLI tools such as `dig`, `drill`, and `delv` should be documented as manual verification commands if not suitable for CI.

Suggested manual checks:

```bash
dig @127.0.0.1 -p <port> example.test A +noall +answer +comments
dig @127.0.0.1 -p <port> example.test MX +noall +answer +comments
dig @127.0.0.1 -p <port> example.test TXT +bufsize=512 +dnssec
dig @127.0.0.1 -p <port> large.example.test TXT +bufsize=512 +ignore
dig @127.0.0.1 -p <port> large.example.test TXT +tcp
```

## Acceptance criteria

- `cargo test -p synvoid-dns` passes.
- New response encoder tests cover all supported RR types listed above.
- No supported record type omits RDLENGTH.
- No unsupported or malformed record can leave partial RR bytes in a response.
- Counts match actual emitted records in all tested paths.
- Truncated responses preserve transaction ID and set TC.
- Large UDP response tests prove TCP retry receives the full answer once Phase 4 runtime tests are available; for Phase 1, the truncation packet itself must be valid.

## Non-goals

This phase should not attempt to finish all DNSSEC validity semantics, recursive resolver policy, DoT/DoH/DoQ behavior, cache invalidation, or config fidelity. It may touch DNSSEC record encoding only where necessary to route signatures through the safe encoder boundary.

## Implementation sequence

1. Add failing tests for current malformed RR encodings and truncation ID behavior.
2. Introduce typed encoded-record helpers.
3. Port A, AAAA, CNAME, NS, PTR, SOA, MX, and TXT first.
4. Port CAA, TLSA, SVCB, HTTPS, NAPTR, and SSHFP.
5. Route DNSSEC-related emitted records through the same boundary.
6. Replace `build_response` count patching with section-vector counts.
7. Replace truncation builder.
8. Run tests and add regression cases for every fixed bug.

## Handoff notes

Prefer correctness over retaining existing byte layout. DNS clients care about valid wire semantics, not current internal packet order. If an existing test asserts malformed behavior, update the test to assert protocol-correct behavior and document the correction in the test name.
