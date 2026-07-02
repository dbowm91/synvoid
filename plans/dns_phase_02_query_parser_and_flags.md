# DNS Phase 2: Canonical Query Parser and Flag Semantics Hardening

## Objective

Replace scattered ad hoc DNS query parsing with one canonical parser and use parsed query state to drive firewall checks, cache keys, coalescing keys, transfer/update/notify dispatch, ordinary lookup, EDNS behavior, DNS cookie handling, and response flag construction.

This phase should make malformed input handling deterministic and should remove direct unchecked packet indexing from query-time logic.

## Current problem summary

The DNS subsystem currently parses QNAME/QTYPE independently in several places: main query handling, cache lookup, query coalescing, firewall pre-checks, transfer detection, IXFR serial extraction, and synthetic negative responses. This creates inconsistent validation, repeated allocation, and risk of slice-bound panics if a helper is reused outside the exact startup path that already ran validation.

Response flags are also hard-coded in several builders. Authoritative responses should not blindly set RD/RA/AD. Flags need to be derived from request flags, server mode, recursion availability, DNSSEC validation state, and response type.

## Primary files and modules

Likely implementation targets:

- `crates/synvoid-dns/src/server/query.rs`
- `crates/synvoid-dns/src/server/response.rs`
- `crates/synvoid-dns/src/wire.rs`
- `crates/synvoid-dns/src/query_validator.rs`
- `crates/synvoid-dns/src/query_coalesce.rs`
- `crates/synvoid-dns/src/firewall.rs`
- `crates/synvoid-dns/src/edns.rs`
- `crates/synvoid-dns/src/tsig.rs`
- `crates/synvoid-dns/src/transfer.rs`
- `crates/synvoid-dns/src/update.rs`
- `crates/synvoid-dns/src/notify.rs`

## Required design

Introduce a canonical parsed query model. Suggested shape:

```rust
pub struct ParsedDnsQuery<'a> {
    pub id: u16,
    pub flags: QueryFlags,
    pub opcode: DnsOpcode,
    pub qdcount: u16,
    pub qname: String,
    pub qname_wire: &'a [u8],
    pub qtype: u16,
    pub qclass: u16,
    pub question_end: usize,
    pub edns: Option<EdnsOptions>,
    pub dnssec_ok: bool,
    pub cookie: Option<ParsedDnsCookie>,
    pub raw: &'a [u8],
}
```

The exact type layout can differ, but it must preserve these invariants:

- All byte offsets are bounds-checked.
- QNAME label length and total name length are validated.
- Compression pointers in query QNAME are rejected unless the project explicitly supports them and can do so safely.
- QDCOUNT policy is explicit. For this server, prefer exactly one question for ordinary query handling.
- QTYPE and QCLASS are available without reparsing.
- EDNS parsing is performed once and carried forward.
- The original question wire bytes can be echoed in responses without reconstructing the name from lossy text.

## Parser behavior requirements

The parser should return structured errors that can map to response codes. Suggested categories:

- `TooShort` -> FORMERR where query ID is available, silent drop otherwise.
- `NotQuery` -> ignore or FORMERR depending on server policy.
- `UnsupportedOpcode` -> NOTIMP for unsupported opcodes where appropriate.
- `BadQuestionCount` -> FORMERR.
- `LabelTooLong` -> FORMERR.
- `NameTooLong` -> FORMERR.
- `PointerInQuestionName` -> FORMERR unless support is explicitly implemented.
- `TruncatedQuestion` -> FORMERR.
- `UnsupportedClass` -> REFUSED or NOTIMP according to policy.
- `MalformedEdns` -> FORMERR or BADVERS if extended RCODE support exists.

Avoid returning `None` from parser code except where the caller truly has no way to build a response.

## Replace current parsing call sites

After adding the parser, update these paths to consume `ParsedDnsQuery`:

1. UDP receive path in `startup.rs`.
2. TCP query path in `query.rs`.
3. `handle_query_with_cache`.
4. `handle_query`.
5. `QueryKey::from_query` or replacement coalescing key constructor.
6. Firewall evaluation path.
7. AXFR/IXFR detection.
8. `extract_ixfr_serial` or a replacement IXFR parser.
9. NOTIFY and UPDATE dispatch.
10. ACME TXT special handling.
11. DNS64 synthesis path.
12. Negative response builders.

Do not leave parallel parsers for qname/qtype extraction unless they are clearly test-only helpers.

## Response flag policy

Create a single response flag constructor. It should consume parsed query flags and server context. Suggested policy:

- Always set QR for responses.
- Set AA for authoritative answers and authoritative negative responses.
- Preserve RD if the query set RD and the project chooses echo semantics.
- Set RA only if recursion is enabled and available to that client under policy.
- Set TC only for truncation.
- Set AD only for validated recursive data, not merely signed authoritative data.
- Set CD only according to recursive validation policy if relevant.
- Set RCODE from explicit response outcome.
- Preserve opcode in the response where appropriate.

For authoritative-only mode, RA should be false. For mixed mode, RA must be per-client-policy-aware, not merely global.

## Coalescing and cache key requirements

The canonical query should provide stable key material. For authoritative responses, key shape must account for all dimensions that can alter output:

- qname normalized to lowercase absolute or canonical project form.
- qtype.
- qclass.
- DNSSEC DO bit.
- EDNS UDP payload size only if it affects truncation/output.
- client IP or ECS prefix if geo-steering, ECS filtering, DNS64, firewall/view policy, or client-dependent answers are enabled.
- transport only if transport changes output.

This phase does not need to repair `broadcast_response`; that is Phase 6. But it should make coalescing key construction use the canonical parser and should avoid reparsing raw packet bytes.

## Firewall and logging requirements

Firewall evaluation should receive parsed qname/qtype/opcode and raw packet only if needed. QNAME privacy integration can be completed in Phase 5/12, but this phase should avoid adding new raw qname logging paths.

Malformed queries should not be logged at high severity unless they indicate a flood or policy violation. Normal malformed internet traffic should be debug or rate-limited warning.

## Test plan

Add parser tests for:

- Valid A query.
- Valid AAAA query.
- Root query.
- Mixed-case qname normalization.
- Trailing-dot behavior.
- QDCOUNT 0.
- QDCOUNT > 1.
- Query shorter than header.
- Truncated qname.
- Label length > 63.
- Full qname length > 255.
- Compression pointer in qname.
- Invalid qclass.
- Unsupported opcode.
- EDNS OPT record with DO bit.
- Malformed EDNS OPT record.
- DNS cookie present, absent, malformed.
- AXFR and IXFR qtype parsing.
- UPDATE and NOTIFY opcode parsing.

Add flag-constructor tests for:

- Authoritative answer with RD unset.
- Authoritative answer with RD set.
- Authoritative-only response does not set RA.
- Truncated response sets TC and preserves ID.
- Unsupported opcode maps to NOTIMP.
- Malformed query maps to FORMERR when possible.
- AD is not set for ordinary authoritative signed responses.

## Acceptance criteria

- `cargo test -p synvoid-dns` passes.
- Main UDP/TCP paths parse each query once and pass parsed state down.
- No production query path manually slices QNAME/QTYPE from raw bytes unless inside the canonical parser.
- Parser errors are structured and mapped to deterministic DNS responses where possible.
- Response flags are built through one policy function.
- Authoritative-only mode does not set RA.
- AD is not set for authoritative signing alone.

## Non-goals

This phase does not need to complete recursive policy isolation, open resolver protections, DNSSEC validation, cache invalidation, or query coalescing broadcast behavior. It should, however, avoid making those later phases harder by keeping parsed query state rich enough for those policies.

## Implementation sequence

1. Add `ParsedDnsQuery`, `QueryFlags`, parser errors, and parser tests.
2. Replace qname/qtype extraction in `handle_query` and `handle_query_with_cache`.
3. Replace coalescer key parsing with parser-derived keys.
4. Replace firewall/startup pre-check extraction with parser-derived fields.
5. Replace transfer/update/notify dispatch parsing.
6. Introduce response flag constructor and update response builders.
7. Remove or mark legacy parser helpers as test-only.
8. Add fuzz or property tests if the project already uses a fuzzing/property test framework.

## Handoff notes

Do not attempt to preserve every legacy return behavior. Silent `None` returns should be narrowed to cases where no valid response can be safely formed. DNS servers are expected to produce explicit error responses for many malformed-but-identifiable queries.
