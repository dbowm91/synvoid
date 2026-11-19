# Phase 02 Plan: Response Envelope and EDNS

Status: **IMPLEMENTED** (2026-11-19; `dns_envelope_contract`, 12 tests).
Audit: `plans/dns_capability_audit.md` (D7, D8, D13, D17).
Registered in: `plans/roadmap.md`.
Campaign: `plans/dns_serving_correctness_roadmap.md`.
Predecessor: Phase 01 (owner encoder).
Depends on: Phase 01 for `encode_rr`'s new signature; this phase touches the
same response builders.

## The finding

**D7 (High).** `build_opt_encoded_record`
(`crates/synvoid-dns/src/server/response_encoder.rs:410-421`) writes:

```rust
bytes.push(0x00);                                            // NAME
bytes.extend_from_slice(&41u16.to_be_bytes());               // TYPE
bytes.extend_from_slice(&(opt_rdata.len() as u16).to_be_bytes()); // CLASS = 6
bytes.extend_from_slice(&opt_rdata);                         // TTL + RDLENGTH
```

`build_opt_record` returns `[udp_payload(2), flags(2), 0(2)]`, so the wire is
`CLASS = 6`, `TTL = 0x1000_0000` (extended RCODE 16, `BADVERS`), `RDLENGTH = 0`.
Every EDNS response carries a bogus RCODE and a 6-byte payload advertisement.
There are ten call sites (`server/response.rs:82,131,171,502,565,602,611,653,
690`; `server/query.rs:1071`) and no test reads the OPT back.

**D8 (High).** `EdnsOptions::parse_from_query` floors the client's advertised
size to 4096 (`edns.rs:293-297`), and `build_opt_record` does the same when
advertising ours (`edns.rs:315-322`). `build_response` uses that value as the
hard response limit (`server/response.rs:20-22`), so a client that advertises
512 or 1232 receives up to 4 KiB.

**D13 (Medium).** `wire::build_error_response` (`wire.rs:277-300`) builds the
header with `build_response_header(id, flags, 0, 0, 0, 0)` — `QDCOUNT = 0` —
and then appends the question bytes. Every validator rejection and NOTIMP
therefore claims zero questions while carrying one.

**D17 (Medium).** `parse_edns_options` (`edns.rs:357-378`) skips the question
using only `QDCOUNT` and then treats trailing bytes as OPT; `ARCOUNT` is never
read. `ParsedDnsQuery` separately guesses `has_edns`/`dnssec_ok` from
`query[question_end + 1..3]` (`parsed_query.rs:198-217`), assuming the first
additional RR starts with a root name. A zero-length root owner is required by
RFC 6891 but is not checked, and the DO bit is read from an
attacker-chosen offset.

## Root cause

The OPT record was assembled by concatenating the option RDATA produced for the
*request* side, instead of being written field by field. EDNS parsing was added
in three places (handler, `ParsedDnsQuery`, validator) with three different
assumptions, and none of them consults the header counts. The envelope tests
only assert ARCOUNT (`response.rs:896`), so the layout error is invisible.

## Fix scope

### R1 — Write the OPT record field by field

Replace `build_opt_encoded_record` with a builder that takes the payload size,
the DO bit, and an extended RCODE:

```text
NAME      = 0x00
TYPE      = 41
CLASS     = udp_payload_size     (advertised, already clamped)
TTL       = (extended_rcode << 24) | (0 << 16) | flags   (DO = 0x8000)
RDLENGTH  = 0 (no options are emitted today)
```

Delete `EdnsOptions::build_opt_record`'s 6-byte layout or reduce it to the
option RDATA it is meant to be, so the two encoders cannot drift. `RDLENGTH`
must equal the bytes actually emitted; when options are added later (cookies,
EDE) they go through the same builder.

### R2 — Honor the client's payload size

`edns_payload(query_size) -> u16`:

- no EDNS → 512 (IPv4 UDP minimum; IPv6 1232 is a config choice, not a floor);
- EDNS → `advertised.clamp(512, 4096)`; never raise a smaller value.

Use it for the response budget *and* for the size we advertise in our own OPT,
and apply the TCP/DoT/DoH/DoQ rule (65535) explicitly rather than inheriting
the UDP budget. The TC decision stays where it is; it simply becomes meaningful
once the budget is honest.

### R3 — Error responses carry a consistent question section

`build_error_response` must either emit `QDCOUNT = 1` plus the parsed question
bytes, or `QDCOUNT = 0` with no question bytes. Prefer the first: copy
`query[12..question_end]` from the parsed query, reject a query whose question
does not parse, and never walk past the buffer. The same helper is used for
REFUSED, NOTIMP, FORMERR, and SERVFAIL paths.

### R4 — One EDNS parse, ARCOUNT-aware

- Require `arcount >= 1`, `query[question_end] == 0`, and 11 bytes in bounds
  before reading the OPT fixed header.
- Exactly one OPT is allowed; a second is a FORMERR (RFC 6891 §6.1.1).
- An OPT in a query with `arcount == 0` is not EDNS; the packet is treated as
  non-EDNS or rejected, never parsed.
- `version != 0` → respond `BADVERS` (extended RCODE 16) with an OPT, do not
  answer the question.
- Return the parsed `EdnsOptions` once, from `ParsedDnsQuery`, and pass it to
  the handler; delete the duplicate positional sniffing in `parsed_query.rs` and
  the second parse in `query.rs`.

### R5 — Tests decode the envelope

Add to `tests/support/response.rs`:

- `parse_opt(resp) -> Option<OptRecord { payload, ext_rcode, version, flags, rdlen }>`;
- `response_question(resp) -> Option<String>`;
- `response_qdcount(resp)`.

New suite `tests/dns_envelope_contract.rs`:

1. an EDNS query's response OPT has `CLASS == 4096` (or the clamped client
   value), `ext_rcode == 0`, `version == 0`, `RDLENGTH == 0`;
2. `DO=1` echoes `DO`; `DO=0` does not;
3. a client advertising 512 receives a response ≤ 512 and `TC=1` when the
   answer does not fit;
4. a client advertising 1232 receives ≤ 1232;
5. a non-EDNS query receives ≤ 512 and no OPT;
6. a request with `version = 1` receives `BADVERS` with an OPT;
7. a request with two OPT records receives FORMERR;
8. `ARCOUNT = 0` with OPT-shaped bytes is not treated as EDNS;
9. every error builder emits `QDCOUNT` equal to the questions it wrote and a
   question that decodes to the query name;
10. `build_error_response` on a truncated question does not panic.

### R6 — CI gate

Add `dns-envelope` to `verify_steps()` in `tools/xtask/src/verify.rs` (the lane
CI runs) plus a `--list` count guard, as in phase 01. No DNS suite is
registered in CI today; adding the step is what makes it gate PRs.

## Out of scope

- EDNS option parsing bounds (phase 03) — this phase assumes the packet is
  structurally valid up to the OPT fixed header.
- Cookies and EDE emission (phase 07).
- DNSSEC record placement (phases 04/05).

## Verification

```bash
cargo test -p synvoid-dns --test dns_envelope_contract --profile ci
cargo test -p synvoid-dns --test dns_interop_truncation --profile ci
cargo test -p synvoid-dns --test dns_interop_dnssec --profile ci
cargo test -p synvoid-dns --profile ci
```

Acceptance:

- no response on any EDNS path has `ext_rcode != 0` or `CLASS != payload`;
- `rg 'udp_payload_size: if udp_payload >= 4096'` returns nothing;
- `rg 'build_opt_record' crates/synvoid-dns/src` shows one OPT encoder;
- the truncation suite still passes and now exercises both 512 and 1232.
