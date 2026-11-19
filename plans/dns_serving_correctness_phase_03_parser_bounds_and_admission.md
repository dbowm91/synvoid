# Phase 03 Plan: Parser Bounds and Unified Admission

Status: **IMPLEMENTED** (2026-11-19; `dns_admission_contract`, 9 tests, plus
the EDNS/TSIG fuzz targets).
Audit: `plans/dns_capability_audit.md` (D3, D12, D14, D15, D16, D12b, D33).
Registered in: `plans/roadmap.md`.
Campaign: `plans/dns_serving_correctness_roadmap.md`.
Predecessor: Phase 01.
Depends on: Phase 02 for the single EDNS header parse this phase bounds; the
admission function added here is what later phases route every query through.

## The findings

**D3 (Critical, confirmed by execution).** `EdnsOptions::parse_from_query`
bounds its option loop with the attacker-declared RDLENGTH:

```rust
while rdata_pos + 4 <= pos + rdlen as usize {   // edns.rs:214
    let option_code = u16::from_be_bytes([query[rdata_pos], query[rdata_pos + 1]]);
```

`pos + rdlen` is never clamped to `query.len()`. A 30-byte query passes the
production validator and panics at `edns.rs:215`. The UDP loop handles packets
inline in one spawned task (`server/startup.rs:180-424`) with `panic = "unwind"`,
so the task unwinds, the socket drops, and nothing respawns it.

**D15 (Medium).** The same loop's entry guard is `while pos + 10 <= query.len()`
(`edns.rs:172`) but the OPT branch reads 11 bytes (`name` + type + class + TTL
+ flags + RDLENGTH); `query[pos + 10]` is one past the end when the packet ends
exactly there.

**D16 (Medium).** ECS prefix length is a `u8` used directly as an array slice
length (`edns.rs:219-241`): `octets[..addr_bytes]` panics for a v4 prefix above
32 or a v6 prefix above 128, even with a correctly sized option.

**D12 (High, latent).** `parse_tsig_from_query` (`tsig.rs:332-421`) does not
follow the RR layout: after the name it reads TYPE, then skips two bytes
(CLASS) but not TTL or RDLENGTH, and the name walk can leave `pos == len`
before the TYPE read. A model of the function panics on random input of 28–51
bytes. It is called before any ACL check on AXFR/IXFR (`server/query.rs:399,
427,613,636`), so enabling transfers turns it into a pre-auth remote panic.

**D14 (Medium).** A packet with `QR=1` is answered with NOTIMP
(`query_validator.rs:385-393`) because `is_standard_query()` is false for
responses. The later `if flags.is_response` branch is unreachable. Two servers
fed each other's responses loop, and a spoofed source turns the server into a
small reflector.

**D12b (High).** UDP and TCP validate the packet, evaluate the firewall, and
apply the per-IP rate limiter (`startup.rs:239-300`, `:485`, `query.rs:206-238`).
DoT, DoH, and DoQ call `DnsServer::handle_query(_with_cache)` directly
(`dot.rs:205-218`, `doh.rs:250-258`, `doq.rs:298-313`), so a client that
switches port bypasses the query validator, every firewall rule, and the rate
limit.

**D33 (Medium).** The TLS accept loop (`secure_server.rs:175-215`) and the DoQ
accept loop (`doq.rs:130-160`) spawn one task per connection with no cap; plain
TCP has `LimitsConfig.max_connections`, the encrypted listeners do not.

## Root cause

Parsing was written per field with bare slice indexing, and admission logic was
copied into the two listener loops instead of being a function. The encrypted
listeners predate the validator/firewall work and were never retrofitted.

## Fix scope

### R1 — Bounded EDNS parsing

- Compute `let opt_end = (pos + rdlen as usize).min(query.len());` and bound
  the option loop and every option body against `opt_end`.
- Entry guard `pos + 11 <= query.len()`.
- ECS: require `family` 1 or 2 and `prefix_len <= 32|128`, require the option
  body to hold the declared address bytes, and write into the array with
  `get_mut(..n)` rather than slicing.
- Cookie/EDE/keepalive: bound each body before reading or slicing.
- No option may advance `rdata_pos` past `opt_end`.

### R2 — Rewrite the TSIG RR parser

Replace the index arithmetic with a reader:

```rust
struct Reader<'a> { buf: &'a [u8], pos: usize }
impl Reader<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]>;
    fn name(&mut self) -> Option<String>;   // labels, no compression
    fn u16(&mut self) -> Option<u16>;
    fn u48(&mut self) -> Option<u64>;
}
```

Parse `NAME, TYPE, CLASS, TTL, RDLENGTH` in order, then the RDATA inside
exactly `RDLENGTH` bytes: algorithm name, time, fudge, mac size, mac, error,
other length, other data. Reject a key name or algorithm name that is not
complete, a MAC longer than the remaining RDATA, and trailing bytes. Return
`Option` on every failure — no indexing.

Keep the parse call before the ACL only if it is bounded; the ACL check should
also be reachable without parsing TSIG (see R3), so an unauthenticated packet
never reaches a parser before a cheaper rejection.

### R3 — One admission function

```rust
pub enum Admission { Allow(ParsedQuery), Reply(Vec<u8>), Drop }
pub fn admit(
    query: &[u8],
    client_ip: IpAddr,
    transport: TransportClass,
    ctx: &QueryContext<'_>,
    limits: &LimitsConfig,
) -> Admission;
```

Order (cheapest first): size bound → 12-byte header → `QR=1` → **Drop** → opcode
(QUERY/NOTIFY/UPDATE only; anything else NOTIMP) → QDCOUNT → question parse →
QCLASS (IN only; ANY per policy) → EDNS version (`BADVERS`) → firewall → rate
limit → Allow.

- `QR=1` is dropped, never answered (D14).
- UDP, TCP, DoT, DoH, and DoQ all call `admit`; the listener keeps only framing
  and response write.
- `handle_query` stays as the dispatch entry but is not called by a listener
  that has not admitted the packet. Add a `debug_assert!` or a token type so a
  future listener cannot skip admission silently.

### R4 — Encrypted listener parity and caps

- DoT/DoH/DoQ call `admit` with their transport class.
- Add a `tokio::sync::Semaphore` to `SecureDnsServerBase::accept_loop` and the
  DoQ accept loop, sized from `LimitsConfig` (new field
  `max_encrypted_connections`, default equal to `max_tcp_connections`), and
  drop-with-log when exhausted. TLS handshake timeout already exists; the DoQ
  handshake needs one.
- Metrics: `synvoid.dns.admission.dropped{reason}` and
  `synvoid.dns.encrypted_connections.saturated`.

### R5 — Fuzz the parsers that had no coverage

Add `fuzz/dns_edns_options.rs` and `fuzz/dns_tsig_parse.rs`; register both in
`fuzz/Cargo.toml` as `[[bin]]` entries (the DNS targets do not auto-discover).
Corpus seeds: a well-formed OPT, a lying RDLENGTH, ECS with prefix 255, a
two-option OPT, a well-formed TSIG, and a TSIG whose name ends on the last byte.

### R6 — Hostile-packet and parity tests

New suite `tests/dns_admission_contract.rs`:

1. the 30-byte EDNS packet from the audit returns FORMERR/REFUSED and does not
   panic (regression for D3);
2. the 40-byte off-by-one packet (D15) returns an error;
3. ECS prefix 255 / family 1 returns an error;
4. `QR=1` produces **no** response on UDP and TCP;
5. a query blocked by a firewall rule is refused identically on UDP, TCP, DoT,
   DoH, and DoQ (drive each listener with `support::runtime_config`'s
   `start_bound_dns_server` and the encrypted-transport harness);
6. a rate-limited client is limited on every transport;
7. the encrypted-connection cap refuses the N+1th connection and the server
   still answers after the first ones close;
8. a TSIG name ending on the final byte is rejected, not panicking (unit test
   beside the parser).

Existing suites that assert NOTIMP for `QR=1` must be updated to assert the
drop; grep `RCODE_NOTIMP` in `authoritative_negative.rs` before changing.

## Out of scope

- TSIG MAC correctness and full-RR emission (phase 07).
- Admission policy changes (allowlists, ACLs) beyond parity.
- QUIC 0-RTT handling and TLS resumption.

## Verification

```bash
cargo test -p synvoid-dns --test dns_admission_contract --profile ci
cargo test -p synvoid-dns --profile ci
cargo +nightly fuzz run dns_edns_options -- -max_total_time=60
cargo +nightly fuzz run dns_tsig_parse -- -max_total_time=60
```

Acceptance:

- `rg 'query\[' crates/synvoid-dns/src/edns.rs` shows only reads preceded by a
  bound check or inside `Reader`;
- the audit's 30-byte packet is a regression test;
- every listener's test path goes through `admit` (grep shows five call sites,
  one per transport);
- fuzz targets run 60 s clean.
