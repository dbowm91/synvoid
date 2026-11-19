# DNS Capability Audit — Wire Correctness and Trust Boundaries

Status: **AUDIT COMPLETE — REMEDIATED** (read-only findings verified at
`ea638ff9`; remediation implemented and gated 2026-11-19 — see
[Remediation status](#remediation-status-2026-11-19)).
Follow-up: D36-D39 were added during remediation planning (2026-11-16);
remediation is planned in `plans/dns_serving_correctness_roadmap.md`.
Scope: `crates/synvoid-dns`, `crates/synvoid-dnssec-keystore`,
`crates/synvoid-config/src/dns`, `src/server/dns_runtime_config.rs`,
`src/server/resources.rs`, the mesh DNS sync path, and the DNS admin surface.
Method: the capability was split into six review scopes. Four ran as parallel
read-only reviews (wire/limits, DNSSEC/keystore, authoritative/zone/update,
resolver/cache); the transport and config/admin scopes stalled without output
and were covered directly by the parent. Every Critical/High claim was then
verified by the parent. D1 and D3 were confirmed by executing probes against the
crate (D3 through the real query validator); the rest are code-verified with
exact line references.
Baseline: `cargo test -p synvoid-dns --profile ci` passes (1260 tests).

This document is a findings index, not a campaign plan. Remediation is planned
in `plans/dns_serving_correctness_roadmap.md` and implemented in the working
tree at the 2026-11-19 gate; the historical findings below are left in their
original form so the evidence trail is intact.

## Remediation status (2026-11-19)

Every row below is **closed** unless marked **deferred**. "Closed" means the
defect is fixed and the named suite decodes or verifies the wire output, so the
suite fails against `ea638ff9`.

| Findings | Phase | Proving evidence |
|---|---|---|
| D1, D2 | 01 | `dns_wire_contract` decodes owner names and the question echo |
| D7, D8, D13, D17 | 02 | `dns_envelope_contract` parses OPT fields, budgets, counts |
| D3, D12, D14, D15, D16, D12b, D33 | 03 | `dns_admission_contract`; fuzz targets `dns_edns_options`, `dns_tsig_parse` |
| D4, D36, D37, L1–L4 | 04 | `dnssec_signature_contract` verifies every served RRSIG with hickory |
| D5, D6, D38, L5 | 05 | `dnssec_denial_contract` (RFC 5155 vectors, proof selection) |
| D24 | 05 | closed by removing the rotation task that never reached the zone; key rotation is a documented manual runbook, keys are reload-only |
| D9, D10, D25, D26, D27 | 06 | `dns_recursive_contract` (failure vs absence, stale fallback, cache key, firewall, ports) |
| D23, D31 | 06 | closed by deleting RFC 5011; `[dns.trust_anchors]` is a typed `Unsupported`, static file anchors only |
| D19, D20, D21, D22, D30, D39 | 07 | `dns_control_plane_contract` (independent RFC 8945 digests, ACL matrix, RFC 2136 metavalues, cookies) |
| D11 | 08 | `dns_mesh_trust_contract`: authenticity **and** publisher binding **and** authorization; real DHT registrations default-deny until mesh phase 04b binds the signer |
| D34, D35 | 08 | `dns_truthfulness_contract`; redaction also covers `GET /config/main` and `dns.dnssec.hsm.pin` |
| D18, D28, D29 | 09 | `dns_authoritative_lookup` (RFC 4592 matrix, referral, ENT, DNAME, dedupe, `Arc<Zone>`) |
| L6 | 10 | a wire label containing a literal dot is rejected (`parsed_query` unit test) instead of being conflated with a label boundary |
| L7 | 03 | QCLASS IN is enforced in `admit` for every transport |
| L8 | — | already iterative with a `max_jumps` cap (`compression.rs`); the audit claim was stale |
| L9 | 02/03 | `validate_edns_options` deleted; one ARCOUNT-aware, bounds-checked parser |
| L10 | **deferred** | `mesh_dnssec.rs` is public dead code with known bugs and no callers. Deleting it is a product decision (it may be the future mesh-validation entry point); it is unreachable today. |
| D40 (found in phase 10) | 10 | The authoritative response cache returned complete cached bytes unchanged, including the producing query's transaction ID, so a second client query for the same name was discarded. Fixed by rewriting the ID on a cache hit; regression test `authoritative_cache_hit_returns_the_current_transaction_id` and the `dig`-driven `dns_external_interop` lane. |

Operator-visible changes are listed in
`architecture/dns_serving_correctness_closeout.md`.

## Bottom line

The DNS capability is marked production-ready in `docs/FEATURE_STATUS.md` but
does not currently produce valid DNS responses in either serving mode:

- **Authoritative answers for any name below the apex carry a relative owner
  name** (`www` instead of `www.example.com`). Confirmed by execution.
- **Recursive answers encode every name in presentation format** (`example.com`
  as ASCII, with no length labels), so no client can parse them.
- **A 30-byte EDNS query panics the process task** that owns the UDP listener,
  so one unauthenticated packet stops DNS service for the process lifetime.
  Confirmed by execution.
- **DNSSEC cannot validate anything this server signs**: RRSIG canonical data
  is built from the same relative name, NSEC/NSEC3 proofs are fabricated, and
  the NSEC3 "hash" is not a hash at default parameters.
- **EDNS responses are malformed**: the OPT record puts the payload size in the
  wrong field and shifts a non-zero extended RCODE (16, `BADVERS`) into every
  response.

The security-critical control plane (AXFR/IXFR, UPDATE, NOTIFY, TSIG) is
config-gated off and therefore latent, but where it exists it checks for the
*presence* of a signature rather than verifying one, and its TSIG parser panics
on hostile input. A single validator change would make those live.

## Reachability model

`DnsConfig::validate()` runs before the runtime projection
(`src/server/dns_runtime_config.rs:99-105`) and rejects: `allow_transfer`
non-empty, `allow_wildcard_transfer`, `dynamic_update.enabled`,
`notify.enabled`, `rpz.enabled`, `prefetch.enabled`, `trust_anchors.enabled`,
`anycast.enabled`, `padding.enabled`, `qname_privacy.enabled`, and deviations
in the transfer knobs (`docs/CONFIGURATION.md`, "DNS features that fail
closed"). The corresponding handlers are also never constructed in
`DnsServer::new` (`update_handler: None`, `notify_handler: None`,
`zone_transfer: None`, `server/mod.rs:2127-2130`).

Live surfaces in a valid configuration: authoritative serving (UDP/TCP), EDNS,
DNSSEC signing when `dnssec.enabled`, cookies, rate limiting, query validation,
the recursive listener when `recursive.enabled`, DoT/DoH/DoQ when enabled, and
the mesh DNS registry when the `mesh` feature is on and a DNS server is present
(`src/worker/unified_server/init_mesh.rs:523`).

Every finding below is tagged **LIVE** or **LATENT** on that basis.

## Critical

### D1 — Authoritative answers use relative owner names (LIVE, confirmed by execution)

`crates/synvoid-dns/src/server/zone.rs:28-56` stores record owners
origin-relative (`"@"`, `"www"`, `"a.b"`), and
`crates/synvoid-dns/src/server/response_encoder.rs:116-129` encodes that name
verbatim, substituting the question name only for `"@"` or the empty string.
Nothing rewrites the owner when the answer is assembled
(`server/response.rs:39-49`, `server/response_encoder.rs:339-378`).

Probe: query `www.test.local/A` against a zone containing `("www", A)`; the
answer RR owner decodes to `"www"`, not `"www.test.local"`. Apex answers are
correct only because `"@"` is replaced by the question name.

Impact: every non-apex answer is out-of-zone. Validating and non-validating
resolvers alike discard it, so a zone can serve `@` but not `www`, `mail`, or
any other name. This is the root cause of D4.

Fix: encode the owner as `record.name` joined with the zone origin (`"@"` →
origin), and add a test that decodes the owner of a non-apex answer.

### D2 — Recursive answers encode names in presentation format (LIVE when recursion is enabled)

`crates/synvoid-dns/src/recursive.rs:739-740` and `:492-493` take
`question.name().to_string()` and convert it to ASCII bytes;
`build_question_section` (`:1149-1165`) and `build_answer_record`
(`:1167-1186`) append those bytes directly, with no length prefixes.

The unit tests encode the same assumption (`:1560-1585` asserts only that the
section is non-empty). Correct `wire::encode_name` is not used on this path.

Impact: no recursive response is parseable. A parser reads `'e'` (0x65 = 101)
as a label length. The recursive listener therefore cannot serve any client;
`build_error_response` is the only well-formed builder it uses.

Fix: encode with `wire::encode_name` (or re-emit the hickory `Message`), and
add a round-trip test through `wire::parse_dns_message`.

### D3 — EDNS option parsing reads past the packet on a declared RDLENGTH (LIVE, confirmed by execution)

`crates/synvoid-dns/src/edns.rs:213-216`:

```rust
let mut rdata_pos = pos;
while rdata_pos + 4 <= pos + rdlen as usize {      // rdlen is attacker-controlled
    let option_code = u16::from_be_bytes([query[rdata_pos], query[rdata_pos + 1]]);
```

`pos + rdlen` is never clamped to `query.len()`. A 30-byte query (question +
OPT header declaring `RDLENGTH = 0xFFFF`) satisfies the loop guard and indexes
`query[30]` with `len == 30`.

Probe: the production validator (`DnsQueryValidator::validate_query_with_response`)
**accepts** that packet, and `DnsServer::handle_query` then panics at
`edns.rs:215` (`index out of bounds: the len is 30 but the index is 30`).

Reachability: `parse_edns_options` runs on every query
(`crates/synvoid-dns/src/server/query.rs:963`; same on TCP and DoH). The UDP
listener processes packets inline in one spawned task whose handle is discarded
(`server/startup.rs:180-424`), and the process uses `panic = "unwind"`
(`Cargo.toml:332`), so the unwinding task takes the socket with it and nothing
respawns it. One unauthenticated datagram stops UDP DNS for the process
lifetime.

Fix: `let opt_end = (pos + rdlen as usize).min(query.len());` and bound every
option body against `opt_end`. Add `parse_edns_options` to the fuzz corpus; it
is not covered today.

### D4 — RRSIG canonical data is built from the relative owner name (LIVE with DNSSEC signing)

`crates/synvoid-dns/src/server/dnssec_impl.rs:515-546` signs `record.name`
verbatim and derives the label count from it:

```rust
let labels = crate::dnssec::count_labels(&record.name);
...
let name_lower = record.name.to_lowercase();
for part in name_lower.trim_end_matches('.').split('.') { ... }
```

For `www` this signs `\x03www\x00` with `labels = 1` instead of
`\x03www\x07example\x03com\x00` with `labels = 3`; the apex signs `\x01@\x00`.

Impact: no RRSIG this server emits can be verified — DNSKEY included, so the
chain of trust never establishes. The zone is bogus end-to-end. This is D1's
consequence in the signing path and is listed separately because the fix is
different (pass the origin into the signer).

### D5 — The NSEC3 hash is not applied at the default iteration count (LIVE with NSEC3)

`crates/synvoid-dns/src/dnssec_signing.rs:169-197`:

```rust
let mut hash = name_lower.as_bytes().to_vec();
hash.extend_from_slice(&config.salt);
for _ in 0..config.iterations { ... }
```

With the default `iterations = 0` (`crates/synvoid-dns/src/dnssec.rs:56-65`)
the loop never runs, so the "hash" is the plaintext name concatenated with the
salt. The input is also the dotted presentation form, not RFC 5155 wire format,
so any non-zero iteration count still hashes the wrong bytes.

Impact: NSEC3 owner names and next-hashes are wrong, and the default
configuration makes the zone enumerable by inspection — the exact property
NSEC3 exists to prevent. `docs/dns-dnssec-architecture.md` warns about the
SHA-256 base32 length but not about this.

Fix: reuse `canonical_name`, and always apply one hash before the iteration
loop (`IH(salt,x,0) = H(x || salt)`).

### D6 — NSEC/NSEC3 denial proofs are fabricated (LIVE with DNSSEC signing)

`crates/synvoid-dns/src/server/dnssec_impl.rs:332-381` builds the NSEC bitmap
from a hardcoded list (`vec![1,2,5,6,15,16,28,33]`) instead of the RRsets
present, and for NXDOMAIN sets the NSEC owner to the queried name — the name
that does not exist — asserting A/NS/CNAME/SOA at it. The NSEC3 builders
(`:242-327`, `:383-470`) assemble closest-encloser/wildcard/next-closer records
with pointers that are not the zone's sorted hash chain, and the next-hash is
computed by hashing the NSEC3 owner-name string.

Impact: every negative answer from a signed zone is bogus to a validating
resolver (SERVFAIL for clients), and the always-set CNAME bit can steer
validation toward a CNAME that does not exist. Call sites:
`server/query.rs:1380` (NODATA) and `:1409` (NXDOMAIN).

Fix: precompute a canonical-ordered NSEC/NSEC3 chain at zone load and serve the
covering proof; derive bitmaps from the records actually present.

## High

### D7 — OPT records are encoded with the payload size in the wrong field (LIVE)

`crates/synvoid-dns/src/server/response_encoder.rs:410-421`:

```rust
bytes.push(0x00);                                   // NAME
bytes.extend_from_slice(&41u16.to_be_bytes());      // TYPE
bytes.extend_from_slice(&(opt_rdata.len() as u16).to_be_bytes()); // CLASS = 6
bytes.extend_from_slice(&opt_rdata);                // TTL + RDLENGTH
```

`opt_rdata` is `[udp_payload(2), flags(2), 0(2)]`, so the wire carries
`CLASS = 6`, `TTL = 0x1000_0000`, `RDLENGTH = 0`. The TTL's high byte is the
extended RCODE: every EDNS response advertises RCODE 16 (`BADVERS`) and a
6-byte UDP payload. Used on every EDNS path (`server/response.rs:82,131,171,
502,565,602,611,653,690`; `server/query.rs:1071`).

Impact: standards-compliant resolvers treat every EDNS answer as BADVERS and
cannot learn the server's payload size. No test asserts the OPT fields.

Fix: emit `CLASS = udp_payload_size` and an explicit TTL
(`ext_rcode<<24 | version<<16 | flags`).

### D8 — The client's advertised EDNS buffer is floored to 4096 (LIVE)

`crates/synvoid-dns/src/edns.rs:293-297` and `build_opt_record` (`:315-322`)
raise any advertised size below 4096 to 4096, and `server/response.rs:20-22`
uses that value as the response size limit. A client asking for 512 or 1232
(DNS Flag Day 2020 default) receives up to 4 KiB.

Impact: fragmentation and dropped answers for modern clients, plus a
spoofed-source reflection factor of up to ~100× from a short query.

Fix: `payload.clamp(512, 4096)` — never exceed what the client sent.

### D9 — Recursive upstream failures and bogus DNSSEC become cached NODATA (LIVE when recursion is enabled)

`crates/synvoid-dns/src/recursive.rs:955-1030`: every resolver error maps to
`Err(_) => Vec::new()`, and an empty record set is unconditionally
negative-cached for `negative_ttl` (300 s default) and answered with
`response_code: 0`.

Impact: SERVFAIL, REFUSED, timeouts, and DNSSEC validation failures are
indistinguishable from "no such data" and are cached across all clients. CAA
NODATA is especially dangerous because it is read as "issuance permitted"
(RFC 8659). Unsupported qtypes (DS/DNSKEY/NAPTR/ANY) also return NODATA.

Fix: map failures to SERVFAIL and never negative-cache them; return NOTIMP for
unimplemented types.

### D10 — Stale data is served instead of refreshed, and TTL 0 is served for a day (LIVE when recursion is enabled)

`crates/synvoid-dns/src/recursive.rs:752-769` returns a cache hit whenever one
exists; `stale` is only a metric. `crates/synvoid-dns/src/recursive_cache.rs:
236-249` treats entries as live for `ttl + stale_ttl` with `stale_ttl = 86400`
and `min_ttl = 0`, and expired records are replayed with their original TTL.

Impact: once bad or stale data lands it is never revalidated for ~24 h, and a
TTL-0 answer is immediately "stale" and served for the full window. RFC 8767
permits stale answers only as a fallback after upstream failure.

Fix: serve stale only on upstream failure, refresh in the background, and treat
TTL 0 as non-cacheable.

### D11 — DHT domain registrations are trusted without an authenticity check (LIVE with mesh + DNS)

`crates/synvoid-dns/src/mesh_sync/dht.rs:5-50` inserts an advertised
`domain -> origin_node_id` mapping with `authenticated: true`,
`cert_chain_verified: false`, and no signature check. The DNS-owned trait
returns plain tuples with no signature (`mesh_sync/dht_capability.rs:100`), and
the sync loop runs periodically (`mesh_sync/registry.rs:188`).

`resolve_from_mesh` (`server/query.rs:869-925`) then answers DNS queries for any
domain with a registered origin, using the registry's node data.

Impact: a mesh peer that can publish a `DnsDomainRegistration` record chooses
the answers a global node serves for that domain. The mesh side verifies DHT
records against the record's own `signer_public_key` with no binding to
`source_node_id` (campaign finding B4), so the DNS registry inherits that gap.
Phase 04b of the mesh campaign fixes the root cause; the DNS registry should
also refuse unauthenticated registrations rather than defaulting the flag to
`true`.

### D12 — The TSIG additional-section scanner reads past the packet (LATENT, remote panic)
`crates/synvoid-dns/src/tsig.rs:338-350`: after the name walk, `pos` can equal
`query.len()`, and the qtype read indexes `query[pos]` with no re-check.
Modelled and fuzzed in isolation: a 28-byte packet panics. Called before any
ACL check on AXFR/IXFR (`server/query.rs:399,427,613,636`) and from
`update.rs:426` / `notify.rs:140`. The parser is also misaligned by the
RR RDLENGTH field, so a conforming TSIG RR never parses correctly.

Impact: once `allow_transfer` is configured, one unauthenticated packet panics
the handler; on UDP that kills the listener task (see D3).

Fix: bounds-check after the name walk and skip class *and* RDLENGTH before
parsing RDATA.

### D12b — Encrypted transports bypass the query validator, DNS firewall, and request rate limiting (LIVE)

The UDP loop and the TCP handler validate the packet and consult the firewall
before dispatch (`server/startup.rs:257-300`; `server/query.rs:227-238`), but
the DoT, DoQ, and DoH listeners call `DnsServer::handle_query(_with_cache)`
directly (`dot.rs:205-218`, `doq.rs:298-313`, `doh.rs:246-262`). None of them
calls `validate_query_with_response`, evaluates `ctx.firewall`, or checks the
request rate limiter. (`doh.rs:250-258`, `dot.rs:205-218`, `doq.rs:298-313`.)

Impact: a client that switches port knocks out every firewall rule configured
for policy (`block_internal_ips`, `block_axfr`, qname blocks) and the per-IP
rate limit, while keeping full authoritative/recursive reachability. The
encrypted listeners are also the only paths that reach D3's parser without a
validator in front, so a malformed query panics the connection task there.

Fix: put validation, firewall, and rate limiting in one admission function used
by every listener, before `handle_query`.

## Medium

| ID | Finding | Evidence | Reachability |
|----|---------|----------|--------------|
| D13 | Error responses set `QDCOUNT=0` but append the question bytes | `wire.rs:277-300` | LIVE |
| D14 | A packet with `QR=1` is answered with NOTIMP instead of dropped; two such servers loop | `query_validator.rs:385-393`; `wire.rs:173-175` | LIVE |
| D15 | EDNS loop guard checks 10 bytes but the OPT branch reads 11 (off-by-one panic) | `edns.rs:172`, `:203` | LIVE |
| D16 | ECS prefix length is unbounded; `octets[..addr_bytes]` panics for >32 (v4) / >128 (v6) | `edns.rs:219-241` | LIVE |
| D17 | OPT parsing ignores ARCOUNT and `has_edns`/`dnssec_ok` are read positionally; DO can be forged without an OPT | `edns.rs:357-378`; `parsed_query.rs:198-217` | LIVE |
| D18 | Every query deep-clones the whole `Zone`, including up to 200 history snapshots | `server/sharded_store.rs:67`; `server/mod.rs:497-516`; `query.rs:1025` | LIVE |
| D19 | `require_tsig` checks presence, not validity; with no verifier a forged TSIG authorizes a transfer/update | `transfer.rs:303-349`; `update.rs:428-458` | LATENT |
| D20 | An ACL entry equal to the zone origin grants every client that zone; no per-zone ACL | `transfer.rs:143-151` | LATENT |
| D21 | IXFR fallback ignores `axfr_enabled`/`tcp_only` and answers over UDP with the full zone, no TC | `transfer.rs:536-553`; `server/zone.rs:382` | LATENT |
| D22 | Dynamic UPDATE keys absolute owner names into a relative-keyed store, uses class 1-4 instead of ANY/NONE, and replaces whole RRsets | `update.rs:499-548`, `:77-83` | LATENT |
| D23 | RFC 5011 accepts a self-referential CDS as proof and never checks a signature by an existing anchor; REVOKE is honoured from an unauthenticated observation | `trust_anchor.rs:549-591`, `:472-478` | LATENT |
| D24 | Key rotation never reaches the served zone: `zone.ksk_key`/`zsk_key` are set once | `server/dnssec_impl.rs:41-45`; `keystore.rs:524-551` | LIVE (fires after 30 days) |
| D25 | Recursive cache key is case-sensitive while the coalescer lowercases; the coalescer broadcasts the owner's raw packet (wrong ID/case/EDNS) | `recursive_cache.rs:76-106`; `query_coalesce.rs:44-52` | LIVE |
| D26 | The recursive listener is constructed with `firewall: None`, so `recursive.firewall` (including rebinding protection) is never enforced | `server/startup.rs:121-126` | LIVE |
| D27 | A custom upstream port is dropped, and a hostname-only list silently falls back to the system resolver | `runtime_config.rs:884-896`; `recursive.rs:250-256` | LIVE |
| D28 | Wildcards and delegations are accepted but not implemented: `*` never matches, child zones are answered authoritatively | `server/query.rs:1085-1112` | LIVE |
| D29 | Duplicate records are not deduplicated, and `add_record` does not normalize names | `server/zone.rs:339-355`, `:210-211` | LIVE |
| D30 | DNS cookies are validated only to write a debug log; there is no config to require them | `server/query.rs:971-987`; `cookie.rs:79` | LIVE |
| D31 | RFC 5011 has no runtime consumer: `start_rfc5011_updates` has no caller and the recursor's anchors are a startup snapshot | `resolver.rs:785`; `:703-711` | LATENT |
| D33 | The encrypted listeners accept unbounded connections (one spawned task each, no semaphore); plain TCP has `max_connections` but DoT/DoH/DoQ do not | `secure_server.rs:175-215`; `doq.rs:130-160` | LIVE |
| D34 | `/health` reports config intent rather than realized state: `axfr_enabled` is hardcoded `true` while AXFR answers NOTIMP, and `dnssec_signing_enabled` mirrors a config flag | `server/mod.rs:2195`, `:2206` | LIVE |
| D35 | `GET /config/dns` returns the whole DNS config, including `tsig_keys[].secret_base64`, in plaintext; the DTO also derives `Debug` | `src/admin/handlers/config.rs:1740-1751`; `dns_dnssec.rs:223-228` | LIVE (admin-authenticated) |

## Findings added during planning (D36–D39)

These were found while writing the remediation plans, after the main audit. They
are folded into the campaign and listed here so the index is complete.

| ID | Sev | Finding | Evidence | Phase |
|----|-----|---------|----------|-------|
| D36 | High | The DNSKEY RRset is signed with the ZSK, not the KSK; a validator trusting the parent DS rejects it (RFC 4035 §2.2) | `server/response.rs:88-93`; `server/query.rs:1188-1201` | 04 |
| D37 | High | The SOA in NXDOMAIN/NODATA responses is added unsigned while the NSEC/NSEC3 next to it is signed (RFC 4035 §3.1.3) | `server/query.rs:1530-1559`, `:1686-1715` | 04 |
| D38 | Med | NSEC3 owner names prefix the base32 string length (52) instead of the hash length (32), and `create_nsec3_record` re-hashes an already-base32 owner for the next-hash field | `dnssec_signing.rs:211-216`, `:243-246` | 05 |
| D39 | High | The TSIG MAC is not RFC 8945 canonical (no TSIG removal, no ARCOUNT decrement, no TSIG variables), and signed responses append bare RDATA with an incremented ARCOUNT instead of a full RR | `tsig.rs:182-199`; `transfer.rs:201-220` | 07 |

## Low

- `find_next_name_in_zone` sorts with `String` order rather than DNSSEC
  canonical order (`dnssec_signing.rs:141`), so some NSEC ranges are wrong.
- A signing failure emits the RRset without its RRSIG instead of SERVFAIL
  (`server/dnssec_impl.rs:554-561`).
- NSEC3 salt length and iteration count are unbounded (`dnssec_signing.rs:173`,
  `:211`).
- `count_labels` truncates to `u8` and returns 1 for the root
  (`dnssec_validation.rs:190-196`).
- TXT canonicalization can sign bytes that differ from the served RDATA
  (`dnssec_validation.rs:61-88`).
- A label containing `.` is accepted and re-split when the question is echoed
  (`wire.rs:105`, `:310`), so distinct wire names collapse to one string.
- QCLASS is never enforced on the DoH/DoQ/DoT paths and responses always claim
  class IN (`server/query.rs:931-963`; `response_encoder.rs:367`).
- `compression.rs::decompress_name` recurses without a depth cap (no callers
  today).
- `validate_edns_options` has the same off-by-one as D15 and no production
  caller (`query_validator.rs:168-189`).
- `mesh_dnssec.rs` reads the RRSIG key tag at offset 12 (should be 16), never
  checks inception/expiration, ignores the DNSKEY in `validate_dnskey_chain`,
  and slices `public_key[..32]` (panic on shorter keys). Dead code today
  (`#[cfg(feature = "mesh")]`, no callers) but `pub`.

## Documentation vs code

| Claim | Reality |
|---|---|
| `docs/FEATURE_STATUS.md:13` — DNS Server "Yes" (production) | Both serving modes emit invalid wire data (D1, D2); one packet stops the listener (D3). |
| `docs/dns-dnssec-architecture.md:3-9` — full inline validation when `dnssec_validation = true` | True only for `upstream_provider = Recursive`; the default `System` forwarder never validates (`recursive.rs:300-310` warns at startup). |
| `docs/dns-dnssec-architecture.md:56-63` — trust-anchor manager "not wired to the runtime resolver… no live runtime consumer" | The manager *is* constructed when validation is enabled (`resolver.rs:663-701`) and fed observations (`:1121-1128`); only its config section is rejected. The update task is never started. |
| `docs/RFC5011_TRUST_ANCHOR.md:231-233` — promotion requires the key still be in the DNSKEY RRset | Not enforced (`trust_anchor.rs:699-716`). |
| `docs/WAF_MESH.md` / mesh campaign | DHT author binding is Phase 04b; DNS trusts registrations today (D11). |

## Checked and sound

- Key custody (`synvoid-dnssec-keystore`): sealed handles, redacted `Debug`,
  `Zeroizing` on drop and clone, `0700`/`0600` atomic writes, over-permissive
  load rejection, HSM fails closed with no software fallback.
- TSIG MAC comparison is full-length and constant-time; algorithm confusion is
  rejected; replay cache is consulted after MAC verification.
- DS digest comparison is constant-time; unsupported digest and algorithm types
  fail closed.
- The authoritative path never sets AD (`server/response.rs:134-136`).
- Authoritative TTL handling: TTL 0 is not cached, negative TTL is
  `min(SOA TTL, SOA MINIMUM, negative_cache_ttl)`.
- Config zone-name normalization rejects out-of-zone, `../`, backslash, and
  control-byte names; exactly one apex SOA is enforced at load and after update.
- `ParsedDnsQuery::parse` rejects QR=1, QDCOUNT=0, compression in QNAME,
  labels > 63, control bytes, and names > 255 octets.
- TCP framing rejects zero and oversized lengths before allocation.
- Upstream response matching (hickory 0.26.3) checks the query ID, the question
  section, and 0x20 case; per-query UDP sockets are connected, so off-path
  spoofing is filtered by the kernel.
- `wire::parse_query_name` caps jumps at 10 and rejects forward pointers.
- The startup path runs `DnsConfig::validate()` before projecting the runtime
  (`src/server/dns_runtime_config.rs:99-105`). The docs claim the admin
  `PUT /config/dns` path applies the same validation; that path was not
  exercised in this audit.

## Coverage gaps

- The DoH/DoQ/DoT review and the config/admin review were interrupted after
  running without output; the parent covered their highest-value questions
  directly (D12b, D33, D34, D35, the TLS setup, the DoQ stream framing, the
  reachability model, and `GET /config/dns`). Deeper transport coverage —
  ALPN edge cases, QUIC 0-RTT, per-connection limits, and the admin zone
  surface — remains open.
- `ShardedZoneStore` per-zone locking was not audited beyond the clone-on-read
  behaviour in D18.
- No live interop run (`dig`, `delv`, `ldns-verify-zone`) was performed; D1 and
  D3 were established by in-process probes, and D2/D7 by code reading.
- The `hickory` recursor's behaviour on a bogus RRset was not exercised.

## Reproduction

D1 — a temporary integration test using `tests/support/context.rs`:

```rust
let (zones, trie, ecs) = setup();               // zone "test.local" with ("www", A)
let ctx = make_ctx(&zones, &trie, &ecs);
let q = build_query(0x4242, "www.test.local", 1);
let resp = DnsServer::handle_query(&ctx, &q, Some(IpAddr::from([127, 0, 0, 1]))).unwrap();
// decode the answer owner: it is "www", not "www.test.local"
```

D3 — a 30-byte query that the production validator accepts:

```text
12 34 01 00 00 01 00 00 00 00 00 01   header (RD, QD=1, AR=1)
01 61 00 00 01 00 01                  question: a. IN A
00 00 29 10 00 00 00 00 00 ff ff      OPT: root, type 41, class 4096, ttl 0, RDLENGTH 0xffff
```

`DnsQueryValidator::validate_query_with_response` returns `Ok(())`; the next
`DnsServer::handle_query` call panics at `edns.rs:215`.

## Suggested remediation order

1. **D3, D15, D16, D12** — bound every parser before anything else; add
   `parse_edns_options` to the fuzz corpus.
2. **D1, D2** — one owner-name encoder for both serving paths, with round-trip
   tests through `wire::parse_dns_message` and a decoded-owner assertion.
3. **D7, D8, D13, D14, D17** — fix the response envelope so EDNS clients work.
4. **D4, D5, D6** — sign and prove from canonical names; add an external
   validator to CI.
5. **D12b, D33, D35** — one admission function for every listener (validation,
   firewall, rate limit), a connection cap on the encrypted listeners, and
   redact TSIG secrets from `GET /config/dns`.
6. **D9, D10, D25, D26, D27** — recursive semantics and failure mapping.
7. **D11** — refuse unauthenticated DHT registrations; land with mesh Phase 04b.
8. **D19–D22, D23, D31** — control-plane verification before any gate is
   lifted; do not enable transfers/updates until TSIG is canonical and verified.
9. **D18, D24, D28, D29, D30, D34** — operational correctness and honest
   health reporting.
