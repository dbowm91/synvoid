# Phase 04 Plan: DNSSEC Signing

Status: **IMPLEMENTED** (2026-11-19; `dnssec_signature_contract`, 13 tests).
Audit: `plans/dns_capability_audit.md` (D4, L1–L4, plus D36–D37 added during
planning).
Registered in: `plans/roadmap.md`.
Campaign: `plans/dns_serving_correctness_roadmap.md`.
Predecessor: Phase 01 (owner encoder).
Depends on: Phase 01 for the canonical owner wire form this phase signs. Phase
05 consumes the signer this phase produces.

## The findings

**D4 (Critical).** `create_signed_rrsig`
(`crates/synvoid-dns/src/server/dnssec_impl.rs:515-546`) signs `record.name`,
which is origin-relative:

```rust
let labels = crate::dnssec::count_labels(&record.name);   // "www" -> 1
let name_lower = record.name.to_lowercase();              // "www"
for part in name_lower.trim_end_matches('.').split('.') { ... }
```

The signed data is `\x03www\x00` with `labels = 1`; the apex is literally
`\x01@\x00` with `labels = 1`. A validator reconstructs the signed data from the
FQDN, so no RRSIG this server emits can verify. DNSKEY is signed the same way,
so the chain of trust never establishes.

**D36 (High, found while planning).** `build_dnskey_records` output is signed
with `zone.zsk_key` (`server/response.rs:88-93`; the DNSKEY branch at
`server/query.rs:1188-1201` passes `zone.zsk_key`). RFC 4035 §2.2 requires the
DNSKEY RRset to be signed by the key that matches the parent DS — the KSK. A
validator that trusts the DS will reject a DNSKEY RRset signed only by the ZSK.

**D37 (High, found while planning).** The SOA included in NXDOMAIN and NODATA
responses is added to the authority section without an RRSIG
(`server/query.rs:1530-1559`, `:1686-1715`), while the NSEC/NSEC3 records next
to it are signed. RFC 4035 §3.1.3 requires the SOA and its RRSIG in a negative
answer; a validator treats the unsigned SOA as bogus.

**L1 (Low).** `canonical_rdata` re-derives TXT wire bytes from the presentation
string (`dnssec_validation.rs:61-88`), guessing a length prefix from the first
byte. `encode_rr` chunks TXT at 255 bytes (`response_encoder.rs:160-172`). The
two disagree for values whose first byte is in `1..len`, so the signature covers
different bytes than are served.

**L2 (Low).** `count_labels` (`dnssec_validation.rs:190-196`) truncates to `u8`,
returns 1 for the root, and counts `*` as a label; `create_rrsig_record` is
tested with `labels = 0` for the root, so the two disagree.

**L3 (Low).** `canonical_name` (`dnssec_validation.rs:111-129`) cannot tell a
relative name from an absolute one: `"www"` and `"www."` both become
`\x03www\x00`. Its own caller duplicates the logic by hand instead of using it.

**L4 (Low).** A signing failure returns an empty RRSIG vector
(`dnssec_impl.rs:554-561`) and the caller keeps the unsigned record in the
answer, so a signed zone silently serves unsigned data.

## Root cause

The signer was written against `DnsZoneRecord.name` (the storage key) rather
than an owner name qualified by the zone, and key selection is "whatever key the
call site has". Tests assert RRSIG *shape* over a literal placeholder
(`tests/dnssec_live_signing.rs:141-170`), so a signature over the wrong name
passes.

## Fix scope

### R1 — One owner wire form

Add to `wire.rs`, beside phase 01's `encode_owner`:

```rust
pub struct OwnerName<'a> { relative: &'a str, origin: &'a str }
impl OwnerName<'_> {
    fn fqdn(&self) -> String;                 // "www.example.com"
    fn wire(&self) -> Result<Vec<u8>>;        // length-prefixed, uncompressed
    fn labels(&self) -> u8;                   // per RFC 4034 §3.1.3, wildcard aware
}
```

`encode_owner` becomes `OwnerName::wire`. The wildcard rule: `*.example.com`
contributes `labels = 2` (the `*` label is not counted).

### R2 — Sign the FQDN

`create_signed_rrsig(record, origin, signer_name, key)` builds the canonical
owner from `OwnerName`, and `labels` from the same type. `signer_name` stays the
zone apex. Update the four call sites: `build_response`
(`server/response.rs:88`), `build_nxdomain_response` (`query.rs:1587`),
`build_nodata_response` (`query.rs:1738`), and the apex RRset builders.

### R3 — Sign each RRset with the right key

- DNSKEY, CDS, CDNSKEY → KSK (D36).
- Everything else, including DS, NSEC, NSEC3, SOA, NSEC3PARAM → ZSK.
- Encode the choice in one function `signing_key_for(record_type) -> &ZoneSigningKey`
  so a call site cannot pick the wrong handle.
- A zone with a KSK but no ZSK (or the reverse) is a startup error for a signed
  zone, not a partially signed response.

### R4 — Sign the SOA in negative answers

`build_nxdomain_response` and `build_nodata_response` sign the SOA with the ZSK
and place its RRSIG in the authority section directly after it (D37). Keep the
existing NSEC/NSEC3 signatures.

### R5 — Canonicalization follows the wire

- TXT: sign the exact RDATA bytes `encode_rr` produces. Introduce
  `rdata_wire(record) -> Vec<u8>` in `response_encoder.rs`, use it for both
  encoding and signing, and delete the presentation-string heuristic (L1).
- `canonical_name` takes `OwnerName` (or a `&str` documented as FQDN-only) and
  rejects a relative input via `debug_assert` + `Result` (L3).
- `count_labels` becomes `OwnerName::labels`; delete the old helper (L2).

### R6 — Fail closed

A signing error aborts the response: return SERVFAIL with the question echoed
(`build_error_response`), increment `dns_dnssec_signing_failures_total`, and
log the RRset. Never emit an RRset whose RRSIG was dropped (L4).

### R7 — Tests that verify, not just shape

New helper in `tests/support/dnssec.rs`:

```rust
fn verify_answer(resp: &[u8], dnskey: &ZoneSigningKey) -> Result<(), String>;
```

It decodes the answer RRset, reconstructs the signed data from the FQDN and the
RRSIG fields, and verifies with the keystore's verifying key (the keystore
exposes the public key through `dnskey_rdata`; no private material leaves it).

New suite `tests/dnssec_signature_contract.rs`:

1. apex `A` and `www` `A` RRSIGs verify against the served DNSKEY;
2. `labels` in the RRSIG equals the FQDN label count, and 2 for `*.example.com`;
3. the DNSKEY RRSIG is made by the KSK (key tag matches the DS/KSK);
4. DS, NSEC, NSEC3PARAM RRSIGs verify;
5. NXDOMAIN carries a verifying SOA RRSIG and a verifying NSEC RRSIG;
6. a TXT value whose first byte is a printable digit verifies (L1);
7. a zone with a missing ZSK returns SERVFAIL and increments the failure metric;
8. the OLD behavior fails this suite: signing `www` without the origin must not
   verify (guard against regression).

## Out of scope

- NSEC/NSEC3 chain construction and selection (phase 05).
- Key rollover re-publication (phase 05, R4).
- Algorithm support (8/15 only, unchanged).

## Verification

```bash
cargo test -p synvoid-dns --test dnssec_signature_contract --profile ci
cargo test -p synvoid-dns --test dnssec_live_signing --profile ci
cargo test -p synvoid-dns --test dns_interop_dnssec --profile ci
cargo test -p synvoid-dns --profile ci
```

Acceptance:

- the new suite fails against `ea638ff9` (run it before the fix to prove it);
- no RRSIG is produced from a relative name (`rg 'record\.name' dnssec_impl.rs`
  shows only the storage key, never the signing input);
- `dnssec_live_signing.rs`'s placeholder-signature test is replaced, not
  duplicated;
- an external validator (`delv`/`ldns-verify-zone`) accepts a served zone when
  the tool is present (see phase 10).
