# Phase 07 Plan: Control Plane Verification

Status: **IMPLEMENTED** (2026-11-19; `dns_control_plane_contract`, 22 tests.
The `allow_transfer` / `dynamic_update.enabled` / `notify.enabled` gates remain
closed per T3/R8).
Audit: `plans/dns_capability_audit.md` (D19, D20, D21, D22, D30, D39 added
during planning).
Registered in: `plans/roadmap.md`.
Campaign: `plans/dns_serving_correctness_roadmap.md`.
Predecessor: Phase 03 (the TSIG parser this phase builds on).
Depends on: Phase 03's bounded TSIG reader and admission path.

## The findings

The transfer, update, and notify handlers are config-gated off today, so all of
these are latent — one validator change from live. They are in this campaign
because a presence check is worse than no auth: it looks like auth.

**D19 (Medium).** `require_tsig` checks only that a TSIG RR exists
(`transfer.rs:303-349`, `update.rs:428-458`). If the verifier is `None` — the
normal case when an operator sets `allow_transfer` without `tsig_keys` — a
forged TSIG with any key name and MAC is accepted and the zone is transferred.

**D39 (High, found while planning).** The TSIG MAC is not RFC 8945 canonical:
`sign` hashes the raw message and appends `key_name.as_bytes()`
(`tsig.rs:182-199`), without removing the TSIG RR, decrementing ARCOUNT, or
including CLASS/TTL/algorithm/time/fudge/error/other fields. Responses append
bare RDATA with an incremented ARCOUNT (`transfer.rs:201-220`) — no NAME, TYPE,
CLASS, TTL, or RDLENGTH — so no conforming client can parse or verify a signed
transfer, and no request can be verified by a conforming server either.

**D20 (Medium).** `is_transfer_allowed` grants a zone to any client when an ACL
entry string equals the zone origin (`transfer.rs:143-151`), and the ACL is one
flat list with no zone association, so an IP entry authorizes every zone.

**D21 (Medium).** IXFR fallback ignores `axfr_enabled` and `tcp_only`
(`transfer.rs:536-553`; AXFR's checks exist only in
`handle_axfr_request_impl`), and the UDP dispatch concatenates all messages with
no TC bit, giving a full-zone dump over UDP.

**D22 (Medium).** Dynamic UPDATE stores absolute owner names into a store keyed
by relative names (`update.rs:499-548`), treats prerequisite classes 1–4 instead
of RFC 2136's ANY(255)/NONE(254) with TTL 0 and RDLENGTH semantics
(`:77-83`), replaces whole RRsets on add, silently drops class-NONE deletes, and
compares text RDATA against wire RDATA.

**D30 (Medium).** DNS cookies are computed and validated only to write a debug
log (`server/query.rs:971-987`); there is no config to require them, so
spoofed-source UDP has no cookie defence.

## Root cause

The control plane was built to pass its own tests: the tests sign and verify
with the same non-canonical function, so the MAC mismatch with the RFC is
invisible; `require_tsig` was implemented as "a TSIG exists" because no verifier
is configured by default; update semantics were written from the record store's
shape rather than from RFC 2136's metavalue table.

## Fix scope

### R1 — RFC 8945 TSIG

Implement, in `tsig.rs`:

```text
request  digest = HMAC(key, message-without-TSIG || tsig_variables)
response digest = HMAC(key, u16(request_mac_len) || request_mac
                          || message-without-TSIG || tsig_variables)
tsig_variables = canonical(name) || CLASS(ANY=255) || TTL(0) || canonical(alg)
                 || time_signed(48) || fudge(16) || error(16)
                 || other_len(16) || other_data
```

- `message-without-TSIG` is the message with the TSIG RR removed and ARCOUNT
  decremented — the existing `original_offset` gives the cut point.
- Emit a complete RR (`NAME, TYPE=250, CLASS=ANY, TTL=0, RDLENGTH, RDATA`), not
  bare RDATA, and increment ARCOUNT once.
- Verification order per RFC 8945 §5.2: key name/algorithm, MAC, time (with
  fudge), truncation policy; a MAC longer than the algorithm output is FORMERR.
- Keep the constant-time compare and the replay cache; the replay cache is
  keyed on the full MAC after verification.
- TCP multi-message responses: every message after the first carries the
  previous message's MAC in the digest (RFC 8945 §5.3.1).

### R2 — Presence implies verification

- `ZoneTransfer::with_security_config` and `DynamicUpdateHandler::with_config`
  reject `require_tsig && verifier.is_none()` at construction, and the
  composition layer fails startup with a clear error.
- If a TSIG is present, it is verified even when `require_tsig` is false; a
  failed verification is REFUSED, never "unsigned fallback".
- The parse happens after the cheap ACL rejection, not before (phase 03 R3).

### R3 — Per-zone transfer authorization

```rust
pub struct TransferAcl { cidrs: Vec<IpNetwork>, zones: Vec<String>, key: Option<String> }
```

Authorize `(client_ip, origin, tsig_key)` jointly: a CIDR entry and a zone entry
must both match (an empty zone list means all zones); a named key must match the
verified TSIG key. Delete the `allowed == origin` grant. Wildcard `"*"` keeps
its existing `allow_wildcard_transfer` + TSIG-required semantics.

### R4 — IXFR obeys the same rules as AXFR

Thread `is_tcp` into `handle_ixfr_request`; the fallback requires
`axfr_enabled`; UDP IXFR returns a truncated response (TC=1) or REFUSED rather
than concatenating messages; cap total transfer bytes per connection and per
zone.

### R5 — RFC 2136 update semantics

- Decode prerequisites by `(class, type, rdlength, ttl)`:
  ANY+ANY+0 = name in use; ANY+type+0 = RRset exists; NONE+ANY+0 = name not in
  use; NONE+type+0 = RRset does not exist; zone-class+type+rdata = value
  dependent, compared on canonical wire RDATA with TTL ignored.
- Updates: zone-class = add to RRset; ANY + TTL 0 + RDLENGTH 0 = delete RRset;
  NONE = delete the specific RR. At the apex, never delete the SOA or the last
  NS (RFC 2136 §3.4.2.4).
- Owner names go through `normalize_record_name`; an out-of-zone name is
  NOTZONE.
- Reject RRSIG/NSEC/NSEC3/DNSKEY writes unless an explicit policy allows them.
- Serial bump, journal entry, and zone-index/denial-chain rebuild (T7) in one
  commit; two concurrent updates serialize on the zone writer instead of
  last-write-wins on a clone.
- Return the RFC's rcodes: FORMERR, NOTAUTH, NOTZONE, NXRRSET, YXRRSET,
  NXDOMAIN, YXDOMAIN, REFUSED.

### R6 — NOTIFY

Verify the TSIG MAC when configured (not merely its presence); the source
allowlist defaults to deny-all and must be configured explicitly; a NOTIFY for
an unknown zone returns NOTAUTH without touching the cache.

### R7 — Cookies: enforce or delete

Preferred: add `dns.settings.require_cookie` (default `false`). When enabled, a
UDP query without a valid server cookie receives BADCOOKIE with a fresh server
cookie (RFC 7873 §5.2.3); a valid cookie lets the query proceed and is
refreshed. DoH/DoT/DoQ are exempt (no spoofing). If the owner prefers not to
enforce, delete the dead validation branch and the cookie server from the query
path rather than leaving a control that controls nothing.

### R8 — Gates stay closed

The phase ends with `allow_transfer`, `dynamic_update.enabled`, and
`notify.enabled` still rejected by `DnsConfig::validate()`. Lifting them is a
separate product decision after this phase is green, and must add the
corresponding config docs and a migration note.

## Tests

New suite `tests/dns_control_plane_contract.rs`:

1. TSIG request MAC matches an independently computed RFC 8945 digest (test
   computes the digest with `ring`/`hmac` directly, not with `tsig.rs`);
2. TSIG response MAC matches the RFC digest that includes the request MAC;
3. a signed transfer response parses as a complete RR and verifies;
4. a truncated MAC, a bad time, a wrong key, and a replayed MAC are each
   rejected with the RFC's error code;
5. `require_tsig` with no verifier fails construction;
6. transfer ACL matrix: CIDR only, zone only, both, wildcard, key mismatch;
7. IXFR over UDP is truncated or refused, never a full dump; fallback honors
   `axfr_enabled`;
8. update matrix from RFC 2136 §3.2.4/§3.4.2 (each metavalue), out-of-zone
   NOTZONE, apex SOA/NS guards, RRset add/delete, atomic rollback;
9. two concurrent updates to one zone produce both `changes` (serialized), not
   a lost update;
10. NOTIFY with a bad MAC and from a non-allowlisted source is refused;
11. cookie flow: no cookie → BADCOOKIE + server cookie; valid cookie → answer;
    tampered cookie → BADCOOKIE.

## Out of scope

- Lifting the config gates (separate decision).
- AXFR/IXFR performance and journal persistence beyond the serial/rollback
  correctness above.
- RPZ (not wired; separate feature decision).

## Verification

```bash
cargo test -p synvoid-dns --test dns_control_plane_contract --profile ci
cargo test -p synvoid-dns --test axfr_ixfr_transfer_semantics --profile ci
cargo test -p synvoid-dns --test update_authorized_semantics --profile ci
cargo test -p synvoid-dns --test update_atomicity_rollback --profile ci
cargo test -p synvoid-dns --test tsig_success_fixtures --profile ci
cargo test -p synvoid-dns --profile ci
```

Acceptance:

- the independent-digest tests pass (they fail against `ea638ff9`);
- `rg 'key_name\.as_bytes' tsig.rs` returns nothing in the digest path;
- no handler treats `Some(tsig)` as authenticated without a verifier;
- the existing transfer/update suites are updated where they encoded the old
  ACL or rcode behavior, and the config gates still reject the features.
