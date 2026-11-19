# DNS / DNSSEC Architecture

## DNSSEC Validation in Recursive Mode

The recursive resolver (`HickoryRecursor`) performs **full inline DNSSEC validation** when `dnssec_validation = true`. This includes:
- Trust anchor verification (DNSKEY vs DS record chain)
- RRSIG signature verification against DNSKEY
- NSEC/NSEC3 proof of nonexistence validation

Validation is enabled via `dnssec_validation = true` in `[dns.recursive]` config.

## DNSSEC Validation in Forwarding Mode

When operating as a forwarding resolver, SynVoid does **not** perform full DNSSEC validation itself. Instead it relies on the upstream recursive resolver:

1. Client sends query with `DO` (DNSSEC OK) bit.
2. SynVoid forwards to upstream with `DO` bit set.
3. Upstream returns RRSIG + DNSKEY/NSEC/NSEC3 records alongside the answer.
4. SynVoid verifies the AD (Authenticated Data) bit from upstream and, if set, propagates it to the client.

## Denial of Existence (NSEC / NSEC3)

A signed zone's denial records are **derived from the zone at load time**, not
synthesized per query (phase 05). `crates/synvoid-dns/src/denial.rs` builds:

- a canonical owner index in RFC 4034 §6.1 order (label sequences compared
  from the root, ASCII case-folded) — not `String` order;
- one NSEC per owner, `next` wrapping to the apex, with a bitmap equal to the
  RRsets present at that owner plus `NSEC` and `RRSIG`. `DS` appears only at a
  delegation (NS present, no SOA); an absent DS is never asserted;
- an NSEC3 chain in hash order when the zone publishes NSEC3PARAM, including
  one record per empty non-terminal (empty bitmap) and none below a zone cut.
  The next-hash field is the next hash **bytes**, and the Hash Length byte is
  the hash length (20 for SHA-1), never the base32 spelling.

`Zone` stores the index behind an `Arc`, so the per-query `Zone` clone copies a
pointer. `Zone::rebuild_denial` is the single builder and runs on load, reload,
`add_record`, dynamic-update commit, and store insert. The query path only
**selects** a proof:

| Answer | NSEC | NSEC3 |
|---|---|---|
| NODATA at an owner | the owner's NSEC | the matching NSEC3 |
| NXDOMAIN | the NSEC covering the qname (canonical predecessor) plus the wildcard-absence NSEC when a wildcard could match | closest-encloser match + next-closer cover + wildcard cover |
| Wildcard answer | the NSEC covering the next closer name | the NSEC3 covering the next closer name |
| Wildcard NODATA | next-closer cover + the wildcard owner's NSEC | closest encloser + next-closer cover + wildcard match |

If a signed zone cannot select a proof, it answers SERVFAIL; it never emits an
unprovable negative answer. Wildcard *lookup* (RFC 4592 synthesis) remains
phase 09; phase 05 supplies and tests the proof the wildcard answer must carry,
which is why a name error for a name under an existing wildcard is currently
SERVFAIL rather than a bogus NXDOMAIN.

### NSEC3 Parameters

```
algorithm:  1 (SHA-1) — the only algorithm with a standard 20-octet hash
flags:      0 (no opt-out) or 1 (opt-out)
iterations: 0 recommended by RFC 9276; capped at 100 by NSEC3_MAX_ITERATIONS
salt:       at most 255 octets (one-octet length field in the RDATA)
```

With Opt-Out set, insecure delegations are omitted from the chain and the
covering NSEC3 carries the flag; a secure delegation stays in the chain with
its DS bit. A salt longer than 255 octets and an unsupported hash algorithm
refuse to build a chain (the zone then fails closed on negative answers)
rather than publish structurally invalid RDATA.

## Key Rotation (manual runbook)

There is **no in-process key-rotation task** (phase 05 R4). The previous task
rotated keystore handles on a timer but never re-published them into the served
zones, so the published DNSKEY and the validating key silently diverged (D24).
The zone's `ksk_key`/`zsk_key` handles are **reload-only**: `initialize_dnssec`
sets them from the keystore's active keys at startup.

To rotate:

1. Stop the server (or take the zone out of service).
2. Generate a new **active** key of the required type with the
   `synvoid-dnssec-keystore` management API (`generate_key` writes a new active
   key file that `load_keys_from_disk` selects). Keep the previous key material
   until the propagation interval has passed. Note: `complete_key_rollover`
   currently swaps the standby handle only in memory and does not promote the
   standby files on disk, so a restart would reload the old active key; use
   `generate_key`, or promote the standby files yourself, before restarting.
3. Start the server. `initialize_dnssec` loads the newest active keys from disk
   and republishes them in every zone's DNSKEY RRset; restarting is what makes
   the served zone and the keystore agree.
4. Confirm the served DNSKEY/RRSIG with a validator (`delv`/`dig +dnssec`)
   before retiring the old key.
5. For a KSK rollover, update the parent DS only after the new DNSKEY has been
   served for at least the propagation interval (2x the zone TTL by default).

Rotating keys in the keystore while the server keeps running is a no-op for
the served zone; do not script it.

## Trust Anchor Management (static; RFC 5011 removed)

SynVoid reads **static** DNSSEC trust anchors from one file at startup:

```rust
// crates/synvoid-dns/src/resolver.rs
pub fn load_static_trust_anchors(path: &Path)
    -> Result<hickory_proto::dnssec::TrustAnchors, String>;
```

The path is `dns.recursive.trust_anchor_path`; `HickoryRecursor::from_paths`
feeds it to hickory as `DnssecPolicy::ValidateWithStaticKey`. Replacing the file
takes effect at the next process start.

**RFC 5011 automated anchor management is not implemented** (decision T5). The
former `crates/synvoid-dns/src/trust_anchor.rs` state machine
(`NewKeySeen → Pending → Valid → Revoked → Removed → Missing`) and the
`process_rfc5011_updates()` task were deleted: nothing fed the state machine
(no DNSKEY observation was ever scheduled) and nothing consumed its output (the
recursor's anchors were a startup snapshot), so promotions and revocations could
not affect validation. The `[dns.trust_anchors]` section still parses, but
`enabled = true` is rejected with a typed `Unsupported` error that names
`dns.recursive.trust_anchor_path` as the only supported source.

Forwarders do not validate locally. `dns.recursive.dnssec_validation = true`
with a forwarder provider is a startup error unless
`dns.recursive.allow_unvalidated_forwarding = true` is set; `/health` then
reports `dnssec_state.validation = "delegated"`.

For the operational notes, see
[`/docs/RFC5011_TRUST_ANCHOR.md`](./RFC5011_TRUST_ANCHOR.md).

## AD Bit Propagation

The AD bit is set on responses only when:

1. The zone is DNSSEC-signed (has DNSKEY records).
2. The RRSIG chain validates successfully (recursive mode) **or** the upstream resolver set AD (forwarding mode).

In forwarding mode AD is passed through from upstream. In authoritative mode AD is **never set** — authoritative servers do not perform validation; AD is a recursive resolver signal (per RFC 4035 §3.1.6).

## Key Custody (Phase 30)

Authoritative signing keys are owned by `crates/synvoid-dnssec-keystore/`
(opaque sealed handles, `0600` atomic persistence, rotation lifecycle).
The DNS crate holds no private key bytes: zones keep sealed handles and
sign via the keystore; trust anchors and mesh anchors are public-only.
HSM/PKCS#11 backing is opt-in (`dns-hsm` feature) and fails closed with
no silent software fallback. Details: `architecture/dnssec_keystore.md`.

## Relevant Source

- `crates/synvoid-dnssec-keystore/src/` — sealed keys, keystore, HSM backends, DS digests
- `crates/synvoid-dns/src/dnssec.rs` — custody facade + `Nsec3Config`
- `crates/synvoid-dns/src/dnssec_signing.rs` — sealed signing entry, NSEC/NSEC3 wire construction, base32 encoding
- `crates/synvoid-dns/src/denial.rs` — canonical owner index, NSEC/NSEC3 chains, proof selection
- `crates/synvoid-dns/src/dnssec_validation.rs` — key tag calculation, DS digests, canonicalization
- `crates/synvoid-dns/src/server/dnssec_impl.rs` — DNSSEC response assembly, signing-key selection, SERVFAIL policy
