# Phase 05 Plan: Denial of Existence and Key Lifecycle

Status: **IMPLEMENTED** (2026-11-19; `dnssec_denial_contract`, 18 tests. R4
took the plan's explicit alternative: the rotation task was removed and key
rotation is a documented manual runbook, because no rotation-to-zone writer
exists and a partial implementation would still serve stale keys after a
restart).
Audit: `plans/dns_capability_audit.md` (D5, D6, D24, L5, D38 added during
planning).
Registered in: `plans/roadmap.md`.
Campaign: `plans/dns_serving_correctness_roadmap.md`.
Predecessor: Phase 04 (signing).
Depends on: Phase 04 for a verifier and for FQDN signing; Phase 01 for the
owner encoder.

## The findings

**D5 (Critical).** `hash_name_nsec3` (`dnssec_signing.rs:160-198`) concatenates
the name and salt and then loops `for _ in 0..config.iterations`. With the
shipped default `iterations = 0` (`dnssec.rs:56-65`) the loop never runs, so the
"hash" is the plaintext name plus salt. RFC 5155 §5 requires
`IH(salt, x, 0) = H(x || salt)` — iteration zero is still a hash. The input is
also the dotted presentation form, not the canonical wire name.

**D6 (Critical).** Denial records are synthesized per query instead of derived
from the zone:

- the NSEC bitmap is a hardcoded list (`dnssec_impl.rs:345-362`), and for
  NXDOMAIN the NSEC owner is the *queried* name (`:366-370`), asserting that a
  name that does not exist holds A/NS/CNAME/SOA;
- `create_nsec_record` ignores `current_name` (`dnssec_signing.rs:90-108`);
- `find_next_name_in_zone` sorts with `String` order (`:141`), not RFC 4034
  §6.1 canonical order, so some ranges do not cover their gap (L5);
- the NSEC3 builders assemble an arbitrary closest/wildcard/next-closer triple
  (`dnssec_impl.rs:193-330`) whose pointers are not the zone's hash order, pass
  already-base32 owner names into `create_nsec3_record`, which hashes them
  again (`dnssec_signing.rs:211-216`, double hash), and derive `next_closer` by
  stripping the encloser so only the leftmost label is hashed
  (`dnssec_impl.rs:249-257`);
- `create_nsec3_owner_name` prefixes the length of the *base32 string* (52)
  instead of the hash length (32) (`dnssec_signing.rs:243-246`);
- bitmaps always include 46/47/50 and omit DS (43) (`dnssec_impl.rs:110-130`).

**D24 (Medium).** Key rotation never reaches the served zone. `initialize_dnssec`
sets `zone.ksk_key`/`zone.zsk_key` once for every zone
(`dnssec_impl.rs:41-45`); `start_key_rotation_task` (`:591-625`) rotates
keystore handles but never re-publishes them, so the served DNSKEY and the
validating key never change. Rollover state is in memory only
(`keystore.rs:78-84`), so a restart resurrects a retired key from disk.

**D38 (Medium, found while planning).** `create_nsec3_record` emits the next
hashed owner by hashing the NSEC3 owner-name string instead of copying the next
hash bytes, and `create_nsec3_owner_name` writes a 52-byte length prefix. Both
make the RDATA structurally invalid independent of D5.

## Root cause

The denial code was written as a query-time approximation because the `Zone`
type has no canonical owner index: records are keyed by relative name in a
`HashMap`, and nothing enumerates owners in DNSSEC order. Key rotation was
written against the keystore alone, treating the zone handles as a startup
detail rather than live state.

## Fix scope

### R1 — Canonical owner index and NSEC chain

Add to the DNS crate:

```rust
pub struct ZoneDenial {
    owners: Vec<(Vec<u8> /* canonical wire */, String /* display */)>,
    nsec: HashMap<String, Arc<DnsZoneRecord>>,       // owner display -> NSEC
    nsec3: Option<Nsec3Chain>,                       // hash-sorted
}
pub struct Nsec3Chain {
    param: Nsec3Config,
    by_hash: BTreeMap<[u8; 20], Arc<DnsZoneRecord>>,
    owner_hashes: BTreeMap<String, [u8; 20]>,        // display owner -> hash
}
```

- Owners are sorted per RFC 4034 §6.1 (compare label sequences from the root,
  ASCII case-folded), not by `String` ordering.
- The NSEC bitmap for an owner is built from `records.keys()` at that owner,
  plus `NSEC` and `RRSIG`, and includes `DS` when the owner is a delegation
  (NS present, no SOA) and excludes it otherwise.
- `next` is the next owner in the sorted list, wrapping to the apex.
- Store `Arc<ZoneDenial>` in `Zone` so the per-query `Zone` clone (D18) clones
  a pointer, and rebuild it in exactly one place (see T7): zone load, reload,
  update commit, and mesh apply.

### R2 — Select proofs, do not synthesize them

- NODATA at an existing owner → that owner's NSEC/NSEC3.
- NXDOMAIN → the NSEC that covers the qname (predecessor in canonical order)
  plus, when the qname is below a wildcard that could have matched, the NSEC
  proving the wildcard's absence (RFC 4035 §3.1.3.3).
- Wildcard answer → NSEC proving the next closer name does not exist.
- The SOA in the authority section is the zone's SOA (phase 04 signs it).

### R3 — Correct NSEC3

- `hash_name_nsec3`: build the canonical wire name (fully qualified, lowercase,
  no compression), apply one hash unconditionally, then iterate `1..=k`;
  salt is raw bytes from `Nsec3Config`.
- `create_nsec3_owner_name`: owner = `base32hex(hash)` + `"."` + zone origin;
  the length byte in RDATA is the hash length, never the base32 length.
- `create_nsec3_record`: next hashed owner field = the next hash **bytes** taken
  from the sorted chain, not a re-hash.
- Proofs: closest encloser (an existing ancestor), next closer (the child of the
  closest encloser on the qname path, hashed in full), and the wildcard hash —
  each selected from the chain by coverage.
- Opt-out flag and iterations come from `Nsec3Config`; validate salt ≤ 255 and
  cap iterations (`RFC 9276` recommends 0).
- RFC 5155 §B known-answer vectors (ai.example, ns1.example, w.example,
  *.w.example, x.w.example, y.w.example, x.y.w.example, xx.example) become
  tests; hickory's own NSEC3 implementation is the independent oracle.

### R4 — Rotation reaches the zone, or it is removed

Preferred (keeps the feature honest):

- The rotation task, on `complete_ready_rollovers`, re-publishes the active
  handles into every zone and bumps the zone serial, through the same
  single-writer path as R1.
- Rollover state (`ksk_rollover_started`, `publish_dnssec`) is persisted next to
  the keys and restored on load, so a restart cannot resurrect a retired key.
- KSK completion waits for the parent DS to be confirmed; until then both keys
  are published and both sign the DNSKEY RRset.
- A ZSK rollover keeps the old ZSK published until the new one has been served
  for the propagation interval (config value; default 2× the zone TTL).

If the owner rejects the added complexity, the alternative is explicit: delete
`start_key_rotation_task`, document rotation as a manual operation with a
runbook, and make `zone.ksk_key`/`zsk_key` reload-only. Silently rotating keys
that are never served is the one option that is not allowed.

### R5 — Tests

New suite `tests/dnssec_denial_contract.rs`:

1. NSEC3 hashes match RFC 5155 §B for the eight names above, with and without
   salt;
2. `create_nsec3_owner_name` emits a 32-byte hash length for SHA-1;
3. the NSEC chain for a test zone covers every possible qname: for a sample of
   names, exactly one NSEC covers it (`owner < qname < next` in canonical
   order);
4. NXDOMAIN for `nope.example.com` carries the predecessor NSEC and a
   verifying RRSIG; a validator accepts it;
5. NODATA for `www.example.com/A` carries the owner's NSEC listing exactly the
   types present (assert the bitmap, not just presence);
6. wildcard `*.example.com` answer carries the wildcard-expansion proof;
7. the same six checks for NSEC3 mode, plus opt-out at a delegation;
8. zone reload rebuilds the chain and invalidates the response cache;
9. rotation: advance the clock past the rollover interval, assert the served
   DNSKEY changes, the old key stays published during the overlap, and the old
   key is gone after the grace period;
10. a property test: for random zones (proptest), every owner has a valid NSEC
    whose next is its canonical successor and whose bitmap equals its RRsets.

## Out of scope

- Signing mechanics (phase 04) — this phase consumes `create_signed_rrsig`.
- Delegation referral semantics (phase 09) — NSEC3 opt-out at a delegation is
  tested here, but referrals themselves are phase 09.
- DNSSEC validation (the resolver side, phase 06).

## Verification

```bash
cargo test -p synvoid-dns --test dnssec_denial_contract --profile ci
cargo test -p synvoid-dns --test dns_interop_dnssec --profile ci
cargo test -p synvoid-dns --profile ci
```

Acceptance:

- the RFC 5155 vectors pass;
- no denial record is built inside `query.rs` (`rg 'build_nsec' src/server/query.rs`
  shows only chain lookups);
- `rg 'hash_name_nsec3\(' ` shows one caller building the chain, not one per
  proof component;
- a served NSEC3 zone validates with `delv`/`ldns-verify-zone` when present.
