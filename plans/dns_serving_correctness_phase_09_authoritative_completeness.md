# Phase 09 Plan: Authoritative Completeness and Bounds

Status: **IMPLEMENTED** (2026-11-19; `dns_authoritative_lookup`, 10 tests).
Audit: `plans/dns_capability_audit.md` (D18, D28, D29, plus the zone-file and
store lows).
Registered in: `plans/roadmap.md`.
Campaign: `plans/dns_serving_correctness_roadmap.md`.
Predecessor: Phase 01 (encoder) and Phase 05 (owner index).
Depends on: phase 05's canonical owner index; wildcard and delegation lookup
extend it rather than build a second one.

## The findings

**D28 (Medium).** The authoritative lookup is an exact hashmap hit
(`server/query.rs:1085-1112`) with no wildcard, referral, or empty-non-terminal
handling anywhere in `server/query.rs` or `server/response.rs`:

- a `*.example.com` record loads successfully (`normalize_record_name` accepts
  `"*"`) and never matches, so `foo.example.com` is NXDOMAIN;
- an NS at a subdomain produces no referral, so the parent answers the child's
  names authoritatively from its own data;
- a name that exists only as an empty non-terminal is reported NXDOMAIN instead
  of NODATA.

**D29 (Medium).** Records are never deduplicated: a config with two identical
`A` entries answers both (`server/zone.rs:210-211`), and `add_record` keys the
map without `normalize_record_name` (`:339-355`), so a mixed-case or
fully-qualified name is stored where the lookup will never find it.

**D18 (Medium).** `ShardedZoneStore::get` clones the whole `Zone`
(`server/sharded_store.rs:67`), and `Zone` contains `history: Vec<ZoneHistory>`
where each entry holds another full record map (up to 200,
`server/mod.rs:539-553`). One query therefore copies `(1 + history) x records`.
`find_by_suffix` clones too (`:163`).

Zone-file and store defects (latent — no production caller, but the code is
`pub` and the fix is cheap):

- `zone_file.rs` keys owners absolutely (`:196-207`), lets `$ORIGIN` rewrite the
  zone identity (`:146-150`), turns inherited-owner lines into a record named
  `IN` (`:66`, `:275-279`), and truncates multi-token RDATA to one token;
- `store.rs` reloads DNAME as CNAME and writes every other unlisted type as 0,
  then drops it as corrupt on load (`:157-181`, `:237-250`); the SOA serial is
  not restored (`:206-208`), so IXFR comparisons start from 0.

## Root cause

The zone model is a flat `HashMap<(relative_name, type), Vec<record>>` with an
exact-match lookup. Wildcards, delegations, and empty non-terminals need the
owner index that phase 05 introduces for DNSSEC; without it, the lookup was
written as a hashmap `get` and the missing cases were never noticed because the
test zone has no wildcard, delegation, or ENT.

## Fix scope

### R1 — Lookup walks the owner index

Replace the exact-match block with one algorithm, used by the signed and
unsigned paths:

1. exact owner + qtype → answer; exact owner + CNAME → answer the CNAME and, if
   the target is in-zone, append its records (loop-guarded);
2. exact owner with other types → NODATA;
3. no exact owner → walk to the closest encloser in the index. If the encloser
   is below a delegation (NS present, no SOA), return a referral:
   AA=0, NS in authority, in-bailiwick glue in additional;
4. otherwise try the wildcard `*.<closest encloser>`; if it exists, synthesize
   the answer at the qname (RFC 4592), including the CNAME-at-wildcard case;
5. if the qname is an empty non-terminal (some owner exists below it), return
   NODATA with SOA;
6. otherwise NXDOMAIN with the phase-05 denial proof.

DNAME: a DNAME at an ancestor synthesizes the CNAME and includes the DNAME
(RFC 6672). Wildcards do not match below a delegation or at the delegation
point.

### R2 — One writer for zone state

All mutation paths (load, reload, update commit, mesh apply, rotation publish)
go through the phase-05 rebuild: normalize names, deduplicate
`(owner, type, rdata)` keeping one TTL, rebuild the owner index and denial
chain, bump the serial, invalidate the response cache. `add_record` uses
`normalize_record_name` and rejects a TTL inconsistent with an existing RRset.

### R3 — Stop cloning the zone per query

- `ShardedZoneStore::get`/`find_by_suffix` return `Arc<Zone>` (store
  `Arc<Zone>` per origin, replace on mutation), so a query holds a pointer.
- `Zone::history` entries hold `Arc<RecordMap>` or are moved out of the hot
  path; a query never clones history.
- The denial chain (phase 05) is already `Arc`; keep it that way.

### R4 — Zone file and store correctness

- `zone_file.rs`: store relative keys via `normalize_record_name`; treat
  `$ORIGIN` as parse-scoped state for subsequent owners, not as a change to the
  zone identity; preserve leading whitespace for owner inheritance; parse the
  full RDATA for every type it claims to support (or reject the type) instead of
  taking one token.
- `store.rs`: round-trip the record type as `u16`; restore `zone.serial` from
  the SOA on load; propagate `save_zone` errors instead of `let _ =`.

## Tests

New suite `tests/dns_authoritative_lookup.rs`:

1. RFC 4592 §2.2.1 examples: `*.example.` matches `a.example.` but not
   `a.b.example.`, and not `example.` itself;
2. wildcard CNAME synthesis and the "wildcard does not match at the delegation
   point" case;
3. delegation: `child.example.com` with NS returns a referral (AA=0, NS in
   authority, glue in additional) and does not answer the child's A;
4. empty non-terminal `a.b.example.com` exists → NODATA with SOA, not NXDOMAIN;
5. DNAME at an ancestor synthesizes the CNAME and carries the DNAME;
6. dedupe: a zone with two identical A records answers one; an RRset has one
   TTL;
7. `add_record("WWW.Example.COM.", ...)` is found by a `www.example.com` query;
8. `get` returns `Arc<Zone>` and two queries share the pointer (`Arc::ptr_eq`);
9. zone-file parser: `$ORIGIN` scoping, inherited owners, a multi-token NAPTR;
10. store round-trip: DNAME, TLSA, SVCB survive save/load, and the serial is
    restored.

## Out of scope

- DNSSEC proofs (phase 05) — the lookup calls into the chain but does not
  change it.
- Zone transfer serialization of the new records (phase 07 owns transfers).
- Mesh zone syncing semantics (phase 08).

## Verification

```bash
cargo test -p synvoid-dns --test dns_authoritative_lookup --profile ci
cargo test -p synvoid-dns --test dns_interop_authoritative --profile ci
cargo test -p synvoid-dns --test authoritative_negative --profile ci
cargo test -p synvoid-dns --profile ci
cargo bench -p synvoid-dns --bench zone_bench --no-run   # clone removal compiles
```

Acceptance:

- no `zone.records.get(&key)` exact-only lookup remains in the query path;
- a query for a 1k-record zone with 200 history entries allocates no record map
  (the `Arc` test);
- the RFC 4592 example matrix passes.
