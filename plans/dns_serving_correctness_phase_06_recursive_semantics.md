# Phase 06 Plan: Recursive Semantics and Trust Anchors

Status: **IMPLEMENTED** (2026-11-19; `dns_recursive_contract`, 25 tests. RFC
5011 was deleted per decision T5; static file anchors are the only source).
Audit: `plans/dns_capability_audit.md` (D9, D10, D23, D25, D26, D27, D31, plus
the recursive lows).
Registered in: `plans/roadmap.md`.
Campaign: `plans/dns_serving_correctness_roadmap.md`.
Predecessor: Phase 01 (owner encoder — the recursive response builder is one of
its two call sites).
Depends on: nothing else. Phase 01 must land first or recursive answers stay
unparseable regardless of the semantics fixed here.

## The findings

**D9 (High).** `resolve_upstream` maps every resolver error to an empty record
vector (`recursive.rs:955-985`), and `resolve_query_with_depth` then
negative-caches an empty set for `negative_ttl` (300 s) and answers with
`response_code: 0` (`:1002-1028`). Timeouts, REFUSED, SERVFAIL, and DNSSEC
validation failures all become cached NODATA, shared by every client. CAA
NODATA is read by CAs as "issuance permitted" (RFC 8659), and DS/DNSKEY/NAPTR/
ANY are never looked up at all.

**D10 (High).** Cache hits are served whenever present (`recursive.rs:752-769`);
the `stale` flag only increments a metric. `recursive_cache.rs:236-249` treats
an entry as live for `ttl + stale_ttl` (`stale_ttl` default 86400, `min_ttl` 0),
and expired records are replayed with their original TTL. A TTL-0 answer is
immediately "stale" and served for a day. RFC 8767 permits stale data only as a
fallback after an upstream failure.

**D23 (Medium, latent).** RFC 5011 accepts a self-referential CDS as proof that
a new key is trusted (`trust_anchor.rs:549-591`) and promotes it without
checking a signature by an existing anchor (`:690-716`). The REVOKE bit is
honoured from an observation whose `authentic_data` flag is captured but never
consulted (`:472-478`, `resolver.rs:1119-1128`).

**D31 (Medium, latent).** `start_rfc5011_updates` has no caller
(`resolver.rs:785`), so the manager never observes the root DNSKEY RRset; the
recursor's anchors are a startup snapshot (`:703-711`). Promotions and
revocations therefore never affect validation, and a revoked key stays trusted
for the process lifetime.

**D25 (Medium).** `RecursiveCacheKey` is case-sensitive
(`recursive_cache.rs:76-106`) while the coalescer lowercases
(`query_coalesce.rs:64`), so case variants fragment the shared cache, and a
coalesced waiter receives the owner's raw packet — wrong message ID, question
case, and EDNS options (`:44-52`, `server/startup.rs:326-355`). The key also
omits CD, so a CD=1 query writes `Unchecked` under a key a CD=0 client reads.

**D26 (Medium).** The recursive listener is constructed with `firewall: None`
(`server/startup.rs:121-126`), so `dns.recursive.firewall` — including
rebinding protection — is parsed and never enforced.

**D27 (Medium).** `CustomUpstreamEndpoint::Literal` discards the port
(`runtime_config.rs:884-896`), `NameServerConfig::udp_and_tcp` always uses 53,
and an empty or hostname-only list silently falls back to the system resolver
(`recursive.rs:250-256`). `GlobalNodeResolver` has the same silent fallback on
upstream error (`resolver_global.rs:48-70`).

Recursive lows carried by this phase:

- AAAA is answered from an A-only lookup (`resolver.rs:1332-1334`), so every
  AAAA query is a 5-minute cached NODATA;
- `max_cname_depth`/`max_recursion_depth` are never incremented
  (`recursive.rs:716-736`) and never reach hickory's `RecursorOptions`;
- NXDOMAIN is stored (`is_nxdomain`) but every cached negative answer is emitted
  as NOERROR (`recursive.rs:1004-1021`), and the SOA minimum is ignored;
- the per-client semaphore table drops new clients silently when full
  (`:143-160`, `:579-585`).

## Root cause

The resolver wrapper was written around hickory's `lookup_*` helpers, which
return `Result<Lookup>` with no distinction between "no records" and "lookup
failed", and the wrapper collapsed both to `Vec::new()`. Stale serving was
added as a cache property rather than a response policy. RFC 5011 was built as
a standalone state machine with tests, but nothing ever fed it or consumed it.

## Fix scope

### R1 — Distinguish failure from absence

`resolve_upstream` returns `Result<AnswerSet, ResolveError>` where `AnswerSet`
carries `records`, `rcode` (NOERROR/NXDOMAIN), and `negative_ttl` derived from
the SOA (`min(SOA TTL, SOA MINIMUM)`, RFC 2308).

- Transport/validation errors → SERVFAIL; never inserted into the cache.
- `NXDomain` → RCODE 3, cached with the SOA-derived TTL, `is_nxdomain` honoured.
- Empty NOERROR → NODATA, cached with the SOA-derived TTL.
- Unsupported qtype → NOTIMP (or a real lookup for DS/DNSKEY/NAPTR; ANY is
  answered from the cache only).

### R2 — Stale is a fallback, not a policy

On a cache hit that is expired:

1. try the upstream first;
2. on failure and only on failure, serve the stale entry with TTL 30
   (RFC 8767 §4), set `stale` in metrics, and schedule a refresh;
3. if the entry is beyond `stale_ttl`, SERVFAIL.

TTL 0 is not cacheable. Served TTLs are decremented by age; the original TTL is
kept only for the cache entry.

### R3 — One cache key, one coalesced answer

- `RecursiveCacheKey` lowercases the qname, keeps qtype/qclass/DO, adds `cd`,
  and keeps the client subnet only when ECS is forwarded (today it is always
  `None`).
- The coalescer broadcasts the response body without the 2-byte ID, and each
  waiter re-encodes its own ID and question case; or, if that is too invasive,
  `QueryKey` gains `cd` and the waiter's question bytes are compared before
  delivery. A waiter must never receive a packet whose question differs from
  its own.

### R4 — Wire encoding

The recursive response builder uses phase 01's encoder. Delete
`build_question_section`/`build_answer_record` string-appending entirely and
encode from a `CachedRecord { owner: OwnerName, ... }`.

### R5 — Firewall parity

`start_recursive_server` builds the firewall from `config.firewall` and passes
it to `RecursiveDnsServer::new`; a firewall that fails to build fails startup.
The UDP and TCP recursive paths evaluate it exactly as the authoritative path
does, before cache lookup, so a blocked qname is not served from cache.

### R6 — Upstreams are explicit

- Carry `port` through `CustomUpstreamEndpoint` into
  `NameServerConfig { ip, port, .. }`.
- An empty or hostname-only upstream list is a startup error, not a system
  fallback. If the system resolver is wanted, `upstream_provider = System` says
  so explicitly.
- `GlobalNodeResolver` returns an error instead of falling back.
- Startup logs one line per upstream with address, port, and provider.

### R7 — Limits that are configured are enforced

- Look up the requested type (A and AAAA separately, DS/DNSKEY when asked).
- Pass `max_cname_depth` and `max_recursion_depth` into `RecursorOptions`
  (hickory exposes `recursion_limit`/`ns_recursion_limit`); delete the dead
  `recursion_depth` parameter.
- Per-client semaphore exhaustion returns REFUSED, never silence, and evicts
  the least-recently-used entry instead of failing closed for new clients.

### R8 — Delete RFC 5011 (decision T5)

- Remove `TrustAnchorManager`'s observation API (`observe_dnskey_at_root`,
  `trust_anchor_check`), the unused `start_rfc5011_updates` task, and the
  `TrustAnchorConfig` state machine, keeping the static file loader and
  `build_trust_anchors`.
- The `[dns.trust_anchors]` config section stays parseable but returns a typed
  `Unsupported` that names the file as the only supported anchor source.
- `docs/RFC5011_TRUST_ANCHOR.md` and the architecture doc are corrected to say
  static anchors, with the removed feature named.

If the owner prefers to keep RFC 5011, the alternative is to implement it
properly: require an RRSIG over the DNSKEY RRset by a currently-Valid anchor
before `Seen → Pending`, consult `authentic_data` before honouring REVOKE, feed
the task from a real DNSKEY poll, and swap the resulting anchor set into the
live resolver. That is a larger phase and is not recommended for this campaign.

### R9 — Contradictory validation config

`dnssec_validation = true` with a forwarder provider (`System`/`Google`/
`Cloudflare`/`Custom`) currently only logs a warning. Make it a startup error
unless a new explicit `allow_unvalidated_forwarding = true` is set, and have
`/health` report validation as `delegated` rather than `enabled` in that mode.

## Tests

New suite `tests/dns_recursive_contract.rs` (uses `support::runtime_config`'s
`start_bound_dns_server` and a stub resolver injected through the existing
`DnsResolver` trait):

1. upstream timeout → SERVFAIL, and a second query hits the upstream again (no
   negative cache);
2. upstream NXDOMAIN → RCODE 3 with the SOA TTL, cached and reused;
3. empty NOERROR → NODATA with SOA TTL;
4. expired entry + upstream failure → stale answer with TTL 30;
5. expired entry + upstream success → fresh answer (no stale);
6. TTL 0 is not cached;
7. CD=1 and CD=0 queries do not share a validation state;
8. mixed-case qnames share one cache entry;
9. two coalesced clients with different IDs each receive their own ID;
10. a firewall-blocked qname is refused on the recursive UDP and TCP paths;
11. a custom upstream on port 5353 is queried on 5353 (stub listener);
12. an empty upstream list fails startup;
13. AAAA returns AAAA records, not a cached NODATA;
14. `max_cname_depth` is enforced (a CNAME chain longer than the limit fails).

Trust-anchor tests: after R8, assert `[dns.trust_anchors].enabled = true` is
rejected with the typed error and that the static file anchors are the only
ones loaded.

## Out of scope

- DNSSEC validation semantics themselves (hickory's recursor is trusted; the
  wrapper reports its result honestly).
- ECS forwarding (config-gated, no-op today).
- Mesh recursive routing.

## Verification

```bash
cargo test -p synvoid-dns --test dns_recursive_contract --profile ci
cargo test -p synvoid-dns --test dns_recursive_isolation --profile ci
cargo test -p synvoid-dns --test dns_recursive_test --profile ci
cargo test -p synvoid-dns --profile ci
```

Acceptance:

- no `Err(_) => Vec::new()` remains in `recursive.rs`;
- every cache insert is either `AnswerSet` with an rcode or a stale-promotion;
- the coalescer test with two IDs passes;
- the recursive listener has a non-`None` firewall in the context.
