# DNS Milestone 2 Follow-Up Corrective Pass

## Context

Since the Milestone 2 handoff plans were created, the DNS subsystem has received a substantial implementation pass. The duplicate legacy DNS tree under `src/dns/` was removed, `crates/synvoid-dns` is now the canonical implementation path, a config-runtime matrix was added, cache key dimensions were expanded, query coalescing was hardened, runtime startup moved toward fail-fast binding and shutdown signaling, and additional DNS config/recursive isolation tests were introduced.

This follow-up pass is not a new feature milestone. It is a corrective closure pass over the post-implementation state, intended to prevent the larger changes from leaving compile, semantic, or integration gaps.

## Current repo shape

The repo is materially cleaner than before this line of work. The highest-value improvements already landed:

- Removed duplicate `src/dns/*` implementation tree.
- Added `architecture/dns_config_runtime_matrix.md`.
- Added config-fidelity tests for cache, DNS64, and ECS behavior.
- Added recursive-isolation tests.
- Expanded cache key dimensions with qclass, DNSSEC shape, client subnet, transport class, and authoritative/recursive namespace.
- Added cache metrics and serve-stale hooks.
- Improved cache fingerprint dimensions beyond qname-only.
- Improved query coalescing key dimensions and lifecycle metrics.
- Added fail-fast bind-address helper.
- Added runtime shutdown signaling.
- Made TCP hard response-size limits enforceable with SERVFAIL instead of warning-only behavior.

The remaining risks are concentrated in verification, full server-path integration of new key dimensions, robust TTL parsing, coalescing key semantics, and transport lifecycle documentation/tests.

## Objective

Close the post-implementation gaps before proceeding further into advanced DNS features. The goal is a stable Milestone 2 base that can be trusted by later DNSSEC, recursive, transport, and performance work.

## Non-goals

Do not broaden this pass into:

- full DNSSEC production hardening;
- full NSEC3 closest-encloser correctness;
- DoT/DoH/DoQ conformance;
- recursive resolver feature expansion;
- RPZ policy expansion;
- performance/load benchmarking;
- new public DNS features.

## Workstream 1: Verification baseline after large deletion

The deletion of `src/dns/*` is architecturally correct, but it must be compile-proven.

Run and record:

```bash
cargo fmt --all --check
cargo test -p synvoid-dns
cargo test -p synvoid-config dns
cargo check -p synvoid-dns --all-features
cargo check --workspace
```

If any command fails:

- classify as DNS-related or unrelated;
- fix DNS-related failures in this pass;
- document unrelated failures with exact command and crate;
- do not claim Milestone 2 closure while `synvoid-dns` or `synvoid-config dns` tests fail.

Acceptance criteria:

- `crates/synvoid-dns` compiles and tests pass.
- workspace status is known and documented.
- no references to deleted `src/dns/*` remain in compiled code.

## Workstream 2: Canonical DNS path cleanup

Tasks:

- Search for references to `src/dns`, `mod dns`, `crate::dns`, or path assumptions that still point at the deleted tree.
- Ensure agent docs, architecture docs, and build scripts identify `crates/synvoid-dns` as canonical.
- Verify removed files are not referenced by include paths, examples, docs, or skills.
- Keep the moved `AGENTS.override.md` under `crates/synvoid-dns` accurate.

Acceptance criteria:

- There is no stale implementation path in source or docs.
- Future agents have exactly one DNS implementation target.

## Workstream 3: Full cache-key integration in server paths

Problem: `CacheKey` now has correct dimensions, but server paths may still mutate only `qname` and `qtype` on a default key, leaving `qclass`, `dnssec_ok`, `transport_class`, `namespace`, and client policy dimensions under-specified.

Tasks:

- Add a canonical constructor:

```rust
CacheKey::from_parsed_authoritative(parsed, client_ip, transport_class)
CacheKey::from_parsed_recursive(parsed, client_ip, transport_class)
```

- Use the constructor in UDP, TCP, DoT/DoH/DoQ adapters where applicable.
- Set `qclass` from parsed query.
- Set `dnssec_ok` from parsed DO bit.
- Set `transport_class` from actual transport and EDNS UDP payload size.
- Set namespace explicitly.
- Decide how ECS/client subnet is represented: client IP, ECS prefix, view key, or redacted subnet.
- Remove ad hoc mutation of cache keys in `handle_parsed_query_with_cache` if possible.

Tests:

- Same qname/qtype with DO=false and DO=true do not collide.
- UDP 512 and UDP EDNS 4096 do not collide if response shape differs.
- TCP and UDP do not collide if TC behavior differs.
- authoritative and recursive entries do not collide.
- qclass differs -> key differs.

Acceptance criteria:

- Server cache insertion and lookup use full key dimensions.
- Cache key tests cover the production construction path, not only standalone constructors.

## Workstream 4: TTL parser hardening

Problem: negative TTL extraction has improved, but positive TTL extraction still appears to rely on manual question/answer skipping. The parser must handle compression pointers and malformed packets safely.

Tasks:

- Create shared helpers:

```rust
skip_dns_name(buf, pos) -> Result<usize, TtlParseError>
first_answer_ttl(buf) -> Result<Option<u32>, TtlParseError>
negative_soa_ttl(buf) -> Result<Option<u32>, TtlParseError>
```

- Use pointer-aware name skipping for question, answer, authority, and additional sections.
- For positive responses, use the minimum TTL across all answer RRs rather than the first RR only.
- For negative responses, derive TTL from SOA authority record using `min(SOA TTL, SOA MINIMUM, configured_negative_cache_ttl)`.
- Do not cache malformed responses.
- Do not cache SERVFAIL by default.
- Decide REFUSED caching policy; default should be no cache unless explicitly configured.

Tests:

- compressed owner name in answer parses TTL.
- multiple answers use minimum TTL.
- malformed compressed pointer returns no-cache.
- NXDOMAIN with SOA uses negative TTL.
- NODATA with SOA uses negative TTL.
- SERVFAIL not cached.
- REFUSED not cached by default.

Acceptance criteria:

- TTL extraction is compression-safe.
- TTL extraction is protocol-aware.
- malformed responses cannot enter cache through a parser blind spot.

## Workstream 5: Coalescing key and lifecycle closure

Problem: coalescing now has better dimensions, but it should be aligned with cache key semantics and transport policy.

Tasks:

- Decide whether `QueryKey` should reuse a subset of `CacheKey` or a separate type with explicit documented deltas.
- Include transport class if UDP/TCP/DoH/DoQ response shapes can differ.
- Include authoritative/recursive namespace if coalescer is shared.
- Replace raw EDNS UDP size offset extraction with parsed EDNS data where possible.
- Exclude AXFR, IXFR, UPDATE, NOTIFY, and malformed queries from coalescing.
- Add async tests for owner/waiter success, cancellation, timeout, cleanup, and multiple waiters.
- Verify metrics are counters where appropriate, not gauges pretending to be totals.

Acceptance criteria:

- Coalescing cannot share output across response-shaping dimensions.
- Waiters do not time out on successful owner path.
- unsafe query classes are excluded.

## Workstream 6: TCP lifecycle and transport docs

Problem: TCP handling still appears to be one query per connection. That may be acceptable as a documented limitation, but must be explicit.

Tasks:

- Decide one-query TCP versus persistent TCP.
- If one-query is retained:
  - rename or document handler as one-query TCP;
  - document compatibility limitations;
  - ensure tests assert the behavior.
- If persistent TCP is implemented:
  - add read loop;
  - enforce idle timeout;
  - enforce maximum queries per connection;
  - keep connection guard for full connection lifetime;
  - ensure AXFR/IXFR multi-message paths still work.
- Fix hard-limit SERVFAIL response to echo the original question where possible, not only a bare header.
- Preserve RD when producing TCP hard-limit SERVFAIL if query was parsed.

Acceptance criteria:

- TCP behavior is intentional, tested, and documented.
- Oversized TCP failure response is valid and policy-consistent.

## Workstream 7: Cache invalidation and mutation hooks

Tasks:

- Verify `add_record`, dynamic update, transfer apply, IXFR apply, zone load, store load, and DNSSEC key rollover all invalidate affected cache variants.
- Invalidate negative cache entries when adding records.
- Invalidate all client/transport/DNSSEC variants for affected qname or zone.
- Ensure fingerprint state is cleared on authoritative zone mutation.
- Add mutation tests.

Acceptance criteria:

- Zone changes cannot leave stale authoritative answers in cache.
- Negative cache entries are invalidated by new records.

## Workstream 8: Docs and matrix reconciliation

Tasks:

- Update `architecture/dns_config_runtime_matrix.md` after implementation fixes.
- Mark fields as implemented only when tests exist.
- Document remaining partial items clearly.
- Keep `architecture/dns.md` consistent with the matrix.
- Add a short milestone status section listing closed, partial, and deferred items.

Acceptance criteria:

- Docs match behavior.
- No overclaiming of cache/coalescing/transport completeness.

## Final acceptance checklist

This follow-up is complete when:

- DNS compile/test baseline is recorded.
- deleted `src/dns` tree has no stale references.
- server cache paths construct full `CacheKey` dimensions from parsed query and context.
- TTL extraction is compression-safe and tested.
- coalescing key semantics are aligned with response-shaping dimensions.
- TCP lifecycle policy is documented/tested.
- authoritative cache invalidation covers zone mutations and negative entries.
- docs/matrix reflect actual support status.
