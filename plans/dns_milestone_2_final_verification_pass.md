# DNS Milestone 2 Final Verification Pass

## Context

The DNS Milestone 2 implementation is now broad and materially improved. Recent commits added full parsed-query cache-key construction, compression-aware TTL extraction, coalescing key dimensions with transport/namespace, unsafe coalescing exclusions, TCP hard-limit SERVFAIL shaping, transport lifecycle tests, config-matrix updates, recursive-isolation tests, and substantial documentation updates.

This final verification pass is deliberately narrow. It is not a feature pass. Its purpose is to prove the current implementation is stable, catch test flakiness, ensure docs match behavior, and leave a clear handoff record before moving to later DNSSEC, recursive, DoT/DoH/DoQ, RPZ, or performance work.

## Objective

Establish that DNS Milestone 2 is ready to close or identify the exact remaining corrective items blocking closure.

## Non-goals

Do not expand scope into:

- full DNSSEC production validation;
- NSEC3 closest-encloser correctness;
- persistent DNS-over-TCP implementation unless current documented behavior contradicts tests;
- DoT/DoH/DoQ conformance;
- RPZ expansion;
- recursive resolver feature expansion;
- performance/load benchmarking;
- new public DNS features.

## Current state to verify

The verification pass should assume the following are intended current properties:

- `crates/synvoid-dns` is the canonical DNS implementation.
- The legacy `src/dns/*` implementation tree has been removed.
- Cache keys are derived from parsed query and runtime transport context.
- Cache key dimensions include qname, qtype, qclass, DO/DNSSEC, client identity/subnet, transport class, and namespace.
- TTL extraction is compression-aware and uses minimum positive answer TTL.
- Negative TTL extraction uses SOA authority data and avoids caching SERVFAIL/REFUSED.
- Query coalescing excludes AXFR, IXFR, NOTIFY, and UPDATE.
- Query coalescing key dimensions include transport class and namespace.
- TCP oversized responses produce a length-prefixed SERVFAIL shaped from the parsed question when possible.
- Transport lifecycle has start/stop and port-reuse tests.
- Config-runtime matrix exists and is intended to match current behavior.

## Workstream 1: Required command baseline

Run these commands from a clean checkout:

```bash
cargo fmt --all --check
cargo test -p synvoid-config dns
cargo test -p synvoid-dns
cargo check -p synvoid-dns --all-features
cargo check --workspace
```

If any command fails:

1. Capture the exact command and first failing error.
2. Classify as DNS-related, workspace unrelated, flaky, or tooling/environmental.
3. Fix DNS-related failures in this pass.
4. Do not mark Milestone 2 closed while `synvoid-dns` tests or all-features check fail.
5. If workspace failures are unrelated, document the crate and failure class in the verification notes.

Acceptance criteria:

- All DNS-specific commands pass.
- Workspace status is either passing or explicitly documented.
- The final commit or handoff note includes command results.

## Workstream 2: CI workflow verification

Recent commits touched `.github/workflows/ci.yml`; the remote status surface must be checked.

Tasks:

- Inspect `.github/workflows/ci.yml` for crate names, feature flags, workspace command correctness, and path assumptions after deleting `src/dns`.
- Confirm the workflow does not reference deleted paths.
- Confirm the workflow exercises `synvoid-dns` and `synvoid-config dns` tests.
- If GitHub status checks are absent, document whether this is expected for the repo or whether CI is not running on direct pushes.
- If workflow runs are available, inspect failed jobs and fix DNS-related failures.

Acceptance criteria:

- CI workflow matches the current workspace layout.
- DNS-specific verification is represented in CI or an explicit follow-up is recorded.

## Workstream 3: Deleted DNS tree audit

Tasks:

Run searches:

```bash
rg "src/dns" .
rg "crate::dns" .
rg "mod dns" .
rg "dns/server" .
rg "AGENTS.override" .
```

Review hits manually.

Expected result:

- Documentation may mention the historical deletion, but no compiled source should depend on `src/dns`.
- Agent instructions should point to `crates/synvoid-dns`.
- No tests or examples should import deleted modules.

Acceptance criteria:

- One canonical implementation path remains.
- Any stale doc reference is corrected.

## Workstream 4: Cache integration verification

Tasks:

- Review all callers of `handle_query_with_cache` and `handle_parsed_query_with_cache`.
- Confirm every production caller supplies an accurate `TransportClass`.
- Confirm UDP no-EDNS uses `Udp512`.
- Confirm UDP with EDNS uses `UdpEdns(size)`.
- Confirm TCP uses `Tcp`.
- Confirm DoT, DoH, and DoQ paths either pass correct transport classes or are documented as deferred/untested.
- Confirm recursive paths use recursive namespace when cached.
- Confirm client identity/ECS handling is deliberately safe even if cache hit rate is reduced.

Required tests to add or confirm:

- DO=false and DO=true do not collide.
- qclass differs -> cache miss.
- UDP512 and TCP do not collide.
- UDP512 and UDP EDNS large-buffer do not collide when response shape differs.
- authoritative and recursive namespaces do not collide.
- missing client IP fallback does not cross-contaminate real client-specific entries.

Acceptance criteria:

- Full cache key dimensions are used in server paths, not just unit constructors.
- Cache safety is prioritized over hit rate.

## Workstream 5: TTL and negative caching verification

Tasks:

- Review `skip_dns_name`, `skip_header_and_question`, `skip_rr_safe`, positive TTL extraction, and negative SOA TTL extraction.
- Confirm compression pointers are safely skipped and do not cause loops.
- Confirm malformed labels/pointers return no-cache behavior.
- Confirm minimum TTL across all answers is used for positive responses.
- Confirm negative TTL uses `min(SOA TTL, SOA MINIMUM, configured_negative_cache_ttl)`.
- Confirm SERVFAIL and REFUSED return TTL 0.
- Re-check NXDOMAIN without SOA fallback. If production authoritative responses should never lack SOA, prefer TTL 0 or fail-closed rather than caching bare NXDOMAIN.

Required tests to add or confirm:

- compressed answer owner TTL extraction.
- multiple answers use minimum TTL.
- malformed pointer returns TTL 0.
- NODATA with SOA uses expected TTL.
- NXDOMAIN with SOA uses expected TTL.
- SERVFAIL TTL 0.
- REFUSED TTL 0.
- bare NXDOMAIN without SOA behavior is explicitly tested and documented.

Acceptance criteria:

- Cache insertion cannot be driven by malformed TTL parsing.
- Negative cache behavior matches the documented policy.

## Workstream 6: Query coalescing verification

Tasks:

- Review `should_skip_coalescing` use at all server call sites.
- Confirm AXFR, IXFR, NOTIFY, UPDATE, and malformed queries bypass coalescing.
- Confirm cookie challenge/error behavior is either included in key dimensions or bypasses coalescing.
- Confirm coalescing key transport and namespace match cache-key semantics.
- Confirm metrics use counters for totals and gauge only for in-flight.
- Confirm owner/waiter behavior is concurrency-tested.

Required tests to add or confirm:

- one owner, one waiter receives response.
- one owner, many waiters receive response.
- owner cancellation cleans up key.
- waiter timeout increments metric and does not wedge key.
- stale cleanup removes expired entries.
- AXFR/IXFR bypass coalescing.
- UPDATE/NOTIFY bypass coalescing.
- transport/DO/qclass/client/namespace differences produce distinct keys.

Acceptance criteria:

- Coalescing is safe to enable under documented conditions.
- No stateful or multi-message DNS operation is coalesced.

## Workstream 7: Transport lifecycle and flake hardening

The new `transport_lifecycle.rs` tests are valuable but use timing and ephemeral port reuse. Verify they are reliable in CI-like conditions.

Tasks:

- Run transport lifecycle tests repeatedly:

```bash
for i in {1..10}; do cargo test -p synvoid-dns --test transport_lifecycle || break; done
```

- Replace fixed sleeps with readiness signals or bounded retry where feasible.
- If direct readiness signaling is not practical, use short retry loops with deadlines for port availability.
- Confirm TCP and UDP tasks actually observe shutdown before port-reuse assertions.
- Confirm coalescer cleanup task exits on shutdown watcher.
- Confirm shutdown before start and repeated shutdown remain panic-free.

Acceptance criteria:

- Transport lifecycle tests are not flaky under repeated local runs.
- Port reuse assertions are robust enough for CI.

## Workstream 8: TCP policy verification

Tasks:

- Confirm whether TCP is intentionally one-query-per-connection or persistent.
- Ensure docs state the current behavior accurately.
- If one-query TCP is retained, add or confirm a test that asserts one-query behavior.
- If docs claim persistent TCP, either implement it or correct docs.
- Confirm oversized TCP SERVFAIL preserves ID, RD, question section when parsed, RA=false, AD=false, and valid length prefix.

Acceptance criteria:

- TCP behavior is intentional, tested, and documented.
- TCP hard-limit response shape is protocol-valid.

## Workstream 9: Config matrix and docs audit

Review these files:

- `architecture/dns.md`
- `architecture/dns_config_runtime_matrix.md`
- `architecture/dns_deep_dive.md`
- `.opencode/skills/dns_dnssec/SKILL.md`
- `crates/synvoid-dns/AGENTS.override.md`
- `AGENTS.md`
- relevant DNS docs under `docs/`

Tasks:

- Ensure implemented/partial/deferred status matches code.
- Ensure no doc claims full DNSSEC production readiness.
- Ensure recursive default safety is accurately described.
- Ensure cache/coalescing/transport claims are backed by tests.
- Ensure qname privacy, ECS, DNS64, padding, prefetch, update, notify, transfer, anycast, mesh, and trust-anchor rows are accurate.

Acceptance criteria:

- Docs are an accurate operator/agent guide, not aspirational marketing.

## Workstream 10: Recursive isolation and safe defaults

Tasks:

- Run and inspect recursive isolation tests.
- Verify default config is not an open resolver.
- Verify authoritative no-zone behavior remains REFUSED.
- Verify recursion requires explicit enablement and allow policy.
- Verify trust-anchor config status in matrix.
- Confirm recursive cache namespace does not satisfy authoritative cache lookups.

Acceptance criteria:

- Recursive functionality cannot accidentally change authoritative default safety posture.

## Workstream 11: Final handoff note

At the end of the pass, update either `architecture/dns.md`, `architecture/dns_config_runtime_matrix.md`, or a short plan-completion note with:

- commands run;
- pass/fail status;
- fixes made;
- any unrelated workspace failures;
- known deferred items;
- whether Milestone 2 is considered closed.

## Closure criteria

Milestone 2 verification is complete when:

- DNS-specific tests/checks pass.
- CI workflow is consistent with current repo layout.
- deleted `src/dns` tree has no stale compiled references.
- cache key construction is fully integrated and tested.
- TTL/negative caching behavior is compression-safe and documented.
- coalescing key/lifecycle policy is tested and safe.
- transport lifecycle tests are stable under repeated runs.
- TCP policy is explicit.
- recursive defaults remain safe.
- docs and matrix match implementation.

## Expected remaining deferrals after successful verification

These should remain deferred unless tests reveal direct regressions:

- full DNSSEC production validation;
- NSEC3 closest-encloser correctness;
- persistent DNS-over-TCP, if intentionally deferred;
- DoT/DoH/DoQ conformance suite;
- RPZ policy expansion;
- large-scale performance/load tests;
- recursive resolver feature expansion;
- DNSSEC key rollover and HSM production workflows.
