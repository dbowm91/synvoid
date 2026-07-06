# DNS Milestone 3 Corrective Semantics Pass

## Context

The first Milestone 3 implementation pass moved the DNS subsystem substantially forward. It added DNS CI coverage, zone lifecycle state and health metadata, SOA validation helpers, serial history/recency helpers, DNSSEC key lifecycle scaffolding, recursive resolver safety machinery, encrypted transport tests, a large verification-gate test suite, and expanded DNS architecture/config documentation.

However, several changes are currently closer to scaffolding or documentation-grade tests than enforceable production semantics. The next pass should convert these into hard behavior. This is a corrective pass over the current Milestone 3 implementation, not a new feature expansion.

## Objective

Tighten Milestone 3 implementation so its tests prove the desired invariants rather than merely documenting current behavior. The main goal is to make failed zone reloads, invalid-zone rejection, mutation authorization, DNSSEC correctness, encrypted transport behavior, and CI visibility enforceable.

## Non-goals

Do not expand into broad resolver parity, performance benchmarking, HSM production ceremony, complete NSEC3 closest-encloser coverage, or anycast/mesh DNS deployment validation. Only fix correctness gaps discovered in the first Milestone 3 pass.

## Current strengths to preserve

- Dedicated DNS CI job now exists.
- Zone lifecycle state model exists.
- Zone health metadata exists.
- Serial history and RFC1982-style comparison helpers exist.
- Single-apex-SOA validation helper exists.
- DNSSEC key manager has active/standby KSK/ZSK and rollover state scaffolding.
- Recursive server now has cache, rate limiter/firewall hooks, metrics, circuit breaker, global concurrency semaphore, and per-client semaphores.
- Encrypted transport test surface exists.
- Verification-gate tests provide broad coverage scaffolding.

## Workstream 1: CI status and DNS job hardening

Problem: the workflow now includes DNS tests, but remote status was not visible through the connector, and the DNS job does not yet include all new Milestone 3 integration suites.

Tasks:

- Confirm GitHub Actions runs for pushes to `main` and PRs.
- Confirm the new `dns-tests` job executes and passes.
- Add newly introduced integration tests to the DNS CI job:
  - `cargo test -p synvoid-dns --test encrypted_transport --release`
  - `cargo test -p synvoid-dns --test verification_gate --release`
- Decide whether to run `cargo check -p synvoid-dns --all-features` inside `dns-tests`; prefer adding it.
- Confirm DNS CI remains independent enough that unrelated workspace failures do not obscure DNS signal.
- If status checks remain absent, document why and add a follow-up issue/plan for repository settings.

Acceptance criteria:

- DNS CI job runs all Milestone 2 and Milestone 3 DNS suites.
- DNS CI includes all-features check.
- DNS pass/fail can be observed from GitHub Actions.

## Workstream 2: Failed reload semantics must preserve old zone

Problem: the current `zone_load_reload_is_atomic` test proves atomic replacement, not failed-reload preservation. A corrupt or invalid reload should not replace a valid active zone unless the configured policy explicitly says fail-closed.

Tasks:

- Introduce a `validate_zone_for_activation` helper that checks:
  - exactly one apex SOA;
  - valid origin normalization;
  - records parse/encode cleanly where applicable;
  - DNSSEC prerequisites when DNSSEC is enabled;
  - transfer/update policy requirements if mutation source is external.
- Add an atomic reload helper at the server/store boundary:
  - validate candidate zone before swap;
  - on success, swap active zone and mark active;
  - on failure, preserve previous active zone and record health error;
  - optionally mark previous zone degraded if policy requires warning.
- Avoid letting raw `ShardedZoneStore::insert` be the high-level reload API for externally loaded or transferred zones.
- Keep low-level insert available only for already-validated zones or tests.

Required tests:

- valid active zone remains active after invalid reload candidate.
- invalid reload candidate records failure metadata.
- valid reload swaps zone atomically.
- failed reload does not invalidate cache for unchanged active zone unless policy says otherwise.
- fail-closed policy, if present, disables active zone instead of preserving it.

Acceptance criteria:

- failed reload preservation is implemented and tested as behavior, not just documented.

## Workstream 3: Invalid-zone rejection at load/store boundary

Problem: current tests show that a zone without SOA can be inserted into `ShardedZoneStore`, then rely on higher-level validation. That is acceptable for a raw map, but production load/update/transfer APIs must not silently accept invalid authoritative zones.

Tasks:

- Clearly separate raw store operations from validated load operations.
- Add `insert_validated_zone` or equivalent that rejects invalid zones before publication.
- Ensure config zone load uses validated insertion.
- Ensure store reload uses validated insertion.
- Ensure AXFR/IXFR apply path uses validated insertion.
- Ensure dynamic update revalidates affected invariants before committing.
- Ensure invalid zones can be represented only as failed candidate state, not active serving state.

Required tests:

- config load rejects no-SOA zone.
- config load rejects multiple apex SOA zone.
- transfer apply rejects no-SOA zone.
- transfer apply rejects multiple SOA zone.
- dynamic update that removes final SOA is refused.
- dynamic update that creates duplicate SOA is refused.

Acceptance criteria:

- invalid zones cannot become active via any production path.

## Workstream 4: UPDATE, NOTIFY, AXFR, and IXFR authorization tests

Problem: code changed in update/notify/transfer paths, but the current inspected tests do not yet prove end-to-end authorization behavior.

Tasks:

- Audit default config for UPDATE, NOTIFY, AXFR, and IXFR; confirm all are disabled or deny-by-default.
- Add tests for each disabled default path.
- Add allowlist tests for each enabled path.
- Add TSIG-required tests where supported.
- Ensure malformed control-plane messages return deterministic response policy and cannot mutate state.
- Ensure every accepted mutation invalidates cache variants.
- Ensure AXFR/IXFR bypass ordinary cache and coalescing paths.

Required tests:

- UPDATE disabled refuses mutation.
- UPDATE unauthorized client refused.
- UPDATE invalid/missing TSIG refused when required.
- UPDATE prerequisite failure leaves zone unchanged.
- NOTIFY disabled ignored/refused according to policy.
- NOTIFY unauthorized source ignored/refused.
- AXFR denied by default.
- AXFR allowed client gets complete SOA-bracketed transfer.
- IXFR denied by default.
- IXFR serial-current request returns no-op/deterministic response.
- IXFR too-old serial falls back/refuses according to config.

Acceptance criteria:

- mutation and transfer paths are deny-by-default, authorized when enabled, and cache-safe.

## Workstream 5: DNSSEC correctness beyond key scaffolding

Problem: key manager scaffolding is stronger, but production DNSSEC correctness requires canonicalization, DS owner-name context, RRSIG semantics, denial proofs, AD/CD boundaries, and external verification.

Tasks:

- Add known-vector tests for DNSKEY key tag and DS digest generation. DS digest must include canonical owner name plus DNSKEY RDATA per DNSSEC rules; verify current `generate_cds_record` behavior is not mistaken for full parent DS generation if owner name is absent.
- Verify DNSKEY flags: KSK=257, ZSK=256, protocol=3.
- Verify RRSIG original TTL, labels, inception, expiration, algorithm, key tag, and signer name.
- Verify canonical RRset ordering and canonical name casing.
- Verify DO=true signed response includes RRSIG; DO=false omits DNSSEC extras unless explicitly requested.
- Verify authoritative responses never set AD merely because locally signed.
- Verify NSEC NODATA and NXDOMAIN proofs for supported cases.
- Mark NSEC3 production support as deferred unless closest-encloser/opt-out semantics are fully tested.

External smoke target where available:

```bash
dig +dnssec @127.0.0.1 -p <port> example.test A
ldns-verify-zone <zonefile>
named-checkzone <origin> <zonefile>
```

Acceptance criteria:

- DNSSEC tests prove protocol semantics, not only key object lifecycle.
- unsupported DNSSEC features are explicitly deferred in docs/config matrix.

## Workstream 6: Encrypted transport adapter proof

Problem: encrypted transport tests now exist, but each adapter must be proven to preserve the same core DNS semantics as UDP/TCP.

Tasks:

- Inspect `encrypted_transport.rs` and split tests by adapter if needed.
- Confirm DoT uses DNS-over-TCP framing and either matches one-query TCP policy or documents persistent behavior if implemented.
- Confirm DoH POST enforces `application/dns-message` and returns DNS wire body with correct content type.
- Confirm DoH GET support is tested if supported, or rejected/documented if not.
- Confirm DoQ support is either tested against the actual adapter or explicitly marked experimental/deferred.
- Confirm each adapter passes accurate `TransportClass` into cache/coalescing paths.
- Confirm firewall/rate limit/client identity policy is applied consistently.
- Confirm malformed/oversized requests fail with deterministic transport-appropriate errors.

Required tests:

- DoT valid query response.
- DoT malformed length prefix rejected.
- DoH POST valid query response.
- DoH wrong content type rejected.
- DoH oversized body rejected.
- DoQ valid query response or explicit deferred test.
- encrypted transport cache key isolation from UDP512/TCP where response shape differs.
- encrypted transport firewall/rate-limit path.

Acceptance criteria:

- encrypted adapters are proven thin wrappers over core DNS policy, not independent semantics forks.

## Workstream 7: Recursive resolver safety proof

Problem: recursive safety machinery exists, but more tests should prove open-resolver prevention, bailiwick behavior, upstream bounds, AD/CD policy, and cache separation.

Tasks:

- Confirm recursive mode disabled by default in config tests.
- Confirm unsafe bind/allow-all recursive profiles fail validation unless explicit override exists.
- Confirm authoritative no-zone behavior remains REFUSED when recursion disabled.
- Confirm recursion path is selected only when enabled and client allowed.
- Add upstream timeout/retry/concurrency tests using mock resolver.
- Add CNAME depth/loop tests.
- Add bailiwick/additional-section poisoning tests if recursive cache stores authority/additional data.
- Confirm ECS is not forwarded by default.
- Confirm AD only set for validated recursive data; otherwise disabled.

Acceptance criteria:

- recursive mode cannot become an open resolver accidentally and cannot poison authoritative/cache state.

## Workstream 8: Verification-gate tests should assert intended behavior

Problem: parts of `verification_gate.rs` currently document gaps or assert current raw-store behavior rather than enforcing production invariants.

Tasks:

- Rename tests that are only documentation to make them explicit, or replace them with enforceable behavior tests.
- Replace `zone_load_reload_is_atomic` with separate tests:
  - successful reload swaps atomically;
  - failed reload preserves previous active zone.
- Replace `store_write_failure_cannot_silently_acknowledge` with a validated-load test that actually rejects invalid zones.
- Ensure every verification-gate test has one clear invariant and fails if production semantics regress.
- Avoid tests that pass while acknowledging a gap unless marked `#[ignore]` with a tracking note.

Acceptance criteria:

- verification-gate tests are release gates, not commentary.

## Workstream 9: Documentation and matrix reconciliation

Tasks:

- Update `architecture/dns.md`, `architecture/dns_config_runtime_matrix.md`, and `architecture/dns_zone_lifecycle.md` after semantic fixes.
- Mark zone lifecycle/update/transfer/DNSSEC/encrypted transport/recursive rows accurately.
- Document any intentionally deferred behavior:
  - persistent DNS-over-TCP if still deferred;
  - EDNS keepalive if still unwired;
  - full NSEC3 closest-encloser proofs;
  - DoQ if experimental;
  - recursive validation limitations;
  - external DNSSEC tooling not available in CI.
- Ensure docs do not overclaim production DNSSEC or recursive parity.

Acceptance criteria:

- docs and config matrix describe implemented semantics, not desired future behavior.

## Workstream 10: Final verification record

Run and record:

```bash
cargo fmt --all --check
cargo test -p synvoid-config dns
cargo test -p synvoid-dns
cargo test -p synvoid-dns --test encrypted_transport
cargo test -p synvoid-dns --test verification_gate
cargo check -p synvoid-dns --all-features
cargo check --workspace
```

If CI is available, record the GitHub Actions status for the DNS job.

Acceptance criteria:

- DNS-specific checks pass locally and in CI.
- any workspace-only failures are classified.
- final verification record lists remaining deferrals.

## Completion criteria

This corrective pass is complete when:

- DNS CI includes Milestone 3 tests and all-features check.
- failed reload preservation is implemented and tested.
- invalid zones cannot become active through production paths.
- UPDATE/NOTIFY/AXFR/IXFR authorization behavior is tested end-to-end.
- DNSSEC semantics have known-vector and response-shape tests beyond key scaffolding.
- encrypted transports are proven to preserve core DNS policy or explicitly deferred.
- recursive resolver safety is proven by behavior tests.
- verification-gate tests assert intended behavior rather than documenting gaps.
- docs/config matrix match implementation.
