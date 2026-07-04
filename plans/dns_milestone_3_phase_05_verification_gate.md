# DNS Milestone 3 Phase 5: Advanced DNS Feature Verification Gate

## Objective

Create a hard verification gate for DNS Milestone 3. This phase closes the advanced DNS feature layer only after zone lifecycle/transfer/update/NOTIFY, DNSSEC correctness, encrypted transports, and recursive isolation have been tested, documented, and bounded by explicit deferrals.

## Scope

This is a verification and release-gate phase. It should not add new feature scope except to fix defects discovered by the gate.

## Gate areas

1. Zone lifecycle and mutation safety.
2. AXFR/IXFR/NOTIFY/UPDATE authorization and atomicity.
3. DNSSEC signing, denial proof, key lifecycle, and AD/CD boundaries.
4. DoT/DoH/DoQ adapter correctness.
5. Recursive resolver safety and isolation.
6. Cache/coalescing behavior under advanced features.
7. Config matrix and docs accuracy.
8. CI coverage and command baseline.

## Gate 1: Command baseline

Required commands:

```bash
cargo fmt --all --check
cargo test -p synvoid-config dns
cargo test -p synvoid-dns
cargo check -p synvoid-dns --all-features
cargo check --workspace
```

Targeted commands:

```bash
cargo test -p synvoid-dns update
cargo test -p synvoid-dns notify
cargo test -p synvoid-dns transfer
cargo test -p synvoid-dns zone
cargo test -p synvoid-dns dnssec
cargo test -p synvoid-dns dnssec_signing
cargo test -p synvoid-dns dnssec_validation
cargo test -p synvoid-dns dot
cargo test -p synvoid-dns doh
cargo test -p synvoid-dns doq
cargo test -p synvoid-dns recursive
cargo test -p synvoid-dns recursive_cache
cargo test -p synvoid-dns dns_recursive_isolation
```

Acceptance criteria:

- all DNS-specific tests/checks pass;
- workspace failures, if any, are classified and unrelated to DNS;
- CI includes DNS-specific test coverage from the housekeeping pass.

## Gate 2: Zone lifecycle/mutation safety

Verify:

- zone load/reload is atomic;
- invalid reload cannot expose half-loaded zone;
- SOA is required and serial policy is RFC 1982-aware;
- UPDATE is disabled by default and authorized when enabled;
- NOTIFY is disabled or source-checked by default;
- AXFR/IXFR are disabled or authorized by default;
- TSIG requirements are enforced consistently;
- store write failures cannot silently acknowledge durable mutation;
- all zone mutations invalidate cache variants.

Acceptance criteria:

- authoritative zone data cannot be corrupted or leaked by mutation/transfer paths.

## Gate 3: DNSSEC correctness

Verify:

- authoritative signed responses include correct DNSSEC records only under intended DO/policy behavior;
- AD is never set just because local authoritative data is signed;
- DNSKEY/DS/RRSIG output has known-vector or external-tool verification;
- NSEC proofs are correct for supported NODATA/NXDOMAIN cases;
- NSEC3 support is either correct for supported cases or explicitly deferred/non-production;
- KSK/ZSK lifecycle and rollover behavior is deterministic;
- DNSSEC key/signature changes invalidate cache variants;
- recursive validation status and AD/CD behavior are documented.

Acceptance criteria:

- DNSSEC claims are backed by tests or explicitly deferred.

## Gate 4: Encrypted transport adapters

Verify:

- DoT preserves DNS-over-TCP framing and TLS config is fail-fast;
- DoH enforces HTTP method/content-type/body-size policy;
- DoQ support is tested or explicitly experimental/deferred;
- all encrypted transports pass accurate transport class into cache/coalescing;
- rate limit/firewall/client identity behavior is consistent;
- shutdown drains listeners and active tasks;
- per-transport metrics/logs exist.

Acceptance criteria:

- encrypted transports cannot bypass core DNS policy or corrupt cache/coalescing semantics.

## Gate 5: Recursive resolver safety

Verify:

- recursive mode is disabled by default;
- recursive listener defaults are safe;
- allow policy prevents open resolver deployment;
- authoritative/recursive routing is deterministic;
- recursive cache cannot collide with authoritative cache;
- upstream resolver retries/timeouts/concurrency are bounded;
- bailiwick and additional-section poisoning controls exist;
- ECS/QNAME privacy behavior is documented and safe by default;
- AD/CD semantics are safe or disabled.

Acceptance criteria:

- recursive mode is suitable for controlled deployment profiles and cannot become open by accident.

## Gate 6: Cache and coalescing under advanced features

Verify:

- zone mutation invalidates positive, negative, DNSSEC, client-specific, and transport-specific cache variants;
- transfer/update/notify are excluded from coalescing;
- encrypted transport classes isolate cache shapes where needed;
- recursive namespace remains separate;
- DNSSEC DO/CD/AD-shaped answers do not collide;
- stale data is not served after authoritative mutation.

Acceptance criteria:

- advanced features do not break the Milestone 2 cache/coalescing invariants.

## Gate 7: Config matrix and docs audit

Review:

- `architecture/dns.md`
- `architecture/dns_config_runtime_matrix.md`
- `architecture/dns_deep_dive.md`
- DNSSEC docs/ADRs
- encrypted transport docs
- recursive docs
- AGENTS and skill files

Verify:

- every implemented feature is accurately marked;
- every partial/deferred feature is visible;
- no doc claims production readiness beyond tested behavior;
- example configs are safe by default;
- operator warnings exist for recursion, transfer, update, anycast/mesh, and DNSSEC limitations.

Acceptance criteria:

- docs are accurate enough for operator use and future agent handoff.

## Gate 8: External interoperability smoke tests

Where local tooling permits, run or document:

```bash
dig @127.0.0.1 -p <port> example.test A
dig +dnssec @127.0.0.1 -p <port> example.test A
dig @127.0.0.1 -p <port> example.test AXFR
kdig +tls @127.0.0.1 -p <dot-port> example.test A
curl -H 'content-type: application/dns-message' --data-binary @query.bin https://127.0.0.1:<doh-port>/dns-query
ldns-verify-zone <zonefile>
named-checkzone <origin> <zonefile>
```

If tools are unavailable in CI, add a documented local smoke script.

Acceptance criteria:

- at least one external DNS interoperability path is documented for each supported advanced feature category.

## Final Milestone 3 close criteria

Milestone 3 can close when:

- DNS-specific command baseline passes.
- CI runs DNS-specific tests.
- zone mutation/transfer/update/notify paths are atomic and authorized.
- DNSSEC status is accurate, tested, and externally smoke-verified where feasible.
- encrypted transports preserve core DNS semantics.
- recursive mode is safe and isolated.
- cache/coalescing invariants hold under advanced features.
- docs/config matrix match implementation.
- remaining limitations are explicit deferrals.

## Expected deferrals after Milestone 3

These may remain for later production hardening:

- high-scale DNS performance/load testing;
- broad RFC conformance suite;
- advanced anycast/mesh DNS deployment validation;
- HSM-backed production key ceremony;
- complete recursive resolver parity with mature resolvers;
- complete NSEC3 closest-encloser proof coverage if not finished;
- automated external-tool conformance in CI if tooling is unavailable.
