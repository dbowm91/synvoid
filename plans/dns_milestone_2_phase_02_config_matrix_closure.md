# DNS Milestone 2 Phase 2: Config Matrix Closure

## Objective

Close the gap between the new DNS config-runtime matrix and actual runtime/test coverage. The first implementation pass added `architecture/dns_config_runtime_matrix.md` and config-fidelity tests, but the matrix should now become an enforceable engineering artifact: every implemented row needs tests, every partial row needs an owner action, and every unsupported row needs explicit docs or validation.

## Current state

Already improved:

- config-runtime matrix exists;
- cache serve-stale/min/max TTL/max-entry-size tests exist;
- DNS64 enabled/disabled/custom prefix/exclusion tests exist;
- ECS filter tests exist;
- recursive isolation tests were added;
- firewall config validation gained additional changes.

Still requiring closure:

- matrix status must match current code exactly;
- server constructors must use full config values consistently;
- qname privacy, padding, prefetch, transfer/update/notify, recursive, anycast/mesh, and trust-anchor rows need stronger classification;
- tests should prove security-sensitive defaults.

## Primary files

- `architecture/dns_config_runtime_matrix.md`
- `architecture/dns.md`
- `crates/synvoid-config/src/dns/*`
- `crates/synvoid-dns/src/server/mod.rs`
- `crates/synvoid-dns/src/server/startup.rs`
- `crates/synvoid-dns/src/cache.rs`
- `crates/synvoid-dns/src/dns64.rs`
- `crates/synvoid-dns/src/edns.rs`
- `crates/synvoid-dns/src/update.rs`
- `crates/synvoid-dns/src/notify.rs`
- `crates/synvoid-dns/src/transfer.rs`
- `crates/synvoid-dns/tests/dns_config_fidelity.rs`
- `crates/synvoid-dns/tests/dns_recursive_isolation.rs`

## Workstream 1: Matrix reconciliation

Tasks:

- Re-read every row in `architecture/dns_config_runtime_matrix.md`.
- For each row, verify the runtime consumer exists and is current.
- Change status to one of:
  - implemented and tested;
  - implemented but untested;
  - partially implemented;
  - validation-only;
  - documented-only;
  - unsupported/fail-fast;
  - deferred.
- Add a `Next action` column if not already present.
- Ensure docs do not mark untested behavior as production-ready.

Acceptance criteria:

- Matrix is accurate at the current commit.
- No config row has ambiguous status.

## Workstream 2: Cache and serve-stale config closure

Tasks:

- Verify `DnsServer::new` uses `DnsCache::with_serve_stale` when serve-stale config is enabled.
- Confirm configured stale window is passed through.
- Clarify `cache_size` semantics: weighted byte capacity versus entry count.
- Update config comments/docs if capacity is weighted by response size.
- Add test that `DnsServer::new` constructs a serve-stale-enabled cache from config, not only direct `DnsCache::with_serve_stale`.

Acceptance criteria:

- serve-stale config is wired through server construction.
- capacity semantics are documented.

## Workstream 3: DNS64/ECS/qname privacy/padding closure

Tasks:

- Verify runtime DNS64 config maps all config fields into `Dns64Translator`.
- Verify ECS filtering is applied on all relevant handler paths.
- Decide qname privacy scope: logs only, upstream recursion, metrics, or all of the above.
- Add qname privacy tests where feasible, or mark as deferred if testability requires log-capture infra.
- Decide padding support scope by transport.
- If padding is not implemented, mark config as deferred or fail validation when enabled.

Acceptance criteria:

- Privacy/security knobs do not silently do nothing.
- matrix clearly identifies implemented and deferred privacy controls.

## Workstream 4: Zone mutation feature flags

Tasks:

- Audit dynamic update, notify, AXFR, IXFR, wildcard transfer, and TSIG config.
- Ensure handlers are not active when the feature is disabled.
- Ensure failure response policy is deterministic: REFUSED, NOTIMP, FORMERR, or drop.
- Add tests for disabled UPDATE/NOTIFY/AXFR/IXFR.
- Add tests for TSIG-required transfer denial.

Acceptance criteria:

- zone mutation and transfer features cannot be enabled accidentally.
- matrix rows for update/notify/transfer are supported by tests.

## Workstream 5: Recursive safety config

Tasks:

- Verify recursive mode is opt-in.
- Verify authoritative no-zone remains REFUSED unless recursion is enabled and client is allowed.
- Ensure recursive bind address/port are separate from authoritative defaults.
- Audit trust-anchor config wiring and validation.
- Ensure default config cannot create an open resolver.

Tests:

- default config recursive disabled;
- no-zone authoritative response REFUSED;
- recursive enabled but client not allowed -> REFUSED;
- recursive enabled and client allowed -> recursive path selected where supported;
- trust-anchor invalid config fails validation.

Acceptance criteria:

- recursive config is safe by default and tested.

## Workstream 6: Anycast/mesh fail-fast behavior

Tasks:

- Verify anycast enabled without mesh feature fails during validation or startup with clear error.
- Verify mesh DNS mode without required feature gate fails clearly.
- Update docs/matrix to avoid claiming feature availability in extracted DNS crate.

Acceptance criteria:

- unsupported deployment modes fail clearly.

## Verification commands

```bash
cargo fmt --all --check
cargo test -p synvoid-config dns
cargo test -p synvoid-dns dns_config_fidelity
cargo test -p synvoid-dns dns_recursive_isolation
cargo test -p synvoid-dns
cargo check -p synvoid-dns --all-features
cargo check --workspace
```

## Completion criteria

Phase 2 is complete when the matrix exactly matches behavior, high-risk config rows are tested, privacy/security knobs are not silent no-ops, and defaults remain safe for authoritative-only operation.
