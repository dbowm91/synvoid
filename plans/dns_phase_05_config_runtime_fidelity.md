# DNS Phase 5: Config-to-Runtime Fidelity Audit

## Objective

Ensure every DNS configuration field is either implemented, explicitly documented as unsupported, or removed from production-facing configuration. The DNS subsystem currently exposes a broad configuration surface. Production readiness requires that enabled settings actually alter runtime behavior, and unsupported settings do not create a false sense of protection or capability.

## Current concerns

The DNS config surface includes authoritative mode, recursive mode, DNSSEC, DoT/DoH/DoQ, RPZ, DNS64, ECS filtering, padding, qname privacy, prefetch, serve-stale, query coalescing, dynamic update, notify, IXFR, transfer controls, rate limits, firewall controls, anycast, mesh mode, trust anchors, and cache settings. Some of these are wired; some are partially wired; some appear only as config fields or docs.

Phase 5 should produce a precise config/runtime matrix and close the high-risk gaps.

## Primary files

- `crates/synvoid-config/src/dns/mod.rs`
- `crates/synvoid-config/src/dns/dns_settings.rs`
- `crates/synvoid-config/src/dns/dns_misc.rs`
- `crates/synvoid-dns/src/server/mod.rs`
- `crates/synvoid-dns/src/server/startup.rs`
- `crates/synvoid-dns/src/cache.rs`
- `crates/synvoid-dns/src/recursive.rs`
- `crates/synvoid-dns/src/dns64.rs`
- `crates/synvoid-dns/src/edns.rs`
- `crates/synvoid-dns/src/query_coalesce.rs`
- `crates/synvoid-dns/src/query_validator.rs`
- `crates/synvoid-dns/src/firewall.rs`
- `architecture/dns.md`

## Deliverable 1: Config-runtime matrix

Create or update a document, preferably `architecture/dns.md` or a dedicated `architecture/dns_config_runtime_matrix.md`, with a table covering every DNS config field.

For each field, record:

- Config path.
- Default value.
- Runtime consumer file/function.
- Current support status: implemented, partially implemented, validation-only, documented-only, unsupported, or deprecated.
- Tests that prove behavior.
- Action required.

Example row format:

| Config path | Default | Runtime consumer | Status | Tests | Action |
| --- | --- | --- | --- | --- | --- |
| `dns.settings.serve_stale.enabled` | false | `DnsCache::with_serve_stale` | partially implemented | none | wire constructor or document unsupported |

Acceptance criteria:

- Every public DNS config field is accounted for.
- Unsupported or partially wired fields are not ambiguous.

## Workstream 1: Cache settings fidelity

Known risk: cache is created with base settings, but serve-stale and related cache policy may not be fully wired in all paths.

Tasks:

- Verify `cache_enabled`, `cache_size`, `cache_max_ttl`, `cache_min_ttl`, `negative_cache_ttl`, and serve-stale settings all reach `DnsCache` construction.
- Use `DnsCache::with_serve_stale` when configured.
- Clarify whether `cache_size` is entry count or weighted byte capacity. If moka weigher uses response length, rename or document as byte-weighted capacity.
- Verify negative responses are cached only when correct and invalidate safely.
- Add tests for min TTL, max TTL, negative TTL, and serve-stale behavior.

Acceptance criteria:

- Cache config fields have direct runtime tests.
- No cache field silently does nothing.

## Workstream 2: DNS64 config fidelity

Milestone 1 propagated DNS64 translator into standard contexts, but Phase 5 should verify full config behavior.

Tasks:

- Confirm `dns64.enabled`, prefix, fallback behavior, exclusion lists, and synthesis policy are wired.
- Ensure DNS64 only synthesizes AAAA when appropriate and never masks existing AAAA records.
- Verify DNS64 behavior differs by client IP if exclusion config applies.
- Add tests for enabled/disabled DNS64, custom prefix, excluded source, existing AAAA, and no A fallback.

Acceptance criteria:

- DNS64 config is completely tested or unsupported fields are documented.

## Workstream 3: EDNS, ECS, padding, qname privacy

Tasks:

- Verify EDNS UDP size, DO bit, cookie, ECS, and padding are parsed and applied consistently.
- Confirm ECS filtering actually removes, truncates, or preserves ECS according to config.
- Decide whether qname privacy config applies to logging, upstream recursion, or both.
- If qname privacy is only intended for logs, ensure logs use redacted qname when configured.
- If padding is configured, implement response padding for supported transports or document as deferred.

Tests:

- EDNS DO changes DNSSEC response shape where applicable.
- ECS filter config affects parsed EDNS options.
- qname privacy prevents full qname emission in logs where testable.
- Padding config either changes response size or is documented unsupported.

Acceptance criteria:

- EDNS-affecting config has deterministic behavior.
- Privacy/security config does not silently do nothing.

## Workstream 4: Query coalescing config fidelity

Phase 6 handles coalescing internals, but Phase 5 should audit config wiring.

Tasks:

- Verify query coalescing is enabled only when configured.
- Verify cleanup interval, max wait, and key dimensions are configurable or documented fixed.
- Verify metrics reflect enabled/disabled state.
- Ensure disabled coalescing bypasses all coalescer work.

Acceptance criteria:

- Query coalescing config is represented in runtime behavior and tests.

## Workstream 5: Dynamic update, notify, transfer, IXFR config

Tasks:

- Audit `dynamic_update`, `notify`, `allow_transfer`, `require_tsig`, `ixfr`, wildcard transfer, and TSIG-related config.
- Ensure update and notify handlers are only active when enabled.
- Ensure transfer handlers enforce allowlists and TSIG requirements consistently for AXFR and IXFR.
- Ensure wildcard transfer behavior is explicit and test-covered.
- Ensure IXFR fallback to AXFR is configurable and documented.

Tests:

- UPDATE disabled returns REFUSED/NOTIMP according to policy.
- NOTIFY disabled returns policy response.
- AXFR denied without allowed client.
- AXFR denied without TSIG when required.
- IXFR allowed/denied based on config.

Acceptance criteria:

- Zone-changing and zone-transfer features are never enabled accidentally.

## Workstream 6: Recursive mode isolation config

Tasks:

- Confirm authoritative and recursive modes have distinct bind addresses, listener ownership, and allow policies.
- Verify authoritative no-zone behavior is REFUSED unless recursion is explicitly enabled and client is allowed.
- Verify recursive cache and authoritative cache do not share unsafe state unless intentionally designed.
- Audit trust anchor config wiring.

Acceptance criteria:

- Recursive mode cannot become an accidental open resolver through default config.
- Authoritative path does not silently recurse unless explicitly configured.

## Workstream 7: Anycast/mesh config fidelity

Tasks:

- Verify `dns.mode`, mesh mode, and anycast config validation fail clearly when required feature gates are unavailable.
- Avoid runtime panic or misleading partial startup when anycast is enabled without mesh support.
- Document feature-gated behavior.

Acceptance criteria:

- Unsupported mesh/anycast runtime modes fail at validation or startup with clear errors.

## Workstream 8: Documentation and config comments

Tasks:

- Update docs with the config-runtime matrix.
- Mark deferred fields explicitly.
- Add examples for a safe authoritative-only profile and a safe recursive profile.
- Add warnings for dangerous features: open recursion, zone transfer, dynamic update, wildcard transfer.

## Verification commands

```bash
cargo fmt --all --check
cargo test -p synvoid-config dns
cargo test -p synvoid-dns config
cargo test -p synvoid-dns cache
cargo test -p synvoid-dns dns64
cargo check -p synvoid-dns --all-features
cargo check --workspace
```

## Completion criteria

Phase 5 is complete when every DNS config field has a known runtime status, high-risk partially wired fields are fixed or disabled, tests cover security-sensitive config behavior, and docs no longer overclaim unsupported features.
