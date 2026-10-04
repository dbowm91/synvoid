# Phase 116 Closeout — DNS Runtime Configuration and Core Neutralization

Plan: `plans/phase_116_dns_runtime_config_core_neutralization.md`.
Date: 2026-10-02.
Disposition: **CLOSED DEFER**. No DNS runtime behavior or public API was changed.

## Evidence and blocker

The Phase 115 inventory captures the current package graph and sources. A source
inventory finds persisted-config ownership throughout DNS runtime modules, not
only in the top-level settings adapter:

- `DnsConfig`/`DnsMode`: `src/config.rs`, `src/server/mod.rs` and public
  re-exports in `src/mod.rs`;
- transport DTOs: DoT, DoH and DoQ modules;
- recursive provider, circuit-breaker, ECS and cache configuration: `recursive.rs`,
  `recursive_cache.rs`;
- zone records, TSIG, NOTIFY, EDNS/Geo filtering, rebinding and anycast config;
- direct persisted DTO use in constructor signatures and in extensive behavioral
  tests/fixtures.

The crate has required normal edges to `synvoid-config` and `synvoid-core`, plus
`synvoid-utils`. Removing these edges safely requires a full DNS-owned runtime
DTO set, exhaustive application-boundary adapters in the root/server composition,
golden effective-config parity for all supported TOML profiles, and differential
tests for restricted-address semantics. A partial local alias or DTO for only
`DnsSettings` would leave persisted schema in public constructors and fail the
phase contract. No complete type inventory/adapters or parity evidence was
available within this implementation pass; starting a partial conversion would
make the boundary less auditable.

## Successor status

Phase 117 is **CLOSED DEFER** because this phase's runtime-config/core
neutralization and parity prerequisite was not delivered. Do not start provider
inversion or claim standalone qualification until Phase 116 is reopened and
qualified. Phase 118, 120, 121, and 122 were independent after Phase 115. Phase
123 must carry both DNS track DEFERs into its final gate.

No persisted config meaning, DNS behavior, DNSSEC custody, or transport behavior
was changed. No standalone status is claimed for `synvoid-dns`.
