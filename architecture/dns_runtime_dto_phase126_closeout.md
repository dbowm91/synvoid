# Phase 126 Closeout — DNS Authoritative and Encrypted-Transport Runtime Cutover

Date: 2026-10-04.
Plan: `plans/phase_126_dns_authoritative_runtime_cutover.md`.
Campaign: `plans/dns_runtime_dto_conversion_roadmap.md`.
Predecessor: Phase 125 `CLOSED QUALIFIED`
(`architecture/dns_runtime_dto_phase125_closeout.md`).
Disposition: **CLOSED QUALIFIED**. Phase 127 is unblocked.

## What was delivered

The canonical `DnsServer` constructor and the DoT/DoH/DoQ transports now consume
DNS-owned runtime values only. The persisted `DnsConfig` no longer reaches
authoritative production code.

```rust
// Before
pub fn new(config: DnsConfig, cert_resolver: Option<Arc<CertResolver>>) -> Self

// After
pub fn new(
    authoritative: AuthoritativeRuntimeConfig,
    deferred: DeferredDnsConfig,
    cert_resolver: Option<Arc<CertResolver>>,
) -> Self
```

| Workstream | Deliverable | Location |
|---|---|---|
| A — authoritative cutover | `authoritative: Arc<AuthoritativeRuntimeConfig>` replaces `config: Arc<DnsConfig>`; cache, limits, rate limit, RRL, firewall, ECS, coalescing, DNS64, TTL, transfer, update, anycast all read runtime values | `crates/synvoid-dns/src/server/mod.rs`, `server/startup.rs`, `server/zone.rs`, `server/dnssec_impl.rs` |
| B — transport cutover | `DotServer`/`DohServer`/`DoqServer` take `DotRuntimeConfig`/`DohRuntimeConfig`/`DoqRuntimeConfig`; `DnsServerConfig` yields a typed `Option<SocketAddr>`; `SecureDnsServerBase::start_server` takes a `SocketAddr` | `dot.rs`, `doh.rs`, `doq.rs`, `secure_server.rs` |
| C — residual edge concentrated | `DeferredDnsConfig` in its own module, holding exactly the sections Phases 127/128 own | `crates/synvoid-dns/src/runtime_config_deferred.rs` |
| D — production cutover | `src/server/resources.rs` calls `dns_server_runtime_config_from_persisted`; the `format!("{addr}:{port}").parse()` hack in composition is gone | `src/server/resources.rs` |
| E — test migration | 46 `DnsServer::new(DnsConfig, ..)` call sites across 9 files converted to runtime fixtures | `crates/synvoid-dns/tests/support/runtime_config.rs` + 8 test files |
| F — guards | 7 campaign gates (3 new in this phase) | `tools/synvoid-repo-guards/tests/dns_runtime_config_ownership.rs` |

## Dependency evidence

The `synvoid-config` normal edge remains by design — Phase 128 owns its
removal. What Phase 126 changes is *where* that edge is visible.

```text
cargo metadata --no-deps -p synvoid-dns  →  7 direct SynVoid normal edges (unchanged)
cargo tree -p synvoid-dns -e normal      →  847 expanded lines (unchanged)
```

`synvoid_config::dns::DnsConfig` in production `src/` went from being the
`DnsServer` constructor's parameter type to appearing in exactly **one** file:

```text
crates/synvoid-dns/src/runtime_config_deferred.rs   1
```

Every other production file is now either converted or waiting on Phase
127/128. The remaining persisted types, by owning phase:

| Phase 127 (recursive) | Phase 128 (zone/DNSSEC/TSIG/HSM) |
|---|---|
| `RecursiveCacheConfig` (24), `RecursiveUpstreamProvider` (8), `EcsForwardingPolicy` (5), `RecursiveDnsConfig` (3), `CircuitBreakerConfig` (3), `RecursiveEcsConfig` (1), recursive `DnsRateLimitConfig`/`DnsFirewallConfig` | `DnsRecordType` (20), `DnsSecConfig`/`DnsSecAlgorithm`, `HsmConfig`/`HsmProvider`, `DnsZonesConfig`/`DnsZoneEntry`, `TsigKeyConfig`, `NotifyConfig` |

## New gates (regression protection for this cutover)

- `authoritative_runtime_has_no_persisted_config_dto` — no production file
  except `runtime_config_deferred.rs` may name `DnsConfig`.
- `dns_server_constructor_takes_runtime_values` — the canonical signature must
  take `AuthoritativeRuntimeConfig` and no bare persistence DTO.
- `authoritative_runtime_module_never_mentions_deferred_config` — the runtime
  vocabulary and the passthrough are not entangled, so a phase cannot satisfy
  its cutover by reading a deferred value.
- `deferred_config_module_exists_with_only_the_planned_passthroughs` — the
  passthrough may only reference `RecursiveDnsConfig`, `DnsSecConfig`,
  `DnsZonesConfig`, each with an owning phase.
- `deferred_module_is_documented_as_temporary`.

## Deliberate behavior changes

Two, both fail-closed and both required by the phase's acceptance criteria:

1. **DNS64 prefix.** Already recorded in Phase 125 (F-3): the adapter rejects an
   unparseable prefix, so `DnsServer::new` no longer contains a
   `parse().unwrap_or_else(warn + default)` path.
2. **DoQ bind validation.** `doq_bind_addr` previously parsed
   `config.bind_address` at startup and rejected an empty string. The address
   is now parsed by the adapter, so the same condition is expressed as
   `bind_address: None`. The observable behavior is unchanged: an enabled DoQ
   with no address still fails before QUIC endpoint creation with the same
   message. A previously-unreachable case (an *unparseable* literal) now
   surfaces earlier, at conversion, as a typed `InvalidValue`.

Also recorded: `configured_bind_addr` no longer re-parses the address. It now
validates only the zero-port condition, because the adapter already parsed and
validated the literal. The startup error text for a zero port is unchanged.

## Removal: dead `DnsSettings` bridge

`crates/synvoid-dns/src/config.rs` (`DnsSettings { config: Arc<DnsConfig>, .. }`)
was a persistence bridge with **zero consumers** once the authoritative
constructor moved off `DnsConfig`. It was removed in this phase along with its
`pub use` re-export, and `architecture/dns.md` was updated. Keeping it would
have left persisted schema in a public type and tripped
`authoritative_runtime_has_no_persisted_config_dto`.

## Verification

All green at the closeout head:

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `cargo clippy --profile ci --all-targets -- -D warnings` | pass |
| `cargo deny check` | pass |
| `cargo audit` | pass (6 pre-existing allowed warnings) |
| `cargo xtask verify` | pass — 10/10 steps |
| `cargo test -p synvoid-dns --profile ci` | pass (all suites) |
| `cargo test -p synvoid-config --profile ci` | pass (100) |
| `cargo test -p synvoid-repo-guards --profile ci` | pass (130, incl. 7 campaign gates) |
| `cargo test --test composition_root_behavioral --features mesh,dns` | pass (12) |
| `cargo test --test dns_runtime_config_parity` | pass (43, unchanged) |
| `cargo test -p synvoid-dns --test runtime_config_absent_by_design` | pass (15, unchanged) |

The Phase 125 parity fixtures were re-run unchanged against the restructured
runtime shape, which is direct evidence that the authoritative projection is
identical before and after the cutover.

## Test-fixture note

`crates/synvoid-dns/tests/support/runtime_config.rs` provides
`AuthoritativeRuntimeBuilder`, `authoritative_runtime()`, and the
`deferred_*` fixtures. Its defaults mirror `DnsConfig::default()` for every
authoritative group. The two fixtures that still construct persisted shapes
(`deferred_config`, `recursive_persisted`) are named so the residual edge stays
explicit; Phase 128 deletes `deferred_config` and the module with the
dependency edge.

One helper, `parse_bind_address`, was added to `runtime_config.rs` so test
fixtures parse IPv6 literals the same way the adapter does (bare `IpAddr` then
`SocketAddr::from`). Without it, a fixture using `format!("{bind}:{port}")`
silently fails for `::1` — the production path was never affected.

## Successor status

**Phase 127 is unblocked and READY.** The recursive subtree is now the single
largest concentration of the persistence edge in the DNS crate
(`recursive_cache.rs` + `recursive.rs` + the recursive half of
`runtime_config_deferred.rs`), and the authoritative side is already clean, so
its cutover is mechanically the same operation with one fewer shared type.

## Not done in this phase (explicitly)

- No recursive cutover (Phase 127).
- No zone/DNSSEC/TSIG/HSM conversion and no `synvoid-config` edge removal
  (Phase 128).
- No `synvoid-core`/`synvoid-utils` neutralization (Phase 129).
- No persisted schema, default, or admin API change.
- No provider inversion, no class/support change, no publication, no
  repository.
