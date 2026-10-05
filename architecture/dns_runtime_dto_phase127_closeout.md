# Phase 127 Closeout — DNS Recursive Resolver Runtime-Config Cutover

Date: 2026-10-04.
Plan: `plans/phase_127_dns_recursive_runtime_cutover.md`.
Campaign: `plans/dns_runtime_dto_conversion_roadmap.md`.
Predecessor: Phase 126 `CLOSED QUALIFIED`
(`architecture/dns_runtime_dto_phase126_closeout.md`).
Disposition: **CLOSED QUALIFIED**. Phase 128 is unblocked.

## What was delivered

The recursive resolver now consumes DNS-owned runtime values. Recursive
upstream strategy, cache policy, client ACL, circuit breaker, depth limits,
timeouts, and ECS forwarding policy are all runtime types; none of them is a
persistence DTO.

```rust
// Before
pub async fn new(config: RecursiveDnsConfig, ...)
fn create_resolver(config: &RecursiveDnsConfig, ...) -> ...
pub fn new(capacity: usize, cache_config: &RecursiveCacheConfig) -> Self
pub fn new(config: &CircuitBreakerConfig) -> Self

// After
pub async fn new(config: RecursiveRuntimeConfig, ...)
fn create_resolver(config: &RecursiveRuntimeConfig, ...) -> ...
pub fn new(capacity: usize, cache_config: &RecursiveCacheRuntimeConfig) -> Self
pub fn new(config: &CircuitBreakerRuntimeConfig) -> Self
```

| Workstream | Deliverable | Location |
|---|---|---|
| A — upstream normalization | `RecursiveUpstreamRuntime` replaces the persisted `upstream_provider` enum; `System` + explicit endpoints now resolves to `CustomEndpoints` instead of being ambiguous | `runtime_config.rs` |
| B — ACL / cache / breaker | `RecursiveClientAclRuntime` (parsed networks + typed action), `RecursiveCacheRuntimeConfig`, `CircuitBreakerRuntimeConfig` | `runtime_config.rs` |
| C — bind + timeouts | `bind_address: SocketAddr` replaces the `format!("{a}:{p}")` bind strings on both the UDP and TCP recursive listeners | `recursive.rs` |
| D — listener build | `start_tcp_listener(SocketAddr)`; upstream construction matched on the runtime enum | `recursive.rs` |
| E — forwarder truthfulness | The "DNSSEC validation is enabled but forwarder mode does not perform validation" warning is now driven by `performs_local_dnssec_validation` instead of re-deriving the mode | `recursive.rs` |
| F — residual edge shrunk | `DeferredDnsConfig` loses its `recursive` field; only `dnssec` and `zones` remain | `runtime_config_deferred.rs` |
| G — production cutover | `DnsServer` gains `recursive: Arc<RecursiveRuntimeConfig>`; `src/server/resources.rs` passes it | `server/mod.rs`, `resources.rs` |
| H — guards | 4 new gates, 11 campaign gates total | `tools/synvoid-repo-guards/tests/dns_runtime_config_ownership.rs` |

## Dependency evidence

The `synvoid-config` normal edge is still present — Phase 128 owns its removal.
The change Phase 127 makes is the concentration of that edge.

```text
cargo metadata --no-deps -p synvoid-dns  →  7 direct SynVoid normal edges (unchanged)
cargo tree -p synvoid-dns -e normal      →  847 expanded lines (unchanged)
```

Persisted types still referenced by `crates/synvoid-dns/src/**`, by owning
phase (production references only, excluding `#[cfg(test)]` modules):

| File | Type | Phase 128 work |
|---|---|---|
| `server/zone.rs` | `DnsRecordType` (20) | zone conversion |
| `server/mod.rs` | `DnsZoneEntry` | `load_zones` input conversion |
| `hsm.rs` | `HsmConfig`, `HsmProvider` | HSM conversion moves to composition |
| `dnssec.rs` | `DnsSecAlgorithm` | `algorithm_from_config` |
| `tsig.rs` | `TsigAlgorithm`, `TsigKeyConfig` | TSIG runtime keys |
| `notify.rs` | `NotifyConfig` | NOTIFY handler |
| `firewall.rs` | `RebindingProtectionConfig` | dead `check_rebinding_protection` (see F-1) |
| `anycast.rs` | `DnsAnycastConfig` | anycast runtime rejection signal |
| `runtime_config_deferred.rs` | `DnsSecConfig`, `DnsZonesConfig` | module deleted |

`recursive.rs` and `recursive_cache.rs` — the two largest concentrations before
this phase, at 21 and 23 references — now have **zero**.

## New gates

- `recursive_runtime_module_has_no_persistence_dependency` — the runtime
  vocabulary may not name `RecursiveDnsConfig`, `RecursiveCacheConfig`,
  `CircuitBreakerConfig`, `RecursiveEcsConfig`, `RecursiveUpstreamProvider`,
  `RecursiveClientAcl`, or `EcsForwardingPolicy` (whole-token match, so
  `RecursiveClientAclRuntime` does not trip it).
- `recursive_server_takes_runtime_config` — the three recursive entry points
  must take runtime types, and `recursive.rs` may not match the persisted
  upstream-provider enum.
- `recursive_cache_takes_runtime_config`.
- `forwarder_modes_cannot_claim_local_dnssec_validation` — the truthfulness
  signal must exist in the runtime contract and `upstream_ips()` must be
  DNS-owned rather than a persistence helper.

The two Phase 126 guards that referenced `recursive` as a deferred field were
narrowed to `{dnssec, zones}`, and `deferred_module_is_documented_as_temporary`
now requires only `Phase 128`.

## Findings carried forward

### F-1 (pre-existing): `check_rebinding_protection` is dead code holding a persistence DTO

`crates/synvoid-dns/src/firewall.rs:548` declares

```rust
pub fn check_rebinding_protection(config: &RebindingProtectionConfig, ...)
```

It has **no callers** anywhere in `crates/` or `src/`. The Phase 125 ledger
already classified `dns.firewall.rebinding_protection.*` as `PERSISTENCE`:
`DnsFirewallConfig::validate_at()` rejects `rebinding_protection.enabled = true`
precisely because the query path never enforces it. Keeping the function means
keeping a public API whose parameter type is a persistence DTO purely so
Phase 45 can reject the setting that would activate it.

**Phase 128 should delete this function** rather than convert it, since the
setting it reads is fail-closed and has no planned runtime consumer. Deleting
it is the honest resolution; converting it would create a runtime setting the
runtime ignores, which is exactly what the absent-by-design contract forbids.
Recorded here rather than actioned because removing public API is a schema-adjacent
decision that Phase 128's own plan should ratify.

### F-2 (pre-existing): a hostname-only custom upstream list silently falls back to the system resolver

`RecursiveRuntimeConfig::upstream_ips()` preserves the pre-Phase-127 semantics
exactly, including this behavior: only `CustomUpstreamEndpoint::Literal`
contributes an address. An operator who configures `upstream_provider = "custom"`
with hostname-only endpoints therefore gets an empty address list, and
`create_resolver` falls back to `HickoryResolver::from_system_config()` — the
operator's custom forwarders are silently ignored.

The persisted schema accepts `upstream_servers[].address` without an `ip`
field, so this is reachable from a valid config file. It is **preserved, not
fixed**, because Phase 127's acceptance criteria require behavior parity and
changing it would be an unannounced resolver-behavior change.

**Follow-up required:** either resolve hostname endpoints at startup (the
correct fix) or reject them at validation time with a typed path. Either needs
its own plan, and both should land with a note in
`architecture/dns.md` §recursive upstream.

### F-3: `CdnOnly` recursive ECS policy is a no-op

`evaluate_ecs_forwarding_policy(RecursiveEcsPolicyRuntime::CdnOnly, _)`
returns `None` — client subnets are never forwarded. This matches the
pre-cutover behavior and is now documented at the match arm. `CdnOnly` is
effectively an alias for `Never`; the matrix records it as PERSISTENCE-quality
(unimplemented) rather than a working policy.

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
| `cargo test -p synvoid-repo-guards --profile ci` | pass (130, incl. 11 campaign gates) |
| `cargo test --test composition_root_behavioral --features mesh,dns` | pass (12) |
| `cargo test --test dns_runtime_config_parity` | pass (43, unchanged) |
| `cargo test -p synvoid-dns --test runtime_config_absent_by_design` | pass (15, unchanged) |

The Phase 125 parity fixtures — including the recursive upstream-normalization
table, ACL parsing, DNSSEC-provider truthfulness, and the shipped
`recursive_local.toml` profile — pass **unchanged** against the cutover. That is
direct evidence the recursive projection is identical before and after.

## Test-fixture note

`crates/synvoid-dns/tests/support/runtime_config.rs` gained
`recursive_runtime()`, `recursive_runtime_on(port)`, `recursive_disabled()`,
`recursive_with_acl(..)`, `recursive_with_upstreams(..)`,
`recursive_cache_runtime(..)`, and `circuit_breaker_runtime(..)`.
`deferred_recursive_enabled()` and `recursive_persisted()` were deleted — the
recursive runtime no longer has a persisted shape.

Four tests in `dns_recursive_test.rs` / `dns_config_test.rs` /
`dns_recursive_isolation.rs` deliberately keep asserting **persisted**
defaults and serde round-trips. Those assert `synvoid-config` behavior, not DNS
runtime behavior, and each now also asserts the corresponding runtime
projection so the two cannot drift.

## Successor status

**Phase 128 is unblocked and READY.** Its scope is now precisely enumerated by
the table above: zone record/entry conversion, DNSSEC algorithm + key manager,
TSIG runtime keys, NOTIFY, anycast, the dead rebinding helper, and finally the
`synvoid-config` normal dependency edge plus the `runtime_config_deferred`
module.

## Not done in this phase (explicitly)

- No zone/DNSSEC/TSIG/HSM conversion and no `synvoid-config` edge removal
  (Phase 128).
- No `synvoid-core`/`synvoid-utils` neutralization (Phase 129).
- No persisted schema, default, or admin API change.
- No provider inversion, no class/support change, no publication, no
  repository.
- F-1 and F-2 are recorded, not actioned.
