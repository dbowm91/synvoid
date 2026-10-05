# Phase 128 Closeout — DNS Zone / DNSSEC / TSIG Runtime Cutover and `synvoid-config` Edge Removal

Date: 2026-10-04.
Plan: `plans/phase_128_dns_zone_dnssec_tsig_config_removal.md`.
Campaign: `plans/dns_runtime_dto_conversion_roadmap.md`.
Predecessor: Phase 127 `CLOSED QUALIFIED`
(`architecture/dns_runtime_dto_phase127_closeout.md`).
Disposition: **CLOSED QUALIFIED**. Phase 129 is unblocked.

## What was delivered

`synvoid-dns` no longer links `synvoid-config` at all. Every persisted DNS
section — zones, DNSSEC policy, TSIG keys, HSM settings, anycast — is now
converted by the single application-owned adapter into DNS-owned runtime
values before it reaches the crate. The temporary
`runtime_config_deferred` passthrough that Phases 126/127 needed is gone.

```rust
// Before
pub fn new(
    authoritative: AuthoritativeRuntimeConfig,
    recursive: RecursiveRuntimeConfig,
    deferred: DeferredDnsConfig,   // carried DnsSecConfig + DnsZonesConfig
    cert_resolver: Option<Arc<CertResolver>>,
) -> Self
pub fn load_zones(&self, zone_configs: Vec<DnsZoneEntry>) -> Result<(), String>
fn keystore_config_from_dns(config: &DnsConfig) -> ...
fn algorithm_from_config(a: &DnsSecAlgorithm) -> Algorithm
impl From<&NotifyConfig> for ...
fn check_rebinding_protection(config: &RebindingProtectionConfig, ...)
pub struct AnycastSocketManager { config: DnsAnycastConfig, ... }
pub fn new(keys_config: Vec<TsigKeyConfig>) -> Result<Self, String>

// After
pub fn new(
    runtime: DnsRuntimeConfig,     // authoritative + recursive + dnssec + zones + tsig_keys
    cert_resolver: Option<Arc<CertResolver>>,
) -> Self
pub fn load_zones(&self, zone_configs: Vec<ZoneSpec>) -> Result<(), String>
fn keystore_config_from_runtime(config: &HsmRuntimeConfig) -> ...
fn algorithm_from_runtime(a: DnssecAlgorithmRuntime) -> Algorithm
// the `From<&NotifyConfig>` impl is removed: NotifyConfig is already DNS-owned
// check_rebinding_protection is deleted
pub struct AnycastSocketManager { config: AnycastSocketConfig, ... }
pub fn new(keys_config: Vec<TsigRuntimeKey>) -> Result<Self, String>
```

| Workstream | Deliverable | Location |
|---|---|---|
| A — zone conversion | `load_zones(Vec<ZoneSpec>)`; the 20-site persisted `DnsRecordType` match in `zone.rs` is replaced by hickory's `RecordType`, re-exported from `runtime_config` | `server/zone.rs`, `runtime_config.rs` |
| B — DNSSEC policy | `DnssecRuntimeConfig` is a `DnsServer` field (`dnssec_runtime`); `algorithm_from_runtime(DnssecAlgorithmRuntime)` replaces `algorithm_from_config` | `server/mod.rs`, `dnssec.rs` |
| C — HSM custody | `keystore_config_from_runtime(&HsmRuntimeConfig)`; `HsmProviderRuntime` is DNS-owned | `hsm.rs` |
| D — TSIG | `TsigKey::from_runtime`, `TsigVerifier::new(Vec<TsigRuntimeKey>)`, `add_key(TsigRuntimeKey)`; `TsigAlgorithmRuntime` gains `to_u16`/`from_u16`/`as_str`/`min_secret_len` | `tsig.rs`, `runtime_config.rs` |
| E — NOTIFY | The `From<&synvoid_config::dns::NotifyConfig>` impl is deleted: `NotifyConfig` was already DNS-owned, so the impl was a no-op over a self-edge | `notify.rs` |
| F — anycast | DNS-owned `AnycastSocketConfig` replaces the persisted `DnsAnycastConfig` on `AnycastSocketManager` | `anycast.rs` |
| G — dead code | `check_rebinding_protection` (Phase 127 F-1) and its now-orphaned `is_private_ip` helper are deleted | `firewall.rs` |
| H — passthrough | `runtime_config_deferred.rs` deleted; `DeferredDnsConfig` is gone from the public surface | `mod.rs` |
| I — production cutover | `src/server/resources.rs` passes the whole `DnsRuntimeConfig`; TSIG keys are taken from the converted runtime, not from `dns_cfg.dnssec` | `resources.rs` |
| J — guards | 4 new gates; the deferred-field guards become a "the module must not come back" gate | `tools/synvoid-repo-guards/tests/` |

## Dependency evidence

This is the phase the campaign's dependency reduction is measured against.

```text
cargo metadata --no-deps -p synvoid-dns  →  6 direct SynVoid normal edges (was 7)
cargo tree -p synvoid-dns -e normal      →  846 expanded lines (was 847)
```

Remaining direct SynVoid normal edges: `synvoid-core`, `synvoid-dnssec-keystore`,
`synvoid-geoip`, `synvoid-mesh` (optional), `synvoid-tls`, `synvoid-utils`.
`synvoid-config` is gone, and `grep -rn "synvoid_config" crates/synvoid-dns/`
returns only comments.

The expanded-tree count fell by exactly one line because `synvoid-config`
contributed a single direct edge line; its transitive closure was already
reachable through the remaining edges.

The Phase 125 baseline recorded 7 edges / 838 lines and Phase 126/127 recorded
7 / 847. The 9-line delta was pre-existing drift from phases before this
campaign, not introduced here; the numbers above are measured, not derived.

## Test relocation

Removing the dependency edge removed `synvoid-config` from the crate's
test compilation entirely. Persisted-schema coverage was **moved, not
deleted**, into `crates/synvoid-config/tests/` where the schema lives:

| From | To | Tests |
|---|---|---|
| `synvoid-dns/tests/dns_config_test.rs` | `synvoid-config/tests/dns_schema_contract.rs` | 13 |
| `synvoid-dns/tests/verification_gate.rs` | same | 16 |
| `synvoid-dns/tests/dns_recursive_isolation.rs` | same | 48 |
| `synvoid-dns/tests/dns_integration_test.rs` | same | 5 |
| `synvoid-dns/tests/encrypted_transport.rs` | same | 6 |
| `synvoid-dns/tests/example_configs_parse.rs` | `synvoid-config/tests/example_configs_parse.rs` | 7 |
| `synvoid-dns/tests/dns_interop_encrypted.rs` | `synvoid-config/tests/encrypted_transport_schema.rs` | 5 |

Two blocks asserted persisted-default/runtime-projection parity
(`test_recursive_cache_config_defaults`, the two ECS defaults tests). They were
split: the persisted half moved, the runtime half stayed in `synvoid-dns`.
The end-to-end persisted→runtime projection remains owned by the root parity
suite `tests/dns_runtime_config_parity.rs` (43 fixtures, unchanged).

`synvoid-config` gained `toml` and `serde` dev-dependencies; both were already
in `Cargo.lock`, so the supply-chain surface did not change (`cargo deny` and
`cargo audit` confirm).

## New gates

In `tools/synvoid-repo-guards/tests/dns_dependency_edges.rs` (new file):

- `synvoid_dns_has_no_config_edge` — `crates/synvoid-dns/Cargo.toml` must not
  declare `synvoid-config` in **any** dependency section, including
  `dev-dependencies`. Whole-token key matching, so `synvoid-dnssec-keystore`
  never trips it.
- `synvoid_dns_has_no_core_edge` / `synvoid_dns_has_no_utils_edge` — the same
  gate for the Phase 129 removals, landed `#[ignore]`d so a forward-looking gate
  cannot fail the suite before its phase. Phase 129 removes the attributes.

In `dns_runtime_config_ownership.rs`:

- `deferred_passthrough_module_does_not_exist` — replaces the two guards that
  constrained the passthrough. A guard that pinned a file's *contents* could
  not express "this file must be gone", so the Phase 126/127 gates become a
  positive absence check on the file and on the `lib.rs` wiring.
- `no_production_file_names_the_persisted_root_dns_config` — the Phase 126
  gate's single allowed file (`runtime_config_deferred.rs`) is deleted, so the
  allowance is now empty. The message points at the adapter.
- `dns_server_constructor_takes_runtime_values` now scopes its scan to each
  `impl DnsServer` block individually. The previous version searched from the
  first `impl DnsServer` to end-of-file, so it matched `Zone::new` in between;
  the literal anchor hid that. It now also requires the constructor to accept a
  `DnsRuntimeConfig`, not merely to avoid `DnsConfig`.

Campaign gate count: 10 in `dns_runtime_config_ownership.rs` (was 11 — two
deferred gates merged into one absence gate, one guard added), plus 1 live and
2 pending in `dns_dependency_edges.rs`.

## Security notes

**TSIG secret handling is unchanged or stricter.** The adapter base64-decodes
and length-checks; `TsigKey::from_runtime` re-checks because
`TsigVerifier::new` is public and a hand-built `TsigRuntimeKey` must not reach
the verifier undersized. Errors carry the key name and algorithm only.
`TsigRuntimeKey` has a hand-written `Debug` that redacts the secret, so a stray
`{:?}` cannot leak key material. This is covered by
`tsig_key_rejection_error_does_not_leak_the_secret` and by the existing
`tsig_key_debug_redacts_secret`.

**DNSSEC private-key custody is unchanged.** The runtime DTO carries a key
*path* and HSM settings; no runtime type holds raw private key bytes.
`synvoid-dnssec-keystore` remains the only key-custody owner, and the
`dnssec_keystore_boundary` guard still passes.

## Findings

### F-1: the Phase 125 TSIG minimum-secret threshold was too low (corrected here)

Phase 125 introduced `TsigAlgorithmRuntime::min_secret_len()` returning the
HMAC **input block size** (16/24/32) with a comment citing RFC 8945. The
pre-cutover server rejected secrets shorter than the HMAC **output length**
(32/48/64) via `synvoid_config::dns::TsigAlgorithm::key_size()`. The Phase 125
adapter therefore silently accepted weaker keys than the server used to reject.

Corrected in Phase 128 to 32/48/64, which is both the pre-cutover value and
what RFC 8945 §4.3.2 actually recommends. Pinned by
`test_tsig_algorithm_min_secret_len_matches_pre_cutover_key_size`.

The error message also changed from `"TSIG secret too short for {algo}"` to
`"TSIG key '{name}' secret too short for {algo}"`, and the algorithm renders as
its FQDN form (`hmac-sha256.` rather than `hmac-sha256`). That is a
diagnostic-text change only.

### F-2 (pre-existing): `[dns.zones]` is converted but never loaded

`DnsServer::new` destructures the runtime and discards the zone specs:

```rust
let DnsRuntimeConfig { authoritative, recursive, dnssec, zones: _, tsig_keys: _, enabled: _ } = runtime;
```

`DnsServer::load_zones(Vec<ZoneSpec>)` has **no production caller** — only
`crates/synvoid-dns/tests/metrics_wiring.rs`. So a shipped `[dns.zones]` entry
is validated, converted by the adapter, and then dropped; zones reach a running
server only through `load_zones_from_store` (the SQLite zone store), not from
`main.toml`.

This is pre-existing and unchanged by the campaign: before Phase 125 the
constructor took `DnsConfig` and equally ignored `config.zones`. Phase 128
makes it *visible* by naming the discarded binding `zones: _` with a comment.

**Not fixed in this campaign.** Loading `[dns.zones]` at startup is a behavior
change, not a refactor, and the phase acceptance criteria require parity.
Follow-up required: either have composition call `load_zones(runtime.zones)`
explicitly, or drop `[dns.zones]` from the shipped schema and document that
zones come from the zone store. Recorded in `architecture/dns_config_runtime_matrix.md`.

### F-3 (pre-existing): TSIG keys are dropped by the constructor by design

`tsig_keys: _` in the same destructuring pattern. This one is *intentional* and
correct: `src/server/resources.rs` reads `runtime_cfg.tsig_keys` before
constructing the server and feeds them to `TsigVerifier` for zone transfers.
TSIG keys only matter when transfer is enabled, so building the verifier
unconditionally would allocate for servers that never transfer. Unlike F-2
this path is wired and exercised; it is noted only so the two discarded
bindings are not confused.

### F-4 (pre-existing): `is_private_ip` became dead after the rebinding deletion

Deleting `check_rebinding_protection` (Phase 127 F-1, ratified here) left
`firewall.rs::is_private_ip` with no callers. It was deleted rather than left
behind, because keeping a private helper that nothing calls is exactly the
"converted but unused" shape the absent-by-design contract forbids.
`synvoid_core::net::is_restricted_ip` is still used elsewhere in the crate, so
the Phase 129 `synvoid-core` work is unaffected by this deletion.

## Phase 129 handoff

Ready to unblock. `synvoid-core` and `synvoid-utils` edges are present and now
gated by `#[ignore]`d tests that Phase 129 makes live.

Measured starting point for Phase 129:

```text
6 direct SynVoid normal edges
846 expanded cargo tree lines
```

Phase 129's acceptance target is **3 edges** (`synvoid-tls`, `synvoid-geoip`,
`synvoid-dnssec-keystore`) plus the optional `synvoid-mesh`. Phase 130 must
re-measure rather than assume any particular expanded-line count.
