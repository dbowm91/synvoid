# Phase 125 Closeout — DNS Runtime DTO Contract, Ownership Matrix and Adapter Parity

Date: 2026-10-04.
Plan: `plans/phase_125_dns_runtime_dto_contract_adapter_parity.md`.
Campaign: `plans/dns_runtime_dto_conversion_roadmap.md`.
Planning baseline: `main` at `1df5680738d0b41cc4e859cc012dc2c699d16456`.
Disposition: **CLOSED QUALIFIED**. Phase 126 is unblocked.

## What was delivered

| Workstream | Deliverable | Location |
|---|---|---|
| A — field ownership ledger | Every persisted DNS field classified RUNTIME / PROVIDER / PERSISTENCE / UNSUPPORTED with runtime destination and adapter normalization | `architecture/dns_config_runtime_matrix.md` §"Phase 125 Runtime-DTO Ownership and Projection Ledger" |
| B — DNS-owned runtime module | Runtime-only vocabulary, parsed types, no persistence derives | `crates/synvoid-dns/src/runtime_config.rs` |
| C — application adapter | The single persisted→runtime conversion path | `src/server/dns_runtime_config.rs` |
| D — absent-by-design contract | 15 tests proving no unsupported active setting leaks into the runtime API | `crates/synvoid-dns/tests/runtime_config_absent_by_design.rs` |
| E — parity fixtures | 43 fixtures asserting exact effective runtime values | `tests/dns_runtime_config_parity.rs` |
| F — dual-constructor discipline | Production still uses the persisted-config constructor | unchanged `src/server/resources.rs` |
| Guard | `src/dns/` stays a pure facade; runtime DTO stays persistence-free | `tools/synvoid-repo-guards/tests/dns_runtime_config_ownership.rs` |

## Dependency evidence

Unchanged by design — Phase 125 is the semantic safety gate and Workstream F
explicitly forbids cutting over constructors.

```text
cargo metadata --no-deps -p synvoid-dns  →  7 direct SynVoid normal edges
  synvoid-config, synvoid-core, synvoid-dnssec-keystore, synvoid-geoip,
  synvoid-mesh, synvoid-utils, synvoid-tls
cargo tree -p synvoid-dns -e normal      →  847 expanded lines
```

The Phase 123 baseline recorded in the campaign roadmap was 7 edges / 838
lines; the 9-line drift is pre-existing and unrelated to this phase (no
manifest change to `synvoid-dns`). Phase 130 must record the then-current
numbers as its own baseline rather than treating 838 as still exact.

## Local verification

All green at the closeout head:

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `cargo clippy --profile ci --all-targets -- -D warnings` | pass |
| `cargo deny check` | pass (advisories/bans/licenses/sources ok) |
| `cargo audit` | pass (6 pre-existing allowed warnings) |
| `cargo xtask verify` | pass — all 10 steps |
| `cargo test -p synvoid-config --profile ci` | pass (100) |
| `cargo test -p synvoid-dns --profile ci` | pass (38 suites, incl. 15 new absent-by-design) |
| `cargo test -p synvoid-repo-guards --profile ci` | pass (125 existing + 2 new) |
| `cargo test --test composition_root_behavioral --features mesh,dns` | pass (12) |
| `cargo test --test dns_runtime_config_parity` | pass (43) |

## Ledger corrections this phase forced

The ledger audit found the Phase 5 matrix overstated several fields. These are
corrections, not new claims:

1. **`doh.path` / `doh.json_path` are inert.** `doh.rs` matches the fixed
   protocol routes `/dns-query`, `/`, `/dns`, `/dns-query/json` and never
   reads the persisted fields. Reclassified `implemented` → `PERSISTENCE`.
   Shipping them as runtime values would have created settings the runtime
   silently ignores.
2. **`dot`/`doh`/`doq` TLS material is provider-owned.** `tls_cert_path`,
   `tls_key_path` and `use_system_cert_store` are consumed only through
   composition's `CertResolver`, never by the DNS crate. Class `PROVIDER`;
   absent from the runtime DTO.
3. **`rrl` has exactly one runtime consumer** (`enabled`, the health flag).
   The other four persisted fields are `PERSISTENCE`.

## Intentional behavior change

**`dns.dns64.prefix` now fails closed.** Previously
`parse().unwrap_or_else(|_| warn!(...))` silently substituted `64:ff9b::` on a
malformed prefix. The adapter rejects it. This is required by the Phase 125
adapter contract ("reject conversion on invalid values rather than
clamp/fallback silently") and is pinned by
`invalid_dns64_prefix_is_rejected_instead_of_defaulted`. It is the only
production behavior change in this phase and it affects only a configuration
that was previously broken.

## Findings requiring follow-up (not in this campaign)

### F-1 (pre-existing bug): `dns.firewall.max_rules` serde default ≠ Rust `Default`

`DnsFirewallConfig` derives `Default` while `max_rules` carries
`#[serde(default = "default_firewall_max_rules")]`. The serde default is
`1000`; the derived Rust `Default` is `0`. Because
`validate_at()` rejects any `max_rules != 1000` while the firewall is enabled,
a **Rust-constructed** `DnsConfig` that enables the firewall fails validation
with `Unsupported DNS feature at dns.firewall.max_rules`.

TOML-loaded configuration is unaffected (the serde default applies), so
production is not at risk. The divergence is pinned by
`firewall_serde_default_disagrees_with_rust_default` rather than fixed,
because persisted defaults are out of scope for Phases 125–130 and Phase 130
forbids default drift without a separately planned change.

**Required follow-up:** give `DnsFirewallConfig` a manual `Default` impl, then
audit every other `#[derive(Default)]` struct that mixes
`#[serde(default = ...)]` field attributes.
`RebindingProtectionConfig::enabled` has the same shape
(`default_true` in serde, `false` via derive) but sits behind the same
firewall gate.

### F-2: adapter defense-in-depth paths are unreachable end-to-end

`RecursiveDnsConfig::validate()` already rejects malformed
`client_acl.allowed_clients` CIDRs and unknown `client_acl.action` values, so
the adapter's own ACL parsing never runs through
`dns_runtime_config_from_persisted`. The checks are retained as defense in
depth; `IpNetwork::parse` is exercised directly by the parity fixtures.

## Guard

`tools/synvoid-repo-guards/tests/dns_runtime_config_ownership.rs`:

- `dns_facade_gains_no_adapter_implementation` — `src/dns/` may not import the
  adapter or `synvoid_config::dns`.
- `dns_runtime_config_module_has_no_persistence_dependency` — the runtime DTO
  module may not reference `synvoid_config`, Serde, Schemars, or Utoipa in
  code (doc comments naming the boundary are allowed).

The dependency-edge guards (`synvoid-config`/`core`/`utils` may not return) are
deliberately **not** enabled here: they gate the Phase 128/129 removals and
would fail today. They land with the removals they protect.

## Ledger change made by this phase

`architecture/root_dependency_ownership.md` gained `server` as an entitled
root consumer of `base64`, `synvoid-config`, and `synvoid-dns`. The root
composition module is now legitimately the persisted-DNS-config consumer
(conversion) and the runtime-DTO consumer (construction). This was caught by
`root_dependencies_have_path_entitlement` and is a guard-satisfying ledger
update, not a widening of the request path.

## Successor status

**Phase 126 is unblocked and READY.** The runtime DTO vocabulary, the adapter,
the exhaustive ledger, and the parity evidence all exist, so the production
constructor cutover has the parity prerequisite its rejection criteria demand.
Phases 127–130 remain gated on 126 in sequence.

## Not done in this phase (explicitly)

- No production constructor cutover (Phase 126).
- No `synvoid-config`, `synvoid-core`, or `synvoid-utils` edge removal
  (Phases 128/129).
- No provider inversion, no class/support change, no publication, no
  repository.
- No persisted schema, default, or admin API change.
