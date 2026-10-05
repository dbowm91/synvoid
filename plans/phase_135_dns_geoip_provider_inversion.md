# Phase 135 Plan: GeoIP Provider Inversion

Status: **PLANNED** (2026-10-05). Phase 133 returned **GO** — see
`architecture/dns_provider_inversion_phase133_closeout.md`.

Campaign: `plans/dns_startup_truthfulness_and_provider_inversion_roadmap.md`.
Predecessor: Phase 134.
Registered in: `plans/roadmap.md`.

## Goal

Remove the direct `synvoid-geoip` dependency edge from `synvoid-dns` by
introducing a DNS-owned country-lookup capability with a DNS-owned result type,
implemented in a composition root.

Conditional: proceeds only on a Phase 133 **GO** for GeoIP. **GO received.**

## Mandatory carry-forward work from Phase 133

These are not optional. Phase 133 recorded them without fixing them, because it
changed no production behavior.

### Workstream 0a — make provider construction total (F-1, severity high)

`GeoIpManager::new` **panics** on a config-reachable input.
`GeoIpUpdater::new` (`crates/synvoid-geoip/src/updater.rs:147`) evaluates
`source.as_ref().unwrap()`, and `DownloadSource::from_config` returns `None`
unless `update_url` or (`account_id` **and** `license_key`) is set. So
`[geoip] enabled = true` with no download credentials aborts the process —
even with `update_enabled = false`.

This is first because Workstream C's composition implementation constructs a
`GeoIpManager` through exactly this path, and because it is a live
config-triggered crash. `a None` source already means "there is nothing to
download", so an absent source should yield zero editions, not a panic.

`enabled_config_without_download_credentials_panics_during_construction` in
`crates/synvoid-geoip/tests/geoip_provider_evidence.rs` currently pins the
panic. **It must be inverted to assert the fixed behavior** rather than deleted;
a `#[should_panic]` test that is simply removed would lose the regression pin.

### Workstream 0b — decide and implement the absent-provider rule (F-2, severity high)

A `GeoLocation` **block** rule with no provider silently allows traffic.
`GeoLocation::matches_ip` returns `false`, so `evaluate_query` skips the rule
and falls through to the default `Allow`, and the decision does not name the
skipped rule. No error, no log line, no blocked traffic.

This phase must choose a fail-closed meaning and implement it, recording the
behavior change and its security rationale. `geo_block_rule_without_provider_silently_allows`
pins today's fail-open behavior and must be updated to the chosen semantics.

## Background

This is the smallest seam in the crate, and Phase 133 proved it is **two**
methods rather than one:

```rust
GeoIpManager::get_country_info(IpAddr) -> Option<CountryInfo>   // 3 call sites
GeoIpManager::get_asn_info(IpAddr) -> Option<AsnInfo>           // 1 call site
```

| Site | Purpose |
|---|---|
| `crates/synvoid-dns/src/mesh_sync/registry.rs:75` | mesh edge steering (mesh-gated) |
| `crates/synvoid-dns/src/firewall.rs:333` | `GeoLocation::contains` — GeoLocation firewall rules |
| `crates/synvoid-dns/src/server/query.rs:881` | client country code for mesh edge steering |
| `crates/synvoid-dns/src/firewall.rs:361` | `GeoLocation::contains` — ASN-scoped rules |

The provider handle is threaded as `Option<Arc<synvoid_geoip::GeoIpManager>>`
through `firewall.rs:47`, `query.rs:870`, `server/mod.rs:1603` and `:1645`, and
`mesh_sync/mod.rs:163`. `GeoLocation` (`firewall.rs:319`) is already a DNS type
that takes the provider as a parameter and holds only primitives.

`dns_names_exactly_the_two_geoip_provider_methods` in
`tools/synvoid-repo-guards/tests/dns_dependency_edges.rs` pins the seam width.
A third call fails the guard.

## Workstream A — DNS-owned capability and result type

```rust
pub struct CountryInfo {
    pub code: String,
    pub name: String,
    pub subdivision: Option<String>,
    pub city: Option<String>,
}

pub trait CountryLookup: Send + Sync {
    fn country_info(&self, ip: IpAddr) -> Option<CountryInfo>;
    fn asn(&self, ip: IpAddr) -> Option<u32>;
}
```

Constraints:

- The trait and result type are DNS-owned and must not mention
  `synvoid_geoip`. `CountryInfo` is a **new** DNS type, not a re-export.
- `asn` returns `Option<u32>`, not `Option<AsnInfo>`: `GeoLocation::matches_ip`
  reads only `asn_info.asn` and discards `organization` (Phase 133 F-10), so
  the provider struct is not needed and must not cross.
- Field set must cover every field the call sites actually read, and nothing
  speculative. `query.rs:881` reads only `c.code`; the firewall reads
  `code`, `subdivision`, `city`, and `asn`. Enumerate the reads and record them.
- `Option` semantics are preserved exactly: `None` means "provider has no
  answer", which is distinct from "provider is absent". Phase 133 pinned both
  (see F-5: the absent-provider case is not constructible from `synvoid-dns`
  without re-adding the `synvoid-config` edge, so it is pinned from both sides).
- Do **not** preserve `get_country_info`'s second lookup. Phase 133 F-9 proved
  it cannot change the answer — both lookups read the same `country.iso_code`
  path — so it is a redundant database traversal per request, not a guard.

## Workstream B — absent-provider semantics

The dangerous half of this inversion is the absent case. `Option<Arc<..>>` at
each site must keep its Phase 133-pinned meaning, and one of them needs an
explicit decision — **see Workstream 0b above, which is now settled input to
this workstream**:

- a **GeoLocation firewall rule evaluated with no provider must not silently
  allow traffic**. Phase 133 pinned the opposite (F-2), so this is a recorded
  behavior change with a security rationale, not a preservation.

Also carried forward:

- F-3: `GeoLocation::from_str` cannot fail, so a misspelled country target
  becomes a never-matching rule with no diagnostic. Decide whether to validate
  the target at rule-construction time.
- F-4: once the trait exists, the positive `contains` matrix becomes testable in
  `synvoid-dns` with a DNS-owned double. It currently lives in the `synvoid-geoip`
  suite because that is where a real MaxMind database exists; add the in-crate
  matrix so the behavior is pinned where the behavior lives.
- F-5: the answerless-provider case is unreachable from `synvoid-dns`. After
  inversion it becomes trivially constructible with a double that returns `None`,
  so it should be tested directly rather than derived.

## Workstream C — composition implementation

- implement `CountryLookup` in root composition over `Arc<GeoIpManager>`,
  mapping `synvoid_geoip::CountryInfo` → DNS `CountryInfo` field by field;
- update the `with_geoip` builders at `crates/synvoid-dns/src/server/zone.rs:389`
  and `crates/synvoid-dns/src/mesh_sync/registry.rs:63`;
- update every `Option<Arc<GeoIpManager>>` field to
  `Option<Arc<dyn CountryLookup>>`;
- record the composition home against
  `architecture/root_module_ledger.md`.

## Workstream D — dependency removal

- remove the `synvoid-geoip` manifest edge;
- zero remaining `synvoid_geoip` references in `crates/synvoid-dns/src/**`;
- mesh-gated sites must still compile and pass with `--features mesh`;
- extend `tools/synvoid-repo-guards/tests/dns_dependency_edges.rs` with the
  `synvoid-geoip` manifest and source-level gates, using whole-token matching.

## Workstream E — parity

- mesh edge steering produces identical country codes;
- GeoLocation firewall rules evaluate identically, including the absent-provider
  case;
- no client-IP disclosure through logging changes — the Phase 133 privacy
  finding stays satisfied;
- `--features mesh` behavior unchanged.

## Workstream F — documentation

- `architecture/dns.md`;
- `architecture/dns_config_runtime_matrix.md` (F-12…);
- campaign roadmap and `plans/roadmap.md`.

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --profile ci --all-targets -- -D warnings
cargo tree -p synvoid-dns -e normal
cargo tree -p synvoid-dns -e normal -i synvoid-geoip
cargo test -p synvoid-dns --profile ci
cargo test -p synvoid-dns --profile ci --features mesh
cargo test -p synvoid-geoip --profile ci
cargo test -p synvoid-repo-guards --profile ci
cargo deny check
cargo audit
cargo xtask verify
```

## Acceptance criteria

- no direct `synvoid-geoip` edge, proven by `cargo metadata` and `cargo tree`;
- zero `synvoid_geoip` references in `crates/synvoid-dns/src/**`;
- firewall and mesh steering parity green, including the absent-provider case;
- direct SynVoid normal edges fall from 3 to 2 (`synvoid-dnssec-keystore` plus
  optional `synvoid-mesh`).

## Rejection criteria

Reject a closeout that:

- re-exports `synvoid_geoip::CountryInfo` instead of owning the type;
- changes absent-provider semantics without recording it as a security-relevant
  behavior change;
- implements the provider inside `synvoid-dns`;
- re-adds the manifest edge for a test;
- touches mesh authority or signed provenance.

## Closeout

`architecture/dns_provider_inversion_phase135_closeout.md`.
