# Phase 135 Plan: GeoIP Provider Inversion

Status: **PLANNED** (2026-10-05).

Campaign: `plans/dns_startup_truthfulness_and_provider_inversion_roadmap.md`.
Predecessor: Phase 134.
Registered in: `plans/roadmap.md`.

## Goal

Remove the direct `synvoid-geoip` dependency edge from `synvoid-dns` by
introducing a DNS-owned country-lookup capability with a DNS-owned result type,
implemented in a composition root.

Conditional: proceeds only on a Phase 133 **GO** for GeoIP.

## Background

This is the smallest seam in the crate. DNS calls exactly one method:

```rust
GeoIpManager::get_country_info(IpAddr) -> Option<CountryInfo>
```

at three sites:

| Site | Purpose |
|---|---|
| `crates/synvoid-dns/src/mesh_sync/registry.rs:75` | mesh edge steering (mesh-gated) |
| `crates/synvoid-dns/src/firewall.rs:333` | `GeoLocation::contains` — GeoLocation firewall rules |
| `crates/synvoid-dns/src/server/query.rs:881` | client country code for mesh edge steering |

The provider handle is threaded as `Option<Arc<synvoid_geoip::GeoIpManager>>`
through `firewall.rs:47`, `query.rs:870`, `server/mod.rs:1603` and `:1645`, and
`mesh_sync/mod.rs:163`. `GeoLocation` (`firewall.rs:319`) is already a DNS type
that takes the provider as a parameter.

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
}
```

Constraints:

- The trait and result type are DNS-owned and must not mention
  `synvoid_geoip`. `CountryInfo` is a **new** DNS type, not a re-export.
- Field set must cover every field the three call sites actually read, and
  nothing speculative. `query.rs:881` reads only `c.code`; the mesh registry and
  firewall read more. Enumerate the reads and record them.
- `Option` semantics are preserved exactly: `None` means "provider has no
  answer", which is distinct from "provider is absent". The Phase 133 evidence
  must have pinned both.

## Workstream B — absent-provider semantics

The dangerous half of this inversion is the absent case. `Option<Arc<..>>` at
each site must keep its Phase 133-pinned meaning, and one of them needs an
explicit decision:

- a **GeoLocation firewall rule evaluated with no provider must not silently
  allow traffic**. If Phase 133 pinned "rule cannot be evaluated", that is
  fail-closed and is preserved. If it pinned anything weaker, correct it here
  and record it as a behavior change with its security rationale.

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
