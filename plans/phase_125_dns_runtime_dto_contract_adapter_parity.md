# Phase 125 Plan: DNS Runtime DTO Contract, Ownership Matrix and Adapter Parity

Status: **PLANNED / READY** (2026-10-04).

Registered in: `plans/roadmap.md` and
`plans/dns_runtime_dto_conversion_roadmap.md`.

Planning baseline: `main` at `f86f99d1ba239cd32e423dede232d684cfeb8fa2`.

Research authority:
`architecture/dns_runtime_dto_conversion_research.md`.

## Goal

Introduce the DNS-owned runtime configuration vocabulary and the single
application-owned persisted-config -> runtime adapter without cutting production
constructors over yet.

This phase is the semantic safety gate. No dependency is required to disappear
yet.

## Workstream A — exhaustive field ownership ledger

Extend `architecture/dns_config_runtime_matrix.md` with ownership/projection
columns for every persisted DNS field:

- persisted owner;
- validation status;
- runtime consumer;
- runtime DTO destination;
- adapter normalization/parsing;
- `absent-by-design` reason when no runtime field should exist.

Every field in `DnsConfig` and nested DNS sections must be accounted for.

Required classifications:

- runtime-owned and converted;
- composition/provider-owned and deferred to later provider inversion;
- persistence-only;
- unsupported/deferred and intentionally omitted.

The ledger is a merge gate for Phases 126–128.

## Workstream B — DNS-owned runtime module

Create `crates/synvoid-dns/src/runtime_config.rs` (or equivalent canonical
module) with runtime-only values.

Initial shape should cover the implemented surfaces required by later phases:

- authoritative bind;
- cache/serve-stale;
- limits;
- DNS rate limiting and RRL;
- implemented firewall controls;
- ECS filter;
- query coalescing;
- DNS64;
- DNSSEC policy values;
- DoT/DoH/DoQ runtime settings;
- recursive runtime subtree;
- zone input specs;
- TSIG runtime key/algorithm specs.

Prefer parsed types such as `SocketAddr`, `Duration`, `PathBuf`, and parsed
network ACLs.

Do not add Serde/Schemars/Utoipa derives unless a real runtime consumer requires
them.

## Workstream C — application adapter

Create canonical composition code under
`src/server/dns_runtime_config.rs`.

The adapter must:

1. accept already-loaded persisted DNS config;
2. invoke or require the existing `DnsConfig::validate()` contract before
   conversion;
3. parse/normalize values into runtime types;
4. reject conversion on invalid values rather than clamp/fallback silently;
5. map only implemented runtime behavior;
6. build keystore-owned HSM values rather than leaking persisted HSM types into
   DNS;
7. preserve typed config validation as the operator-facing failure boundary.

Do not add conversion logic to `src/dns/`.

## Workstream D — absent-by-design contract

Pin tests proving the runtime DTO does not expose active settings for currently
unsupported persisted features, including at minimum:

- RPZ;
- prefetch;
- custom trust-anchor lifecycle;
- padding;
- QNAME privacy;
- unwired rebinding controls;
- unsupported anycast activation;
- unsupported transfer/update/notify settings that remain rejected by config.

The persisted validation tests remain authoritative for typed config paths.

## Workstream E — parity fixtures

Add root/composition tests that construct persisted `DnsConfig`, convert it,
and assert exact effective runtime values.

Cover:

- defaults;
- supported shipped DNS example profiles;
- authoritative-only;
- recursive;
- DNSSEC;
- DoT/DoH/DoQ;
- cache + serve-stale;
- ECS;
- DNS64;
- rate limiting/RRL;
- limits;
- invalid bind/port;
- open-recursive rejection;
- Phase-45 unsupported activation cases.

Where values become parsed types, compare their semantic result rather than
string formatting.

## Workstream F — temporary dual-constructor discipline

Production may continue using the current persisted-config constructor in this
phase. The runtime DTO/adapter may be exercised through tests/internal helpers.

Do not maintain two long-lived behavior implementations. Phase 126 owns the
production cutover.

## Verification

Minimum:

```bash
cargo fmt --all -- --check
cargo test -p synvoid-config --profile ci
cargo test -p synvoid-dns --profile ci
cargo test --test composition_root_behavioral --features mesh,dns --profile ci
cargo test -p synvoid-repo-guards --profile ci
cargo xtask verify
cargo deny check
cargo audit
```

Add a guard that prevents `src/dns/` from gaining adapter implementation and
keeps the facade disposition intact if current guards do not already prove it.

## Acceptance criteria

- every persisted DNS field has an explicit ownership/projection disposition;
- DNS-owned runtime values compile independently of persistence derives;
- one root composition adapter converts validated persisted config;
- parity fixtures cover all implemented field groups and unsupported activation;
- production behavior remains unchanged;
- no persisted schema/admin API change;
- no support/classification change.

## Rejection criteria

Reject implementation that:

- adds a second persisted schema to `synvoid-dns`;
- leaves fields unclassified in the matrix;
- performs lossy parsing with silent defaults;
- lets tests construct runtime config from invalid persisted config;
- cuts over constructors before parity evidence is complete;
- moves provider inversion into this phase.
