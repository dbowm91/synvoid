# Phase 116 Plan: DNS Runtime-Config and Core Neutralization

Status: **CLOSED DEFER** (2026-10-02).

Registered in: `plans/roadmap.md` and
`plans/standalone_crate_generalization_roadmap.md`.

Predecessors: Phase 109 CLOSED DEFER; Phase 115 contract/baseline.

## Goal

Remove application-model ownership from `synvoid-dns` without changing DNS
behavior. After this phase the DNS crate should own its runtime configuration and
neutral utility semantics, while SynVoid owns persisted configuration and
translation.

This phase intentionally does NOT yet remove TLS, GeoIP or mesh dependencies; that
is Phase 117.

## Research constraint

Hickory 0.26.3 remains the qualified protocol/server foundation. Do not reimplement
message parsing, ordinary resolver/recursor mechanics, DNSSEC validation or
encrypted-transport framing merely to make the crate look independent.

The reusable value to preserve is SynVoid's higher-level DNS runtime: policy hooks,
zone/runtime coordination, secure transport composition, DNSSEC custody integration,
health/Geo steering and optional distributed record inputs.

## Workstream A — DNS-owned runtime configuration

Inventory every `synvoid_config` type imported by
`crates/synvoid-dns/src/**`, including public re-exports and constructor
signatures.

Define DNS-owned runtime DTOs under `synvoid-dns`, with names based on domain
semantics rather than SynVoid config-file sections.

Requirements:

- no runtime type depends on TOML layout or SynVoid global config ownership;
- defaults are explicit and parity-tested;
- validation is local where it protects DNS invariants;
- secret material remains represented by handles/provider references rather than
  copied config strings where the existing boundary already avoids that;
- serialization derives are added only when independently required, not as a
  shortcut to copying persisted schema.

At the SynVoid composition boundary, implement exhaustive adapters from persisted
`synvoid-config` DTOs to DNS runtime DTOs.

Golden tests must prove existing tracked config produces the same effective runtime
values.

## Workstream B — remove `synvoid-core` utility/policy reach

Classify every `synvoid-core` use into:

1. generic time helper;
2. generic IP/network helper;
3. actual SynVoid policy.

For generic helpers, use std/local DNS-owned code with differential tests. Do not
create a new generic utility crate merely to remove an edge.

For SynVoid policy, define a narrow DNS-domain value/capability rather than copying
policy rules. Restricted-IP behavior, masks and any firewall/QNAME decisions must
retain exact fail-closed semantics.

The target is zero required `synvoid-core` dependency.

## Workstream C — lifecycle utility neutralization

Replace `synvoid-utils` lifecycle/time dependencies used only for
`DrainFlag`/`RunningFlag`/timestamps with DNS-owned or Tokio/std-neutral
contracts.

Prefer an explicit cancellation/lifecycle capability with deterministic tests.
Do not introduce a global runtime singleton.

If `synvoid-utils` remains for a genuinely reusable non-application primitive,
record the exact reason and dependency cost; zero is preferred.

## Workstream D — public surface audit

No `synvoid_config::*` or `synvoid_core::*` type may appear in the intended
standalone DNS public API.

Compatibility adapters may remain at the root/application boundary, not inside
public DNS constructors.

Update rustdoc to distinguish:

- DNS-owned runtime config;
- SynVoid persisted config adapter;
- provider capabilities deferred to Phase 117;
- paired `synvoid-dnssec-keystore` security boundary.

## Workstream E — dependency and behavior evidence

Before and after:

- direct normal SynVoid dependencies;
- expanded `cargo tree -p synvoid-dns -e normal`;
- package source contents;
- default and `mesh` feature graphs;
- DNS crate test counts.

Add differential tests for configuration conversion and any core/helper
replacement.

## Verification

Minimum:

```bash
cargo check -p synvoid-dns --profile ci
cargo check -p synvoid-dns --profile ci --features mesh
cargo test -p synvoid-dns --profile ci
cargo test -p synvoid-dns --profile ci --features mesh
cargo test -p synvoid-dnssec-keystore --profile ci
cargo check --no-default-features --features dns --profile ci
cargo check --no-default-features --features mesh,dns --profile ci
cargo xtask verify
cargo deny check
cargo audit
```

## Acceptance criteria

- DNS owns its runtime config types;
- root/SynVoid owns persisted configuration and translates exhaustively;
- required `synvoid-core` dependency is removed;
- `synvoid-utils` is removed if its remaining uses are only lifecycle/time
  helpers, otherwise residual use is narrowly justified;
- no DNS wire behavior, DNSSEC custody rule, transport support or config meaning
  changes;
- Phase 117 receives a smaller coupling set consisting primarily of TLS, Geo,
  mesh and the explicit DNSSEC-keystore sibling.

## Rejection criteria

Reject implementation that:

- copies the entire SynVoid config schema into the DNS crate;
- changes persisted TOML as part of neutralization;
- replaces Hickory protocol paths with custom equivalents;
- changes restricted-IP/firewall semantics without explicit migration;
- merges DNSSEC private-key custody into the DNS runtime;
- claims standalone readiness before Phase 117 provider inversion and outside-
  workspace proof.

## Formal closeout

Disposition: **DEFER**. No production changes were made because the complete
DNS-owned DTO inventory, exhaustive root adapters, and golden config parity
needed to satisfy this phase were not established. The source-based blocker and
successor status are recorded in
`architecture/standalone_crate_phase116_closeout.md`. Phase 117 is blocked and
must not proceed until this phase is reopened and qualified.
