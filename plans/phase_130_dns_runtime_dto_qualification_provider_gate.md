# Phase 130 Plan: DNS Runtime-DTO Qualification and Provider-Inversion Gate

Status: **CLOSED QUALIFIED** (2026-10-05). Closeout:
`architecture/dns_runtime_dto_phase130_closeout.md`. The campaign is complete.

Proven, not assumed: 4 direct SynVoid normal edges (`synvoid-tls`,
`synvoid-geoip`, `synvoid-dnssec-keystore`, optional `synvoid-mesh`) and 827
expanded `cargo tree -e normal` lines, against a Phase 123 baseline of 7 / 838.
`synvoid-core` and `synvoid-utils` are absent entirely; `synvoid-config` is no
longer a direct edge and survives in the expanded tree only through
`synvoid-tls` and `synvoid-geoip`.

Provider-inversion readiness: **DEFER**. TLS (2 types) and GeoIP (1 method) are
narrow enough to invert but lack the SNI/reload/ALPN and
missing-DB/deterministic-fallback evidence their gate requires; mesh is not a
narrow seam at all. The per-provider missing evidence is listed in the closeout.

`synvoid-dns` remains class 1. No provider trait was implemented and no
promotion is claimed.

Registered in: `plans/roadmap.md` and
`plans/dns_runtime_dto_conversion_roadmap.md`.

## Goal

Qualify the completed runtime-DTO/core-neutralization campaign, prove dependency
and behavior outcomes, reconcile documentation, and decide whether a subsequent
TLS/Geo/mesh provider-inversion campaign is ready to register.

This phase does not itself perform provider inversion or class-2 promotion.

## Workstream A — dependency proof

Regenerate:

- direct normal/optional SynVoid dependencies;
- expanded `cargo tree -p synvoid-dns -e normal`;
- feature graph;
- package contents.

Expected target, to be proven rather than assumed:

```text
synvoid-dns
  -> synvoid-tls
  -> synvoid-geoip
  -> synvoid-dnssec-keystore
  -> synvoid-mesh (optional)
```

There must be no normal:

- `synvoid-config`;
- `synvoid-core`;
- `synvoid-utils`.

Compare to the Phase 123 baseline of seven direct SynVoid edges / 838 expanded
normal-tree lines.

## Workstream B — runtime/persistence parity

Re-run the complete adapter parity ledger against:

- defaults;
- supported shipped DNS profiles/examples;
- authoritative;
- recursive;
- DNSSEC;
- TSIG/HSM shape;
- DoT/DoH/DoQ;
- cache/serve-stale;
- ECS;
- DNS64;
- rate/RRL;
- limits;
- invalid/open-resolver cases;
- every fail-closed unsupported activation path.

No persisted schema/default/admin API drift is acceptable unless separately
planned.

## Workstream C — DNS functional qualification

Minimum:

```bash
cargo fmt --all -- --check
cargo test -p synvoid-dns --profile ci
cargo test -p synvoid-dns --profile ci --features mesh
cargo test -p synvoid-config --profile ci
cargo test -p synvoid-dnssec-keystore --profile ci
cargo check --no-default-features --features dns --profile ci
cargo check --no-default-features --features mesh,dns --profile ci
cargo test -p synvoid-repo-guards --profile ci
cargo xtask verify
cargo xtask verify-full
cargo deny check
cargo audit
```

Run the repository DNS conformance script and any existing extended DNS
interop suites required by current release policy. Record skipped/external-tool
lanes truthfully.

Package `synvoid-dns` and exercise a bounded outside-workspace consumer for
the now-neutral authoritative/runtime configuration surface. This is evidence
only; it does not make the crate class 2 while TLS/Geo/mesh concrete edges
remain.

## Workstream D — documentation reconciliation

Update current authority:

- `architecture/dns.md`;
- `architecture/dns_deep_dive.md`;
- `architecture/dns_config_runtime_matrix.md`;
- `architecture/dns_application_neutral_readiness_phase109.md` via
  supersession pointer;
- `architecture/dns_runtime_dto_conversion_research.md`;
- `architecture/overview.md`;
- DNS agent/skill guidance;
- this roadmap and `plans/roadmap.md`.

Keep Phase 109/116/117 historical evidence intact.

## Workstream E — provider-inversion readiness decision

Evaluate remaining concrete edges separately:

### TLS

Can DNS depend on a narrow certificate/secure-transport capability without
mirroring `CertResolver` or ACME manager APIs?

Required proof before GO:
- SNI behavior;
- reload semantics;
- private-key ownership;
- ALPN;
- DoT/DoH/DoQ startup/failure parity.

### GeoIP

Can DNS consume a narrow lookup/steering provider without
`GeoIpManager`?

Required proof:
- missing DB behavior;
- unknown location;
- privacy/logging;
- health+Geo ordering;
- deterministic fallback.

### Mesh

Can optional DNS distributed-record behavior consume typed capabilities rather
than concrete `MeshTransport`/DHT/routing types?

Required proof:
- provenance;
- freshness;
- canonical-vs-advisory authority;
- DNSSEC metadata ownership;
- partition/failure behavior.

Record one terminal decision:

- **READY TO REGISTER PROVIDER INVERSION** — write/register a separate successor
  plan after this phase; or
- **DEFER** — list the missing seams/evidence.

Do not implement provider traits in Phase 130.

## Workstream F — class/support status

`synvoid-dns` remains class 1 throughout this campaign unless a later,
separately registered promotion phase satisfies the standalone contract.

No crates.io publication or new repository is authorized.

## Acceptance criteria

- config/core/utils edges are proven absent;
- adapter/runtime parity is exhaustive and green;
- full DNS/feature/repository qualification passes or explicit residuals are
  recorded;
- package consumer proves no hidden config/core/utils assumption;
- docs reflect the actual dependency graph;
- provider-inversion readiness receives an evidence-backed GO/DEFER decision;
- no class/support status is overstated.

## Rejection criteria

Reject qualification that:

- relies only on compile success;
- skips persisted/runtime parity;
- treats an outside-workspace package build as class-2 promotion;
- registers TLS/Geo/mesh provider inversion without separate evidence;
- rewrites historical DEFER records instead of superseding them;
- claims dependency reduction without `cargo metadata`/`cargo tree` proof.
