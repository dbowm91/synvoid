# DNS Runtime-DTO Conversion Roadmap — Phases 125–130

Status: **ACTIVE** (2026-10-04). Phases 125-128 are **CLOSED QUALIFIED**;
Phase 129 is **READY**. Phase 130 remains sequenced behind it.

Registered in: `plans/roadmap.md`.

Planning baseline: `main` at `f86f99d1ba239cd32e423dede232d684cfeb8fa2`.

Research authority:
`architecture/dns_runtime_dto_conversion_research.md`.

## Purpose

Implement the deferred Phase 116 DNS runtime-config/core neutralization work in
bounded, reversible slices while preserving all existing DNS behavior,
fail-closed config semantics, DNSSEC custody, transport behavior and
authoritative/recursive separation.

This campaign does **not** perform TLS/Geo/mesh provider inversion and does not
promote `synvoid-dns` to standalone class 2. Its job is to remove the
application/config/helper edges that block that later work.

Target dependency reduction at campaign close:

```text
before:
synvoid-dns
  -> synvoid-config
  -> synvoid-core
  -> synvoid-tls
  -> synvoid-utils
  -> synvoid-geoip
  -> synvoid-dnssec-keystore
  -> synvoid-mesh (optional)

after:
synvoid-dns
  -> synvoid-tls
  -> synvoid-geoip
  -> synvoid-dnssec-keystore
  -> synvoid-mesh (optional)
```

The exact result must be proven by `cargo metadata` / `cargo tree`, not
assumed from this roadmap.

Baseline re-measured 2026-10-04 (before and after Phase 126): **7** direct
SynVoid normal edges and **847** expanded
`cargo tree -p synvoid-dns -e normal` lines (the Phase 123 closeout recorded
7 / 838; the 9-line difference is pre-existing manifest drift, not a campaign
change). Phase 126 moved no manifest entries by design — Phase 128 owns the
`synvoid-config` removal and Phase 129 the `synvoid-core`/`synvoid-utils`
removal. Phase 130 must re-measure rather than assume 838 is still exact.

## Binding architecture

Persisted configuration remains application-owned:

```text
crates/synvoid-config/src/dns/**
        |
        | deserialize + existing fail-closed validation
        v
src/server/dns_runtime_config.rs
        |
        | application-owned conversion / normalization
        v
crates/synvoid-dns/src/runtime_config.rs
        |
        v
DNS runtime
```

Rules:

1. `src/dns/` remains a pure re-export facade. No adapter logic goes there.
2. `synvoid-config` must never depend on `synvoid-dns`.
3. Unsupported/deferred persisted fields remain fail-closed in
   `DnsConfig::validate()` and are absent from the initial runtime API.
4. DNS-owned runtime types should use parsed domain types where useful
   (`SocketAddr`, `Duration`, `PathBuf`, parsed networks).
5. Do not expose Hickory's non-exhaustive resolver config structs as the stable
   SynVoid runtime contract; lower DNS-owned values to Hickory internally.
6. DNSSEC private-key custody remains in `synvoid-dnssec-keystore`.
7. Provider inversion for TLS, GeoIP and mesh is explicitly outside Phases
   125–130.
8. RPZ, prefetch, custom trust-anchor lifecycle, response padding, QNAME privacy,
   unwired rebinding behavior and unsupported anycast behavior are not made real
   merely because DTO ownership changes.
9. No persisted TOML/admin API shape changes are authorized.
10. No class/support/publication status changes are authorized.

## Execution order

1. **Phase 125 — Runtime DTO contract, ownership matrix and adapter parity**
   — **CLOSED QUALIFIED** (2026-10-04);
   `architecture/dns_runtime_dto_phase125_closeout.md`.
2. **Phase 126 — Authoritative server and encrypted-transport runtime cutover**
   — **CLOSED QUALIFIED** (2026-10-04);
   `architecture/dns_runtime_dto_phase126_closeout.md`.
3. **Phase 127 — Recursive resolver runtime-config cutover** — **CLOSED
   QUALIFIED** (2026-10-04);
   `architecture/dns_runtime_dto_phase127_closeout.md`.
4. **Phase 128 — Zone/DNSSEC/TSIG/HSM conversion and synvoid-config removal** —
   **CLOSED QUALIFIED** (2026-10-04);
   `architecture/dns_runtime_dto_phase128_closeout.md`. The `synvoid-config`
   normal edge is removed: 6 direct SynVoid normal edges (was 7), 846 expanded
   `cargo tree -e normal` lines (was 847).
5. **Phase 129 — synvoid-core / synvoid-utils neutralization** — **READY**
   (unblocked by Phase 128). Its dependency gates already exist in
   `tools/synvoid-repo-guards/tests/dns_dependency_edges.rs`, landed
   `#[ignore]`d so the suite stays green until the phase that owns them.
6. **Phase 130 — Campaign qualification and provider-inversion readiness gate** —
   PLANNED, BLOCKED ON PHASE 129.

The phases are intentionally sequential. Each changes the canonical constructor
or configuration ownership used by the next phase and is a rollback/evidence
boundary.

## Campaign success criteria

- production `crates/synvoid-dns/src/**` contains zero `synvoid_config`
  references;
- normal `synvoid-config` dependency is removed from `synvoid-dns`;
- normal `synvoid-core` and `synvoid-utils` dependencies are removed;
- persisted DNS schema, defaults and typed unsupported-path errors remain
  behaviorally identical;
- root composition constructs DNS runtime values through one canonical adapter;
- DNS crate tests use DNS-owned runtime types rather than persistence DTOs;
- zone activation, recursive isolation, DNSSEC/TSIG, encrypted transports,
  cache/RRL/firewall/ECS/DNS64/coalescing and shutdown behavior retain parity;
- direct SynVoid dependency reachability falls measurably;
- no provider-inversion/class-2 claim is made before Phase 130.

## Campaign rejection criteria

Reject a closeout that:

- mechanically copies all of `DnsConfig` into `synvoid-dns`;
- lets runtime construction bypass `DnsConfig::validate()`;
- places adapter code under the pure `src/dns/` facade;
- makes `synvoid-config` depend on `synvoid-dns`;
- changes TOML/OpenAPI/admin schema as a side effect;
- exposes unsupported config knobs as apparently usable runtime API;
- weakens TSIG/HSM secret handling or DNSSEC custody;
- uses file movement rather than dependency evidence as success;
- performs TLS/Geo/mesh provider inversion inside this campaign.
