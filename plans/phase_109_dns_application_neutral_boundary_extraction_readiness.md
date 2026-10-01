# Phase 109 Plan: DNS Application-Neutral Boundary and Extraction Readiness

Status: **PLANNED — blocked on Phase 108**.

Registered in: `plans/roadmap.md` and
`plans/subsystem_boundary_extraction_roadmap.md`.

Planning baseline for registration: `main` at `19c0636535f3728e80b7c6777ec6a552c38c61a0` (2026-10-01).
Implementation must rebase on the Phase 108 closeout SHA.

Owner: DNS / architecture / release / security.

## Goal

Turn the simplified DNS subsystem into an application-neutral package boundary
and decide whether it is ready to move to an independent repository.

Unlike Phase 108, this phase changes dependency direction. The DNS runtime should
own DNS concepts; SynVoid should supply application integrations through narrow
adapters.

## Workstream A — classify remaining SynVoid dependencies

Recompute actual source usage for each remaining internal edge:

- `synvoid-config`;
- `synvoid-core`;
- `synvoid-tls`;
- `synvoid-geoip`;
- `synvoid-platform`;
- `synvoid-utils`;
- `synvoid-dnssec-keystore`;
- optional `synvoid-mesh`.

For each edge classify it as:

- DNS-domain mechanism that should move/own locally;
- generic external dependency that can replace the SynVoid wrapper;
- application adapter that must be inverted;
- justified retained sibling relationship.

The target independent DNS package must not require the SynVoid application
runtime.

## Workstream B — DNS-owned configuration model

Define DNS-owned runtime configuration types for:

- listener addresses/transports;
- authoritative zones;
- recursion/upstreams;
- cache/limits;
- DNSSEC/trust;
- update/transfer/notify policy;
- firewall/RPZ policy;
- Geo/health steering inputs;
- optional HSM references without embedding SynVoid config types.

Keep SynVoid's persisted config schema stable through an exhaustive translation
adapter.

Do not move `MainConfig` or application-wide configuration behavior into the
DNS project.

Golden fixtures must prove existing tracked SynVoid DNS config remains readable
and equivalent.

## Workstream C — invert mesh integration

Replace optional `synvoid-mesh` ownership inside the DNS engine with one or
more narrow DNS-facing capabilities, such as:

- dynamic record source;
- node-health source;
- registration/event sink;
- canonical distributed-state reader.

Names are illustrative; derive the minimum traits from actual call sites.

The DNS crate must not know about Raft/DHT internals, SynVoid mesh config,
serverless, proxy, or other mesh services.

SynVoid owns the adapter from its distributed-state authority model into these
DNS capabilities.

Preserve canonical/advisory authority rules. An injected mesh-fed record must not
become authoritative merely because the trait is generic.

## Workstream D — invert GeoIP and health steering

Make DNS steering consume an application-neutral lookup/value contract.

Options:

- a narrow `GeoLookup`/steering trait;
- neutral precomputed location/region input;
- a generic database implementation owned by the DNS project if justified.

Do not make the candidate repo depend on `synvoid-geoip`.

Preserve existing missing-database/fallback semantics and avoid leaking raw
location data into metrics/logs beyond current policy.

## Workstream E — TLS/certificate boundary

Audit what `synvoid-tls` actually supplies to DoT/DoH/DoQ.

Prefer DNS-owned neutral TLS policy and certificate/key material or a narrow
certificate-provider interface. The independent DNS runtime must not import
SynVoid server TLS/application config.

Preserve:

- certificate verification semantics;
- PQ/provider policy if it is a documented DNS requirement;
- SNI/ALPN;
- reload behavior;
- private-key custody boundaries.

Do not duplicate TLS parsing if rustls/Hickory already supplies the mechanism.

## Workstream F — platform/utils/core cleanup

Remove application-neutral dependencies by:

- std/direct crate use where appropriate;
- small DNS-owned primitives;
- narrow platform traits only where anycast/socket behavior genuinely needs
  specialization.

Do not create a general-purpose compatibility crate as an extraction crutch.

## Workstream G — DNSSEC keystore topology

Keep `synvoid-dnssec-keystore` as a low-capability sibling candidate rather
than reintegrating private-key custody into the DNS engine.

Decide whether an extracted DNS repository should initially contain:

- DNS runtime crate;
- DNSSEC keystore crate.

Do not create a separate keystore repository in this phase.

Re-evaluate its existing external-support blockers: threat model, HSM matrix,
zeroization/secret-lifetime review, crash consistency, platform permissions,
PKCS#11 qualification, and retained RSA advisory exposure.

## Workstream H — standalone package/consumer proof

Build/test the DNS package outside SynVoid and construct a minimal standalone
consumer capable of:

- loading DNS-owned config;
- serving a synthetic authoritative zone;
- performing recursive resolution where supported;
- exercising DNSSEC;
- running at least one encrypted transport;
- using fake/in-memory Geo/health and record-source adapters;
- shutting down cleanly.

No SynVoid crate may be required by this proof except a sibling DNSSEC keystore
that is explicitly part of the proposed DNS repository topology.

## Workstream I — extraction decision

Allowed dispositions:

- **GO EXTRACT**;
- **DEFER** with exact remaining blocker;
- **RETAIN** if independent repo/release burden exceeds demonstrated maintenance
  benefit.

A GO decision must define:

- repository/crate topology;
- versioning/MSRV policy;
- wire/config compatibility policy;
- supported transport/platform matrix;
- security/threat model;
- SynVoid adapter ownership;
- migration order from path dependency to versioned external dependency.

No publication is automatic.

## Verification

At minimum:

```bash
cargo test -p synvoid-dns --profile ci
cargo test -p synvoid-dns --profile ci --features mesh
cargo test -p synvoid-dnssec-keystore --profile ci
cargo xtask verify
cargo xtask verify-full
cargo xtask verify-release
cargo deny check
cargo audit
```

Plus packaged-outside-workspace and standalone-consumer proof.

## Acceptance criteria

- DNS runtime has no broad SynVoid application dependency;
- persisted SynVoid configuration remains compatible via adapter;
- mesh and Geo/health integrations are narrow and authority-safe;
- TLS/certificate ownership is application-neutral;
- keystore custody remains separate;
- standalone consumer works without SynVoid;
- GO/DEFER/RETAIN is recorded from evidence.

## Rejection criteria

Reject a GO decision that:

- depends on `synvoid-config`, `synvoid-mesh`, root `synvoid`, or another
  application runtime crate;
- weakens DNSSEC/HSM/key-custody semantics;
- turns mesh advisory state into DNS authority;
- changes persisted config without migration;
- claims all DNS features supported merely because modules compile;
- moves the current crate to a new repository with its old dependency graph.
