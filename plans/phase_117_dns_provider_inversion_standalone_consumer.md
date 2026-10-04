# Phase 117 Plan: DNS Provider Inversion and Standalone Consumer Qualification

Status: **CLOSED DEFER — PHASE 116 PREDECESSOR NOT DELIVERED** (2026-10-02).

Registered in: `plans/roadmap.md` and
`plans/standalone_crate_generalization_roadmap.md`.

Predecessors: Phase 116 must close with runtime config/core ownership neutralized.

## Goal

Remove the remaining SynVoid application-service dependencies from
`synvoid-dns` by replacing concrete TLS, GeoIP, mesh/health and lifecycle
objects with narrow DNS-owned capabilities. Then prove the packaged crate from
outside the workspace.

This phase decides **standalone-capable class 2**, not crates.io publication or a
new repository.

## Workstream A — certificate / secure-transport capability

Replace direct `synvoid-tls::CertResolver` and ACME runtime ownership in DNS
constructors with a DNS-owned provider contract for the minimum material/events
required by DoT, DoH, DoQ and secure server startup.

The capability must preserve:

- SNI selection;
- certificate/key reload behavior;
- ALPN requirements;
- certificate expiry/error behavior;
- ACME DNS challenge interaction where applicable;
- private-key ownership rules.

Do not design a generic TLS framework. The API should describe what DNS needs.

SynVoid implements the adapter using `synvoid-tls`.

## Workstream B — Geo/steering capability

Replace concrete `GeoIpManager` reachability with a minimal lookup value/service
contract.

The contract must preserve:

- missing-database behavior;
- unknown-country/location behavior;
- privacy boundaries (no raw location data added to logs/metrics);
- current health+Geo steering order;
- deterministic fallback when provider data is unavailable.

Tests must use fake providers; the DNS crate must not need MaxMind or
`synvoid-geoip` to exercise its core server.

## Workstream C — mesh/distributed record capability

The optional `mesh` feature currently reaches concrete SynVoid mesh transport,
DHT/registry/routing and DNSSEC metadata behavior.

Define the minimum DNS-facing capabilities, likely separated by authority:

- record/registration source;
- node health source;
- change/event stream or snapshot source;
- canonical DNSSEC metadata source where required.

The interface must carry provenance/freshness/authority explicitly enough that an
advisory mesh record cannot silently become canonical DNS state.

SynVoid's `synvoid-mesh` adapter remains above the DNS crate.

Do not expose generic `MeshMessage`, DHT store or routing-manager types in the
DNS API.

## Workstream D — application-neutral lifecycle

Ensure server startup/shutdown/drain can be driven by neutral handles/cancellation
tokens owned by DNS or std/Tokio contracts.

No Supervisor/worker/process type may leak into the package API.

## Workstream E — dependency topology target

Target normal package topology:

```text
synvoid-dns
  -> synvoid-dnssec-keystore   # deliberate paired security leaf
  -> Hickory / Tokio / rustls / QUIC / storage / protocol dependencies
  -> no synvoid-config
  -> no synvoid-core
  -> no synvoid-tls
  -> no synvoid-geoip
  -> no synvoid-utils
  -> no synvoid-mesh
```

If a mesh adapter requires a sibling crate, locate that adapter in SynVoid
composition or a clearly application-owned adapter crate; do not make the generic
DNS crate depend on `synvoid-mesh`.

## Workstream F — outside-workspace qualification

Using the Phase 115 harness, package `synvoid-dns` and construct a consumer
outside the workspace that exercises:

1. authoritative zone serving;
2. ordinary resolution/forwarding or recursor path appropriate to the current
   supported API;
3. DNSSEC signing through the keystore boundary;
4. DoT and at least one HTTP/QUIC encrypted transport;
5. fake Geo/health provider;
6. fake distributed record source;
7. clean startup and drain;
8. fail-closed provider errors.

No root config files or SynVoid environment variables may be available to the
consumer.

## Workstream G — differentiation / duplication decision

Record what the now-neutral package provides above Hickory. Compare each retained
major subsystem to Hickory server/library capabilities.

Classify retained code as:

- Hickory delegation;
- SynVoid-derived but independently useful runtime/policy mechanism;
- application adapter that should move out;
- redundant behavior eligible for a separately proven deletion/upstream plan.

If the independent layer proves too thin to justify standalone support, retaining
the crate in the monorepo is an acceptable result.

## Verification

Run all Phase 116 checks plus:

```bash
cargo package -p synvoid-dns --allow-dirty
cargo publish -p synvoid-dns --dry-run
cargo xtask <standalone-consumer-command> synvoid-dns
RUSTDOCFLAGS="-D warnings" cargo doc -p synvoid-dns --no-deps
cargo xtask verify-full
cargo xtask verify-release
```

No actual publish.

## Acceptance criteria

- zero normal application-specific SynVoid dependencies, with the DNSSEC
  keystore as the only explicitly allowed sibling if still required;
- outside-workspace consumer exercises real serving/security/transport paths;
- Hickory ownership versus SynVoid-added ownership is documented;
- SynVoid adapters preserve existing config, mesh authority, TLS and Geo behavior;
- package can be marked standalone-capable class 2 if and only if the Phase 115
  contract passes;
- no repository extraction or class-3 support is implied.

## Rejection criteria

Reject implementation that:

- defines "provider traits" that merely mirror entire SynVoid manager APIs;
- loses provenance/freshness/authority on distributed records;
- passes only an in-workspace unit test;
- calls a DNS package independent while it reaches root files/env/process state;
- publishes or moves the crate externally under this phase.

## Status reconciliation

Phase 116 closed DEFER because persisted DNS configuration remains present in
public constructors and runtime modules. This phase is therefore blocked before
implementation. Do not introduce provider interfaces or claim standalone
qualification until Phase 116 reopens, completes runtime DTO ownership and
passes its config-parity gate. See
`architecture/standalone_crate_phase116_closeout.md`.

## Formal closeout

Disposition: **DEFER**, closed without provider inversion or package changes.
Phase 116's complete DNS-owned runtime DTOs and application-boundary config
parity were prerequisites and were not delivered. Starting a TLS/Geo/mesh
provider conversion against persisted-config public constructors would create a
partial boundary and could not satisfy this phase's outside-workspace behavior
proof. Reopen only after Phase 116 is completed and qualified. Phase 123 may
record this explicit DEFER as the DNS track outcome. No standalone claim is made
for `synvoid-dns`.
