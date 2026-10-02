# Subsystem Boundary and Extraction Roadmap (Phases 105–112)

Status: **CLOSED QUALIFIED — 2026-10-02**. Proof-bearing SHA `e7c0ec5a1317599b6f98e37a534b53544842a29c`; hosted CI and dependency-security run `36955732943` passed. No downstream extraction plan is unblocked; ICMP remains RETAIN, process sandbox and YARA remain DEFER.

Registered in: `plans/roadmap.md`.

Planning baseline: `main` at `19c0636535f3728e80b7c6777ec6a552c38c61a0`.

## Purpose

Reduce SynVoid's repository-level maintenance and audit surface by separating only
subsystems that have a defensible independent lifecycle, security model, and API
boundary. This is explicitly **not** a crate-count campaign and does not authorize
moving a large subsystem to another repository merely because it is large.

The campaign covers seven target domains researched against the current workspace
and ecosystem:

- DNS;
- honeypot/deception;
- ICMP policy/enforcement;
- process sandboxing;
- mesh/distributed networking;
- tunnel transport;
- YARA execution.

The intended end state is a smaller SynVoid ownership surface while preserving
all supported runtime capabilities and avoiding tightly synchronized repositories.

## Current researched disposition

### Honeypot/deception — application-neutral crate; extraction DEFER

`synvoid-honeypot` already owns its listener/runner, protocol detection,
responders, AI budgets, persistence, port rotation, threat-intelligence scoring,
and an injected `HoneypotThreatPublisher`. The previous direct mesh dependency is
gone.

Phase 106 CLOSED QUALIFIED at implementation SHA `a87d0b0c`: runtime config is
library-owned, persisted DTO translation remains in root, normal SynVoid
dependency edges are zero, and provider egress/publication are injected. The
adapter preserves persisted DTO semantics; current listeners support TCP only.

Phase 107 CLOSED **DEFER**: packaged-source and outside-workspace consumer
qualification passed, but no independent support promise, MSRV, user docs,
versioned storage schema, hard resource ceilings, parser fuzz campaign,
multi-target native evidence, or second production consumer exists. No external
repository or publication is authorized. Exact blockers and API classification
are recorded in `architecture/honeypot_standalone_qualification_phase107.md`.

Disposition: **RETAIN IN WORKSPACE / DEFER EXTRACTION** until a follow-up plan
owns those support and security prerequisites.

### DNS — Hickory qualified; application-neutral extraction DEFER

`synvoid-dns` depends on six required SynVoid siblings (config, core,
dnssec-keystore, geoip, tls, utils) and optional mesh. Phase 109 removed one
unused platform edge. Moving the current crate verbatim would export SynVoid
internals rather than create an independent service.

Phase 105 CLOSED QUALIFIED the Hickory family at 0.26.3 on proof-bearing SHA
`857d2e76dd453dc9dd0c84aa89bc1293cc8a1e1b`; exact-SHA hosted CI and
dependency-security passed in run `36922488692`.

Phase 108 CLOSED QUALIFIED: the current Hickory-backed message decode and
resolver/recursor delegation are confirmed; other protocol/server/transport
overlap remains owned until behavior parity is demonstrated. Phase 108 removed
no source/dependencies and claims no maintenance or size reduction. The source
coupling map and Phase 109 inversion requirements are recorded in
`architecture/dns_hickory_delegation_phase108.md`.

Phase 109 CLOSED **DEFER**: one unused `synvoid-platform` direct dependency was
removed; six required SynVoid siblings and optional mesh remain active. DNS
config, TLS/certificates, Geo, mesh and lifecycle capability inversions plus a
standalone consumer are still required. Exact source references and package
graph evidence are in `architecture/dns_application_neutral_readiness_phase109.md`.

Disposition: **RETAIN IN WORKSPACE / DEFER EXTRACTION** until the application
integrations are inverted and independently qualified. No external DNS repo is
ready or authorized.

### ICMP enforcement — boundary prepared, extraction remains RETAIN

Phases 85–95 produced the portable policy/compiler/enforcement boundary,
operator truth contract, qualification harness, and exact-SHA Linux nftables
native proof (Phase 95). That satisfies the Linux native trigger only. Other
lanes remain experimental/compile-only/unsupported; no second independent
consumer exists; MSRV, semver/support policy, examples, and observability
feature-gating remain publication gaps. Phase 112 rechecked these triggers.

Disposition: **RETAIN unless recorded re-evaluation triggers fire**. Do not reopen
the architecture merely because this campaign discusses extraction.

### Process sandbox — mature boundary, extraction remains DEFER

Phases 81–94 already established the guarantee-oriented sandbox contract
(`Guarantee`, `SandboxRequest`, `EnforcementReport`,
`PreparedSandbox`/`EnteredSandbox`) and corrected backend semantics.

Extraction remains gated on a second independent consumer, native Linux plus
BSD evidence, Windows launch-isolation disposition, API stability, and a fresh
ecosystem comparison. Phase 112 compared Birdcage (archived) and current Skarn;
the guarantee/evidence contract remains specialized but has adjacent
alternatives. No extraction is justified without another real consumer and
support proof.

Disposition: **DEFER unless triggers fire**.

### Mesh — retain internal; no consensus/DHT extraction qualified

`synvoid-mesh` still has live config, tunnel, proxy, proxy-cache, and serverless
edges in adapters/dispatch. Phase 110 mapped ownership and confirmed that
consensus/DHT modules do not yet form an application-service-free one-way seam.
No crate, source edge, or LOC was removed; protocol docs now clarify Rust/wire
compatibility and replay assumptions.

Disposition: **RETAIN INTERNAL**. No external mesh repository is authorized.
Reconsider only after transport dispatch, neutral config and identity
capabilities are narrowed and dependency metadata proves reduced reachability.

### Tunnel — retain pending Eggtunnel protocol evidence

The Eggtunnel checkout/API was unavailable during Phase 111. Inspected Eggress
source exposes generic byte relay and proxy/H3 QUIC/UDP mechanisms but does not
establish authenticated tunnel wire/session parity. SynVoid owns its framing,
session lifecycle, datagrams, VPN/TUN/WireGuard, route and mesh integration; no
migration is safe without Eggtunnel source and mixed-version evidence.

Disposition: **DEFER convergence**. Reopen when Eggtunnel source and tested API
version are available. Do not create `synvoid-tunnel.git`.

### YARA — neutral boundary; upstream and second-consumer gates remain closed

`synvoid-yara` has no SynVoid internal dependency and is structurally
application-neutral. Official YARA-X 1.21.0 (released 2026-09-29) still
resolves Wasmtime 45.0.3; the manifest-only fork pins 48.0.3 to clear the
current advisory set. Eggsec does not depend on or consume `synvoid-yara`, so
there is no second real consumer.

Disposition: **DEFER repository extraction**. Re-evaluate when an official
YARA-X release resolves a Wasmtime line satisfying the security gate and a
second real consumer adopts the neutral API.

## Binding constraints

1. No supported SynVoid capability may be removed to make extraction easier.
2. Configuration and persisted wire/storage formats remain compatible unless an
   independently reviewed migration is explicitly planned.
3. A repository extraction must leave SynVoid consuming a narrow versioned API;
   it must not introduce a new repo that imports SynVoid application crates.
4. Existing Phase 81–101 RETAIN/DEFER decisions remain authoritative until their
   documented triggers are re-proven.
5. Generic mechanism code should move toward existing Eggstack owners where one
   exists rather than creating competing repositories.
6. Public-support status is separate from crate/repository location. Moving code
   does not automatically make an API class-3/stable.
7. Security-sensitive native claims require native evidence. Cross-compilation is
   build evidence only.
8. Any new standalone project must have explicit MSRV, semver, threat/support
   model, examples, packaged-outside-workspace proof, and dependency-security
   policy before SynVoid can treat it as an independently supported dependency.
9. Historical closeouts are not rewritten. Current-authority docs gain
   supersession/re-evaluation notes where necessary.
10. Do not combine DNS simplification, honeypot extraction, mesh decomposition,
    and tunnel convergence into one mechanical refactor.

## Execution order

Two workstreams may start immediately and in parallel:

1. **Phase 105 — DNS Hickory patch adoption and security requalification.**
2. **Phase 106 — honeypot application-neutral boundary preparation.**

Then:

3. **Phase 107 — honeypot standalone qualification and extraction decision.**
4. **Phase 108 — DNS delegate/retain audit and ownership simplification.**
5. **Phase 109 — DNS application-neutral boundary and extraction readiness.**
6. **Phase 110 — mesh consensus/DHT internal boundary decomposition: CLOSED RETAIN INTERNAL.**
7. **Phase 111 — SynVoid tunnel / Eggtunnel / Eggress convergence: CLOSED DEFER.**
8. **Phase 112 — extraction gate refresh and campaign closeout: CLOSED QUALIFIED.**

Phase 108 depends on Phase 105 so the Hickory comparison is made against the
qualified current dependency line. Phase 109 depends on Phase 108. Phase 107
depends on Phase 106. Phases 110 and 111 may execute after Phase 105/106 without
waiting for Phase 107/109 if implementation capacity permits, but the final
cross-campaign reconciliation is Phase 112.

## Detailed plans

- `plans/phase_105_dns_hickory_patch_security_requalification.md`
- `plans/phase_106_honeypot_application_neutral_boundary.md`
- `plans/phase_107_honeypot_standalone_qualification_extraction_decision.md`
- `plans/phase_108_dns_hickory_delegation_ownership_simplification.md`
- `plans/phase_109_dns_application_neutral_boundary_extraction_readiness.md`
- `plans/phase_110_mesh_consensus_dht_boundary_decomposition.md`
- `plans/phase_111_tunnel_eggtunnel_eggress_convergence.md`
- `plans/phase_112_extraction_gate_refresh_campaign_closeout.md`

## Campaign success criteria

This campaign succeeds if it produces measurable maintenance-surface reduction,
not merely more packages:

- honeypot either becomes demonstrably standalone-ready or receives a precise
  RETAIN decision with blockers after SynVoid-specific dependencies are removed;
- DNS runs on the qualified Hickory patch line and no longer maintains redundant
  baseline DNS machinery without an explicit reason;
- DNS application integrations are expressed through narrow adapters rather than
  broad SynVoid crate dependencies where practicable;
- mesh gains one-way low-capability consensus/DHT seams without changing
  canonical-vs-advisory distributed authority;
- generic tunnel/session/relay mechanisms are not duplicated between SynVoid and
  Eggtunnel/Eggress;
- ICMP, sandbox, and YARA extraction status is refreshed from evidence without
  weakening earlier gates;
- current architecture, release, and planning registries agree with the compiled
  dependency graph;
- default/minimal and affected feature profiles remain qualified.

## Rejection criteria

Reject implementation that:

- creates a standalone repo whose library depends on `synvoid-config`,
  `synvoid-core`, root `synvoid`, or another application-specific SynVoid
  crate without a documented unavoidable reason;
- publishes an API merely because it moved repositories;
- treats Hickory feature overlap as permission to delete SynVoid semantics
  without parity evidence;
- moves `synvoid-mesh` wholesale while its application-service dependencies
  remain;
- creates a new tunnel repository instead of adjudicating Eggtunnel/Eggress
  ownership;
- silently changes DNS wire/security semantics, mesh authority, honeypot
  retention/privacy defaults, or YARA artifact behavior;
- converts skipped native evidence into a support claim;
- reopens closed RETAIN/DEFER decisions without satisfying their documented
  triggers.

## Post-closeout corrective / follow-up registration

The Phase 105–112 campaign remains **CLOSED QUALIFIED** on proof-bearing SHA
`e7c0ec5a1317599b6f98e37a534b53544842a29c` with hosted
`ci` + `dependency-security` run `36955732943`.

Two post-closeout plans are registered without reopening the campaign's tested
implementation state:

1. **Phase 113 — Subsystem Boundary Closeout Evidence Reconciliation**
    - Plan:
      `plans/phase_113_subsystem_boundary_closeout_evidence_reconciliation.md`.
    - Status: **CLOSED QUALIFIED** (2026-10-02; docs-only reconciliation).
   - Repairs stale Pending verification/status text in current authority only.
   - Does not change production code, dependencies, proof-bearing SHA, or
     DEFER/RETAIN dispositions.

2. **Phase 114 — Tunnel / Eggtunnel Protocol Parity and Convergence Refresh**
    - Plan:
      `plans/phase_114_tunnel_eggtunnel_protocol_parity_and_convergence_refresh.md`.
    - Status: **CLOSED QUALIFIED** (2026-10-02; RETAIN + DEFER relay reuse; evidence `architecture/tunnel_eggtunnel_parity_phase114.md`; no migration, no cross-repo plan registered, nothing unblocked).
   - Re-runs only Phase 111's cross-repo evidence gap against actual
     `eggstack/eggtunnel` source.
   - Research baseline:
     `eggstack/eggtunnel@ece46fd223265b7b0609e3640b0caa9efadd1535`.
   - Must distinguish the published Eggtunnel `0.2.0` wire 1.0 artifact from
     current repository source that implements wire 1.1 while retaining the
     same workspace version.
   - Produces ADOPT / ADAPT / UPSTREAM / RETAIN / DEFER dispositions before any
     production migration.
   - Any missing generic Eggtunnel/Eggress mechanism receives its own plan in
     the owning repository; no permanent SynVoid fork or unplanned git
     dependency is authorized.

These plans do not alter the terminal campaign decisions for honeypot, DNS,
ICMP, sandbox, YARA, or mesh. Phase 114 has produced the source-backed
evidence (`architecture/tunnel_eggtunnel_parity_phase114.md`, RETAIN +
DEFER relay reuse); tunnel convergence remains DEFER and no separately
registered implementation/upstream plan was warranted.



## Successor campaign (Phases 115–123)

The Phase 105–114 extraction campaign remains historically CLOSED QUALIFIED.
A new monorepo-first successor is registered at
`plans/standalone_crate_generalization_roadmap.md`.

The successor does not reverse the historical DEFER/RETAIN evidence by fiat.
Instead it distinguishes internal crate boundaries and standalone-capable class-2
packages from external repository/public-support decisions. DNS and mesh reopen
only their application-neutral capability seams; sandbox reopens only internal
crate-granularity; honeypot/DNSSEC-keystore/mesh-protocol reopen explicit package
hardening gaps. Any external extraction still requires a later gate after Phase
123.
