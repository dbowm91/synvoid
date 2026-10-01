# Subsystem Boundary and Extraction Roadmap (Phases 105–112)

Status: **ACTIVE / REGISTERED — 2026-10-01**.

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

### Honeypot/deception — strongest near-term extraction candidate

`synvoid-honeypot` already owns its listener/runner, protocol detection,
responders, AI budgets, persistence, port rotation, threat-intelligence scoring,
and an injected `HoneypotThreatPublisher`. The previous direct mesh dependency is
gone.

Phase 106 CLOSED QUALIFIED at proof-bearing SHA `a87d0b0c`: the runtime config
is library-owned, persisted DTO translation remains in the root application,
and normal SynVoid dependency edges are zero. Provider egress and threat
publication are injected. The adapter preserves the persisted DTO vocabulary;
the existing range/count runtime cannot exactly represent sparse port lists,
and current listeners support TCP only. Storage hard limits and platform file
permissions remain unqualified for external support. Phase 107 is READY to run
packaged consumer, release hygiene, and threat-model qualification before an
extraction decision.

Phase 107 CLOSED **DEFER**: packaged-source and outside-workspace consumer
qualification passed, but no independent support promise, MSRV, user docs,
versioned storage schema, hard resource ceilings, parser fuzz campaign,
multi-target native evidence, or second production consumer exists. No external
repository or publication is authorized. Exact blockers and API classification
are recorded in `architecture/honeypot_standalone_qualification_phase107.md`.

Disposition: **RETAIN IN WORKSPACE / DEFER EXTRACTION** until a follow-up plan
owns those support and security prerequisites.

### DNS — strong candidate after simplification and dependency inversion

`synvoid-dns` is a coherent independently deployable service, but the crate
currently depends on SynVoid config/core/TLS/GeoIP/platform/utils/keystore and
optionally mesh. Moving the current crate verbatim would export SynVoid internals
rather than create a clean independent service.

Phase 105 CLOSED QUALIFIED the Hickory family at 0.26.3 on proof-bearing SHA
`857d2e76dd453dc9dd0c84aa89bc1293cc8a1e1b`; exact-SHA hosted CI and
dependency-security passed in run `36922488692`. Phase 108 is unblocked and
ready. SynVoid's custom DNS implementation must be audited against
functionality now owned by Hickory.

Disposition: **GO MAINTAIN + SIMPLIFY**, then **GO PREPARE** an application-neutral
boundary if the simplification evidence supports it.

### ICMP enforcement — boundary prepared, extraction remains RETAIN

Phases 85–95 already produced the portable policy/compiler/enforcement boundary,
operator truth contract, qualification harness, and Linux nftables native proof.
The formal Phase 88 extraction decision remains RETAIN because the crate still has
one real consumer, incomplete native evidence outside Linux, and publication
hygiene/support-burden gaps.

Disposition: **RETAIN unless recorded re-evaluation triggers fire**. Do not reopen
the architecture merely because this campaign discusses extraction.

### Process sandbox — mature boundary, extraction remains DEFER

Phases 81–94 already established the guarantee-oriented sandbox contract
(`Guarantee`, `SandboxRequest`, `EnforcementReport`,
`PreparedSandbox`/`EnteredSandbox`) and corrected backend semantics.

Extraction is still gated on a second consumer, broader native proof, Windows
launch-isolation disposition, API stability, and a fresh comparison against
current reusable Rust sandbox libraries.

Disposition: **DEFER unless triggers fire**.

### Mesh — decompose internally, do not repo-extract the aggregate

`synvoid-mesh` still carries application dependencies including config, tunnel,
proxy, proxy-cache, and serverless. Phase 101 correctly retained mesh consensus
because no application-service-free state-machine boundary existed.

Disposition: **GO internal consensus/DHT decomposition**. No external mesh repo is
authorized by this campaign.

### Tunnel — converge with Eggstack, do not create another repository

`eggstack/eggtunnel` already owns an embeddable authenticated tunnel protocol
and client/server runtime over Eggress transports. SynVoid's tunnel crate still
owns additional UDP/datagram, VPN, TUN/WireGuard, route and mesh integration
semantics.

Disposition: **GO convergence matrix + generic-mechanism migration**. Do not create
`synvoid-tunnel.git`.

### YARA — clean boundary, repository move remains upstream-gated

`synvoid-yara` has no SynVoid internal dependency and is structurally close to
standalone. However SynVoid currently carries a narrow manifest-only YARA-X
compatibility fork to keep the transitive Wasmtime line on a security-qualified
version. Stock YARA-X 1.21.0 does not satisfy the current fork-removal condition.

Disposition: **DEFER repository extraction** until upstream/dependency and
second-consumer triggers are re-evaluated.

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
6. **Phase 110 — mesh consensus/DHT internal boundary decomposition.**
7. **Phase 111 — SynVoid tunnel / Eggtunnel / Eggress convergence.**
8. **Phase 112 — deferred extraction-gate refresh and campaign closeout.**

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
