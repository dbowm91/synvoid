# Phase 101 Plan: Architecture Maintenance Qualification and Closeout

Status: planned/open.

Registered in: plans/roadmap.md and plans/architecture_maintenance_auditability_roadmap.md.

Planning baseline: main at 30e68af8f6e79ce0fe07f0c1871f1d0caa6be6f2. Execute only after Phases 96-100 are implemented.

Depends on: Phases 96, 97, 98, 99, and 100.

## Goal

Prove that the post-95 maintenance campaign improved dependency direction and auditability without reducing SynVoid capability, changing security authority, or introducing material performance/release regressions.

This is a qualification and reconciliation phase. Do not hide unfinished implementation work inside the closeout.

## Workstream A — recompute the workspace graph from source of truth

Use cargo metadata and cargo tree on the final implementation head.

Record:

- workspace member count;
- internal dependency edges and reverse dependencies;
- direct dependency counts for touched crates;
- feature-gated edges;
- duplicate versions relevant to touched dependency families;
- before/after graph for metrics/WAF, block-store/WAF, jail runtime/IPC, HTTP/H3, config/model, mesh application consumers.

Update architecture/crate_granularity_audit.md or its current superseding authority with the actual final graph.

Do not copy expected counts from planning documents.

## Workstream B — capability-preservation matrix

Build a concrete before/after matrix for supported capabilities.

At minimum cover:

- minimal WAF/reverse-proxy data plane;
- default build;
- H1 plaintext and TLS H1;
- H2;
- HTTP/3;
- WAF block/pass/challenge/tarpit behavior;
- admin routes and config mutation;
- mesh startup required/optional/disabled;
- Raft/canonical and advisory DHT behavior;
- DNS with and without mesh;
- WASM jail;
- YARA jail;
- upload scanning including mesh rule source where enabled;
- honeypot mesh integration where enabled;
- tunnels/VPN feature compile paths;
- ICMP feature compile path;
- unsafe-native-extension remains opt-in/off by default.

No row may be closed with "not tested because refactor only" when the refactor touched that capability boundary.

## Workstream C — configuration compatibility proof

Re-run config golden fixtures and bounded fuzz/parsing coverage.

Prove:

- current tracked example/default configs still load;
- no supported field/default disappeared;
- reduced-feature binaries still reject unsupported capability-bearing sections;
- config model/runtime separation did not make validation order or errors silently weaker;
- mesh identity/key realization produces the same results for known-answer fixtures.

If any intentional error-message wording changes, distinguish wording from validation semantics.

## Workstream D — protocol and wire compatibility proof

Jail:

- golden SVJL v1 vectors byte-identical;
- protocol version remains 1;
- dedicated jail binary packaging/version output correct;
- real WASM/YARA round trips pass.

HTTP:

- H1/H2/H3 policy parity suites green;
- no duplicate security-normalization owner introduced.

Mesh:

- protocol/wire compatibility tests green;
- canonical/advisory authority tests green;
- no distribution format changed incidentally.

## Workstream E — security and dependency qualification

Run the repository's current dependency-security contract on the exact implementation head.

At minimum:

    cargo deny check
    cargo audit

Record existing accepted advisories separately from new findings.

Confirm:

- new low-capability crates obey their dependency budgets;
- no new unsafe/native loader ownership was introduced;
- no crypto/private-key dependency migrated into an inappropriate low-level crate;
- no new git dependency or untracked vendoring was introduced without explicit policy;
- temporary third-party compatibility patches retain their existing removal tracking.

## Workstream F — performance and footprint evidence

Measure only the surfaces touched by this campaign.

Required comparisons:

- WAF/request metrics recording after AttackType decoupling;
- block-store block/unblock hot path;
- jail frame encode/decode and process round-trip;
- HTTP/3 request path/streaming;
- config parse/startup if the model split changes construction;
- representative mesh message/DHT/canonical/proxy paths;
- release binary/package size and dependency delta for minimal/default builds.

Use existing benchmark harnesses where possible.

A small statistically noisy delta is not a regression claim. Investigate material repeatable changes and either correct them or record an explicit accepted residual with rationale.

## Workstream G — architecture and operator documentation reconciliation

Update current-authority docs, not historical closeouts, including as applicable:

- architecture/overview.md;
- architecture/crate_granularity_audit.md/current superseding record;
- architecture/root_dependency_ownership.md if root edges changed;
- architecture/sandbox_jail_protocol.md;
- architecture/http_deep_dive.md / http3_deep_dive.md;
- architecture/config.md / config_deep_dive.md;
- architecture/mesh.md / mesh_trust_domains.md / distributed_state_contract.md;
- docs/releasing.md;
- AGENTS.md and subsystem overrides/skills that name canonical owners.

Historical phase closeouts should receive supersession pointers only when necessary; do not rewrite old evidence as if it was produced on the new head.

## Workstream H — adjudicate future simplification/extraction candidates

Re-evaluate, but do not automatically implement:

### Mesh consensus

A future synvoid-mesh-consensus plan is justified only if the final graph shows:

- one-way dependency on low-level protocol/types;
- no application-service dependencies;
- transport through a narrow trait/adapter;
- independent persistence/state-machine invariants;
- measurable audit/dependency benefit.

If those conditions do not hold, record RETAIN and the exact blocker.

### synvoid-filter

Re-evaluate the 134-line filter crate only if the final graph produces a concrete maintenance benefit from merging it. Do not merge for crate count.

### Process manager vs IPC

After jail protocol extraction, reassess whether generic process-manager ownership can be separated from IPC without creating cycles or weakening process lifecycle semantics. Register a future plan only if the boundary is now demonstrably clean.

No candidate is implemented in Phase 101.

## Final verification

Run the repository-defined current verification commands, including:

    cargo fmt --all -- --check
    cargo xtask verify
    cargo xtask verify-full
    cargo xtask verify-release
    cargo deny check
    cargo audit

Run focused tests from Phases 96-100 and the supported feature-profile matrix.

Hosted CI/dependency-security on the exact proof-bearing SHA is required for terminal CLOSED status. Local success alone may be recorded as implementation-complete/pending hosted proof, not final closure.

## Closeout artifact

Create architecture/architecture_maintenance_auditability_closeout.md containing:

- implementation SHA range;
- exact proof-bearing SHA;
- hosted run IDs/results;
- dependency graph deltas;
- capability-preservation matrix;
- protocol/config compatibility evidence;
- security/dependency result;
- performance/footprint deltas;
- accepted residuals;
- future-plan decisions;
- final verdict.

Update the umbrella roadmap and plans/roadmap.md to closed only after that artifact exists and evidence is complete.

## Acceptance criteria

- All Phases 96-100 implementation criteria are satisfied.
- No supported capability is lost.
- No config/wire/security authority regression is observed.
- Intended dependency edges are actually removed/narrowed in cargo metadata.
- New low-capability boundaries have enforceable dependency budgets.
- Performance/footprint results contain no unexplained material regression.
- Current architecture docs match the compiled graph.
- Exact-head local and hosted verification is green.
- Future extraction candidates receive GO/RETAIN/DEFER decisions based on the final graph, not enthusiasm for smaller crates.

## Rejection criteria

Reject closeout if it:

- counts moved files/crates as evidence of improvement;
- omits feature profiles affected by the refactor;
- changes config/wire behavior without explicit compatibility treatment;
- marks hosted proof green without an observed exact-SHA run;
- hides a new dependency/security advisory;
- rewrites historical evidence to manufacture continuity;
- starts a new extraction inside the qualification phase;
- closes with architecture docs and cargo metadata disagreeing.
