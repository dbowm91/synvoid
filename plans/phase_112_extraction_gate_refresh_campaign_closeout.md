# Phase 112 Plan: Extraction Gate Refresh and Campaign Closeout

Status: **IN PROGRESS — terminal campaign phase; release and hosted proof pending** (2026-10-02).

Registered in: `plans/roadmap.md` and
`plans/subsystem_boundary_extraction_roadmap.md`.

Planning baseline for registration: `main` at `19c0636535f3728e80b7c6777ec6a552c38c61a0` (2026-10-01).
Execute against the final implementation head of Phases 105–111.

Execution record: `architecture/subsystem_boundary_extraction_closeout.md`.
This phase cannot be formally closed until final-head verification and hosted
exact-SHA `ci` plus `dependency-security` both pass.

Owner: architecture / security / release.

## Goal

Qualify the maintenance-surface changes from Phases 105–111, refresh the
evidence-based extraction decisions for ICMP, process sandboxing, and YARA, and
leave the repository with one authoritative subsystem-boundary ledger.

This phase does not force extraction. It closes or registers follow-up work only
when concrete triggers have fired.

## Workstream A — recompute the final dependency graph

From the final implementation head record:

- workspace member count;
- internal direct/reverse edges;
- DNS edges before/after;
- honeypot edges before/after;
- mesh consensus/DHT edges before/after;
- tunnel/Eggstack dependency changes;
- any new external package dependencies;
- minimal/default feature graph deltas.

Do not copy expected diagrams from planning files.

## Workstream B — maintenance-surface evidence

For each campaign domain record what actually changed:

- LOC/modules deleted versus merely moved;
- direct/transitive dependency reduction;
- unsafe/native/security-sensitive code ownership;
- CI/native qualification burden;
- number of repositories that must move in lockstep;
- application-specific edges remaining.

Do not use raw crate count as the success metric.

## Workstream C — ICMP extraction trigger refresh

The Phase 88 disposition is RETAIN and remains authoritative unless evidence
changes it.

Re-evaluate the documented triggers against current head:

1. Linux nftables native qualification — later Phases 93/95 have now produced
   native proof; record this trigger as satisfied.
2. Other platform support tiers — identify which have native proof versus
   compile-only/experimental evidence.
3. Second real consumer — determine whether one now exists.
4. Publication hygiene — MSRV, README/examples, de-SynVoid naming,
   feature-gated observability, standalone tests.

Allowed outcomes:

- RETAIN;
- DEFER;
- register a future extraction/promotion plan if the remaining triggers are
  substantively satisfied.

Do not extract ICMP inside Phase 112.

## Workstream D — process sandbox trigger refresh and ecosystem differential

The current disposition is DEFER.

Re-check:

1. whether a second independent consumer now uses the guarantee contract;
2. native Linux + BSD evidence;
3. Windows launch-isolation status;
4. dependency/security health;
5. API stability since Phases 81–94.

Additionally perform a semantic comparison against current reusable Rust
sandbox projects (including Birdcage and Skarn or their current successors).

Map SynVoid's guarantee vocabulary:

- ambient filesystem denial;
- read/write allowlists;
- explicit deny;
- inherited resources/IPC;
- network denial;
- child creation;
- exec denial;
- descendant confinement;
- process/job memory bounds;
- owner termination;
- required/optional enforcement;
- enforcement report/evidence.

The decision question is whether SynVoid's guarantee/evidence model remains
meaningfully differentiated enough to justify independent maintenance.

Allowed outcomes: RETAIN/DEFER, adopt/contribute upstream, or register a future
extraction plan. Do not extract inside this phase.

## Workstream E — YARA extraction trigger refresh

The current YARA boundary is structurally application-neutral but external
movement is dependency-gated.

Re-check:

- latest official YARA-X release;
- resolved Wasmtime version/features;
- whether the temporary `third-party/yara-x-compat` fork can be removed under
  its existing security condition;
- current RustSec state;
- whether another real consumer such as Eggsec can use the
  compiler/scanner/artifact/executor API without SynVoid-specific branches.

If stock upstream now satisfies the security condition, register the narrow
upstream-fork-removal/adoption work first. Do not combine a YARA repository
extraction with an unqualified runtime-major migration.

If a second consumer exists and upstream is clean, a future standalone YARA
boundary plan may be registered.

## Workstream F — honeypot and DNS terminal decisions

Record the Phase 107 and Phase 109 dispositions.

If either is GO EXTRACT but the actual external repository migration has not
been separately approved/executed, state that clearly: "ready" is not
"extracted."

If extraction occurred under a separately approved handoff, prove SynVoid is
using a versioned dependency and no duplicate in-tree implementation remains.

## Workstream G — mesh and tunnel terminal state

Mesh:

- confirm no aggregate external mesh repo was created;
- confirm canonical/advisory authority tests remain green;
- record consensus/DHT boundary graph and any future extraction trigger.

Tunnel:

- record ownership across SynVoid/Eggtunnel/Eggress;
- identify generic duplication remaining intentionally;
- record released/pinned upstream versions if migrations landed;
- document deferred UDP/WireGuard/TUN items without overstating parity.

## Workstream H — architecture/release documentation reconciliation

Update current authority, as applicable:

- `architecture/overview.md`;
- `architecture/crate_granularity_audit.md`;
- DNS/honeypot/mesh/tunnel deep dives;
- public-crate release readiness/policy references;
- root/dependency ownership ledgers;
- `AGENTS.md` and subsystem skill pointers;
- `docs/releasing.md`;
- `plans/roadmap.md`;
- this campaign roadmap.

Historical closeouts receive supersession pointers only when needed.

## Workstream I — capability/security/performance qualification

Run the current full verification contract on the final head.

At minimum cover:

- default/minimal;
- DNS and mesh+DNS;
- honeypot;
- mesh;
- tunnel/VPN;
- jail/YARA;
- ICMP compile/native evidence referenced by current support tier;
- dependency security;
- release/package verification.

For touched hot paths, record before/after measurements only where comparable
fixtures exist. Explicitly identify evidence gaps instead of reporting zero
regression.

## Closeout artifact

Create:

`architecture/subsystem_boundary_extraction_closeout.md`

It must contain:

- implementation SHA range;
- proof-bearing SHA;
- hosted CI/security run IDs;
- dependency graph deltas;
- domain-by-domain maintenance-surface results;
- honeypot/DNS extraction decisions;
- ICMP/sandbox/YARA refreshed gates;
- mesh/tunnel disposition;
- accepted residuals;
- registered future plans;
- final campaign verdict.

## Verification

### Execution record (2026-10-02)

- Final dependency inventory: 53 workspace packages, 47 `synvoid-*` packages,
  1,037 total metadata packages, and 187 internal path edges across dependency
  kinds. These are current inventory counts, not campaign-wide reduction claims.
- `cargo xtask verify`: passed all 10 steps. The first attempt hit the known
  macOS XZ architecture mismatch; rerun with
  `PKG_CONFIG_PATH=/usr/local/opt/xz/lib/pkgconfig` passed.
- `cargo xtask verify-full`: passed all 10 steps. Nextest ran 7,896 tests
  across 217 binaries (8 skipped), followed by workspace doctests. The first
  full run found a deterministic partial-frame bounds panic in the
  `eggserve_plaintext_adoption` test helper; the decoder now waits for full
  16-bit headers/payloads, its focused test passed, and the complete rerun
  passed.
- Phase 112 hosted run `36948353038` passed CI and dependency-security on
  predecessor source SHA `12f52977901ee24ba74c5b9d90d19cea5624b420`; final
  hosted evidence for the test-helper correction is pending.
- `cargo xtask verify-release` and final local `cargo deny check` / `cargo
  audit` remain pending. The release command requires a clean committed tree.

At minimum:

```bash
cargo fmt --all -- --check
cargo xtask verify
cargo xtask verify-full
cargo xtask verify-release
cargo deny check
cargo audit
```

Plus focused affected-package suites and native lanes required by current support
claims.

Hosted exact-SHA CI/dependency-security proof is required for CLOSED QUALIFIED.

## Acceptance criteria

- current dependency graph matches documentation;
- no supported capability/config/wire/security authority is lost;
- maintenance reduction is demonstrated rather than inferred from crate count;
- ICMP/sandbox/YARA retain/defer/extract triggers are re-evaluated from current
  evidence;
- honeypot/DNS decisions are explicit;
- mesh remains authority-correct;
- tunnel ownership is reconciled with Eggtunnel/Eggress;
- no unresolved active plan is hidden by campaign closeout.

## Rejection criteria

Reject closeout that:

- marks an external repo extracted when only readiness was proven;
- overwrites historical RETAIN/DEFER evidence rather than superseding it;
- counts moved LOC as maintenance reduction;
- claims platform support from cross-compilation;
- closes with duplicate active generic implementations unexplained;
- hides dependency-security regressions;
- leaves `plans/roadmap.md` and architecture docs disagreeing with source.
