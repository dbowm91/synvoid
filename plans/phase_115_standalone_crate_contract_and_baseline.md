# Phase 115 Plan: Standalone Crate Contract and Dependency Baseline

Status: **CLOSED / ROUTINE QUALIFICATION DEFERRED** (2026-10-02).

Registered in: `plans/roadmap.md` and
`plans/standalone_crate_generalization_roadmap.md`.

Planning baseline: `main` at
`10ac2e330d74d012819c592b395f67ee8cc09a38`.

## Goal

Create a mechanical, testable distinction between:

- application-internal workspace crate;
- reusable class-2 crate;
- standalone-capable class-2 package;
- externally supported class-3 package.

This phase does not move production code between crates and does not publish
anything. It supplies the contract and reproducible dependency evidence required
by Phases 116–123.

## Why this phase exists

The current release policy intentionally distinguishes class 1/2/3, but the new
campaign needs a package-readiness state that is weaker than class 3. Without it,
adding an MSRV, README or packaged-consumer test can be misread as a support
promise, while "works as a workspace member" can be misread as standalone proof.

A standalone-capable class-2 package must be demonstrably consumable without
turning SynVoid into its external maintainer-of-record yet.

## Workstream A — define the standalone-capable class-2 contract

Add a binding architecture record, preferably
`architecture/standalone_crate_contract.md`, defining:

1. no root `synvoid` dependency;
2. no hidden root-relative files, build-script assumptions or undocumented
   environment variables;
3. no application-policy dependency such as `synvoid-config` or
   `synvoid-core`;
4. allowed paired low-capability leaves must be explicitly declared (for example
   DNS -> DNSSEC keystore);
5. package tarball builds outside the workspace;
6. at least one outside-workspace consumer test exercises the intended public
   surface;
7. features default to a useful, bounded behavior and heavy/native capabilities
   are opt-in where appropriate;
8. serialized/wire/storage surfaces are classified before they can be relied on
   externally;
9. package metadata may describe the crate accurately but MUST say that no class-3
   support promise exists unless promoted separately;
10. native security behavior is claimed only for natively qualified targets.

Do not weaken `architecture/public_crate_release_policy.md`; extend it by
reference or add a companion classification.

## Workstream B — dependency inventory

Generate a machine-readable snapshot for the candidate set:

- `synvoid-dns`;
- `synvoid-dnssec-keystore`;
- `synvoid-honeypot`;
- `synvoid-mesh`;
- `synvoid-mesh-protocol`;
- `synvoid-platform` sandbox surface;
- `synvoid-icmp-filter`;
- `synvoid-yara`;
- `synvoid-proxy-cache`;
- `synvoid-tarpit`.

For each record:

- direct normal SynVoid dependencies;
- optional SynVoid dependencies;
- expanded normal dependency tree size;
- feature graph;
- public exports;
- package contents;
- source references to root-relative paths/env/config;
- current class 1/2/3 status;
- current outside-workspace package proof, if any;
- current independent production consumers.

Use `cargo metadata --format-version 1` plus `cargo tree`; do not maintain a
handwritten dependency count that can silently drift.

## Workstream C — repo guard

Add a focused guard that can validate a small manifest/list of
"standalone-capable class 2" candidates. It must fail if a declared candidate:

- gains `synvoid`, `synvoid-config` or `synvoid-core` as a normal dependency;
- gains an undeclared sibling SynVoid dependency;
- loses required package metadata;
- is accidentally marked/promoted class 3 without the public-release record.

Do not require every class-2 crate to satisfy this contract.

## Workstream D — package-consumer harness

Create a reusable test helper under `tools/xtask` or test tooling that:

1. runs `cargo package -p <crate>`;
2. unpacks the generated crate into a temporary directory outside the workspace;
3. creates/uses a tiny consumer crate with a path dependency on the unpacked
   package;
4. runs build/test/doc checks with workspace environment variables removed;
5. records the exact feature set used.

Do not invoke network publication. The harness must be usable by later phases
without copy/pasted shell logic.

## Verification

Minimum:

```bash
cargo fmt --all -- --check
cargo test -p synvoid-repo-guards --profile ci
cargo test -p xtask --profile ci
cargo xtask verify
cargo deny check
cargo audit
```

Run the package-consumer harness against `synvoid-rate-limit` as a positive
control and at least one intentionally non-standalone crate as a negative
control.

## Acceptance criteria

- the four states (internal, reusable class 2, standalone-capable class 2,
  class 3) cannot be confused in current-authority documentation;
- a reusable command proves packaged-source consumption outside the workspace;
- dependency baseline exists for every campaign candidate;
- no production dependency or runtime behavior changes;
- no crate is published or moved to another repository;
- Phase 116/118/120/121/122 inputs are reproducible rather than relying on stale
  manual counts.

## Rejection criteria

Reject implementation that:

- equates package success with class-3 support;
- adds `publish = false` churn to all internal crates without a separate reason;
- hard-codes current dependency counts into a guard that cannot be regenerated;
- requires network access for routine CI package-consumer tests;
- creates a new repository or registry release.

## Formal closeout

Implementation commit: `c968594`.
Closeout evidence: `architecture/standalone_crate_phase115_closeout.md`.

The contract, generated inventory, focused guard, and positive/negative
packaged-consumer controls are complete. The focused tests passed. The required
full `cargo xtask verify` run did not complete: it was stopped during compilation
of the failure-injection target after earlier routine stages passed. The phase is
closed with that qualification residual explicitly deferred; it is not marked
`CLOSED QUALIFIED`.
