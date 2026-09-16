# Phase 35 Plan: Crate Boundary and Reuse Closeout

Status: planned (2026-09-16).

Roadmap: `plans/crate_boundary_reuse_followup_roadmap.md`.

Primary goal: reconcile the post-Phase-31 architecture after platform canonicalization, rate-limit extraction, and reusable-library cleanup; verify that every new boundary has measurable value; and leave current documentation, dependency ownership, release behavior, and public/reuse policy consistent with the compiled workspace.

## Part A — Recompute the workspace graph

Capture fresh graph evidence after Phases 32-34:

```bash
cargo metadata --all-features --format-version 1
cargo tree --workspace
cargo tree -d
cargo tree -e features --workspace
cargo tree -i synvoid-platform --workspace
cargo tree -i synvoid-rate-limit --workspace
cargo tree -i synvoid-dnssec-keystore --workspace
cargo tree -i synvoid-http-client --workspace
cargo tree -i eggfetch-core --workspace   # if adopted
```

Update `architecture/crate_granularity_audit.md` with actual LOC, reverse dependencies, internal dependencies, independent invariants, feature/build isolation, and reuse value. Do not preserve a "keep" verdict for `synvoid-rate-limit` merely because Phase 33 created it; it must meet the same retention bar as every other crate.

## Part B — Ownership reconciliation

Update and cross-check:

- `architecture/root_module_ledger.md`;
- `architecture/root_dependency_ownership.md`;
- `architecture/root_module_burndown_report.md`;
- `architecture/final_surface_audit.md`;
- `architecture/platform.md`;
- `architecture/crate_granularity_audit.md`;
- relevant WAF/rate-limit architecture notes;
- egress/HTTP ownership notes;
- `AGENTS.md` canonical ownership table and any affected subsystem skills.

No document may claim a crate is canonical while an active duplicate implementation remains in the root package.

## Part C — Root utility cleanup

Re-audit `src/utils` after the rate-limit move and platform cleanup.

For each remaining helper, classify it as:

- root/application-specific;
- canonical `synvoid-utils` candidate;
- standard-library/existing-crate replacement;
- stale/dead.

Likely candidates for consolidation include generic result/option extensions, formatting helpers, host/port parsing, URL decoding, IP hashing, and hot collection aliases. Move only helpers with multiple consumers and stable semantics.

Do not turn `synvoid-utils` into an unbounded dumping ground. In particular:

- helpers that implement approximate SemVer should not be advertised as SemVer unless replaced by a real semantic-version implementation;
- network-interface discovery based on connecting to a public resolver should remain explicitly heuristic or be replaced with a correct platform mechanism;
- application error strings belong near their domain rather than in a generic utility crate.

Add ownership comments/tests for any helper retained at root.

## Part D — Reusable/public library policy

Classify workspace crates into one of:

1. application-internal implementation detail;
2. reusable workspace library with no external support promise;
3. reasonable crates.io/public-library candidate;
4. compatibility facade/transitional surface.

Evaluate at minimum:

- `synvoid-platform`;
- `synvoid-rate-limit` if created;
- `synvoid-dnssec-keystore`;
- `synvoid-filter`;
- `synvoid-yara`;
- `synvoid-mesh-protocol`;
- any retained generic surface in `synvoid-http-client`.

A public-library candidate should have:

- application-neutral API names;
- no dependency on root `synvoid`;
- narrowly justified internal dependencies;
- crate-level docs/examples;
- explicit MSRV/rust-version policy;
- license/repository/description metadata;
- deterministic tests;
- no hidden runtime requirement on SynVoid configuration/layout;
- a semver-support statement.

Do not publish automatically as part of this phase unless release policy explicitly calls for it. The deliverable is a support/publication decision, not registry churn.

## Part E — Feature and package verification

Re-run default/minimal feature analysis after any dependency changes.

Verify:

- `--no-default-features` remains the hardened/minimal supported profile;
- platform/rate-limit crates do not accidentally enable mesh/DNS/HTTP3/HSM features;
- HSM/PKCS#11 remains opt-in;
- eggfetch features, if used, are selected minimally;
- no old Hyper/Rustls client stack remains reachable solely through stale compatibility code after a completed migration;
- package metadata includes any new crate and release/publish ordering remains valid.

If a new crate is internal-only, use deliberate `publish = false` or document why it remains publishable.

## Part F — Static guards

Add or update repository guards for the ownership contracts established by the roadmap.

At minimum enforce:

- no redefinition of canonical platform traits/types under root `src/platform`;
- no domain dependency from `synvoid-rate-limit` upward into WAF/mesh/admin/IPC/config;
- no root `synvoid` import from reusable leaf crates;
- no `synvoid-config` dependency in DNSSEC keystore unless Phase 34 explicitly justified it;
- no reintroduction of `StreamingWafBody`-style WAF policy into a generic HTTP transport owner;
- facade thinness where compatibility paths are retained.

Guards should validate architectural invariants, not exact file lengths or brittle formatting.

## Part G — Security and correctness regression

Run:

```bash
cargo deny check
cargo audit
cargo xtask verify
cargo xtask verify-full
cargo xtask verify-release
```

Also run the targeted suites from Phases 32-34, including platform, rate-limit, DNSSEC custody, egress parity, WAF, mesh, IPC, proxy/upstream, and feature-profile tests.

Review all new unsafe code. The roadmap should preferably reduce duplicate unsafe/platform code; any new unsafe block must have a local safety invariant and testable preconditions.

## Part H — Performance and footprint comparison

Capture before/after evidence where the changes affect hot paths or dependency footprint:

- rate-limit hot-path microbenchmarks;
- default and minimal release binary sizes;
- dependency count/features for HTTP egress before/after any eggfetch adoption;
- cold build/check impact where useful;
- no additional allocation/lock on per-request limiter checks;
- no measurable regression in proxy request path attributable to adapter layering.

The purpose is to catch architectural cleanup that accidentally increases runtime cost or footprint.

## Part I — Final closeout report

Create `architecture/crate_boundary_reuse_closeout.md` containing:

- implemented phases and commit SHAs;
- before/after ownership table;
- duplicate code removed;
- new crate(s) created and why they passed the retention test;
- extraction ideas rejected/deferred and why;
- eggfetch decision and evidence;
- reusable/public-library classification;
- dependency/security deltas;
- performance/footprint deltas;
- verification commands/results;
- remaining explicit risks or future triggers.

Historical Phase 31 and earlier closeouts remain unchanged except for forward references where current docs require them.

## Acceptance criteria

This roadmap can close only when:

- platform ownership documentation matches the actual compiled source owner;
- no duplicate generic platform implementation remains;
- `synvoid-rate-limit`, if present, has multiple real consumers and a low dependency surface;
- mesh/WAF no longer rely on ownership stubs for a shared limiter primitive;
- reusable DNSSEC custody APIs remain fail-closed and application-light;
- egress transport has one deliberate maintenance owner, or any retained overlap is explicitly transitional with an exit condition;
- root utilities have an explicit ownership disposition;
- crate-granularity audit and dependency-ownership ledger are current;
- minimal/default feature profiles pass;
- architecture guards encode the new boundaries;
- release/security verification passes.

## Rejection criteria

Reject closeout that:

- counts crates instead of checking dependency/authority value;
- leaves documentation claiming canonical ownership that the compiler does not enforce;
- keeps both SynVoid and eggfetch generic HTTP stacks without a documented transitional need and exit condition;
- publishes internal crates merely because their APIs look reusable;
- moves application policy into low-level libraries to make the root appear smaller;
- accepts hot-path regressions without evidence and rationale;
- closes without current dependency/security verification.

## Verification matrix

At minimum:

```bash
cargo fmt --all -- --check
cargo xtask verify
cargo xtask verify-full
cargo xtask verify-release
cargo deny check
cargo audit
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo nextest run --workspace --cargo-profile ci --profile ci --exclude synvoid-fuzz
cargo test --workspace --doc --profile ci
```

Add the targeted Phase 32-34 tests/benchmarks to the closeout evidence and record exact toolchain/commit versions.
