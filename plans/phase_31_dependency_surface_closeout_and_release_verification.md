# Phase 31 Plan: Dependency Surface Closeout and Release Verification

Status: complete (2026-09-12). Landing commit: `688fa74ee764f1b0efbd2d109814f93c418b99cb`. Closure evidence: `architecture/track4_dependency_security_closeout.md`. This was the final Track 4 closeout.

The body below is the executed handoff specification, preserved as historical implementation guidance.

Roadmap position: Track 4, Phase 31.

Primary goal: verify that the preceding security/capability extractions actually reduced authority and dependency coupling, remove residual transitional dependencies/facades, and leave one coherent release/security evidence set.

## Context

Track 4 intentionally adds only boundaries with measurable capability value. The final phase must therefore test the premise rather than merely count new crates. A successful closeout should show fewer high-risk dependencies in broad packages/processes, stronger executable dependency policy, and no erosion of Track 3 ownership contracts.

This phase is also where deferred ideas are decided with evidence. In particular, do not automatically create `synvoid-admin-server`, `synvoid-waf-runtime`, or `synvoid-sdk`. Reassess them against the final graph and create a follow-up only if they remove a meaningful dependency family, provide a genuine reusable surface, or are required for public API stability.

## Part A — Recompute the workspace dependency graph

Capture final metadata/tree evidence for every workspace package:

```bash
cargo metadata --all-features --format-version 1
cargo tree --workspace
cargo tree -d
cargo tree -i wasmtime --workspace
cargo tree -i wasmtime-wasi --workspace
cargo tree -i yara-x --workspace
cargo tree -i libloading --workspace
cargo tree -i cryptoki --workspace
cargo tree -i synvoid-mesh --workspace
cargo tree -i synvoid-mesh-protocol --workspace
```

Create/update `architecture/crate_granularity_audit.md` with Track 4 deltas:

- dependency isolation gained;
- feature/build isolation gained;
- reverse dependents;
- security/trust boundary;
- new cross-crate boilerplate/cost;
- keep/merge/defer verdict.

No crate receives a "keep" verdict solely because Track 4 created it; it must satisfy the same retention criteria as existing crates.

## Part B — Root direct dependency cleanup

Re-run the strengthened Phase 25 entitlement checks after all moves.

For every root `[dependencies]` entry:

- identify exact production owner paths;
- remove dependencies whose last root implementation moved to a crate;
- move test-only packages to `[dev-dependencies]`;
- preserve root dependencies required by actual composition/runtime behavior;
- verify target-specific dependencies separately;
- update `architecture/root_dependency_ownership.md` in the same commit.

Pay special attention to crypto, archive/filesystem, database, dynamic loading, YARA/WASM, mesh, and HTTP client dependencies whose ownership may have shifted.

## Part C — Feature/default surface review

Reassess default features from a deployment-security perspective after dependency isolation.

Current defaults include socket handoff, mesh, DNS, erased pool, and Swagger UI. Determine with artifact/dependency evidence whether the default binary should remain full-featured or whether a minimal recommended deployment profile should become the operator default.

Do not change defaults solely to shrink `cargo tree`. Consider:

- expected user compatibility;
- attack surface;
- binary size/startup cost;
- feature test coverage;
- operator surprise;
- release artifact strategy.

At minimum document a supported hardened/minimal profile and continuously compile/test it.

## Part D — Facade/public API cleanup

Audit every remaining root compatibility facade against `architecture/facade_disposition_matrix.md` and semver policy.

For pure facades:

- no orphan implementation source;
- no facade-only direct dependency unless re-export mechanics require it;
- canonical crate path documented;
- deprecation/removal policy explicit.

Evaluate an umbrella `synvoid-sdk` only if there is real demand for a stable aggregation crate after the application root becomes thinner. Criteria for creating it:

- external users need one dependency for multiple domain APIs;
- moving re-exports out of the application package substantially reduces root direct dependencies or publish coupling;
- semver/public API migration can be staged cleanly;
- it remains a pure aggregation surface with near-zero implementation.

Otherwise explicitly defer it. Do not add a crate merely to rename the facade problem.

## Part E — Reassess previously rejected extraction candidates

Using the final graph, re-evaluate:

- root admin composition vs hypothetical `synvoid-admin-server`;
- root WAF composition vs hypothetical `synvoid-waf-runtime`;
- egress layering (`http-client` / `upstream` / `tunnel`);
- `synvoid-filter` future merge candidate;
- app-server vs app-handlers.

Default verdict remains "no change" unless final dependency evidence shows a new, concrete advantage. Record the rationale in the granularity audit so future reviews do not reopen the same question without new evidence.

## Part F — Security policy closeout

Run with fresh databases/tooling:

```bash
cargo deny check
cargo audit
```

For every warning/advisory:

- fix;
- or retain a narrowly scoped exception with dependency path, capability exposure, owner, and review date.

No Track 4 temporary advisory exception may survive closeout without an explicit ongoing upstream blocker. In particular, remove temporary Wasmtime/YARA exceptions if Phases 25/26 eliminated the affected path.

Review source policy:

- no unexpected Git dependencies;
- no unknown registries;
- no malicious/yanked versions;
- lockfile checked in and reproducible;
- Actions/toolchain/tool versions pinned as defined by Phase 25.

## Part G — Release/package verification

Extend `cargo xtask verify-release` if needed to cover Track 4 artifacts:

- dedicated jail binaries included if Phase 29 produced them;
- native-extension compile profile clearly represented;
- no prohibited key/credential files in packages;
- publishable crate dependency order remains valid;
- new crates have license/repository/description metadata;
- crates intended only as internal runtime helpers have deliberate `publish = false` or a documented publication strategy;
- package-from-registry reconstruction is tested where practical.

Run clean-tree release qualification, not only `--allow-dirty`.

## Part H — Runtime/security regression pass

At minimum run:

- canonical `cargo xtask verify`;
- `verify-full`;
- `verify-release` on a clean tree;
- mesh partition/distributed-state suites;
- jail failure-injection/integration tests;
- plugin lifecycle/security tests;
- DNS conformance/interop for key-boundary changes;
- minimal/default feature profiles;
- targeted fuzz smoke for changed protocol/jail parsers.

Do not add all expensive suites to routine CI if the verified contract already classifies them as release/nightly/specialist. Record exact execution evidence.

## Part I — Final architecture evidence

Update current, non-historical documents:

- `architecture/root_module_ledger.md`;
- `architecture/root_dependency_ownership.md`;
- `architecture/root_module_burndown_report.md`;
- `architecture/final_surface_audit.md`;
- `architecture/crate_granularity_audit.md`;
- `architecture/release_hardening_report.md`;
- subsystem docs affected by new ownership;
- `AGENTS.md` architecture/stale-path/security sections;
- `plans/track4_dependency_security_capability_segregation_roadmap.md` status.

Create `architecture/track4_dependency_security_closeout.md` containing:

- before/after high-risk dependency table;
- advisory status;
- process/package capability map;
- final crate additions/removals;
- rejected/deferred extraction decisions;
- verification results;
- remaining explicit risks/upstream blockers.

Historical Track 1-3 plans/results remain archival and should not be rewritten to pretend they described Track 4.

## Acceptance criteria

Track 4 can close only when:

- Phase 25 dependency/security gates remain executable and green;
- high-risk dependency placement matches intended process/package authority;
- temporary YARA/Wasmtime/native-loader coupling is removed or explicitly justified;
- root direct dependency ledger is source-entitlement accurate;
- minimal/default feature behavior is truthful and tested;
- new crates pass the same granularity/retention criteria as old crates;
- no unnecessary admin/WAF/sdk crate was created without evidence;
- release packaging includes all required helper binaries and excludes secrets;
- current architecture/security docs agree;
- clean-tree release verification passes.

## Rejection criteria

Reject closeout that:

- reports fewer root dependencies while high-risk capability remains linked transitively into the same processes;
- retains Track 4 temporary advisory ignores without a current blocker/review date;
- treats crate count as the success metric;
- changes default features without compatibility/operator analysis;
- creates `synvoid-sdk` solely to move re-exports;
- declares release readiness without packaging the required jail/helper binaries;
- updates plan status without creating current architecture closeout evidence.

## Verification

```bash
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
./scripts/dns/conformance.sh
```

Store exact commands, tool versions, commit SHA, and results in the Track 4 closeout report.