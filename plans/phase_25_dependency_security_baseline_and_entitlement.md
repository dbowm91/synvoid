# Phase 25 Plan: Dependency Security Baseline and Entitlement Closure

Status: ready for implementation.

Roadmap position: Track 4, Phase 25 of `plans/track4_dependency_security_capability_segregation_roadmap.md`.

Primary goal: make SynVoid's dependency-security claims mechanically true before additional crate/process extraction begins.

## Context

The repository has strong architecture guards but a weaker dependency-security execution path. Routine CI runs `cargo xtask verify`; `verify_steps()` currently covers formatting, Clippy, a minimal compile, repo guards, security regressions, root guards, admin contract tests, and failure injection, but does not invoke `cargo deny` or `cargo audit`.

The root dependency ownership guard checks that every manifest dependency has a ledger row and that ledger classifications are valid/live. It does not check that the named owner path actually imports/uses the dependency. This permits entitlement drift after extractions.

The root manifest also documents a known test-feature leak: the dev-dependency on `synvoid = { path = ".", features = ["test-utils"] }` retains default features, so nominal no-default test runs still compile mesh/DNS and do not execute their absence branches.

Finally, the Wasmtime advisory rationale is stale. `RUSTSEC-2026-0269` / `GHSA-vqjp-4c8c-hfgg` affects Wasmtime 37.0.0 through 46.0.2 and is patched on that line at 46.0.3. SynVoid's direct runtime is 42.0.2. The vulnerable code is in `wasmtime-wasi` filesystem sandboxing, therefore exposure must be proven from the resolved feature/reachability graph; version 42.0.2 must not be described as patched for this advisory.

## Part A — Freeze a reproducible dependency/toolchain baseline

1. Add `rust-toolchain.toml` pinned to the chosen supported compiler, initially Rust 1.98.1 unless repository compatibility testing proves a different fixed stable is required.
2. Replace CI's floating `dtolnay/rust-toolchain@stable` behavior with the repository toolchain file.
3. Pin third-party GitHub Actions to immutable commit SHAs. Keep an inline comment with the human-readable release/tag for maintenance.
4. Pin the versions of `cargo-nextest`, `cargo-deny`, and `cargo-audit` used by CI/release verification. Do not depend on "latest" installs for release qualification.
5. Record the tool versions in `docs/testing/verification-contract.md` or a dedicated dependency-security section referenced from it.

Acceptance: a clean checkout builds/tests with the same Rust/tooling versions locally and in CI until maintainers intentionally bump them.

## Part B — Correct Wasmtime/YARA advisory handling

Run and preserve evidence for:

```bash
cargo tree -i wasmtime --workspace
cargo tree -e features -i wasmtime --workspace
cargo tree -i wasmtime-wasi --workspace
cargo tree -i yara-x --workspace
cargo audit
cargo deny check advisories
```

Required actions:

1. Separate the direct `synvoid-plugin-runtime` Wasmtime path from the transitive `yara-x` path in the evidence.
2. Upgrade the direct plugin runtime to a patched supported Wasmtime line. Prefer the smallest maintainable fixed line that passes plugin ABI/runtime tests; for `RUSTSEC-2026-0269`, 46.0.3 is the first patched release on the 46.x line and 47.0.4 is patched on 47.x. Do not preserve 42.0.2 merely because it fixed older advisories.
3. Reassess `[patch.crates-io] wasmtime = { git = ..., tag = "v42.0.2" }`. Remove the Git patch if a normal patched crates.io version satisfies the runtime. A security patch should not require an unnecessary Git source.
4. For any transitive vulnerable Wasmtime retained through `yara-x`, keep an ignore only if the exact dependency path is unavoidable until Phase 26 and the vulnerable capability is either process-isolated or shown unreachable. Each ignore must include:
   - dependency path;
   - affected runtime capability;
   - whether `wasmtime-wasi` is actually resolved/enabled;
   - exposure statement;
   - owner;
   - review/remove-by date tied to Phase 26 rather than a generic future date.
5. Add a regression/guard that rejects reintroduction of a known-vulnerable direct Wasmtime line once the upgrade lands.

Do not claim "not exploitable" from package presence alone; do not claim "vulnerable in production" from version alone. Record version, features, and reachable capability separately.

## Part C — Make dependency policy executable in CI

Extend the canonical verification contract rather than creating an unrelated shadow workflow.

Recommended split:

- routine PR/main blocking gate: `cargo deny check` using the pinned cargo-deny version;
- routine or dedicated blocking advisory gate: `cargo audit` against the current RustSec DB;
- scheduled security run (daily or weekly) so newly published advisories are detected even when the repo has no commit;
- release verification repeats both checks and records versions/results.

If advisory freshness makes the main job operationally noisy, separate advisories into a dedicated required job, but do not make the only advisory check permanently `continue-on-error`.

Update `cargo xtask verify` / `verify-release` and `docs/testing/verification-contract.md` so the executable contract and documentation agree.

## Part D — Tighten `deny.toml`

Using the pinned cargo-deny schema/version:

1. Keep yanked crates denied.
2. Change unknown registries from warning to deny unless SynVoid intentionally supports another registry.
3. Deny wildcard dependency requirements for production/workspace crates unless an explicit tooling exception is required.
4. Reassess unmaintained/unsound notices using the current cargo-deny schema. Do not leave `unmaintained = "none"` solely to silence output.
5. Convert advisory ignores to structured entries with reasons if supported by the pinned version, or retain comments with mandatory owner/review date if not.
6. Add a guard/test that fails on expired review dates or at minimum on ignore entries lacking a review/remove-by annotation.
7. Keep Git sources deny-by-default and reduce `allow-git` to the minimum required set; ideally empty after the Wasmtime patch is removed.

## Part E — Repair root dependency entitlement

Upgrade `root_dependency_ownership_guard` from inventory-only to entitlement-aware.

Implementation approach:

1. Extend the ledger with an `Allowed root paths` column (one or more prefixes) for direct non-workspace dependencies.
2. Build a source scanner that maps `use`/qualified crate references in compiled root source to dependency names, after stripping tests/comments where appropriate.
3. Fail if a direct dependency has no production consumer and is not explicitly `test_or_tooling`/build-only.
4. Fail if a dependency is consumed from a root path outside its ledger allowlist.
5. Keep exceptions narrow for macro-generated/proc-macro/build-script dependencies that cannot be mechanically attributed; each exception requires a reason.
6. Run an unused-dependency tool such as `cargo machete` as supporting evidence, but keep the in-repo guard authoritative because feature-gated and generated-code cases require project-specific interpretation.

Immediately reconcile stale ownership descriptions such as facade-era auth/challenge/proxy-cache ownership and the incorrect `stegoeggo` owner label if current source confirms worker image-rights is its root consumer.

## Part F — Remove orphan/stale facade source

Audit every module classified as `pure re-export facade`.

For each facade directory:

- enumerate files physically present;
- compare against modules declared by the facade;
- delete orphan implementation files after confirming no `#[path]`, include, build-script, or test use;
- add a static guard that pure-facade directories cannot contain undeclared `.rs` implementation files except an explicit allowlist such as `AGENTS.override.md`.

Start with `src/honeypot_port/storage.rs`, whose parent module is currently only `pub use synvoid_honeypot::*` while the canonical storage implementation lives in the crate.

## Part G — Make minimal-feature tests honest

Remove the root dev-dependency default-feature leak.

1. Set the self dev-dependency to `default-features = false`.
2. Explicitly feature-gate tests that truly require mesh or DNS.
3. Split feature-specific integration tests into targets with `required-features` where appropriate.
4. Ensure `cargo test --no-default-features` executes actual `cfg(not(feature = "mesh"))` and `cfg(not(feature = "dns"))` behavior rather than compiling those branches out.
5. Add a guard that detects future self-dev dependency default-feature leakage.
6. Update the admin contract feature matrix documentation after the absence branches become real.

## Part H — Dependency hygiene inventory

Produce a short machine-generated or checked-in report for direct/pre-release/duplicate dependencies:

- prerelease dependencies (`dashmap 7.0.0-rc2`, `notify 9.0.0-rc.3`, `openraft 0.10.0-alpha.18`, and any current equivalents);
- duplicated major versions with security/build impact;
- native/FFI dependencies;
- Git dependencies;
- build dependencies that execute code at build time.

Do not force upgrades merely to eliminate all duplicates. Classify each as justified, migrate when a stable compatible line exists, or assign a follow-up owner.

## Required tests/guards

Add or extend:

- `tools/synvoid-repo-guards/tests/module_ownership.rs` for root dependency path entitlement;
- a pure-facade orphan-source guard;
- a root self-dev feature-leak guard;
- dependency advisory ignore metadata validation;
- verification-contract tests/dry-run assertions so `cargo xtask verify` cannot silently drop dependency policy later.

## Documentation updates

At minimum update:

- `deny.toml` comments;
- `SECURITY.md`;
- `docs/testing/verification-contract.md`;
- `docs/RELEASE.md` / release checklist as applicable;
- `architecture/root_dependency_ownership.md`;
- `architecture/final_surface_audit.md` if profile truth changes;
- `AGENTS.md` to remove the no-default-feature test caveat after it is actually fixed.

## Acceptance criteria

Phase 25 is complete when:

- direct Wasmtime is on a patched line or a documented explicit decision proves the vulnerable WASI capability is absent and a removal date is set; 42.0.2 is no longer described as patched for 0269;
- every remaining ignored advisory has correct dependency-path and exposure evidence;
- `cargo deny` and `cargo audit` are executed by the canonical CI/release contract with pinned tool versions;
- Rust compiler and Actions are reproducibly pinned and intentionally updatable;
- nominal no-default test runs are genuinely no-default for mesh/DNS;
- the root dependency ledger reflects actual source ownership and guards unauthorized consumers;
- orphan facade implementation source is removed and guarded;
- security/release documentation matches executable CI behavior;
- `cargo xtask verify`, `verify-full`, and `verify-release` pass under their documented scopes.

## Rejection criteria

Reject closure if it:

- silences RustSec by adding broader ignores;
- treats absence of a PoC as proof of non-exposure;
- adds dependency checks only to documentation, not executable CI;
- keeps floating compiler/Action/tool versions while calling builds reproducible;
- fixes the test leak by deleting absence tests;
- marks root dependencies entitled solely because a ledger row exists;
- removes a facade file without proving it is unreachable.

## Verification commands

```bash
cargo xtask verify
cargo xtask verify-full
cargo xtask verify-release --allow-dirty   # during implementation only; final qualification should use clean tree
cargo deny check
cargo audit
cargo test --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo tree -i wasmtime --workspace
cargo tree -e features -i wasmtime-wasi --workspace
```

Record exact tool versions and advisory DB date in the phase closure evidence.