# Phase 115 Closeout — Standalone Contract and Dependency Baseline

Plan: `plans/phase_115_standalone_crate_contract_and_baseline.md`.
Implementation commit: `c968594` (`feat: add standalone crate contract and consumer harness`).
Date: 2026-10-02.

## Result

The binding standalone-capable class-2 contract is in
[`standalone_crate_contract.md`](standalone_crate_contract.md). The candidate
registry starts empty: a crate is added only after a later phase proves the
contract. The reproducible ten-package candidate snapshot is
[`standalone_crate_dependency_baseline.json`](standalone_crate_dependency_baseline.json),
generated from Cargo metadata, Cargo normal dependency trees, `cargo package
--list`, package manifests, and package source scanning. Regenerate it with
`cargo xtask standalone baseline`.

`cargo xtask standalone consumer <package> [--features a,b]` packages the crate,
extracts it under the system temporary directory, and tests a path-dependent
consumer outside the workspace with Cargo workspace variables removed and
network access disabled. `--consumer-src PATH` supplies the actual public API
smoke test; `synvoid-rate-limit` has a built-in public API smoke test.

## Evidence

- `cargo fmt --all -- --check`: passed.
- `cargo test -p synvoid-repo-guards --profile ci`: 123 passed.
- `cargo test -p xtask --profile ci`: 45 passed.
- `cargo xtask standalone baseline`: generated 10 records.
- `cargo xtask standalone consumer synvoid-rate-limit`: packaged-source public
  API test passed outside the workspace, offline.
- `cargo xtask standalone consumer synvoid --expect-fail`: negative control
  passed; root application package verification fails because `synvoid-admin`
  has no registry package, proving the workspace-only dependency.
- `cargo audit`: completed with six existing allowed unmaintained-dependency
  warnings and no error.
- `cargo deny check`: completed without reported errors.
- `cargo xtask verify`: **not completed**. It passed formatting, lint/build,
  security regression, repo guards (123/123), root tests (647/647), and admin
  contract tests (67/67), then was stopped while compiling the failure-injection
  target after prolonged contention on the shared build directory. This phase is
  therefore closed with routine-verification qualification deferred; no claim
  of a complete `cargo xtask verify` is made.

## Disposition and next phases

Phase 115's contract, candidate snapshot, guard, and reusable package consumer
are implemented. The remaining routine verification is an explicit residual,
not an inferred pass. Its implementation outputs are sufficient inputs for
Phases 116, 118, 120, 121, and 122; the routine-verification residual does not
change their technical dependencies. Phase 117 remains gated on Phase 116, and
Phase 119 remains gated on Phase 118. Phase 123 remains gated on final outcomes
from those tracks. No package was promoted to class 3 or published.
