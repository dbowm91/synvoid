# Milestone D Roadmap: Workspace Debt Closure and Release Readiness

## Purpose

Milestone D follows the Milestone C deception-layer work. The current repository state is classified as **State B**: Milestone C is clean, while unrelated workspace debt remains. Milestone D turns that State B result into a full workspace release-readiness pass by closing the remaining tunnel, IPC, ignored-test, CI, dependency-tooling, and final-validation gaps.

Milestone D should be narrow. Do not reopen upload/archive/honeypot/tarpit architecture unless a workspace validation command proves a regression.

## Baseline from workspace validation

Known clean areas:

- Milestone A/B upload and honeypot hardening.
- Milestone C honeypot storage writer, threat-intel scoring, AI responder containment, tarpit safety, and operator docs.
- Targeted checks for upload, honeypot, tarpit, HTTP, DNS, WAF, proxy, config, plugin-runtime, and guard suites.

Known remaining blockers/debt:

- `synvoid-tunnel` clippy failures: `unnecessary_cast`, `too_many_arguments`.
- `synvoid-ipc` test clippy debt: `clone_on_copy`, `field_reassign_with_default`.
- `synvoid-tunnel` WireGuard feature gate issue: undeclared `wireguard_control` dependency under `--features wireguard`.
- 36 ignored tests: 34 dead overseer-to-supervisor refactor stubs, 2 real bidirectional proxy deadlock tests.
- Local `cargo-deny` / `cargo-audit` were unavailable during the workspace pass even though earlier cargo-deny was reported clean.
- CI lacks tarpit test job and a dedicated mesh integration test job.

## Milestone D phases

1. **Phase 1: Tunnel and WireGuard Feature Gate Closure**
   - Fix `synvoid-tunnel` clippy debt.
   - Correct or explicitly gate the WireGuard dependency path.
   - Add feature-specific compile tests for tunnel profiles.

2. **Phase 2: IPC and Remaining Workspace Clippy Cleanup**
   - Fix `synvoid-ipc` test clippy warnings.
   - Run workspace clippy profiles and eliminate avoidable warnings.
   - Use narrow `allow` only with justification.

3. **Phase 3: Ignored Test Inventory Cleanup**
   - Delete or resurrect 34 dead overseer/supervisor refactor stubs.
   - Triage and fix or isolate the 2 bidirectional proxy deadlock tests.
   - Produce an ignored-test status note.

4. **Phase 4: CI Coverage Parity for Tarpit, Mesh, Audit, and Workspace Gates**
   - Add dedicated tarpit CI job.
   - Add dedicated mesh integration job or explicit mesh-profile validation job.
   - Ensure cargo-deny/cargo-audit coverage is present and current.
   - Ensure CI summary reflects all jobs.

5. **Phase 5: Full Workspace Release Validation and Closure**
   - Run final workspace check/clippy/test/audit/deny matrix.
   - Commit `plans/milestone_d_validation_results.md`.
   - Classify the repo as full release-clean or release-clean with explicit tracked exceptions.

## Completion criteria

Milestone D is complete when:

- `cargo clippy --all-targets --all-features -- -D warnings` passes, or any remaining warnings are explicitly outside supported profiles and documented.
- `synvoid-tunnel` feature profiles compile, including clear WireGuard behavior.
- `synvoid-ipc` test clippy debt is resolved.
- Ignored tests are either removed, fixed, or explicitly documented as non-release-blocking.
- CI contains tarpit and mesh validation coverage.
- Dependency/security audit tooling is available locally or explicitly covered in CI with documented results.
- Final workspace validation results are committed.

## Non-goals

- Do not add new tunnel protocols.
- Do not implement new mesh features.
- Do not expand tarpit/honeypot behavior beyond Milestone C closure.
- Do not use blanket clippy suppression across crates.
- Do not mark the full repo release-clean without a committed validation artifact.
