# Workspace-wide Validation Pass

## Purpose

This plan validates the entire SynVoid workspace after the Milestone A/B upload and honeypot hardening line. The upload/honeypot work is locally clean, license metadata has been added, and `cargo deny check` is reported passing. The next step is to determine whether the full repository is release-clean or whether unrelated workspace issues remain.

This is a validation and triage pass, not a feature pass. The objective is to produce a reproducible, crate-by-crate and feature-by-feature status map, fix small validation blockers where safe, and produce clear handoff notes for anything larger.

## Current baseline

Known-good from recent local validation notes:

- `cargo fmt --all -- --check`: pass.
- `cargo clippy -p synvoid-upload --all-targets -- -D warnings`: pass.
- `cargo test -p synvoid-upload --release`: pass, 169 tests.
- `cargo clippy -p synvoid-honeypot --all-targets -- -D warnings`: pass.
- `cargo test -p synvoid-honeypot --release`: pass, 105 tests.
- `cargo deny check`: pass, advisories/bans/licenses/sources OK.

Known caveat from earlier validation:

- A prior workspace-level `cargo check --all-targets` reportedly had 3 pre-existing errors in `src/http/server/accept_loop.rs`. This must be rechecked and either closed, confirmed stale, or tracked as a release blocker.

## Scope

In scope:

- Workspace manifest and metadata validation.
- Full workspace format, check, clippy, and test matrix.
- Per-crate compile/test isolation.
- Feature matrix validation for important crates.
- Existing CI workflow sanity, even if GitHub Actions is not authoritative.
- Release-blocker triage.
- Documentation/status note updates.

Out of scope:

- New product features.
- New archive formats beyond current ZIP support.
- New honeypot/tarpit behavior.
- Large architecture refactors unless required to unblock workspace build.
- Treating unrelated historical failures as Milestone B regressions without evidence.

## Workstream 1: Manifest and metadata sanity

### Tasks

1. Run metadata checks:

```bash
cargo metadata --no-deps
cargo metadata --all-features --no-deps
```

2. Verify root workspace metadata:

- `[workspace.package]` is valid.
- license expression is accepted by cargo and cargo-deny.
- repository URL is correct.
- authors field is acceptable.
- all first-party crates that use `license.workspace = true` resolve properly.

3. Check for crates not covered by the recent license metadata update:

```bash
find . -name Cargo.toml -not -path './target/*' -print
```

For each manifest, confirm one of:

- it is a workspace member and has license metadata, or
- it is an example/fuzz/admin tool intentionally excluded from first-party release checks, or
- it needs metadata added.

4. Check package naming consistency:

- crate names use `synvoid-*` where intended.
- no accidental duplicate package names.
- examples/fuzz/admin UI manifests are classified correctly.

### Success criteria

- `cargo metadata` passes for default and all-features modes.
- Every first-party package has a clear license metadata story.
- Non-release manifests are explicitly classified.

## Workstream 2: Baseline workspace compile

### Tasks

1. Run default workspace checks:

```bash
cargo check --workspace
cargo check --workspace --all-targets
```

2. Run all-features check if feasible:

```bash
cargo check --workspace --all-features
cargo check --workspace --all-targets --all-features
```

3. If `src/http/server/accept_loop.rs` errors still exist, isolate them:

```bash
cargo check --all-targets 2>&1 | tee /tmp/synvoid-check-all-targets.log
rg -n "accept_loop|error\[E" /tmp/synvoid-check-all-targets.log
```

4. Classify each compile failure:

- regression introduced by recent upload/honeypot work
- pre-existing unrelated failure
- feature-gated missing dependency
- stale API boundary
- test-only compile failure
- platform-specific issue

5. Fix small, low-risk compile failures immediately if they are mechanical:

- missing import
- stale type name
- missing field after struct expansion
- feature gate mismatch
- obvious function signature mismatch

6. If a failure requires design work, create a separate plan file rather than patching opportunistically.

### Success criteria

- Default `cargo check --workspace` passes.
- `cargo check --workspace --all-targets` passes or remaining failures are documented with exact crate/file/error and a follow-up plan.
- Any `accept_loop.rs` failure is either fixed or explicitly marked as a release blocker.

## Workstream 3: Per-crate validation matrix

### Tasks

Run a crate-by-crate validation sweep. Start with core infrastructure, then network/edge crates, then optional subsystems.

Recommended order:

1. Core/config/util:

```bash
cargo check -p synvoid-utils --all-targets
cargo test -p synvoid-utils --all-targets
cargo check -p synvoid-config --all-targets
cargo test -p synvoid-config --all-targets
cargo check -p synvoid-core --all-targets
cargo test -p synvoid-core --all-targets
```

2. HTTP/WAF/upload/honeypot:

```bash
cargo check -p synvoid-waf --all-targets
cargo test -p synvoid-waf --all-targets
cargo check -p synvoid-http --all-targets
cargo test -p synvoid-http --all-targets
cargo check -p synvoid-upload --all-targets
cargo test -p synvoid-upload --all-targets
cargo check -p synvoid-honeypot --all-targets
cargo test -p synvoid-honeypot --all-targets
```

3. Mesh/DNS/TLS/proxy:

```bash
cargo check -p synvoid-mesh --all-targets
cargo test -p synvoid-mesh --all-targets
cargo check -p synvoid-dns --all-targets
cargo test -p synvoid-dns --all-targets
cargo check -p synvoid-tls --all-targets
cargo test -p synvoid-tls --all-targets
cargo check -p synvoid-proxy --all-targets
cargo test -p synvoid-proxy --all-targets
```

4. Plugin/runtime/serverless/platform/admin:

```bash
cargo check -p synvoid-plugin-runtime --all-targets
cargo test -p synvoid-plugin-runtime --all-targets
cargo check -p synvoid-serverless --all-targets
cargo test -p synvoid-serverless --all-targets
cargo check -p synvoid-platform --all-targets
cargo test -p synvoid-platform --all-targets
cargo check -p synvoid-admin --all-targets
cargo test -p synvoid-admin --all-targets
```

5. CLI/app/tunnel/cache/static:

```bash
cargo check -p synvoid-cli --all-targets
cargo test -p synvoid-cli --all-targets
cargo check -p synvoid-app-server --all-targets
cargo test -p synvoid-app-server --all-targets
cargo check -p synvoid-app-handlers --all-targets
cargo test -p synvoid-app-handlers --all-targets
cargo check -p synvoid-tunnel --all-targets
cargo test -p synvoid-tunnel --all-targets
cargo check -p synvoid-static-files --all-targets
cargo test -p synvoid-static-files --all-targets
```

6. Remaining crates:

```bash
cargo check -p synvoid-block-store --all-targets
cargo test -p synvoid-block-store --all-targets
cargo check -p synvoid-challenge --all-targets
cargo test -p synvoid-challenge --all-targets
cargo check -p synvoid-filter --all-targets
cargo test -p synvoid-filter --all-targets
cargo check -p synvoid-geoip --all-targets
cargo test -p synvoid-geoip --all-targets
cargo check -p synvoid-integrity --all-targets
cargo test -p synvoid-integrity --all-targets
cargo check -p synvoid-ipc --all-targets
cargo test -p synvoid-ipc --all-targets
cargo check -p synvoid-metrics --all-targets
cargo test -p synvoid-metrics --all-targets
cargo check -p synvoid-theme --all-targets
cargo test -p synvoid-theme --all-targets
cargo check -p synvoid-vpn-client --all-targets
cargo test -p synvoid-vpn-client --all-targets
cargo check -p synvoid-wasm-pow --all-targets
cargo test -p synvoid-wasm-pow --all-targets
cargo check -p synvoid-tarpit --all-targets
cargo test -p synvoid-tarpit --all-targets
```

### Success criteria

- Per-crate results are recorded in a validation note.
- Failures are isolated to specific crates and not left as broad workspace noise.
- Mechanical failures are fixed.
- Design-level failures become follow-up plans.

## Workstream 4: Feature matrix validation

### Critical feature profiles

Validate at minimum:

```bash
cargo check -p synvoid-upload --all-features --all-targets
cargo test -p synvoid-upload --all-features --all-targets
cargo check -p synvoid-honeypot --all-features --all-targets
cargo test -p synvoid-honeypot --all-features --all-targets
cargo check -p synvoid-http --features mesh --all-targets
cargo test -p synvoid-http --features mesh --all-targets
cargo check -p synvoid-mesh --features mesh --all-targets
cargo test -p synvoid-mesh --features mesh --all-targets
cargo check -p synvoid-dns --all-features --all-targets
cargo test -p synvoid-dns --all-features --all-targets
cargo check -p synvoid-plugin-runtime --all-features --all-targets
cargo test -p synvoid-plugin-runtime --all-features --all-targets
```

If a crate has no `mesh` feature or feature name differs, record the correct feature set.

### Feature audit tasks

1. Run:

```bash
cargo tree -e features -p synvoid-upload
cargo tree -e features -p synvoid-honeypot
cargo tree -e features -p synvoid-http
cargo tree -e features -p synvoid-mesh
```

2. Check for accidental feature coupling:

- upload should not require mesh unless feature enabled.
- honeypot should compile without mesh.
- HTTP mesh feature should pull the expected mesh crates only.
- plugin runtime unsafe/native features should be gated.

3. Check optional dependencies are actually gated by features.

### Success criteria

- Important feature profiles compile/test locally.
- Feature coupling is documented or fixed.
- No accidental always-on heavy subsystem appears in upload/honeypot default builds.

## Workstream 5: Clippy and fmt gates

### Tasks

1. Run formatting:

```bash
cargo fmt --all -- --check
```

2. Run targeted clippy first:

```bash
cargo clippy -p synvoid-upload --all-targets -- -D warnings
cargo clippy -p synvoid-honeypot --all-targets -- -D warnings
cargo clippy -p synvoid-http --all-targets -- -D warnings
cargo clippy -p synvoid-mesh --all-targets -- -D warnings
cargo clippy -p synvoid-dns --all-targets -- -D warnings
```

3. Run workspace clippy if feasible:

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

4. Classify warnings:

- new regression
- old code quality debt
- false positive requiring allow with reason
- feature-specific warning

5. Prefer fixes over `allow`, but if an allow is needed, include a local reason and narrow scope.

### Success criteria

- fmt passes.
- Targeted clippy passes for upload/honeypot/core network crates.
- Workspace clippy either passes or has a documented follow-up plan with exact warnings.

## Workstream 6: Test suite validation

### Tasks

1. Run workspace tests:

```bash
cargo test --workspace
cargo test --workspace --all-targets
```

2. Run release-mode tests for high-value crates:

```bash
cargo test -p synvoid-upload --release
cargo test -p synvoid-honeypot --release
cargo test -p synvoid-dns --release
cargo test -p synvoid-mesh --release
```

3. Run ignored-test inventory:

```bash
cargo test --workspace -- --ignored
rg '#\[ignore\]' . -g '*.rs'
```

4. Classify ignored tests:

- long-running stress
- environment-dependent
- requires external service
- stale/broken
- release-blocking

5. Confirm security-critical ignored tests do not remain ambiguous.

### Success criteria

- Workspace tests pass or failures are fully triaged.
- Release-mode upload/honeypot tests remain passing.
- Ignored tests are classified and documented.

## Workstream 7: Dependency/security policy validation

### Tasks

1. Run dependency gates:

```bash
cargo deny check
cargo audit
cargo tree -d
cargo tree -i wasmtime
cargo tree -i yara-x
cargo tree -i zip
```

2. Confirm deny policy remains accurate:

- advisories ignored only with rationale and re-audit date
- wasmtime advisory exposure assessment still valid
- license allowlist is minimal
- source policy is enforced
- yanked crates denied

3. Confirm recent dependency upgrades did not introduce duplicate/old versions that should be consolidated.

4. Confirm `zip` is only present for upload archive inspection and does not leak into unrelated default builds unexpectedly.

### Success criteria

- `cargo deny check` passes.
- `cargo audit` passes or remaining advisories are documented with owner acceptance.
- duplicate dependency tree is acceptable or has cleanup plan.

## Workstream 8: Documentation and release status audit

### Tasks

1. Check documentation links and existence:

```bash
rg '\]\(([^)]+)\)' README.md docs architecture plans -n
```

2. Validate key docs are accurate:

- `README.md`
- `SECURITY.md`
- `docs/UPLOADS.md`
- `docs/HONEYPOT.md` if present
- `architecture/upload.md`
- `architecture/honeypot.md`
- `docs/CONFIGURATION.md`
- `AGENTS.md`

3. Ensure docs distinguish:

- Milestone B upload/honeypot clean state.
- ZIP-only archive structural inspection.
- nested archives counted but not recursively inspected.
- GitHub CI not authoritative for this recent line.
- full workspace release validation status.

4. Add a final validation note:

- `plans/workspace_wide_validation_results.md`

This note should include command results, failure triage, fixed items, and remaining release blockers.

### Success criteria

- Release status is visible in one place.
- Docs do not overclaim production readiness.
- Any remaining blocker has owner, file, command, and follow-up plan.

## Workstream 9: GitHub workflow sanity

Even if GitHub CI is not authoritative right now, the workflow file should not be obviously stale.

### Tasks

1. Inspect `.github/workflows/ci.yml` for:

- upload test job
- honeypot test coverage
- cargo-deny job
- fmt/clippy/test jobs
- summary job dependencies
- outdated crate/tool invocations

2. Compare local validation commands with workflow commands.

3. Fix low-risk drift:

- commands referencing deleted crates
- missing upload/honeypot gates
- cargo-deny invocation mismatch
- summary job missing new job names

4. Do not depend on workflow results to claim closure unless runs are actually visible and current.

### Success criteria

- Workflow file is not obviously inconsistent with local validation commands.
- Local validation remains the source of truth for this pass unless GitHub Actions becomes reliable.

## Workstream 10: Final classification

After validation, classify the repo into one of these states:

### State A: Full workspace release-clean

Requirements:

- fmt passes
- workspace check passes
- workspace clippy passes or documented narrow allows only
- workspace tests pass
- cargo-deny/audit pass or accepted advisories documented
- docs/status clear

### State B: Milestone B clean, full repo has unrelated blockers

Requirements:

- upload/honeypot passes all targeted checks
- cargo-deny passes
- blockers isolated to unrelated crates/files
- follow-up plans exist for blockers

### State C: Milestone B regression found

Requirements:

- any upload/honeypot/archive/protocol/security regression blocks closure
- create corrective plan before proceeding

## Final acceptance checklist

- [ ] `cargo metadata --no-deps` passes.
- [ ] `cargo fmt --all -- --check` passes.
- [ ] `cargo check --workspace` passes or failures triaged.
- [ ] `cargo check --workspace --all-targets` passes or failures triaged.
- [ ] Upload targeted check/clippy/test passes.
- [ ] Honeypot targeted check/clippy/test passes.
- [ ] DNS/mesh/HTTP targeted checks are run and recorded.
- [ ] Important feature profiles are run and recorded.
- [ ] `cargo deny check` passes.
- [ ] `cargo audit` is run or its absence is documented.
- [ ] Ignored tests are inventoried.
- [ ] Documentation status is reconciled.
- [ ] `.github/workflows/ci.yml` is sanity-checked.
- [ ] `plans/workspace_wide_validation_results.md` is created with exact command results.
- [ ] Final state is classified as A, B, or C.

## Handoff guidance

Do not hide workspace failures behind the successful upload/honeypot work. Conversely, do not reopen Milestone B because of unrelated pre-existing workspace issues. The output of this pass should be a precise release-readiness map and, if needed, narrow follow-up plans for remaining blockers.
