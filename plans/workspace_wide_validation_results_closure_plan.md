# Workspace-wide Validation Results Closure Plan

## Purpose

Close the remaining gap in the workspace-wide validation line: the repository has a validation plan and at least one implementation pass fixing compile, clippy, manifest, archive `Send`, and CI drift issues, but there is not yet a committed final results note proving the full workspace status.

This pass must produce a durable validation artifact, not just another implementation commit. The expected output is `plans/workspace_wide_validation_results.md` with exact commands, outcomes, failure triage, and final release-state classification.

## Current context

Recent state:

- Milestone A/B upload and honeypot work is locally clean.
- Workspace license metadata was added.
- `cargo deny check` was reported passing.
- Upload/honeypot targeted checks and release tests were reported passing.
- The workspace validation implementation pass fixed:
  - missing archive inspection fields in upload config
  - `ZipFile`/`ZipArchive` `!Send` issue by collecting entries before `await`
  - small clippy warnings in `synvoid-utils` and `synvoid-wasm-pow`
  - missing license metadata in admin UI/examples/fuzz manifests
  - missing honeypot CI coverage

Remaining gap:

- No committed final workspace validation results note exists yet.
- Full workspace status is still unknown until workspace-level commands are run and recorded.

## Non-goals

- Do not add new Milestone C functionality in this pass.
- Do not broaden archive scanning beyond current ZIP-only support.
- Do not change honeypot protocol/actionability semantics unless validation exposes a concrete regression.
- Do not claim full release readiness without workspace-level evidence.

## Required output

Create:

- `plans/workspace_wide_validation_results.md`

The note must include:

1. Date, branch, commit SHA, local platform, Rust toolchain, and whether GitHub CI was trusted.
2. Exact command matrix and summarized output.
3. Failure classification by crate/file/command.
4. Fixes applied during the pass, if any.
5. Remaining blockers, if any.
6. Final state classification:
   - State A: full workspace release-clean
   - State B: Milestone B clean, full repo has unrelated blockers
   - State C: Milestone B regression found

## Workstream 1: Environment and baseline capture

Run and record:

```bash
rustc --version
cargo --version
cargo metadata --no-deps
cargo metadata --all-features --no-deps
cargo tree -d
```

Record platform details:

```bash
uname -a
rustup show active-toolchain
```

If `cargo metadata --all-features --no-deps` fails, classify it immediately as a workspace release blocker and include the first actionable error.

## Workstream 2: Formatting, dependency, and policy gates

Run and record:

```bash
cargo fmt --all -- --check
cargo deny check
cargo audit
```

If `cargo audit` is not installed, record that explicitly and install/run it if local workflow permits. Do not substitute `cargo deny check` for `cargo audit` silently; they are complementary checks.

Success criteria:

- fmt passes.
- cargo-deny passes or remaining failure is documented as release-blocking.
- cargo-audit passes or advisories are classified with owner acceptance.

## Workstream 3: Workspace compile gates

Run in this order:

```bash
cargo check --workspace
cargo check --workspace --all-targets
cargo check --workspace --all-features
cargo check --workspace --all-targets --all-features
```

If failures occur:

1. Capture the exact compiler error code and first failure location.
2. Determine whether the failure is:
   - recent upload/honeypot regression
   - pre-existing unrelated workspace issue
   - feature-gate mismatch
   - target-specific issue
   - dependency/toolchain issue
3. Fix mechanical errors in the same pass if low risk.
4. For design-level failures, create a follow-up plan and classify the repo as State B or C depending on impact.

Special check:

- Confirm whether the previously observed `src/http/server/accept_loop.rs` errors are fixed, stale, or still active.

## Workstream 4: Targeted high-value crate gates

Run and record:

```bash
cargo clippy -p synvoid-upload --all-targets -- -D warnings
cargo test -p synvoid-upload --all-targets
cargo test -p synvoid-upload --all-features --all-targets
cargo test -p synvoid-upload --release

cargo clippy -p synvoid-honeypot --all-targets -- -D warnings
cargo test -p synvoid-honeypot --all-targets
cargo test -p synvoid-honeypot --all-features --all-targets
cargo test -p synvoid-honeypot --release

cargo clippy -p synvoid-http --all-targets -- -D warnings
cargo test -p synvoid-http --all-targets

cargo clippy -p synvoid-mesh --all-targets -- -D warnings
cargo test -p synvoid-mesh --all-targets

cargo clippy -p synvoid-dns --all-targets -- -D warnings
cargo test -p synvoid-dns --all-targets
```

If any high-value crate fails, include a precise failure table and classify whether it blocks release.

## Workstream 5: Workspace clippy and tests

Run and record:

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo test --workspace --all-targets
```

If workspace-wide clippy/test is too slow or noisy, do not omit it silently. Record:

- command attempted
- elapsed point/failure point
- reason it could not complete
- targeted substitute commands
- whether the substitute is sufficient for release classification

## Workstream 6: Ignored-test inventory

Run and record:

```bash
rg '#\[ignore\]' . -g '*.rs'
cargo test --workspace -- --ignored
```

Classify every ignored test as:

- long-running stress
- external integration
- platform-specific
- flaky quarantine
- stale/broken
- security-release-blocking

Security-critical ignored tests must either be unignored, fixed, or explicitly documented as release blockers.

## Workstream 7: CI workflow sanity

Inspect `.github/workflows/ci.yml` after the recent upload/honeypot job additions.

Confirm:

- upload job runs fmt/clippy/tests and all-features check.
- honeypot job runs fmt/clippy/tests and all-features check.
- cargo-deny/security job still runs.
- summary job references all jobs that exist.
- workflow commands do not diverge from local validation without reason.

If GitHub CI remains unreliable, state that local validation is authoritative for this pass.

## Workstream 8: Final classification and follow-up output

At the end, classify the repo:

### State A: full workspace release-clean

All of these must be true:

- metadata passes
- fmt passes
- workspace check passes
- workspace clippy passes or only documented narrow allows remain
- workspace tests pass
- deny/audit pass or accepted advisories documented
- ignored tests are classified
- docs/status are current

### State B: Milestone B clean, unrelated workspace blockers remain

Use if:

- upload/honeypot remain green
- dependency/license policy is green
- remaining failures are isolated to unrelated crates or workspace-level debt
- follow-up plans exist

### State C: Milestone B regression found

Use if:

- upload/honeypot/archive/protocol correctness regressed
- cargo-deny regression affects recent work
- archive scan failure semantics regressed

## Required final checklist

- [ ] `plans/workspace_wide_validation_results.md` exists.
- [ ] Results note includes exact commit SHA validated.
- [ ] Results note includes exact commands and outcomes.
- [ ] Workspace metadata status is recorded.
- [ ] Workspace check status is recorded.
- [ ] Workspace clippy/test status is recorded.
- [ ] Upload/honeypot targeted status remains green or failure is classified.
- [ ] `cargo deny check` status is recorded.
- [ ] `cargo audit` status is recorded or absence is documented.
- [ ] Ignored tests are inventoried.
- [ ] Prior `accept_loop.rs` issue is resolved or tracked.
- [ ] Final State A/B/C classification is explicit.

## Handoff guidance

If the validation pass finds only small mechanical issues, fix them and include them in the same commit as the results note. If it finds design-level failures, do not patch opportunistically. Create narrow follow-up plans and leave the repo classified as State B or State C with exact evidence.
