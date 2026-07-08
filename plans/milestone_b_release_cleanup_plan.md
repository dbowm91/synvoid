# Milestone B Release Cleanup Plan

## Purpose

This cleanup pass closes the remaining release-readiness items after the Milestone B upload and honeypot hardening work. The functional/security work is effectively complete; the remaining blocker is repository hygiene and validation evidence, especially the known `cargo deny` license failure caused by missing workspace/crate license metadata.

This plan is intentionally narrow. Do not reopen archive scanning, honeypot protocol detection, or threat-intel confidence semantics unless release validation exposes a concrete regression.

## Current state

Milestone B implementation status:

- Native malware detector correctness: implemented.
- YARA error propagation through native scanner boundary: implemented.
- Bounded ZIP archive inspection: implemented.
- Archive structural violation classification: implemented.
- ZIP symlink detection via Unix mode bits: implemented.
- Archive scan metadata/observability: implemented.
- Honeypot listener concurrency/accounting: implemented.
- Binary-safe protocol detection: implemented.
- Honeypot confidence-aware severity capping: implemented.
- Local upload/honeypot test evidence: recorded in commit messages and `plans/milestone_b_local_validation_note.md`.

Known remaining cleanup:

- `cargo deny` advisories and bans were reported OK after dependency upgrades, but license checks still fail because workspace crates are missing license metadata.
- Several vulnerable dependencies were upgraded, but the lockfile/dependency policy should be rechecked after license metadata is fixed.
- Local validation should be rerun and recorded after metadata cleanup.
- Docs should clearly separate Milestone B completion from future archive-format extensions and broader Milestone C deception/threat-intel work.

## Workstream 1: Workspace and crate license metadata

### Problem

`cargo deny check` license validation fails because first-party workspace crates lack explicit license metadata. This is a release-readiness issue even though it is not a functional security bug.

### Tasks

1. Inspect the root `Cargo.toml` workspace metadata.

Check whether the repository uses:

```toml
[workspace.package]
license = "..."
repository = "..."
authors = ["..."]
edition = "..."
```

2. Decide the intended project license.

Preferred options:

- If the repo already has a `LICENSE` file, use that license expression.
- If no license is present, add or document the missing decision as a release blocker.
- Use a valid SPDX expression accepted by cargo-deny, for example `MIT`, `Apache-2.0`, or `MIT OR Apache-2.0`.

Do not invent a license that conflicts with repository intent. If unsure, add a plan note requiring owner confirmation before publishing/release.

3. Apply license metadata consistently.

Preferred approach:

- Add `license.workspace = true` to each first-party crate where supported and practical.
- Put the canonical license in `[workspace.package]` at the root.

Alternative approach:

- Add explicit `license = "..."` to each first-party crate.

4. Add missing first-party package metadata while touching manifests:

- `repository.workspace = true` or explicit repository URL
- `edition.workspace = true` only if the workspace already standardizes it safely
- optional `description` for crates intended for publication

5. Run:

```bash
cargo metadata --no-deps
cargo deny check licenses
```

6. If third-party license failures remain, classify them separately:

- acceptable license missing from deny allowlist
- unacceptable license requiring dependency change
- crate missing license expression but with license file
- first-party metadata still missing

### Success criteria

- First-party workspace crates have valid license metadata.
- `cargo deny check licenses` no longer fails due to first-party missing license fields.
- Any remaining third-party license issue is explicitly documented and either fixed or intentionally accepted in `deny.toml` with rationale.

## Workstream 2: cargo-deny finalization

### Problem

The previous deny cleanup improved advisories and bans, but full `cargo deny check` still failed on licenses. After metadata cleanup, the whole deny check should be rerun.

### Tasks

1. Run:

```bash
cargo deny check
```

2. Confirm each category:

- advisories: pass or narrowly ignored with rationale and re-audit date
- bans: pass
- licenses: pass
- sources: pass, if configured

3. Review existing advisory ignores, especially wasmtime/YARA-X transitive advisories.

Each ignore must include:

- advisory ID
- reason
- exposure assessment
- re-audit date
- removal condition

4. Confirm recently upgraded dependencies remain upgraded in `Cargo.lock`:

- `anyhow`
- `bcrypt`
- `crossbeam-epoch`
- `memmap2`
- `quinn-proto`

5. If `cargo deny check` cannot fully pass due to an unresolved product decision, add a release-blocking note and do not claim release cleanup closed.

### Success criteria

- `cargo deny check` passes locally, or the only remaining failure is documented as a release blocker with owner decision required.
- Advisory ignores are narrow and dated.
- Lockfile updates are intentional and reproducible.

## Workstream 3: Milestone B local validation note refresh

### Problem

Validation is currently local-first because GitHub CI is not authoritative for this line. The local validation note should be refreshed after license metadata and deny cleanup.

### Tasks

1. Update `plans/milestone_b_local_validation_note.md` with final cleanup validation results.

2. Record exact commands and summarized results:

```bash
cargo fmt --all -- --check
cargo clippy -p synvoid-upload --all-targets -- -D warnings
cargo test -p synvoid-upload --all-targets
cargo test -p synvoid-upload --all-features --all-targets
cargo clippy -p synvoid-honeypot --all-targets -- -D warnings
cargo test -p synvoid-honeypot --all-targets
cargo test -p synvoid-honeypot --all-features --all-targets
cargo deny check
```

3. Add workspace smoke if practical:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

4. If any command fails, record:

- exact command
- failure category: environment, unrelated crate, product regression, missing owner decision
- whether it blocks release
- follow-up file/issue/plan

### Success criteria

- Final local validation note includes post-cleanup results.
- No stale validation counts remain from earlier commits.
- Any non-green command is explicitly classified.

## Workstream 4: Documentation and plan status reconciliation

### Problem

The repo now contains several Milestone A/B implementation and closure plans. The final handoff should make the current state easy to understand without rereading every prior plan.

### Tasks

1. Add or update a compact status section in the local validation note or a new closure note:

- Milestone A: closed from upload/YARA security standpoint, with local validation caveat.
- Milestone B Phase 1: closed.
- Milestone B Phase 2: closed for ZIP-only bounded inspection; non-ZIP archive formats deferred.
- Milestone B Phase 3: closed.
- Milestone B Phase 4: closed.
- Residual archive hardening: closed after symlink/structural/metadata pass.
- Release cleanup: pending until cargo-deny license check passes.

2. Ensure upload docs clearly state:

- ZIP-only structural inspection.
- Nested archives are counted but not recursively inspected.
- `archive_max_depth` is reserved for future recursive inspection.
- TAR/GZIP/BZIP2/7z are not structurally inspected.
- Archive structural violations map through failure policy.
- Fail-open remains allowed-but-indeterminate/non-clean.

3. Ensure honeypot docs clearly state:

- binary-safe first-packet detection only; not full protocol parsing.
- confidence severity capping behavior.
- low-confidence detections cannot trigger aggressive action by themselves.
- listener connection and payload limits.

4. Update `AGENTS.md` if the recommended local validation commands changed.

### Success criteria

- Documentation matches implementation and validation state.
- Non-ZIP archive support is clearly deferred.
- Release blocker status is obvious.

## Workstream 5: Release-readiness boundary check

### Problem

Milestone B cleanup should not accidentally imply production release readiness for the entire repository if unrelated workspace crates still fail tests, lack docs, or have license metadata gaps.

### Tasks

1. Run or attempt workspace-level checks:

```bash
cargo fmt --all -- --check
cargo metadata --no-deps
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check
```

2. Classify failures as:

- Milestone B regression
- unrelated existing workspace failure
- environment/tooling limitation
- release metadata issue
- owner decision needed

3. If workspace-wide tests are too broad or slow, at minimum run:

```bash
cargo check --workspace
```

4. Add unresolved release-readiness items to a follow-up plan only if they are outside Milestone B.

### Success criteria

- Milestone B is not held hostage by unrelated workspace failures, but release blockers are not hidden.
- The handoff clearly states whether the repo is Milestone-B-clean versus release-clean.

## Suggested execution order

1. Determine and apply license metadata across first-party crates.
2. Run `cargo metadata --no-deps` and fix manifest mistakes.
3. Run `cargo deny check licenses`, then full `cargo deny check`.
4. Refresh `plans/milestone_b_local_validation_note.md`.
5. Reconcile docs/status notes.
6. Run final local validation commands.
7. Commit with a message that includes the final validation summary.

## Final acceptance checklist

- [ ] Root workspace has canonical license metadata or a documented owner-decision blocker.
- [ ] First-party crates inherit or define valid license metadata.
- [ ] `cargo metadata --no-deps` passes.
- [ ] `cargo deny check licenses` passes.
- [ ] `cargo deny check` passes or remaining failure is explicitly release-blocking and documented.
- [ ] Upload crate fmt/clippy/tests pass locally.
- [ ] Honeypot crate fmt/clippy/tests pass locally.
- [ ] Local validation note is updated after this cleanup.
- [ ] Upload docs still accurately state ZIP-only/non-recursive archive behavior.
- [ ] Honeypot docs still accurately state confidence capping/actionability behavior.
- [ ] Release readiness status is clear: Milestone-B-clean vs full-repo-release-clean.

## Handoff guidance

Do not treat a passing Milestone B cleanup as a blanket production-release approval for the full repository. This pass should make the upload/honeypot Milestone B line clean and should expose any remaining repo-wide release blockers separately.
