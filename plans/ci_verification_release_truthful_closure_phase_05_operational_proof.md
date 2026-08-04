# Phase 5 — Full, Release, and Operational Closure Proof

**Status:** PLANNED  
**Roadmap:** `plans/ci_verification_release_truthful_closure_roadmap.md`  
**Depends on:** Phases 1–4 complete  
**Purpose:** Produce fresh, internally consistent evidence that routine, full, and release verification are green on the final clean head and that the simplified operating model remains intact.

## 1. Entry Criteria

Do not begin final closure until:

- every Phase 1 ledger row has a committed resolution;
- all confirmed product regressions are fixed;
- all genuine stale expectations have contract-backed corrections;
- all harness defects are repaired;
- every specialist-environment test has a justified disposition and deterministic preflight;
- targeted and owning-crate test suites pass;
- the working tree can remain clean during verification.

A partial pass or a pass using hidden exclusions is not an entry condition.

## 2. Frozen Closure Contract

Final closure must prove all three levels independently:

### Routine

```bash
cargo xtask verify
```

This is the only command invoked by hosted routine CI.

### Full local

```bash
cargo xtask verify-full
```

This must execute the authoritative broad local suite without deliberately duplicating all routine test binaries and without hiding the ledger tests.

### Release

```bash
cargo xtask verify-release
```

This must execute the full contract plus release-specific checks and package validation without publishing anything.

The commands may evolve narrowly during implementation, but documentation, dry-run output, and actual execution must agree at closure.

## 3. Workstream A — Clean Final-Head Baseline

Record:

```bash
git rev-parse HEAD
git status --porcelain
rustc -Vv
cargo -V
cargo nextest --version
protoc --version
uname -a
```

Requirements:

- `git status --porcelain` is empty before authoritative runs;
- generated package files, logs, JUnit output, or build artifacts do not dirty tracked files;
- final evidence identifies the exact commit SHA;
- commands are run from repository root with no undocumented environment overrides.

If an override is required for a legitimate platform reason, record it and decide whether it belongs in the documented command contract.

## 4. Workstream B — Routine Verification and Hosted Proof

### B1. Local routine proof

Run:

```bash
cargo xtask verify --dry-run
cargo xtask verify
```

Record step count, command expansion, per-step duration, total duration, and exit code.

Confirm:

- formatting, linting, compile coverage, repository guards, security regression, root guards, core admin/mesh cases, and failure injection remain represented as documented;
- all commands use the intended profile consistently;
- no affected-package selection or dynamic scheduling is present;
- failure propagation remains fail-closed.

### B2. Hosted routine proof

Push the final implementation and obtain a GitHub Actions run of the sole `ci` job.

Record:

- workflow run ID;
- job ID;
- final commit SHA;
- cache-hit status;
- job start/end times;
- `cargo xtask verify` start/end times;
- conclusion;
- slowest steps.

Acceptance target:

- warm-cache hosted job below ten minutes;
- fifteen minutes remains the blocking threshold requiring investigation;
- no additional job, matrix, schedule, service container, artifact upload, or release step is added to meet the target.

If the run exceeds the target, identify whether the cause is cache miss, runner variance, dependency download, or command regression. Correct command duplication or cache invalidation only when evidence supports it. Do not recreate the former CI architecture.

## 5. Workstream C — Full Verification Proof

Run:

```bash
cargo xtask verify-full --dry-run
cargo xtask verify-full
```

The final full run must:

- pass every included test;
- include every test formerly listed in the Phase 1 ledger unless explicitly and validly moved to a specialist command;
- contain no newly added `#[ignore]` for closure items;
- contain no nextest filter that silently removes closure items;
- avoid duplicate broad execution of the same test binaries;
- preserve explicit stress/endurance separation where those commands are genuinely specialist-only;
- complete within a documented, bounded local duration.

### C1. Ledger reconciliation

For every original ledger row, record one final state:

- fixed product behavior;
- corrected expectation with contract source;
- repaired harness;
- specialist command with preflight and reason.

No row may remain `OPEN`, `UNKNOWN`, `PRE-EXISTING`, or merely `NONBLOCKING` if it belongs to the authoritative full contract.

### C2. Specialist commands

Run or preflight all specialist commands documented by the verification contract where the current environment supports them. At minimum, validate that the command names and test targets exist and that missing prerequisites fail clearly.

Do not claim specialist suites passed if they were not executed. Distinguish:

- executed and passed;
- not executed because prerequisite unavailable;
- command/preflight verified only.

## 6. Workstream D — Release Verification Proof

### D1. Clean-tree behavior

From a clean tree:

```bash
cargo xtask verify-release --dry-run
cargo xtask verify-release
```

The command must pass and leave the tracked tree clean.

### D2. Dirty-tree failure injection

Create one temporary tracked-file modification and run:

```bash
cargo xtask verify-release
```

Expected:

- nonzero exit before release evidence is accepted;
- clear dirty-tree diagnostic;
- explicit `--allow-dirty` guidance;
- no publication action.

Then run:

```bash
cargo xtask verify-release --allow-dirty
```

Expected:

- prominent warning that the result is local diagnostic output, not release evidence;
- verification proceeds according to the documented override;
- final summary remains visibly non-authoritative;
- no publication action.

Revert the temporary change before continuing.

### D3. Metadata and dependency graph

For every publishable workspace crate, validate:

- package name and version;
- non-empty description;
- license/license-file policy;
- repository metadata;
- readme path existence when declared;
- `publish` intent;
- internal path dependency has a compatible semver requirement;
- dependency requirement matches the actual workspace crate version;
- wildcard internal requirements are rejected unless an explicit, documented exception exists;
- publication order is a valid topological order of publishable internal dependencies.

Non-publishable workspace members must not be accidentally inserted into the publication sequence.

### D4. Package-content inspection

For every publishable crate:

```bash
cargo package --list -p <crate>
```

or the equivalent verifier action must prove:

- prohibited credentials/private-key files are rejected using path-aware rules;
- legitimate source names containing words such as `secret` or `private_key` are not rejected solely by substring;
- root package exclusions are intentional and do not remove required license/readme/source files;
- plans, crash corpora, fuzz data, local environment files, and private key material are absent where required;
- package contents are recorded or summarized in the closure evidence.

### D5. Package assembly

Every publishable crate must assemble:

```bash
cargo package --no-verify -p <crate>
```

Record success/failure by crate. No crate may be omitted silently.

### D6. Bounded packaged-source verification

For each crate whose dependencies are resolvable from the registry:

```bash
cargo package --verify -p <crate>
```

Record:

- passed;
- skipped because a named internal dependency is not yet published/resolvable;
- failed with exact reason.

A skip is not a pass. Closure may accept a skip only when:

- package assembly passed;
- source/full verification passed;
- the unresolved dependency is explicitly named;
- manual publication order ensures the predecessor is published first;
- the release documentation explains when to rerun the packaged-source check.

Do not introduce a local registry emulator merely to eliminate these bounded skips.

### D7. Non-publication proof

Search operational code and workflows for:

- `cargo publish`;
- registry tokens;
- crates.io credentials;
- tag-triggered workflows;
- GitHub release creation;
- artifact upload intended for release;
- automatic version/tag mutation.

Any documentation example of manual `cargo publish` must be clearly operator-invoked and outside xtask/workflows.

## 7. Workstream E — Documentation and Status Reconciliation

Update all affected status/evidence documents in the same closure series.

At minimum inspect and reconcile:

- `plans/ci_simplification_corrective_roadmap.md`;
- `plans/ci_simplification_corrective_phase_02_full_release_contract.md`;
- `plans/ci_verification_release_simplification_closure_results.md`;
- `plans/ci_verification_release_truthful_closure_roadmap.md`;
- all five truthful-closure phase plans;
- `docs/testing/verification-contract.md`;
- `docs/releasing.md`;
- `docs/RELEASE.md`;
- `docs/RELEASE_CHECKLIST.md`;
- `AGENTS.md`;
- any platform/release profile document that describes CI enforcement.

Requirements:

- command counts and raw command examples match `verify.rs`;
- no deleted nightly/main-comprehensive/release workflow is described as active;
- specialist checks are described as manual, not nightly;
- test-disposition counts match the final ledger;
- prior provisional classifications are replaced by final outcomes;
- Phase 2 is not marked complete without its implementation/evidence commit;
- closure results do not claim a hosted run, branch setting, or release pass that was not observed;
- all `COMPLETE` labels are evidence-backed and dated.

Historical results may remain, but they must be clearly labeled historical and must not be presented as current-head proof.

## 8. Workstream F — Branch Protection and Repository Settings

Branch protection is external to repository content. Verify manually, if access permits, that:

- `main` requires the current `ci` check only;
- deleted lane/job names are not required;
- no stale release or nightly check blocks merges;
- direct-push/review requirements are recorded accurately without changing them unless explicitly requested.

Capture a screenshot, settings export, or dated operator attestation. If the setting cannot be inspected, state that clearly and leave this item `EXTERNALLY UNVERIFIED`; do not infer it from workflow success.

## 9. Rejection Searches

Before closure, confirm operational code does not restore removed complexity. Search for active references to:

- `pr-fast.yml`;
- `main-comprehensive.yml`;
- `nightly-qualification.yml`;
- `release-qualification.yml`;
- `testing/lanes.toml`;
- affected-package selector scripts;
- selector modes or force-full dispatch;
- automated `cargo publish`;
- tag-triggered release workflows;
- obsolete CI-policy negative fixtures;
- undocumented test exclusions created during this corrective pass.

References inside historical plan documents are permitted only when clearly historical.

## 10. Final Closure Record

Create or rewrite one authoritative closure-results document containing:

1. executive disposition;
2. final SHA and environment;
3. before/after failure-ledger summary;
4. product fixes;
5. expectation corrections;
6. harness corrections;
7. routine local result;
8. hosted routine result;
9. full verification result;
10. specialist-command disposition;
11. release verification result;
12. metadata/dependency/package results by crate;
13. dirty-tree failure injection;
14. non-publication rejection searches;
15. branch-protection evidence or limitation;
16. residual risks, each explicitly deferred with owner and rationale;
17. statement of whether the line is complete.

Do not use “pre-existing” as a reason to omit an authoritative-suite failure. If a genuine unrelated product defect remains, the line stays incomplete or the verification contract must be explicitly and defensibly changed before closure.

## 11. Acceptance Criteria

Phase 5 and the roadmap are complete only when:

- the final tree is clean;
- `cargo xtask verify` passes locally;
- the hosted sole `ci` job passes on the final implementation and satisfies the routine budget or has a resolved documented anomaly;
- `cargo xtask verify-full` passes with all intended tests present;
- every Phase 1 ledger row has a final evidence-backed disposition;
- `cargo xtask verify-release` passes on a clean tree;
- dirty-tree release verification fails by default;
- `--allow-dirty` is visibly diagnostic-only;
- every publishable crate passes metadata, semver, content inspection, and package assembly;
- every registry-resolvable crate passes packaged-source verification;
- every packaged-source skip names the unresolved dependency and publication-order mitigation;
- no xtask or workflow can publish, tag, release, upload release artifacts, or consume registry credentials;
- no removed selector/lane/nightly/release architecture is restored;
- documentation and plan statuses match implementation and evidence;
- branch protection is verified or explicitly left externally unverified;
- the closure record contains no contradictory `COMPLETE` and outstanding-blocker statements;
- all truthful-closure phase plans are updated with implementation commit references and final status.

## 12. Final Stop Conditions

Keep the roadmap `INCOMPLETE` if any of the following remains:

- an authoritative command fails;
- a closure test is ignored or excluded;
- a security-sensitive expectation was weakened without contract evidence;
- a harness still depends on undeclared external state;
- package assembly omits a publishable crate;
- release verification can proceed silently on a dirty tree;
- current documentation describes commands or workflows that do not exist;
- branch protection is claimed without evidence;
- hosted timing exceeds the blocking threshold without resolution;
- any status document claims completion before the evidence commit exists.