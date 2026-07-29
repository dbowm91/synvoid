# CI Simplification Phase 3 — Local Verification and Guard Reduction

## Status

Planned. This phase starts only after the single routine workflow from Phase 2 is green.

## Objective

Delete the verification control plane that existed to coordinate and police the four-lane CI topology. Replace it with three explicit local verification levels and one consolidated product-guard command.

The key distinction is:

- product assurance protects SynVoid behavior and security boundaries
- CI self-assurance protects selectors, lane manifests, workflow parity, summary structure, cache naming, and orchestration conventions

Product assurance remains. CI self-assurance is deleted with the architecture it served.

## Entry criteria

- `.github/workflows/ci.yml` is the sole routine workflow.
- The workflow invokes the canonical routine command frozen in Phase 1.
- The latest implementation commit has a green hosted run.
- The Phase 1 deletion inventory is current.

## Required end state

The repository exposes exactly three primary verification entry points:

```text
verify
verify-full
verify-release
```

The concrete interface may be:

```bash
cargo xtask verify
cargo xtask verify-full
cargo xtask verify-release
```

or:

```bash
./scripts/verify.sh
./scripts/verify-full.sh
./scripts/verify-release.sh
```

A single script with subcommands is also acceptable. The implementation must choose one form and remove competing authorities.

Do not retain aliases for the complete old lane vocabulary. A short transition note is acceptable; executable compatibility shims are not.

## Workstream 1 — Remove affected-package selection

Delete the affected-package execution path in full.

Expected removals include:

```text
scripts/ci/select-affected.py
scripts/test-affected.sh
selector fixtures
selector unit/integration tests
selector scenario tests
selector normalization logic
selector fallback logic
selector output artifacts
selector-gated job predicates
selector documentation
```

Search all workspace code, tools, docs, examples, and agent instructions for:

```text
select-affected
test-affected
affected package
affected-package
changed_packages
reverse dependents
force-full
selector fallback
```

Historical plan and result documents may retain these terms. Current operational surfaces must not.

Do not replace the selector with another change detector, path filter, `dorny/paths-filter`, Cargo graph query, or hand-maintained file-to-package map.

## Workstream 2 — Remove lane definitions and parity machinery

Delete `testing/lanes.toml` and all code whose purpose is to parse, validate, explain, or mirror it.

Remove old xtask commands such as:

```text
test fast
test affected
test comprehensive
test nightly-plan
test qualification
test release
test list
test explain
```

The exact command names must be confirmed from source before deletion.

Delete tests that assert:

- xtask and workflow command equality
- exact four-lane ownership
- lane-specific profile selection
- lane-specific feature lists
- workflow file presence
- job-name presence
- summary-job dependencies
- selector predicate polarity
- fail-closed selector normalization
- cache-key class naming
- release flags being forbidden in a named lane rather than in routine verification generally

Do not retain a generic parser merely because it could be reused later.

## Workstream 3 — Choose the lowest-complexity command implementation

Evaluate the existing xtask code against a small script implementation.

Retain xtask only when all are true:

1. The simplified implementation is materially smaller than the current lane orchestration.
2. It uses ordinary sequential process execution.
3. It does not parse a lane manifest.
4. It does not emit JSON plans or workflow summaries.
5. It does not implement affected selection.
6. It provides clearer cross-platform process handling than a shell script with little additional code.

Otherwise, delete the obsolete xtask testing surface and use scripts.

Whichever implementation is chosen must:

- print each command before running it
- stop on the first failure unless the documented contract explicitly needs aggregate failures
- preserve child exit codes
- use repository-root-relative execution
- avoid hidden environment mutation
- avoid network access except Cargo's normal dependency behavior and release dry-run needs
- contain no concurrency scheduler
- contain no cache policy
- contain no artifact generation

## Workstream 4 — Implement `verify`

`verify` must exactly reproduce hosted routine CI.

Requirements:

- same commands
- same order
- same features and profiles
- same exclusions
- same serialized security-test behavior
- no CI-only branch
- no local-only extra test
- no environment-dependent skip that causes local success and hosted failure

The GitHub workflow must invoke `verify` directly.

Add a lightweight automated test only if needed to prove command construction. Do not create a second command-parity framework. Prefer making CI call the same executable path over testing duplicated strings.

## Workstream 5 — Implement `verify-full`

`verify-full` is manually invoked. It must provide broader correctness without becoming a recreation of nightly qualification.

Expected categories:

- `verify`
- broader workspace tests omitted from routine CI
- important optional-feature compilation
- meaningful doctests
- domain-specific DNS, mesh, plugin, upload, honeypot, tarpit, admin, or integration tests whose cost is inappropriate for every commit
- dependency/security policy checks when tools are installed or through clearly documented setup

Rules:

- Use a static command list.
- Avoid running the same test target through both a blanket command and a named command.
- Do not include fuzz loops, Miri, FreeBSD VM, Alpine container, or broad cross-target compilation by default.
- Provide separate documented commands for those specialist activities.
- Do not require JUnit output.
- Do not upload or persist evidence artifacts.

## Workstream 6 — Consolidate product-level guards

Audit `tools/synvoid-repo-guards` and root guard tests.

Classify each guard:

### Product-level guard examples

- request-path versus composition-root boundaries
- secret-handling rules
- plugin ABI memory constraints
- admin mutation authority
- lifecycle task ownership
- mesh identity enforcement boundaries
- forbidden concrete infrastructure imports
- unsafe-code policy in security-sensitive modules

### CI-policy guard examples

- required workflow filenames
- required lane names
- selector predicate form
- selector fallback behavior
- lane TOML consistency
- workflow/xtask command equality
- artifact upload naming
- summary job shape
- cache-key naming

Delete the second category.

Expose retained static guards through one command:

```bash
cargo test -p synvoid-repo-guards
```

or the equivalent profile-specific command frozen in the contract.

Where root integration guards remain, consolidate only when doing so reduces Cargo invocations without obscuring failure messages. Do not perform broad product architecture refactoring in this phase.

## Workstream 7 — Remove duplicated test execution

Build an execution list for `verify` and `verify-full` and identify overlap caused by:

- workspace blanket tests followed by package tests
- package tests followed by named integration tests
- guard crate tests followed by the same guard through root tests
- default tests followed by equivalent all-feature tests
- doctests repeated through multiple commands

For every intentional repeat, record the distinct property proved. Otherwise remove it.

A simple checked-in table in `docs/testing/verification-contract.md` is sufficient. Do not build a duplicate-detection service.

## Workstream 8 — Preserve specialist tools as explicit commands

Document direct commands for specialist verification without scheduling them automatically:

```text
fuzz one named target for a specified duration or run count
Miri on one compatible crate
FreeBSD or Alpine manual environment verification
cross-target cargo check for a named target
benchmark or stress suite
cargo audit / cargo deny
```

Do not create a wrapper that runs all specialist commands together.

## Workstream 9 — Delete obsolete CI documents and rewrite current authority

Phase 3 may delete or replace current operational documents whose sole purpose is the four-lane system, including:

```text
docs/testing/ci-lane-policy.md
docs/testing/cache-policy.md
docs/testing/feature-target-matrix.md
```

Do not delete historical result records under `plans/`. Current documentation must point to `docs/testing/verification-contract.md` as the authority.

Update `AGENTS.md` command sections enough to prevent agents from invoking deleted selectors and lane commands. The full release and support-policy rewrite occurs in Phase 4.

## Failure-injection requirements

Demonstrate locally:

1. `verify` returns nonzero for a failed first command.
2. `verify` returns nonzero for a failed test late in the sequence.
3. `verify-full` does not report success when an added full-only test fails.
4. The consolidated product guard command reports the specific violated invariant.
5. Deleting or renaming the old lane manifest does not affect `verify`.
6. Deleting the selector does not alter routine command selection because no selection remains.
7. A command wrapper executed outside the repository root either resolves the root correctly or fails with a precise message.

Temporary defects must not remain on `main`.

## Validation commands

Run:

```bash
<verify command>
<verify-full command>
cargo test -p synvoid-repo-guards
```

Then inspect active references:

```bash
rg -n 'select-affected|test-affected|affected package selector' . --glob '!plans/**' --glob '!target/**'
rg -n 'testing/lanes\.toml|ci_lane_consistency|selector_predicate|selector_normalization' . --glob '!plans/**' --glob '!target/**'
rg -n 'cargo xtask test (fast|affected|comprehensive|nightly-plan|qualification|release|list|explain)' . --glob '!plans/**' --glob '!target/**'
rg -n 'PR Fast|Main Comprehensive|Scheduled Qualification|Release Qualification|four validation lanes' AGENTS.md README.md docs scripts tools .github Cargo.toml
```

## Acceptance criteria

Phase 3 is complete only when:

- The affected-package selector, wrapper, tests, fixtures, and operational references are absent.
- `testing/lanes.toml` is absent.
- Old xtask lane commands are absent.
- `verify` exactly reproduces hosted CI through shared execution, not string-parity tests.
- `verify-full` is static, manual, and broader than routine CI without specialist qualification bundles.
- The product guard suite runs through one ordinary command.
- CI-policy guards are removed.
- Product-level guards remain and produce actionable failures.
- Routine and full command overlap is documented and nonduplicative.
- Specialist fuzz, Miri, platform, audit, benchmark, and stress commands remain available directly but are unscheduled.
- Current operational docs and `AGENTS.md` no longer direct contributors to deleted lane or selector commands.
- All seven failure-injection requirements pass.

## Rejection searches

The phase must not close with active matches for:

```bash
rg -n 'select-affected|test-affected|changed_packages|force-full' scripts testing tools .github docs AGENTS.md Cargo.toml
rg -n 'lanes\.toml|ci_lane_consistency|selector_predicate|selector_normalization' scripts testing tools .github docs AGENTS.md Cargo.toml
rg -n 'nightly-plan|qualification|test explain|test list' tools scripts AGENTS.md docs Cargo.toml
```

Matches inside historical plans are allowed. Matches inside current code or operational documentation are closure failures.

## Stop conditions

Do not proceed to Phase 4 if:

- hosted CI and local `verify` execute different commands
- a product security guard was deleted without an equivalent retained assertion
- selector or lane code still has an executable path
- the wrapper swallows a child failure
- `verify-full` silently skips failed commands

Correct the narrow defect. Do not restore the four-lane system.
