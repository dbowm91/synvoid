# CI Simplification Phase 2 — Single Workflow Collapse

## Status

Planned. This phase depends on the frozen command and deletion inventory from Phase 1.

## Objective

Replace the current redirect plus four-lane workflow topology with one routine GitHub Actions workflow that answers one question: whether the commit is acceptable for ordinary integration on the primary supported Linux path.

This phase changes hosted execution only. It must not retain old workflows as disabled compatibility artifacts, add reusable-workflow indirection, or substitute another matrix-driven design.

## Entry criteria

Do not begin until:

- `docs/testing/verification-contract.md` identifies one canonical routine command.
- `docs/testing/ci-deletion-inventory.md` classifies every current workflow and workflow-specific helper.
- The routine command has passed the Phase 1 failure-injection checks locally.
- The final desired required-check name is chosen.

## Required deliverables

```text
.github/workflows/ci.yml
```

Delete:

```text
.github/workflows/pr-fast.yml
.github/workflows/main-comprehensive.yml
.github/workflows/nightly-qualification.yml
.github/workflows/release-qualification.yml
```

Update any local reusable setup action only when it materially reduces the final workflow. Delete it when the final workflow is clearer with direct setup steps.

## Final workflow contract

The workflow must use a stable name and one stable required job name. Preferred shape:

```yaml
name: CI

on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

concurrency:
  group: ci-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

permissions:
  contents: read

jobs:
  ci:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - name: Install system dependencies
        run: sudo apt-get update && sudo apt-get install -y protobuf-compiler
      - uses: Swatinem/rust-cache@v2
      - name: Verify
        run: <canonical routine command>
```

This is a shape constraint, not text to copy blindly. Pinning policy, protobuf requirements, and cache placement must follow actual repository needs.

## Workstream 1 — Replace the redirect workflow

Rewrite `.github/workflows/ci.yml` as the active routine workflow.

Requirements:

- Remove the redirect notice job.
- Use `pull_request`, `push` to `main`, and `workflow_dispatch` only.
- Do not include `master` or `develop` unless they currently exist and are intentionally maintained branches.
- Add read-only permissions unless a retained step requires more.
- Add pull-request cancellation.
- Use Ubuntu only.
- Use no strategy matrix.
- Invoke the canonical routine command once.
- Use no release profile unless the frozen routine contract explicitly and narrowly justifies one command.
- Do not parse JUnit or construct a result summary table.
- Let GitHub Actions' job status be the summary.

## Workstream 2 — Choose one job or justify two

The default is one job. A two-job design is allowed only for:

```text
lint: fmt + clippy
verify: compile + tests + critical guards
```

Before choosing two jobs, compare against the one-job design and record:

- cold and warm wall time
- repeated checkout/toolchain/system-dependency cost
- cache behavior
- duplicated compilation
- time to first actionable failure

Two jobs are rejected if they materially duplicate Rust compilation or only make the YAML resemble conventional CI. The branch-protection surface must remain at most two checks.

## Workstream 3 — Delete active lane workflows

Delete all four active lane files in the same change that activates the replacement workflow.

Do not:

- leave them with only `workflow_dispatch`
- rename them to `legacy-*`
- move them under another directory
- retain the release workflow for tag handling
- retain nightly qualification as nonblocking
- retain main comprehensive as post-merge assurance

Historical behavior is already represented in Git history and plan records. Keeping dormant workflow YAML creates ambiguity and makes future reactivation too easy.

## Workstream 4 — Remove workflow matrices and broad hosted qualification

The final `.github/workflows/` directory must contain no active logic for:

- macOS runners
- Windows runners
- FreeBSD VMs
- Alpine containers
- cross-target build matrices
- AArch64 cross builds
- musl build matrices
- Miri
- fuzz matrices
- outdated dependency scans
- five-profile feature matrices
- release artifact uploads
- tag-triggered builds
- scheduled jobs

This phase does not delete the underlying product tests or fuzz targets. It removes their automatic hosted scheduling. Their local/on-demand command disposition is implemented in Phase 3 and documented in Phase 4.

## Workstream 5 — Remove routine artifacts and synthetic summaries

Delete workflow steps that upload:

- selector JSON
- JUnit XML
- timing summaries
- fuzz corpora from routine paths
- release binaries
- package artifacts
- generated Markdown summary tables

An artifact may remain only if all are true:

1. A named maintainer or automated consumer uses it.
2. It materially shortens diagnosis compared with ordinary logs.
3. Its retention and naming are documented.
4. It is not required to prove that CI itself ran.

The default disposition is deletion.

## Workstream 6 — Rationalize setup and caching

Use one Rust cache in the final workflow. Avoid job-specific and target-specific cache-key policy when no matrix remains.

Requirements:

- No `sccache` service is introduced in this phase.
- No custom cache statistics summary is required.
- Cache failure must not fail verification.
- System dependencies install once per job.
- Do not install nextest unless the frozen routine command actually uses it and measured benefit exceeds installation and maintenance cost.
- Delete `.github/actions/setup-rust-ci` if the remaining abstraction only wraps a handful of obvious steps or retains obsolete lane inputs such as cache-key classes, nextest switches, or matrix-oriented parameters.

## Workstream 7 — Ensure direct and forked PR safety

The workflow must not require secrets for pull requests.

Verify:

- `permissions: contents: read` is sufficient.
- No publication token, signing key, crates.io token, or deployment credential is referenced.
- No `pull_request_target` trigger is used.
- No untrusted PR code executes with elevated permissions.
- Cache configuration does not require write credentials beyond GitHub's normal action behavior.

## Workstream 8 — Preserve failure visibility without orchestration

Use ordinary named steps. The final log should make failures attributable to:

- formatting
- linting
- compilation
- tests
- critical guards

If the canonical wrapper combines these, it must print the command before execution and propagate the first nonzero exit code. Do not recreate a summary parser.

## Validation commands

Run locally where applicable:

```bash
<canonical routine command>
```

Validate workflow syntax with the repository's existing lightweight YAML tooling if present. Do not add a permanent workflow-lint dependency solely for this migration.

Inspect the final topology:

```bash
find .github/workflows -maxdepth 1 -type f -print | sort
rg -n 'schedule:|tags:|matrix:|macos-|windows-|freebsd|alpine|cargo miri|cargo .*fuzz|cargo outdated|upload-artifact' .github/workflows
```

## Hosted failure-injection requirements

Use temporary branches or draft pull requests and close them after observation. Demonstrate:

1. A formatting violation fails the required check.
2. A clippy warning fails the required check.
3. A compile error fails the required check.
4. A selected routine test failure fails the required check.
5. A critical security or product guard failure fails the required check.
6. A second push to the same pull request cancels the superseded run.
7. A tag push does not start a release workflow.

Do not merge injected failures.

## Acceptance criteria

Phase 2 is complete only when:

- `.github/workflows/ci.yml` is an active routine workflow, not a redirect.
- The four lane workflow files are absent.
- Exactly one routine workflow triggers for an ordinary pull request.
- The workflow has one job, or two with documented measured justification.
- The workflow runs on Ubuntu only.
- No workflow contains a target or operating-system matrix.
- No workflow contains a schedule trigger.
- No workflow contains a tag trigger.
- No workflow uploads release artifacts or publishes crates.
- No workflow runs fuzz, Miri, FreeBSD, Alpine, outdated-dependency, or broad platform qualification.
- The canonical routine command runs once and returns its actual status.
- Superseded pull-request runs cancel.
- All seven hosted failure-injection scenarios behave as specified.
- A normal implementation commit receives a green `CI / ci` result, or the final equivalent stable check name.

## Rejection searches

These must return no active matches except harmless action-version names or comments explicitly stating prohibition:

```bash
rg -n 'pr-fast|main-comprehensive|nightly-qualification|release-qualification' .github
rg -n 'schedule:|tags:' .github/workflows
rg -n 'strategy:|matrix:' .github/workflows
rg -n 'macos-|windows-|freebsd|alpine|miri|fuzz|outdated' .github/workflows
rg -n 'upload-artifact|download-artifact|cargo publish|crates.io' .github/workflows
rg -n 'GITHUB_STEP_SUMMARY|junit|affected-packages' .github/workflows
```

## Stop conditions

Stop and correct the phase rather than broadening scope when:

- the canonical routine command is invalid
- protobuf or another system dependency is missing
- a retained product guard cannot run through the canonical command
- branch protection still requires deleted job names

Do not restore deleted lane workflows. Correct the replacement command, setup, or repository setting directly.

## Handoff to Phase 3

Phase 3 begins only after the single workflow is green. It then removes the selector, lane definitions, xtask lane surface, and CI-specific guards that are no longer referenced.
