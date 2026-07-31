# CI Simplification Corrective Phase 1 — Routine Latency Contraction

## Status

Planned. Depends only on the current single-workflow implementation at or after `a154a6adc4f62700034c35b59130a2c363ee9f64`.

## Objective

Reduce routine verification from approximately 998.5 seconds on a warm hosted runner to ten minutes or less without weakening the explicit formatting, lint, compilation, security-regression, architecture-boundary, lifecycle, plugin, admin, mesh, and ABI properties that the current routine contract is intended to protect.

The correction must come from eliminating repeated compilation and unnecessary process boundaries. It must not come from restoring affected-package selection, hiding failures, or replacing deterministic checks with documentation claims.

## Baseline

Hosted run `30600003285` used one Ubuntu job and succeeded. The important measured costs were:

| Item | Measured duration |
|---|---:|
| Cache download/extraction | approximately 52 s |
| Clippy | 179.5 s |
| Security regression | 405.1 s |
| `cargo test --lib --no-run` | 310.4 s |
| Entire `cargo xtask verify` | 998.5 s |
| Entire job | approximately 18 min |

The current command list has 22 Cargo invocations. It mixes default dev/test output with `[profile.ci]`, which causes overlapping workspace graphs to be compiled more than once.

## Non-goals

- No product behavior changes.
- No test-result caching.
- No remote build service or `sccache` deployment.
- No parallel GitHub jobs.
- No selectors, path filters, lane definitions, or dynamic test planning.
- No removal of a critical security or architecture invariant merely because it is slow.
- No new CI benchmark framework.

## Required implementation sequence

### Step 1 — Record the exact current execution graph

From a clean Linux checkout with nextest installed, run:

```bash
cargo xtask verify --dry-run
```

Record for each step:

- command
- Cargo profile used
- package(s) compiled
- test binary or property exercised
- whether another routine command compiles the same package graph
- whether the command executes tests or only compiles

Use the existing hosted timing as the primary baseline. One local warm-cache timing run is sufficient; do not create repeated statistical runs.

### Step 2 — Choose one routine Cargo profile

All routine compile, lint, and test commands must use one compatible Cargo profile wherever the tool supports it.

Preferred direction:

- use the existing `ci` profile for clippy, check, nextest, and cargo-test invocations
- inspect `[profile.ci]` and remove expensive optimization settings that do not prove a distinct routine property
- keep debug information only to the level needed for actionable failures
- do not use `--release`
- do not create a second `ci-fast` profile

If clippy or a specific command cannot safely share the profile, document the exact incompatibility and keep the exception narrow.

Acceptance for this step requires that the final command does not compile substantial root/workspace graphs independently under dev, test, and CI profiles.

### Step 3 — Remove redundant library compilation

Evaluate `cargo test --lib --no-run` against the preceding clippy/check and selected integration-test compilation.

Delete this step unless it is the only routine command that proves a named property. Compilation alone is not a distinct property when:

- clippy compiles the same library and targets
- selected integration tests compile and link the root library
- `cargo check --no-default-features` already proves the core-only build

If a missing target would otherwise be lost, add that target to a consolidated test invocation rather than retaining a full additional build.

### Step 4 — Consolidate test execution

Replace the current sequence of separate `cargo test --test ...` processes with the smallest static set of nextest/cargo invocations that preserves the same selected binaries.

Preferred bounded shape:

```text
1. fmt
2. clippy using the routine profile
3. core-only check using the routine profile
4. repo-guards nextest invocation
5. root-package critical integration tests in one nextest invocation
6. synvoid-core critical integration tests in one nextest invocation
```

A seventh or eighth Cargo invocation is allowed only for a concrete tool/profile limitation.

Implementation rules:

- The selected test-binary list remains static in Rust source or direct command arguments.
- Do not introduce nextest expression-generation code.
- Do not generate a manifest or selector file.
- Do not use a blanket workspace run in routine CI.
- Use repeated `--test` arguments or one direct nextest filter only if the resulting command is easy to read and supported by the installed nextest version.
- Preserve single-threaded execution for security tests only where their environment mutation requires it.
- If nextest cannot apply single-threading to only the security binary in a combined invocation, keep one separate security invocation rather than adding scheduler logic.

### Step 5 — Consolidate or relocate guard binaries only when necessary

First attempt process-level consolidation without moving tests.

Only if Cargo/nextest cannot run the selected root guard binaries in a bounded number of invocations may implementation reorganize the tests into a small number of integration-test binaries. In that case:

- preserve test names and failure messages
- group by existing domain, not by arbitrary size
- avoid one monolithic source file
- do not modify the production modules under test
- do not create a custom test runner

Suggested maximum groups:

```text
architecture and composition
lifecycle and supervision
admin, plugin, security, and ABI
```

This fallback is not preferred if command-line consolidation is sufficient.

### Step 6 — Correct command output and failure propagation

The wrapper must:

- print each consolidated command before execution without requiring `--verbose`
- fail immediately on a failed command
- report the failing step and child exit status
- avoid emitting a JSON report during normal CI
- retain `--dry-run` only as a human inspection aid

Do not add result parsing, JUnit output, or GitHub summary generation.

### Step 7 — Keep the workflow minimal

`.github/workflows/ci.yml` should remain structurally unchanged except where required by the final command.

Allowed changes:

- pin or update an action version when required by current GitHub runner support
- adjust cache settings to avoid storing clearly unnecessary target variants
- pass one explicit environment variable needed for the selected profile

Disallowed changes:

- a second job
- matrix entries
- path filters
- artifact upload
- an additional setup action abstraction
- scheduled or tag triggers

Inspect whether the current approximately 3.1 GB cache is inflated by obsolete profiles. After profile consolidation, permit one cache reset by changing the cache key naturally through lock/profile inputs. Do not add custom pruning scripts unless measured target content remains pathological after consolidation.

## Coverage preservation table

Before implementation, create a temporary mapping from each current routine step to its final command. The implementation is acceptable only when every retained property has one final owner.

Required properties:

| Property | Must remain routine? |
|---|:---:|
| formatting | yes |
| clippy warnings as errors | yes |
| no-default-feature/core compilation | yes |
| repository product guards | yes |
| security regression tests | yes |
| request/composition boundaries | yes |
| lifecycle/task ownership | yes |
| plugin load/runtime boundaries | yes |
| CLI/admin boundaries | yes |
| mesh identity/supervision/task ownership | yes |
| mutation authority and blocklist semantics | yes |
| ABI guest-memory boundary | yes |
| root test ownership | yes |

A property may be removed from routine only if it is demonstrated to be duplicate coverage of another retained deterministic test and the specific duplicate test is deleted, not merely skipped in CI.

## Local validation

Run from a clean checkout:

```bash
cargo fmt --all -- --check
cargo xtask verify --dry-run
time cargo xtask verify
```

Then run it a second time only to obtain a warm-cache value if the first run compiled from cold state.

Record:

- total Cargo invocations
- total wall time
- step durations
- number of profiles populated under `target/`
- command that owns each required property

## Failure injection

Use temporary edits and revert each immediately:

1. Formatting failure stops before Cargo compilation.
2. Clippy warning fails the consolidated clippy step.
3. Core-only compile defect fails the core check.
4. Security regression fails the security-owning invocation.
5. One root architecture guard failure identifies the exact test.
6. One `synvoid-core` admin test failure identifies the exact test.
7. A child-process launch failure causes the wrapper to return nonzero.

Do not create permanent fixtures solely for these seven checks.

## Hosted proof

Push the implementation and observe one ordinary `main` or pull-request run.

Required recorded values:

- run ID and commit SHA
- cache hit/miss state
- cache restore duration and size
- `cargo xtask verify` duration
- complete job duration
- final job conclusion
- number of jobs and workflows started

One successful measured hosted run is sufficient. Do not create a repeated performance workflow.

## Acceptance criteria

Phase 1 is complete only when:

- `cargo xtask verify` uses at most eight Cargo invocations.
- Routine compile/test commands use one primary Cargo profile, with any exception documented.
- `cargo test --lib --no-run` is absent unless a unique retained property is demonstrated.
- Selected root guard binaries are executed through one consolidated command or the smallest technically necessary bounded set.
- Critical security and product guards remain routine.
- Local warm-cache `verify` completes in ten minutes or less on the implementation environment.
- Hosted warm-cache `verify` completes in ten minutes or less.
- The complete hosted job completes in twelve minutes or less.
- The single workflow and single job topology remains intact.
- All seven failure injections fail at the expected owner.
- No selector, matrix, artifact, or new verification service is introduced.

## Stop conditions

Stop and document a blocker rather than weakening coverage when:

- one critical test binary alone exceeds the ten-minute budget due to a real product/runtime defect
- nextest cannot preserve required single-threading semantics
- profile consolidation changes a tested semantic property
- a guard is found to depend on production side effects rather than static or deterministic behavior

In those cases, create a narrow follow-up for the specific test or harness defect. Do not restore the old CI topology.
