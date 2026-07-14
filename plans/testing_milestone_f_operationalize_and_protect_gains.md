# Testing Infrastructure Milestone F — Operationalize and Protect the Gains

## Purpose

Milestone F closes the testing-infrastructure roadmap by turning the optimized CI and test architecture into a stable operating system for developers, reviewers, and release managers.

Milestones A through E should have produced:

- explicit PR, main, nightly, and release lanes;
- a dedicated CI profile;
- nextest scheduling and reporting;
- lightweight repository guards;
- reduced root test scope with enforced ownership;
- rationalized feature and target matrices;
- affected-package selection with fail-closed fallbacks;
- documented cache behavior;
- isolated test resources and lifecycle cleanup;
- narrowed serialization;
- separated fuzz, stress, property, interoperability, and performance workloads.

The remaining task is to make those gains durable. Milestone F provides one developer-facing command surface, aligns local and CI orchestration, defines measurable budgets, adds structural regression guards, validates coverage equivalence through controlled failures, and produces a final operating and closure report.

## Preconditions

Before implementation begins:

- Milestone D final closure is complete;
- Milestone E has stable resource classifications and nextest groups;
- authoritative commands exist for each validation lane;
- affected-package selection is proven on hosted runners;
- branch protection uses stable current checks;
- the feature/target matrix and test ownership documents are authoritative;
- timing data exists for cold, warm, affected, full, and specialized runs;
- known failing tests are either fixed, quarantined with explicit policy, or excluded from required lanes with documented rationale.

## Objectives

1. Provide one reproducible local test interface.
2. Route CI through shared orchestration where practical.
3. Make selector and lane decisions transparent and reproducible.
4. Define timing, structural, and resource budgets.
5. Detect regression in profiles, ownership, duplication, matrix size, and serialization.
6. Prove each assurance category still detects representative failures.
7. Verify branch protection and release qualification behavior.
8. Produce final operating, maintenance, and closure documentation.

## Non-goals

This milestone does not:

- replace Cargo, nextest, or GitHub Actions with a custom build system;
- hard-fail on noisy hosted-runner timing from the first release;
- treat one timing sample as a stable regression signal;
- require developers to run the full qualification lane before every commit;
- centralize all test logic into an opaque script;
- conceal the underlying Cargo commands needed for debugging;
- permanently preserve obsolete compatibility commands merely because they existed before the roadmap.

## Workstream F1 — Select the orchestration mechanism

Choose one primary interface:

- `cargo xtask`;
- `just` with checked-in recipes;
- a typed Rust test-driver binary;
- a small shell/Python wrapper only if it remains maintainable and portable.

Preferred direction: a workspace `xtask` crate because it can parse Cargo metadata, validate configuration, provide typed command dispatch, and work consistently across Linux, macOS, and Windows.

Suggested location:

```text
tools/xtask/
```

Suggested commands:

```bash
cargo xtask test fast
cargo xtask test affected --base origin/main
cargo xtask test package synvoid-dns
cargo xtask test guards
cargo xtask test security
cargo xtask test comprehensive
cargo xtask test nightly-plan
cargo xtask test qualification
cargo xtask test release
cargo xtask test list
cargo xtask test explain <lane-or-package>
```

The interface must expose the actual Cargo/nextest commands it executes.

### Exit criteria

- one primary developer command surface is selected and documented;
- it works on supported developer platforms;
- direct Cargo commands remain available for diagnosis;
- command behavior is covered by tests.

## Workstream F2 — Define stable lane contracts

Create a machine-readable lane manifest, for example:

```text
testing/lanes.toml
```

It should define:

- lane names;
- profiles;
- package groups;
- feature classes;
- test filters;
- platform requirements;
- specialized workload inclusion;
- timeout classes;
- whether affected selection applies;
- whether the lane is merge-blocking;
- expected artifacts.

Example conceptual structure:

```toml
[lane.fast]
profile = "ci"
affected = true
required = true
commands = ["fmt", "clippy", "guards", "security", "affected-packages"]

[lane.release]
profile = "release"
affected = false
required = false
commands = ["release-build-matrix", "full-tests", "all-features-clippy"]
```

The manifest should be consumed by local orchestration and, where practical, CI generation or validation.

Do not dynamically generate workflows unless the generation path is deterministic, reviewed, and guarded against drift. A validator comparing workflows to the manifest may be safer than full generation.

### Exit criteria

- lane semantics have one authoritative source;
- local and CI commands can be compared mechanically;
- undocumented lane additions fail a guard;
- feature/profile/target intent is visible without reading several workflow files.

## Workstream F3 — Implement local fast and affected commands

### Fast command

`cargo xtask test fast` should run the always-required local subset:

- formatting check;
- relevant Clippy scope;
- static/repository guards;
- core compile profile;
- security regression;
- affected or representative domain tests according to policy.

### Affected command

`cargo xtask test affected --base <ref>` should reuse the same selector logic and ownership data as CI.

Requirements:

- print base/head refs;
- print selector mode;
- print changed packages;
- print reverse dependents;
- print selected root tests;
- print fallback reasons;
- support `--dry-run`;
- support `--json`;
- support `--full`;
- return nonzero when any selected command fails;
- emit one copy-pasteable reproduction command per failure.

Avoid maintaining two independent selector implementations. The xtask should call or share a library with the existing selector.

### Exit criteria

- developers can reproduce CI package selection locally;
- output explains why each package or root test was selected;
- fallback behavior matches CI;
- direct and orchestrated results agree on fixture scenarios.

## Workstream F4 — Implement comprehensive, qualification, and release commands

Provide commands that represent—not necessarily execute every hosted-platform action locally—the higher lanes.

Examples:

```bash
cargo xtask test comprehensive
cargo xtask test qualification --plan
cargo xtask test release --plan
```

For unavailable local platforms, `--plan` should print:

- hosted job name;
- target/platform;
- command;
- required toolchain;
- expected artifacts;
- manual dispatch instructions.

The comprehensive command should run the authoritative primary-platform suite.

The release command must not silently substitute the CI profile for production release validation.

### Exit criteria

- each lane has a reproducible local command or explicit execution plan;
- production release profile semantics remain distinct;
- unsupported local platform work is clearly identified rather than skipped silently.

## Workstream F5 — Route CI through shared orchestration

Replace duplicated command sequences in workflows with stable orchestration commands where doing so improves consistency.

Good candidates:

- selector invocation;
- guard suite;
- security suite;
- package validation groups;
- result summarization;
- lane-manifest validation.

Retain direct workflow commands when:

- platform setup is clearer in YAML;
- artifact upload depends on job-local paths;
- a command is trivial and unlikely to drift;
- shell indirection would obscure failures.

Every CI failure should print the equivalent local command.

### Exit criteria

- local and CI orchestration share authoritative logic;
- workflow YAML remains readable;
- failures are reproducible without reverse-engineering Actions steps;
- no hidden behavior exists only in CI.

## Workstream F6 — Define performance budgets

Create:

```text
docs/testing/performance-budgets.md
```

Budgets should cover moving medians or percentiles across a defined observation window.

Initial categories:

- PR fast total wall-clock;
- selector duration;
- always-on job duration;
- affected package job duration;
- comprehensive lane duration;
- nightly qualification duration;
- release qualification duration;
- root guard binary count;
- root integration binary count;
- total Cargo invocation count per lane;
- feature/target matrix size;
- serialized test count;
- fixed-port count;
- arbitrary sleep count;
- slow-test count above threshold;
- cache restore/save overhead;
- cache hit rate where applicable;
- retry count;
- fuzz smoke duration;
- peak disk and memory for representative jobs.

Suggested initial nonblocking thresholds:

| Metric | Initial warning threshold |
|---|---:|
| PR fast moving median | >10 minutes |
| Selector duration | >30 seconds |
| Warm local affected loop | >60 seconds for localized changes |
| New root integration test file | any unapproved addition |
| New release-mode routine test | any unapproved addition |
| New fixed port | any unclassified addition |
| New global serialization override | any unclassified addition |
| Slow test | >30 seconds unless classified |
| Cache restore/save overhead | >25% of job duration |

Tune these using observed baselines.

### Exit criteria

- budgets are measurable;
- noisy metrics start as warnings;
- structural invariants may be blocking immediately;
- each budget has an owner and remediation path.

## Workstream F7 — Add structural regression guards

Extend the lightweight repository guard crate or a dedicated CI-policy validator to detect:

- routine `cargo test --release` outside release qualification;
- `lto = true` CI-profile regressions;
- duplicate test ownership in one lane;
- new root test files without ownership metadata;
- domain tests placed at root;
- inverted selector predicates;
- selector use in nightly or release lanes;
- missing fail-closed normalization;
- new fixed ports in ordinary tests;
- unclassified `--test-threads=1` usage;
- unclassified nextest serialization groups;
- unpinned critical actions where policy requires pinning;
- stale or duplicate feature/target matrix commands;
- workflow commands not represented in lane policy;
- missing local reproduction commands.

Guards must include negative fixtures proving they detect violations.

Avoid brittle exact-source assertions where semantic parsing or structured manifests are available.

### Exit criteria

- major roadmap regressions fail quickly;
- each guard has a negative fixture;
- exceptions are explicit and narrowly scoped;
- policy changes require deliberate documentation updates.

## Workstream F8 — Add cost-regression reporting

Extend `scripts/ci/summarize-test-costs.py` or replace it with the orchestration tool’s reporting module.

The report should include:

- current durations;
- moving baseline;
- percentage change;
- slowest tests;
- longest compilation units;
- Cargo invocation count;
- selected/skipped package jobs;
- root binary count;
- cache statistics where available;
- warning or blocking budget breaches.

Persist historical data using an appropriate mechanism:

- workflow artifacts with limited history;
- a metrics branch or generated data file;
- external metrics storage if already available;
- GitHub job summaries plus periodic committed snapshots.

Do not write untrusted PR data to a privileged branch or cache.

### Exit criteria

- reviewers can see whether a change materially increases test cost;
- comparisons use stable baselines rather than single-run absolutes;
- fork PRs do not gain write access to privileged storage;
- historical data retention is documented.

## Workstream F9 — Establish flaky-test policy

Create:

```text
docs/testing/flaky-test-policy.md
```

Define:

- what qualifies as flaky;
- evidence required;
- quarantine process;
- retry policy;
- owner assignment;
- maximum quarantine duration;
- required issue/plan linkage;
- criteria for restoration;
- prohibition on broad retries hiding deterministic races.

Recommended rules:

- no automatic retries by default;
- retries only for documented external nondeterminism;
- quarantined tests remain visible and run in a nonblocking lane;
- security-critical tests require accelerated remediation;
- quarantine metadata includes owner, date, reason, and expiration;
- repeated failures generate a report.

### Exit criteria

- retries and quarantine are governed;
- no test disappears silently from assurance;
- flaky tests have owners and expiry dates;
- deterministic failures are fixed rather than retried.

## Workstream F10 — Coverage-equivalence matrix

Create:

```text
docs/testing/coverage-equivalence-matrix.md
```

Map every pre-roadmap assurance category to the new authoritative lane and command.

Categories should include:

- formatting;
- Clippy;
- default compile;
- no-default core compile;
- all-features compile;
- unit tests;
- domain integration tests;
- root composition tests;
- architecture guards;
- security regressions;
- DNS interoperability;
- mesh behavior;
- plugin runtime;
- upload/honeypot/tarpit;
- docs;
- dependency audit;
- Miri;
- fuzz;
- Alpine/musl;
- FreeBSD;
- macOS;
- Windows;
- release artifacts;
- performance and stress.

For each category record:

- old command/job;
- new command/job;
- lane;
- profile;
- feature set;
- platform;
- frequency;
- evidence of successful execution;
- responsible owner.

### Exit criteria

- no assurance category is unowned;
- removed duplicate commands have an equivalent authoritative owner;
- release and scheduled coverage remain explicit;
- the matrix is validated against workflows and lane manifests.

## Workstream F11 — Controlled failure injection

Prove that representative failures are detected by the intended lanes.

Use temporary branches or controlled patches that are not merged.

Required injections:

1. formatting violation;
2. Clippy warning promoted to error;
3. unit-test assertion failure;
4. domain integration failure;
5. root composition failure;
6. architecture-boundary violation;
7. security-regression failure;
8. selector failure causing full fallback;
9. omitted ownership entry;
10. duplicate/release-profile workflow regression;
11. platform-specific compile error;
12. fuzz target crash fixture;
13. release build or packaging failure.

For each injection record:

- patch description;
- expected lane/job;
- actual detected lane/job;
- whether branch protection blocked merge;
- whether local reproduction command matched;
- cleanup confirmation.

Never leave intentional failures on `main`.

### Exit criteria

- every critical lane detects its representative failure;
- selector fallback expands rather than narrows validation;
- branch protection blocks required failures;
- release-only failures are caught before release publication;
- evidence is retained in the closure report.

## Workstream F12 — Branch-protection and workflow authority validation

Perform a final live audit:

- required checks use current stable names;
- no legacy workflow is authoritative;
- aggregate summary behavior is correct with skipped jobs;
- cancellation does not leave ambiguous required checks;
- manual force-full dispatch works;
- main/nightly/release workflows have appropriate permissions;
- fork PRs do not receive privileged secrets;
- artifact retention is adequate;
- workflow concurrency groups are correct;
- release workflow requires the intended trigger or approval.

Document exact repository settings that cannot be represented in source control.

### Exit criteria

- branch protection matches documented policy;
- required checks are stable and always produced;
- optional skipped jobs cannot block merge unexpectedly;
- privileged workflows are safe for external contributions.

## Workstream F13 — Final operating guide

Create:

```text
docs/testing/operating-guide.md
```

Include:

- which command to run before committing;
- which command to run before opening a PR;
- how to run affected tests;
- how to force full validation;
- how to reproduce CI failures;
- how to add a new test;
- how to classify a new resource requirement;
- how to add a feature/target matrix entry;
- how to add a new fuzz target;
- how to quarantine a flaky test;
- how to update performance budgets;
- how to run release qualification;
- how to interpret artifacts and summaries;
- ownership and escalation paths.

Update `AGENTS.md` with a concise command reference linking to the guide.

### Exit criteria

- developers have one authoritative testing guide;
- common operations require no workflow archaeology;
- test additions include ownership, lane, resource, and budget classification.

## Workstream F14 — Final closure report

Create:

```text
plans/testing_infrastructure_roadmap_closure_results.md
```

The report must include:

- roadmap phase and milestone status;
- before/after workflow topology;
- before/after root test count;
- before/after Cargo invocation count;
- before/after PR median duration;
- affected-package skip rates;
- compilation and cache behavior;
- slow-test and serialization reductions;
- fixed-port and sleep reductions;
- fuzz/stress lane status;
- coverage-equivalence results;
- failure-injection results;
- branch-protection verification;
- remaining deferred items;
- maintenance ownership;
- final go/no-go assessment.

Be explicit about unmeasured or externally constrained results. Do not claim improvements without evidence.

## Recommended implementation sequence

1. Select orchestration mechanism and create lane manifest.
2. Implement fast and affected commands.
3. Implement comprehensive/qualification/release commands.
4. Align CI with shared orchestration.
5. Define performance and structural budgets.
6. Add regression guards and negative fixtures.
7. Add cost reporting and historical baselines.
8. Establish flaky-test policy.
9. Build coverage-equivalence matrix.
10. Run controlled failure injection.
11. Validate branch protection and workflow authority.
12. Publish operating guide and closure report.

## Validation matrix

At minimum:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo check --workspace --profile ci
cargo xtask test list
cargo xtask test fast
cargo xtask test affected --base HEAD~1 --dry-run
cargo xtask test guards
cargo xtask test security
cargo xtask test comprehensive
cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci
python3 -m pytest tests/ci
```

Run hosted main, nightly, and release workflows and retain artifacts before closure.

## Rollback strategy

- If xtask orchestration obscures failures, retain direct workflow commands and use xtask as a validator/planner until parity is proven.
- If performance thresholds are noisy, keep them warning-only and collect a longer baseline.
- If a structural guard is brittle, replace token matching with manifest or syntax-aware validation.
- If historical metric storage creates security or maintenance risk, retain periodic committed snapshots and job summaries.
- If failure injection exposes missing coverage, restore or add the authoritative command before closing the roadmap.

## Final roadmap exit criteria

The testing-infrastructure roadmap is complete only when:

- developers have one stable test command surface;
- local and CI lane behavior are mechanically aligned;
- affected selection is transparent and reproducible;
- performance and structural budgets exist;
- major cost and ownership regressions are guarded;
- flaky-test handling is governed;
- every assurance category has an authoritative owner;
- controlled failures are detected in the intended lanes;
- branch protection and release qualification are verified live;
- the operating guide is complete;
- before/after evidence is committed;
- remaining deferred work is explicit and does not undermine correctness or release assurance.
