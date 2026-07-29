# CI Simplification Phase 1 — Contract and Deletion Inventory

## Status

Planned. This is the first implementation phase of `plans/ci_verification_release_simplification_roadmap.md`.

## Objective

Freeze a small, explicit verification contract before deleting the current CI architecture. This phase prevents two failure modes: deleting meaningful product assurance without noticing, and preserving CI self-assurance merely because it already exists.

The output is an executable decision record that tells the Phase 2 and Phase 3 implementers exactly what remains, what moves to local verification, and what is deleted without replacement.

## Constraints

- Do not edit workflow behavior beyond minimal instrumentation needed to measure commands.
- Do not create a fifth lane, migration workflow, compatibility workflow, or shadow CI system.
- Do not preserve the affected-package selector as a temporary default path.
- Do not treat every existing check as a required assurance category.
- Do not rewrite historical plans or results to imply that the previous architecture never existed.
- Do not defer the routine command decision to a later phase; this phase must freeze it.

## Required deliverables

Create or update:

```text
docs/testing/verification-contract.md
docs/testing/ci-deletion-inventory.md
plans/ci_simplification_phase_01_contract_and_deletion_inventory.md
```

The implementation may update `AGENTS.md` only enough to point readers to the new contract as pending authority. Full documentation cleanup belongs to Phase 4.

## Workstream 1 — Inventory active execution surfaces

Enumerate every active and manually triggerable GitHub Actions workflow, job, trigger, matrix entry, reusable action, and uploaded artifact.

Record at minimum:

- workflow path and displayed name
- triggers: pull request, branch push, tag push, schedule, manual dispatch
- job name and runner
- matrix dimensions
- Cargo commands
- non-Cargo scripts
- system package installation
- caches
- artifact uploads
- summary jobs
- `continue-on-error` and shell-level failure suppression
- branch-protection relevance
- whether the job proves a product property or only validates CI structure

Suggested commands:

```bash
find .github/workflows -maxdepth 1 -type f -print | sort
find .github/actions -maxdepth 3 -type f -print | sort
rg -n '^(name:|on:|jobs:)|pull_request:|workflow_dispatch:|schedule:|tags:|matrix:|runs-on:|cargo |cross |upload-artifact|continue-on-error|\|\| true|\|\| echo' .github
```

The inventory must cover `ci.yml`, `pr-fast.yml`, `main-comprehensive.yml`, `nightly-qualification.yml`, and `release-qualification.yml` as they exist at implementation start.

## Workstream 2 — Inventory command authorities and CI control-plane code

Identify every location that declares, mirrors, interprets, or validates verification commands.

Include:

- `testing/lanes.toml`
- xtask test-lane command definitions
- `scripts/ci/select-affected.py`
- `scripts/test-affected.sh`
- selector tests and fixtures
- reusable setup actions
- CI policy guards
- selector polarity and normalization guards
- lane consistency guards
- branch-protection documentation
- cache policy tied to lane/job naming
- test ownership tables tied to lane names
- docs that call the four-lane system authoritative

Suggested commands:

```bash
rg -n 'lanes\.toml|cargo xtask test|select-affected|test-affected|ci_lane|selector_|PR Fast|Main Comprehensive|Nightly Qualification|Release Qualification' . --glob '!target/**'
rg -n 'pr-fast\.yml|main-comprehensive\.yml|nightly-qualification\.yml|release-qualification\.yml' . --glob '!target/**'
find tools scripts testing docs -type f -print | sort
```

For each item, classify it as:

- `KEEP_PRODUCT_ASSURANCE`
- `KEEP_LOCAL_ONLY`
- `SIMPLIFY_AND_KEEP`
- `DELETE_CI_SELF_ASSURANCE`
- `HISTORICAL_RECORD`

No item may remain unclassified.

## Workstream 3 — Define assurance categories independently of jobs

Create a property-oriented assurance table. Do not start from workflow jobs. Start from properties the repository actually needs to protect.

At minimum evaluate:

- formatting
- warning-free compilation and linting
- primary Linux compilation
- default-feature correctness
- no-default-feature correctness
- important optional-feature compilation
- workspace library/unit behavior
- cross-crate composition behavior
- security regression behavior
- repository/source architecture boundaries
- plugin ABI and lifecycle boundaries
- DNS behavior
- mesh behavior
- documentation compilation
- package assembly
- publish dry run
- platform-specific compilation
- fuzzing
- Miri
- stress/endurance behavior
- dependency policy and vulnerability audit

For each property record:

| Property | Existing commands | Current frequency | Required routine CI? | Required full local? | Required release local? | Disposition rationale |
|---|---|---|---|---|---|---|

A property is routine-CI eligible only if all are true:

1. It catches regressions likely enough to justify every-commit execution.
2. It is deterministic on hosted Ubuntu.
3. Its cost is proportionate to its incremental assurance.
4. It does not duplicate another retained command.
5. Its failure requires immediate developer action before merge.

## Workstream 4 — Measure candidate routine contracts

Measure candidate static command sets on the same commit and environment. At minimum compare:

### Candidate A — broad workspace correctness

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --profile ci --exclude synvoid-fuzz
```

### Candidate B — bounded routine suite

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo check --workspace
cargo test --workspace --lib --profile ci --exclude synvoid-fuzz
cargo test -p synvoid-repo-guards --profile ci
cargo test --test security_regression --profile ci -- --test-threads=1
```

### Candidate C — bounded suite with explicit critical composition tests

Candidate B plus the smallest nonduplicative set of root integration targets required to protect cross-crate startup, lifecycle, admin, mesh, DNS, and plugin boundaries.

The implementer may adjust invalid Cargo syntax or package exclusions based on actual workspace metadata. Every adjustment must be recorded.

For each candidate capture:

- cold wall time
- warm wall time
- peak memory where available
- number of Cargo invocations
- number of compiled test binaries
- duplicated test targets
- failed or unsupported commands
- properties covered and omitted

Do not create hard performance infrastructure. A checked-in Markdown table with reproducible commands is sufficient.

## Workstream 5 — Freeze the routine command

Select one static command contract and document it in `docs/testing/verification-contract.md`.

The selected contract must:

- complete within a practical routine-CI budget on Ubuntu
- include formatting and warning-as-error linting
- compile the primary supported configuration
- run a bounded deterministic test set
- run critical security regression with required serialization
- run product-level repository guards through one consolidated command
- avoid per-package affected selection
- avoid a target, OS, or feature matrix
- avoid release-profile builds
- avoid routine doctest duplication unless doctests are the only test for a critical behavior

The contract must be expressed as one human-facing command, for example:

```bash
cargo xtask verify
```

or:

```bash
./scripts/verify.sh
```

Choose the implementation form with the lower total maintenance burden. If xtask is retained, remove lane planning, affected selection, JSON output, lane explanation, and workflow parity concepts in Phase 3. If a script is chosen, it must be small, fail-fast, portable across supported local Linux/macOS shells where practical, and must not become a command graph framework.

## Workstream 6 — Freeze full and release contracts

Define but do not yet fully implement:

### Full local verification

Must include broader workspace tests, important feature compilation, doctests where meaningful, and domain-specific suites omitted from routine CI. It is manually invoked before risky merges and during focused subsystem work.

### Release verification

Must include:

- routine verification
- full local verification
- all publishable crate package assembly
- inspection of package file lists
- `cargo publish --dry-run` in dependency order
- release metadata checks
- no actual publication

Fuzzing, Miri, stress, and platform-specific checks are separate explicit tools. Do not silently bundle all of them into every release verification unless the support statement requires them and the maintainer explicitly chooses that cost.

## Workstream 7 — Produce the deletion manifest

`docs/testing/ci-deletion-inventory.md` must list every file or code section scheduled for deletion or rewrite in Phases 2–4.

Use columns:

| Path/symbol | Current purpose | Disposition | Replacement | Owning phase | Verification |
|---|---|---|---|---|---|

Expected deletion candidates include:

```text
.github/workflows/pr-fast.yml
.github/workflows/main-comprehensive.yml
.github/workflows/nightly-qualification.yml
.github/workflows/release-qualification.yml
scripts/ci/select-affected.py
scripts/test-affected.sh
testing/lanes.toml
selector-specific tests and fixtures
CI lane consistency guards
selector predicate/normalization guards
CI policy guards that enforce the four-lane topology
routine JUnit parsing and artifact-upload plumbing
```

The inventory must distinguish whole-file deletion from targeted removal of CI-specific tests inside a product guard crate.

## Failure-injection requirements

Before freezing the routine contract, prove it fails for each class below using temporary changes or dedicated throwaway branches. Do not commit injected defects to `main`.

1. Formatting violation.
2. Clippy warning promoted to error.
3. Primary Linux compilation error.
4. Ordinary unit-test failure.
5. Critical security-regression failure.
6. Product-level architecture guard failure.
7. Failure inside the chosen command wrapper propagates a nonzero exit status.

Record command, expected failure point, actual failure point, and whether later commands were skipped or reported.

## Acceptance criteria

Phase 1 is complete only when:

- Every workflow and verification command authority is inventoried.
- Every current check is classified by product property and disposition.
- Candidate routine contracts are measured on the same commit.
- One routine command is frozen.
- One full local contract and one release contract are frozen.
- The selected routine command has no affected-package selector or matrix.
- The deletion manifest names all obsolete workflow and control-plane components.
- Product-level security and architecture guards are distinguished from CI-policy guards.
- All seven failure-injection classes are demonstrated.
- Phase 2 can implement the workflow without making new scope decisions.

## Rejection searches

The phase is not complete if any of these questions cannot be answered from the two deliverable documents:

```bash
rg -n 'UNCLASSIFIED|TBD|TO DECIDE|UNKNOWN' docs/testing/verification-contract.md docs/testing/ci-deletion-inventory.md
rg -n 'select-affected|test-affected' docs/testing/verification-contract.md
rg -n 'schedule|tag-trigger|release artifact|platform matrix' docs/testing/verification-contract.md
```

The final two searches may contain explicit prohibition text; they must not prescribe those mechanisms as part of routine CI.

## Handoff note

Phase 2 must implement the frozen routine command exactly. If implementation reveals an invalid command, correct the contract document in the same commit with an explicit rationale; do not improvise a broader suite or restore selector behavior.
