# CI Simplification Phase 4 — Manual Release and Documentation

## Status

Planned. This phase depends on stable `verify`, `verify-full`, and `verify-release` command contracts from Phase 3.

## Objective

Codify a manual crates.io release process and remove all current documentation, command language, and repository assumptions that imply GitHub Actions controls release qualification or release cadence.

The release process must be explicit, reproducible, and small. It must verify the exact source package that will be published, but it must not become a second CI system, an evidence-collection framework, or an automated publication pipeline.

## Binding release decisions

- Publication is manual through `cargo publish`.
- Release cadence is decided by the maintainer.
- GitHub Actions does not publish, approve, qualify, schedule, or assemble releases.
- Version tags do not trigger workflows.
- GitHub releases are optional and manual.
- crates.io is the authoritative package distribution channel for publishable Rust crates.
- Published crate versions are immutable. A failed or defective publication is corrected with a new version, not by overwriting the existing version.

## Required deliverables

Create or update:

```text
docs/releasing.md
docs/testing/verification-contract.md
AGENTS.md
README.md
```

Update crate-level READMEs or manifests only where release instructions or publish metadata are inaccurate.

Delete or rewrite current operational documents that present release qualification as a GitHub Actions lane.

## Workstream 1 — Inventory publishable crates and dependency order

Use workspace metadata and manifest inspection to identify every publishable crate.

For each crate record:

- package name
- manifest path
- current version
- `publish = false` status, if any
- internal path dependencies
- crates.io dependency version constraints
- whether README, license, repository, documentation, keywords, and categories metadata are present
- required publication predecessors
- whether the root binary/package is publishable

Suggested commands:

```bash
cargo metadata --no-deps --format-version 1
find . -name Cargo.toml -not -path './target/*' -print | sort
rg -n '^name\s*=|^version\s*=|^publish\s*=|path\s*=|version\s*=' Cargo.toml crates/*/Cargo.toml tools/*/Cargo.toml
```

Create a publication-order table in `docs/releasing.md`.

Do not assume every workspace member should be published. Internal-only crates must remain explicitly nonpublishable.

## Workstream 2 — Implement `verify-release`

`verify-release` must execute locally and must not publish.

Required sequence:

1. Confirm a clean working tree, or clearly warn and require an explicit override for local experimentation.
2. Run `verify`.
3. Run `verify-full`.
4. Validate package metadata for each publishable crate.
5. Run `cargo package --list` for each publishable crate.
6. Inspect package contents for missing README/license/source files and accidental inclusion of secrets, build outputs, corpora, large fixtures, local state, or planning artifacts.
7. Run `cargo package` or `cargo publish --dry-run` in dependency order.
8. Confirm local path dependencies have publishable version specifications.
9. Stop on the first failed crate and identify the exact crate and command.
10. Print the manual publication order without invoking `cargo publish`.

The command must not:

- read a crates.io token
- invoke `cargo publish`
- create a Git tag
- create a GitHub release
- upload binaries
- mutate versions automatically
- modify changelogs automatically
- persist a release evidence ledger

## Workstream 3 — Package-content inspection

For every publishable crate, document the expected package surface.

At minimum reject accidental inclusion of:

```text
target/
.git/
.env files
credentials or key files
fuzz corpora and crash artifacts
CI timing artifacts
JUnit output
local databases
large generated files not required to build
plans/ unless intentionally part of a published root package
```

Use `cargo package --list` as the primary source of truth. Do not invent a separate package manifest unless Cargo's output cannot express a required constraint.

Where a crate requires generated source or bundled assets, document why each asset is required and how it is reproduced.

## Workstream 4 — Manual publication procedure

`docs/releasing.md` must provide a command-oriented procedure.

Required order:

### Prepare

- update intended crate versions
- update internal dependency version constraints
- update changelog or release notes
- confirm repository state and target commit
- run `verify-release`

### Dry run

- run the documented package and dry-run commands in dependency order
- verify crate names and versions are currently available
- inspect warnings rather than suppressing them generically

### Publish

- authenticate to crates.io through the maintainer's local Cargo configuration
- run `cargo publish` manually for each crate in dependency order
- wait for each dependency to become resolvable from crates.io before publishing dependents
- verify the published crate page and downloadable package

### Record

- create the version tag only at the documented point
- push the tag manually
- optionally create a GitHub release manually
- record any release notes without attaching CI-generated binaries unless separately intended

The guide must choose one tag ordering and explain it. Preferred default:

1. Verify exact commit locally.
2. Publish crates.
3. Verify crates.io availability.
4. Create and push the tag pointing to the verified commit.

This avoids a public tag implying successful publication before crates.io accepts the release. If repository policy chooses tag-before-publish, the recovery procedure must explicitly cover a failed publication after tagging.

## Workstream 5 — Immutable-version recovery

Document crates.io immutability and failure recovery.

Required scenarios:

- one crate publishes but a dependent crate fails
- package metadata is wrong after publication
- docs.rs fails after publication
- a severe defect is discovered after publication
- a version number was reserved or published unintentionally
- a crate must be yanked

Required rules:

- never attempt to overwrite a published version
- correct source and increment the affected version
- update dependent version constraints as needed
- use `cargo yank` only when appropriate and document the reason
- do not delete tags silently; if tag history must be corrected, document the exact repository policy
- do not automate retries that could publish an unintended source tree

## Workstream 6 — Remove release automation references

Search and remove active references to:

- release qualification workflow
- tag-triggered validation
- GitHub Actions artifacts as release deliverables
- automated crates.io publishing
- workflow dispatch as the release gate
- nightly qualification as release evidence
- required release summary jobs
- GitHub CI determining release cadence

Suggested search:

```bash
rg -n 'release-qualification|Release Qualification|tag-trigger|push.*tags|workflow_dispatch.*release|cargo publish|crates.io|upload-artifact|release artifact|GitHub release' README.md AGENTS.md docs scripts tools .github Cargo.toml crates
```

Not every `cargo publish` or crates.io match is wrong. Current documentation should describe manual commands only. No active workflow or script may publish automatically.

## Workstream 7 — Rewrite AGENTS.md verification guidance

Replace the four-lane and selector sections with a concise command hierarchy.

The final guidance should identify:

```text
routine development: verify
broader correctness: verify-full
release preparation: verify-release
specialist checks: direct documented commands
publication: manual cargo publish only
```

Remove:

- four-lane tables
- selector commands
- lane explanation commands
- release qualification language
- statements that nextest or release profile is preferred for routine CI unless still true under the frozen contract
- lists of branch-protection checks that no longer exist

Retain product-level security rules and subsystem-specific commands that remain accurate.

## Workstream 8 — Establish truthful platform support language

Review README and platform documentation.

Classify platforms as:

- primary supported and routinely verified
- manually verified or best effort
- not currently qualified

Do not infer support from historical matrix entries.

The primary routine-CI statement should describe Ubuntu/Linux only unless the project deliberately maintains another required runner.

For platform-specific changes, document the maintainer expectation to run the relevant local or manual environment check before merging or releasing. Do not reintroduce an automated matrix.

## Workstream 9 — Security and secret handling

Verify that:

- no crates.io token is referenced in repository workflows
- no publication credential is expected by `verify-release`
- documentation does not instruct users to commit credentials
- local Cargo authentication is described without exposing token values
- package-content inspection rejects common secret file patterns
- release commands print no tokens

## Failure-injection requirements

Demonstrate without publishing:

1. `verify-release` fails on a dirty tree under the chosen policy.
2. `verify-release` fails when a publishable crate package omits a required file.
3. `verify-release` fails when a crate package includes a prohibited test secret fixture or generated credential-like file.
4. `verify-release` fails when an internal dependency lacks a publishable version requirement.
5. A dependent crate dry run fails clearly when its predecessor is unavailable.
6. No command in `verify-release` invokes actual publication.
7. A simulated partial-publication scenario has an unambiguous next-version recovery sequence in the guide.

Use local fixtures or temporary branches. Do not publish test crates or versions.

## Acceptance criteria

Phase 4 is complete only when:

- `docs/releasing.md` identifies all publishable and nonpublishable workspace members.
- Publication order is explicit.
- `verify-release` performs local verification, package inspection, and dry runs without publishing.
- Package-content inspection is based on Cargo's actual package list.
- The manual guide covers preparation, dry run, publication, crates.io verification, tagging, optional GitHub release, yanking, and immutable-version recovery.
- No workflow or repository script publishes crates.
- No workflow triggers from version tags.
- AGENTS.md no longer describes four CI lanes or affected selection.
- README and current docs accurately describe the primary supported platform and manual release model.
- No crates.io or signing secret is required for verification.
- All seven failure-injection scenarios are demonstrated.

## Rejection searches

The phase must not close with active automation matches:

```bash
rg -n 'cargo publish' .github scripts tools --glob '!**/testdata/**'
rg -n 'push:\s*$|tags:' .github/workflows
rg -n 'release-qualification|Release Qualification|four validation lanes|PR Fast|Main Comprehensive|Scheduled Qualification' README.md AGENTS.md docs .github scripts tools
rg -n 'upload-artifact|release artifact' .github/workflows
rg -n 'CARGO_REGISTRY_TOKEN|CRATES_IO_TOKEN|crates.*token' .github scripts tools
```

Manual `cargo publish` examples are expected only in release documentation and must be clearly labeled as maintainer-executed commands.

## Stop conditions

Do not proceed to closure if:

- package dry runs are not performed against actual package contents
- publication order is inferred rather than documented
- any workflow still reacts to tags
- any script can publish after a confirmation prompt or environment flag
- support documentation still claims routine qualification on deleted platforms
- immutable-version recovery is omitted

Correct the release contract directly. Do not add GitHub Actions release automation as a workaround.
