# CI Simplification Corrective Phase 2 — Full and Release Contract Correction

## Status

Planned. Begins after Phase 1 has stabilized the routine command and its shared execution primitives.

## Objective

Make `cargo xtask verify-full` and `cargo xtask verify-release` usable, deterministic, and semantically correct without turning either command into another CI topology.

The full verifier must provide broader local assurance without intentionally rerunning the routine suite through a blanket workspace command. The release verifier must validate the exact source/package surfaces that can be validated before publication, use correct Cargo dependency semantics, and remain incapable of publishing.

## Current defects

- `verify-full` prepends all routine commands and then runs broad workspace tests that re-execute repository guards, security regression tests, and root guard binaries.
- The current full run fails on WAF wave/stress and proxy-pipeline tests, including timeouts.
- `verify-release` inherits the failing full run.
- Release package discovery partly relies on line-oriented `Cargo.toml` parsing even though Cargo metadata exposes package and dependency facts.
- Internal path dependencies are rejected unless they use `version = "*"`, which is not a valid publication policy.
- Package-content rules match broad substrings such as `secret`, creating false-positive risk for legitimate source paths.
- Dirty working trees only warn.
- Running `cargo publish --dry-run` for every newly versioned crate before internal predecessors exist on crates.io can fail for reasons unrelated to package correctness.

## Non-goals

- No automated publication.
- No GitHub release creation.
- No version bump automation.
- No changelog generator.
- No crates.io network polling service.
- No product feature refactor.
- No blanket suppression of failing tests.
- No reintroduction of nightly or release workflows.

## Part A — Correct `verify-full`

### A1. Define a full-only property inventory

List the properties not already owned by routine verification. The initial expected set is:

- mesh-only feature compilation
- DNS-only feature compilation
- combined mesh+DNS feature compilation
- deterministic workspace unit/integration tests not already selected by routine
- doctests
- DNS subsystem tests not included through the workspace selection
- plugin-runtime subsystem tests not included through the workspace selection
- deterministic honeypot and tarpit tests

Do not include a step merely because it existed in the old comprehensive/nightly lanes.

### A2. Stop prepending the complete routine command

Refactor command construction so `verify-full` does not call `verify_steps()` and then append a blanket workspace test.

Use shared primitive groups rather than command nesting. Acceptable groups include:

```text
format/lint preflight
feature compilation
routine critical tests
broad deterministic tests
subsystem-only tests
release-only checks
```

`verify` and `verify-full` may share a cheap formatting/lint step when the command is invoked independently, but full verification must not run a routine test binary and then run the same binary again through `nextest --workspace`.

### A3. Build an explicit test disposition

From the current `nextest-all` failures, classify every failing or timing-out test as one of:

- `REAL_PRODUCT_REGRESSION`
- `STALE_EXPECTATION`
- `HARNESS_OR_TIMEOUT_DEFECT`
- `STRESS_OR_ENDURANCE`
- `ENVIRONMENT_DEPENDENT`

Rules:

- A real product regression remains blocking and receives a separate product issue/plan; do not exclude it to green the verifier.
- A stale expectation may be corrected in test code without changing production behavior.
- A harness/timeout defect may be corrected in fixtures, clocks, resource setup, or teardown.
- A stress/endurance test moves to a direct documented specialist command and is removed from the default full suite.
- An environment-dependent test must either create its own bounded environment or move to a clearly named manual platform/integration command.

Do not use name-pattern exclusions without a checked-in disposition table in `docs/testing/verification-contract.md`.

### A4. Use one broad deterministic invocation

Prefer a single nextest invocation covering deterministic workspace tests, with explicit package/binary exclusions only for:

- `synvoid-fuzz`
- stress/endurance suites assigned to specialist commands
- platform-only tests that cannot run on the primary Linux environment
- routine critical binaries when nextest can exclude them cleanly and they would otherwise be repeated

Keep expressions readable. Do not generate them dynamically.

If excluding all routine binaries makes the expression fragile, choose the simpler alternative: do not run routine critical binaries separately in `verify-full`; let the broad deterministic command own them once. The full command is not required to preserve routine step-level ordering.

### A5. Avoid subsystem duplication

Before retaining separate DNS, plugin, honeypot, or tarpit commands, confirm whether the broad deterministic invocation already executes those binaries.

Retain a separate subsystem command only when it enables a distinct feature/profile or test set not included by the broad command. Record that distinction in the verification contract.

### A6. Full command acceptance

`verify-full` must:

- execute from a clean checkout without external services unless explicitly documented
- complete with no known failure or timeout
- stop on the first command failure
- avoid executing any test binary twice intentionally
- avoid release profile, fuzzing, Miri, platform matrices, or package publication checks
- remain a manually invoked local command

## Part B — Correct publishable package discovery

### B1. Use `cargo metadata` as the authority

Discover workspace members and publishability through Cargo metadata.

Use metadata fields for:

- package name and version
- manifest path
- `publish` restrictions
- dependency name, source, path, and semver requirement
- workspace membership

Do not infer `publish = false` with line-prefix scanning.

A small manifest read is allowed only for metadata that Cargo does not expose, such as validating an explicitly referenced README path. Prefer a proper existing parser if one is already present; do not reintroduce a large dependency solely for trivial checks.

### B2. Define the publishable set explicitly

Generate the discovered set and compare it with documented intent.

For each member classify:

- `PUBLISHABLE`
- `INTERNAL_ONLY`
- `EXAMPLE_ONLY`
- `FUZZ_OR_TOOLING`

The classification should be expressed in manifests with `publish = false` wherever possible. Minimize hard-coded crate-name lists in xtask.

Acceptance requires that a newly added workspace member cannot become publishable accidentally merely because it is absent from a constant list.

### B3. Correct dependency-version policy

For a publishable crate with an internal path dependency:

- require a registry-compatible semver requirement
- reject a missing version requirement
- reject `*` unless an explicit repository policy justifies it for a specific crate
- accept ordinary compatible requirements such as `0.1`, `^0.1.0`, or an inherited workspace requirement
- verify that the requirement contains the dependency's intended published version
- allow dev-dependencies to follow Cargo publication rules, but do not treat them as runtime publication predecessors when Cargo excludes them

Use Cargo metadata's parsed requirement rather than substring extraction.

### B4. Topological ordering

Topologically sort publishable crates using internal normal/build dependencies that must resolve from crates.io. Detect and report cycles with package names.

Do not recurse into nonpublishable internal dependencies as though they could be published. Instead fail with an actionable message when a publishable crate depends on an internal-only crate in a way Cargo cannot publish.

## Part C — Correct package-content validation

### C1. Keep `cargo package --list` as source of truth

Run `cargo package --list -p <crate>` for each publishable crate and inspect normalized relative paths.

### C2. Replace broad substring matching

Use path-aware rules.

Reject by exact component or extension where appropriate:

```text
target/
.git/
.env and .env.*
known private-key extensions: .key, .pem, .p12, .pfx, .keystore
known private-key basenames: id_rsa, id_ed25519, id_ecdsa
credential-store names: credentials, credentials.toml, htpasswd
fuzz corpus/crash directories
local database or generated evidence directories explicitly identified by the repository
```

Do not reject arbitrary source files because a path contains `secret`, `private_key`, or `key` as part of a legitimate module name.

For certificate/test-vector fixtures:

- permit only intentionally checked-in public or synthetic fixtures
- require a narrow path allowlist and comment explaining why publication is needed
- never permit real private credentials

### C3. Metadata validation

For every publishable crate require:

- nonempty description
- license or license-file
- repository URL, inherited or direct
- README path exists when declared
- crate name/version are documented in the publication-order table

Correct missing manifest metadata in this phase. These are package-surface changes, not production behavior changes.

## Part D — Correct release preparation semantics

### D1. Dirty-tree policy

`cargo xtask verify-release` must fail on a dirty tree by default.

Provide one explicit `--allow-dirty` flag for local experimentation. When used:

- print a prominent warning
- record that package output is not release evidence
- do not change any other validation behavior

Do not infer permission from an environment variable.

### D2. Separate package assembly from registry dry-run

The pre-publication release verifier must be able to pass before newly versioned internal dependencies exist on crates.io.

Required default sequence:

1. run corrected `verify-full`
2. validate publishable package metadata
3. validate internal dependency requirements and publication order
4. inspect `cargo package --list`
5. assemble each package with `cargo package --no-verify` or the narrow Cargo command that validates package construction without requiring unpublished internal versions from the registry
6. print the manual publication order

Do not call actual `cargo publish`.

Document that the maintainer runs:

```bash
cargo publish --dry-run -p <crate>
cargo publish -p <crate>
```

for each crate in topological order, after predecessor versions are available from crates.io.

If Cargo provides a reliable workspace-local dry-run mechanism at implementation time, it may be used only when it works before publication and does not require a private registry or temporary registry server.

### D3. Package verification after assembly

Because `--no-verify` skips Cargo's packaged-source build, retain correctness through the already completed full source verification and add one bounded packaged-source check where feasible for crates whose dependencies are already resolvable.

Do not build a local registry emulator. For a multi-crate release with unpublished internal versions, the truthful contract is:

- source tree fully verified before release
- package contents inspected before release
- per-crate `cargo publish --dry-run` performed manually immediately before each actual publish

### D4. Publication incapability

Add a direct unit/guard assertion that release-verifier process construction cannot form `cargo publish` without `--dry-run`, or keep the implementation structurally incapable by exposing no publish function at all.

Do not add confirmation prompts around actual publication; actual publication remains outside xtask.

## Documentation updates

Update:

```text
docs/testing/verification-contract.md
docs/releasing.md
docs/RELEASE.md
docs/RELEASE_CHECKLIST.md
AGENTS.md
```

Required corrections:

- full verification is deterministic local verification, not a deleted main/nightly lane
- stress/endurance and environment-specific tests have direct commands
- path dependencies require meaningful semver requirements
- release verifier fails dirty by default
- pre-publication package assembly is distinct from per-crate registry dry-run
- actual publication remains manual

## Validation

Run from a clean Linux checkout:

```bash
cargo xtask verify
cargo xtask verify-full
cargo xtask verify-release
```

Then inspect release incapability:

```bash
rg -n 'Command::new\("cargo"\)|args\(' tools/xtask/src/verify.rs
rg -n 'cargo publish' .github scripts tools --glob '!**/testdata/**'
```

Manual release commands in documentation are allowed. Executable publication paths are not.

## Failure injection

Demonstrate and revert:

1. A deterministic full-only test failure makes `verify-full` fail.
2. A stress test removed from full remains runnable through its documented direct command.
3. A publishable crate with no version requirement on an internal path dependency fails release verification.
4. A compatible semver path dependency passes; `version = "*"` fails unless explicitly allowlisted.
5. A packaged `src/secret_handling.rs` file does not false-positive.
6. A packaged `.env.production` or `id_rsa` file fails.
7. A missing declared README fails.
8. A dirty tree fails by default and proceeds only with `--allow-dirty`.
9. A newly versioned dependent package can complete pre-publication assembly before its predecessor is on crates.io.
10. No execution path invokes actual publication.

## Acceptance criteria

Phase 2 is complete only when:

- `verify-full` passes on the reviewed commit.
- `verify-full` has no intentional duplicate test-binary execution.
- Every previously failing/timing-out test has an explicit disposition.
- Real product regressions are not excluded or reclassified as infrastructure.
- Stress/endurance tests removed from full have direct documented commands.
- `verify-release` passes on a clean reviewed commit.
- Publishability is derived primarily from Cargo metadata and manifest `publish` settings.
- Publishable internal path dependencies require meaningful compatible semver requirements.
- Package inspection is path-aware and does not broadly reject legitimate source names.
- Dirty trees fail by default.
- Pre-publication verification does not require future internal versions to already exist on crates.io.
- Actual publication remains impossible through xtask, scripts, or workflows.
- All ten failure injections behave as specified.

## Stop conditions

Stop and document a separate blocker when:

- a full-suite failure is a confirmed production defect
- Cargo package assembly exposes an actual unpublishable dependency graph
- a publishable crate depends on an internal-only crate
- a test requires privileged or external infrastructure not available in the documented full-verification environment

Do not weaken the release contract or create CI automation to bypass these conditions.
