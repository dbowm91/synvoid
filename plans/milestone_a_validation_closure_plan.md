# Milestone A Validation and Closure Plan

## Purpose

This plan is a focused validation and closure pass for the YARA-X upload security work completed after the Milestone A plans. It is not intended to add new feature scope. The goal is to prove that the implementation commits satisfy the intended security invariants, close any test/CI/documentation gaps, and leave a clear handoff state before starting Milestone B.

Milestone A covered four implementation areas:

1. YARA scan failure semantics and upload safety closure.
2. Full-file and large-file scanning correctness.
3. Bounded YARA execution and atomic rule reloads.
4. YARA rule provenance, hardened directory loading, signed bundles, and dependency policy enforcement.

The repo now has implementation commits corresponding to these areas. This validation pass should treat the implementation as mostly complete but not yet proven until CI, edge-case tests, and end-to-end reload/pressure behavior have been verified.

## Scope

In scope:

- Verify that scan failure can no longer be represented as a clean upload under production defaults.
- Verify that every upload validation entry point uses the same scan policy behavior.
- Verify that large-file validation no longer scans only the first 8 KiB unless explicitly configured for `header_only`.
- Verify that full and windowed scan modes report accurate coverage metadata.
- Verify that scan admission is bounded and cannot create unbounded background scan tasks.
- Verify that rule reloads use last-known-good behavior and do not block on in-flight scans.
- Verify that local rule directory loading is deterministic and bounded.
- Verify that signed bundle verification rejects tampered or unsigned remote/mesh updates in production mode.
- Verify that dependency policy checks actually fail on the forbidden YARA-X/wasmtime/RSA-related regressions described in the security docs.
- Reconcile ignored tests and any local-only validation claims with CI.

Out of scope:

- Native malware heuristic improvements such as PE/ZIP polyglot fixes. Those belong to Milestone B.
- Real archive traversal and archive-bomb inspection. Those belong to Milestone B.
- Honeypot listener, protocol detector, storage, AI responder, and tarpit hardening. Those belong to Milestones B and C.
- Admin UI observability expansion beyond confirming current status hooks compile and are usable. Full observability belongs to Milestone D.

## Phase 1: Baseline CI and feature-matrix verification

### Tasks

1. Run formatting and linting:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

If full `--all-features` is too broad because of known optional dependency conflicts, document the failing feature combination and run the supported production feature set explicitly.

2. Run upload-focused tests:

```bash
cargo test -p synvoid-upload --all-targets
```

3. Run relevant config and integration tests:

```bash
cargo test -p synvoid-config --all-targets
cargo test -p synvoid-http --all-targets
```

4. Run root workspace tests for the default feature set:

```bash
cargo test --workspace
```

5. Run dependency policy checks:

```bash
cargo deny check
cargo audit
```

6. Ensure GitHub Actions or equivalent CI executes on `main` or on a validation branch. The previous inspection found no workflow status attached to the latest Milestone A commit, so local claims are not sufficient for closure.

### Success criteria

- Formatting passes.
- Clippy passes for the supported feature set.
- Upload crate tests pass.
- Workspace default tests pass or documented non-upload failures are triaged separately.
- Dependency policy checks pass or have narrowly scoped, documented, review-dated exceptions.
- A CI run exists for the validation commit or branch.

## Phase 2: Scan failure semantics regression tests

### Required invariants

- Scan success with no matches is `Clean`.
- Scan success with matches is `Malicious` and blocks upload.
- Scan disabled is `Disabled` and not mislabeled as clean-scanned.
- Scanner unavailable is `Unavailable` and follows the configured failure policy.
- Scanner timeout/error/panic is `Indeterminate` and follows the configured failure policy.
- `fail_open` is opt-in and must still record `Indeterminate`, `scan_error`, and a metric/log event.
- `quarantine_on_error` rejects the upload and quarantines when a sandbox/quarantine path exists.
- `fail_closed` rejects the upload without pretending a scan completed cleanly.

### Tasks

1. Review all validation paths and confirm they call the centralized scan helper or equivalent centralized policy handling:

- `validate_bytes`
- `validate_bytes_with_declared_type`
- `validate_with_sandbox`
- `validate_large_file`

2. Add or confirm tests for each failure policy across at least `validate_bytes` and `validate_large_file`.

3. Add a test double or injectable scanner failure path if current tests rely on fragile YARA-X behavior to simulate scan errors.

4. Confirm HTTP dispatch maps scan-indeterminate and scanner-unavailable errors to blocking responses, not generic success.

5. Confirm `ValidationResult::is_clean()` does not return true for `Indeterminate` or `Unavailable`.

### Success criteria

- No production-default path returns a clean/allowed result after a YARA scan error, timeout, panic, queue timeout, queue full, reload failure that invalidates scanning, or scanner-unavailable condition.
- Fail-open tests prove the result is explicitly indeterminate and observable.
- Tests cover all validation entry points or explicitly justify why an entry point shares an already-tested helper.

## Phase 3: Large-file scan coverage validation

### Required invariants

- `full` mode scans the entire file up to configured upload limits.
- `windowed` mode scans deterministic bounded windows and reports that it is partial coverage.
- `header_only` is explicitly opt-in and reports low/header-only coverage.
- MIME detection may remain header-based, but malware scanning coverage is independent from MIME sniffing.
- Coverage metadata accurately reports scanned bytes, total bytes, scan mode, coverage ratio, window count, and duration.

### Tasks

1. Add synthetic fixture tests with malicious payloads located:

- before byte 8192
- immediately after byte 8192
- in the middle of a larger file
- near EOF
- around a magic-marker offset

2. For `full` mode, assert that all payload positions are detected.

3. For `windowed` mode, assert deterministic window selection and accurate coverage metadata. Where a payload is outside the windows, the test should verify the result is partial coverage rather than clean full-file coverage.

4. For `header_only` mode, assert it is opt-in and that coverage metadata communicates header-only behavior.

5. Validate that `validate_large_file` applies the Phase 1 failure policy consistently in all scan modes.

6. Check memory behavior in `full` mode for large accepted files. If full scan currently reads the entire file into memory, document that explicitly and ensure the configured max upload size bounds the allocation.

### Success criteria

- The old header-only bug has a direct regression test: a payload after the first 8 KiB is detected in `full` mode.
- Coverage metadata cannot imply full coverage when the scan was windowed or header-only.
- Large-file scan errors are indeterminate/rejected under production defaults.
- Config docs accurately describe the operational cost of `full` mode on low-power targets.

## Phase 4: Bounded scan executor and reload stress validation

### Required invariants

- Scan work cannot be admitted without bounded concurrency control.
- Queue exhaustion produces explicit `QueueFull` or `QueueTimeout` errors.
- Queue/admission errors flow through the Phase 1 failure policy.
- Input cloning for large buffers occurs after admission where practical.
- A timed-out request cannot create unbounded background tasks.
- Rule reload compiles/prepares off-path and atomically swaps active generations.
- Failed reload preserves the last-known-good generation.
- In-flight scans can continue with the old generation while new scans use the new generation after swap.

### Tasks

1. Add a deterministic executor saturation test using a fake/blocking scan path or a test hook. The test should prove no more than `yara_max_concurrent_scans` are active at once.

2. Add a queue timeout test with `yara_max_concurrent_scans = 1`, a very short queue timeout, and a blocked active scan.

3. Add a queue-full test if the implementation tracks max queued scans independently from semaphore waiting. If max queued scans is documented but not materially enforced, either implement it or correct the docs/config semantics.

4. Add a reload-while-scanning test:

- Start scan using generation A.
- Reload generation B.
- Confirm in-flight scan finishes using A.
- Confirm later scan uses B.

5. Add failed reload tests:

- source compile failure
- compiled rule deserialization failure
- bad bundle/provenance failure

Each failure should preserve the previous generation and populate last reload error state.

6. Run a small stress test outside unit tests if needed:

```bash
cargo test -p synvoid-upload yara -- --nocapture
```

or a purpose-built ignored/stress test that can be run locally and documented.

### Success criteria

- Executor saturation cannot exceed configured concurrency.
- Queue timeout/full errors are test-covered and policy-covered.
- Reloads are lock-free from the perspective of scan-held global locks.
- Last-known-good rules survive bad reloads.
- Documentation matches actual queue behavior.

## Phase 5: Rule provenance, signed bundle, and mesh reload validation

### Required invariants

- Active rule generations expose provenance metadata.
- Local directory loading is deterministic.
- Local directory loading rejects symlinks by default.
- Local directory loading enforces max rule file count and aggregate source bytes.
- Strict directory mode fails when empty; directory-with-fallback mode uses bundled fallback when configured.
- Signed manifests verify content and signer identity.
- Tampered source/compiled content fails verification.
- Unsigned remote/mesh rule updates are rejected in production mode unless explicitly configured otherwise.
- Bad updates preserve last-known-good generation.

### Tasks

1. Review the two ignored tests noted in the Phase 4 commit message. Decide whether to:

- fix the test fixtures so they run normally,
- replace them with stable equivalent tests, or
- keep them ignored with a tracked reason and a follow-up issue/plan.

2. Add or confirm deterministic directory loading tests that create files in non-sorted order and assert stable merged content/provenance.

3. Add symlink rejection tests on Unix. If Windows behavior differs, gate the test with `cfg(unix)` and document it.

4. Add manifest verification tests:

- valid signature
- tampered source
- tampered compiled bytes
- wrong key
- missing signature in production mode
- allowed unsigned local development mode, if supported

5. Add an end-to-end mesh reload test or integration test path that exercises the actual mesh manager reload flow, not only the manifest helper.

6. Confirm operator status hooks are accessible and return useful data:

- rule source type
- version
- content hash
- verification state
- source count/bytes
- last reload error

### Success criteria

- No ignored test remains unexplained.
- Rule provenance tests cover local, bundled, inline, compiled, and mesh/source update cases as applicable.
- Mesh production reload rejects unsigned/tampered rules through the real reload path.
- Last-known-good behavior is proven through the same public/internal API used by production reloads.

## Phase 6: Dependency policy closure

### Required invariants

- `deny.toml` blocks known-disallowed vulnerable `wasmtime` versions.
- YARA-X feature changes that materially alter dependency exposure are visible in review.
- RSA advisory exposure remains documented and low-risk only while RSA-backed YARA rule signing is not used by SynVoid.
- Advisory ignores are narrow, justified, and review-dated.
- Yanked crates are denied unless a narrowly justified exception exists.

### Tasks

1. Run:

```bash
cargo deny check
cargo audit
```

2. Confirm `deny.toml` has no broad unreviewed ignores.

3. Add a short dependency policy note if the current wasmtime patch/lockfile relationship is non-obvious.

4. Verify the lockfile resolves `wasmtime` as intended under the current YARA-X dependency set.

5. Confirm CI executes dependency checks.

### Success criteria

- Dependency checks are automated or at least documented as a required release gate.
- The YARA-X/wasmtime/RSA posture in `SECURITY.md` matches actual lockfile/dependency policy behavior.
- No known-vulnerable dependency path is silently accepted without rationale.

## Phase 7: Documentation and operator sanity check

### Tasks

1. Review these docs for consistency with actual config names and defaults:

- `SECURITY.md`
- `architecture/upload.md`
- `docs/UPLOADS.md`
- `docs/CONFIGURATION.md`
- admin UI config docs if applicable
- example site config

2. Confirm the docs explain:

- `yara_failure_policy`
- `fail_closed`, `quarantine_on_error`, and `fail_open`
- large-file scan modes
- full vs windowed vs header-only coverage
- bounded executor knobs
- rule provenance and signed bundle behavior
- directory rule loading limits
- dependency policy expectations

3. Add an operator checklist for validating upload scanning in a deployment:

- confirm scanning enabled
- confirm active rule version/hash
- upload benign fixture
- upload malicious test fixture in a safe environment
- test scanner unavailable/timeout behavior
- confirm quarantine path behavior

### Success criteria

- Docs match code defaults.
- Risky modes are clearly marked.
- Operators can understand whether an upload was clean, malicious, disabled, unavailable, or indeterminate.
- Example config does not accidentally recommend `fail_open` or `header_only` for production.

## Final closure checklist

- [ ] CI run exists for the validation branch or latest `main` commit.
- [ ] `cargo fmt --all -- --check` passes.
- [ ] `cargo clippy` passes for the supported production feature set.
- [ ] `cargo test -p synvoid-upload --all-targets` passes.
- [ ] Workspace default tests pass or non-upload failures are separately triaged.
- [ ] Dependency policy checks pass.
- [ ] All scan-failure policies are tested.
- [ ] All upload validation entry points use consistent scan policy semantics.
- [ ] Large-file payload-after-8KiB regression test exists.
- [ ] Full/windowed/header-only coverage metadata tests exist.
- [ ] Executor concurrency/queue tests exist.
- [ ] Reload-while-scanning and failed-reload tests exist.
- [ ] Directory rule loading deterministic/symlink/limit tests exist.
- [ ] Signed bundle tamper/wrong-key/missing-signature tests exist.
- [ ] Mesh reload path is tested end-to-end or explicitly queued as a remaining gap.
- [ ] Ignored tests are eliminated or documented with follow-up.
- [ ] Docs/config examples match code behavior.

## Expected handoff result

At the end of this validation pass, Milestone A should be labeled either:

- `Closed`: all closure checklist items pass, with CI evidence; or
- `Closed with tracked exceptions`: all release-blocking items pass, with remaining non-blocking exceptions documented in a follow-up plan; or
- `Not closed`: one or more security invariants are not proven or fail under test.

Do not start Milestone B implementation until Milestone A is at least `Closed with tracked exceptions` and the exceptions do not affect upload security boundaries.
