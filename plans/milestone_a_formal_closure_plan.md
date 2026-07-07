# Milestone A Formal Closure Plan

## Purpose

This plan closes the remaining validation gaps for Milestone A of the YARA-X upload security hardening line. The prior implementation and regression-test pass materially improved the repository, but the milestone should not be called formally closed until the remaining proof gaps are resolved.

This plan is intentionally narrow. It should not introduce new honeypot, tarpit, native malware heuristic, archive traversal, or observability scope. It exists to prove that the YARA upload security boundary is correct and release-gatable.

## Current status

Implemented and partially validated:

- YARA scan failure semantics are explicit through `UploadScanStatus`, `UploadScanFailurePolicy`, scan error state, and validation errors.
- Large-file scan behavior now has `Full`, `Windowed`, and `HeaderOnly` modes with coverage metadata.
- YARA scanning uses bounded admission and atomic rule generations.
- Rule provenance, directory hardening, signed manifest support, and dependency policy documentation are present.
- A regression-test pass added 31 tests and raised upload tests from 83 to 114 passing tests.

Remaining formal-closure gaps:

1. Some scan-failure tests construct equivalent `ValidationResult` states rather than exercising the actual validator execution path.
2. Two pre-existing ignored YARA-X compatibility tests remain unresolved.
3. No GitHub CI/status evidence has been observed on the latest validation commits.
4. Mesh rule reload verification needs an end-to-end path test through the real mesh manager/reload flow.
5. `yara_max_queued_scans` must either be materially enforced or documentation/config must be corrected to match actual semaphore-only behavior.

## Closure criteria

Milestone A is formally closed only when all of the following are true:

- Real validator entry points are tested for scan unavailable, scan error, timeout, queue timeout/full, and fail-open behavior.
- Ignored tests are either eliminated or documented with a non-release-blocking rationale and tracked follow-up.
- CI runs on the latest commit and enforces format, lint, upload tests, dependency policy, and at least the default workspace test set.
- Mesh rule reload has an end-to-end test or a documented, explicitly accepted exception if the mesh test harness is not yet available.
- Queue configuration semantics are accurate and tested.
- Documentation matches the final implementation.

## Workstream 1: Real validator-path failure tests

### Problem

The latest regression pass added useful invariant tests, but some unavailable-scanner and failure-policy tests construct `ValidationResult` directly instead of exercising `UploadValidator` through `validate_bytes`, `validate_bytes_with_declared_type`, `validate_with_sandbox`, and `validate_large_file`.

Constructed-state tests prove that `is_clean()` and status semantics are sane. They do not prove that the real validator paths produce the right state or error under scanner failure.

### Implementation tasks

1. Add a test-only scanner abstraction or injectable failure hook.

Preferred option:

- Introduce a small internal trait, for example `UploadMalwareScanner`, implemented by the existing `MalwareScanner`.
- Store the scanner behind `Arc<dyn UploadMalwareScanner + Send + Sync>` where practical, or use a narrower test-only constructor if avoiding production abstraction churn is preferred.
- Provide test scanner implementations:
  - `AlwaysCleanScanner`
  - `AlwaysMaliciousScanner`
  - `AlwaysErrorScanner`
  - `AlwaysTimeoutScanner`
  - `BlockingScanner` for executor/admission tests

Lower-churn option:

- Add `#[cfg(test)]` constructors on `UploadValidator` that allow setting `malware_scanner` to `None` or a failure-producing scanner wrapper.
- Keep production constructors unchanged.

2. Add direct `validate_bytes` tests for:

- `FailClosed` + scanner unavailable -> `Err(ScanIndeterminate)` or `Err(ScannerUnavailable)` according to final error taxonomy.
- `QuarantineOnError` + scanner unavailable -> blocking error; quarantine only where a quarantine handle/path exists.
- `FailOpen` + scanner unavailable -> `Ok(ValidationResult)` with `scan_status = Unavailable` or `Indeterminate`, `scan_error = Some`, and `is_clean() == false`.
- scanner error -> policy-specific behavior.
- scanner timeout -> policy-specific behavior.
- scanner malicious result -> `Err(MalwareDetected)`.
- scanner clean result -> `Ok` with `scan_status = Clean`.

3. Add `validate_bytes_with_declared_type` tests for:

- scanner error with `FailClosed`
- scanner error with `FailOpen`
- MIME mismatch still takes precedence where configured, or document the intended precedence explicitly

4. Add `validate_with_sandbox` tests for:

- scanner error with `QuarantineOnError` quarantines or records quarantine action when sandbox/quarantine infrastructure is available
- malicious result quarantines as before
- fail-open does not return clean status

5. Add `validate_large_file` tests for:

- full scan + scanner error -> policy-specific behavior
- windowed scan + scanner error -> policy-specific behavior
- header-only scan + scanner error -> policy-specific behavior
- fail-open large-file path returns `Ok` but remains explicitly non-clean/indeterminate

### Success criteria

- Constructed `ValidationResult` tests remain as low-level invariant tests, but the release-blocking behavior is tested through real validator entry points.
- No scan-enabled production-default path can return a clean result when scanner execution fails.
- Fail-open behavior is explicitly observable and never reports `is_clean() == true` after scanner failure.

## Workstream 2: Ignored YARA-X compatibility test disposition

### Problem

The latest validation commit states that two pre-existing ignored tests remain unchanged. Ignored tests are acceptable only if they are intentionally non-release-blocking and documented. For a security boundary, ignored tests should not remain ambiguous.

### Implementation tasks

1. Locate the two ignored tests.

Use:

```bash
rg '#\[ignore\]|ignore' crates/synvoid-upload src crates -n
```

2. Classify each ignored test:

- stale test fixture
- YARA-X bundled rule compatibility issue
- environment-sensitive test
- long-running/stress-only test
- true product gap

3. Prefer to unignore by making fixtures deterministic and compatible with the current YARA-X version.

4. If unignoring is not practical, add a comment above each ignored test with:

- exact reason it is ignored
- whether it is release-blocking
- how to run it manually
- expected behavior
- follow-up plan file or issue reference if it tracks a real gap

5. Add a `docs` or plan note if the ignored tests represent a known limitation rather than test instability.

### Success criteria

- Zero ambiguous ignored tests remain.
- Any remaining ignored test is explicitly non-release-blocking, documented, and manually runnable.
- If either ignored test is release-relevant, it is fixed or Milestone A remains not closed.

## Workstream 3: CI and release-gate enforcement

### Problem

No GitHub workflow/status evidence was observed on the latest validation commits. Local claims of test success are useful, but formal closure requires repeatable CI.

### Implementation tasks

1. Inspect existing workflows:

```bash
ls -la .github/workflows
```

2. If no workflow exists, add a minimal CI workflow for pull requests and pushes to `main`.

Required jobs:

- `cargo fmt --all -- --check`
- `cargo clippy -p synvoid-upload --all-targets -- -D warnings`
- `cargo test -p synvoid-upload --all-targets`
- `cargo test --workspace` for default feature set, unless known unrelated failures are documented
- dependency policy job using `cargo deny check`

Optional but preferred:

- `cargo audit`
- `cargo test -p synvoid-config --all-targets`
- `cargo test -p synvoid-http --all-targets`
- feature-specific upload tests with `mesh` enabled if feasible

3. If workspace tests are not currently clean due unrelated crates, do not hide that. Split jobs:

- `upload-required`: must pass
- `workspace-default`: must pass or be documented as currently failing with specific unrelated issue
- `dependency-policy`: must pass

4. Add CI documentation in `docs/UPLOADS.md` or a release checklist if needed.

5. Ensure the final closure commit has visible CI status.

### Success criteria

- The latest formal-closure commit has GitHub CI evidence.
- Upload-specific gates pass.
- Dependency policy gates pass.
- Any non-upload workspace failures are explicitly documented and not silently ignored.

## Workstream 4: Mesh rule reload end-to-end validation

### Problem

Rule manifests, provenance helpers, and reload primitives are tested, but formal closure needs proof that the actual mesh rule reload path preserves the same security properties.

### Implementation tasks

1. Identify the production mesh reload flow used by upload validation.

Likely surfaces include:

- upload validator reload hook
- mesh YARA rule manager
- compiled-rule reload path
- source-rule reload path
- rule version comparison
- last-known-good preservation

2. Add an end-to-end test for valid mesh reload:

- Start validator/scanner with generation A.
- Provide a mesh rule manager/update with signed valid generation B.
- Trigger reload through the same path production uses.
- Assert active provenance/version/hash changes to B.
- Assert subsequent scans use B.

3. Add end-to-end tests for invalid mesh reload:

- unsigned update in production mode
- tampered source hash
- bad signature
- compiled rule deserialization failure
- source rule compilation failure

Each should:

- return/log a reload failure
- populate `last_reload_error`
- keep generation A active
- avoid accepting an unverified/tampered generation

4. If the mesh harness is too expensive for the upload crate unit tests, add a focused integration test behind a feature gate:

```bash
cargo test -p synvoid-upload --features mesh mesh_yara_reload
```

or a workspace integration test that uses the real mesh types.

5. If true mesh E2E is not currently possible, create a separate follow-up plan and mark Milestone A as `Closed with tracked exception`, not fully closed.

### Success criteria

- Signed valid mesh reload succeeds through the production path.
- Unsigned/tampered mesh reload fails through the production path.
- Last-known-good behavior is proven through production reload APIs, not only helper-level tests.

## Workstream 5: Queue-limit semantics and executor pressure tests

### Problem

The implementation documents `yara_max_concurrent_scans`, `yara_max_queued_scans`, and `yara_queue_timeout_ms`. Concurrency and timeout are meaningful only if the implementation enforces them as documented. If `yara_max_queued_scans` is only a config field and not a distinct queue bound, docs/config must be corrected or enforcement added.

### Implementation tasks

1. Inspect executor implementation and determine whether `yara_max_queued_scans` is actually enforced.

Possible outcomes:

- It is enforced by a bounded queue or equivalent admission counter.
- It is not enforced separately; only semaphore wait timeout exists.
- It is partially enforced but not race-safe.

2. If not enforced, choose one of two closure paths.

Preferred path: implement real queue bound.

- Track waiting scan requests with a semaphore/counter separate from active scan permits.
- Enforce `max_queued_scans` before waiting on the active scan permit.
- Return `YaraError::QueueFull` immediately when queue slots are exhausted.
- Release queue slot once active permit is acquired or request exits.
- Add tests for queue-full and queue-timeout separately.

Acceptable low-churn path: correct semantics.

- Rename/remove `yara_max_queued_scans` if it is not used.
- Update docs to say only active concurrency and wait timeout are enforced.
- Remove or deprecate queue-full claims if not implemented.
- Keep `QueueTimeout` but do not claim `QueueFull` unless it can happen.

3. Add pressure tests:

- active concurrency never exceeds configured limit
- queued waiters never exceed configured queue limit, if implemented
- queue timeout produces policy-handled scan indeterminate behavior
- timed-out request does not report clean
- scanner recovers after saturation

4. Keep test runtime short and deterministic. Use blocking test scanner hooks rather than slow real YARA rules.

### Success criteria

- Executor behavior matches config names and documentation.
- `QueueFull` is either reachable and tested or removed/deprecated from documentation.
- Queue pressure cannot produce clean upload results under production defaults.

## Workstream 6: Final documentation reconciliation

### Tasks

1. Re-read and update:

- `SECURITY.md`
- `architecture/upload.md`
- `docs/UPLOADS.md`
- `docs/CONFIGURATION.md`
- admin config docs
- example site config
- Milestone A plan files if they now contain stale assumptions

2. Ensure docs accurately state:

- production default failure policy
- fail-open warning
- large-file scan mode defaults
- whether full mode reads entire file into memory
- windowed mode coverage limitations
- exact executor queue semantics
- rule provenance fields
- mesh signing behavior
- ignored/stress test status, if any remains
- CI/release gate expectations

3. Add a final Milestone A closure note, either in a plan file or docs, recording:

- final closure status
- CI evidence expectations
- known exceptions, if any
- remaining non-Milestone-A work deferred to Milestone B/C/D

### Success criteria

- No docs claim a behavior that is not implemented.
- Risky options remain clearly marked as risky.
- Milestone A handoff state is clear to the next implementer.

## Suggested implementation order

1. Inspect and resolve `yara_max_queued_scans` semantics first. This may affect executor tests and docs.
2. Add scanner injection/test hooks for real validator-path tests.
3. Add real validator-path failure tests across all entry points.
4. Resolve ignored tests.
5. Add mesh reload E2E tests.
6. Add or update CI workflow.
7. Reconcile docs and write final closure status.

## Commands to run before final closure

Minimum required:

```bash
cargo fmt --all -- --check
cargo clippy -p synvoid-upload --all-targets -- -D warnings
cargo test -p synvoid-upload --all-targets
cargo deny check
```

Preferred:

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
```

Feature-specific, if available:

```bash
cargo test -p synvoid-upload --features mesh --all-targets
cargo test -p synvoid-http --all-targets
cargo test -p synvoid-config --all-targets
```

## Final acceptance checklist

- [ ] Real validator-path failure tests exist for `validate_bytes`.
- [ ] Real validator-path failure tests exist for `validate_bytes_with_declared_type`.
- [ ] Real validator-path failure tests exist for `validate_with_sandbox`.
- [ ] Real validator-path failure tests exist for `validate_large_file`.
- [ ] Fail-open returns allowed-but-indeterminate, never clean.
- [ ] Scanner unavailable/error/timeout/queue pressure cannot pass as clean under production defaults.
- [ ] Ignored tests are removed or explicitly documented as non-release-blocking.
- [ ] Mesh valid reload succeeds through production path.
- [ ] Mesh unsigned/tampered reload fails through production path.
- [ ] Last-known-good generation survives bad mesh reload.
- [ ] Queue-full semantics are implemented and tested, or docs/config are corrected.
- [ ] CI workflow exists and runs on `main`/pull requests.
- [ ] Upload tests and dependency policy checks are CI-gated.
- [ ] Docs match the final implementation.
- [ ] Milestone A is marked `Closed` or `Closed with tracked exceptions` with explicit rationale.

## Handoff guidance

Do not expand this closure pass into Milestone B work. If native malware heuristics, archive traversal, honeypot, tarpit, threat-intel scoring, or AI responder issues are encountered during this pass, document them under the existing roadmap and continue closing the Milestone A proof gaps first.
