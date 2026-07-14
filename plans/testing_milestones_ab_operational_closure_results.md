# Testing Infrastructure Milestones A/B Operational Closure Results

**Date:** 2026-07-14
**Commit range:** Pre-closure state → lifecycle guard fix + doc updates

## Summary

Operational closure pass for testing milestones A/B. The primary work was resolving the known lifecycle guard failure, verifying nextest inventory behavior, auditing the legacy workflow, running the validation matrix, and updating documentation.

## Workstream Results

### Workstream 3 — Known Lifecycle Guard Disposition

**Target:** `lifecycle_task_guard::plugin_runtime_owner_is_stored_for_runtime_lifetime`

**Root cause:** The test asserted `let mut plugin_owner =` but the actual code in `src/server/mod.rs:411` uses `let plugin_owner = {` (immutable binding). The `mut` is unnecessary because the inner block uses its own `let mut owner` for mutable operations. The invariant is maintained: `plugin_owner` is created as a local variable and dropped after `shutdown_and_join`.

**Disposition:** Fixed the guard to match actual code semantics. The assertion now checks for `let plugin_owner =` instead of `let mut plugin_owner =`.

**Result:** 48/48 lifecycle_task_guard tests pass deterministically.

### Workstream 6 — Nextest Inventory Behavior

**Findings:**
- `cargo nextest list -p synvoid-repo-guards` works correctly — returns 26 tests
- `cargo nextest run -p synvoid-repo-guards` works correctly — 26 tests pass
- `cargo test -p synvoid-repo-guards -- --list` produces no output (known integration-test listing quirk)
- `cargo test -p synvoid-repo-guards` works correctly — 26 tests pass

**Classification:** The empty output from `cargo test -- --list` is a known quirk with integration tests. `cargo nextest list` is the reliable machine-readable inventory path.

**Documentation updated:** `docs/testing/milestone-b-results.md` Known Issues section corrected.

### Workstream 5 — Legacy Workflow Non-Authority Audit

**Findings:**
- `.github/workflows/ci.yml` has only `workflow_dispatch` trigger — no push or PR events launch it
- The workflow contains a single `redirect-notice` job that prints a notice about the split
- No branch protection checks reference legacy job names (verified via ci-lane-policy.md)
- No required status checks point to legacy jobs

**Disposition:** Retained as manual diagnostic workflow. Already correctly configured.

### Validation Matrix

| Command | Result |
|---------|--------|
| `cargo fmt --all -- --check` | PASS (after auto-fix) |
| `cargo check --workspace --profile ci` | PASS (2m 20s, 179 crates) |
| `cargo nextest run -p synvoid-repo-guards --profile ci` | PASS (26/26) |
| `cargo test --profile ci --test lifecycle_task_guard` | PASS (48/48) |
| `cargo test --profile ci --test security_regression -- --test-threads=1` | PASS (15/15) |
| `cargo test --workspace --doc --profile ci` | PASS (3 passed, 5 ignored) |
| `cargo clippy -p synvoid-repo-guards --all-targets -- -D warnings` | PASS (clean) |
| All standalone guard tests (13 files) | PASS (290/290) |

### Formatting

`cargo fmt --all` applied minor formatting fixes to:
- `tools/synvoid-repo-guards/tests/negative_fixtures.rs` (line length, brace style)

## Documentation Updates

| File | Changes |
|------|---------|
| `tests/lifecycle_task_guard.rs` | Fixed assertion to match actual code (`let plugin_owner =` not `let mut plugin_owner =`) |
| `docs/testing/milestone-b-results.md` | Updated lifecycle guard: 48/48 pass, removed known failure note, corrected test counts |
| `docs/testing/ci-performance-baseline.md` | Removed lifecycle guard from known failures table |
| `docs/testing/architecture-guard-ownership.md` | Updated lifecycle_task_guard test count to ~48 |

## Remaining Items (Deferred to Milestone C)

1. **Branch protection migration** — Requires repository admin to update required status checks from legacy `ci.yml` job names to `pr-fast.yml` job names. See `docs/testing/ci-lane-policy.md` for exact check names.
2. **Hosted-runner workflow activation** — Requires triggering workflows on GitHub-hosted runners and recording timing data.
3. **Cold/warm performance baseline** — Requires GitHub-hosted runner measurements.
4. **Root crate test failures** — 59 failures in root crate tests (wave10_test, integration_test, etc.) are pre-existing and not part of the CI PR fast lane. These are in the root crate which requires specific feature configurations.

## Go/No-Go Recommendation

**Go** — All CI-relevant tests pass. The lifecycle guard is fixed. The nextest inventory is working. The legacy workflow is correctly configured as manual-only. Documentation is updated. The repository is ready for Milestone C.

## Exit Criteria Checklist

- [x] Lifecycle guard passing deterministically
- [x] Nextest inventory working correctly
- [x] Legacy workflow confirmed manual-only
- [x] Validation matrix passing
- [x] Documentation updated
- [ ] Branch protection migration (requires admin)
- [ ] Hosted-runner workflow activation (requires CI)
- [ ] Cold/warm baseline (requires CI)
