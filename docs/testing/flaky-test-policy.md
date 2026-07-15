# Flaky Test Policy

## Definition

A test is **flaky** if it passes and fails non-deterministically without any code changes between runs. Flaky tests undermine CI trust, waste developer time investigating phantom failures, and can mask real regressions.

**Non-examples** (not flaky):
- Tests that fail consistently due to a code change
- Tests that require `--test-threads=1` due to global state (these are deterministic but resource-constrained)
- Tests that depend on external services (these are environment-dependent, not flaky — use skip guards instead)

## Evidence Required

A test must meet **all three** criteria before quarantine:

1. **Intermittent failure across 3+ CI runs** — The test must have failed at least 3 times in separate CI runs while passing in others, with no code changes between those runs.
2. **Reproduction steps** — Document the exact command, environment, and any conditions observed (e.g., "fails only under load," "fails after 10+ consecutive runs").
3. **Timing correlation** — Note whether failures correlate with specific conditions: parallel execution, CI runner load, filesystem state, or time-of-day patterns.

Without all three, the test should be investigated as a deterministic bug, not quarantined as flaky.

## Quarantine Process

When a test is confirmed flaky, the following steps must be completed in order:

### 1. Mark the test as ignored

Add `#[ignore]` with a reason containing `FLAKY` and the assigned owner:

```rust
#[test]
#[ignore = "FLAKY: non-deterministic failure under parallel load (owner: @username)"]
fn test_that_intermittently_fails() {
    // ...
}
```

### 2. Add to the tracking table

Add a row to the [Known Flaky Tests](#known-flaky-tests) table below with the quarantine date, reason, owner, and expiration date.

### 3. Run in nonblocking lane only

Quarantined tests run **only** in the scheduled qualification lane (nightly). They must **not** block the PR fast lane or main comprehensive lane. In CI configuration, quarantine tests are excluded from required status checks.

### 4. Maximum quarantine duration

Quarantined tests have a **30-day maximum** quarantine window. After 30 days, the test must either be restored or deleted. Extensions require explicit approval and a new expiration date.

## Retry Policy

### Default: No retries

Tests do not receive automatic retries. If a test fails, it fails — and the failure is investigated.

### When retries are permitted

Retries are allowed **only** when all of the following are true:

1. The source of nondeterminism is **external** (network latency, filesystem timing, DNS resolution, clock skew) and cannot be fixed by test isolation.
2. The retry is **explicitly opted-in** per test via a documented annotation or CI configuration.
3. The retry count is **bounded** (maximum 2 retries per run).

### Prohibition on broad retries

Blanket retry policies (e.g., `cargo test --retry` across all tests) are **forbidden**. Broad retries mask deterministic races, timing bugs, and resource leaks. A test that fails due to a race condition must be fixed, not retried.

### Opt-in annotation

```rust
#[test]
#[flaky(max_retries = 2)]  // Only for documented external nondeterminism
fn test_that_depends_on_network_timing() {
    // ...
}
```

## Owner Assignment

Every quarantined flaky test **must** have an assigned owner. The owner is responsible for:

- Investigating the root cause within 7 days of quarantine
- Restoring the test to passing status or escalating for deletion
- Providing status updates in weekly CI triage
- Sign-off required before restoration (see [Restoration Criteria](#restoration-criteria))

If no owner is assigned, the quarantine request is rejected.

## Security-Critical Tests

Security-critical tests (security regression, auth boundary, threat-intel enforcement, plugin capability boundary) follow an **accelerated remediation** schedule:

- **7-day maximum** quarantine duration (not 30 days)
- Root cause investigation must begin **within 24 hours** of quarantine
- Owner must provide a remediation plan within **48 hours**
- If the test cannot be restored within 7 days, the underlying functionality must be reviewed by a second engineer

Security-critical test quarantine requires approval from a repository maintainer.

## Restoration Criteria

A quarantined test may be restored to active CI when **all** of the following are met:

1. **10 consecutive passes** on CI in the scheduled qualification lane (nightly runs)
2. **Owner sign-off** confirming the root cause is understood and addressed
3. **No recurrence** in the 7 days following the 10 consecutive passes

The restoration commit must:
- Remove the `#[ignore]` annotation
- Update the tracking table status to `Restored` with the date
- Include a brief note in the commit message explaining the fix

## Reporting

Flaky tests generate a report visible in CI summaries:

- The nightly qualification lane produces a **flaky test report** listing all quarantined tests, their status, and days since quarantine.
- CI summary jobs reference the count of active quarantined tests.
- Weekly CI triage reviews the flaky test table and escalates stale entries.

## Known Flaky Tests

| Test | Owner | Date Quarantined | Reason | Expiration | Status |
|------|-------|------------------|--------|------------|--------|
| `platform::sandbox::tests::test_basic_sandbox_succeeds_with_stub` | Unassigned | Pre-existing | Assertion failure at `src/platform/sandbox.rs:1247`; sandbox stub returns unexpected result | Pending assignment | Active |

## Tracking Table Template

Use this template when quarantining a new flaky test:

```markdown
| Test | Owner | Date Quarantined | Reason | Expiration | Status |
|------|-------|------------------|--------|------------|--------|
| `full::test::path` | @username | YYYY-MM-DD | Brief description of nondeterministic behavior | YYYY-MM-DD | Active / Restored / Deleted |
```

## Related Documents

- [CI Lane Policy](./ci-lane-policy.md) — Lane definitions and permitted workload
- [CI Performance Baseline](./ci-performance-baseline.md) — Timing baselines and known failures
- [Test Suite Ownership](./test-suite-ownership.md) — Test ownership manifest
