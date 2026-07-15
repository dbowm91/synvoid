# Hosted-Runner Performance Baseline

## Purpose

This document records observed performance characteristics from GitHub-hosted runners (Ubuntu latest) for SynVoid CI lanes. It serves as the reference for evaluating timing regressions and budget compliance.

## Baseline Date

2026-07-15 — Local validation baseline established on commit `3673e516`.

## Local Validation Baseline

The following measurements were taken locally on a development machine. Hosted-runner measurements will be added as GitHub Actions runs complete.

### PR Fast Lane

| Metric | Value |
|--------|-------|
| Steps | 6 (fmt, clippy, guards, security, compile, affected) |
| Formatting | PASS (clean) |
| Clippy | `cargo clippy --all-targets -- -D warnings` |
| Repo guards | 63 passed, 0.169s |
| Root test ownership | 2 passed, 0.00s |
| Selector tests (pytest) | 90 passed |
| xtask dry-run | All 6 steps pass |

### Comprehensive Lane

| Metric | Value |
|--------|-------|
| Steps | 12 |
| Profile checks | 5 (core, mesh, dns, full, default) |
| xtask dry-run | All 12 steps pass |

### Guards Lane

| Metric | Value |
|--------|-------|
| Steps | 16 |
| Repo-guards crate | 63 tests |
| Root guard tests | 15 individual tests |
| xtask dry-run | All 16 steps pass |

### Security Lane

| Metric | Value |
|--------|-------|
| Steps | 1 |
| Command | `cargo nextest run --test security_regression --cargo-profile ci --profile ci -- --test-threads=1` |

## CI Profile Definition

```toml
[profile.ci]
inherits = "dev"
opt-level = 1
debug = "line-tables-only"
incremental = false
```

## Cache Architecture

| Layer | Tool | Status |
|-------|------|--------|
| Cargo source caches | `Swatinem/rust-cache@v2` | Active |
| Tool binaries | `taiki-e/install-action` | Active |
| Compiler outputs (sccache) | sccache | **Deferred** — GitHub Actions cache backend unavailable |
| Cargo target metadata | `Swatinem/rust-cache@v2` | Active |

## sccache Deferral

sccache remains formally deferred. No workflow currently enables it. The `setup-rust-ci` composite action supports an optional `sccache: 'true'` input, but the GitHub Actions cache backend was unavailable in the runner context. Re-enable only when a supported backend (S3, Redis, or self-hosted) is verified to store and retrieve artifacts successfully.

## Hosted-Runner Measurements

> **Pending.** Hosted-runner timing data will be recorded here as GitHub Actions workflow runs complete on the `validation/testing-operational-proof` branch. Each entry will include run ID, runner OS, workflow duration, job durations, queue time, cache hit rate, and artifact availability.

### PR Runs

| Run | Scenario | Total Duration | Longest Job | Cache State | Run ID |
|-----|----------|---------------|-------------|-------------|--------|
| — | Documentation-only | — | — | — | — |
| — | Single-crate affected | — | — | — | — |
| — | Full-validation PR | — | — | — | — |

### Main Runs

| Run | Scenario | Total Duration | Longest Job | Cache State | Run ID |
|-----|----------|---------------|-------------|-------------|--------|
| — | Cold comprehensive | — | — | — | — |
| — | Warm comprehensive | — | — | — | — |
| — | Post-dependency-change | — | — | — | — |

### Nightly/Release Runs

| Run | Scenario | Total Duration | Longest Job | Cache State | Run ID |
|-----|----------|---------------|-------------|-------------|--------|
| — | Nightly qualification | — | — | — | — |
| — | Release qualification | — | — | — | — |

## Budget Interpretation

| Budget | Threshold | Local Status | Hosted Status |
|--------|-----------|-------------|---------------|
| PR fast total | <10 min warning, >15 min blocking | N/A (dry-run) | Pending |
| Selector execution | <30s warning, >60s blocking | <1s (local) | Pending |
| Cargo invocations | <50 warning, >70 blocking | 6 (fast lane) | Pending |
| Guard binary count | <30 warning, >40 blocking | 63 tests | Pending |

## Limitations

- Local measurements are on a development machine, not GitHub-hosted runners
- Hosted-runner timing includes queue time, tool installation, and cache restore overhead
- Cross-platform measurements require the main-comprehensive or nightly-qualification lanes
- sccache deferral means all compilation uses uncached compiler outputs beyond `Swatinem/rust-cache@v2`
