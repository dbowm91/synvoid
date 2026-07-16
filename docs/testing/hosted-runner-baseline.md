# Hosted-Runner Performance Baseline

## Purpose

This document records observed performance characteristics from GitHub-hosted runners (Ubuntu latest) for SynVoid CI lanes. It serves as the reference for evaluating timing regressions and budget compliance.

## Baseline Date

2026-07-16 — Local validation baseline established on commit `3673e516`. Hosted-runner evidence collected from GitHub Actions runs on 2026-07-15 and 2026-07-16.

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

> Hosted-runner timing data collected from GitHub Actions workflow runs.

### PR Runs

| Run | Scenario | Total Duration | Longest Job | Skipped Jobs | Cache State | Run ID |
|-----|----------|---------------|-------------|--------------|-------------|--------|
| 1 | Documentation-only (proof branch) | ~10m | Clippy (7m38s) | 4 | Warm | 29436788977 |
| 2 | Leaf crate change | ~20m | Security Regression (19m48s) | 4 | Warm | 29539079154 |
| 3 | Full-validation PR | — | — | 0 | — | — |

### Main Runs

| Run | Scenario | Total Duration | Profile Matrix | DNS Tests | Cache State | Run ID |
|-----|----------|---------------|---------------|-----------|-------------|--------|
| 1 | Post-fix comprehensive | ~25m | 5/5 PASS | PASS | Warm | 29512444402 |
| 2 | Post-fix comprehensive | ~25m | 5/5 PASS | PASS | Warm | 29505534163 |

### Nightly/Release Runs

| Run | Scenario | Total Duration | Status | Run ID |
|-----|----------|---------------|--------|--------|
| 1 | Nightly qualification | ~20m | FAIL (pre-existing) | 29436966790 |
| 2 | Release qualification | ~15m | FAIL (pre-existing) | 29436968077 |

### PR Fast Lane Timing

| Phase | Documentation-Only | Leaf Crate Change |
|-------|-------------------|-------------------|
| Queue to first job | ~3s | ~5s |
| Fastest job (No Unsafe in DNS) | 6s | 5s |
| Slowest job (Clippy or Security Regression) | 7m38s | 19m48s |
| Total wall-clock | ~10m | ~20m |
| Jobs skipped (selector-gated) | 4 | 4 |

### Main Comprehensive Timing

| Job | Duration | Status |
|-----|----------|--------|
| Profile Matrix (each) | ~4m | 5/5 PASS |
| DNS Crate Tests | ~10m | PASS |
| Plugin Runtime Guardrails | ~10m | PASS |
| Security Audit | ~1m | PASS |
| Dependency Audit | ~1m | PASS |
| Build (x86_64-linux) | ~10m | PASS |
| Cross-compiled builds | ~10m | Pre-existing failures |

## Budget Interpretation

| Budget | Threshold | Documentation-Only | Leaf Crate | Classification |
|--------|-----------|-------------------|------------|----------------|
| PR fast total | <10m warning, >15m blocking | ~10m | ~20m | warning (Clippy/Security Regression dominate) |
| Selector execution | <30s warning, >60s blocking | 9-22s | 12s | PASS |
| Cargo invocations | <50 warning, >70 blocking | 8 | 8 | PASS |
| Guard binary count | <30 warning, >40 blocking | 63 tests | 63 tests | PASS |

### Job Duration Summary

| Job | Typical Duration | Variance | Notes |
|-----|-----------------|----------|-------|
| Select Affected Packages | 9-22s | Low | Depends on diff size |
| Rustfmt | 17-22s | Low | Consistent |
| No Unsafe in DNS | 4-6s | Low | Fastest job |
| Forbidden Import Patterns | 5-9s | Low | Fast |
| Core Profile | 4m13s-4m22s | Low | Consistent |
| Clippy | 6m24s-7m38s | Medium | Dominates PR fast lane |
| Architecture Guard Tests | 1m28s-10m | High | Varies with test count |
| Security Regression | 11m43s-19m48s | High | Dominates when slow |
| DNS Crate Tests | ~10m | Medium | Includes formatting check |
| Profile Matrix (each) | ~4m | Low | Consistent |

## Limitations

- Local measurements are on a development machine, not GitHub-hosted runners
- Hosted-runner timing includes queue time, tool installation, and cache restore overhead
- Cross-platform measurements require the main-comprehensive or nightly-qualification lanes
- sccache deferral means all compilation uses uncached compiler outputs beyond `Swatinem/rust-cache@v2`
