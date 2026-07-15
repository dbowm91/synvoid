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

> Hosted-runner timing data collected from GitHub Actions workflow runs.

### PR Runs

| Run | Scenario | Total Duration | Longest Job | Cache State | Run ID |
|-----|----------|---------------|-------------|-------------|--------|
| 1 | Documentation-only (proof branch) | ~10m | Clippy (7m38s) | Warm | 29436788977 |
| 2 | Single-crate affected | — | — | — | — |
| 3 | Full-validation PR | — | — | — | — |

### Main Runs

| Run | Scenario | Total Duration | Longest Job | Cache State | Run ID |
|-----|----------|---------------|-------------|-------------|--------|
| 1 | Cold comprehensive | In progress | — | Cold | 29436815104 |
| 2 | Warm comprehensive | — | — | — | — |
| 3 | Post-dependency-change | — | — | — | — |

### Nightly/Release Runs

| Run | Scenario | Total Duration | Longest Job | Cache State | Run ID |
|-----|----------|---------------|-------------|-------------|--------|
| 1 | Nightly qualification | In progress | — | — | 29436966790 |
| 2 | Release qualification | In progress | — | — | 29436968077 |

### PR Fast Lane Timing (Proof Branch — Documentation-Only)

| Phase | Duration |
|-------|----------|
| Queue to first job | ~3s |
| Fastest job (No Unsafe in DNS) | 6s |
| Slowest passing job (Clippy) | 7m38s |
| Total wall-clock (to last job) | ~10m |
| Jobs skipped (selector-gated) | 4 (tarpit, honeypot, upload, mesh) |

### Main Comprehensive Timing (In Progress)

| Phase | Duration |
|-------|----------|
| Security Audit (cargo-audit) | Completed |
| Dependency Audit (cargo-deny) | Completed |
| Profile Matrix (5 checks) | All completed — all PASS |
| Cross-compiled builds | musl/aarch64-linux FAIL (protoc) |
| Platform builds | FreeBSD/Windows FAIL (pre-existing) |
| macOS builds | In progress |

## Budget Interpretation

| Budget | Threshold | Local Status | Hosted Status |
|--------|-----------|-------------|---------------|
| PR fast total | <10 min warning, >15 min blocking | N/A (dry-run) | ~10m (warning — Clippy dominates) |
| Selector execution | <30s warning, >60s blocking | <1s (local) | 9s (PASS) |
| Cargo invocations | <50 warning, >70 blocking | 6 (fast lane) | 8 (fast lane with skipped jobs) |
| Guard binary count | <30 warning, >40 blocking | 63 tests | 63 tests |

## Limitations

- Local measurements are on a development machine, not GitHub-hosted runners
- Hosted-runner timing includes queue time, tool installation, and cache restore overhead
- Cross-platform measurements require the main-comprehensive or nightly-qualification lanes
- sccache deferral means all compilation uses uncached compiler outputs beyond `Swatinem/rust-cache@v2`
