# CI Performance Baseline

## Environment
- Runner: Local development machine (not GitHub-hosted)
- OS: Linux (x86_64)
- Rust: stable
- Date: 2026-07-13

## Baseline Measurements

### Cold Cache / First Build

| Suite | Profile | Wall Time | Notes |
|-------|---------|-----------|-------|
| Root lib tests (898 tests) | release | 5.75s | 1 known failure: platform::sandbox::tests::test_basic_sandbox_succeeds_with_stub |
| DNS crate (1101 tests, 31 binaries) | release | 2m27s | All pass |
| Plugin runtime (389 tests) | release | 3m18s | All pass |
| Security regression (15 tests) | release | 1m22s | All pass |
| Guard suite subset (5 tests) | release | ~1.1s exec | ~10s compile on first run |
| Clippy (default features) | dev | 2.7s | Clean |
| Clippy (--all-features) | dev | 1m40s | FAILS: 24 eBPF compilation errors |
| Root full suite (--no-fail-fast) | release | >60min TIMEOUT | ~621 integration test binaries, compilation-dominated |

### Key Findings
- **Compilation is the dominant cost** — test execution is fast (5s for 898 lib tests)
- **Root crate produces ~621 integration test binaries** — linking is the bottleneck
- **CI profile does not exist yet** — all measurements used release mode
- **--all-features is broken** — 24 eBPF compilation errors in synvoid-icmp-filter
- **1 known test failure** — platform sandbox stub test

### CI Profile (Added in Milestone A)
```toml
[profile.ci]
inherits = "dev"
opt-level = 1
debug = "line-tables-only"
incremental = false
panic = "unwind"
```

Expected improvement: opt-level=1 with no LTO and no codegen-units=1 should significantly reduce compile/link time while keeping test runtime reasonable.

## Current CI Topology

### Total Cargo Invocations: 135
### Qualification-Only Jobs Blocking PRs: 5 (alpine, freebsd, fuzz, platform-compat, profile-matrix)
### Duplicate Invocations: 32 (26 DNS + 6 plugin guard)

### Waste Summary
| Source | Redundant Invocations |
|--------|----------------------|
| DNS individually listed tests (blanket already covers) | 26 |
| Plugin guard tests (duplicated in guard-suite + plugin-runtime-guardrails) | 6 |
| Total recoverable | 32 (24% of all cargo invocations) |

## Milestone A Results

(To be filled after implementation)

### Before/After Comparison

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| PR fast lane jobs | 25 (all) | TBD | - |
| PR Cargo invocations | 135 | TBD | - |
| DNS Cargo invocations | 29 | 1 (blanket only) | -28 |
| Plugin guard duplicates | 6 | 0 | -6 |
| Profile for routine tests | --release | --profile ci | - |
| Qualification jobs on PR path | 5 | 0 | -5 |
