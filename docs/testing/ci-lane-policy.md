# CI Lane Policy

## Overview

SynVoid CI is organized into four validation lanes, each with a specific purpose, trigger, and permitted workload.

## Pull-Request Fast Lane

**Trigger:** Pull requests to main/master
**Purpose:** Fast developer feedback (<10 min target)
**Required for merge:** Yes

### Permitted workload:
- `cargo fmt --all -- --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo check --no-default-features` (core profile)
- `python scripts/check_imports.py` (forbidden imports)
- `cargo test --test security_regression -- --test-threads=1`
- Architecture guard tests (24 structural guards)
- Plugin runtime guardrails (6 plugin guards + unit tests + clippy)
- Per-crate tests: synvoid-dns, synvoid-plugin-runtime, synvoid-upload, synvoid-honeypot, synvoid-tarpit, synvoid-mesh (all with `--profile ci`)
- `cargo test --test docs_path_reference_guard` (continue-on-error)
- DNS unsafe check (grep only)

### Not permitted:
- FreeBSD VM testing
- Alpine/musl full test
- Miri
- Fuzz smoke matrix
- Outdated dependency scan
- Full platform compatibility matrix
- Profile matrix (5 cargo check variants)
- Full release artifact builds
- Long stress/endurance tests

### Concurrency:
Superseded PR runs are automatically cancelled.

## Main Comprehensive Lane

**Trigger:** Push to main/master/develop
**Purpose:** Full validation after merge
**Required for merge:** No (runs post-merge)

### Permitted workload:
- Full build matrix (8 targets, release profile)
- DNS full test suite (blanket `cargo test -p synvoid-dns --profile ci` + all-features check)
- Plugin runtime full suite (unit tests + guard tests + clippy)
- Profile matrix (5 cargo check variants)
- Documentation build (`cargo doc --no-deps --release`)
- Security audit (`cargo audit`)
- Dependency audit (`cargo deny check`)

### Not permitted:
- Alpine/musl (moved to scheduled)
- FreeBSD VM (moved to scheduled)
- Miri (moved to scheduled)
- Fuzz smoke (moved to scheduled)
- Platform compatibility (moved to scheduled)
- Outdated dependencies (moved to scheduled)

## Scheduled Qualification Lane

**Trigger:** Nightly schedule (4 AM UTC) or manual dispatch
**Purpose:** Expensive qualification that doesn't block PR iteration

### Permitted workload:
- Alpine Linux (musl) build + test
- FreeBSD VM build + test
- Platform compatibility cross-target check
- Miri safety checks (continue-on-error)
- Fuzz smoke tests (16 targets × 1000 runs)
- Outdated dependency reporting (continue-on-error)

### Notes:
- These jobs are expensive and slow
- They catch portability and safety issues that Linux-only PR checks miss
- Results are reviewed in morning triage

## Release Qualification Lane

**Trigger:** Version tags (v*) or manual dispatch
**Purpose:** Production artifact validation

### Permitted workload:
- Full release profile builds for all targets
- Full test suite in release mode
- Packaging and artifact smoke tests
- Release-specific security validation
- Performance baseline comparison

## Branch Protection

### Required status checks (PR fast lane):
- `fmt`
- `clippy`
- `security-regression`
- `guard-suite` (or equivalent)
- At least one per-crate test job

### Not required (but tracked):
- All scheduled qualification jobs
- Release qualification jobs
- Summary jobs

## Migration Notes

### From the legacy ci.yml:
- All 25 jobs have been reassigned to exactly one lane
- 6 plugin guard tests were deduplicated (owned by plugin-runtime-guardrails)
- 26 DNS integration test reruns were removed (blanket run covers all)
- Qualification-only jobs now have conditions to skip on PRs
- `--release` replaced with `--profile ci` for routine correctness tests
- Concurrency cancellation added for PR iteration
