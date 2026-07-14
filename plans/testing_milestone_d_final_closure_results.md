# Testing Infrastructure Milestone D — Final Closure Results

## Executive Summary

This final closure pass corrects the non-Linux DNS fallback test construction, formally defers sccache (removing stale configuration), adds cross-platform test compilation coverage, fixes a pre-existing clippy warning, and reconciles all Milestone D documentation with current reality.

## Completion Status

| Workstream | Status | Notes |
|-----------|--------|-------|
| D-C1: Non-Linux DNS fallback test fix | Complete | `TcpStream::bind` replaced with `loopback_tcp_stream()` helper |
| D-C2: Cross-platform regression guard | Complete | `platform-compat` job now uses `--tests` to verify test code compiles |
| D-C3: sccache reconciliation | Complete | Stale `SCCACHE_GHA_ENABLED` removed; `cache-policy.md` updated |
| D-C4: Hosted-runner selector validation | Deferred | Requires CI observation after merge |
| D-C5: Branch-protection authority audit | Deferred | Requires repository admin access |
| D-C6: Final validation matrix | Complete | All local checks pass |
| D-C7: Closure documentation | Complete | This file |

## Changes Made

### D-C1: DNS Fallback Test Fix (`crates/synvoid-dns/src/platform.rs`)

**Problem:** `std::net::TcpStream::bind("127.0.0.1:0")` is not a valid constructor — `TcpStream` has no `bind` method. `TcpStream::connect("127.0.0.1:0")` would attempt an outbound connection to port 0, which fails.

**Fix:** Added `loopback_tcp_stream()` helper using `TcpListener::bind` + `accept` to create a valid loopback TCP pair. Two tests updated: `test_fallback_enable_tcp_pktinfo_returns_error` and `test_fallback_error_message_mentions_tcp`.

**Validation:** 23 platform tests pass on Linux (fallback tests are `cfg(not(linux))` and will be exercised by nightly platform-compat CI on macOS/Windows/FreeBSD).

### D-C2: Cross-Platform Regression Guard (`.github/workflows/nightly-qualification.yml`)

**Change:** Added `--tests` to the `platform-compat` job's `cargo check` loop. This ensures platform-only test code (like the `fallback_tests` module) is compiled on all 5 target triples, catching invalid constructors before merge.

**Targets covered:** `x86_64-unknown-linux-gnu`, `x86_64-unknown-linux-musl`, `x86_64-apple-darwin`, `x86_64-pc-windows-msvc`, `x86_64-unknown-freebsd`.

### D-C3: sccache Deferral

**Disposition chosen:** Disposition A — Formally defer sccache.

**Changes:**
- `.github/workflows/pr-fast.yml`: Removed stale `SCCACHE_GHA_ENABLED: "true"` environment variable
- `docs/testing/cache-policy.md`: Updated Layer 3 to "Dormant — deferred"; removed sccache from per-lane cache tables; updated cache size totals; marked sccache stats section as dormant; updated future considerations
- `plans/testing_milestone_d_results.md`: Corrected D2 status to "Deferred"; updated cache architecture and CI integration descriptions
- `plans/testing_milestone_d_corrective_closure_results.md`: Added final closure workstream entries; added sccache backend to remaining limitations

**Active cache layers (post-deferral):**
1. Cargo source caches (`Swatinem/rust-cache@v2`)
2. Tool binaries (`taiki-e/install-action` built-in caching)
4. Cargo target metadata (`Swatinem/rust-cache@v2`)

### D-C6: Additional Fix

**Pre-existing clippy error** in `src/admin/mod.rs:131`: `let mut state_builder` was conditionally mutable (only with `icmp-filter` feature). Fixed by using `#[cfg(feature = "icmp-filter")] let state_builder = ...` pattern to avoid the `mut` when the feature is disabled.

## Validation Results

| Check | Result |
|-------|--------|
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --all-targets -- -D warnings` | PASS |
| `cargo check --workspace --profile ci` | PASS |
| `cargo test -p synvoid-dns --lib -- platform` | PASS (23 tests) |
| `cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci` | PASS (36 tests) |
| `python3 -m pytest tests/ci/test_select_affected.py` | PASS (90 tests) |
| `python3 scripts/ci/select-affected.py --base HEAD~1 --head HEAD --format json` | PASS |
| `bash scripts/test-affected.sh HEAD~1 --dry-run` | PASS |

## Files Modified

| File | Change |
|------|--------|
| `crates/synvoid-dns/src/platform.rs` | Fixed fallback TCP test helper |
| `src/admin/mod.rs` | Fixed pre-existing clippy `unused-mut` warning |
| `.github/workflows/pr-fast.yml` | Removed stale `SCCACHE_GHA_ENABLED` |
| `.github/workflows/nightly-qualification.yml` | Added `--tests` to platform-compat |
| `docs/testing/cache-policy.md` | Updated to reflect sccache deferral |
| `docs/testing/feature-target-matrix.md` | Updated platform-compat entries |
| `plans/testing_milestone_d_results.md` | Corrected sccache claims |
| `plans/testing_milestone_d_corrective_closure_results.md` | Added final closure entries |
| `plans/testing_milestone_d_final_closure_results.md` | This file |

## Unresolved External Constraints

1. **Hosted-runner validation (D-C4)** — Requires CI observation after merge to verify selector skipping, fail-closed fallback, and cache behavior on real runners.
2. **Branch-protection audit (D-C5)** — Requires repository admin to verify required check names match current workflow job names and that skipped optional jobs don't block merging.
3. **sccache backend** — Deferred until a supported backend (self-hosted runners, S3, Redis) is available and verified to store/retrieve artifacts successfully.

## Go/No-Go Recommendation

**GO for Milestone E.** All locally-verifiable Milestone D gaps are closed:
- Non-Linux DNS fallback tests are correctly constructed
- Cross-platform test compilation is covered by nightly `platform-compat --tests`
- sccache is formally deferred with stale configuration removed
- All validation checks pass
- Pre-existing clippy warning fixed

The remaining deferred items (D-C4 hosted-runner validation, D-C5 branch-protection audit, sccache backend) are external constraints that do not block Milestone E work.
