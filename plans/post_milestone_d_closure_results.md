# Post-Milestone D Closure Results

**Date**: 2026-07-12
**Classification**: **State B** — release-ready for all supported profiles

## Summary

5-workstream corrective closure pass addressing remaining gaps from Milestone D.

## Workstream Results

### 1. synvoid-icmp-filter eBPF Classification — RESOLVED

**Before**: 6 compilation errors with `--all-features` (aya not declared, stale paths, missing return).
**After**: All 4 check commands pass (default + all-features × check + clippy).

**10 fixes applied**:
1. Added `aya = { version = "0.13", optional = true }` to Cargo.toml
2. Added `icmp-ebpf = ["dep:aya"]` feature gating
3. Fixed stale module paths (`crate::icmp_filter::config` → `crate::config`)
4. Added missing return value in `FilterType::Ebpf` cfg-not branch
5. Added `unsafe impl aya::Pod` for 5 eBPF map structs
6. Restructured `load_and_attach_program()` borrow scope
7. Updated aya 0.13 API (`take_map()`, `PerCpuValues::iter()`)
8. Fixed `set()` signature (removed `&` borrows)
9. Changed `update_icmp_type_rules` to standalone function
10. Fixed clippy `explicit_counter_loop`

**Classification**: **Beta** — compiles cleanly, runtime returns explicit error when eBPF unavailable. Not in default profile.

### 2. Supported Profile Matrix — CREATED

New document: `architecture/release_profile_matrix.md`
- 5 compilation profiles (default, core, mesh, dns, full)
- 17 feature gates (13 Supported, 4 Beta)
- 8 platform targets
- Release support matrix
- eBPF feature classification (Beta)

### 3. Dependency/Audit Evidence — VERIFIED

- `cargo deny check`: **PASS** (advisories ok, bans ok, licenses ok, sources ok)
- 199 duplicate crates (non-pathological — major version ecosystem boundaries)
- 12 advisory ignores documented in `deny.toml` with re-audit dates 2026-10-01
- wasmtime 40.0.4 (yara-x) + 42.0.2 (direct) tracked and mitigated

### 4. CI Workflow — COMPLETED

- 26 CI jobs present and parsed cleanly
- Added `alpine-test`, `freebsd-test`, `platform-compat` to summary `needs` + table
- All release-critical jobs now referenced in CI summary

### 5. Release-Polish Note — THIS DOCUMENT

## Files Modified

| File | Change |
|------|--------|
| `crates/synvoid-icmp-filter/Cargo.toml` | Added aya optional dep, feature gating |
| `crates/synvoid-icmp-filter/src/ebpf.rs` | Fixed 10 compilation issues |
| `crates/synvoid-icmp-filter/src/lib.rs` | Fixed missing return in eBPF cfg block |
| `.github/workflows/ci.yml` | Added 3 missing jobs to summary needs + table |
| `architecture/release_profile_matrix.md` | New: compilation profiles, feature gates, platform coverage |
| `AGENTS.md` | Updated Known Issues, Recent Completions, Architecture Quick Reference |

## Release Readiness

| Gate | Status |
|------|--------|
| Default profile compiles | ✅ |
| All 5 profiles compile | ✅ |
| Clippy clean (all features) | ✅ |
| cargo-deny passes | ✅ |
| CI summary references all jobs | ✅ |
| eBPF feature classified | ✅ Beta |
| Profile matrix documented | ✅ |
| Advisory ignores documented | ✅ |

**Conclusion**: State B — release-ready for all supported profiles. The only tracked exception is the eBPF feature (Beta), which compiles cleanly but has hard runtime constraints.
