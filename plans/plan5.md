# MaluWAF Dependency Security & Modernization Plan

**Status**: Planning Phase
**Last Updated**: 2026-04-27
**Review Phase**: Pending User Review

---

## Executive Summary

This plan addresses dependency security vulnerabilities, unmaintained crates, and modernization opportunities identified in a comprehensive audit of MaluWAF's dependency tree.

**Critical Security Items**:
- KyberSlash (RUSTSEC-2023-0079) - Replace `pqc_kyber` with `pqc_kyber_edit`
- yara-x crypto feature - Remove unused RSA dependencies via feature reduction
- wasmtime 40.0.4 transitive - Monitor yara-x for wasmtime update

**Important Updates**:
- sysinfo 0.33.1 → 0.38.4 (low risk, straightforward)
- bcrypt 0.15.1 → 0.19.0 (low risk, straightforward)
- tempfile 3.0.0 → 3.27.0 (low risk, backward compatible)

**Deferred (await stable releases)**:
- dashmap 5.5.3 → 7.0.0-rc2 (medium-high risk, major breaking changes)
- notify 6.0.0 → 9.0.0-rc.3 (medium-high risk, major API changes)

**Informational**:
- quinn-proto patch - Already removed, can mark complete in SECURITY.md
- bincode via admin-ui - Not used at runtime, acceptable to ignore

---

## Architecture Context

The overseer/master/worker architecture is **not affected** by any dependency changes in this plan. All modifications are isolated to:
- `src/wasm_pow/` - pqc_kyber replacement
- `src/admin/` - sysinfo updates
- `src/upload/` - yara-x feature reduction
- Test code - bcrypt/tempfile updates

---

## Phase 1: Critical Security Fixes

### 1.1 pqc_kyber → pqc_kyber_edit (KyberSlash)

**Issue**: RUSTSEC-2023-0079 - Timing side-channel vulnerability in ML-KEM-768 division operations (CVSS 7.4)

**Current State**:
- Crate: `pqc_kyber` 0.7.1 in `src/wasm_pow/Cargo.toml:30`
- Used for: WASM PoW (proof-of-work) challenges in browser
- Vulnerability: Division timing leaks secret key material

**Fix**: `pqc_kyber_edit` 0.7.2 from SentClose (fork with KyberSlash fix)

**Investigation Finding**: API is 100% compatible - identical function signatures, structs, and features.

**Files to Modify**:

1. `src/wasm_pow/Cargo.toml:30`
```diff
- pqc_kyber = { version = "0.7", features = ["wasm", "kyber768", "zeroize"] }
+ pqc_kyber_edit = { version = "0.7", features = ["wasm", "kyber768", "zeroize"] }
```

2. `src/wasm_pow/src/pqc.rs:6`
```diff
- use pqc_kyber::*;
+ use pqc_kyber_edit::*;
```

**Verification**:
```bash
# Compile check
cargo check -p wasm-pow

# Run wasm tests
cargo test -p wasm-pow

# Verify no pqc_kyber references remain
grep -r "pqc_kyber" src/wasm_pow/
# Should only show pqc_kyber_edit
```

**Risk Assessment**: **LOW** - Drop-in replacement with identical API

**Testing Strategy**:
1. Compile wasm-pow crate
2. Verify key generation, encapsulation, decapsulation work
3. Verify WASM module still produces valid PoW challenges

**Note on Interoperability**: Keys generated with old `pqc_kyber` are compatible with `pqc_kyber_edit` (same algorithm). Existing persisted keys will continue to work.

---

### 1.2 yara-x Crypto Feature Reduction

**Issue**: RUSTSEC-2023-0071 (Marvin Attack) via `rsa` crate pulled by yara-x's `crypto` feature

**Investigation Finding**: This is a **false positive** for our use case:
- yara-x's `crypto` feature is NOT used (we only use pattern matching)
- Our `rsa = "0.9"` direct dependency is for DNSSEC/TLS, NOT YARA
- yara-x IS pure Rust (not a C wrapper) - the project is 95.5% Rust rewrite

**Current State**:
```
yara-x = "1.15"  # default features include crypto
  └── crypto module pulls: rsa, ecdsa, p256, sha1, md5, etc.
```

**What yara-x crypto provides**:
- RSA/DSA/ECDA signatures for YARA rule signing (we use Ed25519 via ed25519-dalek)
- Cryptographic hash functions for PE/Mach-O/ELF modules
- DNSSEC validation in YARA-X modules

**What we actually use**:
- `yara_x::compile()` - Rule compilation
- `yara_x::Scanner::new()` / `scanner.scan()` - Pattern matching only
- NO YARA modules (PE, ELF, MachO parsing)
- Rule signing via `ed25519-dalek` NOT YARA's RSA scheme

**Proposed Change** (`Cargo.toml:117`):
```diff
- yara-x = "1.15"
+ yara-x = { version = "1.15", default-features = false, features = ["default-modules"] }
```

**What default-modules includes** (without crypto):
- console-module, cuckoo-module, dex-module, dotnet-module, elf-module, hash-module, lnk-module, math-module, string-module, time-module
- `elf-module` uses crypto but only as optional dependency
- `macho-module`, `pe-module`, `crx-module` are excluded (they require crypto)

**Verification**:
```bash
# Verify compilation works without crypto
cargo check --lib

# Verify rsa crate is no longer pulled by yara-x
cargo tree -i rsa
# Should not show yara-x as parent

# Run YARA-related tests
cargo test --test integration_test -- yara
```

**Files to Verify**: `src/upload/yara_scanner.rs`, `src/mesh/yara_rules.rs`, `src/upload/yara_rule_feed.rs`

**Risk Assessment**: **LOW** - We don't use YARA crypto features; reducing features removes attack surface

**Important Clarification**: The `rsa` crate (RUSTSEC-2023-0071) is still needed for DNSSEC signing/verification and TLS certificate handling. This plan does NOT remove the direct `rsa = "0.9"` dependency in Cargo.toml - only the yara-x transitive pulling of a separate `rsa` through crypto feature.

---

### 1.3 wasmtime 40.0.4 Transitive Vulnerability (Monitor)

**Issue**: yara-x 1.15.0 pulls wasmtime 40.0.4 (yanked) as transitive dependency

**Vulnerabilities**: RUSTSEC-2026-0095 (CRITICAL), RUSTSEC-2026-0096 (CRITICAL), +8 medium/low

**Current Mitigation**: `[patch.crates-io]` in Cargo.toml patches direct `wasmtime` to 42.0.2

**Problem**: Cargo's `[patch]` mechanism only patches **direct** dependencies, not transitives

**Investigation Finding**: This is **acceptable risk** because:
1. Direct wasmtime (42.0.2) is patched - our WASM plugin system is secure
2. yara-x processes locally-controlled YARA rules (not untrusted input)
3. WASM sandbox escape requires executing malicious WASM code

**Timeline**: yara-x will update to wasmtime 42+ eventually (estimated 2-6 weeks)

**Action Required**: Monitor yara-x releases
```bash
# Check for updates
cargo search yara-x

# Verify wasmtime versions in tree
cargo tree -i wasmtime
```

**Files to Monitor**: `Cargo.toml:117` (yara-x entry)

**No code changes needed** - just ongoing monitoring until yara-x releases update.

---

## Phase 2: Dependency Updates (Low Risk)

### 2.1 sysinfo 0.33.1 → 0.38.4

**Breaking Changes in 0.34+**:
- `multithread` feature disabled by default (rayon removed as default dep)
- `System::physical_core_count()` now associated function (not method)
- Dead processes removed from list by default

**Current Usage**:
- `src/admin/metrics.rs:29` - CPU/memory monitoring
- `src/admin/state.rs:751-763` - CPU/memory percentage calculation

**Methods Used** (all unchanged in 0.38):
- `System::new_all()`
- `System::refresh_all()`
- `System::cpus()`
- `Cpu::cpu_usage()`
- `System::used_memory()` / `System::total_memory()`

**Proposed Change** (`Cargo.toml`):
```diff
- sysinfo = "0.33"
+ sysinfo = "0.38"
```

**Verification**:
```bash
cargo check --lib
cargo test --lib --no-run
```

**Risk Assessment**: **LOW** - API compatible, no code changes needed

---

### 2.2 bcrypt 0.15.1 → 0.19.0

**Current Usage**:
- `src/auth/mod.rs` - password hashing
- `src/auth/basic.rs` - basic auth
- `src/admin/auth.rs` - admin authentication

**Methods Used**: `bcrypt::hash()`, `bcrypt::verify()` - unchanged in 0.19

**Proposed Change**:
```diff
- bcrypt = "0.15"
+ bcrypt = "0.19"
```

**Verification**:
```bash
cargo check --lib
cargo test --lib --no-run
```

**Risk Assessment**: **LOW** - API fully compatible

---

### 2.3 tempfile 3.0.0 → 3.27.0

**Current State**: Already at 3.27.0 in Cargo.lock (no TOML change needed)

**Current Usage**: 35+ locations across tests and production code

**Breaking Changes**:
- `Builder::keep` renamed to `Builder::disable_cleanup` (3.21.0, with deprecation warning)
- MSRV bumped to 1.63 (3.7.0)

**Verification**:
```bash
cargo check --lib
cargo test --lib --no-run
```

**Risk Assessment**: **LOW** - backward compatible

**Note**: Already at latest version in Cargo.lock. No TOML change required. Deprecation warnings acceptable.

---

## Phase 3: Deferred Major Updates

### 3.1 dashmap 5.5.3 → 7.0.0-rc2

**Status**: **DEFERRED** - Await stable v7.0.0 release

**Breaking Changes**:
1. **Detached Guards** (Critical): `Ref`/`RefMut` lifetime semantics changed fundamentally
2. **Hashbrown 0.15**: Internal data structure changed from `HashMap` to `HashTable`
3. **Crossbeam-utils**: Uses `CachePadded` instead of `parking_lot` directly
4. **Equivalent trait**: Key comparison behavior changed
5. **Iterator lifetime changes**: `Map` trait modified
6. **MSRV bump**: 1.56 → 1.70

**Codebase Impact** (172 usages):
- Heavy usage in hot paths: metrics, mesh transport, proxy cache, waf detectors
- `.get().cloned()` pattern (156 matches) - guard semantics differ
- Async code passing guards across tokio::spawn boundaries

**Risk Assessment**: **MEDIUM-HIGH**

**Migration Steps** (when ready):
1. Update Cargo.toml to `dashmap = "7.0.0-rc2"`
2. Run `cargo check --lib` - expect compilation errors
3. Fix guard access patterns:
   ```rust
   // Before (v5)
   let guard = map.get(&key).unwrap();
   let value = (*guard).clone();

   // After (v7)
   let value = map.get(&key).unwrap().clone();
   ```
4. Run integration tests focusing on concurrent DashMap access

**Testing Strategy**:
- Unit tests for each DashMap usage location
- Integration tests for mesh transport, proxy cache
- Load tests for concurrent access patterns

**Recommendation**: Wait for stable v7.0.0. Budget 2-3 days for migration and testing when proceeding.

---

### 3.2 notify 6.0.0 → 9.0.0-rc.3

**Status**: **DEFERRED** - Consider v8.x first, await stable v9.0.0

**Breaking Changes**:
1. **MSRV bump**: 1.57 → 1.81
2. **notify-types crate**: Event types moved to separate `notify-types v2.1.0` crate
3. **bitflags**: ^1.0.4 → ^2.7.0
4. **walkdir**: ^2.2.2 → ^2.4.0
5. **mio**: ^0.8 → ^1.0
6. **kqueue**: ^1.0 → ^1.1.1
7. **Windows-sys**: ^0.45.0 → ^0.61.0
8. **Path handling**: Preserves representation differences

**Codebase Impact** (13 usages):
- Plugin hot-reload: `src/plugin/mod.rs:303`
- Certificate watching: `src/tls/cert_resolver.rs:464`

**API Compatibility**: Types are re-exported from `notify` crate, most code should work unchanged

**Risk Assessment**: **MEDIUM-HIGH** (MSRV 1.81 requirement is significant)

**Recommended Approach**:
1. First migrate to notify v8.x (stable is 8.2.0) - smaller jump, lower risk
2. Then evaluate v9 when stable

**Migration Steps** (for v8):
1. Update Cargo.toml to `notify = "8"`
2. Run `cargo check` - expect minimal issues (types re-exported)
3. Test plugin hot-reload functionality
4. Test certificate watching functionality

**Note**: There's no notify 9.0.0 yet - 9.0.0-rc.3 is the latest pre-release. Stable v8.2.0 is available and may be safer to adopt first.

---

## Phase 4: Informational Items

### 4.1 quinn-proto Patch Status

**Finding**: Patch already removed, quinn-proto 0.11.14 from registry is in use.

**SECURITY.md Status**: Documented as "TODO: Remove patch when quinn 0.11.10+ releases" - **can be marked complete**.

**Verification**:
```bash
cargo tree -p quinn-proto
# Output shows: source = "registry+https://github.com/rust-lang/crates.io-index" ✓
```

**Action**: Update SECURITY.md to mark patch as removed.

---

### 4.2 bincode via admin-ui Transitive

**Finding**: bincode 1.3.3 via gloo-worker in admin-ui is **never executed at runtime**.

**Evidence**:
- admin-ui uses `gloo::timers` and `gloo::net::http`
- Does NOT use `gloo-worker` (Web Workers API)
- bincode is only invoked for Web Worker message serialization

**Risk**: **VERY LOW** - theoretical only

**Current Mitigation**: Already ignored in `deny.toml` (RUSTSEC-2025-0141)

**Action**: Continue ignoring - acceptable risk

---

### 4.3 rsa crate (Marvin Attack)

**Finding**: Our `rsa = "0.9"` is for DNSSEC/TLS, NOT for YARA.

**Usage**:
- `src/dns/dnssec_signing.rs:22-26` - RSA signing for DNSSEC (algorithm 8)
- `src/dns/dnssec_key_mgmt.rs:233-272` - RSA key generation
- `src/dns/mesh_dnssec.rs:106-132` - RSA verification
- `src/tls/cert_resolver.rs:168-192` - RSA private key parsing

**Risk Assessment**: **LOW** - DNSSEC signatures are validated, not decrypting attacker-provided ciphertexts

**No Action Required**: The Marvin Attack vulnerability requires attacker to provide adaptively-chosen ciphertexts. DNSSEC validation reads signatures from network, not from attacker-controlled sources.

---

## Implementation Order

```
Phase 1: Critical Security Fixes
├── 1.1 pqc_kyber → pqc_kyber_edit (KyberSlash)
├── 1.2 yara-x crypto feature reduction (removes rsa transitive)
└── 1.3 wasmtime 40.0.4 monitoring (no code change)

Phase 2: Low-Risk Dependency Updates
├── 2.1 sysinfo 0.33 → 0.38
├── 2.2 bcrypt 0.15 → 0.19
└── 2.3 tempfile 3.27.0 (already current - no change needed)

Phase 3: Deferred Major Updates
├── 3.1 dashmap 5 → 7 (await stable)
└── 3.2 notify 6 → 8 first, then 9 later

Phase 4: Informational
├── 4.1 Update SECURITY.md (quinn-proto patch done)
└── 4.2 Document bincode non-usage in deny.toml comment
```

---

## Files Summary

| Phase | Action | Files Modified |
|-------|--------|----------------|
| 1.1 | pqc_kyber → pqc_kyber_edit | `src/wasm_pow/Cargo.toml`, `src/wasm_pow/src/pqc.rs` |
| 1.2 | yara-x crypto feature reduction | `Cargo.toml` |
| 1.3 | wasmtime monitoring | None (just monitor) |
| 2.1 | sysinfo update | `Cargo.toml` |
| 2.2 | bcrypt update | `Cargo.toml` |
| 2.3 | tempfile (none needed) | None |
| 4.1 | SECURITY.md update | `SECURITY.md` |

---

## Risk Assessment Summary

| Item | Risk | Effort | Timeline |
|------|------|--------|----------|
| pqc_kyber_edit | LOW | 2 lines | Immediate |
| yara-x crypto reduction | LOW | 1 line | Immediate |
| sysinfo update | LOW | 1 line | Immediate |
| bcrypt update | LOW | 1 line | Immediate |
| tempfile | NONE | None | Already current |
| dashmap → 7 | MEDIUM-HIGH | 2-3 days testing | Deferred |
| notify → 9 | MEDIUM-HIGH | 1-2 days testing | Deferred |
| wasmtime monitoring | N/A | Ongoing | Until yara-x updates |

---

## Verification Commands

```bash
# Phase 1 security fixes
cargo check -p wasm-pow
cargo check --lib
cargo tree -i rsa  # Verify yara-x no longer pulls rsa

# Phase 2 updates
cargo check --lib
cargo test --lib --no-run

# Monitor wasmtime
cargo tree -i wasmtime

# Full verification
cargo fmt
cargo clippy -- -D warnings
cargo test --test integration_test
```

---

## Dependencies

- **wasmtime patch**: Already in place via `[patch.crates-io]`
- **No feature flag changes**: All changes work with default features
- **No architecture changes**: overseer/master/worker unaffected

---

## Notes

1. **Architecture Preserved**: All changes maintain the multi-process architecture. No IPC message changes, no process management changes.

2. **WASM PoW Impact**: The pqc_kyber_edit change only affects WASM PoW challenges. Server-side crypto (ML-KEM via aws-lc-rs, Ed25519 via ed25519-dalek) is unaffected.

3. **YARA Functionality**: yara-x with reduced features still provides full pattern matching. The crypto module is only needed for YARA's optional rule signing scheme (which we don't use).

4. **DNSSEC/TLS RSA**: The `rsa` crate remains a direct dependency for DNSSEC algorithm 8 (RSA/SHA-256) and TLS key parsing. This is separate from yara-x's crypto feature.

5. **dashmap/notify deferral**: These are substantial jumps with breaking changes. Proper migration requires dedicated testing time and should not be rushed.

---

## SECURITY.md Updates Required

After completing Phase 1:
- Mark "KyberSlash" as resolved via `pqc_kyber_edit`
- Add note about yara-x crypto feature reduction
- Mark quinn-proto patch as removed (already done)
- Document monitoring status for wasmtime transitive

---

**Plan Created**: 2026-04-27
**Review Status**: Pending user review before implementation