# Dependency Security & Maintainability Improvement Plan

**Plan ID**: 17  
**Date**: 2026-04-23  
**Status**: Draft  
**Priority**: High (Security)  

## Executive Summary

This plan addresses security vulnerabilities and maintainability issues identified in the MaluWAF dependency tree through comprehensive audit including `cargo audit`, source code analysis, and research into upstream fixes.

### Key Findings

| # | Issue | Severity | Status |
|---|-------|----------|--------|
| 1 | KyberSlash (pqc_kyber) | HIGH | DEFERRED - Wait for ml-kem stable |
| 2 | wasmtime transitive via yara-x | CRITICAL | MITIGATE - Test patch overlay |
| 3 | hickory-recursor cache poisoning | HIGH | DEFERRED - Keep current |
| 4 | proc-macro-error via utoipa | INFO | FIX NOW - Upgrade to utoipa 5.x |
| 5 | bincode via yara-x | INFO | MONITOR - No action |
| 6 | rsa Marvin Attack | MEDIUM | ACCEPT - Low exposure |
| 7 | quinn-proto DoS | HIGH | PATCHED - Git patch |
| 8 | axum update | - | UPDATE - Safe drop-in |
| 9 | tonic update | - | UPDATE - Safe drop-in |

---

## Phase 1: High Priority Security Fixes

### 1.1 FIXED: proc-macro-error via utoipa (RUSTSEC-2024-0370)

#### Issue Details

| Aspect | Value |
|--------|-------|
| Advisory ID | RUSTSEC-2024-0370 |
| Type | Unmaintained (INFO) |
| Severity | None (not a CVE) |
| Source | utoipa-gen |
| Current | proc-macro-error 1.0.4 |
| Fix Target | utoipa 5.x |

#### Root Cause

The `proc-macro-error` crate is unmaintained (last release 2020). It's used by `utoipa-gen` for proc-macro error diagnostics. This is a **build-time warning only** - not a runtime vulnerability.

#### Solution: Upgrade to utoipa 5.x

**utoipa 5.4.0** removes the `proc-macro-error` dependency entirely.

#### Breaking Changes (utoipa 4.x → 5.x)

| Change | Impact | Workaround |
|--------|--------|------------|
| OpenAPI 3.0 dropped | All schemas must be 3.1 | Verify schemas are compatible |
| Schema auto-collection | Components listing optional | Simplify or keep explicit |
| Generic type bounds | Must implement ToSchema | Add bounds to generics |
| content_type array syntax | Removed | Use content attribute |
| #[serde(tag)] discriminator | Changed | Update enum schemas |

#### Migration Steps

```bash
# Step 1: Update Cargo.toml
# From:
utoipa = "4"
utoipa-swagger-ui = { version = "7", features = ["axum"] }

# To:
utoipa = "5"
utoipa-swagger-ui = { version = "7", features = ["axum"] }
```

```bash
# Step 2: Build and identify issues
cargo build 2>&1 | grep -E "(error|warning:.*utoipa)"
```

```bash
# Step 3: Common fixes
# - Add ToSchema to generic type parameters
# - Update content_type = [...] to content = ...
# - Simplify components() if using auto-collection
```

#### Files to Review

| File | Purpose | Changes |
|------|---------|---------|
| `src/admin/openapi.rs` | OpenAPI definition | Schema listing simplification |
| `src/admin/handlers/config.rs` | Config handlers | 50+ ToSchema derives |
| `src/admin/handlers/mesh_admin.rs` | Mesh admin | 30+ ToSchema derives |
| `src/admin/handlers/sites.rs` | Sites handlers | 10+ ToSchema derives |
| `src/admin/state.rs` | Admin state | Schema definitions |

#### Effort: MEDIUM
#### Risk: MEDIUM (mostly compatible)
#### Testing Required: Yes - compile + runtime

---

### 1.2 MITIGATE: wasmtime Transitive via yara-x (RUSTSEC-2026-0096)

#### Issue Details

| Aspect | Value |
|--------|-------|
| Advisory IDs | RUSTSEC-2026-0086, RUSTSEC-2026-0092, RUSTSEC-2026-0093, RUSTSEC-2026-0096 |
| Severity | CRITICAL (9.0 CVSS) |
| Vulnerable | wasmtime 40.0.4 |
| Your Direct | wasmtime 42.0.2 (PATCHED) |
| Problem | yara-x 1.15.0 bundles wasmtime 40.0.4 |

#### Root Cause

yara-x uses `wasmtime = "40.0.4"` in their Cargo.toml. The direct patch doesn't work because yara-x bundles it at that version.

```
yara-x 1.15.0
└── wasmtime 40.0.4  ← CRITICAL CVE
```

#### Solution Attempts

##### Attempt 1: Crates.io patch (recommended first)

```toml
# In Cargo.toml, change:

# FROM:
[patch.crates-io]
wasmtime = { git = "https://github.com/bytecodealliance/wasmtime", tag = "v42.0.2" }

# TO:
[patch.crates-io]
wasmtime = "42.0.2"
```

```bash
# Test:
cargo build 2>&1 | grep wasmtime
cargo tree -p wasmtime
```

##### Attempt 2: Replace directive (legacy)

```toml
[replace]
"https://github.com/bytecodealliance/wasmtime#wasmtime" = { version = "42.0.2" }
```

##### Attempt 3: Accept and monitor

If neither patch works:
- Document the vulnerability in SECURITY.md
- Monitor yara-x releases for wasmtime 42+ update
- Consider opening issue on VirusTotal/yara-x

#### Risk: LOW if patch works
#### Effort: LOW
#### Testing Required: Yes - verification

---

### 1.3 UPDATE: axum 0.8.x

| Aspect | Value |
|--------|-------|
| From | 0.8.x |
| To | 0.8.9 |
| Changes | Minimal (MSRV → 1.80) |

#### Changes in 0.8.9
- WebSocket subprotocol selection APIs
- MSRV bump to 1.80
- Multipart error fix
- Relaxed Send/Sync bounds

#### Migration

```toml
# In Cargo.toml:
axum = "0.8.9"
```

```bash
cargo build
```

#### Effort: LOW
#### Risk: NONE

---

### 1.4 UPDATE: tonic 0.14.x

| Aspect | Value |
|--------|-------|
| From | 0.14.x |
| To | 0.14.5 |
| Changes | None significant |

#### Changes in 0.14.5
- Channel credentials API
- TCP listener API
- xDS worker
- max connections

#### Migration

```toml
# In Cargo.toml:
tonic = "0.14.5"
```

#### Effort: LOW
#### Risk: NONE

---

## Phase 2: Deferred Items (Research Complete)

### 2.1 DEFERRED: pqc_kyber → ml-kem (KyberSlash)

| Aspect | Value |
|--------|-------|
| Advisory | RUSTSEC-2023-0079 |
| Severity | HIGH |
| Status | No upstream fix available |

#### Why Deferred

- ml-kem 0.3.0-rc.2 is still in release candidate
- MSRV is Rust 1.85 (wasm-pow uses 2021)
- API changes require code modifications

#### When to Revisit

- Wait for ml-kem stable release (1.0)
- Re-evaluate in 1-2 months

#### Alternative

Consider `safe_pqc_kyber` 0.6.3 as interim fix if needed:
```toml
# In src/wasm_pow/Cargo.toml:
safe_pqc_kyber = "0.6.3"
```

---

### 2.2 DEFERRED: hickory-recursor (RUSTSEC-2026-0106)

| Aspect | Value |
|--------|-------|
| Advisory | RUSTSEC-2026-0106 |
| Severity | HIGH |
| Fix | hickory-dns 0.26.0 (released 2026-04-16) |

#### Why Deferred

- User chose to keep current configuration
- DNS recursive is opt-in feature

#### Mitigation Available

Avoid `upstream_provider = "Recursive"` in DNS config.

---

### 2.3 MONITOR: bincode via yara-x (RUSTSEC-2025-0141)

| Aspect | Value |
|--------|-------|
| Advisory | RUSTSEC-2025-0141 |
| Severity | INFO (unmaintained, no CVE) |

#### Why Monitor

- bincode is unmaintained but NOT vulnerable
- Project was archived due to doxxing incident
- yara-x uses it for internal serialization only

#### No Action Required

- yara-x uses bincode for rule serialization only
- No external attack surface

---

### 2.4 ACCEPT: rsa Marvin Attack (RUSTSEC-2023-0071)

| Aspect | Value |
|--------|-------|
| Advisory | RUSTSEC-2023-0071 |
| Severity | MEDIUM (5.9 CVSS) |

#### Why Accept

- Code path requires local timing measurement
- Not network-exploitable
- Server-side DNSSEC signing only
- Ed25519 available as alternative

---

## Implementation Checklist

### Phase 1 Execution

| # | Task | Effort | Risk | Status |
|---|------|--------|------|--------|
| 1.1 | Upgrade utoipa 4 → 5 | Medium | Medium | [ ] Pending |
| 1.2 | Test wasmtime patch | Low | Low | [ ] Pending |
| 1.3 | Update axum → 0.8.9 | Low | None | [ ] Pending |
| 1.4 | Update tonic → 0.14.5 | Low | None | [ ] Pending |

### Phase 2 Items (Deferred)

| # | Task | Reason |
|---|------|--------|
| 2.1 | pqc_kyber → ml-kem | Wait for ml-kem stable |
| 2.2 | hickory-recursor update | Keep current config |
| 2.3 | bincode via yara-x | No action - advisory only |
| 2.4 | rsa Marvin Attack | Accept low exposure |

---

## SECURITY.md Updates Required

After implementing Phase 1:

1. **Add**: RUSTSEC-2026-0106 (hickory-recursor) to vulnerability table
2. **Update**: Mark proc-macro-error as **FIXED via utoipa 5.x**
3. **Update**: wasmtime transitive status - patch attempted
4. **Add**: Todo note for ml-kem migration when stable

---

## Risk Summary

| Item | Risk Eliminated | Remaining |
|------|-----------------|------------|
| utoipa 5.x | proc-macro-error | - |
| wasmtime patch | CRITICAL CVEs | yara-x transitive |
| axum update | - | - |
| tonic update | - | - |
| pqc_kyber | KyberSlash | DEFERRED |
| hickory-recursor | Cache poisoning | DEFERRED |

---

## References

- RustSec Advisory Database: https://rustsec.org/
- yara-x Releases: https://github.com/VirusTotal/yara-x/releases
- hickory-dns: https://github.com/hickory-dns/hickory-dns
- ml-kem: https://github.com/RustCrypto/kems/tree/master/ml-kem
- utoipa: https://github.com/leto-gg/utoipa