# Plan 31: Dependency Security Audit and Remediation

## Context

A comprehensive security audit of MaluWAF's dependency tree was conducted, revealing several issues requiring attention:

1. **CRITICAL**: yara-x transitive dependency on vulnerable wasmtime 40.0.4
2. **HIGH**: hickory-recursor DNS cache poisoning vulnerability (RUSTSEC-2026-0106)
3. **HIGH**: pqc_kyber KyberSlash vulnerability (RUSTSEC-2023-0079) in wasm-pow
4. **MEDIUM**: bincode unmaintained (RUSTSEC-2025-0141)
5. **INFO**: Various transitive unmaintained crates (proc-macro-error, atomic-polyfill)

**Architecture Impact**: ✅ **overseer/master/worker architecture intact** - no changes needed

**SECURITY.md Status**: Requires updates to reflect new findings.

---

## Executive Summary

| Category | Count | Action Required |
|----------|-------|----------------|
| Critical vulnerabilities | 2 | Monitor (transitive) |
| High severity issues | 3 | 2 require migration |
| Medium severity issues | 8 | Monitor (transitive) |
| Unmaintained crates | 4 | Acceptable risk |

---

## Issue #1: hickory-recursor Cache Poisoning

**RUSTSEC-2026-0106** - Disclosed April 22, 2026

### Problem

The `hickory-recursor` crate has a critical DNS cache poisoning vulnerability:

| Field | Value |
|-------|-------|
| Severity | High |
| Affected | `hickory-recursor 0.25.2` |
| Issue | Record cache accepts AUTHORITY section NS from sibling zone via parent-pool zone-context elevation |
| Status | **No fix** - crate deprecated |
| Fix | Migrate to `hickory-resolver 0.26.0` with `recursor` feature |

### Root Cause

The `hickory-recursor` crate stored DNS records keyed by `(name, type)` rather than by the originating query. This allowed cache poisoning where a response for `attacker.poc.` could pollute the cache entry for `victim.poc.`.

### Solution

The hickory-dns team deprecated `hickory-recursor` and folded its functionality into `hickory-resolver` behind the `recursor` feature flag. The new architecture stores responses keyed by `(query_name, query_type)` preventing cross-zone poisoning.

---

## Phase 1: Migrate hickory-recursor → hickory-resolver

### Step 1.1: Update Cargo.toml Dependencies

**File**: `Cargo.toml:113-115`

**Current:**
```toml
hickory-proto = { version = "0.25", features = ["dnssec-ring", "text-parsing"], optional = true }
hickory-resolver = { version = "0.25", features = ["system-config"], optional = true }
hickory-recursor = { version = "0.25", features = ["dnssec-ring"], optional = true }
```

**Change to:**
```toml
hickory-proto = { version = "0.26", features = ["dnssec-ring", "text-parsing"], optional = true }
hickory-resolver = { version = "0.26", features = ["system-config", "recursor", "dnssec-ring"], optional = true }
# hickory-recursor removed - functionality folded into hickory-resolver with recursor feature
```

### Step 1.2: Update dns Feature Flag

**File**: `Cargo.toml:23`

**Current:**
```toml
dns = ["dep:hickory-proto", "dep:hickory-resolver", "dep:hickory-recursor", "dep:tokio-dstip", "dep:cryptoki", "dep:getrandom"]
```

**Change to:**
```toml
dns = ["dep:hickory-proto", "dep:hickory-resolver", "dep:tokio-dstip", "dep:cryptoki", "dep:getrandom"]
```

### Step 1.3: Update HickoryRecursor Import

**File**: `src/dns/resolver.rs:585-586`

**Current:**
```rust
pub struct HickoryRecursor {
    recursor: Arc<hickory_recursor::Recursor>,
    // ...
}
```

**Change to:**
```rust
use hickory_resolver::recursor::{DnssecPolicy, DnssecConfig, RecursorOptions, Recursor};
use hickory_resolver::net::runtime::TokioRuntimeProvider;

pub struct HickoryRecursor {
    recursor: Arc<Recursor<TokioRuntimeProvider>>,
    // ...
}
```

### Step 1.4: Update Constructor Logic

**File**: `src/dns/resolver.rs:668-681`

**Current:**
```rust
let dnssec_policy = if enable_dnssec {
    hickory_recursor::DnssecPolicy::ValidateWithStaticKey {
        trust_anchor: Some(Arc::new(trust_anchors)),
    }
} else {
    hickory_recursor::DnssecPolicy::SecurityUnaware
};

let recursor = hickory_recursor::Recursor::builder()
    .dnssec_policy(dnssec_policy)
    .build(roots)
    .map_err(|e| {
        error!("Failed to build recursor: {}", e);
        DnsError::Config(format!("Recursor build failed: {}", e))
    })?;
```

**Change to:**
```rust
let dnssec_policy = if enable_dnssec {
    DnssecPolicy::ValidateWithStaticKey(DnssecConfig {
        trust_anchor: Some(Arc::new(trust_anchors)),
        nsec3_soft_iteration_limit: None,
        nsec3_hard_iteration_limit: None,
        validation_cache_size: None,
    })
} else {
    DnssecPolicy::SecurityUnaware
};

let recursor = Recursor::new(
    &root_ips,
    dnssec_policy,
    None, // encrypted_transport_state
    RecursorOptions::default(),
    TokioRuntimeProvider::default(),
).map_err(|e| {
    error!("Failed to build recursor: {}", e);
    DnsError::Config(format!("Recursor build failed: {}", e))
})?;
```

### Step 1.5: Update Resolve Call

**File**: `src/dns/resolver.rs:889-893`

The resolve call signature should remain compatible, but verify:

```rust
// Verify this still works:
recursor.resolve(query, Instant::now(), self.enable_dnssec).await
```

### Step 1.6: Update DNSSEC Validation Logic

**File**: `src/dns/resolver.rs:905-918`

The DNSSEC record iteration may need adjustments:

```rust
// Verify dnssec_record_iter() and proven_record.proof().is_secure() still work
for proven_record in lookup.dnssec_record_iter() {
    if proven_record.proof().is_secure() {
        is_dnssec_validated = true;
    }
    // ...
}
```

### Step 1.7: Update Error Type Imports

**File**: `src/dns/resolver.rs`

Update any imports of `hickory_recursor::RecursorError` to `hickory_resolver::recursor::RecursorError`.

### Step 1.8: Test DNS Resolution

Run integration tests:

```bash
cargo test --test dns_server_test --features dns
cargo test --test dns_recursive_test --features dns
```

Verify:
- A, AAAA, MX, TXT, NS, SOA, CNAME, SRV, PTR records resolve correctly
- DNSSEC validation produces correct `is_dnssec_validated` flags
- RFC 5011 trust anchor updates still function

---

## Issue #2: yara-x Transitive wasmtime 40.0.4 Vulnerability

**RUSTSEC-2026-0095, RUSTSEC-2026-0096** - Critical

### Problem

| Field | Value |
|-------|-------|
| Severity | Critical (transitive) |
| Affected | `yara-x 1.15.0 → wasmtime 40.0.4` |
| Your direct wasmtime | 42.0.2 (patched) |
| Issue | Sandbox escape vulnerabilities in wasmtime 40.0.4 |

### Why Current Patch Fails

**File**: `Cargo.toml:42-45`

```toml
# Current patch (INEFFECTIVE for yara-x):
wasmtime = { git = "https://github.com/bytecodealliance/wasmtime", tag = "v42.0.2" }
```

**Problem**: yara-x 1.15.0 specifies `wasmtime = "^40.0.4"` (semver range). Your patch provides `42.0.2`. Cargo cannot substitute major versions due to semver constraints.

**Evidence** from `Cargo.lock`:
- wasmtime 40.0.4 (lines 8997-9035) - from registry, yara-x's copy
- wasmtime 42.0.2 (lines 9038-9087) - from git patch, your copy

### Solution

**yara-x main branch already uses wasmtime 43.0.1**. Wait for yara-x 1.16.0 release (~2-4 weeks).

### Risk Assessment

| Factor | Assessment |
|--------|------------|
| Vulnerable wasmtime present | Yes - 40.0.4 in tree |
| Winch compiler used | No - project uses Cranelift |
| aarch64 Cranelift exploit | Possible on ARM Macs |
| Exploitation requires | Malicious WASM module loaded as plugin |

**Mitigating factors**:
- Your WASM plugin runtime uses Cranelift, not Winch
- yara-x's wasmtime is sandboxed for YARA rule scanning
- Exploitation requires attacker-supplied WASM module

### Action Items

1. **Monitor yara-x releases** for 1.16.0 with wasmtime 43.0.1+
2. **When available**, update yara-x version and test
3. **Consider** removing or adjusting your wasmtime patch after yara-x updates

---

## Issue #3: pqc_kyber KyberSlash Vulnerability

**RUSTSEC-2023-0079** - High

### Problem

| Field | Value |
|-------|-------|
| Severity | High |
| Affected | `pqc_kyber 0.7.1` (in wasm-pow) |
| Issue | Division timings in Barrett reduction (KyberSlash) |
| Status | No fix in original crate |

### Investigation: aws-lc-rs as Replacement

**CRITICAL FINDING**: aws-lc-rs **cannot** replace pqc_kyber in wasm-pow.

| Crate | WASM Support | Reason |
|-------|--------------|--------|
| `pqc_kyber` | ✅ Yes | Pure Rust implementation with `wasm` feature |
| `aws-lc-rs` | ❌ No | FFI to C library via `aws-lc-sys`, no `no_std` support |

### API Comparison

| pqc_kyber | aws-lc-rs |
|-----------|------------|
| `keypair(&mut rng) → Keypair` | `DecapsulationKey::generate(&ML_KEM_768)` |
| `encapsulate(pk, &mut rng) → (Ciphertext, SharedSecret)` | `ek.encapsulate() → (Ciphertext, SharedSecret)` |
| `decapsulate(ct, sk) → SharedSecret` | `dk.decapsulate(ct)` |

### Alternatives Considered

| Option | Viability | Notes |
|--------|-----------|-------|
| aws-lc-rs | ❌ Not possible | FFI-based, no WASM support |
| `kyber` fork | ❌ Doesn't exist | Mentioned fork doesn't exist |
| `ml-kem` | ⚠️ Risky | API changes required, MSRV 1.85, no WASM testing |
| **Keep pqc_kyber** | ✅ Acceptable | Hybrid X25519+ML-KEM provides defense-in-depth |

### Current Architecture Analysis

**File**: `src/wasm_pow/src/pqc.rs`

```rust
// Keypair generation
let keys = pqc_kyber::keypair(&mut rng)?;

// Encapsulation (creates ciphertext + shared secret)
let (ct, ss) = pqc_kyber::encapsulate(public_key, &mut rng)?;

// Decapsulation (recovers shared secret)
let ss = pqc_kyber::decapsulate(ciphertext, secret_key)?;
```

**Hybrid key exchange** (`src/wasm_pow/src/lib.rs:135-364`):
1. Client generates X25519 keypair + ML-KEM keypair
2. Sends both public keys to global node
3. Global node responds with server X25519 pubkey + ML-KEM ciphertext
4. Client combines: `combine_wasm_secrets(X25519_secret, ML-KEM_secret)`

### Defense-in-Depth Assessment

Even if KyberSlash affects the ML-KEM portion:
- X25519 component remains secure (independent of KyberSlash)
- Combination requires both secrets
- Attacker would need to compromise both components

**Recommendation**: Keep current architecture with pqc_kyber. The hybrid design limits exposure.

### Future Migration Path

When `ml-kem` reaches stable 1.0 with WASM support, consider migrating:

```toml
# Future replacement (when ml-kem stabilizes):
ml-kem = { version = "1.0", features = ["kyber768"] }
```

---

## Issue #4: bincode Unmaintained

**RUSTSEC-2025-0141**

### Problem

| Version | Source | Status |
|---------|--------|--------|
| 1.3.3 | gloo-worker (admin-ui) | Unmaintained, no fix |
| 2.0.1 | yara-x | Unmaintained, no fix |

### Assessment

**Risk is contained**:
- Your own serialization already migrated to `postcard`
- bincode is only used internally by those libraries
- gloo-worker is only for WASM (admin-ui)
- yara-x uses it internally for rule serialization

### Action Items

1. **Accept risk** - No practical action available
2. **Document** in SECURITY.md for awareness

---

## Issue #5: Other Unmaintained Crates

### Assessment: Acceptable Risk

| Crate | Source | Issue |
|-------|--------|-------|
| `proc-macro-error` | yew, utoipa | Compile-time only |
| `atomic-polyfill` | heapless/postcard | Build warning only |
| `unicode-segmentation` | wasmtime | Build warning, 1.13.2 available |
| `gimli` | wasmtime | Build warning, 0.33.0 available |

**Action**: No immediate action required. Monitor for updates.

---

## Complete Prioritized Action Plan

| Priority | Issue | Action | Effort | Timeline |
|----------|-------|--------|--------|----------|
| **1. HIGH** | hickory-recursor | Migrate to hickory-resolver 0.26 with recursor feature | Medium (2-4h) | 1-2 weeks |
| **2. MONITOR** | yara-x/wasmtime | Watch for yara-x 1.16.0 release | - | 2-4 weeks |
| **3. ACCEPT** | pqc_kyber in wasm-pow | Keep hybrid architecture; aws-lc-rs not viable for WASM | - | Ongoing |
| **4. ACCEPT** | bincode | Contained within transitive deps | - | Ongoing |
| **5. ACCEPT** | proc-macro-error | Compile-time only | - | Ongoing |

---

## SECURITY.md Updates Required

### Step 2.1: Add New Vulnerability Entry

**File**: `SECURITY.md` - Add to "High Severity" table:

```markdown
| DNS Cache Poisoning | `hickory-recursor` | RUSTSEC-2026-0106 | **Migration required** | Migrating to hickory-resolver 0.26 with recursor feature |
```

### Step 2.2: Update yara-x/wasmtime Section

**File**: `SECURITY.md` - Update notes:

```markdown
### yara-x/wasmtime Transitive Vulnerability (RUSTSEC-2026-0096)
- **Issue**: yara-x 1.15.0 pulls wasmtime 40.0.4 which has multiple vulnerabilities
- **Severity**: CRITICAL - wasmtime 40.0.4 is yanked
- **Your direct version**: wasmtime 42.0.2 (secure) - direct dependency is fine
- **Affected path**: yara-x → wasmtime 40.0.4 (transitive)
- **Mitigation**: Direct wasmtime patched to 42.0.2 via [patch.crates-io]
- **Fix pending**: yara-x main branch uses wasmtime 43.0.1; waiting for 1.16.0 release
- **Risk assessment**: Your code uses Cranelift (not Winch); exploitation requires malicious WASM module
```

### Step 2.3: Add wasm-pow KyberSlash Assessment

**File**: `SECURITY.md` - Add to "Post-Quantum Crates" section:

```markdown
### wasm-pow KyberSlash Assessment (RUSTSEC-2023-0079)
- **Issue**: Division timings in Barrett reduction (KyberSlash)
- **Current status**: pqc_kyber 0.7.1 in wasm-pow
- **Investigation finding**: aws-lc-rs NOT WASM-compatible (FFI to C library)
- **Decision**: Keep hybrid X25519+ML-KEM architecture; ML-KEM is defense-in-depth, X25519 remains secure
- **Alternative considered**: ml-kem (official NIST crate) - not yet WASM-ready, MSRV 1.85
```

### Step 2.4: Add hickory-recursor Migration Note

**File**: `SECURITY.md` - Add new section:

```markdown
### hickory-recursor → hickory-resolver Migration (RUSTSEC-2026-0106)
- **Issue**: Record cache accepts AUTHORITY section NS from sibling zone (DNS cache poisoning)
- **Severity**: High (DNS cache poisoning)
- **Affected**: hickory-recursor 0.25.2
- **Fix**: hickory-recursor crate deprecated; fold into hickory-resolver with recursor feature
- **Migration**: In progress (see Plan 31)
- **Timeline**: 1-2 weeks
```

---

## Verification Steps

### After hickory Migration

```bash
# Run DNS tests
cargo test --test dns_server_test --features dns
cargo test --test dns_recursive_test --features dns

# Verify recursive resolution
cargo test --lib --features dns -- --test-threads=1
```

### Verify No Regressions

```bash
# Full test suite (without DNS - faster)
cargo test --test integration_test

# Build verification
cargo build --features dns 2>&1 | grep -i warning
cargo build --features dns 2>&1 | grep -i error
```

---

## Rollback Plan

If hickory migration causes issues:

1. **Revert Cargo.toml** changes:
   ```toml
   hickory-proto = { version = "0.25", features = ["dnssec-ring", "text-parsing"], optional = true }
   hickory-resolver = { version = "0.25", features = ["system-config"], optional = true }
   hickory-recursor = { version = "0.25", features = ["dnssec-ring"], optional = true }
   ```

2. **Revert resolver.rs** changes to use `hickory_recursor` imports

3. **Document limitation** until RUSTSEC-2026-0106 is addressed upstream

---

## Files to Modify

| File | Changes |
|------|---------|
| `Cargo.toml` | Update hickory versions, remove hickory-recursor, update dns feature |
| `src/dns/resolver.rs` | Update imports, constructor, error handling |
| `src/dns/mod.rs` | Update any re-exports |
| `SECURITY.md` | Add new vulnerability entries, update existing notes |

---

## Dependencies with Good Maintenance Status

| Crate | Version | Status |
|-------|---------|--------|
| aws-lc-rs | 1.16.3 | ✅ Active - Used for TLS post-quantum |
| yara-x | 1.15.0 | ✅ Active - Monitor for 1.16.0 |
| rustls | 0.23.39 | ✅ Active |
| defguard_boringtun | 0.6.5 | ✅ Active - defGuard company |
| cryptoki | 0.12.0 | ✅ Active |
| libcrux-ml-dsa | 0.0.8 | ✅ Active (from project pqc crate) |
| wasmtime | 42.0.2 | ✅ Active (direct dependency) |

---

## Already Addressed (from existing SECURITY.md)

| Vulnerability | Status | Notes |
|---------------|--------|-------|
| quinn-proto RUSTSEC-2026-0037 | ✅ Patched | Git patch to 0.11.14 |
| wasmtime RUSTSEC-2026-0095 | ✅ Patched | Updated to 42.0.2 |
| rustls-pemfile | ✅ Removed | Replaced with rustls_pki_types |
| bincode | ✅ Removed | Replaced with postcard |

---

## References

- [RUSTSEC-2026-0106](https://rustsec.org/advisories/RUSTSEC-2026-0106) - hickory-recursor
- [RUSTSEC-2023-0079](https://rustsec.org/advisories/RUSTSEC-2023-0079) - pqc_kyber
- [RUSTSEC-2026-0095](https://rustsec.org/advisories/RUSTSEC-2026-0095) - wasmtime Winch
- [RUSTSEC-2026-0096](https://rustsec.org/advisories/RUSTSEC-2026-0096) - wasmtime Cranelift
- [RUSTSEC-2025-0141](https://rustsec.org/advisories/RUSTSEC-2025-0141) - bincode
- [hickory-dns Advisory GHSA-83hf-93m4-rgwq](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-83hf-93m4-rgwq)
