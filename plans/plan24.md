# MaluWAF Security Improvement Plan

**Plan ID**: 24
**Date**: 2026-04-23
**Status**: Draft
**Priority**: High (Security)
**Target**: Address all findings from security audit deep dive

---

## Executive Summary

This plan addresses 8 security issues identified in a comprehensive security audit with deep-dive analysis. Issues are categorized by severity with concrete code changes and estimated effort.

### Summary Table

| Priority | Count | Items |
|----------|-------|-------|
| CRITICAL | 2 | Stored XSS in directory listing, RSA 1024 in DNSSEC key gen |
| HIGH | 2 | SHA-1 deprecation (RFC 9905), QUIC DoS (RUSTSEC-2026-0037) |
| MEDIUM | 3 | IPC key fallback risk, CGI no sandboxing, Unsafe code FD leaks |
| LOW | 1 | Rule feed placeholder warning-only |

---

## Security Issues Inventory

### CRITICAL Priority

#### Issue C1: Stored XSS in Directory Listing

**Severity**: HIGH (Stored Cross-Site Scripting)
**CVSS Estimate**: 6.1-7.5 (Medium-High)
**Location**:
- `src/static_files/directory.rs:120-127`
- `src/theme/dir_listing.rs:509-520`
- `src/static_files/file_manager.rs:758-762` (upload sanitization)

**Problem**: User-controlled filenames are rendered in HTML without output encoding. An attacker can upload a file with a malicious filename containing JavaScript (e.g., `<img src=x onerror=alert(1)>.txt`) which will execute in the browser when viewing directory listings.

**Attack Vector**:
1. Attacker uploads file with malicious filename via `FileManager::upload_file()` or WebDAV
2. FileManager sanitization only strips `/`, `\`, `\0`, `..` — does NOT sanitize HTML special chars
3. Directory listing renders `entry.name` directly into HTML template
4. Victim views directory listing → JavaScript executes

**Current Behavior**:
```rust
// directory.rs:120-127 - NO escaping applied
format!(
    r#"<tr>
        <td><a href="{}">{} {}</a></td>
        <td>{}</td>
        <td class="size">{}</td>
    </tr>"#,
    entry.href, icon, entry.name, entry.modified, entry.size  // entry.name NOT ESCAPED
)
```

**Available Escape Function**: `src/waf/endpoints.rs:248-254` has `escape_html()` but is NOT used in static files/theme code.

**Fix Plan**:
1. Import or define `escape_html()` in theme module
2. Apply escaping to `entry.name` in both `render_custom_template()` and `DirectoryListingTemplate::render()`
3. Optionally enhance FileManager upload sanitization to reject filenames with HTML chars (but this breaks legitimate filenames)

**Implementation**:
```rust
// In dir_listing.rs:509-520, change:
name = escape_html(&entry.name)

// Import escape_html from endpoints or define locally:
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}
```

**Files to modify**:
- `src/static_files/directory.rs` - Add escape_html import, apply to entry.name (~15 lines)
- `src/theme/dir_listing.rs` - Apply escape_html to entry.name (~10 lines)

**Est. lines**: ~25
**Risk**: Low (output encoding is safe, preserves filenames on disk)
**Effort**: Low (2-4 hours)

---

#### Issue C2: RSA 1024 in DNSSEC Key Generation

**Severity**: HIGH (Below NIST minimum security threshold)
**Standards**: RFC 8624, NIST SP 800-57 Rev 5
**Location**: `src/dns/dnssec_key_mgmt.rs:240-247`

**Problem**: DNSSEC key generation allows RSA 1024-bit keys, which provide only ~80-bit security — below NIST's 112-bit minimum for new U.S. government use since 2015. RFC 8624 explicitly lists RSASHA1 as "NOT RECOMMENDED" and modern DNSSEC operators use RSA 2048+ or ECDSA256SHA256.

**Current Behavior**:
```rust
// dnssec_key_mgmt.rs:240-247
if !matches!(bits, 1024 | 2048 | 4096) {
    return Err(format!("Unsupported RSA key size {}. Use 1024, 2048, or 4096.", bits));
}
```

**User Requirement**: User requested NO startup blocking. Instead, provide automatic bridge to convert 1024→2048.

**Fix Plan**:
1. Add automatic key size upgrade: if RSA 1024 is detected, automatically regenerate as RSA 2048
2. Add warning log when upgrade occurs
3. Update error message to encourage ECDSA256SHA256 for new keys
4. Add config option to enforce minimum key size (default 2048)

**Implementation**:
```rust
// In generate_dnssec_key() or key creation flow:
if bits == 1024 {
    tracing::warn!(
        "RSA 1024-bit keys are below NIST minimum security threshold (112 bits). \
         Automatically upgrading to RSA 2048-bit key. \
         Consider using ECDSAP256SHA256 for better security and performance."
    );
    bits = 2048;
}

// Update error message:
if !matches!(bits, 2048 | 4096) {
    return Err(format!("Unsupported RSA key size {}. Use 2048 or 4096 (RSA) or ECDSAP256SHA256 (recommended).", bits));
}
```

**Files to modify**:
- `src/dns/dnssec_key_mgmt.rs` - Add auto-upgrade logic (~20 lines)

**Est. lines**: ~20
**Risk**: Low (key generation upgrade, no runtime blocking)
**Effort**: Low (1-2 hours)

---

### HIGH Priority

#### Issue H1: SHA-1 Deprecation for DNSSEC (RFC 9905 - November 2025)

**Severity**: HIGH (Standards compliance and cryptographic soundness)
**References**: RFC 9905, RFC 8624, RFC 8945, NIST SP 800-131A
**Locations**:
- `src/dns/tsig.rs:8,15` - HMAC-SHA1 for TSIG
- `src/dns/dnssec_signing.rs:179,205` - RSASHA1, NSEC3 SHA-1
- `src/dns/dnssec_validation.rs:244,294` - DS digest validation

**Problem**: RFC 9905 (November 2025) formally deprecates SHA-1 for DNSSEC:
- RSASHA1 (5) and RSASHA1-NSEC3-SHA1 (7): **MUST NOT** for zone signing
- DS records with SHA-1 digest: **MUST NOT** for new delegations
- HMAC-SHA1 for TSIG: NOT RECOMMENDED, HMAC-SHA256 is RECOMMENDED

**Current State**:
- TSIG HMAC-SHA1: Still used (RFC 2845 → RFC 8945 still mandates implementation but NOT RECOMMENDED)
- DS Digest SHA-1: Allowed for validation, MUST NOT for new delegations
- RSASHA1 signing: Still accepted for validation

**Fix Plan**:

**Phase H1a: TSIG HMAC-SHA-256 Support** (8-16 hours)
1. Add `HmacSha256` to TSIG algorithm enum in `src/dns/tsig.rs`
2. Update `sign_tsig()` and `verify_tsig()` to support HMAC-SHA-256
3. Make HMAC-SHA-256 the default for new TSIG keys
4. Keep HMAC-SHA-1 for backward compatibility with legacy servers

**Phase H1b: DS Digest SHA-256 Default** (4-8 hours)
1. Change default DS digest algorithm to SHA-256
2. Add warning when SHA-1 DS is configured
3. Ensure SHA-256 DS records are created alongside any SHA-1 DS

**Phase H1c: DNSKEY Signing Algorithm Migration** (8-16 hours)
1. Update key generation to default to ECDSAP256SHA256
2. Add validation warning for RSASHA1 keys
3. Update documentation with migration path

**Implementation Details**:

TSIG Algorithm Addition:
```rust
// src/dns/tsig.rs
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum TsigAlgorithm {
    HmacSha1 = 5,      // NOT RECOMMENDED - keep for legacy
    HmacSha256 = 16,   // RECOMMENDED - new default
    HmacSha384 = 18,
    HmacSha512 = 20,
}

impl TsigAlgorithm {
    pub fn default() -> Self {
        TsigAlgorithm::HmacSha256
    }

    pub fn is_recommended(&self) -> bool {
        matches!(self, TsigAlgorithm::HmacSha256 | TsigAlgorithm::HmacSha384 | TsigAlgorithm::HmacSha512)
    }
}
```

DS Digest Migration:
```rust
// In DS record creation, change default:
pub fn create_ds_record(...) -> RResult<Record> {
    // Use SHA-256 by default
    let digest = compute_ds_digest(key_tag, key, DigestType::SHA256);
    // Optionally also include SHA-1 for backward compat, but warn
}
```

**Files to modify**:
- `src/dns/tsig.rs` - Add HMAC-SHA-256 support (~80 lines)
- `src/dns/dnssec_signing.rs` - Update defaults (~20 lines)
- `src/dns/dnssec_validation.rs` - Add SHA-1 warnings (~10 lines)
- `src/dns/dnssec_key_mgmt.rs` - Default to ECDSA256SHA256 (~20 lines)
- `src/config/dns/` - Add migration warnings config (~10 lines)

**Est. lines**: ~140
**Risk**: Medium (TSIG interop, DS digest compatibility)
**Effort**: Medium (16-32 hours total across phases)

---

#### Issue H2: QUIC DoS Vulnerability (RUSTSEC-2026-0037)

**Severity**: HIGH (DoS via malformed transport parameters)
**CVE**: CVE-2026-31812
**CVSS**: 8.7 HIGH
**Patch Status**: ✅ APPLIED — `quinn-proto-0.11.14` via git tag in Cargo.toml

**Problem**: Quinn-proto had a panic (DoS) when parsing QUIC transport parameters with invalid values. An unauthenticated remote attacker could crash QUIC endpoints by sending malformed parameters.

**Current State**: Already patched via git tag:
```toml
# Cargo.toml:36-38
[patch."https://github.com/quinn-rs/quinn"]
quinn-proto = { git = "https://github.com/quinn-rs/quinn", tag = "quinn-proto-0.11.14" }
```

**Action Items** (Monitoring):
1. Track when quinn 0.11.10+ is officially released with integrated fix
2. Remove git patch when official release available (see TODO in Cargo.toml)
3. Consider adding rate-limiting on QUIC transport parameter parsing

**Files to check**:
- `Cargo.toml` - Monitor for official quinn release
- `src/mesh/transport.rs` - QUIC transport usage

**Est. lines**: 0 (monitoring only)
**Risk**: Already mitigated
**Effort**: Low (monitoring)

---

### MEDIUM Priority

#### Issue M1: IPC Key Fallback Security

**Severity**: MEDIUM (Information disclosure in multi-tenant environments)
**Locations**:
- `src/process/manager.rs:365` - Fallback env var
- `src/process/ipc_signed.rs:159` - Key reading
- `src/config/security.rs:25` - `allow_insecure_ipc_key` config

**Current Protection**:
- ✅ Temp file preferred (0600 permissions, deleted after use)
- ✅ Fallback disabled by default (`allow_insecure_ipc_key = false`)
- ✅ Warning logged when fallback triggers

**Problem**: If `allow_insecure_ipc_key = true` and temp file creation fails, the IPC session key is passed as an environment variable visible via `/proc/<pid>/environ` and `ps aux`. In multi-tenant/containerized environments, this allows local privilege escalation.

**Current Behavior**:
```rust
// src/process/manager.rs:356-376
if let Some(ref key) = self.config.ipc_session_key {
    let key_hex = ...;
    match self.write_ipc_key_to_tempfile(&key_hex) {
        Ok(path) => {
            cmd.env("MALUWAF_IPC_KEY_FILE", path);  // Secure
        }
        Err(e) => {
            if self.config.allow_insecure_ipc_key {
                tracing::warn!(...);  // Only WARN, no error!
                cmd.env("MALUWAF_IPC_KEY", key_hex);  // INSECURE
            } else {
                panic!(...);  // Blocks startup — good
            }
        }
    }
}
```

**Fix Plan**:
1. Change fallback warning to `tracing::error!` in production (when `cfg!(not(debug_assertions))`)
2. Add metrics counter for fallback occurrences
3. Add documentation that `allow_insecure_ipc_key = true` is unsafe for multi-tenant deployments
4. Consider adding startup check that verifies temp file creation works

**Implementation**:
```rust
// src/process/manager.rs - Change warn to error in production:
if self.config.allow_insecure_ipc_key {
    if cfg!(not(debug_assertions)) {
        tracing::error!(
            "CRITICAL SECURITY: IPC session key fallback to environment variable is enabled. \
             This exposes the key via /proc/<pid>/environ. \
             Fix: Ensure temp file creation succeeds or disable allow_insecure_ipc_key."
        );
    } else {
        tracing::warn!(...);
    }
    cmd.env("MALUWAF_IPC_KEY", key_hex);
}
```

**Files to modify**:
- `src/process/manager.rs` - Change to error-level logging (~10 lines)

**Est. lines**: ~10
**Risk**: Low (logging change only)
**Effort**: Low (2-4 hours)

---

#### Issue M2: CGI Script Execution - No Process Sandboxing

**Severity**: MEDIUM (Privilege escalation if CGI is compromised)
**Location**: `src/cgi/mod.rs:328`

**Current Protections**:
- ✅ `sanitize_cgi_path()` removes `..` components
- ✅ Canonical path prefix check prevents traversal
- ✅ Extension allowlist (cgi, pl, py, sh, rb, php, lua, exe)
- ✅ Executable permission check
- ✅ `env_clear()` — only controlled env vars passed

**Missing**:
- ❌ No chroot/jail
- ❌ No seccomp/Landlock restriction
- ❌ No namespace isolation
- ❌ No resource limits (memory, CPU, fd)

**User Requirement**: Documentation sufficient.

**Action Items**:
1. Add security documentation in code comments explaining CGI runs with worker privileges
2. Document recommended deployment patterns (separate worker pools for CGI)
3. Consider adding Landlock sandboxing in future (out of scope for this plan)

**Files to document**:
- `src/cgi/mod.rs` - Add security documentation comments (~20 lines)

**Est. lines**: ~20 (documentation only)
**Risk**: N/A (no code change)
**Effort**: Low (2 hours)

---

#### Issue M3: Unsafe Code - FD/Ruleset Leaks on Error Paths

**Severity**: MEDIUM (Resource leaks, not memory safety issues)
**Locations**:
- `src/platform/sandbox.rs:324-326` - ruleset_fd leak if restrict_self() fails
- `src/process/ipc.rs:1442-1444` - CloseHandle result unchecked on Windows

**Problems Found**:

1. **Landlock ruleset_fd leak**:
```rust
// sandbox.rs:322-326
let ruleset_fd = create_landlock_ruleset(...)?;
if let Err(e) = restrict_self(ruleset_fd) {
    return Err(e);  // ruleset_fd LEAKED here!
}
close(ruleset_fd)?;  // Only reached on success
```

2. **Windows CloseHandle unchecked**:
```rust
// ipc.rs:1442-1444
if result == 0 {
    CloseHandle(handle);  // Result unchecked
    return Err(...);
}
```

**Fix Plan**:
```rust
// In sandbox.rs, change apply() to:
if let Err(e) = restrict_self(ruleset_fd) {
    let _ = close(ruleset_fd);  // Clean up on error
    return Err(e);
}
```

```rust
// In ipc.rs, check CloseHandle result:
if result == 0 {
    let close_result = CloseHandle(handle);
    if close_result == 0 {
        tracing::error!("Failed to close handle on error path: {}", GetLastError());
    }
    return Err(...);
}
```

**Files to modify**:
- `src/platform/sandbox.rs` - Fix ruleset_fd leak (~5 lines)
- `src/process/ipc.rs` - Check CloseHandle result (~5 lines)

**Est. lines**: ~10
**Risk**: Low (resource cleanup improvement)
**Effort**: Low (1-2 hours)

---

### LOW Priority

#### Issue L1: Rule Feed Placeholder - Warning Only, No Startup Blocking

**Severity**: LOW (Denial of feature, not bypass)
**Location**: `src/waf/rule_feed.rs:322-348`

**Current Behavior**:
1. Warning logged at startup: "Rule feed public key is still set to the placeholder value..."
2. Random key generated
3. Rule feed signature verification is non-functional
4. System operates on bundled/internal rules only

**Comparison to Admin Token**:
- Admin `changeme` token: Blocked in release builds (`#[cfg(not(debug_assertions))]`)
- Rule feed placeholder: Warning only — no blocking

**Fix Plan** (Optional):
1. Add `#[cfg(debug_assertions)]` blocking similar to admin token
2. Or add `rule_feed.enforce_valid_key: bool` config option
3. Add metrics counter for "rule_feed_signature_failures"

**Implementation** (if desired):
```rust
// In rule_feed.rs startup validation:
if key_str == PLACEHOLDER_KEY {
    if cfg!(not(debug_assertions)) {
        return Err(anyhow::anyhow!(
            "Rule feed public key is set to placeholder value. \
             Set [waf.rule_feed.public_key] in TOML config to a valid key. \
             Startup blocked in release builds."
        ));
    }
    tracing::warn!(...);
}
```

**Files to modify** (optional):
- `src/waf/rule_feed.rs` - Add startup blocking in release (~15 lines)
- `src/config/waf.rs` - Add `enforce_valid_key` option (~5 lines)

**Est. lines**: ~20 (optional)
**Risk**: Low (configurable behavior)
**Effort**: Low (2 hours)

---

### Dependency Vulnerability Monitoring

#### D1: Wasmtime RUSTSEC-2026-0096 / CVE-2026-34971

**Severity**: CRITICAL (but aarch64-specific, mitigated in x86_64 deployments)
**CVSS**: 9.0 CRITICAL
**Affected**: Wasmtime 32.0.0-36.0.6, 37.0.0-42.0.1, 43.0.0
**Patched**: >= 36.0.7, >= 42.0.2, >= 43.0.1
**Patch Status**: ✅ APPLIED — `tag = "v42.0.2"` from bytecodealliance/wasmtime

**Action**: Monitor for official crates.io release. Currently using git tag.

---

#### D2: Wasmtime RUSTSEC-2026-0086 / CVE-2026-34945

**Severity**: LOW (information disclosure, Winch-specific)
**CVSS**: 2.3 LOW
**Affected**: Wasmtime 25.0.0-36.0.6, 37.0.0-42.0.1, 43.0.0
**Patched**: >= 36.0.7, >= 42.0.2, >= 43.0.1
**Patch Status**: ✅ APPLIED — Same patch as D1

**Action**: Monitor for official crates.io release.

---

## Implementation Phases

### Phase 1: Critical Security Fixes (Low Risk, High Impact)

| Issue | Lines | Risk | Benefit |
|-------|-------|------|---------|
| C1: Stored XSS | ~25 | Low | Eliminate stored XSS attack vector |
| C2: RSA 1024→2048 | ~20 | Low | Automatic upgrade to NIST minimum |
| M3: FD leaks | ~10 | Low | Prevent resource leaks |
| **Subtotal** | **~55** | **Low** | **High security improvement** |

### Phase 2: Standards Compliance (Medium Risk)

| Issue | Lines | Risk | Benefit |
|-------|-------|------|---------|
| H1a: TSIG SHA-256 | ~80 | Medium | RFC 8945 compliance |
| H1b: DS SHA-256 | ~30 | Medium | RFC 9905 compliance |
| H1c: ECDSA default | ~40 | Medium | Modern crypto adoption |
| **Subtotal** | **~150** | **Medium** | **Standards compliance** |

### Phase 3: Hardening & Documentation (Low Risk)

| Issue | Lines | Risk | Benefit |
|-------|-------|------|---------|
| M1: IPC fallback error | ~10 | Low | Better logging in production |
| M2: CGI docs | ~20 | None | Security documentation |
| L1: Rule feed blocking | ~20 | Low | Consistent with admin token |
| **Subtotal** | **~50** | **Low** | **Hardening** |

### Phase 4: Dependency Monitoring (Ongoing)

| Item | Action | Effort |
|------|--------|--------|
| D1/D2: Wasmtime | Monitor for official release, remove git patch | Low |
| H2: QUIC | Monitor for quinn 0.11.10+ release | Low |

---

## Total Estimated Effort

| Phase | Lines | Priority | Risk |
|-------|-------|----------|------|
| Phase 1 | ~55 | CRITICAL | Low |
| Phase 2 | ~150 | HIGH | Medium |
| Phase 3 | ~50 | MEDIUM | Low |
| Phase 4 | 0 | LOW | None |
| **Total** | **~255** | **-** | **-** |

---

## Backwards Compatibility Notes

| Issue | Compatibility Concern |
|-------|----------------------|
| C1: XSS fix | Safe — filenames unchanged on disk, only output escaped |
| C2: RSA upgrade | Safe — 1024 keys automatically upgraded, no blocking |
| H1: SHA-256 TSIG | Interoperable — SHA-1 still supported for legacy |
| H1: DS SHA-256 | Interoperable — SHA-1 DS still validated |
| M3: FD leaks | Safe — error path cleanup only |

---

## Testing Requirements

For each phase:

1. `cargo test --lib --no-run` — Verify test compilation
2. `cargo clippy --lib -- -D warnings` — Catch type errors
3. `cargo fmt` — Code formatting
4. Integration tests for changed paths

**Security validation**:
- XSS: Upload file with `<script>` in name, verify directory listing escapes
- RSA: Generate 1024 key, verify auto-upgrade to 2048
- TSIG: Test HMAC-SHA-256 signing and verification
- IPC: Verify error-level log appears in production when fallback triggers

---

## Risk Assessment Summary

| Risk Level | Issues | Mitigation |
|------------|--------|------------|
| Low | 5 (C1, C2, M1, M3, L1) | Output encoding, auto-upgrade, logging |
| Medium | 1 (H1 - SHA-256 migration) | Interoperable with legacy |
| None | 2 (M2 docs, D1/D2 monitoring) | Documentation and monitoring |

---

## User Decisions Required

| Issue | Decision |
|-------|----------|
| **C1: XSS fix** | ✅ Approved — escape at render time |
| **C2: RSA 1024** | ✅ Approved — auto-upgrade to 2048, no startup block |
| **H1: SHA-1 deprecation** | ✅ Approved — implement all three phases |
| **M2: CGI sandboxing** | ✅ Approved — documentation only |
| **L1: Rule feed blocking** | Pending — do we want debug-build blocking? |

---

## References

- AGENTS.md: Security architecture guidelines
- `skills/dns_dnssec.md`: DNSSEC detailed architecture
- RUSTSEC-2026-0096: https://rustsec.org/advisories/RUSTSEC-2026-0096.html
- RUSTSEC-2026-0037: https://rustsec.org/advisories/RUSTSEC-2026-0037.html
- RFC 9905: Deprecating SHA-1 in DNSSEC
- RFC 8624: DNSSEC Algorithm Implementation Requirements
- RFC 8945: TSIG (Secret Key Transaction Authentication for DNS)
- NIST SP 800-57: Cryptographic Key Management

---

## Appendix: Issue Locations Quick Reference

| ID | File | Line(s) | Fix Complexity |
|----|------|---------|----------------|
| C1 | `src/static_files/directory.rs` | 120-127 | Low |
| C1 | `src/theme/dir_listing.rs` | 509-520 | Low |
| C1 | `src/static_files/file_manager.rs` | 758-762 | Low |
| C2 | `src/dns/dnssec_key_mgmt.rs` | 240-247 | Low |
| H1 | `src/dns/tsig.rs` | 8, 15 | Medium |
| H1 | `src/dns/dnssec_signing.rs` | 179, 205 | Medium |
| H1 | `src/dns/dnssec_validation.rs` | 244, 294 | Low |
| H2 | `Cargo.toml` | 36-38 | Monitoring |
| M1 | `src/process/manager.rs` | 365 | Low |
| M2 | `src/cgi/mod.rs` | 328 | Documentation |
| M3 | `src/platform/sandbox.rs` | 324-326 | Low |
| M3 | `src/process/ipc.rs` | 1442-1444 | Low |
| L1 | `src/waf/rule_feed.rs` | 322-348 | Low |

(End of file)