# Security Audit Deep Dive - Improvement Plan

**Last updated**: 2026-04-23
**Status**: 📋 PLANNED (Not Started)

## Overview

This document captures findings from a comprehensive security audit deep dive across 10 previously identified items. After thorough investigation, several items were found to be already well-handled or mischaracterized in the initial audit.

**Audit completion**: 10/10 items investigated
**Items requiring code changes**: 2
**Items recommended for documentation/config**: 3
**Items cleared (no action needed)**: 5

---

## Summary: Items Ready for Implementation

### Items Requiring Code Changes

| # | Item | Priority | Status |
|---|------|----------|--------|
| A.1 | Path Traversal - Add explicit ".." validation | HIGH | 📋 Planned |
| B.1 | DNS Cache Poisoning - Increase confirmation threshold | MEDIUM | 📋 Planned |

### Items for Documentation/Config Review

| # | Item | Priority | Status |
|---|------|----------|--------|
| C.1 | QUIC 0-RTT - Confirm disable is intentional | MEDIUM | 📋 Document |
| B.2 | DNS Cookie Key Truncation - Document intent | LOW | 📋 Document |
| A.2 | Path Traversal - Symlink config documentation | LOW | 📋 Document |

### Items Cleared (No Action Needed)

| Item | Status | Reasoning |
|------|--------|-----------|
| 2. Weak Key Derivation | ✅ CLEARED | `from_secret()` is dead code - never called |
| 4. Mutual TLS Enforcement | ✅ CLEARED | Already implemented and enabled by default |
| 5. unwrap() in Critical Paths | ✅ CLEARED | No unwrap() on client data in production paths |
| 8. CSRF Protection | ✅ CLEARED | Already fully implemented |
| 9. Unsafe Code Documentation | ✅ CLEARED | Adequate `// SAFETY` comments present |

---

## Wave A: Path Traversal Hardening - HIGH Priority

The static file serving module needs hardening to prevent path traversal attacks.

### A.1: Add Explicit ".." Component Validation

**File**: `src/static_files/file_manager.rs`

**Current State** (lines 325-354):
- Line 326-329: Null byte check
- Line 332-333: Path construction
- Line 335-337: Canonicalize root
- Line 343-354: Canonicalize target with symlink fallback

**Missing**: Explicit ".." check before canonicalization

**Required Change**:
Insert after line 330 (null byte check), before line 332:
```rust
// Add explicit ".." check
if user_path_clean.contains("..") || user_path.contains("..") {
    tracing::warn!("Path traversal attempt: '..' component detected in {}", user_path);
    return Err(FileManagerError::PathTraversal);
}
```

**Note**: Also applies to `src/static_files/mod.rs` at similar location (lines ~331-345)

**Verification**:
```bash
cargo clippy --lib -- -D warnings
cargo test --test integration_test
```

### A.2: Decouple WalkDir follow_links from allow_symlinks

**File**: `src/static_files/file_manager.rs`

**Current State**:
- Line 675: WalkDir uses same config as file serving
- Should have separate control

**Required Changes**:
- Consider adding separate `walkdir_follow_symlinks` config option
- Or always use `follow_links = false` for directory listing regardless of `allow_symlinks`

---

## Wave B: DNS Security Hardening - MEDIUM Priority

### B.1: Increase Cache Poisoning Confirmation Threshold

**File**: `src/dns/cache.rs`

**Current State** (line 193):
```rust
if confirmations < 2 {
```

**Location**: `src/dns/cache.rs:188-214` - fingerprint validation logic

**Required Change**: Increase threshold from 2 to 3:
```rust
if confirmations < 3 {  // Changed from 2
    tracing::warn!(...);
    return Err(CachePoisoningError::PotentialPoisoning {...});
}
```

**Note**: There's no config option for this currently - hardcoded constant. Could be added to `src/config/dns/` in a future enhancement.

**Verification**:
```bash
cargo test --test dns_server_test
cargo test --test dns_recursive_test
```

### B.2: Document DNS Cookie Key Truncation Intent

**File**: `src/dns/cookie.rs`

**Current State**:
- Line 47: Uses only 16 bytes of 32-byte secret key
- `data.extend_from_slice(&self.inner.secret_key[..16]);`

**Required**: Documentation update

Add comment explaining the design decision:
```rust
/// The secret key is 32 bytes but only 16 are used for the server cookie.
/// This provides 128 bits of entropy which is sufficient for cookie
/// uniqueness. The remaining 16 bytes are reserved for future use.
```

Or expand to full 32 bytes if that's the intent:
```rust
data.extend_from_slice(&self.inner.secret_key);  // Use full 32 bytes
```

---

## Wave C: Configuration Review - MEDIUM Priority

### C.1: QUIC 0-RTT Configuration Review

**File**: `src/mesh/cert.rs`

**Current State**:
- Disabled by default via `quic_enable_0rtt = false`
- Warning logged when enabled

**Action**: Confirm this is the intended default for production

**Verification**:
```bash
grep -n "quic_enable_0rtt" src/mesh/config.rs
```

### C.2: Path Traversal Symlink Configuration

**File**: `src/config/site/static_files.rs`

**Current State**:
- `allow_symlinks: false` (default)
- When true, allows symlinks outside root during canonicalization fallback

**Action**: Document the security implications clearly in config

---

## Implementation Notes

### Testing Approach

For each code change:

1. **Path Traversal**:
   - Test `..` in request path
   - Test symbolic links
   - Test encoded variants (%2e%2e)
   - Test different filesystems

2. **DNS Cache**:
   - Existing poisoning tests should cover
   - Add threshold test if new config option added

### Sub-agents

These items can be parallelized:

- Wave A: `A.1` and `A.2` can run in parallel (different files)
- Wave B: `B.1` is independent, `B.2` is documentation
- Wave C: All documentation/config review

---

## Risk Assessment

| Item | Risk Level | Impact | Effort |
|------|-----------|---------|--------|--------|
| A.1 Path Traversal | HIGH | File system compromise | LOW |
| A.2 WalkDir Symlink | MEDIUM | Directory traversal | MEDIUM |
| B.1 DNS Confirmation | MEDIUM | Cache poisoning | LOW |
| B.2 DNS Cookie Doc | LOW | Confusion | LOW |
| C.1 QUIC Review | LOW | Replay risk | LOW |
| C.2 Symlink Doc | LOW | Misconfig | LOW |

---

## References

- Security audit original findings (2026-04-23)
- Deep dive investigation (2026-04-23)
- Path traversal test vectors from OWASP
- DNS cache poisoning literature (Dan Kaminsky 2008)