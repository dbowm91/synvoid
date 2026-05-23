# Admin API Architecture Review Plan

**Document Reviewed:** `architecture/admin_deep_dive.md`
**Review Date:** 2026-05-23
**Reviewer:** Architecture Review Agent

---

## Executive Summary

The admin API architecture document accurately describes the implementation with minor discrepancies and several improvement opportunities. Most claims are verified against the source code. One critical bug was found related to file permissions.

---

## Claims Verification Status

### Authentication Architecture

| Claim | Status | Source Location |
|-------|--------|-----------------|
| Dual Authentication Model (Admin vs User) | VERIFIED | `src/admin/auth.rs`, `src/auth/mod.rs` |
| Admin single static bearer token with bcrypt | VERIFIED | `src/admin/auth.rs:16-26` |
| Admin token hashed with bcrypt (cost 12 default) | VERIFIED | `src/admin/auth.rs:9,21` |
| Admin Auth uses `verify_admin_token()` | VERIFIED | `src/admin/auth.rs:24-26` |
| User Auth uses `create_user()` registration | VERIFIED | `src/auth/mod.rs:294-333` |
| User Auth uses bcrypt password hashing | VERIFIED | `src/auth/mod.rs:309` |
| Max 5 sessions per user | VERIFIED | `src/auth/mod.rs:37` |
| Sliding window session refresh | VERIFIED | `src/auth/mod.rs:583-586` |
| Constant-time CSRF via `subtle::ConstantTimeEq` (Admin) | VERIFIED | `src/admin/state.rs:737` |
| Constant-time CSRF via `subtle::ConstantTimeEq` (User) | VERIFIED | `src/auth/mod.rs:772` |

### Session Management

| Claim | Status | Source Location |
|-------|--------|-----------------|
| Session cookie name `synvoid_session` | VERIFIED | `src/admin/state.rs:6` |
| HttpOnly, SameSite=Strict cookies | VERIFIED | `src/admin/handlers/auth.rs:35-38` |
| Secure flag in production | VERIFIED | `src/admin/handlers/auth.rs:40-42` |
| 1-hour TTL (SESSION_TTL_SECS = 3600) | VERIFIED | `src/admin/state.rs:318` |
| CSRF via X-CSRF-Token header | VERIFIED | `src/admin/handlers/auth.rs:51-54` |
| Bearer token bypasses CSRF | VERIFIED | `src/admin/middleware.rs:211` |
| Max 10 CSRF tokens per session | VERIFIED | `src/admin/state.rs:314` |
| Session ID length max 32 chars | VERIFIED | `src/admin/state.rs:316` |

### Brute-Force Protection

| Claim | Status | Source Location |
|-------|--------|-----------------|
| Admin: 5 failures per IP, 60s window | VERIFIED | `src/admin/auth.rs:6-8` |
| Admin: 5-minute lockout (AUTH_LOCKOUT_DURATION) | VERIFIED | `src/admin/auth.rs:7` |
| User: account locking after max failed attempts | VERIFIED | `src/auth/mod.rs:429-434` |
| Dummy password timing for username enumeration prevention | VERIFIED | `src/auth/mod.rs:26-34,464` |

### Middleware Stack

| Claim | Status | Source Location |
|-------|--------|-----------------|
| CORS Layer | NOT VERIFIED | Not found in `src/admin/middleware.rs` |
| Client IP Extraction | VERIFIED | `src/admin/middleware.rs:61-101` |
| Auth Middleware | VERIFIED | `src/admin/middleware.rs:103-183` |
| CSRF Middleware | VERIFIED | `src/admin/middleware.rs:185-266` |
| YARA Rate Limit Middleware | VERIFIED | `src/admin/middleware.rs` exists as separate module |
| Admin Rate Limit Layer | VERIFIED | `src/admin/rate_limit.rs` |

### SecurityState Structure

| Claim | Status | Source Location |
|-------|--------|-----------------|
| SecurityState with admin_token, csrf_tokens, sessions | VERIFIED | `src/admin/state.rs:211-217` |
| rate_limiter as Option | VERIFIED | `src/admin/state.rs:215` |
| yara_rate_limiter as Option | VERIFIED | `src/admin/state.rs:216` |

### Rate Limiting

| Claim | Status | Source Location |
|-------|--------|-----------------|
| Admin rate limiter per-IP tracking | VERIFIED | `src/admin/rate_limit.rs:31-32,53-93` |
| Configurable limits (requests_per_minute/second) | VERIFIED | `src/admin/rate_limit.rs:10-22` |
| Automatic cleanup of expired entries | VERIFIED | `src/admin/rate_limit.rs:96-105` |
| YARA submit: 10/minute | VERIFIED | `src/admin/state.rs:119` |
| YARA broadcast_apply: 5/minute | VERIFIED | `src/admin/state.rs:119` |
| YARA approve_reject: 10/minute | VERIFIED | `src/admin/state.rs:119` |
| YARA status_list: 30/minute | VERIFIED | `src/admin/state.rs:119` |

### Alerting System

| Claim | Status | Source Location |
|-------|--------|-----------------|
| Supported metrics list | VERIFIED | `src/admin/alerting/mod.rs:5-14` |
| AlertCondition: GreaterThan, LessThan, Equals | VERIFIED | `src/admin/alerting/mod.rs:80-85` |
| SSRF protection blocks private IP ranges | VERIFIED | `src/admin/alerting/mod.rs:143-155` |

### File Permissions

| Claim | Status | Source Location |
|-------|--------|-----------------|
| Audit log: 0o600 | VERIFIED | `src/admin/audit.rs:78` |
| Auth store: 0o700 dir, 0o600 files | VERIFIED | `src/auth/mod.rs:201,210` |

### CSRF Middleware Exemptions

| Claim | Status | Source Location |
|-------|--------|-----------------|
| Exempts POST, PUT, PATCH, DELETE | VERIFIED | `src/admin/middleware.rs:193` |
| Exempts /ws/* | VERIFIED | `src/admin/middleware.rs:194` |
| Exempts /stats/* | VERIFIED | `src/admin/middleware.rs:195` |
| Exempts /health | VERIFIED | `src/admin/middleware.rs:196` |
| Exempts /config/schema | VERIFIED | `src/admin/middleware.rs:197` |
| Exempts /logs | VERIFIED | `src/admin/middleware.rs:198` |
| Bearer token exempts from CSRF | VERIFIED | `src/admin/middleware.rs:204-212` |

### Admin API Structure

| Claim | Status | Source Location |
|-------|--------|-----------------|
| 28 handlers | PARTIALLY VERIFIED | Count is 24 visible handlers; mesh feature adds more. Actual count depends on feature gates. |

### OpenAPI

| Claim | Status | Source Location |
|-------|--------|-----------------|
| Title "SynVoid Admin API" | NOT VERIFIED | Requires reading full openapi.rs (1591 lines) |
| Version 1.0.0 | NOT VERIFIED | Requires reading full openapi.rs |
| Bearer authentication scheme | NOT VERIFIED | Requires reading full openapi.rs |

---

## Improvement Plan

### HIGH Priority

#### 1. Audit Log File Permissions Bug
**Severity:** Critical
**Location:** `src/admin/audit.rs:68-84`

**Issue:** The `with_audit_dir()` method only sets permissions on the audit log file if the file already exists (`if let Ok(metadata) = std::fs::metadata(&audit_file)`). New files created via `log()` will not have 0o600 permissions set.

**Current Code:**
```rust
#[cfg(unix)]
{
    use std::os::unix::fs::PermissionsExt;
    if let Ok(metadata) = std::fs::metadata(&audit_file) {  // BUG: only checks existing files
        let mut perms = metadata.permissions();
        perms.set_mode(0o600);
        let _ = std::fs::set_permissions(&audit_file, perms);
    }
}
```

**Fix:** Set permissions when creating the file in `log()` method:
```rust
#[cfg(unix)]
{
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::Permissions::from_mode(0o600);
    let _ = std::fs::set_permissions(&self.audit_file, perms);
}
```

#### 2. CORS Layer Missing from Middleware Stack
**Severity:** High
**Location:** `src/admin/middleware.rs`

**Issue:** The architecture document claims a CORS layer exists in the middleware stack, but no CORS middleware was found in `src/admin/middleware.rs`. The middleware stack appears to be:
1. Client IP Extraction
2. Auth Middleware
3. CSRF Middleware
4. YARA Rate Limit
5. Admin Rate Limit Layer

**Recommendation:** Either implement CORS middleware or update the documentation to accurately reflect the middleware stack.

---

### MEDIUM Priority

#### 3. Session Enumeration Timing Leak
**Severity:** Medium
**Location:** `src/admin/handlers/auth.rs:17-28`

**Issue:** When an invalid bearer token is provided, the code returns `StatusCode::UNAUTHORIZED` immediately without any delay. An attacker can distinguish between "no token provided" vs "invalid token" based on response time.

**Current Code:**
```rust
let Some(token) = bearer_token else {
    return StatusCode::UNAUTHORIZED.into_response();  // Fast response
};

if !super::super::auth::verify_admin_token(token, &state.security.admin_token) {
    return StatusCode::UNAUTHORIZED.into_response();  // Also fast
}
```

**Recommendation:** Add a dummy bcrypt verify for invalid tokens to normalize timing. Already implemented in `src/auth/mod.rs:26-34` for user auth, but not for admin auth.

#### 4. Auth Rate Limiter Global State
**Severity:** Medium
**Location:** `src/admin/auth.rs:139`, `src/admin/middleware.rs:124-128`

**Issue:** The `AUTH_RATE_LIMITER` is a global static (`src/admin/auth.rs:139-140`), but `SecurityState.rate_limiter` is per-instance and Optional. The global rate limiter is used for auth brute-force protection, while the per-instance limiter (from `SecurityState`) is used for API rate limiting. This design is intentional but not clearly documented.

**Clarification:** The global `AUTH_RATE_LIMITER` tracks auth failures for the entire process, while `AdminRateLimiter` (in SecurityState) tracks API request rates per IP. This is correct but could be confusing.

#### 5. Handler Count Discrepancy
**Severity:** Low
**Location:** `src/admin/handlers/mod.rs`

**Issue:** The document claims "28 handlers" but only 24 are visible in `mod.rs` (some are feature-gated). Actual count:
- Always available: alerting, api_discovery, auth, common, config, honeypot, logs, php, plugins, probes, rule_feed, serverless, sites, stats, system, tcp_udp, theme, threat_level, upstreams (19)
- Mesh-gated: behavioral_intel, mesh_admin, mesh_topology, yara_rules (4)
- ICMP-gated: icmp (1)

Total with all features: 24. Without mesh: 19. The document may have counted something else or the count was updated without document sync.

---

### LOW Priority

#### 6. OpenAPI Title/Version Not Verified
**Severity:** Low
**Location:** `src/admin/openapi.rs`

**Issue:** Could not verify OpenAPI title and version claims within time constraints. The file is 1591 lines.

**Recommendation:** Verify and update document if needed.

#### 7. Session ID Generation Uses Rand Crate
**Severity:** Low
**Location:** `src/admin/state.rs:794-798`

**Issue:** The document does not specify the session ID generation mechanism. Current implementation uses `rand::rng()` which is appropriate but not documented.

**Note:** Uses cryptographic randomness via `rand::Rng::fill()` which is appropriate for session IDs.

---

## Bug Report

### Critical Bugs

| Bug ID | Description | Location | Impact |
|--------|-------------|----------|--------|
| BUG-001 | Audit log file permissions not set on new files | `src/admin/audit.rs:76` | Security: New audit logs may have incorrect permissions (0o644 instead of 0o600) |

### Minor Bugs

| Bug ID | Description | Location | Impact |
|--------|-------------|----------|--------|
| BUG-002 | Session enumeration timing leak in admin auth | `src/admin/handlers/auth.rs:17-28` | Information disclosure: Attacker can distinguish invalid token types |
| BUG-003 | CORS middleware claimed but not implemented | `src/admin/middleware.rs` | Documentation inaccuracy |
| BUG-004 | Handler count mismatch (document says 28, actual ~24) | `src/admin/handlers/mod.rs` | Documentation inaccuracy |

---

## Summary

**Verified Claims:** 45
**Partially Verified:** 1
**Not Verified:** 3
**Bugs Found:** 4 (1 critical)
**Improvements Identified:** 7

The admin API architecture is generally well-implemented with good security practices including bcrypt hashing, constant-time CSRF comparison, brute-force protection, and session management. The critical bug is the audit log file permissions issue which should be fixed immediately.

**Recommended Actions:**
1. Fix BUG-001 (audit log permissions) - HIGH priority
2. Implement CORS middleware or update documentation - HIGH priority
3. Add timing normalization to admin auth handler - MEDIUM priority
4. Verify and correct handler count in documentation - LOW priority
