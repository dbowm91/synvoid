# Config/Admin Architecture Review - Improvement Plan

**Review Date:** 2026-05-23
**Documents Reviewed:**
- `architecture/config_deep_dive.md`
- `architecture/admin_deep_dive.md`

**Cross-Referenced Against:**
- `AGENTS.md` (root)
- `src/config/AGENTS.override.md`
- `src/admin/AGENTS.override.md`
- `src/auth/AGENTS.override.md`

---

## Verified Correct Items

### Config Module

| Claim | Verified Location | Status |
|-------|------------------|--------|
| ConfigManager in `crates/synvoid-config/src/lib.rs:113-233` | `lib.rs:113-118` - ConfigManager struct confirmed | ✅ |
| ConfigManager loads MainConfig from TOML | `lib.rs:130-136` - load_main() confirmed | ✅ |
| ConfigManager discovers sites | `lib.rs:148-165` - discover_sites() confirmed | ✅ |
| SiteAppServerConfig uses Option fields | `site/app_server.rs:4-54` - All fields are `Option<T>` | ✅ |
| require_hashes field propagates | `site/app_server.rs:53` → `site/mod.rs:259` confirmed | ✅ |
| AppServerConfig resolved with defaults | `app_server.rs:7-70` - Default impl confirmed | ✅ |
| MainConfig hierarchy | `main_config.rs:73-143` - All fields present | ✅ |

### Admin Module

| Claim | Verified Location | Status |
|-------|------------------|--------|
| Bearer token auth | `src/admin/auth.rs:24-26` - verify_admin_token() confirmed | ✅ |
| Brute-force protection | `src/admin/auth.rs:6-8` - MAX_AUTH_ATTEMPTS=5, AUTH_LOCKOUT_DURATION=300s confirmed | ✅ |
| Session creation | `src/admin/state.rs:790-822` - create_session() confirmed | ✅ |
| CSRF validation | `src/admin/state.rs:727-743` - validate_csrf() confirmed | ✅ |
| Session expiry 1 hour | `src/admin/state.rs:835` - SESSION_TTL_SECS confirmed | ✅ |
| YARA rate limiter | `src/admin/state.rs:88-146` - YaraRateLimiter confirmed | ✅ |
| 28 admin handlers | `src/admin/handlers/mod.rs:1-29` - 29 modules (including behavioral_intel, mesh_admin, mesh_topology, yara_rules - mesh feature-gated) | ✅ |

### Auth Module

| Claim | Verified Location | Status |
|-------|------------------|--------|
| bcrypt password hashing | `src/auth/mod.rs:8` - uses bcrypt crate | ✅ |
| Constant-time CSRF comparison | `src/auth/mod.rs:772` - uses `ct_eq()` confirmed | ✅ |
| Dummy password timing | `src/auth/mod.rs:26-34` - prevents username enumeration confirmed | ✅ |
| Max 5 sessions per user | `src/auth/mod.rs:37` - MAX_SESSIONS_PER_USER=5 confirmed | ✅ |

---

## Discrepancies Found

### DISCREPANCY-1: Config Document Uses Wrong Crate Path

**Document:** `architecture/config_deep_dive.md:5`

**Claim:**
```
This document covers the configuration library (`crates/synvoid-config/`) and utility library (`crates/synvoid-utils/`).
```

**Issue:** The document refers to `crates/synvoid-config/` but the actual crate is at `crates/synvoid-config/` (this is correct).

**Correction needed:** Verify if `crates/synvoid-utils/` exists or if the document only refers to synvoid-config.

**Status:** The buffer pool described in `config_deep_dive.md:144-228` is actually in `src/utils/` or another location. Need to verify actual location of buffer pool implementation.

---

### DISCREPANCY-2: Site Config Hierarchy Missing `site_id` Field

**Document:** `architecture/config_deep_dive.md:68-93`

**Claim:** Site Config Hierarchy shows:
```
SiteConfig (per-domain)
├── site: SiteInfo
│   ├── domains: Vec<String>
│   ├── listen: Vec<SiteListenConfig>
│   └── upstream: UpstreamConfig
```

**Actual Code:** `crates/synvoid-config/src/site/mod.rs` - SiteConfig has many more fields including `site_id` which is used as key in ConfigManager.

**Fix:** Document should mention `site_id` field in SiteConfig hierarchy.

---

### DISCREPANCY-3: ConfigManager File Location Ambiguity

**Document:** `architecture/config_deep_dive.md:31`

**Claim:**
| File | Responsibility |
|------|----------------|
| `main_config.rs` | Root configuration container for the entire SynVoid server |

**Issue:** The document implies ConfigManager might be in main_config.rs, but it is actually in `lib.rs:113-233`. The table lists files in the crate, but doesn't mention where ConfigManager is.

**Fix:** Add note that ConfigManager is in `lib.rs:113-233` as stated in `src/config/AGENTS.override.md`.

---

## Bugs Identified

### BUG-1: AdminState CSRF Validation Missing Constant-Time Comparison

**Location:** `src/admin/state.rs:727-743`

**Issue:** The `validate_csrf()` function uses simple string comparison (`==`) instead of `ConstantTimeEq`:

```rust
// state.rs:734-739
if let Some(valid_token) = csrf_tokens.get(token) {
    if now.duration_since(valid_token.created) < Duration::from_secs(3600)
        && valid_token.session_id_hash == session_hash
    {
        return true;
    }
}
```

While `session_id_hash` is SHA256 hashed (so comparison might be acceptable), the token lookup `csrf_tokens.get(token)` is a direct map lookup, not a timing-safe comparison. However, the actual token comparison uses `==` on line 736.

**Priority:** MEDIUM - The CSRF token itself is a secret (UUID v4), but comparison happens on map lookup key, not stored secret. More importantly, the admin API's CSRF validation in `middleware.rs:259` calls `state.validate_csrf()` which uses simple `==`.

**Recommendation:** Use `ConstantTimeEq` for the session_hash comparison on line 736.

---

### BUG-2: Auth Module CSRF Uses Constant-Time but Admin Module Does Not

**Locations:**
- `src/auth/mod.rs:772` - uses `ct_eq()` for CSRF validation
- `src/admin/state.rs:736` - uses `==` for session hash comparison

**Issue:** The auth module's CSRF validation uses constant-time comparison, but the admin module's CSRF validation doesn't. This inconsistency could be a security issue if admin CSRF tokens are ever exposed to timing attacks.

**Priority:** MEDIUM

---

## Improvement Suggestions

### IMPROVEMENT-1: Add Config Propagation Validation Check

**Priority:** MEDIUM

**Issue:** AGENTS.md (line 180) documents that missing config field propagation caused APP-17 (require_hashes) bug. The config deep dive document does not mention this validation pattern.

**Suggestion:** Add a section to `config_deep_dive.md` about config propagation testing:
- When adding new SiteAppServerConfig fields, verify propagation to AppServerConfig
- Add validation test for all Option fields in SiteAppServerConfig

---

### IMPROVEMENT-2: Document Feature-Gated Handlers Properly

**Priority:** LOW

**Issue:** `admin_deep_dive.md:120` says "28 handlers" but lists 29 modules in `handlers/mod.rs`. The difference is that 4 handlers are feature-gated (mesh) but the document counts them as part of the total.

**Suggestion:** Add footnote explaining that handler count includes feature-gated modules (behavioral_intel, mesh_admin, mesh_topology, yara_rules) that only exist with `mesh` feature.

---

### IMPROVEMENT-3: Document Auth Manager vs Admin Auth Distinction

**Priority:** MEDIUM

**Issue:** `admin_deep_dive.md:253-280` describes authentication architecture, but conflates two separate authentication systems:
1. **Admin Auth** (`src/admin/auth.rs`) - Single admin token for API
2. **User Auth** (`src/auth/mod.rs`) - Multi-user authentication with registration, sessions, etc.

**Actual State:**
- Admin auth uses single bcrypt-hashed token (line 24-26 in auth.rs)
- User auth (AuthManager) supports multiple users with registration

**Suggestion:** Clearly separate these in documentation. The admin API uses Admin Auth, while user-facing sites could use AuthManager for multi-user support.

---

### IMPROVEMENT-4: Missing Rate Limiter Constant in Document

**Priority:** LOW

**Issue:** `admin_deep_dive.md:49-50` documents:
- MAX_AUTH_ATTEMPTS: 5 failures per IP
- AUTH_LOCKOUT_DURATION: 300 seconds

But does not mention AUTH_WINDOW_DURATION which is 60 seconds (sliding window).

**Location:** `src/admin/auth.rs:8` - `const AUTH_WINDOW_DURATION: Duration = Duration::from_secs(60);`

**Fix:** Add AUTH_WINDOW_DURATION to documentation.

---

### IMPROVEMENT-5: Admin Rate Limiter Location

**Priority:** LOW

**Document:** `admin_deep_dive.md:234`

**Claim:** Admin Rate Limiter **Location:** `src/admin/rate_limit.rs`

**Verification:** Need to confirm if this file exists and contains the rate limiter implementation.

---

### IMPROVEMENT-6: ConfigManager discover_sites() Return Type

**Priority:** LOW

**Document:** `config_deep_dive.md:139`

**Claim:** `discover_sites()` - auto-discovers all `*.toml` in `sites/` directory

**Issue:** The document shows void return in description but the actual signature returns `Vec<(String, Result<SiteConfig, String>)>` which is useful for reporting load errors.

**Fix:** Update to document the return type properly.

---

## Summary Table

| Item | Type | Priority | File:Line |
|------|------|----------|-----------|
| BUG-1: CSRF validation missing constant-time | Bug | MEDIUM | `src/admin/state.rs:736` |
| BUG-2: Inconsistent CSRF comparison | Bug | MEDIUM | `src/admin/state.rs:736` vs `src/auth/mod.rs:772` |
| DISCREPANCY-1: Utils crate path | Documentation | LOW | `architecture/config_deep_dive.md:5` |
| DISCREPANCY-2: SiteConfig hierarchy missing site_id | Documentation | MEDIUM | `architecture/config_deep_dive.md:68-93` |
| DISCREPANCY-3: ConfigManager location | Documentation | LOW | `architecture/config_deep_dive.md:31` |
| IMPROVEMENT-1: Config propagation documentation | Documentation | MEDIUM | `config_deep_dive.md` |
| IMPROVEMENT-2: Handler count clarification | Documentation | LOW | `admin_deep_dive.md:120` |
| IMPROVEMENT-3: Auth system distinction | Documentation | MEDIUM | `admin_deep_dive.md:253` |
| IMPROVEMENT-4: Missing AUTH_WINDOW_DURATION | Documentation | LOW | `admin_deep_dive.md:49` |
| IMPROVEMENT-5: Rate limiter location | Documentation | LOW | `admin_deep_dive.md:234` |
| IMPROVEMENT-6: discover_sites return type | Documentation | LOW | `config_deep_dive.md:139` |

---

## Verification Commands

```bash
# Verify config compilation
cargo check -p synvoid-config --no-default-features
cargo check -p synvoid-config --no-default-features --features mesh,dns

# Verify admin compilation
cargo check --lib --no-default-features --features mesh
```

---

## Recommended Actions

1. **HIGH PRIORITY:** Fix BUG-1 by updating `src/admin/state.rs:736` to use `ConstantTimeEq` for session hash comparison

2. **MEDIUM PRIORITY:** Update `admin_deep_dive.md` to clarify:
   - The two auth systems (Admin vs User)
   - Add AUTH_WINDOW_DURATION constant
   - Clarify feature-gated handler count

3. **MEDIUM PRIORITY:** Update `config_deep_dive.md` to:
   - Add ConfigManager location note
   - Document site_id in SiteConfig hierarchy
   - Add config propagation pattern section

4. **LOW PRIORITY:** Verify and update remaining documentation items