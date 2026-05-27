# Auth Module Architecture Review

## Verified Correct Items

### Data Structures (All Match Documentation)
- **User struct** (`src/auth/mod.rs:40-50`) - All fields match: id, username, password_hash, role, sites, created_at, last_login, failed_attempts, locked_until
- **Session struct** (`src/auth/mod.rs:62-71`) - All fields match: id, user_id, username, created_at, expires_at, ip_address, user_agent, csrf_token
- **SessionInfo struct** (`src/auth/mod.rs:801-807`) - Matches documentation
- **AuthStore struct** (`src/auth/mod.rs:73-78`) - HashMap<String, User> and HashMap<String, Session> match
- **LoginLog struct** (`src/auth/mod.rs:80-89`) - All fields match including MAX_LOGIN_LOGS = 10,000
- **AuthError enum** (`src/auth/mod.rs:818-834`) - All 7 variants match with correct error messages
- **UserRole enum** (`src/auth/mod.rs:52-59`) - Admin and User(default) match

### Security Implementation (Correct per AGENTS.md)
- **Constant-time CSRF comparison** (`src/auth/mod.rs:772`) - Uses `subtle::ConstantTimeEq` correctly
- **File permissions** - Auth dir `0o700` (`mod.rs:201`), store file `0o600` (`mod.rs:210`) - Correct
- **Pure Rust bcrypt** - Uses `bcrypt` crate confirmed pure Rust per AGENTS.md
- **Timing-attack mitigation** (`mod.rs:404-407`) - Dummy password hash for non-existent users
- **verify_dummy_password** (`mod.rs:26-34`) - Ensures consistent timing (~200ms minimum)

### Core APIs (All Present and Functional)
- `verify_login()` - Lines 393-533, handles lockout, brute-force, session creation
- `validate_session()` - Lines 561-629, with auto-refresh at >50% elapsed
- `validate_session_with_ip()` - Lines 631-711, hijacking detection working
- `destroy_session()` - Lines 713-717
- `create_user()`, `delete_user()`, `update_user_sites()`, `list_users()` - All present
- `validate_csrf_token()`, `get_csrf_token()` - Lines 766-786, constant-time comparison
- `cleanup_expired_sessions()` - Lines 741-756, handles lock expiry
- `get_login_logs()`, `get_active_sessions()` - Lines 719-739
- `flush()` - Lines 282-292, drain-aware shutdown working

### Session Management
- **5 sessions per user limit** (`mod.rs:494-513`) - Correct eviction of oldest sessions
- **Session refresh threshold 0.5** (`mod.rs:586`) - Creates new session with new ID and CSRF token when >50% elapsed
- **IP binding validation** (`mod.rs:654-659`) - Logs warning and removes session on IP mismatch

### Basic Auth
- **BasicAuthManager** (`src/auth/basic.rs:7-83`) - Realm, users HashMap, check_credentials with bcrypt
- **BasicAuthResult enum** - Authenticated, CredentialsRequired, Unauthorized
- Uses same bcrypt verification as main auth

### Integration Points
- **WafCore integration** (`src/waf/mod.rs:179`) - auth_manager: Arc<AuthManager> stored in WafCore
- **Default instance creation** (`src/waf/mod.rs:398-405`) - Falls back to AuthManager::new if not provided

---

## Discrepancies Found

### 1. Hardcoded Configuration Values (Documentation Inaccurate)

**Issue**: Documentation states `AuthManager::new()` accepts parameters for session_refresh_threshold and min_password_length, but these are hardcoded constants in the implementation:

```
src/auth/mod.rs:160-161:
min_password_length: 8,           // Hardcoded, not configurable
session_refresh_threshold: 0.5,    // Hardcoded, not configurable
```

**Documentation says**:
> pub fn new(data_dir: PathBuf, session_duration_secs: u64, max_failed_attempts: u32, lockout_duration_secs: u64)

But describes configurable values that don't exist in the signature.

**Severity**: LOW (Documentation error, not a bug)

---

### 2. WafCore Default max_failed_attempts=5 vs Documented Default=3

**Issue**: The documented default for max_failed_attempts is 3, but WafCore creates AuthManager with max_failed_attempts=5:

```
src/waf/mod.rs:398-404:
Arc::new(AuthManager::new(
    data_dir.clone().unwrap_or_else(|| PathBuf::from("data")),
    3600, // session_duration_secs
    5,    // max_failed_attempts  <-- Documented as 3
    300,  // lockout_duration_secs
))
```

**Severity**: MEDIUM (Inconsistency between documented defaults and actual implementation)

---

### 3. Challenge Module Location Mismatch

**Issue**: Documentation states the Challenge module is at `src/challenge/` and includes it in Section 7, but this is a separate module from Auth and not part of the `src/auth/` submodule structure.

**Actual**: Challenge is at `src/challenge/` with pow.rs, css.rs, mesh_pow.rs, honeypot.rs, mod.rs

**Severity**: LOW (The documentation correctly notes it's "related but separate", but presentation could be clearer)

---

## Bugs Identified

### BUG-AUTH-1: No Username Length Validation

**Location**: `src/auth/mod.rs:305-307`

**Issue**: Only checks for empty username. Does not validate maximum length or character restrictions. RFC 5321 allows local-part up to 64 characters, but no upper bound is enforced.

**Severity**: LOW (Could allow unusually long usernames that might cause issues in storage/display)

---

### BUG-AUTH-2: No Username Character Validation

**Location**: `src/auth/mod.rs:305-307`

**Issue**: Username is stored as-is without validation. Could contain control characters, newlines, or other problematic characters.

**Severity**: LOW (Potential XSS or log injection if username is displayed without sanitization)

---

### BUG-AUTH-3: Session Data Clone in validate_session

**Location**: `src/auth/mod.rs:564-577`

**Issue**: The code clones the entire session data into SessionData struct manually rather than deriving Clone. This is manual repetition that could be simplified with `#[derive(Clone)]` on SessionData.

**Severity**: NONE (Code is correct, just not idiomatic)

---

## Suggested Improvements

### 1. Add Configuration for min_password_length

**Priority**: LOW

Currently hardcoded at 8 characters. Should be configurable via AuthManager::new() or configuration file to allow stricter password policies.

**Files to modify**:
- `src/auth/mod.rs:106-111` - Add parameter to new()
- `src/auth/mod.rs:160` - Remove hardcoded constant
- `src/waf/mod.rs:398-404` - Pass configurable value

---

### 2. Add Configuration for session_refresh_threshold

**Priority**: LOW

Currently hardcoded at 0.5 (50%). Should be configurable to allow operators to tune session refresh behavior based on their security requirements.

**Files to modify**:
- `src/auth/mod.rs:106-111` - Add parameter to new()
- `src/auth/mod.rs:161` - Remove hardcoded constant

---

### 3. Align max_failed_attempts Default with Documentation

**Priority**: MEDIUM

Change WafCore default from 5 to 3 to match documented default, or update documentation to reflect actual default.

**Files to modify**:
- `src/waf/mod.rs:402` - Change 5 to 3, OR
- `architecture/auth.md` - Update section 5 to say default is 5

---

### 4. Add Username Validation

**Priority**: MEDIUM

Add username length and character validation in create_user():
- Maximum length (e.g., 64 or 128 characters)
- Allow only safe characters (alphanumeric, underscore, hyphen, dot)
- Reject control characters and newlines

**Files to modify**:
- `src/auth/mod.rs:294-307` - Add validation before password check

---

### 5. Add Password Complexity Validation

**Priority**: LOW

Currently only checks length (min 8). Could add:
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character

**Files to modify**:
- `src/auth/mod.rs:294-303` - Add complexity checks in create_user()

---

### 6. Document update_password Session Invalidation

**Priority**: LOW

The implementation at `src/auth/mod.rs:555` correctly invalidates all user sessions on password change, but this important security behavior is not documented.

**Files to modify**:
- `architecture/auth.md` - Add note to user management API table

---

### 7. Add Password Last Changed Tracking

**Priority**: LOW

Could add `password_changed_at: Option<DateTime<Utc>>` to User struct to enable:
- Forcing re-authentication after password change
- Password expiry policies
- Audit trail for password changes

**Files to modify**:
- `src/auth/mod.rs:40-50` - Add field to User struct
- `src/auth/mod.rs:536-559` - Update update_password to set timestamp
- `src/auth/mod.rs:468-478` - Check password_changed_at in verify_login if set

---

## Summary

The Auth module implementation is **largely correct** and matches the architecture document. The main issues are:

1. **Documentation inaccuracies** regarding configurable parameters
2. **Inconsistent default value** for max_failed_attempts
3. **Missing username validation** (length and character restrictions)

No critical security bugs were identified. The CSRF token comparison, timing-attack mitigation, brute-force protection, and session management are all correctly implemented.

**Recommended Actions** (in priority order):
1. Align max_failed_attempts default (MEDIUM)
2. Add username validation (MEDIUM)
3. Fix documentation to reflect hardcoded constants (LOW)
4. Add password complexity validation (LOW)