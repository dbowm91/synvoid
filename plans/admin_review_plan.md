# Admin Architecture Review Plan

## Verified Correct

### Authentication Architecture
- **Dual Authentication Model**: Accurately describes Admin Auth (single token) vs User Auth (multi-user) at `src/admin/auth.rs` and `src/auth/mod.rs`
- **Admin Token Hashing**: `hash_admin_token()` and `verify_admin_token()` correctly implemented at `src/admin/auth.rs:16-26` with bcrypt cost 12
- **Brute-Force Protection**: Global per-IP rate limiter correctly implemented with MAX_AUTH_ATTEMPTS=5, AUTH_LOCKOUT_DURATION=300s, AUTH_WINDOW_DURATION=60s at `src/admin/auth.rs:6-8`
- **Timing Normalization**: `verify_dummy_admin_token()` correctly applied before both UNAUTHORIZED returns at `src/admin/handlers/auth.rs:14-22`

### CSRF Protection
- **Token Architecture**: UUID v4 format, bound via SHA256 hash of session ID, max 10 tokens per session, 1-hour expiration correctly implemented at `src/admin/state.rs:728-779`
- **Constant-Time Comparison**: `validate_csrf()` uses `subtle::ConstantTimeEq` at `src/admin/state.rs:737-742`
- **Middleware Logic**: CSRF middleware correctly exempts `/ws/*`, `/stats/*`, `/health`, `/config/schema`, `/logs` and bypasses for bearer token at `src/admin/middleware.rs:185-266`

### Middleware Stack
- **Order**: Client IP Extraction (61-101), Auth Middleware (103-183), CSRF Middleware (185-266), Admin Rate Limit Layer correctly documented
- **Public Routes**: `/health`, `/api/openapi.json`, `/api/docs/*`, `/ws/*` correctly bypass auth

### Session Management
- **Session Creation**: `create_session()` at `src/admin/state.rs:796-828` correctly generates 32-byte random session ID, stores hash of ID, sets 1-hour TTL
- **Session Validation**: `validate_session()` at `src/admin/state.rs:830-852` implements sliding window expiration correctly
- **Cookie Properties**: HttpOnly, SameSite=Strict, Secure (production) correctly implemented at `src/admin/handlers/auth.rs:48-55`

### SecurityState Structure
- **Location and Fields**: Accurately documented at `src/admin/state.rs:210-217`

### AdminState Structure
- **Location and Fields**: Accurately documented at `src/admin/state.rs:257-267`

### Rate Limiting
- **YARA Rate Limiter**: Default limits correctly documented (submit: 10, broadcast_apply: 5, approve_reject: 10, status_list: 30) at `src/admin/state.rs:118-120`
- **Admin Rate Limiter**: Per-IP tracking with minute windows at `src/admin/state.rs:48-79`

### Alerting System
- **Supported Metrics**: All 8 metrics correctly listed at `src/admin/alerting/mod.rs:5-14`
- **Alert Conditions**: GreaterThan, LessThan, Equals correctly implemented at `src/admin/alerting/mod.rs:80-85`
- **SSRF Protection**: Private IP blocking (localhost, 127.x.x.x, 10.x.x.x, 192.168.x.x, 172.x.x.x) correctly implemented at `src/admin/alerting/mod.rs:146-153`

### Audit Logging
- **File Permissions**: 0o600 correctly set in `log()` method at `src/admin/audit.rs:131-139`
- **Version Limit**: MAX_CONFIG_VERSIONS=100 at `src/admin/audit.rs:11`

### User Authentication System
- **Location and Features**: Accurately documented at `src/auth/mod.rs:1-629`
- **Constant-Time CSRF Comparison**: Uses `subtle::ConstantTimeEq` at `src/auth/mod.rs:15`
- **Max Sessions Per User**: 5 correctly documented at `src/auth/mod.rs:37`

### HTTP Basic Auth
- **Location**: `src/auth/basic.rs` - correctly documented

### API Organization (26 handlers)
- **Handler Count**: 27 handler files exist in `src/admin/handlers/`
- **Feature-Gated Handlers**: mesh, dns correctly documented with `#[cfg(feature = "mesh")]` and `#[cfg(feature = "dns")]`

### WebSocket Endpoints
- `/ws/metrics` and `/ws/logs` correctly implemented at `src/admin/mod.rs:777-778`

### OpenAPI Documentation
- **Location**: `src/admin/openapi.rs` - Title "SynVoid Admin API", Version 1.0.0 correctly documented

---

## Discrepancies Found

### 1. CORS Layer Documentation
**Document says**: "CORS is fully implemented via `create_cors_layer()` at `src/admin/mod.rs:50-97`. The CORS layer is created and added to the router in the admin API setup."

**Code shows**: CORS layer IS added to the router at line 806 in `build_router_from_state()`.

**However**, the AGENTS.override.md states: "**Note**: No CORS layer - intentional design since Admin API uses bearer/session tokens, not browser-based access."

**Discrepancy**: The documentation is internally inconsistent. The admin deep dive says CORS is "fully implemented" but the AGENTS override says "No CORS layer". The code shows CORS IS actually implemented and used.

### 2. Session/CSRF Validation Line Numbers
**Document says**: 
- `create_session()` at `src/admin/state.rs:788-820`
- `validate_session()` at `src/admin/state.rs:822-844`
- `validate_csrf()` at `src/admin/state.rs:725-741`
- `generate_csrf_token()` at `src/admin/state.rs:743-771`

**Code shows**:
- `create_session()` at `src/admin/state.rs:796-828`
- `validate_session()` at `src/admin/state.rs:830-852`
- `validate_csrf()` at `src/admin/state.rs:728-749`
- `generate_csrf_token()` at `src/admin/state.rs:751-779`

**Impact**: Line numbers are off by 8-18 lines. Minor documentation accuracy issue.

---

## Bugs Identified

### High Severity

**BUG-CORS-1: CORS Configuration Ignored in `create_admin_router_with_state`**

The `create_admin_router_with_state()` function at `src/admin/mod.rs:157-171` does NOT apply the CORS layer:
```rust
pub async fn create_admin_router_with_state(state: Arc<AdminState>) -> Router {
    let cfg = state.process.config.read().await;
    let admin_cors_config = cfg.main.admin.cors.clone();  // <-- Reads config
    // ... but never uses it!
    let router = build_router_from_state(
        state,
        admin_cors_config,  // <-- Passed but ignored
        rate_limit_config,
        trusted_proxies.clone(),
    );
    // CORS layer NOT added here
    middleware::set_trusted_proxies(trusted_proxies);
    router
}
```

Compare to `build_router_from_state()` which correctly applies CORS at line 806. The `create_admin_router_with_state()` function is used by `start_admin_server()` (line 925), so CORS settings from config may not be properly applied in that code path.

---

## Suggested Improvements

### 1. Documentation Consistency
- Resolve the CORS contradiction between `admin_deep_dive.md` (says CORS is "fully implemented") and `AGENTS.override.md` (says "No CORS layer")
- Consider whether CORS should be enabled or disabled for the admin API (bearer token model suggests it may not be needed)

### 2. Line Number References
- Update line number references in documentation to match actual code locations
- Or use relative path references that don't require line numbers

### 3. CORS Configuration Verification
- Investigate whether `create_admin_router_with_state()` properly applies CORS configuration
- Consider if CORS is truly needed for an API-only admin interface using bearer tokens

### 4. Handler Count Documentation
- Document states "26+ handlers" but 27 handler files exist
- Clarify exact count and which handlers are feature-gated

### 5. Session Timing Normalization
- Well documented in AGENTS.override.md but could be added to main admin_deep_dive.md for completeness

### 6. Security Summary Table Accuracy
- The "Admin Session Security" row says "Secure flag in production" - this is accurate based on `src/admin/handlers/auth.rs:53-55`
- The "File Permissions" row correctly notes 0o600 for audit log
