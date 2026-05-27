# Admin API Architecture Review Plan

## Verified Correct Items

- **Admin Auth Functions**: `src/admin/auth.rs:16-26` - `hash_admin_token_with_cost()`, `hash_admin_token()`, `verify_admin_token()` all exist and match documentation
- **Timing Normalization**: `src/admin/handlers/auth.rs:14-22` - `verify_dummy_admin_token()` exists with 200ms minimum delay
- **Session Creation**: `src/admin/state.rs:796-828` - `create_session()` correctly generates random 32-byte session IDs with SHA256 hash binding
- **Session Validation**: `src/admin/state.rs:830-852` - `validate_session()` with sliding window expiration and `last_used` updates
- **CSRF Validation**: `src/admin/state.rs:728-749` - `validate_csrf()` uses `subtle::ConstantTimeEq` for session binding
- **CSRF Generation**: `src/admin/state.rs:751-779` - `generate_csrf_token()` caps at 10 tokens per session, removes oldest on overflow
- **CSRF Middleware**: `src/admin/middleware.rs:185-266` - Correct exempted paths (`/ws/*`, `/stats/*`, `/health`, `/config/schema`, `/logs`), bearer token bypass
- **SecurityState**: `src/admin/state.rs:211-217` - Struct matches documentation with `csrf_tokens`, `sessions`, `rate_limiter`, `yara_rate_limiter`
- **YaraRateLimiter**: `src/admin/state.rs:89-146` - Separate per-operation rate limits (submit: 10, broadcast_apply: 5, approve_reject: 10, status_list: 30)
- **AdminRateLimiter**: `src/admin/rate_limit.rs` - Per-IP tracking with configurable limits and automatic cleanup
- **Admin Auth Constants**: `src/admin/auth.rs:6-9` - `MAX_AUTH_ATTEMPTS = 5`, `AUTH_LOCKOUT_DURATION = 300s`, `AUTH_WINDOW_DURATION = 60s`, `BCRYPT_COST = 12`
- **Alert Metrics**: `src/admin/alerting/mod.rs:5-14` - Matches 8 supported metrics
- **Alert Conditions**: `src/admin/alerting/mod.rs:80-85` - `GreaterThan`, `LessThan`, `Equals` match documentation
- **Audit Logging Permissions**: `src/admin/audit.rs:76-79` - Sets `0o600` on audit file
- **Handler Count**: 26 handlers + 1 mesh-gated (`yara_rules`) - matches documentation
- **Feature-Gated Handlers**: `src/admin/handlers/mod.rs:4-5,11-14,28` - `behavioral_intel`, `mesh_admin`, `mesh_topology`, `yara_rules` all gated with `#[cfg(feature = "mesh")]`
- **CORS Layer Function**: `src/admin/mod.rs:50-97` - `create_cors_layer()` implementation exists with proper origin/methods/headers handling
- **CORS Application**: `src/admin/mod.rs:806` - CORS layer correctly applied to outer router
- **Session Cookie**: `src/admin/handlers/auth.rs:48-62` - HttpOnly, SameSite=Strict, Max-Age=3600, Secure in non-debug builds

## Discrepancies Found

### 1. Line Number Inaccuracies (Documentation vs Reality)

| Documented Location | Actual Location | Status |
|---------------------|-----------------|--------|
| `src/admin/state.rs:796-828` - create_session() | **Correct** - lines match | ✅ |
| `src/admin/state.rs:830-845` - validate_session() | **Correct** - lines match | ✅ |
| `src/admin/state.rs:86-143` - YaraRateLimiter | **Incorrect** - Actual is `state.rs:89-146` | Minor offset |
| `src/admin/handlers/auth.rs:14-22` - verify_dummy_admin_token() | **Correct** - lines match | ✅ |
| `src/admin/handlers/auth.rs:24-65` - Session creation endpoint | **Incorrect** - Actual function is `create_session()` at lines 24-70, not 24-65 | Minor inaccurate range |

### 2. Handler Count Documentation

Document says "26 handlers + 1 mesh-gated handler" but lists 4 mesh-gated handlers:
- `behavioral_intel` (mesh)
- `mesh_admin` (mesh)
- `mesh_topology` (mesh)
- `yara_rules` (mesh)

**Actual**: 26 always-available handlers + 4 mesh-gated = 30 total, not 26+1=27. The documentation understates the total.

### 3. SecurityState Documentation Location

Documented at `src/admin/state.rs:257-267` but actual location is `state.rs:211-217`. The struct definition moved but documentation wasn't updated. Relatedly, `AdminState` struct at `state.rs:257-267` IS correctly documented.

### 4. API Discovery Handler Missing from Table

Document's API Organization table lists 23 handlers but there are 26 regular handlers + 4 mesh-gated = 30 total. The table omits: `common`, `probes`, `theme` which exist as handlers.

### 5. `/config/defaults/*`, `/config/versions`, `/config/rollback/{id}` Not Found in Router

Documented at lines 226-228 but I could not locate these exact routes in the router builder. May exist in nested config routes - not fully verified.

### 6. `/system/overseer` "Functional But Legacy" Statement

Document claims endpoint is functional but will be removed in Supervisor migration. This is forward-looking and assumes architectural knowledge the code doesn't enforce.

## Bugs Identified

### BUG-CORS-1 (Low Severity) - CORS Not Applied to Nested `/api` Routes

**Location**: `src/admin/mod.rs:179-189` (nested api_routes), line 806 (CORS layer on outer router)

**Issue**: CORS layer is applied to the outer router at line 806, but the nested `/api` routes (built as `api_routes` at lines 179-189) are added to this outer router via `.nest("/api", api_routes)` at line 792. Axum's `nest()` applies the outer CORS layer to nested routes **if** the nested router doesn't have its own CORS layer. However, the nested `api_routes` are built as a standalone `Router::new()` without CORS.

**Impact**: For browser-based API access (if ever used), CORS preflight requests to `/api/*` endpoints may fail depending on browser behavior with nested routes. Since the Admin API uses bearer tokens (not browser sessions), this may be intentional.

**Status**: AGENTS.md correctly documents this as "may be intentional" but marks BUG-CORS-1 as "fixed" via removal of dead code. The dead code removal doesn't fix the underlying architectural issue.

**Severity**: LOW (Admin API uses bearer tokens, not browser CORS)

### Security Note: Session ID Not Constant-Time Compared

**Location**: `src/admin/state.rs:830-852` - `validate_session()`

**Issue**: Session validation at line 840 does a simple `HashMap::get()` which uses hash comparison for the key lookup. This is NOT constant-time. A HashMap's internal comparison of the session_id key could theoretically leak information through timing.

**However**: This is likely **acceptable** because:
1. The session_id is a random 32-byte value (not user-controlled input that could trigger hash collision attacks)
2. The actual secret binding is the CSRF token which IS constant-time compared
3. Session IDs are high-entropy and not enumerable in the way passwords are

**Severity**: LOW (defense-in-depth concern, not exploitable given session_id entropy)

## Suggested Improvements

### 1. Fix Documentation Line Numbers

Update `architecture/admin_deep_dive.md` to reflect correct line numbers:
- `state.rs:86-143` → `state.rs:89-146` for YaraRateLimiter
- `state.rs:211-217` for SecurityState (currently documented at 257-267)
- `state.rs:257-267` for AdminState is correct

### 2. Update Handler Count in Documentation

Clarify the handler count: "26 regular handlers + 4 mesh-gated = 30 total (23 handlers always available when mesh disabled)".

### 3. Add Missing Handlers to Table

Add `common`, `probes`, `theme` handlers to the API Organization table.

### 4. Clarify CORS Intentionality

If CORS on nested `/api` routes is intentional (because Admin API isn't browser-accessible), document this rationale explicitly. The current "may be intentional" designation is ambiguous.

### 5. Add Constant-Time Session ID Comparison (Future Improvement)

Consider using `ConstantTimeEq` for session ID comparison in `validate_session()`, or document why this isn't necessary given session_id entropy.

### 6. Remove `/system/overseer` "Legacy" Documentation

The statement about `/system/overseer` being functional but deprecated adds confusion. Either remove the endpoint or update the documentation to reflect actual status without speculation about future migrations.

### 7. Add SSRF Validation Exemptions to Documentation

The documentation mentions blocked IP ranges but doesn't mention any exemptions (e.g., localhost connections for testing). Consider adding a complete list of allowed/blocked schemes and ranges.
