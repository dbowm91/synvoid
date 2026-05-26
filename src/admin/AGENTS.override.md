# Admin API Module - AGENTS.override.md

Specialized guidance for Admin API patterns.

## Security Patterns

### Constant-Time Comparison

Always use `subtle::ConstantTimeEq` for comparing secrets, tokens, keys, MACs:

**Location requiring constant-time comparison**:
- Session ID comparison (`src/admin/state.rs`)
- Cache purge token comparison

### CSRF Functions

CSRF token functions in `src/admin/state.rs`:
- `generate_csrf_token()` at line 751
- `validate_csrf()` at line 728 (uses `ct_eq()` for constant-time comparison)

### Session Functions

Session management functions in `src/admin/state.rs`:
- `create_session()` at line 796
- `validate_session()` at line 830
- `invalidate_session()` at line 854
- `cleanup_expired_sessions()` at line 859

**Note**: There is no `refresh()` function - use `validate_session()` to check and extend a session.

Admin auth now includes timing normalization to prevent session enumeration attacks:

- Dummy bcrypt verify with minimum 200ms delay on invalid tokens
- Pattern: `verify_dummy_admin_token()` at `src/admin/handlers/auth.rs:14-22`
- Applied before both `UNAUTHORIZED` returns in `create_session()`

### Middleware Stack

The Admin API middleware stack (in order):
1. Client IP Extraction (`src/admin/middleware.rs:61-101`)
2. Auth Middleware (`src/admin/middleware.rs:103-183`)
3. CSRF Middleware (`src/admin/middleware.rs:185-266`)
4. Admin Rate Limit Layer (`src/admin/rate_limit.rs`)

**Note**: No CORS layer - intentional design since Admin API uses bearer/session tokens, not browser-based access.

## Skills Reference

See `skills/admin_api.md` for Admin API patterns.