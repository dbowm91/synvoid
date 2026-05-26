# Admin API Module - AGENTS.override.md

Specialized guidance for Admin API patterns.

## Security Patterns

### Constant-Time Comparison

Always use `subtle::ConstantTimeEq` for comparing secrets, tokens, keys, MACs:

**Location requiring constant-time comparison**:
- Session ID comparison (`src/admin/state.rs`)
- Cache purge token comparison

### Session Timing Normalization (2026-05-23)

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