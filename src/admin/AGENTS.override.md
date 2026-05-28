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

The Admin API middleware stack (in order, from outermost to innermost):
1. Rate Limit Layer (`src/admin/rate_limit.rs`)
2. YARA Rate Limit Layer
3. CSRF Middleware (`src/admin/middleware.rs:185-266`)
4. Auth Middleware (`src/admin/middleware.rs:103-183`)
5. Client IP Extraction (`src/admin/middleware.rs:61-101`)

**Note**: Documentation in `admin_deep_dive.md` has this order reversed — verify against source before relying on docs.

**Note**: CORS implementation status:
- CORS layer IS implemented via `create_cors_layer()` at `src/admin/mod.rs:50-97`
- CORS is applied to outer router at line 173 in `build_router_from_state()` (`.layer(create_cors_layer(&admin_cors_config))`)
- Nested `/api` routes (lines 179-189) do NOT have CORS applied
- Since Admin API uses bearer/session tokens rather than browser-based cross-origin requests, this gap may be intentional
- BUG-CORS-1 was fixed by removing dead code (`let _cors_config = cfg.cors.clone()`) at `src/admin/mod.rs:860`

### CORS Configuration Bug (BUG-CORS-1 - P0)

`src/admin/mod.rs:860`:

```rust
let _cors_config = cfg.cors.clone();  // underscore = dropped!
```

**Problem**: The CORS config is cloned into `_cors_config`, but the underscore prefix means it is immediately dropped. The CORS layer is only applied to the outer router at line 173 in `build_router_from_state()`, but nested `/api` routes (lines 179-189) do NOT have CORS.

**Impact**: Even when `cfg.cors` is configured, CORS headers may not be properly applied to nested routes if they use a different router builder.

**Fix Direction**: Ensure `create_admin_router_with_state()` applies CORS layer consistently, or clarify whether CORS is intentionally not applied to nested routes.

## Skills Reference

See `skills/admin_api.md` for Admin API patterns.

## Security Issues (Open)

### SSRF Bypass via HTTPS (SEC-2)

`src/admin/alerting/mod.rs:143-154` — SSRF check in `AlertConfig::validate()` is inline (not a named function). Line 143: `if url_lower.starts_with("http://")` — only validates `http://` URLs against private IPs. HTTPS URLs to private IPs (e.g., `https://127.0.0.1/admin`) bypass the check entirely. Fix: extend validation to also check `https://` URLs.

### Email Alerting is a Stub

`send_email_internal()` at `src/admin/alerting/mod.rs:349-373` logs a message then returns `Ok(())` without actually sending any email. No SMTP or email transport is implemented.