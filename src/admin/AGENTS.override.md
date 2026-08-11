# Admin API Module - AGENTS.override.md

Specialized guidance for Admin API patterns.

## Router Architecture (Phase 1)

The admin router uses a two-tier architecture:

1. **Protected API router** (`/api/*`): Auth + CSRF middleware applied
2. **Public router**: Static SPA fallback, health check, WebSocket routes (no auth middleware)

Key design decisions:
- SPA assets are resolved deterministically via `resolve_admin_ui_assets()` — not CWD-relative
- SPA fallback serves `index.html` for browser navigation, 404 for missing static assets
- `/api/*` misses return API 404 (never SPA shell)
- Feature-gated routes: mesh routes under `#[cfg(feature = "mesh")]`, ICMP under `#[cfg(feature = "icmp-filter")]`, DNS under `#[cfg(feature = "dns")]`
- Core routes (system, alerts, theme, auth) are always available regardless of mesh feature

### Static Asset Resolution Priority

1. `SYNVOID_ADMIN_UI_DIR` env var
2. `{exe_dir}/admin-ui/dist`
3. `{CARGO_MANIFEST_DIR}/admin-ui/dist`
4. `./admin-ui/dist` (CWD fallback)

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
3. Client IP Extraction (`src/admin/middleware.rs:61-101`)

**Protected API routes** (nested under `/api`) additionally have:
4. CSRF Middleware (`src/admin/middleware.rs:185-266`)
5. Auth Middleware (`src/admin/middleware.rs:103-183`)

**Public routes** (health, SPA fallback, WebSocket) do NOT have auth/CSRF middleware.

**Note**: CORS layer is applied to the outer router via `create_cors_layer()` at `src/admin/mod.rs`.

## Skills Reference

See `skills/admin_api.md` for Admin API patterns.

## Security Issues

### SSRF Bypass via HTTPS (SEC-2 — RESOLVED)

`src/admin/alerting/mod.rs:143-154` — SSRF check now validates both `http://` and `https://` URLs against private IPs. Both schemes are checked in the same condition block.

### Email Alerting is a Stub

`send_email_internal()` at `src/admin/alerting/mod.rs:349-373` logs a message then returns `Ok(())` without actually sending any email. No SMTP or email transport is implemented.