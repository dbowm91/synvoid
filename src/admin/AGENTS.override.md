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

### Session-First Browser Auth (Phase 2)

Browser clients must use session-based authentication, not the raw bearer token:

1. **Login**: Browser sends bearer token to `POST /api/auth/session` → receives `HttpOnly` session cookie
2. **Session restore**: On page reload, `GET /api/auth/csrf` with session cookie → returns CSRF token
3. **Mutating requests**: `X-CSRF-Token` header + session cookie
4. **Logout**: `DELETE /api/auth/session` → invalidates session + CSRF tokens, expires cookie

**Never**: Store bearer token in `localStorage`, `sessionStorage`, JS-readable cookies, or WebSocket URLs.

**Cookie policy**: `Secure` flag is based on bind address (external = Secure, loopback = no Secure), not `debug_assertions`.

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
2. Client IP Extraction (`src/admin/middleware.rs:61-101`)
3. CORS Layer (`create_cors_layer()`)
4. YARA Rate Limit Layer

**Protected API routes** (nested under `/api`) additionally have:
5. CSRF Middleware (`src/admin/middleware.rs:185-266`) — validates `X-CSRF-Token` for session-authenticated mutations
6. Auth Middleware (`src/admin/middleware.rs:103-183`) — bearer token or session cookie

**Public routes** (health, SPA fallback) do NOT have auth/CSRF middleware.

**WebSocket routes**: Auth handled per-connection (bearer token, session cookie, or legacy WS cookie), not via blanket middleware.

**Note**: CSRF exclusion list: `/health`, `/ws/*`, `/stats*`, `/config/schema`. All other mutating endpoints require CSRF for session-authenticated requests.

## Skills Reference

See `skills/admin_api.md` for Admin API patterns.

## Security Issues

### SSRF Bypass via HTTPS (SEC-2 — RESOLVED)

`src/admin/alerting/mod.rs:143-154` — SSRF check now validates both `http://` and `https://` URLs against private IPs. Both schemes are checked in the same condition block.

### Email Alerting is a Stub

`send_email_internal()` at `src/admin/alerting/mod.rs:349-373` logs a message then returns `Ok(())` without actually sending any email. No SMTP or email transport is implemented.