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

**WebSocket routes**: Auth handled per-connection (bearer token or session cookie), not via blanket middleware. Legacy `synvoid_ws_token` cookie removed.

**Note**: CSRF exclusion list: `/health`, `/ws/*`, `/stats*`, `/config/schema`. All other mutating endpoints require CSRF for session-authenticated requests.

## Skills Reference

See `skills/admin_api.md` for Admin API patterns.

## Security Issues

### SSRF Protection

Webhook URLs are validated at configuration time via IP classification (`is_restricted_ip()`), and at request time via DNS resolution with IP validation. All private/loopback/link-local/multicast IPv4 and IPv6 addresses are blocked. Redirects are not followed (hyper does not auto-follow). Only 2xx HTTP responses count as delivery success.

### Webhook Delivery Result

`send_webhook_internal()` returns `WebhookDeliveryResult` with `outcome` (`Success`/`PartialFailure`/`Failure`), counts, and per-destination details. The `/alerting/test-webhook` endpoint returns `TestWebhookResult`.

## Phase 6 Corrections

### Login Form Semantics

The admin-ui login uses proper HTML form submission:
- `<form onsubmit={on_submit}>` with `type="submit"` button
- Token input uses `type="password"` (non-echoing)
- Submit button disabled during flight to prevent double submission
- Invalid credentials show bounded generic error without reflecting the token

### Destructive Operation Confirmation

All destructive operations require explicit confirmation via `ConfirmDialog`:
- Site deletion
- Worker restart
- Tier key revoke/unbind
- Threat level backup delete
- Threat level baseline reset

The `ConfirmDialog` component (`admin-ui/src/components/confirm_dialog.rs`) supports `Danger`/`Warning`/`Primary` confirmation types.

### API Error Handling

API methods return `Result<T, ApiError>` where `ApiError` contains `status: u16` and `message: String`. Error messages are bounded (512 bytes max) and sanitized. Known JSON error shapes (`error`, `message`, `detail` fields) are extracted; arbitrary text is truncated.