# Auth/Admin Boundary Decision

## 1. Is `src/auth` only admin auth, or does WAF challenge/auth also use it?

`src/auth` is **NOT** admin-only. It provides general user authentication:

- **`src/auth/mod.rs`**: Full `AuthManager` with user registration, login, session management, bcrypt hashing, brute-force protection, login audit logging. Used by WAF (`src/waf/mod.rs:35` imports `AuthManager`).
- **`src/auth/basic.rs`**: HTTP Basic auth support (`BasicAuthManager`, `BasicAuthResult`).

`src/admin/auth.rs` is a **separate** admin-specific module providing:
- `hash_admin_token` / `verify_admin_token` (bcrypt-based admin bearer token)
- `AuthRateLimiter` (admin API brute-force protection)

These are two distinct auth subsystems:
1. **User auth** (`src/auth/`) — end-user login/sessions, consumed by WAF
2. **Admin token auth** (`src/admin/auth.rs`) — single admin bearer token, consumed only by admin API

## 2. Should auth become `synvoid-auth`, or stay with `synvoid-admin`?

**Create `synvoid-auth`** for user auth primitives that WAF and other subsystems need.

**Keep admin token auth in `synvoid-admin`** (`src/admin/auth.rs`) since it is admin-API-specific.

Rationale:
- `AuthManager` is consumed by WAF (`src/waf/mod.rs`), not just admin
- Making WAF depend on `synvoid-admin` would be wrong — WAF should not depend on admin API code
- Admin token hashing (`hash_admin_token`) is only used by admin middleware/handlers
- Clean separation: `synvoid-auth` for user-facing auth, `synvoid-admin` for admin API

## 3. Which crates need to consume auth primitives?

| Crate | Auth Need | Module |
|-------|-----------|--------|
| `synvoid-waf` | `AuthManager` (user sessions, login audit) | `src/auth/mod.rs` |
| `synvoid-admin` | `hash_admin_token`, `verify_admin_token`, `AuthRateLimiter` | `src/admin/auth.rs` |
| Root `synvoid` | Both (compatibility shims) | Both |

## Summary

| Component | Destination |
|-----------|-------------|
| `src/auth/mod.rs` (AuthManager, User, Session, etc.) | `synvoid-auth` (future wave) |
| `src/auth/basic.rs` (BasicAuthManager) | `synvoid-auth` (future wave) |
| `src/admin/auth.rs` (admin token hashing, rate limit) | `synvoid-admin` (this wave) |
