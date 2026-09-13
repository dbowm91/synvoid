---
name: auth
description: Authentication and sessions — users, bcrypt, brute-force lockout, CSRF, HTTP Basic. Use when touching login, sessions, or auth middleware.
---

# Skill: Auth

## Context

Canonical implementation lives in `crates/synvoid-auth` (there is no
`src/auth/` — the removed root path maps here). Admin-session specifics
(HttpOnly cookie + CSRF, bearer-for-exchange-only) are governed by
`architecture/admin_control_plane_authority.md` (see `admin_contract` skill).
Full reference: `architecture/auth.md`, `architecture/auth_deep_dive.md`.

## When to Use

- Changing login, session issuance/validation, or lockout behavior
- Touching CSRF or HTTP Basic handling
- Adding a new authenticated surface (admin, metrics, WS)

## Key Files

| File | Purpose |
|------|---------|
| `crates/synvoid-auth/src/lib.rs` | `AuthManager`, `AuthStore`, `User`/`UserRole`, `Session`, brute-force lockout |
| `crates/synvoid-auth/src/basic.rs` | HTTP Basic handling |
| `src/admin/handlers/auth.rs` | Admin login transport (facade over the crate + session-cookie issue) |

## Non-Negotiables

1. **Constant-time comparison** for secrets, password hashes, and tokens
   (`subtle::ConstantTimeEq`) — never `==` on secret material.
2. **Never store raw session tokens** — audit/auth logs carry
   `AdminActor.session_id_hash`, not the token.
3. **Browser clients**: HttpOnly session cookie + CSRF token; bearer token
   only for the session-exchange call; frontend treats 401/403 as session
   expiry.
4. Brute-force lockout thresholds (`max_failed_attempts`,
   `lockout_duration_secs`) stay enforced on every password path; do not add
   unauthenticated oracles (timing or message) distinguishing bad-user from
   bad-password.

## Verification

```bash
cargo nextest run -p synvoid-auth --cargo-profile ci --profile ci
cargo nextest run --test admin_smoke_flow --features mesh,dns,icmp-filter --cargo-profile ci --profile ci
```
