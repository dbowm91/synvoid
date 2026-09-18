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
Phase 43 hardened CPU isolation and persistence (see plan
`plans/phase_43_auth_cpu_and_persistence_hardening.md`).

## When to Use

- Changing login, session issuance/validation, or lockout behavior
- Touching CSRF or HTTP Basic handling
- Adding a new authenticated surface (admin, metrics, WS)

## Key Files

| File | Purpose |
|------|---------|
| `crates/synvoid-auth/src/lib.rs` | `AuthManager` (`try_new` fail-closed), `AuthStore`, `User`/`UserRole`, `Session`, brute-force lockout, atomic persistence, `MAX_LOGIN_LOGS` |
| `crates/synvoid-auth/src/crypto.rs` | `PasswordCrypto` bounded executor (semaphore + `spawn_blocking`, `Busy` overload) |
| `crates/synvoid-auth/src/basic.rs` | Async HTTP Basic (`authenticate_request_async`, `BackendBusy` → 503) |
| `crates/synvoid-admin/src/auth.rs` | Bounded admin token verify (`verify_admin_token_async`, `verify_dummy_admin_token_async`, single verify) |
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
5. **Bounded password crypto (Phase 43)**: no bcrypt on a Tokio core thread,
   no `RwLock<AuthStore>` held across bcrypt, no `block_in_place` in sync
   wrappers. Snapshot state → release lock → bounded `spawn_blocking` →
   reacquire + revalidate generation. Overload (`Busy`/`BackendBusy`) fails
   closed and authenticates nobody.
6. **Single-verify timing**: exactly one bounded bcrypt per login/admin/Basic
   attempt (dummy hash for unknown users/missing tokens) + minimum-delay pad;
   never a real verify followed by a second dummy verify.
7. **Atomic auth persistence**: temp + fsync + rename with `0600`/`0700` from
   creation; failures preserve the previous store. Corrupt/overly-permissive
   stores fail closed via `try_new` — never silently become an empty DB.
   Login audit bounded at insertion (`MAX_LOGIN_LOGS`); prune expired
   sessions before snapshotting.

## Verification

```bash
cargo nextest run -p synvoid-auth --cargo-profile ci --profile ci
cargo nextest run --test admin_smoke_flow --features mesh,dns,icmp-filter --cargo-profile ci --profile ci
```
