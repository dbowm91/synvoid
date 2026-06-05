# Wave F Report: CONT-F01 through CONT-F04

## CONT-F01: Auth Ownership Decision

Created `plans/auth_admin_boundary.md`.

**Decision:**
- `src/auth/` (AuthManager, User, Session) → **future `synvoid-auth` crate** (consumed by WAF)
- `src/admin/auth.rs` (admin token hashing, rate limiting) → **`synvoid-admin` crate** (this wave)

Rationale: WAF imports `AuthManager` from `src/auth/mod.rs:35`. Making WAF depend on `synvoid-admin` would be wrong. Admin token auth is admin-API-specific.

## CONT-F02: Scaffold synvoid-admin

Created `crates/synvoid-admin/` with:
- `Cargo.toml` — dependencies as specified
- `src/lib.rs` — crate root
- `src/auth.rs` — admin token hashing/verification + brute-force rate limiter (14 tests)
- `src/schema.rs` — OpenAPI schema helpers (DateTimeUtc, PathBufWrapper)
- `src/rate_limit.rs` — Admin rate limit Tower middleware layer

Added to workspace members and root dependencies.

## CONT-F03: Move OpenAPI/Schema Export

Moved to `synvoid-admin`:
- `DateTimeUtc`, `PathBufWrapper` schema types
- `hash_admin_token`, `verify_admin_token`, `AuthRateLimiter`
- `AdminRateLimitLayer`, `AdminRateLimitMiddleware`, `ClientIp`

Root shims created:
- `src/admin/schema.rs` → re-exports `DateTimeUtc`, `PathBufWrapper` from crate; keeps `AuditLog`/`ConfigVersion` schema impls (depend on root `audit.rs`)
- `src/admin/auth.rs` → re-exports all admin auth primitives from crate
- `src/admin/rate_limit.rs` → re-exports rate limit types from crate
- `src/admin/middleware.rs` → uses `synvoid_admin::rate_limit::ClientIp` (shared type)

**NOT moved:** `openapi.rs` (synvoidOpenApi type, #[openapi] macro) — references `crate::admin::handlers::*` in macro paths; cannot move to separate crate without moving all 26 handler modules.

`--export-openapi` and `--export-api-spec` preserved (unchanged in main.rs).

## CONT-F04: Move Admin Routes and State

**Stop condition hit:** `AdminState` directly owns supervisor internals:
- `ProcessState.process_manager: Option<Arc<ProcessManager>>`
- `ProcessState.plugin_manager: Option<Arc<PluginManager>>`
- `MeshState.mesh_transport: Option<Arc<MeshTransport>>`
- `WafTrackingState` with WAF tracker types
- `HoneypotState` with honeypot controllers

Per the task's stop condition: **defined admin-facing traits would be needed** to decouple AdminState from root types. This is deferred to a future wave.

What WAS moved:
- Self-contained types (auth, schema, rate limiting) that have no root dependencies
- `ClientIp` type shared between middleware and rate limiter

## Validation Results

```
cargo check -p synvoid-admin          ✅ (0 warnings in crate)
cargo test -p synvoid-admin           ✅ (14/14 tests pass)
cargo check --no-default-features     ✅ (core profile)
cargo check --no-default-features --features dns  ✅ (dns profile)
cargo check --no-default-features --features mesh  ❌ PRE-EXISTING (synvoid-mesh: 2476 errors, file not found + missing deps)
cargo check --no-default-features --features mesh,dns  ❌ PRE-EXISTING (same mesh errors)
```

## Files Changed

| File | Action |
|------|--------|
| `plans/auth_admin_boundary.md` | Created |
| `crates/synvoid-admin/Cargo.toml` | Created |
| `crates/synvoid-admin/src/lib.rs` | Created |
| `crates/synvoid-admin/src/auth.rs` | Created (moved from src/admin/auth.rs) |
| `crates/synvoid-admin/src/schema.rs` | Created (extracted from src/admin/schema.rs) |
| `crates/synvoid-admin/src/rate_limit.rs` | Created (extracted from src/admin/rate_limit.rs) |
| `Cargo.toml` | Added synvoid-admin to workspace + root deps |
| `src/admin/auth.rs` | Replaced with re-export shim |
| `src/admin/schema.rs` | Replaced with re-export + AuditLog/ConfigVersion impls |
| `src/admin/rate_limit.rs` | Replaced with re-export shim |
| `src/admin/middleware.rs` | Updated ClientIp to use crate's type |

## Blockers

1. **synvoid-mesh pre-existing breakage**: 2476 compilation errors in `crates/synvoid-mesh` prevent `--features mesh` profile checks. Not caused by this wave.
2. **AdminState deep coupling**: Full route/state migration requires admin-facing traits for ProcessManager, PluginManager, MeshTransport, WAF trackers. Deferred per stop condition.
3. **OpenAPI macro**: `#[openapi]` paths reference `crate::admin::handlers::*` — cannot move to crate without moving all handler modules.
