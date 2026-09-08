# Phase 18 Plan: Authentication and Challenge Boundary Extraction

Status: detailed handoff plan.

Roadmap position: Track 3, Phase 18 of `plans/roadmap.md`.

Primary goal: remove two high-value root dependencies that currently pin WAF and admin composition to the root crate by giving authentication/session logic and challenge orchestration clear domain ownership while preserving root compatibility paths.

## Context

`architecture/root_module_ledger.md` still classifies both `auth` and `challenge` as `split_required`.

Current state:

- `src/auth/mod.rs` is a substantial implementation containing authentication, sessions, CSRF, lockout, persistence, and related behavior.
- `src/challenge/mod.rs` already re-exports most primitives from `synvoid-challenge`, but still owns `ChallengeManager`, `ChallengeConfig`, attempt tracking, theme integration, and mesh-PoW composition.
- `src/waf/mod.rs::WafCore` directly imports `crate::auth::AuthManager` and `crate::challenge::{ChallengeConfig, ChallengeManager}`.
- admin handlers also depend on authentication/session behavior.

This phase should reduce those root dependencies before the WAF ownership phase. It is primarily an ownership move, not a redesign of authentication or challenge algorithms.

## Constraints

- Preserve all existing browser/admin authentication guarantees established by the completed admin corrective roadmap.
- Do not weaken CSRF, session-cookie, lockout, audit, or credential-storage behavior to simplify extraction.
- Do not expose long-lived bearer secrets to browser code.
- Preserve challenge cookie/session semantics and challenge ordering.
- Do not introduce a general identity/RBAC system; SynVoid's existing authority model remains unchanged.
- Preserve feature profiles and avoid root↔domain dependency cycles.
- Root public paths must remain available as compatibility facades unless semver/stability policy explicitly permits removal.

## Part A: Extract authentication into `synvoid-auth`

### A1. Dependency inventory

Inventory every dependency of:

- `src/auth/mod.rs`
- `src/auth/basic.rs`
- `src/admin/` authentication/session middleware and handlers
- WAF references to `AuthManager`
- any worker/HTTP references

Classify each dependency as:

- standard/library dependency appropriate for `synvoid-auth`
- shared DTO/config dependency already owned by a workspace crate
- root-only lifecycle/composition dependency
- accidental compatibility import that should be replaced with a dedicated-crate import

The root ledger currently indicates that authentication has very few true root dependencies. Confirm that before creating the crate.

### A2. Create the crate only if the dependency graph is clean

Preferred outcome: add `crates/synvoid-auth/` and move domain behavior there.

The crate should own, where applicable:

- `AuthManager`
- session creation/validation/invalidation
- CSRF token/session binding primitives
- failed-login accounting and lockout state
- basic-auth parser/validator helpers
- auth persistence formats and bounded cleanup behavior

It must not own:

- Axum router construction
- admin endpoint definitions
- root shutdown/supervisor orchestration
- browser UI
- mesh propagation

If one small lifecycle concern (for example a root drain flag) is the only blocker, replace the concrete root type with an existing low-level cancellation/drain abstraction or a narrow trait rather than importing the root crate.

### A3. Preserve compatibility facade

After migration, `src/auth/mod.rs` should become a thin compatibility facade plus genuinely root-only adapters, ideally:

```rust
//! Compatibility facade for `synvoid-auth`.
pub use synvoid_auth::*;
```

If a root adapter remains, ledger classification should become `keep_app_root` only when the remaining code is demonstrably process/composition logic. Do not leave a large mixed implementation under a new label.

### A4. Security regression coverage

Move/add tests for:

- session issuance and expiration
- logout/invalidation
- CSRF verification and session binding
- lockout threshold/window behavior
- cleanup bounds
- persistence corruption/failure behavior
- basic-auth parsing edge cases
- constant-time or password-hash verification behavior where already promised

Admin browser/session integration tests must continue to pass through the root facade/new crate.

## Part B: Complete challenge ownership

### B1. Inventory root challenge logic

For `src/challenge/mod.rs` and `src/challenge/mesh_pow.rs`, classify:

- core challenge manager behavior
- attempt/rate-limit state
- POW/CSS/honeypot selection
- theme/rendering dependencies
- mesh-PoW protocol/client behavior
- root-only runtime wiring

Most primitives already live in `synvoid-challenge`; the goal is to determine whether `ChallengeManager` is also domain logic rather than root composition.

### B2. Move `ChallengeManager` and configuration when feasible

Preferred outcome: `synvoid-challenge` owns `ChallengeManager`, `ChallengeConfig`, attempt tracking, and normal challenge rendering/orchestration.

It is acceptable for mesh-specific integration to remain behind a narrow adapter if moving it would make `synvoid-challenge` depend on the full root or mesh composition layer. In that case:

- define a small mesh-PoW service trait or data-only adapter in the challenge crate
- implement the adapter in root/mesh code
- keep mesh transport/discovery outside the challenge crate

Do not duplicate `ChallengeManager` into two implementations.

### B3. Keep rendering dependencies directional

If `synvoid-challenge` already depends cleanly on `synvoid-theme`, retain that dependency. Do not make the theme crate depend back on challenge.

Challenge response payload construction should remain deterministic and bounded. Preserve cookie names, TTLs, challenge attempt limits, and existing public behavior unless a bug is proven.

### B4. Migrate callers

Update WAF and HTTP code to import canonical challenge types from `synvoid_challenge` rather than root compatibility paths wherever crate boundaries permit.

Root application code may continue using the compatibility facade for external stability, but domain crates must not depend on `synvoid::*` compatibility imports.

## Part C: Architecture and dependency guards

Update:

- `architecture/root_module_ledger.md`
- `architecture/root_module_burndown_report.md`
- `architecture/root_dependency_ownership.md`
- `architecture/final_surface_audit.md`
- `architecture/semver_stability_policy.md` if stability labels change

Tighten guards so:

- `synvoid-auth` cannot import root `synvoid::*`
- `synvoid-challenge` cannot gain root imports
- root `auth` facade remains thin if classified `facade_existing_crate`
- WAF/admin domain code preferentially imports canonical crates

## Acceptance criteria

Phase 18 is complete when:

- authentication/session/CSRF/lockout domain behavior has one canonical owner
- `src/auth` is a thin compatibility facade or a precisely justified root adapter, not a duplicate implementation
- `ChallengeManager` and `ChallengeConfig` have one canonical owner
- any remaining mesh challenge adapter is narrow and does not force a root dependency into `synvoid-challenge`
- `WafCore` no longer requires root `crate::auth` or root challenge domain implementations solely because those types were never extracted
- admin authentication/session behavior remains functionally unchanged and security tests pass
- no raw secrets/session IDs are newly logged or exposed
- root module ledger and burn-down report agree on classifications and remaining blockers
- no domain crate imports root compatibility paths

## Rejection criteria

Reject an implementation that:

- creates `synvoid-auth` but leaves a second live session/lockout implementation in root
- moves Axum/admin routing into the auth crate
- weakens CSRF/session/browser guarantees
- creates a dependency cycle between challenge, WAF, HTTP, or root
- copies `ChallengeManager` rather than moving it
- moves mesh networking/discovery wholesale into `synvoid-challenge`
- removes public root exports without applying the repository stability policy

## Verification

At minimum run:

```bash
cargo fmt --all -- --check
cargo check
cargo check --no-default-features
cargo test -p synvoid-auth
cargo test -p synvoid-challenge
cargo test --test root_facade_boundary_guard
cargo test --test root_module_ledger_guard
cargo test --test root_dependency_ownership_guard
cargo test --test request_path_capability_boundary_guard
```

Also run the focused admin auth/session/CSRF tests and WAF challenge tests that cover the migrated call sites.
