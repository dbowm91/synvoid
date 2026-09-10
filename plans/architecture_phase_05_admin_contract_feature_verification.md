# Phase 05 — Admin Contract and Feature-Profile Verification

Status: implementation handoff plan
Baseline: completed admin-panel corrective roadmap and current admin route/client wiring

## Objective

Make future admin-panel drift mechanically detectable across backend route registration, frontend API calls, capability gating, WebSocket paths, API discovery/OpenAPI metadata, and supported feature profiles. Close the remaining low-severity logout state inconsistency at the same time.

This is a hardening phase, not a rewrite of the admin panel. The current panel is considered functionally wired; the purpose is to keep it that way as the route surface evolves.

## Current state

The backend registers roughly 240 admin endpoints across many route families. The frontend uses a same-origin `/api` client with HttpOnly session cookies and CSRF, WebSockets use canonical `/api/ws/metrics` and `/api/ws/logs` paths, and sidebar capability gating reads `/api/system/capabilities`.

Existing tests cover important historical contract failures such as worker restart path mismatch, ICMP method mismatch, router composition, auth/session behavior, and mutation response shape. However, the complete route/client/capability matrix remains multiply authored and therefore can drift as new features are added.

A small auth-state residual remains: `ApiService::logout()` clears CSRF state before a failed non-401/403 logout is fully resolved, while root `AuthState` may remain authenticated. This is not an auth bypass but can leave the UI in an inconsistent state until another request reconciles it.

## Scope

- `src/admin/mod.rs`
- `src/admin/handlers/api_discovery.rs`
- `src/admin/openapi.rs` and Utoipa annotations where relevant
- `src/admin/middleware.rs`
- `crates/synvoid-admin/src/handlers/*`
- `admin-ui/src/services/api.rs`
- `admin-ui/src/hooks/use_websocket.rs`
- `admin-ui/src/components/layout/sidebar.rs`
- admin UI pages with direct endpoint usage
- `tests/admin_route_contract.rs`
- `tests/admin_router_composition.rs`
- `tests/admin_smoke_flow.rs`
- mutation/auth/admin verification tests
- CI/workflow feature checks
- admin API/UI documentation

## Work plan

### 1. Establish a canonical machine-checkable route inventory

Do not introduce a large code-generation framework. Prefer a small test-only/static inventory derived from or compared against the actual Axum route registration and existing API-discovery metadata.

For every admin endpoint relevant to the UI, capture at minimum:

- path template;
- HTTP method or WebSocket transport;
- auth classification (public/session/bearer/per-connection);
- CSRF requirement for mutations;
- feature gate/capability name if optional;
- whether the frontend currently consumes it.

The inventory should make it possible for a test to fail when the frontend calls a path/method absent from the backend or when a capability advertises an unavailable route family.

### 2. Make frontend endpoint usage discoverable

Centralize remaining direct REST endpoint strings into `ApiService` methods where doing so improves contract visibility. Do not force purely local UI routes into the API layer.

For WebSockets, retain a small canonical constant/function set for `/api/ws/metrics` and `/api/ws/logs` if this reduces duplication across hooks/pages/tests.

Ensure query-building uses proper URL encoding for user-controlled values. Where current code manually concatenates request-log filters, replace only if needed with a lightweight encoding helper already available in the workspace/browser stack; do not add a heavy URL framework solely for this.

### 3. Extend route-contract tests toward exhaustive UI coverage

Enhance `admin_route_contract` or add a companion test that asserts every frontend-consumed endpoint has a backend route with the expected method under the appropriate feature profile.

At minimum cover:

- auth session create/restore/logout;
- stats/dashboard endpoints;
- sites CRUD and site subresources;
- upstreams;
- config read/write families used by settings pages;
- workers/supervisor/process controls;
- alerts;
- probes/threat-level/rule-feed;
- capability endpoint;
- WebSocket metrics/log paths;
- DNS/mesh/ICMP/tier-key/serverless/plugin families when compiled.

Tests must fail for a path singular/plural typo, wrong method, missing `/api` namespace, stale feature gate, or frontend-only route.

### 4. Cross-check capability reporting against compiled route families

For each capability surfaced by `/system/capabilities`, assert one of:

- capability `true` and its canonical route family is registered; or
- capability `false` and the feature-specific route family is absent/returns the documented unsupported behavior.

Do not allow capability flags to be maintained independently from compile-time/runtime availability without tests.

Sidebar behavior should be tested at the data/decision level where practical rather than requiring a fragile full-browser screenshot suite.

### 5. Verify API discovery/OpenAPI consistency

Compare actual route inventory against API discovery and Utoipa/OpenAPI coverage for operator-facing endpoints.

Do not require OpenAPI to model WebSocket semantics as ordinary HTTP if that is inaccurate; represent/document WS separately.

The goal is to catch stale docs/metadata, not to force every internal/private endpoint into public API documentation.

### 6. Normalize logout failure state

Change logout behavior so client authentication state and CSRF state transition atomically from the UI's perspective.

Preferred semantics:

- on successful logout: clear CSRF + set unauthenticated;
- on server-confirmed 401/403/session-invalid state: clear CSRF + set unauthenticated;
- on network/5xx/non-auth failure where the session may still be valid: either retain CSRF/auth state and report the error, or perform an explicit session revalidation before choosing state.

Do not clear the only mutation credential while telling the root UI it remains authenticated.

Add tests for success, 401/403, 5xx, and network-error state transitions where feasible.

### 7. Rationalize feature-profile CI

Use the repository's existing explicit matrix as the starting point. Add only combinations that represent real optional admin route/capability behavior and are not already covered.

At minimum preserve checks for:

- default;
- `--no-default-features`;
- mesh;
- dns;
- icmp-filter;
- mesh + dns.

Evaluate `cargo-hack check --each-feature` or a bounded `--feature-powerset --depth N` only if it replaces manual duplication and fits current CI latency goals. Cargo feature testing is combinatorial; full powerset is not automatically appropriate for a large workspace. The repository previously simplified CI, so do not reintroduce an expensive exhaustive matrix without evidence.

If `cargo-hack` is adopted, document included/excluded/mutually dependent features and keep the job compilation-oriented (`cargo check`) unless behavior tests are needed for a specific profile.

### 8. Add regression checks for admin auth/middleware classification

Ensure public/auth/WebSocket/protected route classification cannot drift silently.

Tests should assert:

- SPA/public health routes are not incorrectly forced through admin auth;
- session bootstrap/CSRF endpoints have intended auth semantics;
- protected REST routes require valid session/bearer auth;
- state-changing REST routes require CSRF for browser session use;
- WebSockets authenticate per connection/session and are not accidentally exposed by middleware exclusions;
- middleware exclusions are exact enough not to create broad prefix bypasses.

### 9. Update docs and closeout evidence

Update `docs/ADMIN_UI.md`, API reference/architecture docs, and admin agent guidance only after code/tests establish canonical behavior.

Add a final phase closeout section/file recording:

- routes/profile matrix tested;
- test commands and results;
- any intentionally uncovered feature combinations;
- known residuals with owner/rationale.

## Rejection criteria

Reject an implementation that:

- creates a second hand-maintained giant route list without comparing it mechanically to real registration;
- generates Axum routing from OpenAPI metadata if doing so obscures middleware/feature composition;
- relies on browser E2E tests alone for route-contract correctness;
- duplicates endpoint aliases solely to satisfy stale frontend paths;
- advertises capability `true` for an absent route family;
- treats WebSockets as public merely because blanket REST middleware is skipped;
- expands CI back into a high-latency full feature powerset without measured benefit;
- clears CSRF/auth state inconsistently after recoverable logout failure.

## Acceptance criteria

1. Every endpoint consumed by the admin UI is mechanically checked against backend path + method registration.
2. Optional capabilities are checked against compiled/registered route families.
3. Canonical WebSocket paths are covered by the same contract guard or a focused equivalent.
4. API discovery/OpenAPI metadata drift for operator-facing REST endpoints is detectable.
5. Logout success/auth-failure/non-auth-failure transitions leave `AuthState` and CSRF state coherent.
6. Default and selected feature profiles compile/test with a documented, intentionally bounded matrix.
7. Existing admin smoke, route, router-composition, auth, and mutation tests remain green.
8. No historical compatibility aliases are reintroduced.

## Verification

Run at minimum:

```text
cargo fmt --all -- --check
cargo clippy --profile ci --all-targets -- -D warnings
cargo test --test admin_route_contract --profile ci
cargo test --test admin_router_composition --profile ci
cargo test --test admin_mutation_response_guard --profile ci
cargo test --test admin_smoke_flow --profile ci
cargo check --no-default-features --profile ci
cargo check --no-default-features --features mesh --profile ci
cargo check --no-default-features --features dns --profile ci
cargo check --no-default-features --features icmp-filter --profile ci
cargo check --no-default-features --features mesh,dns --profile ci
cd admin-ui && cargo check
```

If a bounded `cargo-hack` job is added, document the exact command in CI and remove equivalent redundant checks where safe so the net CI complexity does not increase unnecessarily.
