# Admin Panel Phase 1 — Router Composition, Feature Boundaries, and Static Application Delivery

## Status

**PLANNED**

## Objective

Establish one deterministic admin router whose route set is unambiguous under default and reduced feature profiles, whose public/static surface can load before authentication, whose protected API remains protected, and whose SPA assets/routes are served independently of the daemon's current working directory.

This phase is foundational. Do not begin broad frontend endpoint repair until the router can be constructed reliably and the integrated browser shell can actually be reached.

## Scope

Primary files expected to change:

- `src/admin/mod.rs`
- `src/admin/middleware.rs` only where public/protected route classification needs a narrow interface adjustment
- `src/admin/handlers/api_discovery.rs`
- `src/admin/handlers/system.rs` or the canonical equivalent only if capability reporting needs correction
- `admin-ui/src/app.rs`
- `admin-ui/src/components/sidebar.rs`
- `admin-ui/Trunk.toml` and packaging/static-asset support as needed
- focused tests under the existing admin/root test locations
- admin architecture/docs only where they describe the corrected route/delivery contract

Do not change WAF request behavior, mesh transport semantics, DNS implementation, process architecture, or CI topology in this phase.

## Baseline problems

### Duplicate route registrations

The current router registers multiple same-method canonical routes. At minimum:

- `/config/supervisor` GET/PUT is registered in more than one place.
- `/system/supervisor` GET is registered more than once in the default mesh-enabled route chain.
- `/mesh/attest-capability` POST is registered more than once.

Axum route collisions must be removed at source. Do not depend on handler registration order.

### Static/login shell is behind authentication

The router currently applies auth middleware around a `ServeDir("admin-ui/dist")` fallback. Public exemptions do not include `/`, `/login`, or the built JS/WASM/CSS assets. The integrated server therefore cannot reliably bootstrap an unauthenticated browser into the login application.

### Accidental feature scoping

A large route chain sits beneath `#[cfg(feature = "mesh")]` even though parts of the chain are not mesh features. ICMP, system status/workers, alerts, theme, authentication/session, WebSockets, and other unrelated admin behavior must not disappear solely because `mesh` is absent.

### Static path and BrowserRouter fragility

`ServeDir("admin-ui/dist")` is process-CWD-relative. Direct navigation to a client-side route also requires an explicit SPA fallback to the application shell.

### Feature-blind navigation

The frontend advertises feature-specific pages without a canonical capability check, which turns valid reduced builds into visible 404/unsupported controls.

## Implementation plan

### 1. Inventory and classify every admin route

Before editing registration, build a small source-level route inventory from `build_router_from_state()` grouped into:

- public transport/bootstrap routes
- authenticated core routes available regardless of mesh/DNS/ICMP feature selection
- `dns` routes
- `mesh` routes
- `icmp-filter` routes
- any runtime-optional routes whose build feature is always present but whose manager/handle can be absent

This inventory is implementation guidance, not a new permanent route registry unless a small test helper naturally falls out of it.

The classification must resolve every duplicate route to one canonical registration and one canonical handler.

### 2. Remove duplicate registrations

For each duplicate:

- determine which handler is canonical based on current types/semantics
- retain exactly one registration for that method/path
- delete stale duplicate discovery metadata and stale frontend/client aliases if present
- if two handlers expose materially different information under the same path, rename one path only when both semantics are actually required; do not silently discard useful distinct behavior

Special attention:

- reconcile the two `/system/supervisor` handlers (`get_supervisor_status` vs `get_supervisor`) rather than arbitrarily selecting one
- ensure `/config/supervisor` has one GET and one PUT registration
- ensure `/mesh/attest-capability` has one POST registration

### 3. Separate public application delivery from authenticated API enforcement

Refactor router composition so authentication middleware does not need a growing path exception list for SPA files.

Preferred shape:

- a public outer/static router serving the application shell and immutable/static frontend assets
- an `/api` router containing protected API routes plus explicitly public API endpoints such as health/OpenAPI/session bootstrap as appropriate
- authentication/CSRF layers scoped to protected API routes rather than to arbitrary filesystem fallbacks
- WebSocket authentication handled by the WebSocket/session contract rather than by a blanket public bypass

`POST /api/auth/session` necessarily accepts the presented bearer token before a session exists; it must be reachable without an existing session while validating the supplied bearer itself.

Do not make unrelated API endpoints public merely to simplify nesting.

### 4. Correct feature-gate boundaries

Move each route registration beneath only the feature gate that genuinely owns it.

Required outcomes:

- auth/session, theme, core stats, system information, alerts, and other non-mesh admin routes remain present in non-mesh builds when their underlying implementation is available
- mesh-only handlers/routes are compiled and registered only with `mesh`
- DNS config endpoints are registered only with `dns`
- ICMP endpoints use the actual `icmp-filter` feature boundary rather than piggybacking on `mesh`
- frontend capabilities can distinguish build-time absence from runtime manager-unavailable states

Avoid broad cfg blocks spanning unrelated chains. Prefer short feature-specific router extension blocks.

### 5. Establish deterministic static asset location

Remove dependence on the process current working directory.

Choose the smallest deployment-appropriate solution:

- preferred if practical: embed the production admin UI assets in the binary/build artifact, or
- otherwise resolve an explicit installation/config-relative asset root that is stable regardless of CWD

Do not add a general-purpose asset framework for this.

If external files remain required, startup must produce a clear error/warning identifying the resolved path when the built admin assets are absent rather than silently serving 404s.

### 6. Add SPA fallback behavior

For non-API browser GETs that do not correspond to an existing static asset, serve `index.html` so BrowserRouter deep links such as `/settings`, `/sites/<id>`, and `/mesh` can bootstrap normally.

Constraints:

- `/api/...` misses must remain API 404s and must never receive `index.html`
- missing static assets with recognizable asset paths should not be rewritten into HTML in a way that creates MIME/type confusion
- the fallback applies to browser application routes only

### 7. Make capability reporting authoritative enough for navigation

Use the existing `/system/capabilities` surface or a similarly narrow existing endpoint as the source for feature availability.

It must provide at least enough information for the SPA to know whether to expose:

- mesh administration
- DNS administration
- ICMP filter administration
- honeypot controls if runtime-optional
- process/worker controls when the process manager is absent
- any other page whose backend can legitimately be unavailable

Do not introduce a second manually maintained giant endpoint list. Capabilities describe feature availability, not every route.

### 8. Capability-gate frontend navigation

Update the sidebar/app route presentation so unavailable feature pages are hidden or clearly disabled based on capabilities. A direct URL to an unavailable page must resolve to a deliberate unavailable/not-found state rather than endlessly loading or repeatedly issuing 404s.

The login route itself must not depend on an authenticated capabilities call.

### 9. Reconcile API discovery with the actual router

`src/admin/handlers/api_discovery.rs` currently contains stale and duplicate entries. In this phase:

- remove known duplicate entries
- remove entries for routes that do not exist yet
- do not re-add `/config/mesh` or tier-key routes until Phase 3 actually registers them
- ensure feature-specific discovery does not claim unavailable build features

If the current manual discovery file is too error-prone, reduce it to a small, clearly scoped discovery response and rely on OpenAPI for endpoint-level detail. Do not build a code generator.

## Focused tests

Add only tests that prevent recurrence of the composition defects.

### Router construction tests

Construct `build_router_from_state()`/public router through testable helpers for supported profiles. At minimum prove:

- default feature router constructs without panic
- core/no-default feature router constructs without panic
- mesh-only profile constructs without panic
- dns-only profile constructs without panic
- mesh+dns constructs without panic

Where cargo feature compilation prevents one test binary from covering all profiles, provide one focused test target plus explicit cargo commands per profile rather than a matrix framework.

### Public/protected delivery tests

Using Axum `oneshot`/service tests where possible:

- `GET /` succeeds without auth and returns the admin shell
- a built asset path succeeds without auth
- a valid deep SPA route returns the shell
- `GET /api/stats/summary` without auth is rejected
- `POST /api/auth/session` is reachable and performs its own bearer validation rather than being blocked by pre-session middleware
- `/api/does-not-exist` returns an API 404, not the SPA shell

### Feature-boundary tests

For each compiled profile, assert presence/absence of representative routes consistent with the feature, especially that non-mesh core routes remain available when mesh is disabled.

## Acceptance criteria

Phase 1 is complete only when:

- no duplicate same-method route registration remains in `src/admin/mod.rs` for the known collisions or any newly discovered collision
- default-feature admin router construction succeeds without panic
- all required reduced feature profile checks compile and their router-construction test succeeds
- `/`, `/login` or equivalent application route, and built SPA assets can be loaded without prior authentication
- protected API reads/mutations remain protected
- session bootstrap remains reachable without an existing session but rejects invalid/missing bearer credentials itself
- direct reload of at least `/settings` and one parameterized application route returns the SPA shell
- missing `/api/*` paths never receive `index.html`
- the static asset root is deterministic and independent of process CWD, demonstrated by a test or local launch from a non-repository working directory
- non-mesh builds still expose core authentication/session, theme, stats/system, and alerting routes when those modules are otherwise available
- ICMP routes are gated by the ICMP feature, not by mesh
- DNS and mesh routes are present only when their owning feature is compiled
- capability reporting accurately represents at least mesh/DNS/ICMP/process-manager availability
- frontend navigation does not show controls for build-time unavailable capabilities
- `api_discovery` contains no duplicate canonical entries and does not advertise the currently unwired mesh-config/tier-key routes before Phase 3
- no new broad route registry/code-generation layer or admin-specific CI workflow is introduced

## Rejection criteria

Reject this phase if it:

- makes all static and API paths public
- keeps a blanket auth middleware around static assets and merely adds a long list of asset exceptions
- fixes collisions by changing methods/paths without reconciling handler semantics
- moves all routes out from behind feature gates regardless of whether their code compiles
- hard-codes a developer workstation path to `admin-ui/dist`
- rewrites API 404s to the SPA shell
- introduces an endpoint-generation subsystem larger than the problem being solved
- leaves capability-blind sidebar entries that knowingly target unavailable routes

## Verification commands/evidence

Record the exact final commands used. Expected minimum:

```bash
cargo check --no-default-features --profile ci
cargo check --no-default-features --features mesh --profile ci
cargo check --no-default-features --features dns --profile ci
cargo check --no-default-features --features mesh,dns --profile ci
cargo test --profile ci <focused-admin-router-test-target>
```

Also perform one local integrated launch from a directory other than the repository root and verify the application shell/assets still load from the configured/embedded location.

Do not run or modify the entire CI apparatus solely for this phase.
