# Admin Panel Runtime Closure Corrective Pass

## Status

**PLANNED**

## Baseline

This is a narrow corrective pass against current `main` at:

```text
48ce1bb6676e87ab3b968dc017b2cbd669677546
admin: final corrective closure — auth state, WS paths, discovery, honeypot, UTF-8, secure-cookie
```

It follows:

- `plans/admin_panel_corrective_roadmap.md`
- `plans/admin_panel_phase_01_router_and_delivery.md`
- `plans/admin_panel_phase_02_browser_auth_security.md`
- `plans/admin_panel_phase_03_api_contract_and_wiring.md`
- `plans/admin_panel_phase_04_realtime_and_operator_state.md`
- `plans/admin_panel_phase_05_alerting_and_outbound_security.md`
- `plans/admin_panel_phase_06_verification_and_closeout.md`
- `plans/admin_panel_final_corrective_closure.md`

Most of the original admin-panel defects are now fixed. The current remaining work is concentrated at the browser/runtime boundary and in the quality of the final proof. The prior corrective pass fixed important backend and API details but marked the roadmap complete before satisfying its own runtime acceptance criteria.

This plan exists only to close those remaining gaps. It is not a new roadmap and must not reopen completed work.

## Current remaining issues

The implementation agent should begin by confirming these against current `main` before changing code. If a listed issue has already changed on the working branch, adapt the implementation while preserving the acceptance criteria.

### R1 — Unauthenticated application routes still render protected UI

Current `admin-ui/src/app.rs` uses a root `AuthState`, but the `Unauthenticated` branch still renders the same `Switch<Route>` as the authenticated application. `Route::Home` and `Route::Dashboard` map directly to `<Dashboard />`.

Consequences:

- a fresh unauthenticated request to `/` can render dashboard UI instead of the login UI
- page components can start protected API activity even though session restoration failed
- the route guard promised by the prior plan does not exist
- the apparent UI state and server authentication state can diverge immediately on startup

### R2 — Session expiry does not transition the root Yew application

`ApiService::handle_auth_error()` currently clears in-memory CSRF state and returns an `ApiError` for 401/403. The old redundant thread-local auth boolean was removed, but no replacement signal connects API-level session expiry to the root `App` `AuthState`.

Consequences:

- the application can remain visually `Authenticated` after the server session has expired
- dashboard/pages can continue polling/fetching after session invalidation
- realtime reconnect/polling paths can continue to run
- repeated unauthorized requests can accumulate against auth/rate-limit behavior
- the previous “single authoritative auth state” claim is incomplete because the authority is not notified of session failure

### R3 — Logout client behavior still ignores the server outcome

`ApiService::logout()` now correctly sends CSRF and credentials, which closes the original protocol bug. However the root logout callback still intentionally ignores the result:

```rust
let _ = ApiService::logout().await;
auth_state.set(AuthState::Unauthenticated);
```

The browser may choose to return to login when the session is already invalid, but it must distinguish that condition from an unrelated server/network failure. Closure documentation must not claim server invalidation when no successful invalidation was observed.

### R4 — WebSocket path code is fixed, but proof is stale and can pass on 404

The server now uses canonical:

- `/api/ws/metrics`
- `/api/ws/logs`

The current `tests/admin_smoke_flow.rs` still contains a WebSocket test against `/ws/metrics` and only asserts the response is not HTTP 200. A 404 therefore passes.

The current test does not prove:

- canonical WS route registration
- session-cookie authenticated upgrade reaches the handler
- logs WS route exists
- bearer upgrade behavior, if retained
- the old route family is absent intentionally
- the browser actually reaches `Connected` instead of silently using HTTP polling

### R5 — The route-contract guard was not expanded to the promised production surface

`tests/admin_route_contract.rs` was not materially expanded by the last corrective pass. The closure record itself acknowledges that exhaustive coverage was deferred.

At minimum, the guard still needs explicit coverage for the production HTTP/WebSocket paths that previously drifted, including:

- create/restore/delete session
- canonical metrics/logs WebSockets
- discovery `/api`
- negative `/api/api`
- negative legacy `/ws/*`
- Supervisor status/config
- worker restart path
- ICMP PUT path
- Mesh config path when enabled
- Tier Key mutations when enabled

This must remain a small, finite contract guard. Do not build a general Rust parser, OpenAPI code generator, or frontend code-generation system for this pass.

### R6 — Secure-cookie policy is explicit only when configured; default still infers HTTPS from bind address

`AdminConfig.secure_cookie: Option<bool>` is a useful improvement, but `None` still falls back to `is_external_bind(&admin_bind_address)`.

That means the default still assumes:

- non-loopback listener implies HTTPS/reverse proxy
- loopback listener implies plaintext HTTP

Neither assumption is transport truth. A remote plaintext listener can get an unusable Secure cookie, while a TLS proxy forwarding to loopback can get a non-Secure cookie unless explicitly configured.

The prior acceptance criteria required the transport contract to be explicit rather than derived from bind address.

### R7 — The recorded “integrated smoke” is a router integration test, not the required runtime/browser smoke

`tests/admin_smoke_flow.rs` uses `create_admin_router()` plus `tower::ServiceExt::oneshot`. This is valuable integration coverage, but it does not execute:

- the actual SynVoid runtime launch path
- the compiled Trunk/Yew browser bundle
- browser routing behavior
- browser cookie semantics
- local/session storage behavior
- browser WebSocket state transitions
- `ws://` vs `wss://` derivation under real origin state
- reverse proxy behavior

Several test steps explicitly use stand-ins such as `/health` for “app shell loads” or accept `200 || 404`, which is too weak for closeout evidence.

### R8 — HTTPS/reverse-proxy acceptance smoke was never executed

The current closure record labels HTTPS/proxy smoke as a manual residual. The prior plan allowed it to be manual, but did not allow it to be skipped.

The final pass needs actual local evidence for:

- Secure HttpOnly session cookie under HTTPS
- `wss://` derivation
- canonical WebSocket operation through the proxy
- no mixed-content failure
- trusted proxy forwarded-client identity
- rejection/ignoring of spoofed forwarded headers from untrusted peers
- logout through the secure origin

### R9 — Planning state is currently optimistic

`admin_panel_corrective_roadmap.md` and `admin_panel_final_corrective_closure.md` are marked `COMPLETE`, while the browser/runtime acceptance criteria above are not satisfied.

Do not rewrite historical files immediately. Correct code and produce runtime evidence first. Only then reconcile status truthfully.

## Goals

This pass is complete when:

1. unauthenticated browsers cannot render protected application routes
2. root application auth state is the single visible authority and is notified on server-session expiry
3. expired sessions stop background work rather than generating repeated unauthorized traffic
4. logout outcome is handled intentionally and server invalidation is proven where claimed
5. canonical WebSocket paths have positive authenticated handshake coverage and negative legacy-path coverage
6. the finite production route-contract guard covers the high-risk path families that previously drifted
7. Secure-cookie behavior uses an explicit transport policy with no silent bind-address inference
8. the production admin UI bundle is built using the supported Yew/Trunk workflow
9. an actual local runtime/browser smoke is executed and recorded
10. an actual HTTPS/reverse-proxy smoke is executed and recorded
11. roadmap/closure documents are only marked complete after those proofs pass on the exact final commit

## Non-goals / constraints

- Do not add RBAC, multi-user auth, OAuth/OIDC, or a new identity model.
- Do not redesign the session store.
- Do not persist the long-lived admin bearer token in browser storage or JavaScript-readable cookies.
- Preserve bearer-token authentication for legitimate non-browser API clients.
- Preserve CSRF requirements for cookie-authenticated mutations.
- Do not weaken rate limiting to hide repeated-session-failure behavior.
- Do not create a Redux-like state framework, generic event bus, or broad global store solely for auth.
- Do not add a browser farm, Playwright/Selenium matrix, admin-specific hosted CI workflow, new release gate, or external testing service.
- Do not add a generalized route parser/code generator.
- Do not reopen the webhook DNS-rebinding work beyond maintaining the existing truthful residual documentation unless a directly relevant regression is found.
- Do not reopen completed Mesh/Honeypot/API-discovery fixes unless verification finds a concrete regression.
- Keep production code changes small and localized.

---

# Workstream 1 — Enforce the root browser auth boundary

## 1.1 Introduce an actual unauthenticated route guard

Refactor `admin-ui/src/app.rs` so that authenticated and unauthenticated routing are not the same switch.

Required behavior:

- while `AuthState::Restoring`, render only the restoration/loading UI
- when `AuthState::Unauthenticated`, `/login` renders `<Login />`
- when `AuthState::Unauthenticated`, `/`, `/dashboard`, and every other application route resolve to `/login` or directly render the login page without mounting protected page components
- when `AuthState::Authenticated`, `/login` redirects to `/` or `/dashboard`
- authenticated application routes render normally
- no redirect loop occurs
- direct navigation to a nested route such as `/settings`, `/workers`, or `/mesh` after a fresh load must restore the session first and either render that route after successful restore or move to login after failed restore

Preferred implementation options:

1. separate authenticated and unauthenticated switch functions at the root, or
2. a small root-level route guard component that receives `AuthState`

Do not add per-page auth checks.

## 1.2 Keep the application shell from mounting while unauthenticated

The Sidebar, realtime header, dashboard, polling components, and protected page hooks must not mount merely because the browser navigated to a protected URL while unauthenticated.

Acceptance probe:

- fresh browser profile at `/dashboard` with no session must show login and must not begin dashboard API/WebSocket traffic

## 1.3 Login transition must update root state directly

Inspect the current Login component flow. Successful login must notify the root application that authentication succeeded rather than relying solely on location reload side effects.

A page reload after login is acceptable if the existing architecture deliberately restores the session from the HttpOnly cookie, but the flow must remain deterministic and must not retain the bearer token.

Preferred shape:

- root passes a small `Callback<()>` / `Callback<AuthState>` to Login
- Login calls it after successful session bootstrap
- root navigates to the intended route or default dashboard

If a reload-based approach is retained, document why and prove no token persistence occurs.

### Workstream 1 acceptance criteria

- unauthenticated `/` does not render Dashboard
- unauthenticated `/dashboard` does not render Dashboard
- unauthenticated nested routes do not mount protected page components
- `/login` works unauthenticated
- authenticated `/login` does not expose a second login form unnecessarily
- session restoration gates route rendering
- no long-lived bearer token is stored after login

---

# Workstream 2 — Propagate session expiry to root auth state

## 2.1 Add one small auth-expiry notification path

The root `AuthState` should remain the UI authority. Add the smallest mechanism that allows API/realtime code to say “this browser session is no longer valid.”

Preferred patterns, in order:

1. Yew context containing a narrowly scoped `on_session_expired` callback
2. a tiny browser-auth context with current state plus transition callback
3. another local mechanism that keeps ownership at the root and does not become a general event framework

Avoid a global mutable boolean disconnected from Yew state.

## 2.2 Differentiate auth expiry from ordinary request failure

`ApiError` should preserve enough classification for callers/root plumbing to distinguish:

- 401 session invalid/expired
- cookie-authenticated 403 that semantically indicates session/CSRF invalidation
- ordinary 403 application authorization/policy failure, if any such cases exist
- network failure
- unrelated 4xx/5xx

Given the current single-admin model, a simple explicit session-expired variant/flag is sufficient. Do not over-generalize an error taxonomy.

Do not automatically treat every future 403 as “log out” without reviewing server semantics.

## 2.3 Stop background work on session expiry

When the root transitions to `Unauthenticated`:

- realtime WebSockets must close or cease reconnect attempts
- HTTP polling intervals must be cancelled
- new protected fetch effects must not mount because the protected route tree is unmounted
- current requests may finish, but their failures must not schedule more work
- login UI should appear once

This should naturally fall out of unmounting authenticated components plus the existing cleanup behavior. Prefer that to adding a large cancellation subsystem.

## 2.4 Avoid auth-lockout amplification

Add focused coverage or instrumentation proving one expired browser session does not generate enough repeated auth failures to trivially hit the five-attempt lockout through its own mounted polling/reconnect loops.

The fix should be stopping stale browser work, not raising the lockout threshold.

### Workstream 2 acceptance criteria

- force an active browser session invalid/expired
- first protected 401/session-expiry signal transitions root state to unauthenticated
- protected route tree unmounts
- polling/reconnect loops stop
- browser returns to login once
- no burst of repeated requests drives the test client into auth lockout
- re-login with valid token succeeds after normal expiry handling

---

# Workstream 3 — Make logout outcome explicit

## 3.1 Preserve the corrected CSRF-aware DELETE

Keep browser logout using:

- `DELETE /api/auth/session`
- current CSRF token
- session cookie credentials

Do not add a CSRF exemption.

## 3.2 Classify logout results

Root logout behavior should intentionally handle at least:

### Success

- server invalidates session
- server expires session cookie
- client clears CSRF state
- root becomes unauthenticated
- browser navigates to login

### Session already invalid / unauthorized

It is acceptable to clear local state and return to login because there is no valid browser session to preserve.

### Network or unrelated server failure

Choose one deliberate behavior:

- show a bounded logout error and remain in authenticated UI until server state is known, or
- fail closed to login but clearly log/display that remote invalidation was not confirmed

The implementation and documentation must not claim successful server invalidation when the DELETE was not confirmed.

## 3.3 Keep server lifecycle regression coverage

The existing router integration should continue to prove:

1. session can access protected API
2. logout without CSRF fails
3. logout with CSRF succeeds
4. old session fails afterward
5. old CSRF cannot authorize mutations afterward

### Workstream 3 acceptance criteria

- successful logout invalidates server session
- reload does not restore logged-out session
- failed/unconfirmed logout is not silently represented as confirmed server invalidation
- client auth state is cleared on valid “already unauthenticated” cases

---

# Workstream 4 — Replace stale WebSocket proof with positive contract coverage

## 4.1 Update `tests/admin_smoke_flow.rs`

Remove/replace tests that call legacy `/ws/metrics` and merely assert “not 200.”

Add positive canonical checks for:

- `/api/ws/metrics`
- `/api/ws/logs`

At router level, construct a valid WebSocket upgrade request with required headers (`Connection`, `Upgrade`, `Sec-WebSocket-Version`, `Sec-WebSocket-Key`) and authentication.

Prove:

- unauthenticated canonical upgrade is rejected
- session-cookie authenticated canonical upgrade reaches upgrade handling and does not 404
- bearer authenticated canonical upgrade reaches upgrade handling if bearer WS auth remains supported
- logs and metrics endpoints both exist
- `/ws/metrics` and `/ws/logs` are absent if no compatibility aliases are intended

Do not count an arbitrary non-200 response as success.

## 4.2 Keep HTTP polling fallback separate

The fallback polling tests should prove fallback behavior independently. They must not be used as evidence that WebSockets function.

## 4.3 Browser smoke must demonstrate live WebSocket state

The runtime smoke later in this plan must verify that the frontend reaches its `Connected`/live state for metrics using the canonical route before any deliberate fallback scenario is tested.

Open the Logs page and verify the logs WS path reaches the server as well.

### Workstream 4 acceptance criteria

- canonical metrics WS has positive authenticated handshake evidence
- canonical logs WS has positive authenticated handshake evidence
- unauthenticated canonical WS is rejected
- legacy WS routes are negative fixtures
- browser runtime proves metrics is not silently operating only by polling

---

# Workstream 5 — Expand the finite admin route-contract guard

## 5.1 Keep the guard explicit and bounded

Update `tests/admin_route_contract.rs` or add one narrowly scoped adjacent test module. Do not introduce route-generation infrastructure.

The guard should have a finite table of production operations with method + canonical path.

## 5.2 Required contract entries

Include at minimum:

### Auth

- `POST /api/auth/session`
- `GET /api/auth/csrf`
- `DELETE /api/auth/session`

### Discovery

- `GET /api`

### Realtime

- WS `/api/ws/metrics`
- WS `/api/ws/logs`

### Supervisor/workers

- `GET /api/system/supervisor`
- `GET /api/config/supervisor`
- `PUT /api/config/supervisor`
- `POST /api/system/workers/{worker_id}/restart`

### ICMP when compiled

- `GET /api/icmp/config`
- `PUT /api/icmp/config`
- `POST /api/icmp/enable`
- `POST /api/icmp/disable`

### Mesh/Tier Keys when compiled

- `GET /api/config/mesh`
- `PUT /api/config/mesh`
- `GET /api/tier-keys`
- `POST /api/tier-keys/issue`
- `POST /api/tier-keys/revoke`
- `POST /api/tier-keys/unbind`

### Representative core operations

- one Site mutation
- one Threat Level mutation
- Alerts config/test-webhook
- Capabilities

## 5.3 Required negative fixtures

The contract test must explicitly reject at least:

- `/api/api`
- `/ws/metrics`
- `/ws/logs`
- `/api/system/worker/{id}/restart`
- `/api/system/overseer`
- `/api/config/overseer`
- `POST /api/icmp/config`

## 5.4 Validate actual client literals where practical

If production endpoint paths are already centralized enough to import into tests, use those constants. If they are scattered page-local literals, do not perform a broad refactor unless necessary.

A small frontend `routes`/`endpoints` module is acceptable if it reduces obvious drift and can be introduced without touching every endpoint in the admin application.

The objective is to guard historically unstable boundaries, not achieve theoretical route deduplication across the entire project.

### Workstream 5 acceptance criteria

- the canonical WS mismatch that previously survived would now fail the guard
- `/api/api` regression would fail the guard
- wrong worker/overseer/ICMP forms fail the guard
- feature-specific entries are compiled/tested under their appropriate profiles

---

# Workstream 6 — Make secure-cookie transport policy fully explicit

## 6.1 Remove bind-address inference from the default runtime decision

Do not use `is_external_bind()` as the default authority for whether the browser-facing origin is HTTPS.

Preferred minimal design:

```rust
pub secure_cookie: bool
```

with a clearly documented default chosen for the repository's supported deployment model, or an explicit small enum such as:

```rust
pub enum AdminTransportSecurity {
    Http,
    HttpsProxy,
}
```

If preserving `Option<bool>` is important for configuration compatibility, then `None` must resolve to a documented deterministic policy that is not based on bind address.

Examples:

- `None => false` for backward-compatible local HTTP, while docs require `secure_cookie = true` for remote HTTPS
- or configuration validation rejects remote/external admin use unless secure transport is explicitly declared

Choose the least disruptive option consistent with existing config compatibility.

## 6.2 Keep transport responsibility explicit

SynVoid does not need a new admin TLS stack in this pass. Reverse-proxy termination is acceptable.

Document:

- loopback/local HTTP development configuration
- HTTPS reverse-proxy configuration
- requirement to set secure-cookie mode for HTTPS
- trusted proxy configuration separately from TLS state

Do not conflate “trusted proxy” and “TLS proxy” into one boolean if the current configuration treats them independently.

## 6.3 Add config-level tests

Cover at least:

- default behavior
- explicit secure mode
- explicit insecure/local mode if supported
- serialization/deserialization/backward compatibility
- cookie header includes `Secure` only under configured secure mode

### Workstream 6 acceptance criteria

- session cookie Secure flag is not inferred from loopback/non-loopback bind address
- HTTPS mode explicitly produces `Secure; HttpOnly; SameSite=Strict`
- local HTTP mode can intentionally function without `Secure`
- docs state the remote-admin TLS requirement clearly

---

# Workstream 7 — Preserve corrected API discovery/Honeypot behavior

No architecture work is expected here. Add only regression checks needed to ensure the final pass does not undo the last corrections.

Confirm:

- discovery is `/api`, not `/api/api`
- Mesh/Tier Keys/YARA are absent from discovery without Mesh
- ICMP absent without `icmp-filter`
- DNS absent without `dns`
- Honeypot routes remain available independently of Mesh when the subsystem is available

These checks can live in existing router/discovery tests.

Do not reopen the feature architecture unless a current failure is found.

---

# Workstream 8 — Production admin UI build proof

`cd admin-ui && cargo check` is not sufficient closeout evidence for the integrated frontend.

Use the repository-supported Trunk/Yew production build command. Inspect `admin-ui/Trunk.toml`, package scripts, docs, or existing build instructions and run the supported production-equivalent build, for example:

```bash
cd admin-ui
trunk build --release
```

Use the actual documented command if different.

Record:

- exact command
- tool versions if relevant
- output asset directory
- whether JS/WASM/CSS assets were emitted successfully
- any warnings that materially affect runtime behavior

Do not add a new frontend build system.

### Workstream 8 acceptance criteria

- production browser assets build successfully
- emitted assets are the assets used by the runtime smoke
- no runtime smoke uses stale preexisting `dist` artifacts

---

# Workstream 9 — Execute a real local runtime/browser smoke

This is the key closure requirement. Router `oneshot` tests do not substitute for this workstream.

Launch the actual SynVoid admin server through the normal binary/runtime composition path using a disposable local configuration. Run it from a working directory other than the repository root to preserve the CWD-independence proof.

Use a clean browser profile/session. Manual browser testing is acceptable; lightweight deterministic browser automation already available in the developer environment is also acceptable. Do not add browser automation as a project dependency or CI gate.

## Required runtime/browser checks

Record pass/fail for each item:

1. Start the actual SynVoid runtime from a non-repository working directory.
2. Load `/` over the local admin origin.
3. Verify HTML, JS, WASM, CSS and other required static assets load successfully before authentication.
4. Navigate directly to a nested SPA route and verify the SPA shell loads.
5. With no session, verify `/`, `/dashboard`, and the nested route display/redirect to Login and do not mount protected dashboard UI.
6. Verify unauthenticated `/api/system/info` returns 401.
7. Submit an invalid admin bearer token and verify failure does not reflect/store the supplied token.
8. Submit a valid admin token and verify an HttpOnly session is created and CSRF state is established.
9. Inspect browser localStorage, sessionStorage, and JavaScript-readable cookies; verify no long-lived bearer token is retained.
10. Verify authenticated dashboard/API reads succeed via session cookie.
11. Verify metrics WebSocket reaches live/connected state using `/api/ws/metrics`.
12. Open Logs and verify `/api/ws/logs` reaches the server/handler with the browser session.
13. Verify polling is not the only functioning realtime path.
14. Perform one reversible CSRF-protected mutation and verify success.
15. Visit one capability-gated page appropriate to the compiled feature set and verify UI capability state matches backend availability.
16. Trigger logout; verify DELETE succeeds with CSRF, cookie is expired, and the server session is invalidated.
17. Verify the old session cookie cannot call a protected API after logout.
18. Verify the old session cannot establish either canonical WebSocket after logout.
19. Reload; verify the old session is not restored and Login remains visible.
20. Force/invalidate an active session while authenticated, then trigger one protected request.
21. Verify root app transitions to Login exactly once.
22. Verify protected components unmount and realtime/polling activity stops.
23. Verify the expiry event does not produce a burst sufficient to trip the auth lockout.
24. Verify a new valid login succeeds afterward.

## Evidence requirements

Add a new section to `plans/admin_panel_corrective_closure_results.md` or create a linked runtime-closure results file if preserving the prior record is clearer.

Record:

- exact final candidate commit SHA
- exact build command
- exact launch command/config
- origin URL used
- non-repo CWD used
- each numbered check with PASS/FAIL
- noteworthy browser console/network observations
- WebSocket response/path evidence
- storage/cookie observations without recording secret values

Never paste the raw admin bearer token, raw session ID, CSRF secret, or other credentials into the evidence file.

### Workstream 9 acceptance criteria

All 24 checks pass. If any fail, the plan remains open.

---

# Workstream 10 — Execute HTTPS/reverse-proxy smoke

Use a local TLS-terminating reverse proxy already available in the development environment or a minimal supported local configuration. Do not add a permanent proxy dependency to SynVoid.

The proxy should terminate HTTPS and forward to the admin listener with the configuration required by the selected trusted-proxy model.

## Required HTTPS checks

1. Load the production admin SPA over `https://...`.
2. Verify valid login succeeds through the proxy.
3. Verify the session cookie contains `Secure`, `HttpOnly`, and `SameSite=Strict` under explicit secure-cookie mode.
4. Verify browser realtime URL derives `wss://`, not `ws://`.
5. Verify `/api/ws/metrics` connects successfully through the proxy.
6. Verify `/api/ws/logs` reaches the server through the proxy.
7. Verify no mixed-content errors appear.
8. From an untrusted/direct peer, send spoofed `X-Forwarded-For` and verify it is ignored for client identity.
9. Through the explicitly trusted proxy, send/observe forwarded client identity and verify SynVoid accepts the configured proxy hop.
10. Verify auth/rate-limit identity uses the resolved trusted-proxy client IP rather than a blanket `unknown` bucket.
11. Logout over HTTPS and verify the Secure session is invalidated.
12. Reload over HTTPS and verify the logged-out session is not restored.

## Evidence requirements

Record:

- proxy/tool used
- relevant non-secret proxy config
- SynVoid trusted-proxy config
- explicit secure-cookie setting
- exact origin
- each check PASS/FAIL
- no private key material or raw credentials

### Workstream 10 acceptance criteria

All 12 checks pass. “Manual / not automated” is not a pass by itself; manual execution with recorded evidence is acceptable.

---

# Workstream 11 — Focused automated verification

Keep the verification surface narrow and use the existing repository policy.

Expected commands, adjusted only if repository guidance has changed:

```bash
cargo fmt --all -- --check
cargo clippy --profile ci --all-targets -- -D warnings

cargo test --test admin_route_contract --profile ci
cargo test --test admin_router_composition --profile ci
cargo test --test admin_mutation_response_guard --profile ci
cargo test --test admin_smoke_flow --profile ci
cargo test --test admin_alerting_verification --profile ci

cargo check --no-default-features --profile ci
cargo check --no-default-features --features mesh --profile ci
cargo check --no-default-features --features dns --profile ci
cargo check --no-default-features --features icmp-filter --profile ci
cargo check --no-default-features --features mesh,dns --profile ci
```

Also run the repository's canonical routine verifier if current `AGENTS.md` still requires it:

```bash
cargo xtask verify
```

Run the supported production admin UI build from Workstream 8.

Do not add new hosted CI merely to run the manual browser/proxy smoke.

## Automated test quality requirements

Tests must fail for the actual defect they claim to guard.

Reject tests that:

- accept both 200 and 404 when route presence is the contract
- call legacy WS paths and treat any non-200 as success
- substitute `/health` for browser asset loading
- call router `oneshot` and label that proof of browser redirect behavior
- assert only that an error occurred without checking why

Router-level tests are still useful; label them accurately as router/integration coverage.

---

# Workstream 12 — Documentation and truthful closeout

Only after code, automated verification, runtime/browser smoke, and HTTPS/proxy smoke all pass:

## 12.1 Update closure evidence

Update `plans/admin_panel_corrective_closure_results.md` or a clearly linked addendum with:

- exact final tested SHA
- automated command results
- production UI build result
- 24-step runtime/browser smoke result
- 12-step HTTPS/proxy smoke result
- accepted non-blocking residuals

Retain the existing webhook DNS-rebinding residual unless the implementation materially changed it.

## 12.2 Reconcile plan status

Set:

- `plans/admin_panel_runtime_closure_corrective.md` → `COMPLETE`
- `plans/admin_panel_corrective_roadmap.md` → `COMPLETE` with wording that the runtime closure pass supplied the previously missing browser/proxy proof
- `plans/admin_panel_final_corrective_closure.md` → leave historical content intact but add/adjust a note if necessary to point to this final runtime closure pass

Do not claim the earlier commit `48ce1bb...` itself had browser/HTTPS proof if that proof is only executed on a later commit.

## 12.3 Update operational docs only where behavior changed

Update current docs/skills for:

- unauthenticated route behavior
- session-expiry behavior
- logout outcome semantics
- canonical WebSocket paths
- explicit secure-cookie configuration
- HTTPS reverse-proxy requirement
- trusted proxy distinction

Avoid broad documentation rewrites.

---

# Suggested implementation sequence

Follow this order so automated tests do not mask the browser defect:

1. Root unauthenticated route guard.
2. Root auth-expiry notification mechanism.
3. Stop background/realtime work via authenticated-tree unmount/cleanup.
4. Explicit logout result handling.
5. Canonical positive WebSocket handshake tests.
6. Route-contract expansion and negative fixtures.
7. Remove bind-address Secure-cookie inference and finalize explicit transport policy.
8. Add/adjust focused config/router/auth tests.
9. Run formatting/clippy/admin test targets/reduced feature checks.
10. Build production admin UI assets with the supported Trunk/Yew command.
11. Launch actual SynVoid runtime from non-repo CWD and execute 24-step browser smoke.
12. Execute 12-step HTTPS/reverse-proxy smoke.
13. Fix any failures found by steps 11–12; rerun affected proof from the final candidate SHA.
14. Record exact evidence.
15. Reconcile plan/roadmap status only after the exact final SHA has passed all required proof.

---

# Final acceptance criteria

The admin-panel corrective roadmap may be considered genuinely closed only if every item below is true.

## Browser authentication

- unauthenticated `/` cannot render Dashboard
- unauthenticated `/dashboard` cannot render Dashboard
- unauthenticated nested application routes resolve to Login without mounting protected page components
- successful session restore enables authenticated routes
- failed restore leaves only unauthenticated/login UI mounted
- successful login transitions root auth state correctly
- long-lived bearer token is not retained by browser storage or JavaScript-readable cookies

## Session expiry

- root `AuthState` is notified when the browser session becomes invalid
- first relevant auth-expiry signal transitions to unauthenticated state
- protected route tree unmounts
- WebSocket reconnect and HTTP polling activity stop
- login is shown exactly once without a redirect loop
- ordinary expiry does not self-trigger the five-attempt auth lockout

## Logout

- logout uses cookie + valid CSRF
- successful DELETE invalidates server session
- cookie is expired
- old CSRF is no longer usable
- old HTTP session is rejected
- old WebSocket session is rejected
- reload does not restore the old session
- unconfirmed network/server logout failure is not falsely documented as confirmed server invalidation

## WebSockets

- `/api/ws/metrics` is canonical and positively tested
- `/api/ws/logs` is canonical and positively tested
- valid browser session can reach both handlers
- unauthenticated access is rejected
- legacy `/ws/metrics` and `/ws/logs` are absent unless an explicit compatibility requirement is documented
- browser runtime proves metrics WebSocket reaches connected/live state
- polling is fallback, not a mask for route failure

## Route contracts

- `/api` discovery is canonical
- `/api/api` is a negative fixture
- auth session routes are covered
- WS routes are covered
- Supervisor/worker/ICMP historically drifted paths are covered
- representative Mesh/Tier Key routes are covered under the appropriate feature
- wrong historical forms cause test failure

## Secure transport

- Secure-cookie decision no longer silently derives from bind address
- transport/cookie mode is explicit and documented
- local HTTP development remains intentionally usable
- HTTPS proxy mode produces a Secure HttpOnly SameSite session cookie
- frontend derives `wss://` under HTTPS
- trusted forwarded identity is accepted only from configured trusted proxy hops
- direct spoofed forwarding headers are ignored

## Verification/evidence

- focused Rust admin tests pass
- required reduced feature profiles compile
- repository routine verification passes if required
- production admin UI bundle builds successfully
- all 24 actual runtime/browser checks pass on the final candidate commit
- all 12 HTTPS/proxy checks pass on the final candidate commit
- evidence records exact final SHA and commands without secrets
- closure documents do not use router-only tests as a substitute for browser/runtime proof
- no new browser farm, CI matrix, external testing service, or broad framework is introduced

---

# Rejection criteria

Do **not** mark this pass complete if any of the following are true:

- unauthenticated `/` or `/dashboard` can still mount Dashboard
- root auth state remains authenticated after the server session expires
- API code merely clears CSRF state without notifying the root app
- expired-session polling/reconnect loops continue issuing repeated protected requests
- logout always transitions locally while silently discarding unrelated server/network failure information
- a WebSocket test passes because `/ws/metrics` returns 404
- no positive authenticated handshake exists for `/api/ws/metrics`
- no positive authenticated handshake exists for `/api/ws/logs`
- route-contract tests still omit WebSocket/discovery negative fixtures
- Secure-cookie mode defaults through `is_external_bind()` or equivalent bind-address inference
- `cargo check` is the only frontend build evidence
- router `oneshot` tests are described as the required browser smoke
- the actual runtime is never launched from a non-repo CWD
- no browser storage/cookie inspection is performed
- no browser WebSocket connection is observed
- HTTPS/proxy smoke is skipped because it is manual
- trusted proxy behavior is not exercised through an actual proxy path
- roadmap/plan status is changed to complete before runtime and HTTPS evidence passes

## Expected closure state

If this plan lands correctly, no further admin-panel corrective roadmap should be necessary. Future admin work should return to ordinary feature/maintenance development rather than another closure phase.