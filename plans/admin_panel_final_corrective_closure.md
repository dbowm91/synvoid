# Admin Panel Final Corrective Closure Pass

## Status

**PLANNED**

## Baseline

This plan is a narrow follow-up to the completed implementation sequence for:

- `plans/admin_panel_corrective_roadmap.md`
- `plans/admin_panel_phase_01_router_and_delivery.md`
- `plans/admin_panel_phase_02_browser_auth_security.md`
- `plans/admin_panel_phase_03_api_contract_and_wiring.md`
- `plans/admin_panel_phase_04_realtime_and_operator_state.md`
- `plans/admin_panel_phase_05_alerting_and_outbound_security.md`
- `plans/admin_panel_phase_06_verification_and_closeout.md`

The implementation through `7f34f48ad09eb39486cdead6122d857cf14206ca` fixed most of the original admin-panel defects and passes the current repository verification suite. A post-implementation review found several integration gaps that are not represented accurately by the existing Phase 6 `COMPLETE` marker or closure record.

This pass exists to close those remaining gaps only. It must not reopen the broader admin roadmap, redesign the control plane, add unrelated admin features, or expand verification infrastructure.

## Remaining defects covered by this pass

1. Browser logout calls `DELETE /api/auth/session` without the CSRF header required by the server, clears only client-side auth state, and can leave the server session/cookie valid.
2. `AuthState::Unauthenticated` still renders the normal route switch, so unauthenticated navigation to `/` can render the dashboard instead of forcing `/login`.
3. API-side session expiry clears a thread-local authentication flag that is not the same state used by the root Yew `App`; expired sessions do not reliably transition the application back to login.
4. Repeated API failures after session expiry can count as independent authentication failures and drive the IP-based auth limiter into a temporary lockout before the UI stops issuing authenticated work.
5. Server WebSocket routes are registered as `/ws/metrics` and `/ws/logs`, while production frontend code connects to `/api/ws/metrics` and `/api/ws/logs`. The dashboard can therefore silently degrade to polling while realtime WebSockets never connect.
6. API discovery is mounted from a `"/api"` child route under the outer `/api` nest, producing an ambiguous/incorrect discovery path, while its metadata advertises `/api`.
7. API discovery unconditionally advertises Mesh, Tier Key, YARA, and ICMP endpoints even when the corresponding compile-time feature is absent.
8. Honeypot admin routes are still captured by the Mesh feature block even though the honeypot subsystem itself is not mesh-only.
9. The frontend/backend route-contract test is useful but manually enumerated and does not cover all production admin HTTP/WebSocket endpoint strings; this allowed the WebSocket path mismatch to survive closeout.
10. `ApiError` truncation slices response strings by byte index and can panic when a multibyte UTF-8 character crosses the truncation boundary.
11. Secure-cookie behavior is inferred from non-loopback binding rather than an explicit secure-transport/proxy contract. This assumption was not proven by the required HTTPS/proxy smoke.
12. Webhook outbound validation performs request-time DNS classification but then connects using the original hostname, leaving the already-documented DNS rebinding/TOCTOU residual. The closure record must either document this honestly or close it with a narrow existing-client mechanism if one already exists.
13. The existing Phase 6 closure evidence does not record the required integrated 15-step browser smoke or HTTPS/proxy smoke, so the admin corrective line was declared complete without the runtime proof required by its own plan.
14. Planning state is inconsistent: the phase closeout says complete while the overarching admin corrective roadmap remains planned.

## Binding constraints

- Keep this pass narrow. Do not introduce new admin product features.
- Preserve the existing single-admin-token authority model and session exchange model.
- The browser must use the long-lived admin token only for the initial session exchange; no new browser token persistence is permitted.
- Preserve bearer-token support for non-browser API clients.
- Preserve `AdminMutationResult`, `AdminMutationAuthority`, and audit semantics.
- Do not weaken CSRF requirements to make logout easier. Fix the client path instead.
- Do not disable or relax auth rate limiting to hide session-expiry behavior. Stop stale browser work promptly and make limiter identity/order correct.
- Select one canonical WebSocket path family. Do not keep duplicate permanent aliases unless there is an explicit external compatibility requirement.
- Do not add a general OpenAPI client generator or AST parser solely for route-contract testing.
- Do not add a browser farm, admin-specific CI workflow, new release gate, external test service, telemetry service, or evidence database.
- Prefer deletion of stale state/helpers and correction of existing abstractions over adding another auth/event framework.
- Treat DNS rebinding protection pragmatically: use an existing narrow connection-pinning/resolver hook only if available without broad HTTP-client redesign; otherwise document the residual precisely.
- Remote admin exposure must have an explicit secure-transport contract. Do not infer HTTPS solely from build profile or bind address.

## Workstream 1 — Make browser authentication state authoritative

### 1.1 Replace split authentication state

The current browser has both:

- root `App` `UseState<AuthState>` state
- thread-local `IS_AUTHENTICATED` state in `ApiService`

Choose one authoritative application-level state transition mechanism.

Preferred implementation:

- keep root `AuthState` as the UI authority
- keep CSRF token storage private to the API service if convenient
- remove the unused/redundant thread-local authentication boolean if nothing outside `ApiService` legitimately consumes it
- give API/session-expiry code a small callback/event mechanism that lets the root app transition to `Unauthenticated`

Acceptable alternatives are fine if they remain local and simple. Do not introduce Redux-like global state or a generic event bus solely for auth.

### 1.2 Enforce unauthenticated route behavior

When session restoration fails or the application is otherwise unauthenticated:

- `/login` renders the login page
- any authenticated application route redirects to `/login`
- `/` must not render the dashboard before authentication
- navigation history should not create an infinite redirect loop
- after successful login, the app should transition once to `/` or `/dashboard`

Prefer a route guard/switch behavior in the root application rather than duplicating checks on every page.

### 1.3 Make session expiry a terminal browser transition

On HTTP `401` or session-authenticated `403` caused by expired/invalid browser session:

- clear in-memory CSRF state
- transition root auth state to `Unauthenticated`
- stop/refrain from starting additional polling and WebSocket reconnect work
- redirect/show login once
- do not continue issuing background requests that can accumulate auth failures

Do not classify an application-level authorization failure as session expiry if future non-admin role semantics are added; for the current single-admin model, document the 401/403 interpretation explicitly.

## Workstream 2 — Fix logout end-to-end

### 2.1 Send CSRF on logout

Route browser logout through the same CSRF-aware request machinery as other state-changing operations, or explicitly attach the current CSRF token to `DELETE /api/auth/session`.

Do not exempt logout from CSRF server-side merely to make the current client work.

### 2.2 Handle logout outcome deliberately

Successful logout must:

- invalidate the server session
- invalidate session-bound CSRF tokens
- expire the session cookie
- clear browser in-memory CSRF/auth state
- stop realtime/polling activity
- transition to `/login`

If the server logout request fails because the session is already invalid, the browser may still transition to login, but the distinction must be intentional and documented. Do not silently claim the server session was invalidated if the request failed for an unrelated server error.

### 2.3 Add focused logout regression coverage

Add a test that proves:

1. a valid browser session can access a protected endpoint
2. DELETE without CSRF is rejected
3. DELETE with valid CSRF succeeds
4. the same session cookie cannot access the protected endpoint afterward
5. the old CSRF token is unusable afterward

Use existing router/state test helpers; do not add a new test harness.

## Workstream 3 — Canonicalize realtime WebSocket routing

### 3.1 Choose one canonical path

Preferred canonical paths, because the browser API namespace already uses them:

- `/api/ws/metrics`
- `/api/ws/logs`

Either move the server routes under `/api/ws/*` or change every production browser/documentation reference to root `/ws/*`. Pick one and make all layers agree.

The canonical choice must be reflected consistently in:

- `src/admin/mod.rs`
- `src/admin/ws/mod.rs` comments/tests where applicable
- `admin-ui/src/hooks/use_websocket.rs`
- `admin-ui/src/pages/logs.rs`
- dashboard/site-detail realtime consumers
- admin UI/API documentation
- admin-specific skill/agent guidance
- contract tests

Do not leave two equivalent permanent route families unless there is a documented external compatibility requirement.

### 3.2 Prove session-authenticated upgrade behavior

Focused tests must prove:

- canonical unauthenticated WebSocket upgrade is rejected
- canonical session-cookie-authenticated upgrade reaches the WebSocket handler rather than a 404
- bearer-token auth remains available for non-browser clients if currently intended
- the old/noncanonical path is absent if no compatibility alias is retained

A full browser WebSocket protocol test is not required if the router-level handshake path plus integrated smoke gives sufficient proof.

### 3.3 Keep polling fallback as fallback

Polling must remain bounded fallback behavior, not the normal hidden path because the WebSocket route is wrong.

During the local smoke, prove at least one actual WebSocket connection reaches `Connected`/live state before deliberately testing fallback behavior.

## Workstream 4 — Reconcile API discovery with real feature-specific routing

### 4.1 Fix discovery mount path

Make the discovery endpoint have one unambiguous canonical URL.

Preferred options:

- child route `"/"` under the `/api` nest, yielding `/api`
- or explicit `/api` route outside the nested API router

Do not retain an accidental `/api/api` route while advertising `/api`.

### 4.2 Feature-gate discovery metadata

`get_api_endpoints()` must describe only routes actually compiled into the current binary.

At minimum:

- Mesh category/endpoints only under `mesh`
- Tier Keys only under `mesh`
- YARA only under `mesh`
- ICMP only under `icmp-filter`
- DNS config only under `dns`
- Honeypot according to its real capability boundary after Workstream 5

Prefer small `#[cfg]` category construction over a second runtime capability framework.

### 4.3 Add discovery-vs-router guard coverage

Add focused tests proving representative feature-gated endpoints are absent from discovery when their feature is disabled and present when enabled.

The test should catch a metadata claim for a route that the same profile does not register.

## Workstream 5 — Correct the remaining feature boundary

### 5.1 Move honeypot admin routes out of Mesh-only composition

The honeypot admin routes currently live in the Mesh-only route chain. Unless code inspection reveals a genuine hard Mesh dependency for those handlers, move:

- `/honeypot/status`
- `/honeypot/control`
- `/honeypot/config`

into the core or correctly scoped honeypot admin route block.

### 5.2 Correct capabilities/navigation

After route correction:

- `CapabilitiesResponse.honeypot` must describe real availability, not `cfg!(feature = "mesh")` simply because the route was accidentally gated
- the sidebar/page guard must use the corrected capability
- reduced non-mesh builds must not lose honeypot admin solely because Mesh is absent

If there is a separate runtime requirement for an initialized controller, distinguish `compiled capability` from `currently initialized/running` rather than using Mesh as a proxy.

### 5.3 Regression coverage

Under a non-mesh profile, prove:

- honeypot route is registered if the subsystem is compiled
- mesh routes remain absent
- core system/auth/alert routes remain present

## Workstream 6 — Strengthen the route-contract guard without new machinery

The current manual `tests/admin_route_contract.rs` caught several Phase 3 defects but did not cover the production WebSocket route strings and does not substantiate the claim that all production admin requests are covered.

### 6.1 Establish a small authoritative contract source

Choose the smallest maintainable option:

**Preferred:** centralize production admin endpoint constants in one small frontend module and consume those constants from the Yew client/pages. Mirror/validate the finite set in root integration tests.

**Acceptable:** extend the existing manual route-contract fixture to cover all production HTTP/WebSocket operations and add a lightweight repository guard that scans only the known admin endpoint literal call sites.

Do not build a generalized Rust parser or code generator.

### 6.2 Coverage requirements

The guard must cover at least:

- session create/restore/delete
- worker status/scale/restart/batch restart
- ICMP GET/PUT/enable/disable
- Mesh status/config when enabled
- Tier Key list/issue/revoke/unbind when enabled
- Alerts config/test-webhook
- realtime metrics WebSocket
- realtime logs WebSocket
- Supervisor status/config
- capabilities
- one representative site mutation
- one representative threat-level mutation

It must explicitly include the method as well as the path for HTTP mutations.

### 6.3 Negative fixtures

The guard must fail for deliberately incorrect fixtures including:

- singular `/system/worker/{id}/restart`
- POST `/icmp/config`
- `/system/overseer`
- `/config/overseer`
- the noncanonical WebSocket path family
- `/api/api` if `/api` is canonical discovery

## Workstream 7 — Make API error truncation UTF-8 safe

### 7.1 Introduce one bounded truncation helper

Replace byte-index slicing such as `&text[..MAX_ERROR_BODY]` with a helper that:

- limits output to a bounded size
- never slices inside a UTF-8 code point
- preserves reasonable operator-readable detail
- appends an ellipsis only when truncation occurred

Use it for all browser error-body truncation paths, including login and generic `ApiError` handling.

### 7.2 Test boundary cases

Unit-test at least:

- ASCII shorter than limit
- ASCII longer than limit
- multibyte UTF-8 with boundary before a code point
- multibyte UTF-8 crossing the nominal byte limit
- empty response

Do not introduce a Unicode segmentation dependency solely for this; Rust char-boundary handling is sufficient.

## Workstream 8 — Make secure-cookie/remote-admin transport policy explicit

### 8.1 Stop using bind address as transport truth

The current `is_external_bind()` heuristic equates non-loopback bind with secure reverse-proxy deployment. Replace this with an explicit configuration or existing deployment signal that states whether the browser-facing admin origin is HTTPS.

Preferred minimal designs:

- existing admin config gains a boolean/enum such as `secure_cookie` / `external_scheme = https` if no equivalent already exists
- or trusted reverse-proxy/TLS deployment configuration already present in SynVoid becomes the authoritative signal

Do not infer TLS from debug/release profile or non-loopback binding.

### 8.2 Define safe defaults

- loopback HTTP development may use non-Secure cookie intentionally
- remote/external production admin exposure must be documented as requiring TLS termination and Secure cookies
- configuration that claims secure external mode while actually serving plain HTTP should fail obviously during smoke/configuration rather than silently producing an unusable login

Avoid implementing an entire new TLS listener in this pass unless the repo already has a directly reusable admin TLS path. Reverse-proxy termination remains acceptable.

### 8.3 Trusted proxy identity proof

The HTTPS/proxy smoke must prove that:

- direct/untrusted clients cannot spoof `X-Forwarded-For`
- an explicitly trusted proxy hop can provide the client IP
- auth rate limiting uses the resolved client identity

## Workstream 9 — Resolve or document the webhook DNS rebinding residual

### 9.1 Inspect the existing HTTP client before changing architecture

Determine whether the existing SynVoid HTTP client can, with a narrow local change:

- connect to an already validated resolved socket address while preserving original Host/SNI, or
- inject a resolver that validates the address immediately at connection time

If yes, use that mechanism for webhook delivery only and add focused tests.

### 9.2 Do not overbuild if pinning is not already practical

If closing the validate-then-connect gap requires broad HTTP client redesign:

- keep request-time resolution validation
- keep redirects disabled/non-followed
- document that DNS rebinding between validation and actual connection remains a residual risk
- state why the residual is accepted for this admin-authenticated outbound feature

Do not claim full DNS-rebinding resistance without connection-time enforcement.

This residual alone does not block admin-panel closure if it is truthfully documented and the existing private/link-local/loopback protections remain tested.

## Workstream 10 — Execute the runtime proof that Phase 6 omitted

The line must not be marked closed again on compile/unit-test evidence alone.

### 10.1 Integrated local browser/API smoke

Launch the actual SynVoid admin server through its real runtime/composition path and execute the following from a clean browser profile or equivalent deterministic browser session:

1. run SynVoid from a working directory other than repository root
2. `GET /` and required JS/WASM/CSS assets load without authentication
3. direct navigation to a nested SPA route loads the application shell
4. fresh unauthenticated navigation resolves to the login UI, not dashboard content
5. unauthenticated protected API call returns 401
6. invalid login fails without reflecting the supplied token
7. valid admin token creates an HttpOnly session and returns CSRF state
8. browser local/session storage and JavaScript-readable cookies contain no long-lived bearer token
9. authenticated dashboard/API read succeeds via session
10. canonical metrics WebSocket reaches live/connected state
11. canonical logs WebSocket reaches the server when Logs page is opened
12. one reversible CSRF-protected mutation succeeds
13. one capability-gated page matches the compiled feature set
14. logout succeeds with CSRF and invalidates the server session/cookie
15. subsequent API and WebSocket access with the old session fail and the application stays on login
16. reload after logout does not restore the old session
17. simulate/force session expiry and verify the UI transitions once to login without driving repeated auth failures/lockout

Record exact commands/configuration and pass/fail evidence in the closure record.

### 10.2 HTTPS/reverse-proxy smoke

Using the project's supported local reverse-proxy/TLS mode:

1. load the admin SPA over HTTPS
2. successful login produces a Secure HttpOnly session cookie under the configured secure mode
3. realtime metrics uses `wss://`
4. no mixed-content WebSocket error occurs
5. canonical WebSocket path succeeds through the proxy
6. trusted proxy client-IP extraction behaves as configured
7. untrusted forwarded headers are ignored
8. logout invalidates the secure session

This remains local/manual evidence. Do not create a hosted browser environment to satisfy it.

## Workstream 11 — Reconcile documentation and planning state only after proof

### 11.1 Update runtime documentation

After the implementation and smoke pass, update current docs/skills only where behavior changed:

- canonical WebSocket URLs
- session expiry/logout semantics
- authenticated vs unauthenticated route behavior
- explicit Secure-cookie/TLS proxy configuration
- feature-gated discovery behavior
- honeypot capability semantics
- webhook DNS-rebinding residual or connection-pinning behavior

### 11.2 Correct roadmap/phase status

The existing planning state is contradictory. On successful completion:

- update `plans/admin_panel_corrective_roadmap.md` to `COMPLETE`
- leave historical Phase 1–5 completion notes intact
- update Phase 6/closure notes to state that this final corrective pass supplied the missing runtime proof and remaining fixes
- update `plans/admin_panel_corrective_closure_results.md` with the exact final implementation SHA and smoke evidence, or create a clearly linked final addendum if preserving historical evidence is cleaner
- mark this plan `COMPLETE`

Do not rewrite history to imply the omitted smoke had already been run at `7f34f48`.

## Focused verification

Run the smallest existing commands that prove the touched boundaries. Expected command set should include at least:

```bash
cargo fmt --all -- --check
cargo clippy --profile ci --all-targets -- -D warnings

cargo test --test admin_router_composition --profile ci
cargo test --test admin_route_contract --profile ci
cargo test --test admin_mutation_response_guard --profile ci

cargo check --no-default-features --profile ci
cargo check --no-default-features --features mesh --profile ci
cargo check --no-default-features --features dns --profile ci
cargo check --no-default-features --features icmp-filter --profile ci
cargo check --no-default-features --features mesh,dns --profile ci

cd admin-ui && cargo check
```

Add only the focused test target(s) needed for session lifecycle/discovery/WebSocket contract if those checks do not fit naturally into existing targets.

Run the broader repository verifier/full suite only if current repository policy requires it for the final implementation commit. Do not expand routine CI because this pass contains manual browser/proxy smoke evidence.

## Acceptance criteria

This corrective pass is complete only when all of the following are true:

### Authentication/session

- browser logout sends valid CSRF and the server accepts it
- logout invalidates the server-side session and session-bound CSRF tokens
- logout expires the browser session cookie
- a session used before logout cannot access protected HTTP endpoints afterward
- the same logged-out session cannot authenticate WebSockets afterward
- reloading after logout does not restore the old session
- unauthenticated `/`/dashboard navigation renders or redirects to login rather than dashboard content
- session expiry transitions the root Yew application to unauthenticated state exactly once
- session expiry stops background polling/reconnect work promptly enough that ordinary expiry does not accumulate a five-attempt auth lockout
- no long-lived bearer token is persisted or reintroduced into browser storage/cookies

### WebSockets/contracts

- frontend and backend use one canonical metrics WebSocket path
- frontend and backend use one canonical logs WebSocket path
- both canonical WebSocket paths succeed with a valid browser session
- noncanonical WebSocket paths are absent unless an explicitly documented compatibility alias is required
- polling is verified as fallback rather than the only functioning realtime path
- the route-contract guard covers production WebSocket path constants in addition to HTTP routes

### API discovery/feature boundaries

- API discovery has one canonical URL and does not accidentally mount at `/api/api`
- discovery does not advertise Mesh/Tier Key/YARA routes without Mesh
- discovery does not advertise ICMP routes without `icmp-filter`
- discovery does not advertise DNS config without `dns`
- honeypot routes are no longer disabled merely because Mesh is absent, unless a verified hard dependency proves that boundary intentional
- capabilities/sidebar behavior reflects the corrected honeypot feature boundary
- default and representative reduced-feature router composition remains panic-free

### Robustness/security

- browser error truncation cannot panic on valid UTF-8 input
- error response detail remains bounded
- Secure-cookie behavior is controlled by explicit secure-transport configuration rather than bind-address inference
- HTTPS/proxy smoke proves Secure cookie and `wss://` behavior
- trusted proxy smoke proves forwarded client identity is accepted only from explicitly trusted hops
- webhook DNS rebinding is either closed with connection-time enforcement or explicitly documented as an accepted residual; no unsupported claim of full rebinding resistance remains

### Verification/closure

- focused admin tests pass on the exact final implementation commit
- required reduced feature `cargo check` profiles pass
- admin UI compiles under the supported build workflow
- the 17-step integrated local smoke is executed and recorded
- the 8-step HTTPS/proxy smoke is executed and recorded
- no admin-specific CI workflow/browser farm/new release gate is added
- `admin_panel_corrective_roadmap.md`, Phase 6 status/notes, and closure results are reconciled truthfully
- final closure evidence names the exact commit tested and contains no unresolved blocking item

## Rejection criteria

Do not close this pass if any of the following remain true:

- logout merely clears local UI state while the server session survives
- logout is made to work by exempting it from CSRF
- unauthenticated users can render dashboard/application pages before login
- expired sessions leave the root app authenticated or cause repeated background 401/403 traffic
- normal session expiry can trivially drive the shared client IP into auth lockout
- frontend still connects to a WebSocket path not registered by the server
- realtime appears healthy only because polling masks a broken WebSocket route
- API discovery advertises routes not compiled into the current feature profile
- `/api/api` remains the accidental discovery URL while docs advertise `/api`
- Honeypot remains Mesh-gated without a demonstrated architectural dependency
- route-contract closure claims all production requests are covered while WebSocket or page-local endpoint literals remain outside the guard
- `ApiError` can panic on multibyte UTF-8 truncation
- Secure-cookie behavior still assumes non-loopback means HTTPS
- closure claims DNS-rebinding resistance beyond what the actual connection path enforces
- Phase 6/roadmap is marked fully closed without recorded local browser and HTTPS/proxy smoke evidence
- completing this pass requires adding broad CI/test infrastructure unrelated to the defects above

## Handoff sequencing

Implement in this order to avoid masking failures:

1. authoritative auth-state + unauthenticated route guard
2. CSRF-correct logout + server-session invalidation regression test
3. canonical WebSocket paths + session-authenticated upgrade coverage
4. API discovery mount/feature gating
5. honeypot feature-boundary correction
6. route-contract guard expansion
7. UTF-8-safe error truncation
8. explicit secure-cookie/transport policy
9. webhook rebinding decision/documentation
10. focused compile/test passes
11. integrated browser smoke
12. HTTPS/proxy smoke
13. documentation/planning reconciliation and final closure record

Do not update the corrective roadmap to `COMPLETE` before steps 11 and 12 have actually passed.