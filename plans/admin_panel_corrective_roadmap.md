# Admin Panel Corrective Roadmap

## Status

**COMPLETE** — all phases implemented and verified. Final corrective pass (`plans/admin_panel_final_corrective_closure.md`) addressed remaining integration gaps and produced runtime proof.

## Purpose

The current admin surface has substantial implemented capability, but the composition between the Yew/WASM frontend, Axum router, browser authentication model, WebSocket transport, feature gates, and several backend handlers has drifted. The result is a mixture of startup-breaking route collisions, an integrated login path that is not reachable through the authenticated static fallback, browser-side retention of the long-lived admin bearer secret, incorrectly ordered client-IP/auth middleware, frontend/backend endpoint mismatches, feature-gating errors, partially or completely unwired pages, and misleading realtime/alerting behavior.

This roadmap fixes that line of work only. It is not a redesign of SynVoid's WAF, mesh, DNS, process model, plugin system, CI apparatus, or release process. Changes outside the admin/control-plane and directly required supporting types are out of scope unless they are necessary to expose an already-existing runtime capability safely to the admin surface.

## Baseline defects covered by this roadmap

The implementation phases must close the following observed defects rather than merely document them:

1. Duplicate same-method Axum routes exist for `/config/supervisor`, `/system/supervisor`, and `/mesh/attest-capability`; default-feature router construction must not rely on overlapping-route behavior.
2. The integrated `ServeDir("admin-ui/dist")` fallback sits behind authentication middleware, while `/`, `/login`, CSS, JS, and WASM assets are not public exceptions; a fresh browser cannot reliably load the login application through the integrated server.
3. The browser exchanges the static bearer token for an HttpOnly session but continues retaining and using the raw static token through JavaScript-accessible storage/cookies, bypassing the intended session/CSRF boundary.
4. Auth lockout obtains `ClientIp` before the client-IP extraction middleware has inserted it, collapsing unauthenticated clients into the `"unknown"` limiter bucket.
5. A raw newly created session identifier is written to an audit event even though session credentials must never be stored raw in audit logs.
6. WebSocket URL construction hard-codes `ws://`, breaking secure dashboards that require `wss://`.
7. The frontend and backend disagree on multiple endpoint contracts, including worker restart, ICMP config mutation, legacy overseer configuration, mesh configuration, and tier-key administration.
8. `admin-ui/src/pages/mesh.rs` does not perform its initial fetch/clear its loading state and targets a mesh config endpoint that is not registered by the router.
9. `admin-ui/src/pages/tier_keys.rs` exposes issue/revoke/unbind flows for routes that are not registered, and currently discards mutation failures.
10. Several unrelated admin routes are accidentally nested under `#[cfg(feature = "mesh")]`, causing non-mesh builds to lose system, alerting, theme, auth/session, WebSocket, and other functionality.
11. Feature-specific frontend navigation is unconditional even though backend capabilities vary by build/runtime.
12. Static admin assets are resolved from a process-working-directory-relative path and deep BrowserRouter links have no explicit SPA fallback.
13. Realtime UI derives a displayed "Threat Level" from request rate rather than the actual threat-level subsystem and renders range controls that do not change behavior.
14. Email alert delivery is a stub that reports success without sending mail, and webhook testing can report success when every destination failed.
15. Webhook SSRF validation relies on textual host-prefix checks rather than destination-address validation robust to IPv6, DNS resolution, redirects, and private/link-local targets.
16. Browser UX lacks a coherent logout/expired-session path and frequently discards useful API error response bodies.

## Binding constraints

- Keep the existing single-admin-token authority model unless a separate product decision explicitly replaces it. Multi-user RBAC is not part of this roadmap.
- The long-lived admin token may be used by non-browser API clients as a bearer token. The browser application must exchange it for a bounded server-side session and must not persist or continue using the long-lived bearer secret.
- Preserve `AdminMutationResult`, `AdminMutationAuthority`, and `AdminAuditEvent` semantics for admin mutations. Do not regress mutation/audit authority in order to simplify UI wiring.
- Never store raw session IDs, CSRF secrets, bearer tokens, private keys, SMTP passwords, or equivalent credentials in audit or ordinary application logs.
- Keep mesh propagation semantics best-effort where the underlying operation is best-effort. UI success messages must not overstate distributed delivery.
- Do not expose a frontend control unless its backend capability is actually registered and available. A feature may be hidden/disabled when absent, but a visible control may not silently target a 404/405/stub.
- Do not solve endpoint drift by adding duplicate compatibility routes indefinitely. Select one canonical route, migrate the frontend, retain a compatibility alias only when there is an external API-compatibility reason, and mark that alias explicitly.
- Do not introduce an OpenAPI/client-code-generation subsystem solely for this correction. Prefer a small authoritative route/contract mechanism and targeted tests over new build machinery.
- Do not add broad browser-test farms, matrices, or admin-only CI workflows. Verification for this roadmap is intentionally narrow and local/repository-test based.
- Default admin binding remains loopback-oriented. Remote admin exposure must have an explicit transport/trust contract; release builds alone are not evidence of HTTPS.
- Prefer deletion of stale/dead client methods and duplicate discovery metadata over additional abstractions.
- Keep changes to runtime subsystems outside admin code minimal. If an already-existing capability needs a narrow adapter/handle in `AdminState`, add only that boundary.

## Phases

### Phase 1 — Router composition, feature boundaries, and static application delivery

Detailed plan: `plans/admin_panel_phase_01_router_and_delivery.md`

Make router construction deterministic under default and reduced feature sets; remove duplicate routes; split public static/login delivery from authenticated API routes; correct feature gates; make SPA/static delivery independent of process CWD; and expose build/runtime capabilities consistently.

### Phase 2 — Browser session, CSRF, client identity, and audit hardening

Detailed plan: `plans/admin_panel_phase_02_browser_auth_security.md`

Make the browser session the sole browser credential after login, eliminate static-token persistence, correct middleware ordering, implement coherent logout/session-expiry behavior, authenticate WebSockets from the bounded session, remove raw session material from audit records, and make transport/cookie assumptions explicit.

### Phase 3 — Frontend/backend API contract reconciliation and missing control-plane wiring

Detailed plan: `plans/admin_panel_phase_03_api_contract_and_wiring.md`

Reconcile every currently shipped frontend request with one registered backend method/path, remove legacy route drift, wire Mesh and Tier Keys through existing control-plane authorities where supported, fix worker/ICMP/process-management mismatches, and make feature availability drive navigation and controls.

### Phase 4 — Realtime metrics, WebSocket behavior, and operator-state correctness

Detailed plan: `plans/admin_panel_phase_04_realtime_and_operator_state.md`

Correct `ws://`/`wss://` selection, reconnect/poll fallback behavior, actual threat-level reporting, range controls, stale/live state presentation, and mutation feedback so the UI reports runtime truth rather than approximations or optimistic state.

### Phase 5 — Alerting delivery and outbound-request hardening

Detailed plan: `plans/admin_panel_phase_05_alerting_and_outbound_security.md`

Turn alerting controls into truthful operations: either implement the currently configured SMTP path fully or remove the unsupported UI/config surface in the same phase, make webhook test status reflect actual delivery, and harden outbound webhook destination validation against private/link-local/loopback resolution and redirects.

### Phase 6 — UX/error handling, focused verification, and closeout

Detailed plan: `plans/admin_panel_phase_06_verification_and_closeout.md`

Finish the small usability/security details, add focused contract/router/browser-flow tests, verify default and reduced feature profiles, reconcile admin documentation/API discovery, and produce closure evidence without expanding CI complexity.

## Dependency order

Phases execute in order unless a small mechanical fix is necessary to unblock compilation:

1. Phase 1 establishes a router that can be constructed and a browser shell that can be loaded.
2. Phase 2 establishes the browser trust boundary all later pages use.
3. Phase 3 reconciles functional API wiring once authentication and routing are authoritative.
4. Phase 4 repairs realtime/operator-state behavior on the corrected API/session substrate.
5. Phase 5 closes outbound alerting behavior and security after the admin mutation boundary is stable.
6. Phase 6 performs UX polish, narrow regression coverage, documentation reconciliation, and final end-to-end proof.

Do not collapse the entire roadmap into one large implementation commit. Each phase should be reviewable and leave the repository in a coherent state.

## Global acceptance criteria

This corrective line is complete only when all of the following are true:

- Constructing the admin router under the repository's default feature set does not panic and contains no duplicate same-method route registrations.
- Admin router construction also succeeds for the supported reduced profiles relevant to admin operation, including at minimum `--no-default-features`, `--no-default-features --features mesh`, `--no-default-features --features dns`, and `--no-default-features --features mesh,dns` where the root crate supports them.
- A fresh unauthenticated browser can load `/`, the SPA asset bundle, and the login route without possessing an admin credential, while protected `/api/*` resources still reject unauthenticated access except for intentionally public health/OpenAPI resources.
- Direct navigation/reload of a valid SPA route returns the application shell rather than a filesystem 404.
- Admin static assets are served from a deterministic install/build location or embedded asset source rather than depending on the daemon's current working directory.
- The browser never stores the long-lived admin bearer token in `localStorage`, `sessionStorage`, IndexedDB, a JavaScript-readable cookie, URL/query state, or long-lived application state after session exchange.
- Browser API mutations authenticate by session cookie and pass CSRF validation; bearer-token API clients continue to function without CSRF as explicitly designed.
- Logout invalidates the server session and CSRF material, clears browser auth state, closes realtime connections, and returns the application to the login state.
- Expired/invalid sessions produce one deterministic browser recovery path rather than repeated failing requests.
- Authentication rate limiting uses the correctly extracted direct/trusted-proxy client identity; independent clients do not share the literal `unknown` auth bucket during normal server operation.
- No raw session ID appears in newly emitted audit records or ordinary logs.
- HTTPS-origin dashboards use `wss://`; HTTP-origin dashboards use `ws://` only where permitted by the deployment contract.
- Every request method/path invoked by production `admin-ui` code maps to an actually registered backend route for the feature profile in which the control is shown.
- Worker restart, worker scaling, ICMP configuration mutation, process/supervisor configuration, Mesh, Tier Keys, Alerts, Theme, Honeypot, and other shipped controls either execute a real backend operation or are capability-gated out of the UI.
- Mesh initial loading completes deterministically and reflects backend state; saving performs a real canonical mutation and refreshes from the returned/re-read state.
- Tier-key listing/issue/revoke/unbind operations use existing mesh/org-key authority, return typed mutation outcomes where appropriate, audit security-sensitive mutations, and surface failures to the operator.
- Non-mesh builds retain unrelated system/auth/theme/alerting functionality instead of losing it through accidental `mesh` cfg scoping.
- The UI consumes a canonical capabilities response (or an equivalent small authoritative mechanism) to hide/disable feature-specific controls that are unavailable.
- The displayed threat level comes from the actual threat-level subsystem, not a request-rate heuristic.
- Realtime range controls either change the requested/displayed history window as labeled or are removed; inert controls are not shipped.
- WebSocket failures degrade to bounded polling without duplicate timers, unbounded reconnect loops, credential leakage, or permanent false-connected state.
- SMTP/email alerting is either genuinely implemented and verified through a local test transport or the unsupported configuration/UI claims are removed; no stub returns success for a nonexistent send.
- Webhook test operations return success only when the required delivery criterion is met and report partial/complete failure accurately.
- Webhook destination validation rejects loopback, private, link-local, unspecified, multicast, and equivalent disallowed targets for IPv4/IPv6 after DNS resolution, and redirect handling cannot escape the policy.
- API errors expose bounded, sanitized server error detail useful to the operator instead of reducing every failure to only an HTTP status code.
- The login credential field is non-echoing and submission works through normal form semantics; a visible logout action exists when authenticated.
- The manual API discovery/OpenAPI/admin documentation no longer advertises routes that are not registered and does not duplicate canonical routes.
- Focused router/auth/contract tests and one local browser/API smoke flow pass on the final reviewed commit.
- No new admin-specific GitHub Actions workflow, platform matrix, browser farm, generated evidence subsystem, or long-running CI lane is introduced.

## Rejection criteria

Reject an implementation that does any of the following:

- fixes the integrated login problem by making the whole admin API unauthenticated
- stores the static admin bearer token in another browser-readable persistence mechanism under a different name
- disables CSRF globally for session-authenticated mutations
- relies on `debug_assertions` as the sole definition of secure transport
- trusts `X-Forwarded-For` from untrusted direct peers
- keeps duplicate canonical routes solely to preserve accidental internal frontend paths
- makes missing features appear successful through placeholder responses
- wires Tier Keys or Mesh mutations directly around existing control-plane authority/audit rules
- treats every non-2xx alert delivery as success
- implements SSRF filtering only by string-prefix matching hostnames
- adds broad new CI infrastructure for this localized correction
- declares the roadmap complete while any shipped admin control predictably targets an absent route or inert stub

## Required closure evidence

Keep evidence compact. The final closeout needs only:

- router-construction test results for default and reduced feature profiles
- focused admin auth/session/CSRF/client-IP regression test results
- a frontend/backend route-contract test result
- a local integrated smoke record showing unauthenticated shell/login load, successful login/session exchange, dashboard read, at least one safe mutation, realtime connection or polling fallback, logout, and post-logout rejection
- one HTTPS-equivalent/proxy test proving `wss://` selection and secure-cookie/session behavior under the documented deployment mode
- alert webhook test results covering success, total failure, and blocked private/redirect targets
- email-delivery proof if SMTP support remains advertised
- a rejection search showing no browser persistence of the long-lived token and no stale known endpoint strings

Do not create a permanent evidence database or CI artifact pipeline for this roadmap.
