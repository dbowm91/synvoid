# Admin Panel Phase 2 — Browser Session, CSRF, Client Identity, and Audit Hardening

## Status

**PLANNED**

## Objective

Make the integrated browser admin application use the server's bounded session/CSRF design as its actual trust boundary, rather than retaining and reusing the long-lived static bearer token. Correct client identity extraction before rate limiting/auth, make logout/session expiry deterministic, authenticate realtime connections without JavaScript-readable master credentials, and eliminate raw session material from audit records.

This phase assumes Phase 1 has already produced a reachable public SPA/login shell and a protected `/api` router with deterministic route composition.

## Scope

Primary files expected to change:

- `admin-ui/src/services/api.rs`
- `admin-ui/src/pages/login.rs`
- `admin-ui/src/app.rs`
- `admin-ui/src/hooks/use_websocket.rs`
- `admin-ui/src/components/realtime_header.rs`
- authenticated layout/header/sidebar component where logout belongs
- `src/admin/middleware.rs`
- `src/admin/handlers/auth.rs`
- `src/admin/state.rs` if session/CSRF lifecycle helpers need narrowly scoped correction
- `src/admin/ws.rs`
- `crates/synvoid-admin/src/auth.rs` and/or rate-limit support only where necessary
- focused auth/session tests and admin documentation

Do not introduce multi-user accounts, RBAC, OAuth/OIDC, password databases, or a second authentication subsystem.

## Security model to preserve

SynVoid intentionally supports two client classes:

1. **Non-browser API clients** may present the configured long-lived admin token in `Authorization: Bearer ...`. These clients do not require CSRF because ambient browser credentials are not involved.
2. **Browser clients** present the long-lived token only to `POST /api/auth/session`, receive an HttpOnly bounded session cookie, and subsequently authenticate through that session. State-changing browser requests carry a CSRF token tied to the session.

The implementation must make these classes real rather than documenting them while the SPA continues using class 1.

## Baseline problems

- The SPA retains the long-lived token in JavaScript-readable persistence and reuses it as a bearer token after exchanging for a session.
- Bearer-authenticated mutations bypass CSRF by design, so the shipped browser behavior makes CSRF mostly irrelevant.
- WebSocket token helpers accept token arguments but do not use them consistently, while other code stores token material for realtime use.
- Auth lockout reads `ClientIp` before the extractor has populated it, allowing the literal `"unknown"` bucket to represent unrelated clients.
- Session creation logs the raw session ID as an audit target.
- Cookie security is tied to debug/release compilation rather than the actual deployment transport contract.
- There is no complete browser logout/session-expiry recovery flow.

## Implementation plan

### 1. Remove persistent browser storage of the long-lived admin token

Search the complete `admin-ui` production source for:

- `admin_token`
- `synvoid_ws_token`
- `localStorage`/`local_storage`
- `sessionStorage`/`session_storage`
- cookie writes related to auth
- query-string or fragment token use

The login flow may hold the entered token in component memory long enough to call session creation. After the session exchange completes successfully, discard it.

Requirements:

- do not persist the raw token to local/session storage
- do not write it to any JavaScript-readable cookie
- do not retain it in a top-level application state after login
- do not include it in WebSocket URLs/subprotocol strings unless a future explicit protocol requires that and the security model is re-reviewed
- do not log it in browser console/tracing

Theme or other non-secret local storage remains allowed.

### 2. Make `ApiService` session-first for the browser

Refactor the browser API client so ordinary application calls rely on same-origin cookie credentials.

For mutating requests:

- attach the current CSRF token in `X-CSRF-Token`
- do not add `Authorization` automatically from browser persistence
- preserve content type and response parsing

For reads:

- rely on the session cookie
- no CSRF header is required unless server policy intentionally requires it

Keep an explicit one-shot session bootstrap function that accepts the user-entered bearer token and sends it only to `/api/auth/session`.

Do not remove server bearer support for CLI/curl/API clients.

### 3. Define CSRF token browser lifecycle

The CSRF token may be retained in in-memory application state for the active session. If the application reloads while a valid HttpOnly session cookie remains:

- call `/api/auth/csrf` to obtain/rotate a CSRF token
- restore authenticated SPA state only after session validation succeeds
- never require recovery of the static bearer token from persistence

On logout or session failure, discard the in-memory CSRF token.

If multiple CSRF tokens per session are currently allowed, ensure bounded cleanup/rotation remains sane. Do not create unbounded token accumulation.

### 4. Correct middleware ordering and client identity

Rebuild the middleware stack so client IP extraction runs before components that consume `ClientIp`.

Required security order conceptually:

1. receive direct `ConnectInfo`
2. derive trusted client identity using configured trusted proxies
3. apply per-client request/auth rate limiting
4. authenticate request/session
5. apply CSRF policy to session-authenticated mutations
6. execute handler

Exact Tower layering syntax may reverse visual order; tests must prove runtime behavior rather than relying on comments.

Trusted proxy behavior must remain strict:

- ignore `X-Forwarded-For` from direct peers not present in `trusted_proxies`
- validate parsed IP syntax
- document whether first-hop or another forwarded address is selected
- do not let a malformed proxy header fall back to an attacker-controlled arbitrary string

### 5. Separate authentication-failure limiting from general request limiting cleanly

Keep the existing brute-force protection, but ensure:

- failed auth attempts are keyed to resolved client identity
- one client reaching lockout does not lock unrelated direct clients
- a successful authentication only clears that client's failure state
- `Retry-After` is consistent with the actual remaining lockout duration
- cleanup remains bounded

Do not add distributed rate-limit infrastructure for the admin panel.

### 6. Stop writing raw session IDs to audit/log output

Update `create_session` to hash/redact the session identifier before any audit record is emitted, matching the principle already used during session deletion.

Prefer a shared helper for session-ID hashing if it avoids duplicate hashing code without over-abstracting.

Search admin code for every log/audit use of:

- session ID
- CSRF token
- bearer token

Correct any additional raw-secret emission found in this narrow area.

### 7. Implement coherent logout

Add a visible authenticated logout action.

Logout flow:

- issue `DELETE /api/auth/session` with valid session/CSRF semantics
- server invalidates session and all associated CSRF tokens
- server expires the session cookie using attributes compatible with the creation cookie
- client discards auth/CSRF state
- client closes/reinitializes realtime connections
- client returns to login route/state

Logout must not merely delete browser UI state while leaving the server session valid.

### 8. Implement session-expiry recovery

Centralize handling of `401 Unauthorized` (and CSRF-specific `403` where appropriate) in the browser API layer.

Required behavior:

- one expired session causes one transition to unauthenticated state
- stop repeated background polling/realtime reconnect attempts that continue hammering authenticated endpoints
- clear in-memory CSRF/session UI state
- redirect/render login
- preserve no raw bearer credential

Do not automatically reauthenticate using a saved static token because there must be no saved static token.

### 9. Authenticate WebSockets from the bounded browser session

Use the HttpOnly session cookie during the same-origin WebSocket handshake. The WebSocket handler must validate the session before upgrading/streaming sensitive metrics/logs.

Requirements:

- remove browser need for a dedicated JS-readable WebSocket bearer cookie
- `/api/ws/metrics` and `/api/ws/logs` must reject unauthenticated/expired sessions
- if non-browser WebSocket bearer clients are intentionally supported, define a separate explicit mechanism; do not weaken browser session security for it
- no token in URL query parameters

### 10. Make transport/cookie policy explicit

The current code associates `Secure` cookie behavior with release builds. Replace this with a deployment-aware rule.

Acceptable small designs include:

- an admin configuration flag declaring externally secure transport when behind an approved TLS reverse proxy, validated against trusted proxy configuration, or
- first-class HTTPS admin serving if already available without broad new infrastructure

At minimum:

- loopback HTTP development can function intentionally
- remote/external deployment documentation requires TLS
- secure deployments set `Secure`
- `SameSite=Strict`, `HttpOnly`, bounded `Max-Age`, and appropriate `Path` remain
- creation/deletion cookies use compatible attributes

Do not infer security solely from `debug_assertions`.

### 11. Add baseline browser security headers if absent

Because the SPA is a privileged control plane and long-lived secrets must no longer be JS-accessible, add a small set of headers at the admin application boundary if not already supplied externally:

- `Content-Security-Policy` appropriate for Trunk/Yew WASM assets and WebSocket connections
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy` restrictive value
- frame-embedding protection through CSP `frame-ancestors` (or equivalent)
- HSTS only when the listener/proxy contract is actually HTTPS; never emit it blindly on plain loopback HTTP

Keep CSP as narrow as the real asset loader permits; do not use `unsafe-eval` unless the built application demonstrably requires it and the reason is documented.

## Focused tests

### Session bootstrap and persistence tests

Browser/unit/source guard coverage must prove:

- successful login creates session state without writing the bearer token to local/session storage or JS-readable cookies
- application reload can restore an existing valid session via `/api/auth/csrf` without the static token
- invalid session restoration becomes unauthenticated

A lightweight source guard may complement behavior tests for forbidden persistence keys, but do not rely on grep alone.

### CSRF tests

Server tests must prove:

- bearer API mutation with a valid bearer token succeeds without CSRF
- session-authenticated mutation without CSRF is rejected
- session-authenticated mutation with the correct CSRF token succeeds
- CSRF from a different/invalid session is rejected
- safe GETs do not require CSRF

### Client identity/auth limiter tests

Prove:

- two distinct direct client IPs maintain independent auth failure buckets
- trusted proxy forwarding uses the validated forwarded client
- untrusted direct peers cannot spoof client identity through `X-Forwarded-For`
- lockout and retry behavior is keyed to the resolved identity

### Audit-secret tests

Prove newly created/deleted session audit events do not contain the raw session ID or bearer token.

### WebSocket auth tests

Prove:

- valid session cookie permits upgrade
- missing/expired session is rejected
- logout invalidation causes subsequent upgrade failure

## Acceptance criteria

Phase 2 is complete only when:

- production `admin-ui` contains no path that persists the long-lived admin bearer token in browser-readable storage or cookies
- `ApiService` ordinary requests no longer synthesize bearer authentication from browser persistence
- login uses the bearer token only for session exchange and discards it afterward
- a page reload can recover a valid session through the HttpOnly cookie and CSRF endpoint without asking for/recovering the static token
- session-authenticated POST/PUT/PATCH/DELETE operations require and send CSRF tokens
- direct bearer API clients retain their documented no-CSRF behavior
- middleware runtime ordering provides `ClientIp` before auth/request rate limiters consume it
- independent client IPs cannot lock each other out through the normal `unknown` bucket
- untrusted `X-Forwarded-For` values are ignored
- no raw session ID is emitted in session-create audit events, and a targeted search finds no other raw admin session/token logging
- logout invalidates server session and CSRF state, expires the cookie, clears client auth state, terminates realtime activity, and returns to login
- an expired session produces one deterministic login transition rather than repeated background request failures
- browser WebSockets authenticate from the bounded session cookie and do not require a JS-readable bearer cookie/token URL
- secure-cookie behavior is based on the actual deployment transport contract, not simply debug versus release build
- the documented remote admin deployment contract requires encrypted transport
- baseline security headers are present or explicitly delegated to/documented for the supported reverse-proxy deployment mode
- focused auth/session/CSRF/client-IP/WebSocket tests pass

## Rejection criteria

Reject this phase if it:

- moves the bearer token from `localStorage` to another JavaScript-readable persistence mechanism
- disables CSRF to make the frontend easier to wire
- makes session cookies JavaScript-readable
- places bearer/session/CSRF secrets in WebSocket query parameters
- trusts forwarding headers from arbitrary direct clients
- globally shares auth lockout state across unrelated clients by design
- logs raw session IDs for troubleshooting
- ties `Secure` cookie semantics only to release mode
- adds OAuth/RBAC/account infrastructure unrelated to this correction

## Verification commands/evidence

Use focused existing/new targets rather than a broad suite. Record at minimum:

```bash
cargo test --profile ci <admin-auth-session-test-target>
cargo test --profile ci <admin-middleware-client-ip-test-target>
cargo test --profile ci <admin-websocket-auth-test-target>
```

Build the admin UI and perform one local browser smoke:

1. open unauthenticated login shell
2. log in with a valid token
3. confirm subsequent requests carry session cookie and CSRF rather than Authorization bearer
4. reload page and remain authenticated through session recovery
5. log out
6. confirm protected API and WebSocket access are rejected afterward

Capture only concise textual evidence; do not introduce browser automation infrastructure solely for this phase.
