# Admin Panel Phase 6 — UX/Error Handling, Focused Verification, and Closeout

## Status

**COMPLETE**

## Objective

Close the admin-panel corrective line with the remaining small operator-facing fixes, one coherent error/session experience, focused regression coverage that catches the defects found in this review, synchronized documentation/API discovery, and an integrated local smoke proof. This phase must not turn the correction into a new verification framework.

Phases 1–5 must be functionally complete before final closeout is declared.

## Scope

Expected files may include:

- `admin-ui/src/pages/login.rs`
- authenticated layout/sidebar/header components
- `admin-ui/src/services/api.rs`
- pages with remaining error/confirmation defects identified during smoke testing
- focused tests under existing root/admin/repo-guard locations
- `docs/ADMIN_UI.md`
- `docs/API_REFERENCE.md` where current
- `architecture/admin_deep_dive.md` / admin control-plane authority docs where behavior changed
- `.opencode/skills/admin_ui/SKILL.md`, `.opencode/skills/admin_api/SKILL.md`, or `src/admin/AGENTS.override.md` only when their operational guidance is stale
- `src/admin/handlers/api_discovery.rs` / OpenAPI registration for final reconciliation
- one concise closure/results file if the repository's planning workflow expects implementation evidence

Do not add a new browser-test service, hosted test environment, CI matrix, or release requirement.

## Remaining UX/security corrections

### Login form semantics

The login screen should use a normal HTML form submission path so keyboard Enter works and browser accessibility semantics are correct.

Requirements:

- token input uses `type="password"` or equivalent non-echoing input
- autocomplete behavior is selected deliberately for a bearer/admin secret
- form submit disables repeated submission while in flight
- invalid credentials show a bounded generic error without reflecting the credential
- successful session exchange transitions once to the authenticated application

### Logout visibility

A user who is authenticated must have a visible, discoverable logout action. Do not require clearing browser data manually.

### Useful API error bodies

The browser API layer currently tends to reduce failures to `HTTP error: <status>`. Improve it so the UI can show bounded server-provided error detail.

Requirements:

- read a bounded response body for non-2xx responses
- parse known JSON error shapes when present
- sanitize/truncate arbitrary text before display/logging
- preserve HTTP status/category
- never reflect secrets or unbounded server content into DOM/logs

Prefer one `ApiError` type over per-page string conventions if it remains small and local to the frontend client.

### Mutation confirmation for destructive controls

Review destructive controls introduced/already present in the admin UI, especially:

- site deletion
- tier-key revoke/unbind
- threat-history prune/backup delete
- mesh/blocklist bans/unbans if exposed
- worker batch restart if exposed
- configuration rollback/import

Require explicit confirmation for operations whose accidental activation has material operational/security effect. Do not add confirmation to harmless toggles or create modal fatigue.

### Loading/error terminal states

Every page that starts a loading state must have explicit success/error transitions. During the final smoke, identify any page capable of an indefinite spinner after a failed initial request and correct it.

### Accessibility/basic semantics

Keep this narrow:

- controls have usable labels
- disabled/loading state is exposed through actual disabled attributes where possible
- keyboard submission/navigation works for login and destructive confirmation
- status is not represented by color alone where a text label already fits

This is not a visual redesign milestone.

## Verification design

The corrective line needs tests at three layers only:

1. server/router/security unit/integration tests
2. one frontend/backend contract guard
3. one local integrated browser/API smoke flow

Do not introduce more layers unless a defect cannot be guarded otherwise.

## Implementation plan

### 1. Consolidate focused admin regression targets

Reuse tests created by Phases 1–5 and organize/note them so an implementer can run the complete admin correction without invoking the entire workspace.

The focused set must cover:

- router construction / duplicate-route absence
- public SPA versus protected API boundary
- feature gating and capabilities
- session bootstrap, restore, logout, CSRF
- client-IP/trusted-proxy/auth lockout behavior
- raw session/token audit secrecy
- WebSocket session auth and ws/wss scheme helper
- frontend/backend method/path contract
- representative Worker, ICMP, Mesh, Tier Key mutations
- actual threat-level realtime payload
- webhook success/failure/SSRF/redirect policy
- SMTP delivery if retained

Do not duplicate tests already owned by a crate/root target just to put them under an `admin` name.

### 2. Add a lightweight duplicate-route/contract guard if runtime construction alone is insufficient

Router-construction tests should catch Axum overlapping-route panics. If feature-specific source duplication can still escape those tests, add one small repository guard that detects duplicate `(method, path)` declarations in the admin router source or, preferably, validates a test-only canonical route manifest emitted from router composition.

Keep the guard narrowly tailored; do not write a generalized Rust AST tool.

### 3. Add the frontend/backend contract regression test

Finalize the Phase 3 contract guard so it covers all production `admin-ui` HTTP operations.

Acceptance behavior of the test itself:

- changing `/system/workers/{id}/restart` back to singular must fail
- changing ICMP PUT back to POST must fail
- adding a frontend call to an absent route must fail
- feature-specific operations may be marked capability-gated rather than required in all profiles

Do not parse test/demo/dead code as production operations unless deliberately included.

### 4. Verify reduced feature profiles

Run the root profile checks required by repository policy and the admin-focused representative tests under relevant profiles.

At minimum:

```bash
cargo check --no-default-features --profile ci
cargo check --no-default-features --features mesh --profile ci
cargo check --no-default-features --features dns --profile ci
cargo check --no-default-features --features mesh,dns --profile ci
```

Also compile the ICMP admin surface with `icmp-filter` using the smallest relevant feature command supported by the repository.

The goal is to prove accidental mesh cfg capture is gone, not to create a permanent feature matrix workflow.

### 5. Build the production admin UI

Build the Yew/Trunk production assets using the repository's supported toolchain.

Verify:

- no compile warnings elevated by current policy
- production asset paths match the server's delivery strategy from Phase 1
- no missing WASM/JS/CSS references
- no source reference to forbidden auth persistence keys

If the UI build is not part of current `cargo xtask verify`, do not automatically expand routine CI in this phase. Document the local command unless the existing routine contract already intends to own it.

### 6. Run an integrated local smoke flow

Launch SynVoid's admin server through the real runtime/composition path, not a test-only mock router.

The smoke flow must include:

1. start from a working directory other than the repository root
2. unauthenticated `GET /` loads the application shell/assets
3. direct navigation to a nested SPA route loads the shell
4. unauthenticated protected API request is rejected
5. invalid login is rejected without leaking token detail
6. valid token creates an HttpOnly session
7. browser storage inspection shows no persisted long-lived bearer token
8. authenticated dashboard/API read succeeds by session
9. one CSRF-protected safe mutation succeeds (choose a reversible/non-destructive operation, e.g. theme change or test-scoped setting)
10. realtime metrics use WebSocket or bounded polling fallback
11. actual threat level is displayed from backend state
12. one representative capability-gated page behaves correctly for the compiled feature set
13. logout invalidates the session
14. protected API and WebSocket access fail after logout
15. page returns to login cleanly

Do not use production secrets or destructive live infrastructure for the smoke.

### 7. Run an HTTPS/proxy-mode smoke

Using the project's documented supported TLS reverse-proxy/deployment mode or a simple local TLS proxy:

- load the admin SPA over HTTPS
- confirm session cookie is Secure under the configured secure transport contract
- confirm realtime URL is `wss://`
- confirm no mixed-content error
- confirm trusted proxy/client-IP behavior uses only the explicitly trusted proxy hop

This can remain a local/manual acceptance step; it does not need a hosted browser environment.

### 8. Reconcile API discovery/OpenAPI/docs

Update current documentation to reflect the final implementation.

Required topics:

- browser token -> session exchange model
- bearer API client model
- CSRF requirements for browser mutations
- logout/session expiry
- WebSocket session authentication
- trusted proxies/client identity
- remote admin TLS requirement
- capabilities/feature gating
- canonical Supervisor naming
- Mesh/Tier Key endpoints if implemented
- Alerts SMTP disposition and webhook destination policy
- static asset/install/deep-link behavior

Remove stale claims including:

- routes that do not exist
- duplicate supervisor entries
- browser bearer-token persistence
- email alerting support if SMTP was removed
- old middleware ordering comments

The source and docs must agree on middleware runtime order.

### 9. Update admin-specific agent/skill guidance

`src/admin/AGENTS.override.md` currently contains historical notes and an email-stub warning. Update it after implementation so future agents do not reintroduce the defects.

At minimum document:

- actual outermost-to-innermost middleware behavior after correction
- browser session-only post-login rule
- no raw browser token persistence
- no raw session IDs in audit
- canonical feature-gating rule
- outbound webhook destination policy
- email support's final real status

Do not turn the agent file into a duplicate of the entire architecture document.

### 10. Create concise closure evidence

After all acceptance criteria pass, add one results/closure file for this roadmap if consistent with current repo practice, e.g. `plans/admin_panel_corrective_closure_results.md`.

It should contain:

- final commit SHA tested
- focused commands and pass/fail
- feature-profile checks
- local browser smoke outcome
- HTTPS/proxy smoke outcome
- alerting tests
- any explicitly accepted non-blocking residual

Do not declare complete if a shipped control remains knowingly unwired or falsely successful.

## Global rejection search

Before closeout, search production admin source for known stale patterns, including at minimum:

- `admin_token` browser storage reads/writes
- `synvoid_ws_token`
- `/config/overseer`
- `/system/worker/`
- POST call to `/icmp/config`
- duplicate `/config/supervisor` route declarations
- duplicate `/system/supervisor` GET declarations
- duplicate `/mesh/attest-capability` POST declarations
- request-rate-derived threat-level code
- unsafe tier key prefix slicing

Every hit must be classified as fixed canonical usage, test fixture, documentation example, or stale code requiring removal.

## Acceptance criteria

Phase 6 and the overall roadmap are complete only when:

- login uses a non-echoing credential field and normal form submission semantics
- authenticated UI exposes a visible logout action
- non-2xx API responses preserve bounded/sanitized useful error detail
- destructive controls receive deliberate confirmation where accidental activation is materially harmful
- no production page remains capable of a known indefinite initial-loading state after request failure
- focused admin regression targets all pass on the final reviewed commit
- default and required reduced feature `cargo check` profiles pass
- production admin UI build succeeds
- the frontend/backend contract guard covers all production admin requests and catches deliberately wrong path/method fixtures
- router construction remains panic-free and duplicate canonical routes are absent
- integrated local smoke completes all 15 required steps
- HTTPS/proxy smoke proves `wss://`, secure-cookie behavior, and trusted-proxy identity handling
- alerting tests prove truthful delivery status and outbound destination restrictions; SMTP proof exists if support remains advertised
- API discovery/OpenAPI/current docs describe only actual canonical routes and behavior
- `src/admin/AGENTS.override.md`/relevant admin skill guidance no longer describes stale middleware/auth/alerting behavior
- rejection search finds no unresolved production occurrence of the known stale patterns
- no new admin-specific CI workflow, browser matrix/farm, release gate, telemetry service, or evidence database has been introduced
- a concise closure record identifies the exact commit and has no unresolved blocking item

## Rejection criteria

Do not close this roadmap if:

- the browser still persists the long-lived bearer token
- router construction still depends on duplicate route behavior
- any visible control intentionally targets a missing route/stub
- Mesh or Tier Keys remain visibly interactive but unwired
- threat level remains heuristic
- email continues to report success without a real send while advertised as supported
- webhook total failure still returns a success message
- HTTPS dashboard realtime still attempts `ws://`
- reduced non-mesh builds lose unrelated core admin routes
- docs claim tests or controls are operational without the required local evidence
- closure requires adding broad CI infrastructure to obtain confidence

## Suggested final command record

Use the actual focused target names created during implementation. A final record should look conceptually like:

```bash
cargo fmt --all -- --check
cargo check --no-default-features --profile ci
cargo check --no-default-features --features mesh --profile ci
cargo check --no-default-features --features dns --profile ci
cargo check --no-default-features --features mesh,dns --profile ci
cargo test --profile ci <focused-admin-router-auth-contract-targets>
cargo test --profile ci <focused-admin-mesh-tier-key-targets> --features mesh
cargo test --profile ci <focused-admin-alert-targets>
# admin UI production build command
```

Run broader `cargo xtask verify` only if repository policy requires it for the implementation commit. Do not expand the canonical routine verifier merely because this admin correction has a local browser smoke step.
