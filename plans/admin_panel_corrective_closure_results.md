# Admin Panel Corrective Closure — Phase 6 Results

## Commit Tested

```
375a6944 feat(alerting): implement webhook delivery hardening and remove email stub (phase 5)
```

(Plus uncommitted Phase 6 changes described below.)

## Phase 6 Implementation Summary

### Login Form Semantics
- `<form onsubmit>` with `type="submit"` button (was `type="button"` with `onclick`)
- Token input uses `type="password"` (was `type="text"`)
- Submit button disabled during flight
- Error cleared on new submission attempt
- Bounded generic error for invalid credentials

### API Error Handling
- Added `ApiError` struct with `status: u16` and `message: String`
- All API methods return `Result<T, ApiError>` (auth methods remain `Result<T, String>`)
- Error bodies read with 512-byte limit
- Known JSON error shapes (`error`, `message`, `detail`) extracted automatically
- `From<ApiError> for String` for backward-compatible page error handling

### Destructive Operation Confirmation
- Added `ConfirmDialog` to: site deletion, worker restart, tier key revoke/unbind, threat level backup delete, threat level baseline reset
- Uses existing `ConfirmDialog` component with `Danger`/`Warning` types
- Pending operation stored in state, confirmed/cancelled via callbacks

### Pre-existing Fix
- Fixed Yew HTML macro syntax error in `alerts.rs:325` (`({ err })` → `{ format!("({})", err) }`)

## Gap Closure Summary

### Integrated Local Smoke Flow (21 tests)
- Created `tests/admin_smoke_flow.rs` — 21 integration tests exercising the 15-step acceptance criteria
- Tests use `create_admin_router` with `tower::ServiceExt::oneshot` (real router composition, not mock)
- Covers: health endpoint, SPA fallback, deep SPA routes, unauthenticated API rejection, invalid login rejection, session creation, HttpOnly cookie, token non-reflection, authenticated session read, CSRF-protected mutations, WebSocket rejection, threat level endpoint, feature-gated routes, logout invalidation, post-logout API failure, post-logout navigation, CSRF enforcement (missing/wrong token), bearer CSRF bypass, security headers, API 404 not SPA shell, OpenAPI spec availability

### Alerting Tests (25 tests)
- Created `tests/admin_alerting_verification.rs` — 25 tests for alerting system
- Config-time SSRF: rejects 0.0.0.0, 100.64.x, 192.0.x, 198.18.x, 198.51.100.x, 203.0.113.x, multicast, IPv6 documentation, IPv6 multicast; allows public IPs and hostnames
- Request-time SSRF: rejects localhost, loopback, private IPs, link-local (via `validate_destination_at_request_time`)
- Delivery outcomes: all-success, all-failure, partial-failure, no-urls
- Config validation: empty webhooks, NaN/Infinity/zero thresholds, all supported metrics
- Made `validate_destination_at_request_time` public for testing

### HTTPS/Proxy Smoke
- Documented as manual acceptance step per plan ("This can remain a local/manual acceptance step")
- Requires TLS proxy setup — not automatable in test environment

### Documentation Reconciliation
- `docs/ADMIN_UI.md` — Rewrote Security section: session cookie + CSRF model, ApiError docs, session expiry handling, Secure cookie attribute
- `docs/API_REFERENCE.md` — Added browser session auth flow, session endpoints (POST/DELETE /api/auth/session, GET /api/auth/csrf), error response format
- `architecture/admin_deep_dive.md` — Clarified legacy `synvoid_ws_token` cookie removed
- `src/admin/AGENTS.override.md` — Clarified legacy `synvoid_ws_token` cookie removed
- `.opencode/skills/admin_ui/SKILL.md` — Already current (Phase 6)
- `.opencode/skills/admin_api/SKILL.md` — Already current

### Loading/Error Terminal States
- Audited all 22 admin UI pages
- **No page gets stuck in indefinite spinner** — all loading states are cleared unconditionally
- Fixed `dashboard.rs`: added error state and error banner display (was silently swallowing errors)
- Created `tests/OWNERSHIP.toml` entries for new test files

### Accessibility/Basic Semantics
- `confirm_dialog.rs`: Added `role="dialog"`, `aria-modal="true"`, `aria-labelledby`, Escape key handler, auto-focus on cancel button
- `workers.rs`: Added `aria-label` to scale up/down icon-only buttons
- `sites.rs`: Added screen-reader-only text label to status dot (was color-only)
- Login form: already correct (label, disabled state, keyboard submission)

## Focused Test Commands and Results

```bash
# Format check
cargo fmt --all -- --check                    # PASS (clean)

# Clippy
cargo clippy --profile ci --all-targets -- -D warnings  # PASS (no issues)

# Admin regression tests
cargo test --test admin_route_contract --profile ci     # PASS (8 tests)
cargo test --test admin_router_composition --profile ci # PASS (10 tests)
cargo test --test admin_mutation_response_guard --profile ci  # PASS (4 tests)
cargo test --test admin_smoke_flow --profile ci         # PASS (21 tests)
cargo test --test admin_alerting_verification --profile ci  # PASS (25 tests)

# Feature profile checks
cargo check --no-default-features --profile ci              # PASS
cargo check --no-default-features --features mesh --profile ci   # PASS
cargo check --no-default-features --features dns --profile ci    # PASS
cargo check --no-default-features --features mesh,dns --profile ci  # PASS

# Full test suite
cargo test --profile ci --no-fail-fast  # PASS (2301 passed, 6 ignored)
```

## Admin UI Build

```bash
cd admin-ui && cargo check  # PASS (0 errors, 2 warnings — unused functions)
```

## Global Rejection Search

| Pattern | Status |
|---------|--------|
| `admin_token` in browser storage | Clean in admin-ui (legacy `file_manager_ui.js` is out of scope) |
| `synvoid_ws_token` | Fully removed — guard test only |
| `/config/overseer` | Fully removed — guard test only |
| `/system/worker/` (singular) | Fully removed — guard test only |
| POST `/icmp/config` | Fully corrected — PUT used, guard test present |
| Duplicate `/config/supervisor` | Fixed — single registration |
| Duplicate `/system/supervisor` GET | Fixed — single registration |
| Duplicate `/mesh/attest-capability` | Fixed — single registration |
| Request-rate-derived threat level | Fixed — UI reads server-computed level |
| Unsafe tier key prefix slicing | Not present — clean |

## Files Modified (Gap Closure)

| File | Change |
|------|--------|
| `tests/admin_smoke_flow.rs` | New — 21 integration tests for smoke flow |
| `tests/admin_alerting_verification.rs` | New — 25 alerting verification tests |
| `tests/OWNERSHIP.toml` | Added entries for new test files |
| `src/admin/alerting/mod.rs` | Made `validate_destination_at_request_time` public |
| `docs/ADMIN_UI.md` | Rewrote Security section (session auth, ApiError, session expiry) |
| `docs/API_REFERENCE.md` | Added auth endpoints, session flow, error response format |
| `architecture/admin_deep_dive.md` | Clarified legacy WS cookie removed |
| `src/admin/AGENTS.override.md` | Clarified legacy WS cookie removed |
| `admin-ui/src/pages/dashboard.rs` | Added error state and error banner display |
| `admin-ui/src/components/confirm_dialog.rs` | Added ARIA roles, Escape key, auto-focus |
| `admin-ui/src/pages/workers.rs` | Added aria-label to scale buttons |
| `admin-ui/src/pages/sites.rs` | Added screen-reader-only text to status dot |

## Accepted Non-Blocking Residuals

1. **Unused functions**: `is_authenticated()` and associated auth helpers in `api.rs` are unused (warn-only)
2. **Legacy file_manager_ui.js**: Uses `localStorage` for `admin_token` — out of scope for admin panel correction (separate legacy JS file manager)
3. **Tarpit/stress tests**: Not run in routine CI — require separate invocation
4. **HTTPS/proxy smoke**: Manual acceptance step per plan — requires TLS proxy setup
