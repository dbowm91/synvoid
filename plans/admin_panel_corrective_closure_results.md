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

# Feature profile checks
cargo check --no-default-features --profile ci              # PASS
cargo check --no-default-features --features mesh --profile ci   # PASS
cargo check --no-default-features --features dns --profile ci    # PASS
cargo check --no-default-features --features mesh,dns --profile ci  # PASS

# Full test suite
cargo test --profile ci --no-fail-fast  # PASS (2255 passed, 6 ignored)
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

## Documentation Updates

- `.opencode/skills/admin_ui/SKILL.md` — Updated API return types, added ApiError docs, added ConfirmDialog pattern, added login/logout semantics
- `src/admin/AGENTS.override.md` — Added Phase 6 corrections section (login form, confirmation dialogs, API error handling)
- `plans/admin_panel_phase_06_verification_and_closeout.md` — Status changed to COMPLETE

## Accepted Non-Blocking Residuals

1. **Unused functions**: `is_authenticated()` and associated auth helpers in `api.rs` are unused (warn-only)
2. **Legacy file_manager_ui.js**: Uses `localStorage` for `admin_token` — out of scope for admin panel correction (separate legacy JS file manager)
3. **Tarpit/stress tests**: Not run in routine CI — require separate invocation
