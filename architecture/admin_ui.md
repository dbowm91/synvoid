# Admin UI (`admin-ui`)

## 1. Purpose and Responsibility

`admin-ui/` is the Yew-based WASM single-page dashboard for SynVoid's admin control plane. It compiles to WASM via Trunk and talks to the backend exclusively through the REST/WebSocket admin API.

## 2. Build System

- `Trunk.toml` drives builds (`trunk build` / `trunk serve`), output to `dist/`.
- Toolchain: wasm-pack, Tailwind CSS + PostCSS.
- The backend serves the built assets; API alignment is guarded by the `admin_route_contract` test suite (frontend expectations vs backend routes).

## 3. Pages (24 route-level pages)

Dashboard, Sites (list/editor/detail), DNS, Mesh, Settings, Workers, Logs, Request Logs, Alerts, Honeypot, ICMP, Probes, Process Management, System Status, Threat Level, Tier Keys, Traffic Shaping, Upstreams, TCP/UDP, Login, **Observability**, **Audit Log**, **Error Pages**.

`admin-ui/src/pages/` holds one module per page plus `mod.rs`. Every module is
declared in `pages/mod.rs`, has a `Route` variant and a `switch()` arm in
`app.rs`, and (except `login`) a sidebar entry.

The last three pages were added after a route-coverage audit found that 113
backend endpoints had no caller at all. See §3.1.

### 3.1 Deliberately unwired backend routes

Not every admin route should have a dashboard surface. The following are
intentionally REST-only; this is a recorded decision, not an oversight.

| Family | Routes | Why it stays REST-only |
|---|---|---|
| `/config/defaults/*` | 18 `GET` (+1 `PUT /defaults/auth`) | A config-*generation* surface for external tooling. The panel already edits the whole document through `GET/PUT /config/main`; a second editor for per-section defaults would be a second source of truth that can silently disagree with the first. |
| `/v1/mesh/dht/stats`, `/v1/mesh/raft/status` | 2 `GET` | Legacy aliases duplicating `/mesh/dht/stats` and `/mesh/raft/status`. Exposing both would present the same number twice under two names. |
| `GET /logs` | 1 | **A backend stub**: `get_logs` ignores its entire query struct (`#[allow(dead_code)]`) and returns a constant empty page. A UI over it would render an empty table with no error. Live log surfaces are `/api/ws/logs` (used by the Logs page) and `GET /stats/requests` (Request Logs page). |
| `GET /config/schema` | 1 | Returns the schemars JSON Schema for `MainConfig`, a large machine-readable document. Useful to tooling, not to an operator scanning a dashboard. |

`GET /auth/csrf`, `POST /auth/session` and `DELETE /auth/session` **are** wired
— they are called by raw `/api/...` URLs in `services/api.rs` (session
exchange), which a `"/path"` prefix scan does not match. They are not part of
this exclusion list.

### 3.2 Still unwired

The following families were identified by the coverage audit and are **not yet
built**. They are the remaining work, not a decision to leave them alone:

- **Mesh operations** — `/mesh/topology`, `/mesh/topology/graph`, `/mesh/nodes`,
  `/mesh/dht/stats`, `/mesh/raft/status`, `/mesh/bans`, `/mesh/ban/*`,
  `/mesh/behavioral/*`, `/mesh/organizations*`, `/mesh/threat-intel/policy-shadow*`,
  `/mesh/wasm-modules`, `/mesh/blocklist/catchup-stats`,
  `/mesh/attest-capability`, `/mesh/audit/report`,
  `/mesh/report/signature-failure`. The Mesh page is currently a
  *configuration form* and calls only `GET /mesh/status` and
  `POST /mesh/derive-signing-key`.
- **YARA** — `/yara/submissions*`, `/yara/submit`, `/yara/apply`,
  `/yara/broadcast`, `/yara/sync`. Settings exposes only `GET /yara/status`.
- **Rules feed** — `/rules/status`, `/rules/check`, `/rules/apply`,
  `/rules/discard`. Runtime-gated on `rule_feed_manager` being present.
- **Plugins** — `/plugins/status`, `/plugins/metrics`, `/plugins/{name}/reload`.
- **Serverless / Spin** — `/spin/apps*`, `/serverless/config`,
  `/serverless/functions/{name}/stats`.
- **Config versions** — `/config/versions`, `/config/versions/{id}`,
  `/config/diff`, `/config/rollback/{id}`.
- **Misc reads** — `/stats/attacks`, `/upstreams/{site_id}`,
  `/sites/{site_id}/bot-detection`, `/system/php-pools*`,
  `/system/app-servers/{site_id}/logs`, `/honeypot/config`, `/icmp/config`,
  `/theme/presets`, `/theme/css`.

## 4. Shared Components

`charts`, `forms`, `tables`, `layout`, `confirm_dialog`, `toast`, `tooltip`, `skeleton`, `realtime_header` — plus service/type/hook layers wrapping the API client.

## 4.1 Theme tokens and the `action-*` ramp

Theming is CSS custom properties on `<html>`, overridden per preset class
(`theme-ocean`, `theme-forest`, `theme-sunset`, `.light`). `tailwind.config.js`
maps semantic names (`primary`, `secondary`, `tertiary`, `card`, `accent`,
`default`) onto those variables.

The `action-*` ramp (`action-300` … `action-900`) is the themeable replacement
for a hardcoded Tailwind `blue-*` ramp that ~190 call sites used to pin
literally, which left Ocean/Forest/Sunset presets rendering blue buttons on a
green or orange panel.

Two constraints shape it:

- **It is declared as raw RGB channel triplets**, not colours —
  `rgb(var(--action-600) / <alpha-value>)`. A plain `var(--x)` cannot accept
  Tailwind's opacity modifier, and the panel already relies on
  `bg-action-500/10`, `/20`, `bg-action-900/50`, `/90` for badge and toast
  tints. Writing a hex value into `--action-600` makes every tinted badge
  render fully opaque.
- **The values mirror Tailwind's blue ramp**, so the migration was a 1:1
  `blue-NNN` → `action-NNN` rename that is appearance-neutral in the default
  and light presets. Only Ocean/Forest/Sunset retint.

`src/styles.css` is a **committed build artifact**. Any class added to Rust
without re-running `npm run build:css` silently ships unstyled.

## 4.2 Request/response shape contract

Matching path + method is not sufficient. Three shipped call sites matched
both and were still broken, because the body shape was wrong:

| Call site | Defect |
|---|---|
| `validate_config` | Sent `{}`; the backend requires `{ "config": <MainConfig> }`. Every pre-flight validation 400'd, so **Settings → Server → Save never succeeded**. Invalidity is also a 200 with `valid: false`, which the old code ignored. |
| `export_config` | Used `get()`, which parses JSON; the backend returns a raw TOML document as `text/plain`. Every export failed with a parse error. |
| `import_config` | Posted a bare JSON document; the backend expects `{"config": "<TOML string>"}`. |

`AdminMutationResult.target` is modelled as `serde_json::Value`, not `String`:
the backend field is generic, and `PUT /error-pages/{code}` sends a JSON
**number**. Likewise `GET /config/log-level` reports the level inside the prose
of `message` rather than a field, so it is parsed by `parse_log_level()`.

## 5. Session Semantics (guard-relevant)

- Browser clients authenticate with an **HttpOnly session cookie + CSRF token**; bearer tokens are used only to bootstrap a session via exchange.
- 401/403 responses are treated as session expiry by the frontend, never as retryable errors.
- WebSocket connections authenticate per connection via session cookie or bearer (`/api/ws/metrics`, `/api/ws/logs` — exact paths in `src/admin/ws/mod.rs`); the legacy `synvoid_ws_token` cookie is unsupported.
- Logout is atomic: success / 401-403 clears CSRF + unauthenticated; 5xx / network retains CSRF/auth for retry.
- `ApiService` owns all REST paths (base `"/api"`; poll paths omit the prefix, WS hooks take the full path) and URL-encodes user-controlled query/path values.
- These rules mirror `architecture/admin_control_plane_authority.md`; see also [`admin_deep_dive.md`](./admin_deep_dive.md) for the backend contract.

## 6. Contract tests (Phase 05)

- `tests/admin_route_contract.rs` — exhaustive UI endpoint ↔ backend path+method check (405 vs 404 distinguishes wrong method from missing route).
- `tests/admin_router_composition.rs` — capability ↔ family cross-check, discovery/OpenAPI consistency (WS documented separately), auth/middleware classification with exact exclusions.
- Sidebar gating is a pure `sidebar_visibility()` decision function (unit-tested).
- Bounded feature matrix: minimal, `mesh`, `dns`, `icmp-filter`, `mesh,dns` (`cargo xtask verify-full`); routine CI runs the contract with `--features mesh,dns,icmp-filter`.

## 7. Related Docs

- [`admin_control_plane_authority.md`](./admin_control_plane_authority.md)
- [`admin_deep_dive.md`](./admin_deep_dive.md)
- [`security_observability.md`](./security_observability.md)
