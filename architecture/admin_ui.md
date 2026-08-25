# Admin UI (`admin-ui`)

## 1. Purpose and Responsibility

`admin-ui/` is the Yew-based WASM single-page dashboard for SynVoid's admin control plane. It compiles to WASM via Trunk and talks to the backend exclusively through the REST/WebSocket admin API.

## 2. Build System

- `Trunk.toml` drives builds (`trunk build` / `trunk serve`), output to `dist/`.
- Toolchain: wasm-pack, Tailwind CSS + PostCSS.
- The backend serves the built assets; API alignment is guarded by the `admin_route_contract` test suite (frontend expectations vs backend routes).

## 3. Pages (~21 route-level pages)

Dashboard, Sites (list/editor/detail), DNS, Mesh, Settings, Workers, Logs, Request Logs, Alerts, Honeypot, ICMP, Probes, Process Management, System Status, TCP/UDP, Threat Level, Tier Keys, Traffic Shaping, Upstreams.

## 4. Shared Components

`charts`, `forms`, `tables`, `layout`, `confirm_dialog`, `toast`, `tooltip`, `skeleton`, `realtime_header` — plus service/type/hook layers wrapping the API client.

## 5. Session Semantics (guard-relevant)

- Browser clients authenticate with an **HttpOnly session cookie + CSRF token**; bearer tokens are used only to bootstrap a session via exchange.
- 401/403 responses are treated as session expiry by the frontend, never as retryable errors.
- WebSocket connections authenticate via session cookie only.
- These rules mirror `architecture/admin_control_plane_authority.md`; see also [`admin_deep_dive.md`](./admin_deep_dive.md) for the backend contract.

## 6. Related Docs

- [`admin_control_plane_authority.md`](./admin_control_plane_authority.md)
- [`admin_deep_dive.md`](./admin_deep_dive.md)
- [`security_observability.md`](./security_observability.md)
