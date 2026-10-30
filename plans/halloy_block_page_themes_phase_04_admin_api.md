# Phase 04 — Admin API: dynamic catalog + dual-scheme fields

Status: **Ready**. Needs Phase 02 (config fields).

## Goal

`/theme` exposes the 50-theme catalog and the dual-scheme selection; the PUT
contract stays `AdminMutationResult` (already correct per the admin-control
authority — Phase 05 fixes the client that misparses it).

## Changes (`src/admin/handlers/theme.rs` + discovery/openapi)

1. `ThemeResponse` gains `dark_theme`, `light_theme`, `scheme`; keep
   `preset`, `mode`, `allow_only`, `colors` (colors now reflects the resolved
   dark-theme translation for backward compat).
2. `presets_available` becomes dynamic: the 50 registry names from Phase 01
   (plus the legacy `default` alias mapped to the configured default). Delete
   both hardcoded 6-entry lists (`build_theme_response`, `get_theme_presets`).
3. `UpdateThemeRequest` gains optional `dark_theme`, `light_theme`,
   `scheme`; keep accepting legacy `preset` (sets both, Phase 02 compat) and
   `mode` (maps to `scheme`). Unknown names → registry fallback, never 500.
4. Update `openapi.rs` / `api_discovery.rs` entries and the settings search
   index if it names the old fields. Audit event `requested_state` records
   the new fields.

## Acceptance

- `GET /theme` lists 50 entries; `PUT` with new fields round-trips and
  persists to `main.toml`; legacy `PUT {"preset","mode"}` still applies.
- Admin contract tests (`admin_route_contract`, `admin_router_composition`,
  `admin_smoke_flow` with `mesh,dns,icmp-filter`) green; new root test files
  carry `tests/OWNERSHIP.toml` entries in the same commit.
- Live probe: authenticated `curl` GET/PUT cycle against `:8081`.
