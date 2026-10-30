# Phase 02 — Config: `dark_theme` / `light_theme` / `scheme`

Status: **Ready**. Depends on nothing. Unblocks Phases 03 and 04.

## Goal

`[defaults.theme]` gains blog-style dual-scheme selection
(`app/services/theme_settings.py` resolution pattern) while the legacy
`preset` + `mode` fields keep working: existing configs and API clients see
no breakage.

## Changes (`crates/synvoid-config/src/theme.rs` + example + schema)

1. `ThemeDefaults` gains `dark_theme: String` (default `"Catppuccin Mocha"`),
   `light_theme: String` (default `"Catppuccin Latte"` — blog defaults),
   `scheme: String` (default `"system"`; accepted `"system" | "dark" |
   "light"`). Keep `preset`, `mode`, `allow_only`, `colors`, `spacing`,
   `effects`, `branding` untouched.
2. Compat rule in `apply_preset()` (or a dedicated `resolve_scheme()`):
   when the new fields are at their defaults but `preset` names a legacy
   preset, both resolve to that preset's Halloy equivalent and `scheme`
   follows `mode` (`dark`/`light` → forced, `auto` → `system`). Explicit new
   fields always win. Unknown theme names fall back via Phase 01's
   `selected_halloy_theme()`, never fail closed the boot.
3. `ThemeConfig` carries the resolved pair + scheme to the renderer
   (Phase 03).
4. Update the shipped config example, `schemars`/`utoipa` schemas, and any
   config reference docs naming `preset`/`mode` as the only knobs. Mark
   `preset`/`mode` as legacy-preferred-read (still written by old clients)
   without removing them.

## Acceptance

- Old config (`preset = "ocean"`, `mode = "dark"`, new fields absent)
  resolves to ocean/ocean + forced-dark; new config resolves verbatim;
  unknown names fall back to defaults with no boot failure
  (unit tests in `synvoid-config`).
- `cargo test -p synvoid-config --profile ci` green; JSON-schema snapshot /
  example-config consistency tests updated, not deleted.
- Reduced-feature rule holds: no new config section, so no new feature gate.
