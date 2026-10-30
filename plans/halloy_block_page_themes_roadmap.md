# Halloy Block-Page Themes Roadmap

Status: **READY** (branch `plans/halloy-block-page-themes`; no phase started).

Registered in: `plans/roadmap.md`.

Origin: the admin panel's Settings → Theme section offers 6 hardcoded presets
(`default/dark/light/ocean/forest/sunset`, hand-listed in three places) that
drive the WAF block/error pages, while the panel's own styling is a separate
internal 5-way scheme. There is no Halloy support anywhere in synvoid
(`grep -ri halloy` over the repo is empty). Research (2026-10-30, live
Chromium pass + API probes) also found three defects in the current theme
surface that this series repairs as prerequisites:

- `PUT /theme` returns `AdminMutationResult`, but the UI parses it as
  `ThemeResponse` — every save "fails" client-side while persisting
  server-side.
- The ThemeSection `<select value={...}>` sets the `value` content attribute,
  which the browser ignores for current selection — the pickers display the
  last options (`Sunset` / `Light`) regardless of server state. The shared
  `components/forms/select.rs` already uses the correct per-option
  `selected={...}` pattern; ThemeSection does not use it.
- No `::selection` rule exists in admin CSS, so selected secondary/tertiary
  text is near-unreadable on the browser-default highlight.

Decisions (operator, 2026-10-30):

- (a) The 50 Halloy themes drive the **block/error pages**, optionally — they
  are **not tied to admin-panel styling**, which stays internal to the admin
  (sidebar toggle, `use_theme.rs`, `tailwind.css` theme classes untouched).
- (b) Settings offers a **dark-theme picker and a light-theme picker**
  (blog-style: `theme_dark_name` / `theme_light_name` /
  `theme_default_scheme`), each listing the 50 Halloy themes; the renderer
  selects via `prefers-color-scheme` with a forced-scheme override.

Reuse (do not reinvent):

- The 50 `.toml` files: identical set in `eggpool`
  `rust/assets/dashboard/themes/` and the blog `app/themes/bundled/`
  (verified byte-identical file + identical filename set; upstream source
  https://themes.halloy.chat/). Vendor the same 50 files plus an
  attribution file adapted from the blog's `ATTRIBUTION.md`.
- Registry/translation logic: eggpool `rust/src/server/dashboard/theme.rs`
  (`THEME_NAMES` allowlist + fallback, `include_bytes!` embedding,
  path-with-fallback lookup, color math, `opaque_hex`, per-theme WCAG guard
  tests). Schema subset: blog `docs/themes/supported-schema.md`.
  Dual-scheme resolution: blog `app/services/theme_settings.py`.

Phases (in order; 01 and 02 are independent of each other, 03 needs 01+02,
04 needs 02, 05 needs 04, 06 runs last):

| Phase | File | Status |
|---|---|---|
| 01 | `halloy_block_page_themes_phase_01_registry.md` | **Ready** — vendor 50 files + registry in `synvoid-theme`, contrast guard tests |
| 02 | `halloy_block_page_themes_phase_02_config.md` | **Ready** — `dark_theme` / `light_theme` / `scheme` on `[defaults.theme]`, legacy `preset`+`mode` compat |
| 03 | `halloy_block_page_themes_phase_03_renderer.md` | **Ready** — per-scheme CSS generation + `::selection`, needs 01+02 |
| 04 | `halloy_block_page_themes_phase_04_admin_api.md` | **Ready** — dynamic `presets_available`, new request/response fields, needs 02 |
| 05 | `halloy_block_page_themes_phase_05_admin_ui.md` | **Ready** — dual pickers + scheme select, select-binding fix, mutation-result fix, needs 04 |
| 06 | `halloy_block_page_themes_phase_06_verification_closeout.md` | **Ready** — terminal gate + live proof, runs last |

Binding constraints for all six phases:

- Admin authority (`architecture/admin_control_plane_authority.md`): `PUT
  /theme` keeps returning `AdminMutationResult`; Phase 05 fixes the frontend
  to parse it (backend already correct). No new mutating endpoint.
- Request-path boundary: the registry is pure functions over embedded bytes
  (no concrete state, no config access); rendering stays in `synvoid-theme`.
- Facades/ledger: `admin` stays `keep_app_root`; reusable logic in
  `synvoid-theme` / `synvoid-config`. No new crate. `synvoid-theme` gains a
  `toml` edge only if not already present — ledger check in Phase 01.
- Reduced-feature binaries fail closed (Phase 41): new fields live on the
  existing `[defaults.theme]` table with defaults; no new capability section.
- `admin-ui/dist/` is committed: Phase 05 rebuilds with the pinned
  `trunk@0.21.14` and keeps `admin_ui_dist_integrity` green.
- Every new root `tests/*.rs` file needs a `tests/OWNERSHIP.toml` entry in
  the same commit; `class = "domain"` rejected.
- Historical closeouts corrected by pointer only, never rewritten.

Explicitly out of scope: admin-panel internal styling (`use_theme.rs`,
sidebar toggle, `tailwind.css` theme classes); a custom `themes_dir`
override (eggpool has one — deferred to a follow-up); per-site error-page
themes (`site_editor.rs` stays on legacy presets); the `::selection` fix for
the admin panel itself (separate from block-page `::selection` in Phase 03).

Verification strategy (all phases):

```bash
cargo fmt --all -- --check
cargo clippy --workspace --profile ci --all-targets -- -D warnings
cargo xtask verify        # full gate before merge
```

Live deployment evidence (operator-local `~/prodtest`, never committed):
authenticated `curl` against `:8081` for each touched endpoint plus a
Playwright Chromium pass over Settings → Theme (50-entry pickers,
save round-trip, block-page render in both schemes).
