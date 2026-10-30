# Phase 05 — Admin UI: dual pickers + two client fixes

Status: **Ready**. Needs Phase 04 (dynamic catalog + new fields).

## Goal

Settings → Theme becomes the blog-style dual picker (dark theme, light
theme, scheme) over the 50-theme catalog, and repairs the two client defects
found in research. The panel's own internal styling (sidebar toggle,
`use_theme.rs`, `tailwind.css` classes) is untouched.

## Changes (`admin-ui/src/pages/settings.rs`, `services/api.rs`, `types/mod.rs`)

1. ThemeSection renders **Dark theme** and **Light theme** selects plus a
   **Scheme** select (`System` / `Dark` / `Light`), all populated from
   `presets_available` (no hardcoded lists). Preview pane gains a dark/light
   toggle that previews the corresponding selection (the existing
   preview-light toggle wires to it).
2. Select-binding fix: use per-option `selected={...}` (the pattern already
   in `components/forms/select.rs`) instead of bare `value={...}` on
   `<select>`, which Yew 0.23 renders as an ignored content attribute
   (pickers displayed `Sunset` / `Light` regardless of state — proven live).
   Prefer reusing the shared `Select` component; apply the same fix to the
   other hand-rolled theme selects in `site_editor.rs` if touched.
3. Mutation-result fix: `update_theme` (and `update_site_theme` if likewise
   affected) parses `AdminMutationResult`, then re-`GET`s `/theme` to
   reconcile state — ending the "save reports failure while persisting"
   behavior. Success toast only on applied status.
4. `on_save` applies the new selection to the preview immediately; panel
   re-theme still follows the existing boot-fetch path (panel styling stays
   internal per the series decision).
5. Rebuild with the pinned `trunk@0.21.14` toolchain
   (`admin-ui/scripts/extract-bootstrap.py`); keep
   `admin_ui_dist_integrity` and no-inline-scripts guards green.

## Acceptance

- Pickers list 50 themes and reflect server state on load (Playwright:
  initial paint matches `GET /theme`, save round-trips without error toast,
  reload preserves choice).
- `cargo xtask` frontend gates (repo-guards UI tests) green; committed
  `dist/` rebuilt, byte-reproducible per the existing script.
