# Phase 03 — Renderer: per-scheme CSS + `::selection`

Status: **Ready**. Needs Phases 01 (registry) and 02 (resolved pair+scheme).

## Goal

`ThemeRenderer` serves the selected Halloy themes for the block/error pages:
dark variables by default, light variables under
`prefers-color-scheme: light` for `scheme = "system"`, forced single-scheme
output for `scheme = "dark" | "light"`, keeping the existing
`allow_only` (DarkOnly/LightOnly/Both) restriction semantics.

## Changes (`crates/synvoid-theme/src/renderer.rs`)

1. Translate Halloy fields to the existing `--waf-*` token set via the
   Phase 01 lookup (same path-with-fallback discipline as eggpool's
   `theme_variables()`): page/surface/text/border/primary/accent from
   `[general]` + `[text]` + `[buffer]`, preserving current fallbacks so an
   incomplete file still renders a complete page.
2. Emit a per-theme `::selection` pair (background + text) derived from the
   theme — prefer Halloy `[buffer] selection` where present, else derive —
   so selected text on block pages is never author-color-on-default-blue
   (the admin-panel instance of this bug is documented in the roadmap; the
   panel itself is out of scope for this series).
3. Keep `opaque_hex` handling for surfaces (eggpool lesson: alpha channels
   let the canvas through).
4. Keep the template layer (`template.rs`, `dir_listing.rs`) untouched —
   it consumes `--waf-*` vars only.

## Acceptance

- `/theme/css` output for `system` scheme contains both schemes plus the
  media query; forced schemes contain one; `::selection` present in all.
- Renderer unit tests: token completeness per scheme for all 50 themes
  (no missing var), selection-pair contrast floor, unknown-name fallback.
- `cargo test -p synvoid-theme --profile ci` green; clippy/fmt green.
