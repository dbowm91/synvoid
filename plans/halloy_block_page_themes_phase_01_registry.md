# Phase 01 — Vendor + Halloy Registry in `synvoid-theme`

Status: **Ready**. Depends on nothing. Unblocks Phase 03.

## Goal

The 50 Halloy `.toml` files live in the repo and a pure-function registry
exposes them to the renderer: name validation with safe fallback, embedded
byte access, path-with-fallback value lookup, and the color math the renderer
and guards need. No behavior change — nothing consumes the registry yet.

## Reuse pointers (copy, do not redesign)

- Files: the identical 50-file set in eggpool
  `rust/assets/dashboard/themes/` or blog `app/themes/bundled/` (verified
  same set, same bytes; upstream https://themes.halloy.chat/).
- Logic: eggpool `rust/src/server/dashboard/theme.rs` — `THEME_NAMES`,
  `selected_theme()`, `theme_bytes()` (`include_bytes!`), `theme_value()`,
  `parse_theme_rgb`, `theme_relative_luminance`, darken/lighten, `mix_*`,
  HSL `adjust_*`, `opaque_hex`.
- Schema: blog `docs/themes/supported-schema.md` (the `[general]` /
  `[text]` / `[buffer]` (+ `selection`) / `[buttons.*]` subset with
  fallbacks per path).

## Changes

1. New directory `crates/synvoid-theme/themes/` holding the 50 vendored
   `.toml` files plus `ATTRIBUTION.md` (adapt the blog's text: Halloy
   origin, per-file `[metadata]` credits, no-endorsement disclaimer).
2. New module `crates/synvoid-theme/src/halloy.rs` (wired through `lib.rs`):
   `HALLY_NAMES: &[&str]` (the 50 names, no `default` entry — the alias
   lives at the config layer, Phase 02), `selected_halloy_theme()` (allowlist
   + `MAX_THEME_NAME_BYTES` + fallback to a `DEFAULT_HALLOY_THEME`),
   `halloy_bytes()` (`include_bytes!("../themes/…")` per name),
   `halloy_value()` (TOML path lookup with fallback), color helpers and
   `opaque_hex` ported from eggpool.
3. Guard tests in the same module (port eggpool's `mod tests` pattern,
   adapted to the `--waf-*` usages Phase 03 will serve): every bundled theme
   yields AA-safe text/pill foregrounds against its own surfaces, roles stay
   distinguishable, and a deliberate regression test proves the guards can
   fail. The tests read the served values through the same lookup the
   renderer uses, so a theme change cannot silently invalidate them.
4. Ledger check: if `synvoid-theme`'s `Cargo.toml` lacks `toml`, add the
   workspace-pinned version and record the edge per
   `architecture/root_dependency_ownership.md`.

## Acceptance

- `cargo test -p synvoid-theme --profile ci` green, including the new
  per-theme guard tests (50/50 pass, deliberate-regression tests fail
  without the guard).
- `cargo clippy -p synvoid-theme --profile ci --all-targets -- -D warnings`
  green; `cargo fmt --all -- --check` green.
- No other crate touched; no config, API, or UI change in this phase.
