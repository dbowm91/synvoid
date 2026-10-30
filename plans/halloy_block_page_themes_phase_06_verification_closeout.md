# Phase 06 — Verification + closeout

Status: **Ready**. Runs last; needs Phases 01–05.

## Goal

Terminal proof that the series holds: full gate green, live deployment
exercises the new pickers end to end, and the roadmap flips to IMPLEMENTED
with evidence pointers.

## Steps

1. Full gate on the series branch (`plans/halloy-block-page-themes`):
   `cargo fmt --all -- --check`, `cargo clippy --workspace --profile ci
   --all-targets -- -D warnings`, `cargo deny check`, `cargo xtask verify`
   (includes repo-guards, `security_regression` single-threaded, admin
   contract with `mesh,dns,icmp-filter`, failure injection).
2. Live pass against `~/prodtest` (operator-local, never committed):
   authenticated `curl` GET/PUT over `:8081` (legacy `preset`/`mode` PUT
   still applies; unknown name falls back), then Playwright Chromium:
   login → Settings → Theme shows two 50-entry pickers + scheme select
   matching server state; pick dark + light themes, save with no error
   toast; block-page render checked in both schemes (force via scheme
   select); text selection on the block page readable in both schemes.
3. Docs: operator-facing theme notes (wherever `[defaults.theme]` is
   documented for operators) updated for `dark_theme` / `light_theme` /
   `scheme` + legacy mapping; attribution file committed with the vendored
   themes (Phase 01).
4. Flip `halloy_block_page_themes_roadmap.md` and the `plans/roadmap.md`
   entry to **IMPLEMENTED** with proof-bearing commit SHAs. Historical
   closeouts corrected by pointer only.

## Acceptance

- `cargo xtask verify` green on the series head; live Chromium evidence
  archived operator-locally (paths, not contents, referenced in the
  closeout); roadmap statuses flipped in the same terminal commit.
