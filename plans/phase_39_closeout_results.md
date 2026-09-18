# Phase 39 Closeout: Minify-HTML / Oxc Blocker Remediation

Status: complete (2026-09-18).
Plan: `plans/phase_39_minify_html_oxc_blocker_remediation.md`.
Roadmap: `plans/runtime_dependency_blocker_followup_roadmap.md` (Phase 39 is
the minifier step; Phase 40 owns the YARA-X upgrade).

## Landed state

| Item | Before (Phase 38 exit) | After (Phase 39 exit) |
|---|---|---|
| yara-x | 1.15.0 | 1.15.0 (unchanged; Phase 40 owns >=1.19) |
| Transitive wasmtime (via yara-x) | 40.0.4 | 40.0.4 (unchanged) |
| Direct wasmtime (plugin-runtime) | 36.0.15 LTS | 36.0.15 LTS (unchanged) |
| minify-html | 0.18.1 (registry, Oxc 0.95) | 0.18.1 (**vendored path fork**, Oxc 0.111) |
| oxc_allocator | 0.95.0 (pins bumpalo =3.19.0) | **0.111.0** (no external bumpalo edge) |
| bumpalo | 3.19.0 (single) | 3.19.0 (single; now cranelift/wasmtime only — **no minify-html edge**) |
| wasmtime-wasi / wasi-filesystem | absent | absent (unchanged) |
| Git sources | none | none (unchanged; fork is a path patch, no `allow-git`) |
| Advisory ignores | 16 | 16 (unchanged; verified exact) |
| `YARA_ENGINE_VERSION` | `yara-x/1.15` | `yara-x/1.15` (unchanged) |

Exact landed versions: yara-x 1.15.0, wasmtime 36.0.15 + 40.0.4, bumpalo
3.19.0, minify-html 0.18.1 (vendored) → oxc_allocator 0.111.0.

## What changed (complete file list)

- `third-party/minify-html-compat/` (new): exact 0.18.1 `src/` + manifest-only
  Oxc 0.95 -> 0.111; `README.SYNVOID.md` documents the complete delta.
- `Cargo.toml`: root `[patch.crates-io]` path override (only patch in the
  workspace) with owner/date/re-audit/removal metadata.
- `Cargo.lock`: minify-html now path-sourced; Oxc family 0.95 -> 0.111
  (+ `oxc_str` 0.111.0); no other version floats.
- `crates/synvoid-static-files/tests/minify_parity.rs` (new, 16 tests):
  parity corpus + upstream API-shape pin.
- `tools/synvoid-repo-guards/tests/dependency_security.rs`:
  `minify_fork_is_temporary_guard` (single path-only patch, Oxc pins,
  metadata, no git, `unknown-git = deny` with zero allows).
- Docs: `architecture/dependency_security_baseline_phase25.md` §10 (binding) +
  header through Phase 39; `AGENTS.md` Known Issues;
  `.opencode/skills/supply_chain/SKILL.md`;
  `architecture/upload.md`; `SECURITY.md` (wasmtime upgrade + GHSA sections);
  this closeout; plan status line.

## Acceptance criteria disposition (plan §Acceptance)

- Resolver failure reproduced and documented: yes — isolated scratch crate
  (`oxc_allocator =0.95.0` + `wasmtime =45.0.3` → `bumpalo =3.19.0` vs
  `^3.20.0` unresolvable); workspace `cargo update -p yara-x --precise 1.20.0`
  additionally hits the `linkme` feature removal first (Phase 40 manifest
  work), recorded in §10.
- Crate-local parity coverage: yes — 16 tests, passing on the 0.18.1 baseline
  before the switch.
- Fork minimal and pinned: yes — byte-identical `src/` (recursive diff),
  manifest-only Oxc bump, path patch (workspace commit is the immutable pin),
  no git source.
- `minify-html` no longer resolves Oxc 0.95: yes (`oxc_allocator@0.95` matches
  nothing; 0.111.0 in lock).
- External bumpalo 3.19 path gone: yes (`cargo tree -i bumpalo` has no
  oxc/minify edge; remaining 3.19.0 is cranelift/wasmtime only).
- YARA-X 1.20 probe past the old conflict: yes — disposable copy with `linkme`
  dropped resolves past bumpalo (then wasm-bindgen float); full `cargo update`
  in that copy lands yara-x 1.20.0 + wasmtime 45.0.3 + single bumpalo 3.20.3.
  Stock 1.20.0 deliberately NOT committed (Phase 40).
- Semantics acceptable: yes — parity goldens byte-identical (zero diffs to
  classify); throughput +15% (20.3k -> 23.3k iters/s), output bytes identical.
- Temporary metadata + removal trigger: yes — both manifests + guard +
  baseline §10; re-audit 2026-10-01.
- Full verification green: see below.

## Verification (2026-09-18, pre-commit, all green locally)

- `cargo fmt --all -- --check`: clean (one formatting pass applied to the new
  parity test file only; vendored fork excluded as a non-member path patch).
- `cargo test -p synvoid-static-files --test minify_parity --profile ci`: 16/16
  (both before and after the fork — byte-identical).
- `cargo test -p synvoid-static-files --profile ci`: 23 unit + 16 parity pass.
- `cargo test -p synvoid-repo-guards --profile ci`: all pass, including the new
  `minify_fork_is_temporary_guard` (19/19 in `dependency_security`).
- `cargo test -p synvoid-http --profile ci`: pass.
- `cargo clippy -p synvoid-static-files --all-targets --profile ci` and
  workspace `cargo clippy --profile ci --all-targets`: pass
  (2 lifetime-elision warnings inside vendored upstream `parse/mod.rs` are
  dependency warnings, not denied; vendored `src/` intentionally untouched).
- `cargo check -p synvoid-static-files --all-targets --profile ci`: pass.
- `cargo tree` proofs: §10 resolver set (minify path source, oxc 0.111, no
  minify->bumpalo edge, features).
- `cargo deny check`: pass (advisories/bans/licenses/sources ok).
  `cargo audit`: exit 0 (16 mirrored ignores; 6 pre-existing unmaintained
  warnings on unrelated transitive crates, none from the Oxc/minify change).
- Feature profiles: `--no-default-features` (+ `mesh` / `dns` / `mesh,dns`):
  all compile.
- `cargo xtask verify`: 10/10 pass (439s).
- `cargo xtask verify-full`: 10/10 pass (659s).

## Non-goals honored

No YARA-X upgrade committed; direct runtime stays on Wasmtime 36 LTS; no
Wasmtime convergence forced; Oxc not vendored wholesale (registry 0.111 family
still used); fork has no SynVoid-specific behavior and is upstreamable as the
PR #270 manifest bump; no minification features removed.

## Handoff to Phase 40

Phase 40 needs (no minifier work): drop `linkme` from
`crates/synvoid-yara/Cargo.toml` (feature removed upstream >=1.19), float the
lock (including the admin-ui `wasm-bindgen` chain: 0.2.122 -> >=0.2.125),
re-validate engine behavior, bump `YARA_ENGINE_VERSION`, and clear the
transitive 0269 ignore when wasmtime 40.x leaves the graph. Prefer an official
YARA-X release containing the PR #769 (or successor) Wasmtime fix; never land
stock 1.20.0 solely to trade wasmtime 40 for affected 45.0.3 without the fix.
