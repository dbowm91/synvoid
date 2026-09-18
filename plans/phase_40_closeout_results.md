# Phase 40 Closeout: YARA-X 1.20 Upgrade via Compat Fork

Status: complete (2026-09-18).
Plan: `plans/phase_40_yara_x_upgrade_reopen.md`.
Roadmap: `plans/runtime_dependency_blocker_followup_roadmap.md` (Phase 39 was
the minifier step; this phase owns the YARA-X upgrade).

## Landed state

| Item | Before (Phase 39 exit) | After (Phase 40 exit) |
|---|---|---|
| yara-x | 1.15.0 | **1.20.0 (vendored path fork**, PR #769 delta) |
| Transitive wasmtime (via yara-x) | 40.0.4 | **47.0.4** |
| Direct wasmtime (plugin-runtime) | 36.0.15 LTS | 36.0.15 LTS (unchanged) |
| minify-html | 0.18.1 (vendored fork, Oxc 0.111) | 0.18.1 vendored fork (unchanged; upstream still 0.18.1) |
| bumpalo | 3.20.3 (single, post-fork float) | **3.20.3 (single)** |
| wasmtime-wasi / wasi-filesystem | absent | absent (unchanged) |
| Git sources | none | none (unchanged; fork is a path patch, no `allow-git`) |
| Advisory ignores | 16 | **2** (0071 rsa, 0235 rkyv) |
| `YARA_ENGINE_VERSION` | `yara-x/1.15` | **`yara-x/1.20`** |
| `COMPILED_FORMAT_VERSION` | 1 | 1 (unchanged; engine-only change) |

Exact landed versions: yara-x 1.20.0 (fork), wasmtime 36.0.15 + 47.0.4,
bumpalo 3.20.3, wasm-bindgen 0.2.128 (lock float as anticipated in Phase 39).

## Part A — upstream refresh (2026-09-18)

- Latest yara-x release: **1.20.0** (2026-08-24; requires `wasmtime ^45.0.3`).
- Upstream PR #769 ("fix(deps): Bump wasmtime and msrv version", branch
  `wasmtime-47.0.4-msrv-1.94`): **OPEN, unmerged** (updated 2026-09-12).
- Advisory fixed ranges (local advisory DB): April-2026 batch patched at
  `>=43.0.1`; RUSTSEC-2026-0114 at `>=43.0.2` / `>=44.0.1`;
  RUSTSEC-2026-0222 at `>=46.0.2,<47.0.0` / `>=47.0.3`; RUSTSEC-2026-0269 at
  `>=46.0.3,<47.0.0` / `>=47.0.4`. So stock 1.20.0 (45.0.3) is affected by
  0222 + 0269; 47.0.4 (crates.io, 2026-08-20) is the minimum line patched
  for both. Wasmtime 48.0.2 stable exists (2026-09-10) but no
  upstream-reviewed yara-x change targets it — not used.
- Toolchain: SynVoid pins Rust 1.98.1; satisfies 47.0.4's `rust-version =
  "1.94.0"`. Direct plugin runtime stays on wasmtime 36.0.15 LTS (no move
  for version-matching; plan rejection criterion honored).

## Branch decision (plan Part B)

No official fixed yara-x release exists → Branch 1 does not apply; stock
1.20.0 rejected as final state (plan: "do not land stock 1.20.0 if it still
resolves 45.0.3"). Landed via **Branch 2 project-controlled minimal fork**
instead of keeping mitigated 1.15, because: GHSA-2jx3-ff3v-j7jj
version-remediation is the point of the Phase 36→40 chain (mitigation was
temporary); the 14 wasmtime-40.0.4 ignores expire at Re-audit 2026-10-01 and
the April batch + 0114 are genuinely version-affected on 40.0.4; the fork
delta is exactly the upstream PR #769 two-line change with removal metadata.
The fork does NOT track the contributor's PR branch.

## What changed (complete file list)

- `third-party/yara-x-compat/` (new): exact upstream 1.20.0 crate sources
  (`src/`, `build.rs`, `benches/`, `README.md`, `Cargo.toml.orig` retained;
  `Cargo.lock`/`.cargo_vcs_info.json` removed) + manifest-only delta
  (`wasmtime 45.0.3 -> 47.0.4`, `rust-version 1.93 -> 1.94`, lines marked
  `SYNVOID-PHASE40`) + provenance header + `README.SYNVOID.md` (complete
  delta, verification command, removal condition). Recursive diff vs the
  released crate: only `Cargo.toml` differs, by two lines.
- `Cargo.toml`: `yara-x = { path = "third-party/yara-x-compat" }` added to
  the single shared `[patch.crates-io]` section with owner/date/re-audit/
  removal metadata (minify-html entry untouched).
- `Cargo.lock`: yara-x 1.20.0 path-sourced; wasmtime 40.0.4 gone, 47.0.4 in;
  single bumpalo 3.20.3; wasm-bindgen → 0.2.128; no `wasmtime-wasi`, no git+.
- `crates/synvoid-yara/Cargo.toml`: yara-x `1.15 -> 1.20`, dropped the
  upstream-removed `linkme` feature; Phase 36 blocker comment replaced.
- `crates/synvoid-yara/src/artifact.rs`: `YARA_ENGINE_VERSION`
  `yara-x/1.15 -> yara-x/1.20`; new pinned 1.15-rejection unit test.
- `crates/synvoid-yara/tests/yara_boundary.rs`: 1.15-rejection pinned at
  the boundary suite too; blocker comment replaced.
- `tools/synvoid-repo-guards/tests/dependency_security.rs`: 0269-presence
  assertion → stale-ignore rejection + dual-line patched requirement; new
  `wasmtime_transitive_matches_baseline` (anchor pin + 40.x absence); new
  `yara_fork_is_temporary_guard`; minify-guard prose updated for the shared
  section.
- `tools/synvoid-repo-guards/tests/yara_execution_boundary.rs`: root
  ownership scan skips `[patch]` sections (governed by fork guards instead);
  version-example comment updated.
- `deny.toml` + `.cargo/audit.toml`: 14 retired 40.x-only ignores removed
  (0085–0096, 0114, 0222, 0269); 0071 comment re-pathed to yara-x 1.20.
- Docs: `architecture/dependency_security_baseline_phase25.md` (title, §2/§3/
  §5/§6, transitive anchor → 47.0.4, new §11; this closeout), `AGENTS.md`
  Known Issues (new Phase 40 entry), `SECURITY.md` (triage rows struck as
  remediated; YARA sections rewritten), `docs/RELEASE.md`,
  `architecture/{release_profile_matrix,layer_3_5_deep_dive,
  agent_knowledge_maintenance}.md`, `CHANGELOG.md` (`[Unreleased]`),
  `.opencode/skills/supply_chain/SKILL.md` (16 → 2 ignores, fork ownership).

## Acceptance criteria disposition (plan §Acceptance)

- YARA-X >= 1.19: yes — 1.20.0 (fork).
- Resolved Wasmtime line security-fixed for relevant advisories: yes —
  47.0.4 patched for 0222/0269 + April batch + 0114; `cargo audit` zero
  findings; `cargo deny check` green with no `advisory-not-detected`.
- Wasmtime 40.0.4 absent: yes (`Cargo.lock` has 36.0.15 + 47.0.4 only;
  guard-enforced).
- Phase 36 remote-source-only execution enforced: yes — no deserialize
  restored; guards re-run green; `COMPILED_FORMAT_VERSION` stays 1.
- Old engine artifacts reject deterministically: yes — pinned 1.15
  rejection tests (unit + boundary).
- YARA tests + full verification green: yes — see below.
- Obsolete ignores removed: yes — 14 removed, 2 retained with metadata.
- Direct/transitive separation clear: yes — 36.0.15 LTS vs 47.0.4 fork,
  separate owners/consumers, documented in §11.
- Temporary fork has removal metadata: yes — both manifests + README +
  baseline §11 + `yara_fork_is_temporary_guard`.
- Docs no longer say blocked: yes — blocker comments replaced; historical
  phase docs intentionally untouched (superseded by this closeout).

## Rejection criteria (none triggered)

No stock-1.20.0 landing, no contributor-branch dependency, no plugin-runtime
move, no remote-deserialize restoration, no unproven exception deletion
(every removal verified by `advisory-not-detected` + clean audit), no
convergence claim without measurement (Part H measured; dual runtime kept).

## Verification (2026-09-18, pre-commit, all green locally)

- `cargo fmt --all -- --check`: clean.
- `cargo check -p synvoid-yara --all-targets`: pass (fork lib warnings are
  upstream's, not denied).
- `cargo test -p synvoid-yara --profile ci`: 54 unit + 8 boundary pass.
- Upstream parity: fork `src/` inline unit tests from an out-of-workspace
  copy (`--no-default-features --features default-modules`): 298 passed /
  26 failed with a byte-identical failure set to a pristine stock-1.20.0
  control (25 missing-fixture module tests — fixtures excluded from the
  published crate — + 1 lock-drift goldenfile; none wasmtime-related).
- `cargo test -p synvoid-upload --profile ci`: 124 pass.
  `cargo test -p synvoid-static-files --profile ci`: 23 + 16 pass.
  `cargo test -p synvoid-repo-guards --profile ci`: all pass (21/21 in
  `dependency_security`, incl. 2 new tests).
- `cargo tree` proofs: 36.0.15 → plugin-runtime only; 47.0.4 → yara-x fork
  only (`cranelift`+`runtime`, zero `wasi` nodes); no `wasmtime-wasi` /
  `wasi-filesystem` packages; `synvoid-yara` subtree 321 → 331 unique.
- `cargo audit`: exit 0 (2 mirrored ignores; pre-existing unmaintained
  warnings only). `cargo deny check`: advisories/bans/licenses/sources ok.
- Feature profiles: `--no-default-features` (+ `mesh` / `dns` / `mesh,dns`):
  all compile (see full verify).
- Part H (same host, release, temp in-tree harness, removed before commit):
  bundled compile 9.8 → 8.0 ms; clean scan 0.241 → 0.216 ms; match scan
  0.229 → 0.203 ms; reload 5.0 → 3.6 ms. No regression. Release-binary size
  was not separately diffed (no full release link of the old graph was
  retained; `verify-release` qualification passes on the new graph).
  Footprint proxies recorded instead: `synvoid-yara` subtree 321 → 331
  unique crates (+10); dual-runtime cost explicit and accepted.
- Part I: minify-html upstream still 0.18.1 → fork retained with trigger.
- `cargo xtask verify`: 10/10 pass (609s, 2026-09-18).
- `cargo xtask verify-full`: 10/10 pass (971s, 2026-09-18).
- `cargo xtask verify-release`: (result recorded after commit; fails on dirty tree).

## Non-goals honored

No plugin-runtime move off 36 LTS; no Wasmtime convergence forced; no remote
compiled-rule execution restored; no new advisory ignores; frozen
`docs/testing/verification-contract.md` untouched (its toolchain example
still factually true); historical phase docs untouched.
