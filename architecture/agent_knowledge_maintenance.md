# Agent Knowledge Maintenance

How `AGENTS.md`, `.opencode/skills/`, `docs/`, `README.md`, and `plans/`
stay accurate. For agents, by an agent audit (2026-09-11, follow-up 2026-09-13,
Phase 37 pass 2026-09-17, Phase 40 pass 2026-09-18, Phase 47 pass 2026-09-19).

## What was audited (2026-09-19, Phase 47 public-crate release readiness)

- Promoted `synvoid-rate-limit` 0.1.0 to class 3 (first externally supported
  library; MSRV 1.81 with packaged-tarball evidence): new
  `architecture/public_crate_release_policy.md` (binding semver/MSRV/support
  bar) + `architecture/public_crate_release_readiness_phase47.md` (per-candidate
  decisions), crate README/CHANGELOG/rustdoc quickstart/property tests,
  `docs/releasing.md` §1a externally supported order (rate-limit only), root
  `README.md` Reusable libraries section, `AGENTS.md` Known Issues + index,
  new `public_crate_release_policy` repo-guard test, this file + new checklist
  item 9.
- Deferred with recorded reasons (no metadata implying support):
  mesh-protocol (wire-versioning/`non_exhaustive` policy), proxy-cache (object
  cache, NOT RFC 9111), dnssec-keystore (threat model/PKCS#11 CI/RSA advisory),
  platform (MSRV/semver/examples), yara (compat fork), http-client (eggfetch
  still 0.1.4, no 0.1.5+ matrix refresh), utils/core (permanently internal).
- Skills: no stale publication claims found (only `supply_chain` mentions
  `cargo publish`, correctly as manual-only) — no skill changes needed.
- Historical records deliberately NOT rewritten: `plans/*` phase history,
  `architecture/crate_boundary_reuse_closeout.md` (Phase 35 class-2 table
  stays as the pre-promotion record; the Phase 47 doc records the delta).

## What was audited (2026-09-18, Phase 40 YARA-X 1.20 upgrade)

- YARA engine 1.15 → 1.20.0 (temporary `third-party/yara-x-compat` fork,
  wasmtime 40.0.4 → 47.0.4): updated `AGENTS.md` Known Issues (new Phase 40
  entry; Phase 36 entry kept with version-remediation noted),
  `architecture/dependency_security_baseline_phase25.md` (title, §2/§3/§5/§6,
  transitive anchor 40.0.4 → 47.0.4, new §11 addendum),
  `architecture/{release_profile_matrix,layer_3_5_deep_dive}.md`,
  `docs/RELEASE.md`, `CHANGELOG.md` (`[Unreleased]` entry; 1.1.0 history
  untouched), `.opencode/skills/supply_chain/SKILL.md` (ignore count
  16 → 2, fork ownership), and this file's checklist item 8.
- `deny.toml` + `.cargo/audit.toml`: 14 retired 40.x-only ignores removed
  (0085–0096, 0114, 0222, 0269); retained 0071 (`rsa`, no upstream fix) and
  0235 (`rkyv` via minify chain).
- Historical records deliberately NOT rewritten: `plans/*` phase/closeout
  history (superseded by `plans/phase_40_closeout_results.md`),
  `architecture/track4_*`, `docs/testing/verification-contract.md` (frozen).
- Pruned: stale "bumpalo-blocked / Phase 40 owns the upgrade" forward
  references in `crates/synvoid-yara` (manifest comment, `artifact.rs` doc,
  boundary-test comment) — replaced with landed-state documentation.

## What was audited (2026-09-17, Phase 37 Wasmtime LTS migration)

- Direct runtime 42.0.2 → 36.0.15 LTS: updated `AGENTS.md` Known Issues,
  `SECURITY.md` (triage rows, dependency-policy, patch sections, limitations),
  `architecture/dependency_security_baseline_phase25.md` (§1/§3/§4/§6 + anchors),
  `architecture/{plugin_wasm,spin,layer_3_5_deep_dive}.md`, `docs/RELEASE.md`,
  `.opencode/skills/supply_chain/SKILL.md`.
- Pruned `.opencode/skills/serverless_wasm/SKILL.md` "WASI Support (Wave 4.6)":
  the `wasmtime_wasi::WasiCtxBuilder` sample described code that does not exist
  (no `wasmtime_wasi` import anywhere; `wasi_enabled` is inert `false`
  plumbing) and contradicted the guard-enforced WASI-absence invariant.
  Replaced with the absence-by-design statement.
- `README.md`: no version-pinned wasmtime content — correctly untouched.
- Historical records deliberately NOT rewritten: `plans/*` phase/closeout
  history, `architecture/track4_*`, `architecture/crate_boundary_reuse_closeout.md`,
  the 2026-09-11/13 audit entries in this file.
- New recurring checklist item 8 (wasmtime direct/transitive versions +
  guard anchors) so the next audit catches version drift mechanically.

## What was audited (2026-09-13 follow-up)

- All 37 skills re-checked; thin (<100-line) skills verified as intentional
  pointer-style guides with correct canonical paths — kept, not bulk-expanded.
- 2 skill fixes: `dht_persistence` dangling code fence + Cyrillic typo;
  `proxy_upstream` dropped a nonexistent `crates/synvoid-proxy/AGENTS.override.md`
  reference.
- 1 skill rewritten: `supply_chain_hashes` (single-fix record) →
  `supply_chain` (deny/audit gates, ignore-metadata rules, wasmtime baseline,
  pip `require_hashes`).
- 5 skills added (previously uncovered guard-enforced subsystems):
  `block_store`, `tls_termination`, `waf_engine`, `plugin_runtime`, `auth`
  — 42 total.
- 5 stale `skills/<name>.md` references fixed in `AGENTS.override.md` files
  (`src/worker/`, `src/http3/`, `src/waf/`, `crates/synvoid-dns/`; the
  `performance_patterns` ref mapped to the existing `implementation_patterns`
  skill). Canonical form is `.opencode/skills/<name>/SKILL.md`.
- `docs/`: 5 precision fixes — `PERFORMANCE.md` invalid `distributed`
  rate-limit mode → `shared` (only `shared`|`isolated` validate);
  `DEPLOYMENT.md` Docker healthcheck `/api/health` → `/health`;
  `DEVELOPER.md` `unified_server_workers` 1 → 4 (shipped `config/main.toml`);
  `CONFIGURATION.md` PQ `prefer_post_quantum` clarified as config-default-true
  but requiring `--features post-quantum` at build, empty Threat Level heading
  restructured; `WAF_MESH.md` compiled-by-default vs runtime-disabled note.
  Claims checked and left alone: `MeshConfig::enabled` defaults `false`
  (WAF_MESH "disabled by default" correct), gRPC control-plane TLS is a real
  `control_api_tls` path (DEVELOPER.md checklist kept), `wasmtime` 40.0.4 +
  42.0.2 still in `Cargo.lock` (AGENTS.md Known Issues current).
- `architecture/`: 15 one-time phase/closure reports deliberately NOT moved
  to `_archived/` — `overview.md` already labels them "Historical / closure
  reports" in the Documentation Map, and moves would churn external links for
  no agent value. Revisit only if a report starts getting cited as authority.
- `README.md`, `plans/` (completed handoff history): no action needed.

## What was audited (2026-09-11)

## What was audited (2026-09-11)

- All 35 skills in `.opencode/skills/*/SKILL.md` checked against the
  codebase. Result: no fully stale skills; 5 fixed stale paths and 2 new
  skills added (`config_system`, `admin_contract`) — 37 total.
- `architecture/` (136 docs): one live stale import fixed
  (`waf.md` `crate::upload::UploadValidator` → `synvoid_upload::…`;
  `crate::upload` was removed in Phase 03). Remaining
  `crate::auth|cgi|…` hits are intentional historical context in
  `facade_disposition_matrix.md` / `root_module_burndown_report.md`.
- `docs/` + `README.md`: no removed-facade or stale-path references.
  `README.md` gained the `protobuf-compiler` prerequisite (default `mesh`
  feature needs `protoc`; previously only `AGENTS.md` said so).
- `plans/` (186 files): completed-phase handoff artifacts retained as
  history by decision — not moved/archived to avoid a noisy rewrite.
  They are development artifacts, not operator docs (`README.md`
  says so explicitly).
- `CHANGELOG.md` member counts left untouched: `43` was correct for the
  1.1.0 release window, not a staleness bug.

## Recurring checklist for future audits

1. `grep -rn "src/config/main\|src/config/site\|src/proxy\.rs\|src/serverless/\|src/waf/attack_detection/" .opencode/skills/`
   — root `src/config/` holds only override docs; `src/serverless/`,
   `src/proxy/`, `src/waf/attack_detection/`, `src/dns/` are facades.
   Canonical code lives in `crates/synvoid-*/src/`.
2. `grep -rn "crate::auth\|crate::cgi\|crate::challenge\|crate::filter\|crate::integrity\|crate::php\|crate::proxy_cache\|crate::upload" architecture/ .opencode/skills/ docs/`
   — outside the two intentional history docs above, any hit is a bug
   (map to `synvoid_auth`, `synvoid_app_handlers::{cgi,php}`,
   `synvoid_challenge`, `synvoid_filter`, `synvoid_integrity`,
   `synvoid_proxy_cache`, `synvoid_upload`).
3. New `synvoid-*` crate or guard-enforced contract without a skill is a
   gap candidate — check the Skills list in `AGENTS.md`.
4. Skill cross-references use the canonical form
   `.opencode/skills/<name>/SKILL.md` — bare `skills/<name>.md` refs in
   `AGENTS.override.md` files are stale (audit 2026-09-13 fixed five).
   Skill directory names must match the `name:` front-matter field.
5. `README.md` Build section vs `AGENTS.md` Build & Setup: prerequisites
   (`protoc`, feature matrix) must agree.
6. `AGENTS.md` process-model line vs `src/supervisor/process.rs`
   (`spawn_unified_server_workers(config.unified_server_workers)`) and
   `config/main.toml` (`[defaults.worker_pool] workers`).
7. Operator docs vs config validation: rate-limit modes (`shared`|`isolated`
   in `crates/synvoid-config/src/site/ratelimit.rs`), health path (`/health`,
   no `/api` prefix), shipped worker count (`config/main.toml`), and
   feature-gated config defaults (`prefer_post_quantum` needs the
   `post-quantum` feature at build).
8. Wasmtime versions vs `Cargo.lock`: `rg -n '42\.0\.2|wasmtime.*42' AGENTS.md
   SECURITY.md deny.toml .cargo/audit.toml architecture/dependency_security_baseline_phase25.md
   .opencode/skills/` — any direct-42 reference outside historical
   phase/closeout reports is a bug (direct is 36.0.15 LTS; transitive 47.0.4
   via the yara-x compat fork). Guard anchors in the baseline doc
   (`wasmtime-direct-version`, `wasmtime-transitive-version`,
   `wasmtime-wasi-absent-from-lock`) must match the lock.
9. Public-crate boundary: `rg -ln 'rust-version' crates/*/Cargo.toml` must
   list only class-3 crates (currently just `synvoid-rate-limit`); any
   "externally supported"/"published"/"stable API" claim for another
   `synvoid-*` crate in `architecture/`, `.opencode/skills/`, `docs/`, or
   `README.md` is a bug unless `public_crate_release_readiness_phase47.md`
   (or a successor promotion record) names it class 3.

## Index

Indexed from `AGENTS.md` → Architecture Index ("Agent knowledge" row).
Binding detail lives with each subsystem's primary doc; this file is
process, not authority.
