# Agent Knowledge Maintenance

How `AGENTS.md`, `.opencode/skills/`, `docs/`, `README.md`, and `plans/`
stay accurate. For agents, by an agent audit (2026-09-11, follow-up 2026-09-13).

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

## Index

Indexed from `AGENTS.md` → Architecture Index ("Agent knowledge" row).
Binding detail lives with each subsystem's primary doc; this file is
process, not authority.
