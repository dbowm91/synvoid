# Agent Knowledge Maintenance

How `AGENTS.md`, `.opencode/skills/`, `docs/`, `README.md`, and `plans/`
stay accurate. For agents, by an agent audit (2026-09-11).

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
4. `README.md` Build section vs `AGENTS.md` Build & Setup: prerequisites
   (`protoc`, feature matrix) must agree.
5. `AGENTS.md` process-model line vs `src/supervisor/process.rs`
   (`spawn_unified_server_workers(config.unified_server_workers)`) and
   `config/main.toml` (`[defaults.worker_pool] workers`).

## Index

Indexed from `AGENTS.md` → Architecture Index ("Agent knowledge" row).
Binding detail lives with each subsystem's primary doc; this file is
process, not authority.
