---
name: config_system
description: Config system canonical paths, --config-path directory semantics, --configtest CWD caveat, and site/upstream schema. Use when touching configuration schema, site TOML, or config load paths.
---

# Config System Skill

## Canonical paths

All config implementation lives in `crates/synvoid-config/src/`. Root
`src/config/` contains only `AGENTS.override.md` — there is **no**
`src/config/main.rs`, `src/config/admin.rs`, or `src/config/site/*.rs`.
Never cite those paths; they do not exist.

Key files:

- `crates/synvoid-config/src/lib.rs` — crate root, re-exports
- `crates/synvoid-config/src/main_config.rs` — `MainConfig` load wiring
  (calls `mesh_config.load_node_identity()` at load time)
- `crates/synvoid-config/src/mesh.rs` — mesh config incl.
  `load_node_identity()`
- `crates/synvoid-config/src/site/` — per-site schema (`proxy.rs`,
  `backend.rs`, `attack_detection.rs`, `listen.rs`, …)
- `crates/synvoid-config/src/admin.rs` — admin service config
- `crates/synvoid-config/src/serverless.rs` — `FunctionDefinition`
- `crates/synvoid-config/src/process.rs` — `unified_server_workers`,
  worker-pool sizing

Full reference: `architecture/config.md`, `architecture/core_types.md`,
subsystem rules in `src/config/AGENTS.override.md`.

## CLI semantics (do not regress)

- `--config-path` takes the **directory** containing `main.toml` + `sites/`,
  not the TOML file itself.
- `--configtest` ignores `--config-path` and validates `./config/`
  relative to CWD. Run it from the intended configuration root; a passing
  test never covers another directory.

## When adding a config option

1. Add the field with a `#[serde(default = ...)]` in the owning
   `crates/synvoid-config/src/` module (site-level under `site/`,
   global under the topical file).
2. Check `architecture/dns_config_runtime_matrix.md` if the option is
   DNS-related (config-vs-runtime matrix constraints apply).
3. Update `docs/CONFIGURATION.md` and `config/main.toml.example` if the
   option is user-facing.
4. Config parsing lives behind the composition boundary: request-path code
   consumes config snapshots, never the loader.
