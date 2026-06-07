# Admin / OpenAPI / Schema Ownership Audit

> Created as part of MDM-A01.
> Scope: `utoipa`, `schemars`, `utoipa-swagger-ui`, OpenAPI route
> annotations, and `JsonSchema`/`ToSchema` derives.
> No code movement in this audit.

## Summary

Schema derives (`ToSchema`, `JsonSchema`) are **scattered** across the
workspace but with a clear concentration:

- `synvoid-config` is the largest single owner (53 files, ~339 derives).
- Root `src/admin/handlers/*` is the largest single owner of route
  annotations (`#[utoipa::path(...)]`): 19 files, ~250 annotations.
- `synvoid-admin` is already partially extracted and owns 6 handler
  files plus a `schema.rs` (logs, probes, system, stats, common, state).
  Its schemas are simple wrappers; route annotations are present but
  smaller than root's.
- A handful of leaf crates (`synvoid-app-handlers`, `synvoid-metrics`,
  `synvoid-mesh`) sprinkle 1–2 derives for types that appear in admin
  responses.

The full OpenAPI spec is built by `src/admin/openapi.rs:synvoidOpenApi`
(re-exported as `crate::admin::synvoidOpenApi` in `src/admin/mod.rs:17`).
That is **the** binary entry point for OpenAPI export
(`src/main.rs:34-46`), and it lives only in root. The `--export-openapi`
flag is what consumes `synvoidOpenApi::openapi_json()` and
`schemars::schema_for!(MainConfig)`.

The root binary needs to assemble the full schema, so the
`utoipa`/`schemars`/`utoipa-swagger-ui` direct deps at root are
structurally legitimate for the binary. Without measurements showing
that `utoipa`/`schemars` dominate common `cargo check` timings, there is
no case for splitting them off into a new crate or moving them into
`synvoid-admin`.

## Files in scope (count)

| Bucket | File count | Crate |
|---|---|---|
| Route annotations `#[utoipa::path(...)]` | 19 | root `src/admin/handlers/*` |
| Route annotations | 1 | root `src/admin/openapi.rs` |
| Schema DTO derives `ToSchema`/`JsonSchema` | 22 | root `src/admin/handlers/*` (also includes `openapi.rs`, `schema.rs`, `state.rs`) |
| Schema DTO derives | 53 | `synvoid-config` |
| Schema DTO derives | 7 | `synvoid-admin` (handlers + schema.rs) |
| Schema DTO derives | 2 | `synvoid-metrics` (bandwidth, payloads) |
| Schema DTO derives | 1 | `synvoid-app-handlers` (fastcgi/pool) |
| Schema DTO derives | 1 | `synvoid-mesh` (mesh/threat_intel) |
| OpenAPI spec assembly | 1 | root `src/admin/openapi.rs` |
| OpenAPI re-export | 1 | root `src/admin/mod.rs:17` |
| Schema DSL `PartialSchema`/`RefOr` | 1 | root `src/admin/schema.rs` |
| CLI export entry | 1 | root `src/main.rs:34-46` |

| File | Current crate | Exports user-facing schema? | Root binary dep? | Candidate target | Notes |
|---|---|---|---|---|---|
| `src/admin/openapi.rs` (1413 lines) | root | YES — full OpenAPI 3.1 spec | YES (binary export) | root-only for binary export | Re-exports `core_openapi::CoreOpenApi as synvoidOpenApi` (line 1372) and `mesh_openapi::MeshOpenApi as synvoidOpenApi` (line 1375). Owns the canonical `OpenApi` derive. ~26 `#[utoipa::path]` annotations and full schema composition. |
| `src/admin/mod.rs:17` | root | re-exports `synvoidOpenApi` | YES | root | single line `pub use openapi::synvoidOpenApi;`. Used by `src/main.rs:45`. |
| `src/admin/schema.rs` (10 derives) | root | YES — `PartialSchema` impls for `DateTimeUtc`, `PathBufWrapper` | YES | root-only | 10 uses. `#[utoipa::PartialSchema]` and `#[derive(ToSchema)]`. These are reused via `src/admin/schema.rs:2 pub use synvoid_admin::schema::{DateTimeUtc, PathBufWrapper};` (shim over the crate). |
| `src/admin/handlers/config.rs` (98 `utoipa::path`, 197 `utoipa` mentions) | root | YES — REST endpoints for /config | YES | root for now | 197 total `utoipa` references (largest handler by far). Not in `synvoid-admin` because it crosses many subsystems. |
| `src/admin/handlers/mesh_admin.rs` (16 `utoipa::path`) | root | YES | YES | root for now | Mesh admin endpoints; touches `crate::mesh::*` directly. |
| `src/admin/handlers/yara_rules.rs` (10 `utoipa::path`, 25 derives) | root | YES | YES | root for now | 25 `utoipa` references. Touches `crate::waf::YaraRulesManager` and mesh. |
| `src/admin/handlers/sites.rs` (11 `utoipa::path`, 22 derives) | root | YES | YES | root for now | 22 references. Site CRUD. |
| `src/admin/handlers/threat_level.rs` (11 `utoipa::path`, 21 derives) | root | YES | YES | root for now | 21 references. Threat level read/write endpoints. |
| `src/admin/handlers/icmp.rs` (6 `utoipa::path`, 14 derives) | root | YES | YES | root for now | 14 references. |
| `src/admin/handlers/spin.rs` (5 `utoipa::path`, 12 derives) | root | YES | YES | root for now | 12 references. |
| `src/admin/handlers/serverless.rs` (5 `utoipa::path`, 11 derives) | root | YES | YES | root for now | 11 references. |
| `src/admin/handlers/plugins.rs` (5 `utoipa::path`, 10 derives) | root | YES | YES | root for now | 10 references. |
| `src/admin/handlers/theme.rs` (4 `utoipa::path`, 11 derives) | root | YES | YES | root for now | 11 references. |
| `src/admin/handlers/tcp_udp.rs` (4 `utoipa::path`, 10 derives) | root | YES | YES | root for now | 10 references. |
| `src/admin/handlers/rule_feed.rs` (4 `utoipa::path`, 8 derives) | root | YES | YES | root for now | 8 references. |
| `src/admin/handlers/honeypot.rs` (4 `utoipa::path`, 10 derives) | root | YES | YES | root for now | 10 references. |
| `src/admin/handlers/upstreams.rs` (3 `utoipa::path`, 8 derives) | root | YES | YES | root for now | 8 references. |
| `src/admin/handlers/alerting.rs` (3 `utoipa::path`, 7 derives) | root | YES | YES | root for now | 7 references. |
| `src/admin/handlers/behavioral_intel.rs` (2 `utoipa::path`, 5 derives) | root | YES | YES | root for now | 5 references. |
| `src/admin/handlers/api_discovery.rs` (1 `utoipa::path`, 5 derives) | root | YES | YES | root for now | 5 references. |
| `src/admin/handlers/php.rs` (2 `utoipa::path`, 5 derives) | root | YES | YES | root for now | 5 references. |
| `src/admin/handlers/common.rs` (3 derives, 4 `utoipa` refs) | root | YES | YES | root for now | 4 references. |
| `src/admin/state.rs` (2 derives) | root | YES | YES | root for now | 2 references. |
| `src/admin/mod.rs:37` | root | OpenApi trait import | YES | root | single import for trait composition. |
| `src/main.rs:34-46` | root | binary export entry | YES | root | calls `schemars::schema_for!(MainConfig)` (line 36) and `synvoidOpenApi::openapi_json()` (line 46). |
| `crates/synvoid-config/src/*` (53 files, 339 derives) | `synvoid-config` | YES — `MainConfig` JSON schema, every config DTO | only via `schemars::schema_for!` from root | `synvoid-config` (KEEP) | Largest schema-derive surface in the workspace. Already in its own crate. The `Cargo.toml:25-26` adds `schemars` and `utoipa` as direct deps so config DTOs can be reused in admin responses. |
| `crates/synvoid-config/Cargo.toml:25-26` | `synvoid-config` | n/a (manifest) | n/a | n/a | `schemars = "0.8"`, `utoipa = { version = "5", features = ["axum_extras", "chrono"] }`. |
| `crates/synvoid-admin/src/handlers/common.rs` (4 derives) | `synvoid-admin` | YES | indirect (via root) | `synvoid-admin` (KEEP) | small handler with simple response DTOs. |
| `crates/synvoid-admin/src/handlers/logs.rs` (5 `utoipa::path`, 13 derives) | `synvoid-admin` | YES | indirect | `synvoid-admin` (KEEP) | 5 endpoints, 13 derives. |
| `crates/synvoid-admin/src/handlers/probes.rs` (11 `utoipa::path`, 25 derives) | `synvoid-admin` | YES | indirect | `synvoid-admin` (KEEP) | 11 endpoints, 25 derives. |
| `crates/synvoid-admin/src/handlers/state.rs` (1 `utoipa::path`) | `synvoid-admin` | YES | indirect | `synvoid-admin` (KEEP) | 1 endpoint, small. |
| `crates/synvoid-admin/src/handlers/system.rs` (10 `utoipa::path`, 23 derives) | `synvoid-admin` | YES | indirect | `synvoid-admin` (KEEP) | 10 endpoints, 23 derives. |
| `crates/synvoid-admin/src/handlers/stats.rs` (7 `utoipa::path`, 16 derives) | `synvoid-admin` | YES | indirect | `synvoid-admin` (KEEP) | 7 endpoints, 16 derives. |
| `crates/synvoid-admin/src/schema.rs` (4 uses) | `synvoid-admin` | YES — `PartialSchema` impls | indirect | `synvoid-admin` (KEEP) | 4 uses. Defines `DateTimeUtc`, `PathBufWrapper`. |
| `crates/synvoid-admin/Cargo.toml:14-19` | `synvoid-admin` | n/a (manifest) | n/a | n/a | has its own `schemars`, `utoipa`, `utoipa-swagger-ui` (optional, behind `swagger-ui` feature). |
| `crates/synvoid-app-handlers/src/fastcgi/pool.rs:10` | `synvoid-app-handlers` | YES (1 `ToSchema` derive) | indirect | `synvoid-app-handlers` (KEEP) | 1 derive on `PooledConnection`. Tiny. |
| `crates/synvoid-metrics/src/bandwidth.rs:3,11` (2 derives) | `synvoid-metrics` | YES | indirect | `synvoid-metrics` (KEEP) | `BandwidthPersistedState`, `BucketKey`. Used in admin /metrics responses. |
| `crates/synvoid-metrics/src/payloads.rs:5,73` (2 derives) | `synvoid-metrics` | YES | indirect | `synvoid-metrics` (KEEP) | small. |
| `crates/synvoid-mesh/src/mesh/threat_intel.rs:12,33` (1 derive) | `synvoid-mesh` | YES (1 `JsonSchema` derive) | indirect | `synvoid-mesh` (KEEP) | single `JsonSchema` derive on `ThreatIntelligenceConfig`. |
| `Cargo.toml:241-243` | root | n/a (manifest) | YES | root-only for binary export | `schemars = "0.8"`, `utoipa = { version = "5", features = ["axum_extras", "chrono"] }`, `utoipa-swagger-ui = { version = "9", features = ["axum", "vendored"], optional = true }`. |
| `Cargo.toml:22,39` | root | n/a (manifest) | YES | root | `default = [..., "swagger-ui"]` (line 22) and `swagger-ui = ["dep:utoipa-swagger-ui"]` (line 39). |

## Concentrated vs. scattered verdict

| Pattern | Verdict |
|---|---|
| `#[utoipa::path(...)]` route annotations | **Concentrated** in root `src/admin/handlers/*` (19 files) and `crates/synvoid-admin/src/handlers/*` (6 files). Almost nothing in other crates. |
| `ToSchema`/`JsonSchema` DTO derives | **Scattered** but with a single dominant owner: `synvoid-config` (53 files, 339 derives). After that, root `src/admin/handlers/*` (22 files). |
| OpenAPI spec assembly (`synvoidOpenApi`) | **Concentrated** in root `src/admin/openapi.rs` (1 file). |
| `schemars` schema-for export | **Concentrated** in root `src/main.rs:36` (single `schemars::schema_for!(MainConfig)` call). |
| `utoipa-swagger-ui` UI | **Concentrated** in root `src/admin/mod.rs:802` (single `url("/api/openapi.json", openapi::synvoidOpenApi::openapi())` route). Feature-gated. |

So the audit is not "concentrated or scattered?" — the answer is **"mostly
concentrated, with one big schema-derive cluster in `synvoid-config`."**

## Root binary dep evidence

`src/main.rs:34-46`:

```rust
if args.export_openapi {
    let schema = schemars::schema_for!(MainConfig);
    ...
} else if args.export_api_spec {
    use synvoid::admin::openapi::synvoidOpenApi;
    let spec = synvoidOpenApi::openapi_json();
    ...
}
```

The root binary is the **only** consumer of the `--export-openapi` and
`--export-api-spec` flags. It needs:

- `schemars` to call `schema_for!(MainConfig)` and write JSON.
- `utoipa` for the trait imports inside `src/admin/openapi.rs`.
- `utoipa-swagger-ui` (optional, feature-gated by `swagger-ui`) for the
  `/api/openapi.json` UI route in `src/admin/mod.rs:802`.

If we ever split the admin handler set into `synvoid-admin` completely, the
root binary would still need at least `schemars` (for `MainConfig` JSON
schema) and `utoipa` (for the `OpenApi` trait import in
`src/admin/openapi.rs`). The `utoipa-swagger-ui` dep would also stay
unless the UI is also moved.

`synvoid-admin` already has its own `utoipa`, `schemars`,
`utoipa-swagger-ui` deps (Cargo.toml:14-19), so the question is not
"can it own these?" — it can. The question is "does the root binary
itself compile OpenAPI directly enough to justify the root direct dep?"
The answer is **yes**: `src/main.rs:34-46` and `src/admin/openapi.rs` are
root-owned and compile-time-required for the export feature.

## Existing `synvoid-admin` extraction (partial)

`synvoid-admin` is already a partial extraction:

- 6 handler files (logs, probes, system, stats, common, state) with
  `#[utoipa::path]` and `ToSchema` derives.
- 1 `schema.rs` with `PartialSchema` impls.
- Own Cargo.toml deps for `schemars`, `utoipa`, `utoipa-swagger-ui`
  (optional, behind `swagger-ui` feature).
- Re-exported by root `src/admin/handlers/mod.rs:1-4`:
  `pub use synvoid_admin::handlers::{logs, probes, stats, system};`.
- Re-exported by root `src/admin/schema.rs:2`:
  `pub use synvoid_admin::schema::{DateTimeUtc, PathBufWrapper};`.
- Re-exported by root `src/admin/auth.rs:3`,
  `src/admin/rate_limit.rs:3`, `src/admin/middleware.rs:51`.

But the **largest** admin handlers are still in root:

- `config.rs` (197 `utoipa` references, 98 `utoipa::path`)
- `mesh_admin.rs` (16 `utoipa::path`, 41 references)
- `yara_rules.rs` (10 `utoipa::path`, 25 references)
- `sites.rs` (11 `utoipa::path`, 22 references)
- `threat_level.rs` (11 `utoipa::path`, 21 references)
- and 15 more

These are not in `synvoid-admin` because they cross many subsystems
(mesh, waf, config, sites) and are tightly coupled to root-only state.
The plan's non-goal "do not move worker/supervisor" extends implicitly
to the cross-subsystem admin endpoints that orchestrate those layers.

## Where the OpenAPI spec is built

`src/admin/openapi.rs` is the spec composer. It is the only file that
`use utoipa::OpenApi` at the type level and has the canonical
`synvoidOpenApi` impl. It imports handlers from across the workspace
through the admin module. It is **not** movable into `synvoid-admin`
without dragging along every other admin handler (since it references
all of them through the path-level `#[utoipa::path]` macros).

## Schema-derive alternatives (not recommended)

If we wanted to remove `utoipa` from root entirely, we would need to:

1. Move `src/admin/openapi.rs` into `synvoid-admin`.
2. Move `src/admin/schema.rs` (the `PartialSchema` impls) into
   `synvoid-admin` (already done — root file is a re-export shim).
3. Move `src/main.rs:34-46` (the CLI export flags) into a `synvoid-admin`
   binary export entrypoint, or accept that the root binary keeps the
   export.

This is a large move for no measured gain. The plan's default
recommendation is the right one: "Do not split config/schema derives
unless compile timings show schemars/utoipa dominate common checks."

## Conclusion

- Route annotations are concentrated in root `src/admin/handlers/*` (19
  files). Schema DTO derives are scattered but dominated by
  `synvoid-config` (53 files, 339 derives).
- The root binary needs `utoipa`, `schemars`, and `utoipa-swagger-ui`
  directly to compile the spec composer (`src/admin/openapi.rs`) and the
  CLI export entry (`src/main.rs:34-46`). These deps are structurally
  legitimate.
- `synvoid-admin` is a partial extraction that already owns its own
  `utoipa`/`schemars` deps. The remaining admin handlers in root are
  not in `synvoid-admin` because they cross subsystem boundaries.
- No measurement data is available in this audit to show that
  `utoipa`/`schemars` dominate common `cargo check` timings.
- The default plan recommendation is to defer. The audit agrees.

## MDM-A02 Decision

| Option | Verdict | Reason |
|---|---|---|
| `KEEP_ROOT_FOR_BINARY_EXPORT` | partially correct but incomplete | True for the binary export entry (`src/main.rs:34-46`) and the spec composer (`src/admin/openapi.rs`). False for the cross-crate `synvoid-config` derives, which are already in their own crate. |
| `MOVE_TO_SYNVOID_ADMIN` | not justified | `synvoid-admin` already owns 6 handler files + a `schema.rs`. The 19 remaining root handlers are not movable because they cross subsystem boundaries (mesh, waf, config, sites). Moving `src/admin/openapi.rs` would drag the whole admin handler set with it. |
| `FEATURE_GATE_SCHEMA_DERIVES` | not recommended | Would add a `schema` feature flag across 53 `synvoid-config` files and 22 root admin handler files. Adds maintenance cost. The current `swagger-ui` feature gate (Cargo.toml:39) is the only schema-related feature flag and is already minimal. |
| `DEFER_LOW_VALUE` | **SELECTED** | Default per the plan. No measurements show `utoipa`/`schemars` dominate common `cargo check` timings. The current arrangement is structurally correct: `synvoid-config` owns its derives, `synvoid-admin` owns its partial handler set, root owns the spec composer and binary export. **No code changes in this audit pass.** |

**Overall MDM-A02 verdict:** `DEFER_LOW_VALUE`. The schema/OpenAPI
ownership is correct as-is. The plan's default recommendation holds:
"do not split config/schema derives unless compile timings show
schemars/utoipa dominate common checks." We do not have those timings in
this audit, so we defer.

The only follow-up that might be valuable (not part of MDM-A02) would be
to **run MDM-M02** (compile-time measurement) and re-evaluate this
decision if `cargo check -p synvoid-config` or `cargo check --workspace
--all-targets` is dominated by `utoipa`/`schemars` derive expansion. That
is a measurement-driven question that this audit cannot answer.
