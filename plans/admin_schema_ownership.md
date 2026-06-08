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

---

# RHP-A01: Admin/Schema Ownership Audit Refresh (2026-06-08)

> Refresh pass on the admin/schema ownership audit.

## Inspection findings (refresh, 2026-06-08)

**Search command**:

```bash
rg -n "utoipa|ToSchema|OpenApi|schemars|JsonSchema|swagger|export-openapi|export-api-spec" \
   src/ crates/ admin-ui/ Cargo.toml
```

**Refreshed totals**:

| Metric | root `src/` | extracted `crates/` |
|---|---:|---:|
| utoipa / ToSchema / OpenApi mentions | **529** (24 files) | **313** (50 files) |
| schemars / JsonSchema mentions | **4** (3 files) | **361** (67 files) |
| `#[utoipa::path(...)]` route annotations | **217** (20 files) | **33** (4 files in `synvoid-admin`) |
| `admin-ui/` matches | **0** | n/a |

**Binary-only export flags** (unchanged from MDM-A01):

- `--export-openapi` and `--export-api-spec` are defined in
  `crates/synvoid-cli/src/lib.rs:175,178` (bool fields) and read only
  in `src/main.rs:34,44`.
- Both branches print JSON via `serde_json::to_string_pretty` and
  call `std::process::exit(0)`. **No runtime consumer** (no admin
  HTTP route, no background task).
- `schemars::schema_for!(MainConfig)` is called at
  `src/main.rs:36`; `synvoidOpenApi::openapi_json()` is called at
  `src/main.rs:46`.

**Root `src/admin/mod.rs` swagger-ui feature gate** (unchanged):

- Line 17: `pub use openapi::synvoidOpenApi;`
- Line 37: `use utoipa::OpenApi;`
- Lines 38-39: `#[cfg(feature = "swagger-ui")] use utoipa_swagger_ui::SwaggerUi;`
- Lines 799-802: `SwaggerUi::new("/api/docs").url("/api/openapi.json", openapi::synvoidOpenApi::openapi())`

**Manifest entries** (unchanged):

- Root `Cargo.toml:22`: `default = ["socket-handoff", "mesh", "dns", "erased_pool", "swagger-ui"]` — swagger-ui is **default-on**.
- Root `Cargo.toml:39`: `swagger-ui = ["dep:utoipa-swagger-ui"]`.
- Root `Cargo.toml:231-233`: `schemars = "0.8"`, `utoipa = { version = "5", features = ["axum_extras", "chrono"] }`, `utoipa-swagger-ui = { version = "9", features = ["axum", "vendored"], optional = true }`.

## Per-file table (refresh)

| File | Owner | Dep | User-facing? | Candidate owner | Notes |
|------|-------|-----|--------------|-----------------|-------|
| `src/admin/openapi.rs` (1611 lines) | root | utoipa | Yes (CLI export) | `synvoid-admin` (deferred) | Spec composer; 85 utoipa mentions |
| `src/admin/handlers/config.rs` (197 lines) | root | utoipa, schemars | Yes | `synvoid-admin` (deferred) | Largest single-file consumer |
| `src/admin/handlers/*.rs` (19 files) | root | utoipa | Yes | `synvoid-admin` (deferred) | Cross subsystem boundaries (mesh, waf, config, sites) |
| `src/admin/schema.rs` | root | utoipa | Yes | `synvoid-admin` (deferred) | Schema helpers |
| `src/admin/state.rs` | root | utoipa | Yes | `synvoid-admin` (deferred) | Admin state types |
| `src/admin/mod.rs` | root | utoipa, utoipa-swagger-ui | Yes | `synvoid-admin` (deferred) | Includes Swagger UI mount at lines 799-802 |
| `src/main.rs` | root | utoipa, schemars | CLI export | root (binary-only) | `--export-openapi` / `--export-api-spec` |
| `src/mesh/dht/mod.rs` | root (mesh shim) | schemars | Yes (config schema) | `synvoid-mesh` (deferred) | `JsonSchema` derive |

## RHP-A01 conclusion

**Defer**, same as MDM-A02. The schema/OpenAPI ownership is
structurally correct. No source code changes were made in this audit
pass. RHP-A02 (next) makes the decision affirmative (see below).

---

# RHP-A02: Root Schema Dependency Ownership Decision (2026-06-08)

> Decision pass on whether the root binary's `utoipa` / `schemars` /
> `utoipa-swagger-ui` direct dependencies remain justified given the
> post-RHP-A01 evidence. No source code changes.

## 1. Inspection findings summary

The RHP-A01 audit (this document, just above) confirmed:

- **utoipa in root `src/`**: 529 mentions across 24 files, dominated
  by `src/admin/openapi.rs` (85) and `src/admin/handlers/config.rs`
  (197). The 24 files are nearly all under `src/admin/handlers/*`
  (19 files, ~217 `#[utoipa::path]` annotations) plus
  `src/admin/openapi.rs`, `src/admin/schema.rs`,
  `src/admin/state.rs`, `src/admin/mod.rs`, and `src/main.rs`.
- **schemars in root `src/`**: 4 mentions across 3 files
  (`src/main.rs:36` for `schemars::schema_for!(MainConfig)`,
  `src/admin/handlers/config.rs` for `use schemars::schema_for;`,
  `src/mesh/dht/mod.rs` for `use schemars::JsonSchema;`).
- **utoipa-swagger-ui in root `src/`**: 1 use at
  `src/admin/mod.rs:799-802`, feature-gated by `swagger-ui`
  (`Cargo.toml:22,39`), default-on.
- **`--export-openapi` and `--export-api-spec` are binary-only**:
  defined in `crates/synvoid-cli/src/lib.rs:175,178`, read **only**
  in `src/main.rs:34,44`. Both code paths print JSON and `exit(0)`.
  **No runtime consumer** (no admin HTTP route, no background task).
- The OpenAPI spec composer is root-owned: `src/admin/openapi.rs`
  (1611 lines), re-exported as `synvoidOpenApi` at
  `src/admin/mod.rs:17` and consumed by `src/main.rs:45`.
- `synvoid-admin` already declares its own `utoipa`, `schemars`, and
  `utoipa-swagger-ui` deps in `crates/synvoid-admin/Cargo.toml:19-21,42`,
  but it **does not own the live admin HTTP server**; it owns 6
  handler files plus a `schema.rs`, all re-exported by root.

## 2. Classification per dependency

| Dependency | Classification | Reason |
|---|---|---|
| `utoipa` | **KEEP_ROOT_FOR_BINARY_EXPORT** | The spec composer (`src/admin/openapi.rs`) and 19 of 24 root consumers (`src/admin/handlers/*`) are root-owned. `src/main.rs:45` consumes `synvoidOpenApi` for the `--export-api-spec` path. `utoipa::OpenApi` is the trait import at `src/admin/mod.rs:37` that the spec composer depends on. Root cannot drop this dep. |
| `schemars` | **KEEP_ROOT_FOR_BINARY_EXPORT** | The single `schemars::schema_for!(MainConfig)` call at `src/main.rs:36` is what powers `--export-openapi`. The 2 other root mentions (`src/admin/handlers/config.rs`, `src/mesh/dht/mod.rs`) are re-exports / `JsonSchema` derives that would either need to follow their parent types or be removed if config / mesh DHT move. The dominant `schemars` footprint is in `synvoid-config` (already crate-local). |
| `utoipa-swagger-ui` | **KEEP_ROOT_FOR_BINARY_EXPORT** | Single root use at `src/admin/mod.rs:799-802` mounts Swagger UI at `/api/docs` against the root-owned `synvoidOpenApi::openapi()` value. The `swagger-ui` feature is default-on (`Cargo.toml:22`). |

## 3. Decision: KEEP_ROOT_FOR_BINARY_EXPORT

This decision matches the plan's default recommendation in
`plans/remaining_http_runtime_and_schema_path.md` § 7:

> "Keep root schema export if it is used only by binary flags such as
> --export-openapi / --export-api-spec and does not dominate compile
> timing. Move only if measurements show schemars/utoipa are a hot path."

RHP-A01 already confirmed `--export-openapi` / `--export-api-spec`
have no runtime consumer — they are binary-only CLI paths. The spec
composer (`src/admin/openapi.rs`) is root-owned and structurally
required. The 19 root admin handler files that consume `utoipa` are
intentionally not in `synvoid-admin` because they cross subsystem
boundaries (mesh, waf, config, sites) and the plan's § 2 non-goal is
"do not move worker or supervisor" — the admin handler set that
orchestrates those layers is implicitly out of scope. Moving the spec
composer to `synvoid-admin` would require moving all 24 root admin
handler files with it; this is out of scope for this pass and is not
justified by any current measurement.

`synvoid-admin` already owns its own `utoipa`/`schemars`/
`utoipa-swagger-ui` deps for its 6-file partial handler set, so the
question is not "can it own these?" — it can. The question is
"does the root binary compile OpenAPI directly enough to justify a
root direct dep?" — and the answer is yes, because
`src/main.rs:34,44` and `src/admin/openapi.rs` are root-owned and
compile-time required for the export feature.

**Rejected alternatives**:

| Option | Why rejected |
|---|---|
| `MOVE_TO_SYNVOID_ADMIN` | Would require moving all 24 root `utoipa`-using files (or at minimum the spec composer + every handler it references through `#[utoipa::path]`). Out of scope per plan § 2 non-goal. |
| `FEATURE_GATE_SCHEMA_DERIVES` | Would add a `schema` feature flag across 53 `synvoid-config` files, 22 root admin handler files, and the spec composer. Maintenance cost is high. The existing `swagger-ui` feature flag (root `Cargo.toml:22,39`) is already the minimal schema-related feature gate. |
| `CREATE_SYNVOID_SCHEMA_LATER` | Premature — the dominant `schemars` owner (`synvoid-config`) is already in its own crate. A new `synvoid-schema` crate would just re-export the same `MainConfig` and admin DTOs without removing any root dep. |
| `DEFER_LOW_VALUE` | Considered, but `KEEP_ROOT_FOR_BINARY_EXPORT` is a positive, evidence-grounded decision (not a punt). |

## 4. Re-evaluation preconditions

This decision is conditional. The following would each be sufficient
cause to revisit it and re-run the audit:

1. **MDM-M02 measurements show `utoipa`/`schemars` dominate
   `cargo check -p synvoid` or `cargo check --workspace --all-targets`
   timings.** Currently no such measurement exists. A profile that
   shows, for example, `utoipa` macro expansion contributing >20% of
   root binary compile time would justify splitting the spec composer
   into `synvoid-admin` and forcing a bigger admin handler extraction.
2. **A new runtime consumer of the OpenAPI surface appears** — e.g.
   the admin server begins serving the live spec via an HTTP route
   consumed by the UI at request time, or a remote admin client
   fetches the spec over the mesh. Today the spec is exported only
   via one-shot CLI flags; if that changes, the ownership question
   also changes (the spec would then be a live data-plane artifact,
   not a build-time export).
3. **The admin handler set consolidates into `synvoid-admin`**, which
   would only happen if the plan's § 2 non-goal "do not move
   worker/supervisor" is relaxed and the cross-subsystem admin
   endpoints are extracted. Multi-month refactor, not in any active plan.
4. **The `swagger-ui` feature is removed or moved to default-off.**
   This would let `utoipa-swagger-ui` become a `FEATURE_FORWARD_ONLY`
   candidate.

## 5. MDM-M02 measurement follow-up needed

Per the plan's § 7 default, the next concrete action item is to
**run MDM-M02** — a compile-time measurement of:

- `cargo clean && cargo check -p synvoid 2>&1 | tee /tmp/synvoid-check.log`
  — record wall-clock time, and `cargo build --timings` for a
  per-crate breakdown.
- `cargo clean && cargo check --workspace --all-targets 2>&1 | tee /tmp/workspace-check.log`
  — same.
- Optionally, use `cargo nextest` or `cargo llvm-lines` to attribute
  compile time to specific crates.

If the measurement shows `utoipa`/`schemars` contribute less than
~20% of root binary compile time, this decision stands. If they
contribute more, re-open RHP-A02 with the measurements attached.

**No source code changes in this decision pass.** RHP-A02 is
documentation only.

---

# RHP-A03: Stale Schema Imports Cleanup (2026-06-08)

> Cleanup pass: replace any root `schemars`/`utoipa` imports where
> the symbol has been moved to an extracted crate.

## Search results

| Search | Result |
|--------|--------|
| `rg -n "use schemars::" src/` | 2 statements (main.rs, admin/handlers/config.rs) |
| `rg -n "use utoipa::" src/` | 33 statements across 24 files |
| `rg -n "pub use schemars\|pub use utoipa" crates/` | **0 matches** — no extracted crate re-exports these symbols |

## Findings

Every root import already points at the upstream `schemars`/`utoipa`
crate, which is the canonical home. No extracted crate has **moved**
any of these symbols, so there is nothing to redirect.

Reasons each import was left alone:

1. **Root struct derives are root-owned.** The structs that derive
   `#[derive(utoipa::ToSchema)]` or `#[derive(schemars::JsonSchema)]`
   live in root. The `use utoipa::ToSchema;` import at the top of
   those files is mandatory to bring the derive macro into scope.
2. **The spec composer (`src/admin/openapi.rs`) is root-owned.** The
   `use utoipa::OpenApi;` at `src/admin/mod.rs:37` is required
   because `synvoidOpenApi` (defined in root) implements
   `utoipa::OpenApi`.
3. **`schemars::schema_for!(MainConfig)` at `src/main.rs:36`** powers
   `--export-openapi`. The call is binary-only and uses the upstream
   crate directly.
4. **`src/mesh/dht/mod.rs`'s `use schemars::JsonSchema;`** is for the
   root mesh shim's DHT types. The DHT schema derives are used by
   the spec composer (`src/admin/openapi.rs`).
5. **`utoipa_swagger_ui::SwaggerUi` at `src/admin/mod.rs:799-802`**
   is the only root consumer; `synvoid-admin` declares the dep but
   no caller enables the crate's `swagger-ui` feature flag from
   root.

## Validation

| Command | Result |
|---------|--------|
| `cargo check --lib --no-default-features` | 2 errors (pre-existing Send-bound at `src/http/server/accept_loop.rs:154`) |
| `cargo check --workspace --all-targets` | 3 errors (pre-existing, same file) |

No new errors introduced.

## Verdict

**No stale imports exist.** Zero files modified. The schema
imports are all already canonical (pointing at the upstream crate
that owns the macro/trait).

## File:line changes

**None.**
