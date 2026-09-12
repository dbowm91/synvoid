# Phase 05 Closeout — Admin Contract and Feature-Profile Verification

Status: implemented (this commit).

## Routes / profile matrix tested

- Always-available families (exhaustive in `tests/admin_route_contract.rs`):
  auth session lifecycle, stats (7 + filtered variants), sites/upstreams/logs,
  config read/write incl. all `defaults/*` sub-configs, TCP/UDP +
  probes/threat-level/rule-feed, system/process/alerts/theme/honeypot/
  observability/discovery, canonical WebSockets.
- Feature-gated families (cfg-gated assertions, executed with
  `--features mesh,dns,icmp-filter` in routine CI):
  `dns` (`/config/dns`), `mesh` (config + YARA/mesh/topology/plugins/
  serverless/spin/tier-keys), `icmp-filter` (`/icmp/*`).
- Absence enforced: `/system/master`, `/system/overseer`,
  `/config/overseer`, singular worker restart, `/api/logs/realtime`,
  namespaced `/api/mesh/tier-keys`, fabricated routes, non-canonical
  `/api/ws/*` near-misses. Wrong-method drift distinguished (405 vs 404).
- Capability ↔ family cross-check
  (`capabilities_match_compiled_route_families`): `mesh_admin`→`mesh`,
  `dns_admin`→`dns`, `icmp_admin`→`icmp-filter`; `honeypot`/`process_manager`
  always true with always-registered families.
- Discovery (`GET /api/`) + OpenAPI (`/api/openapi.json`, public) consistency:
  operator categories present, sampled endpoints registered, WebSockets
  documented separately (never as HTTP paths).
- Auth/middleware classification: public health/OpenAPI/docs, session
  bootstrap semantics, protected REST 401, session CSRF 403 + bearer bypass,
  per-connection WS auth (401 without creds), exact middleware exclusions.

## Test commands and results

Routine (CI, 9 invocations):

```text
cargo xtask verify
# fmt → clippy → core-compile → repo-guards → security-regression
# → root-guards → core-admin-tests
# → admin-contract (admin_route_contract + admin_router_composition +
#    admin_smoke_flow --features mesh,dns,icmp-filter)
# → failure-injection
```

Local qualification:

```text
cargo fmt --all -- --check
cargo clippy --profile ci --all-targets -- -D warnings
cargo test --test admin_route_contract --profile ci
cargo test --test admin_router_composition --profile ci
cargo test --test admin_mutation_response_guard --profile ci
cargo test --test admin_smoke_flow --profile ci
cargo check --no-default-features --profile ci
cargo check --no-default-features --features mesh --profile ci
cargo check --no-default-features --features dns --profile ci
cargo check --no-default-features --features icmp-filter --profile ci
cargo check --no-default-features --features mesh,dns --profile ci
cd admin-ui && cargo check
```

Results: recorded in CI run for this commit (must be green before merge;
local `cargo xtask verify` + `verify-full` profiles run pre-push).

## Intentionally uncovered combinations

- Full feature powerset (combinatorial; no measured benefit). Bounded matrix
  only: minimal, `mesh`, `dns`, `icmp-filter`, `mesh,dns`.
- `cargo-hack --each-feature` / `--feature-powerset` not adopted (would
  reintroduce high-latency exhaustive CI without evidence).
- Browser E2E/screenshot suites not added (contract is mechanical oneshot +
  pure `sidebar_visibility()` unit tests by design).
- `mesh,dns,icmp-filter` triple compile covered implicitly by the routine
  `admin-contract` invocation; `verify-full` keeps the documented 5-row
  bounded matrix.

## Known limitation: mesh/dns runtime absence branches (residual)

> **Closed by Phase 25 (2026-09-12).** The self dev-edge now keeps
> `default-features = false`; `src/http/server.rs` mesh test imports,
> `src/worker/unified_server/init_mesh.rs` mesh-supervision tests,
> `tests/integration_test.rs` mesh/dns/ACME-DNS mods, the
> `iter87_behavioral_guardrails` mod, and `tests/mesh_startup_rollback.rs`
> (`required-features = ["mesh"]`) are gated. `cargo test
> --no-default-features` executes the absence branches (650 lib tests + 202
> integration + 18 admin composition pass minimally), and `verify-full`
> runs them via the `minimal-tests` step. The original Phase 05 note is
> preserved below for history.

`#[cfg(not(feature = "mesh"/"dns"))]` runtime tests — including the
capability-absence direction of
`capabilities_match_compiled_route_families` and the pre-existing
`mesh/dns_routes_absent_without_feature` guards — compile out under every
`cargo test` / nextest invocation in this workspace and only serve as
compile assertions today. Root cause: the root self dev-dependency
(`synvoid = { path = ".", features = ["test-utils"] }` without
`default-features = false`) re-enables default features for all test builds,
so `cargo test --no-default-features` still builds with mesh/dns on.
Flipping it breaks compilation of ungated mesh/dns uses in
`src/http/server.rs` + `src/worker/unified_server/init_mesh.rs` test code,
`tests/integration_test.rs`, and `tests/mesh_startup_rollback.rs` — gating
those is a separate phase (owner: follow-up, rationale: out of Phase 05
hardening scope). Live absence guarantees that DO execute in routine CI:
`icmp-filter` absence (off by default), all stale-path absence tests
(always compiled), and the full presence direction under
`--features mesh,dns,icmp-filter`. The `cargo check` profile matrix still
proves minimal/mesh/dns/icmp/mesh,dns compilation.

## Known residuals (owner / rationale)

- None open from the Phase 05 plan: the logout atomicity residual is closed
  (`ApiService::logout` retains CSRF/auth on 5xx/network; clears only on
  success or 401/403; `app.rs` converges `AuthState` on the same classes).
- Frontend `MasterStatus` type name is legacy (shape matches canonical
  `/system/supervisor` response); kept to avoid churn, documented at the
  call site. Rename only with a coordinated type migration.
- `verify-full` wall time grows by two fast `cargo check` rows (minimal +
  icmp-filter); within the <10min routine budget (routine adds one
  nextest invocation over default+`mesh,dns,icmp-filter`).

## Genuine defects found and fixed by the new gates

1. **Capability flags never tracked compiled features.** `synvoid-admin`'s
   `mesh`/`dns`/`icmp-filter` features gate `CapabilitiesResponse`, but root
   features never enabled them — every build reported `mesh_admin=false` /
   `dns_admin=false` / `icmp_admin=false` while serving those route families
   (sidebar hid Mesh/DNS/ICMP pages in the default build). Fixed by wiring
   root features to `synvoid-admin/*` in root `Cargo.toml`
   (`capabilities_match_compiled_route_families` now guards this).
2. **All config persists failed with `icmp-filter`.** `InterfaceSpec::All`
   (untagged) serializes as null, which TOML cannot represent, so
   `toml::to_string_pretty` errored and every config PUT returned 500
   (found via `tls_config_validation_accepts_disabled` under the triple
   profile; pre-existing on main). Fixed with
   `skip_serializing_if = "InterfaceSpec::is_all"` (missing key defaults
   back to `All`) plus TOML round-trip regression tests in
   `crates/synvoid-config/src/icmp_filter.rs`.
