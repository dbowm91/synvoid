# Root Integration Test Ownership

This document classifies every root integration test in `tests/` by ownership category.
Each entry records why root ownership is necessary or identifies the destination crate for migration.

## Categories

- **STATIC_POLICY**: Source/repository policy checks → migrate to `synvoid-repo-guards`
- **DOMAIN**: Single-crate behavior → migrate to owning crate's `tests/`
- **COMPOSITION**: Cross-crate interaction → may remain at root
- **FACADE**: Public root API compatibility → remains at root
- **EXECUTABLE**: Startup/CLI/process behavior → remains at root
- **PLATFORM**: OS-specific → migrate to owning crate
- **QUALIFICATION**: Stress/interop → migrate to owning crate or scheduled lane

## Classification

| File | Tests | Category | Owner(s) | Disposition |
|------|-------|----------|----------|-------------|
| `abi_memory_boundary_guard` | 9 | STATIC_POLICY | plugin-runtime | **KEEP** — ABI boundary is workspace-wide policy |
| `admin_auth_boundary` | 8 | COMPOSITION | core, admin | **KEEP** — cross-crate admin authority boundary |
| `admin_mutation_blocklist` | 10 | COMPOSITION | block-store, core | **KEEP** — block-store + core mutation interaction |
| `admin_mutation_response_guard` | 4 | STATIC_POLICY | admin | **KEEP** — admin mutation contract is workspace-wide |
| `architecture_test` | 2 | STATIC_POLICY | — | **KEEP** — architecture boundary validation |
| `boundary_composition_guard` | 56 | STATIC_POLICY | waf, proxy, http, http3 | **KEEP** — composition boundary is workspace-wide policy |
| `cli_admin_guard` | 79 | STATIC_POLICY | cli, admin | **KEEP** — CLI/admin boundary is workspace-wide policy |
| `composition_root_behavioral` | 8 | COMPOSITION | worker, mesh | **KEEP** — worker+mesh composition |
| `corpus` | 0 | DOMAIN | waf | **KEEP** — shared test infrastructure (lib module) |
| `dns_config_test` | 45 | DOMAIN | dns, config | MIGRATE → `synvoid-dns` |
| `dns_integration_test` | 45 | DOMAIN | dns | MIGRATE → `synvoid-dns` |
| `dns_recursive_test` | 36 | DOMAIN | dns | MIGRATE → `synvoid-dns` |
| `dns_server_test` | 41 | DOMAIN | dns | MIGRATE → `synvoid-dns` |
| `dht_integration_test` | 90 | COMPOSITION | mesh, dht | **KEEP** — mesh DHT composition |
| `drain_e2e_test` | 4 | COMPOSITION | process, ipc | **KEEP** — IPC drain e2e composition |
| `e2e_process_test` | 4 | COMPOSITION | process, ipc | **KEEP** — IPC e2e composition |
| `failure_injection` | 7 | COMPOSITION | supervisor, block-store, plugin | **KEEP** — multi-crate fault injection |
| `fault_injection_test` | 0 | COMPOSITION | supervisor, block-store, plugin | **KEEP** — multi-crate fault injection (cfg(unix)) |
| `integration_test` | 240 | COMPOSITION | all | **KEEP** — full-stack composition |
| `ipc_test` | 42 | DOMAIN | process, ipc | MIGRATE → `synvoid-ipc` |
| `lifecycle_task_guard` | 48 | STATIC_POLICY | worker, supervisor | **KEEP** — lifecycle task ownership policy |
| `manifest_authority_wiring` | 5 | DOMAIN | plugin-runtime | MIGRATE → `synvoid-plugin-runtime` |
| `mesh_admin_edge_cases` | 8 | COMPOSITION | core, admin | **KEEP** — mesh+admin composition |
| `mesh_forced_cleanup` | 4 | DOMAIN | mesh | MIGRATE → `synvoid-mesh` |
| `mesh_http_framing` | 1 | DOMAIN | mesh | MIGRATE → `synvoid-mesh` |
| `mesh_id_boundary_guard` | 6 | STATIC_POLICY | block-store, mesh | **KEEP** — mesh-id boundary policy |
| `mesh_lifecycle_tests` | 33 | DOMAIN | mesh | MIGRATE → `synvoid-mesh` |
| `mesh_startup_rollback` | 90 | COMPOSITION | mesh, transport | **KEEP** — mesh startup composition |
| `mesh_task_ownership_guard` | 164 | STATIC_POLICY | mesh | **KEEP** — mesh task ownership policy |
| `plugin_failure_does_not_poison_manager` | 6 | DOMAIN | plugin-runtime | MIGRATE → `synvoid-plugin-runtime` |
| `plugin_guard` | 52 | STATIC_POLICY | plugin-runtime | **KEEP** — plugin capability boundary policy |
| `process_lifecycle_test` | 33 | DOMAIN | process, ipc | MIGRATE → `synvoid-ipc` |
| `property_tests` | 7 | DOMAIN | dns | MIGRATE → `synvoid-dns` |
| `property_tests_common` | 6 | DOMAIN | waf, utils | MIGRATE → `synvoid-waf` |
| `root_facade_boundary_guard` | 1 | STATIC_POLICY | root | **KEEP** — root facade boundary policy |
| `security_guard` | 48 | STATIC_POLICY | security | **KEEP** — security observability policy |
| `security_regression` | 16 | COMPOSITION | process, proxy, platform | **KEEP** — cross-crate security regression |
| `socket_handoff_test` | 2 | PLATFORM | platform | MIGRATE → `synvoid-platform` |
| `traffic_regression_test` | 62 | COMPOSITION | proxy, upstream | **KEEP** — proxy+upstream composition |
| `waf_corpus_test` | 4 | DOMAIN | waf | MIGRATE → `synvoid-waf` |
| `wave10_test` | 67 | DOMAIN | waf | MIGRATE → `synvoid-waf` |
| `worker_mesh_supervision_boundary_guard` | 98 | STATIC_POLICY | worker, mesh | **KEEP** — worker-mesh boundary policy |
| `worker_supervision_control_flow` | 46 | COMPOSITION | worker, mesh | **KEEP** — worker+mesh composition |

## Summary

- **Total root test files**: 43
- **KEEP at root**: 30 (cross-crate composition, policy, executable)
- **MIGRATE to owning crates**: 13

### Migration Destinations

| Destination Crate | Tests to Migrate |
|-------------------|-----------------|
| `synvoid-dns` | `dns_config_test`, `dns_integration_test`, `dns_recursive_test`, `dns_server_test`, `property_tests` |
| `synvoid-ipc` | `ipc_test`, `process_lifecycle_test` |
| `synvoid-plugin-runtime` | `manifest_authority_wiring`, `plugin_failure_does_not_poison_manager` |
| `synvoid-mesh` | `mesh_forced_cleanup`, `mesh_http_framing`, `mesh_lifecycle_tests` |
| `synvoid-waf` | `property_tests_common`, `waf_corpus_test`, `wave10_test` |
| `synvoid-platform` | `socket_handoff_test` |
