# Test Suite Ownership

## Maintenance Rule
Every new test target must declare an owner, lane, and profile before merge. Unowned tests are candidates for removal.

## Root Integration Tests

| Test Target | Owning Crate | Lane | Profile | Features | Platform | Serialization | Notes |
|-------------|-------------|------|---------|----------|----------|---------------|-------|
| root_facade_boundary_guard | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| root_module_ledger_guard | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| root_dependency_ownership_guard | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| unified_server_lifecycle_ownership_guard | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| supervisor_task_ownership_guard | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| request_path_capability_boundary_guard | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| data_plane_composition_boundary_guard | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| http_request_pipeline_boundary_guard | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| http3_waf_boundary_guard | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| mesh_id_boundary_guard | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| threat_intel_boundary_guard | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| threat_intel_consumer_actionability_guard | synvoid (root) | PR | ci | mesh,dns | any | None | Architecture guard |
| admin_mutation_response_guard | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| admin_mutation_blocklist | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| admin_auth_boundary | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| mesh_admin_edge_cases | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| security_observability_guard | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| failure_injection | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| worker_mesh_supervision_boundary_guard | synvoid (root) | PR | ci | mesh,dns | any | None | Architecture guard |
| mesh_task_ownership_guard | synvoid (root) | PR | ci | mesh,dns | any | None | Architecture guard |
| cli_command_dispatch_guard | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| manual_enforcement_provenance_guard | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| background_task_ownership_guard | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| unified_worker_composition_root_guard | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| plugin_lifecycle_guard | synvoid (root) | PR | ci | default | any | None | Plugin guard (owned by guard-suite) |
| unsafe_native_sandbox_language_guard | synvoid (root) | PR | ci | default | any | None | Plugin guard (owned by guard-suite) |
| abi_memory_boundary_guard | synvoid-plugin-runtime | PR | ci | default | any | None | Plugin guard (owned by plugin-runtime-guardrails) |
| plugin_capability_boundary_guard | synvoid-plugin-runtime | PR | ci | default | any | None | Plugin guard (owned by plugin-runtime-guardrails) |
| plugin_signature_policy_guard | synvoid-plugin-runtime | PR | ci | default | any | None | Plugin guard (owned by plugin-runtime-guardrails) |
| manifest_authority_wiring | synvoid-plugin-runtime | PR | ci | default | any | None | Plugin guard (owned by plugin-runtime-guardrails) |
| manifest_authority_load_path_guard | synvoid-plugin-runtime | PR | ci | default | any | None | Plugin guard (owned by plugin-runtime-guardrails) |
| plugin_failure_does_not_poison_manager | synvoid-plugin-runtime | PR | ci | default | any | None | Plugin guard (owned by plugin-runtime-guardrails) |
| security_regression | synvoid (root) | PR | ci | default | linux | full binary | Serial execution required |
| docs_path_reference_guard | synvoid (root) | PR | ci | default | any | None | continue-on-error |

## Per-Crate Test Suites

| Crate | Lane | Profile | Features | Notes |
|-------|------|---------|----------|-------|
| synvoid-dns | PR (main for full) | ci | default | 1101 tests, 31 binaries |
| synvoid-plugin-runtime | PR | ci | default | 389 tests |
| synvoid-upload | PR | ci | default, mesh | Unit + mesh tests |
| synvoid-honeypot | PR | ci | default | Unit tests |
| synvoid-tarpit | PR | ci | default | All targets |
| synvoid-mesh | PR | ci | mesh | All targets |

## CI Jobs and Ownership

| Job | Lane | Owner | Notes |
|-----|------|-------|-------|
| fmt | PR | CI infrastructure | Formatting gate |
| clippy | PR | CI infrastructure | Lint gate |
| unsafe-dns | PR | DNS team | Grep-only, no cargo |
| core-profile | PR | CI infrastructure | Feature profile check |
| import-check | PR | CI infrastructure | Python script |
| security-regression | PR | Security | Serial execution |
| guard-suite | PR | Architecture | 24 structural guards |
| plugin-runtime-guardrails | PR | Plugin team | 6 plugin guards + unit tests + clippy |
| docs-link-guard | PR | Documentation | continue-on-error |
| dns-tests | Main | DNS team | Full DNS suite |
| build | Main/Release | Release | 8-target matrix |
| upload-tests | PR | Upload team | Per-crate tests |
| honeypot-tests | PR | Honeypot team | Per-crate tests |
| tarpit-tests | PR | Tarpit team | Per-crate tests |
| mesh-tests | PR | Mesh team | Per-crate tests |
| docs | Main | Documentation | Doc build |
| security-audit | Main | Security | cargo-audit |
| dependency-audit | Main | Security | cargo-deny |
| profile-matrix | Main/Scheduled | CI infrastructure | 5 profile checks |
| alpine-test | Scheduled | Platform | Alpine/musl |
| freebsd-test | Scheduled | Platform | FreeBSD VM |
| platform-compat | Scheduled | Platform | Cross-target check |
| miri-test | Scheduled | Safety | continue-on-error |
| fuzz-smoke | Scheduled | Security | 16 fuzz targets |
| outdated-deps | Scheduled | Maintenance | continue-on-error |
