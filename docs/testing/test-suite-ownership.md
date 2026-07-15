# Test Suite Ownership

## Maintenance Rule
Every new test target must declare an owner, lane, and profile before merge. Unowned tests are candidates for removal.

## Root Integration Tests (28 files)

Root integration tests are governed by `tests/OWNERSHIP.toml`. Every root test must have an explicit ownership entry in the manifest. The `root_test_ownership_guard` test enforces this invariant. Domain tests that do not require root composition belong in their owning crate.

| Test Target | Owning Crate | Lane | Profile | Features | Platform | Serialization | Notes |
|-------------|-------------|------|---------|----------|----------|---------------|-------|
| boundary_composition_guard | synvoid (root) | PR | ci | default | any | None | Consolidated: data-plane, request-path, HTTP pipeline, HTTP/3 WAF, manifest authority |
| lifecycle_task_guard | synvoid (root) | PR | ci | default | any | None | Consolidated: background tasks, supervisor spawns, unified server lifecycle |
| plugin_guard | synvoid (root) | PR | ci | default | any | None | Consolidated: plugin capability, lifecycle, signature policy |
| cli_admin_guard | synvoid (root) | PR | ci | default | any | None | Consolidated: CLI dispatch, enforcement provenance, worker composition |
| security_guard | synvoid (root) | PR | ci | default | any | None | Consolidated: security observability, threat-intel boundary, consumer actionability |
| root_facade_boundary_guard | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| mesh_id_boundary_guard | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| admin_mutation_response_guard | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| admin_mutation_blocklist | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| admin_auth_boundary | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| mesh_admin_edge_cases | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| failure_injection | synvoid (root) | PR | ci | default | any | None | Architecture guard |
| worker_mesh_supervision_boundary_guard | synvoid (root) | PR | ci | mesh,dns | any | None | Architecture guard |
| mesh_task_ownership_guard | synvoid (root) | PR | ci | mesh,dns | any | None | Architecture guard |
| root_test_ownership_guard | synvoid (root) | PR | ci | default | any | None | Enforces OWNERSHIP.toml manifest completeness |
| abi_memory_boundary_guard | synvoid (root) | PR | ci | default | any | None | ABI memory boundary (cross-crate plugin boundary) |
| security_regression | synvoid (root) | PR | ci | default | linux | env-var-guard (OnceLock<Mutex>) | Serial execution required |
| composition_root_behavioral | synvoid (root) | PR | ci | mesh,dns | any | None | Validates worker+mesh composition root dataflow |
| drain_e2e_test | synvoid (root) | PR | ci | default | any | None | Validates IPC drain end-to-end |
| dht_integration_test | synvoid (root) | PR | ci | mesh | any | None | Validates mesh DHT integration |
| e2e_process_test | synvoid (root) | PR | ci | default | any | None | Validates IPC end-to-end |
| fault_injection_test | synvoid (root) | PR | ci | default | any | None | Validates fault injection across supervisor, block-store, plugin. ProcessGuard RAII cleanup |
| integration_test | synvoid (root) | PR | ci | default | any | None | Validates full-stack composition across all major subsystems |
| architecture_test | synvoid (root) | PR | ci | default | any | None | Validates architecture boundary constraints across workspace |
| mesh_startup_rollback | synvoid (root) | PR | ci | mesh | any | None | Validates mesh startup composition |
| overseer_lifecycle_test | synvoid (root) | PR | ci | default | any | None | Validates supervisor lifecycle across worker and supervisor |
| traffic_regression_test | synvoid (root) | PR | ci | default | any | None | Validates proxy+upstream traffic regression |
| worker_supervision_control_flow | synvoid (root) | PR | ci | mesh,dns | any | None | Validates worker+mesh supervision control flow |


## Per-Crate Test Suites

| Crate | Lane | Profile | Features | Notes |
|-------|------|---------|----------|-------|
| synvoid-dns | PR (main for full) | ci | default | 1101 tests, 31 binaries (+5 migrated from root: dns_config_test, dns_config_fidelity, dns_recursive_isolation, authoritative_negative, property_tests) |
| synvoid-dns (support) | DNS team | ci | default | New: crates/synvoid-dns/tests/support/ — shared query/zone/context/response helpers |
| synvoid-plugin-runtime | PR | ci | default | 389 tests (+2 migrated from root: manifest_authority_wiring, plugin_failure_does_not_poison_manager) |
| synvoid-upload | PR | ci | default, mesh | Unit + mesh tests |
| synvoid-honeypot | PR | ci | default | Unit tests |
| synvoid-tarpit | PR | ci | default | All targets |
| synvoid-mesh | PR | ci | mesh | All targets (+3 migrated from root: mesh_forced_cleanup, mesh_http_framing, mesh_lifecycle_tests) |
| synvoid-waf | PR | ci | default | All targets (+3 migrated from root: waf_corpus_test, wave10_test, property_tests_common) |
| synvoid-ipc | PR | ci | default | Unit tests (+2 migrated from root: ipc_test, process_lifecycle_test) |
| synvoid-platform | PR | ci | default | Unit tests (+1 migrated from root: socket_handoff_test) |

## CI Jobs and Ownership

| Job | Lane | Owner | Notes |
|-----|------|-------|-------|
| fmt | PR | CI infrastructure | Formatting gate |
| clippy | PR | CI infrastructure | Lint gate |
| unsafe-dns | PR | DNS team | Grep-only, no cargo |
| core-profile | PR | CI infrastructure | Feature profile check |
| import-check | PR | CI infrastructure | Python script |
| security-regression | PR | Security | Serial execution |
| guard-suite | PR | Architecture | 23 structural guards |
| plugin-runtime-guardrails | PR | Plugin team | 6 plugin guards + unit tests + clippy |

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

## Test Resource Classes (Milestone E)

| Class | Max Threads | Tests | Rationale |
|-------|-------------|-------|-----------|
| global-env | 1 | security_regression, metrics_wiring | Process-global state mutation |
| process-spawn | 2 | fault_injection_test | OS process lifecycle |
| network-heavy | 4 | (reserved) | Future use for network-bound tests |

## synvoid-testkit Boundary (Milestone E)

The `synvoid-testkit` crate is intentionally minimal with zero current consumers. It contains:
- Generic assertion macros
- Config fixtures (temp dirs, minimal config)
- Request fixtures (test request contexts)

New helpers require ≥2 crate consumers, tests, and doc comments. See `crates/synvoid-testkit/README.md`.
