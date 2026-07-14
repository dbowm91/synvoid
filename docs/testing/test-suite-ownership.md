# Test Suite Ownership

## Maintenance Rule
Every new test target must declare an owner, lane, and profile before merge. Unowned tests are candidates for removal.

## Root Integration Tests

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
| abi_memory_boundary_guard | synvoid-plugin-runtime | PR | ci | default | any | None | Plugin guard (owned by plugin-runtime-guardrails) |
| manifest_authority_wiring | synvoid-plugin-runtime | PR | ci | default | any | None | Plugin guard (owned by plugin-runtime-guardrails) |
| plugin_failure_does_not_poison_manager | synvoid-plugin-runtime | PR | ci | default | any | None | Plugin guard (owned by plugin-runtime-guardrails) |
| security_regression | synvoid (root) | PR | ci | default | linux | full binary | Serial execution required |


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
