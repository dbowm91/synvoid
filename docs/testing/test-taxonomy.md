# Test Taxonomy

## Purpose

This document classifies every test modality in the SynVoid workspace by category, owner, CI lane, compilation profile, platform requirements, serialization constraints, and estimated duration. It serves as the single source of truth for:

1. **What runs where** — every test maps to exactly one CI lane (PR, Main, Scheduled, or Release).
2. **Who owns it** — every modality has a named owning team.
3. **What it costs** — estimated duration and resource requirements are recorded.
4. **What must never run in PR** — exclusion rules prevent expensive or non-deterministic tests from blocking developer iteration.

## Modality Definitions

| # | Modality | Definition | Example |
|---|----------|-----------|---------|
| 1 | **Static Policy Guards** | Source/manifest scanning tests that enforce architectural invariants without executing production code. Read `.rs`/`.md` files, check imports, assert absence of violations. | `boundary_composition_guard`, `mesh_task_ownership_guard` |
| 2 | **Composition / E2E Tests** | Cross-crate integration tests that validate end-to-end subsystem composition. Spawn processes, bind ports, exercise IPC/HTTP/mesh paths. | `integration_test`, `e2e_process_test`, `drain_e2e_test` |
| 3 | **Security Regression** | Targeted security invariant tests that must run serially to avoid global state contention. Validate IPC key handling, block-store permissions, and cross-crate security boundaries. | `security_regression` |
| 4 | **Per-Crate Unit Tests** | Domain-specific unit and integration tests within individual workspace crates. Each crate's suite is independently gated. | `synvoid-dns` (1101 tests), `synvoid-plugin-runtime` (389 tests) |
| 5 | **DNS Integration Suites** | Standalone DNS integration binaries covering protocol semantics, config fidelity, DNSSEC, encrypted transport, control-plane authorization, and recursive isolation. | `transport_lifecycle`, `dns_config_fidelity`, `dns_recursive_isolation` |
| 6 | **Fuzz Smoke Tests** | Short-duration fuzz campaigns (1000 iterations per target) using `cargo-fuzz` to validate parser robustness against malformed inputs. | `dns_message_decode`, `plugin_manifest`, `http_path_normalization` |
| 7 | **Stress Tests** | Resource-limit enforcement tests that validate behavior under load: connection limits, query limits, cache capacity, memory stability. | `dns_stress_resource_limits`, `scripts/dns/stress_tests.sh` |
| 8 | **Interoperability Tests** | Protocol conformance tests that validate DNS behavior against authoritative/recursive/encrypted/DNSSEC expectations. | `dns_interop_authoritative`, `dns_interop_dnssec`, `dns_interop_transfers` |
| 9 | **Benchmarks** | Criterion-based performance benchmarks that establish baselines and detect regressions. Run in release mode for accurate timing. | `cache_bench`, `wire_bench`, `zone_bench`, `coalescer_bench`, `limits_bench` |
| 10 | **Property Tests** | QuickCheck/proptest-based invariant validation that generates random inputs and asserts correctness properties. | `property_tests` (DNS), `property_tests_common` (WAF) |
| 11 | **Platform Qualification** | Cross-platform compilation and testing on non-default targets (musl, FreeBSD, macOS, Windows) to validate portability. | `alpine-test`, `freebsd-test`, `platform-compat` |
| 12 | **Safety Checks** | Memory safety analysis via Miri that detects undefined behavior in unsafe code and pointer manipulation. | `cargo miri test -p synvoid-utils` |
| 13 | **Dependency Audit** | Supply-chain security checks via `cargo-audit` (advisory database) and `cargo-deny` (licenses, bans, sources). | `cargo audit`, `cargo deny check` |
| 14 | **Documentation Build** | Validates that `cargo doc --no-deps --release` builds cleanly with no broken intra-doc links or missing documentation. | `cargo doc --no-deps --release` |
| 15 | **Failure Injection** | Validates graceful degradation under injected failures: supervisor shutdown, blocklist catchup, plugin failure isolation. | `failure_injection` |

## Full Classification Table

### 1. Static Policy Guards

| Test | Owner | Lane | Profile | Platform | Features | Serialization | Est. Duration |
|------|-------|------|---------|----------|----------|---------------|---------------|
| `boundary_composition_guard` | Architecture | PR | ci | any | default | None | ~2s |
| `lifecycle_task_guard` | Architecture | PR | ci | any | default | None | ~1s |
| `plugin_guard` | Architecture | PR | ci | any | default | None | ~4s |
| `cli_admin_guard` | Architecture | PR | ci | any | default | None | ~6s |
| `security_guard` | Architecture | PR | ci | any | default | None | ~13s |
| `root_facade_boundary_guard` | Architecture | PR | ci | any | default | None | ~1s |
| `mesh_id_boundary_guard` | Architecture | PR | ci | any | default | None | ~6s |
| `admin_mutation_response_guard` | Architecture | PR | ci | any | default | None | ~2s |
| `admin_mutation_blocklist` | Architecture | PR | ci | any | default | None | <1s |
| `admin_auth_boundary` | Architecture | PR | ci | any | default | None | ~1s |
| `mesh_admin_edge_cases` | Architecture | PR | ci | any | default | None | <1s |
| `worker_mesh_supervision_boundary_guard` | Architecture | PR | ci | any | mesh,dns | None | ~8s |
| `mesh_task_ownership_guard` | Architecture | PR | ci | any | mesh,dns | None | ~3s |
| `root_test_ownership_guard` | Architecture | PR | ci | any | default | None | <1s |
| `abi_memory_boundary_guard` | Architecture | PR | ci | any | default | None | ~2s |
| `architecture_test` | Architecture | PR | ci | any | default | None | <1s |
| `manifest_authority_wiring` | Plugin | PR | ci | any | default | None | <1s |
| `plugin_failure_does_not_poison_manager` | Plugin | PR | ci | any | default | None | <1s |
| `synvoid-repo-guards` (nextest) | Architecture | PR | ci | any | — | None | ~1s |

### 2. Composition / E2E Tests

| Test | Owner | Lane | Profile | Platform | Features | Serialization | Est. Duration |
|------|-------|------|---------|----------|----------|---------------|---------------|
| `integration_test` | Root | PR | ci | any | default | None | ~30s |
| `e2e_process_test` | Root | PR | ci | any | default | None | ~10s |
| `drain_e2e_test` | Root | PR | ci | any | default | None | ~5s |
| `dht_integration_test` | Root | PR | ci | any | mesh | None | ~15s |
| `fault_injection_test` | Root | PR | ci | any | default | None | ~5s |
| `composition_root_behavioral` | Root | PR | ci | any | mesh,dns | None | ~10s |
| `mesh_startup_rollback` | Root | PR | ci | any | mesh | None | ~10s |
| `overseer_lifecycle_test` | Root | PR | ci | any | default | None | ~5s |
| `traffic_regression_test` | Root | PR | ci | any | default | None | ~10s |
| `worker_supervision_control_flow` | Root | PR | ci | any | mesh,dns | None | ~10s |

### 3. Security Regression

| Test | Owner | Lane | Profile | Platform | Features | Serialization | Est. Duration |
|------|-------|------|---------|----------|----------|---------------|---------------|
| `security_regression` | Security | PR | ci | linux | default | `--test-threads=1` | ~450s |

### 4. Per-Crate Unit Tests

| Crate | Owner | Lane | Profile | Platform | Features | Serialization | Est. Duration |
|-------|-------|------|---------|----------|----------|---------------|---------------|
| `synvoid-dns` | DNS | PR (affected), Main (full) | ci | any | default | None | ~103s |
| `synvoid-plugin-runtime` | Plugin | PR | ci | any | default | None | ~294s |
| `synvoid-waf` | WAF | PR | ci | any | default | None | ~60s |
| `synvoid-mesh` | Mesh | PR | ci | any | mesh | None | ~193s |
| `synvoid-ipc` | IPC | PR | ci | any | default | None | ~30s |
| `synvoid-honeypot` | Honeypot | PR | ci | any | default | None | ~120s |
| `synvoid-tarpit` | Tarpit | PR | ci | any | default | None | ~119s |
| `synvoid-platform` | Platform | PR | ci | any | default | None | ~20s |
| `synvoid-upload` | Upload | PR | ci | any | default, mesh | None | ~30s |

### 5. DNS Integration Suites (34 binaries)

| Test Binary | Owner | Lane | Profile | Platform | Features | Serialization | Est. Duration |
|-------------|-------|------|---------|----------|----------|---------------|---------------|
| `transport_lifecycle` | DNS | Main | ci | any | default | None | ~15s |
| `dns_config_fidelity` | DNS | Main | ci | any | default | None | ~10s |
| `dns_recursive_isolation` | DNS | Main | ci | any | mesh,dns | None | ~30s |
| `authoritative_negative` | DNS | Main | ci | any | default | None | ~5s |
| `dns_config_test` | DNS | Main | ci | any | default | None | ~15s |
| `dns_integration_test` | DNS | Main | ci | any | default | None | ~10s |
| `dns_recursive_test` | DNS | Main | ci | any | mesh,dns | None | ~15s |
| `dns_server_test` | DNS | Main | ci | any | default | None | ~10s |
| `dnssec_live_signing` | DNS | Main | ci | any | default | None | ~10s |
| `dnssec_known_vectors` | DNS | Main | ci | any | default | None | ~5s |
| `encrypted_transport` | DNS | Main | ci | any | default | None | ~10s |
| `verification_gate` | DNS | Main | ci | any | default | None | ~15s |
| `control_plane_authorization` | DNS | Main | ci | any | default | None | ~5s |
| `control_plane_exclusion` | DNS | Main | ci | any | default | None | ~10s |
| `control_plane_cache_completion` | DNS | Main | ci | any | default | None | ~5s |
| `update_authorized_semantics` | DNS | Main | ci | any | default | None | ~5s |
| `update_atomicity_rollback` | DNS | Main | ci | any | default | None | ~5s |
| `notify_behavior` | DNS | Main | ci | any | default | None | ~5s |
| `notify_scheduling_semantics` | DNS | Main | ci | any | default | None | ~5s |
| `ixfr_record_delta` | DNS | Main | ci | any | default | None | ~5s |
| `axfr_ixfr_transfer_semantics` | DNS | Main | ci | any | default | None | ~5s |
| `tsig_success_fixtures` | DNS | Main | ci | any | default | None | ~5s |
| `property_tests` | DNS | Main | ci | any | default | None | ~10s |
| `health_integration` | DNS | Main | ci | any | default | None | ~10s |
| `metrics_wiring` | DNS | Main | ci | any | default | None | ~5s |
| `example_configs_parse` | DNS | Main | ci | any | default | None | ~5s |
| `dns_interop_authoritative` | DNS | Main + Scheduled | ci | any | default | None | ~10s |
| `dns_interop_truncation` | DNS | Main + Scheduled | ci | any | default | None | ~10s |
| `dns_interop_dnssec` | DNS | Main + Scheduled | ci | any | default | None | ~10s |
| `dns_interop_transfers` | DNS | Main + Scheduled | ci | any | default | None | ~10s |
| `dns_interop_update_notify` | DNS | Main + Scheduled | ci | any | default | None | ~10s |
| `dns_interop_encrypted` | DNS | Main + Scheduled | ci | any | default | None | ~5s |
| `dns_interop_recursive` | DNS | Main + Scheduled | ci | any | mesh,dns | None | ~10s |

### 6. Fuzz Smoke Tests (17 targets)

| Target | Owner | Lane | Profile | Platform | Iterations | Est. Duration |
|--------|-------|------|---------|----------|------------|---------------|
| `dns_message_decode` | Security | Scheduled | ci | linux | 1000 | ~30s |
| `plugin_manifest` | Security | Scheduled | ci | linux | 1000 | ~30s |
| `http_path_normalization` | Security | Scheduled | ci | linux | 1000 | ~30s |
| `fuzz_attack_detection` | Security | Scheduled | ci | linux | 1000 | ~30s |
| `fuzz_early_parse` | Security | Scheduled | ci | linux | 1000 | ~30s |
| `fuzz_ipc` | Security | Scheduled | ci | linux | 1000 | ~30s |
| `blocklist_event_decode` | Security | Scheduled | ci | linux | 1000 | ~30s |
| `blocklist_snapshot_decode` | Security | Scheduled | ci | linux | 1000 | ~30s |
| `admin_mutation_result_decode` | Security | Scheduled | ci | linux | 1000 | ~30s |
| `http_header_normalization` | Security | Scheduled | ci | linux | 1000 | ~30s |
| `mesh_protocol_compressed_decode` | Security | Scheduled | ci | linux | 1000 | ~30s |
| `parsed_query_parse` | Security | Scheduled | ci | linux | 1000 | ~30s |
| `fuzz_raft_response` | Security | Scheduled | ci | linux | 1000 | ~30s |
| `fuzz_raft_commit_notification` | Security | Scheduled | ci | linux | 1000 | ~30s |
| `fuzz_serialization` | Security | Scheduled | ci | linux | 1000 | ~30s |
| `fuzz_serialization_new` | Security | Scheduled | ci | linux | 1000 | ~30s |
| `fuzz_protocol_proto_decode` | Security | Scheduled | ci | linux | 1000 | ~30s |

### 7. Stress Tests

| Test / Script | Owner | Lane | Profile | Platform | Features | Serialization | Est. Duration |
|---------------|-------|------|---------|----------|----------|---------------|---------------|
| `dns_stress_resource_limits` | DNS | Scheduled | ci | any | default | `--test-threads=1` | ~60s |
| `scripts/dns/stress_tests.sh` | DNS | Scheduled | ci | any | default | Script | ~120s |
| `scripts/dns/run_benchmarks.sh` | DNS | Scheduled | release | any | default | Script | ~300s |

### 8. Interoperability Tests

| Test Binary | Owner | Lane | Profile | Platform | Features | Serialization | Est. Duration |
|-------------|-------|------|---------|----------|----------|---------------|---------------|
| `dns_interop_authoritative` | DNS | Main + Scheduled | ci | any | default | None | ~10s |
| `dns_interop_truncation` | DNS | Main + Scheduled | ci | any | default | None | ~10s |
| `dns_interop_dnssec` | DNS | Main + Scheduled | ci | any | default | None | ~10s |
| `dns_interop_transfers` | DNS | Main + Scheduled | ci | any | default | None | ~10s |
| `dns_interop_update_notify` | DNS | Main + Scheduled | ci | any | default | None | ~10s |
| `dns_interop_encrypted` | DNS | Main + Scheduled | ci | any | default | None | ~5s |
| `dns_interop_recursive` | DNS | Main + Scheduled | ci | any | mesh,dns | None | ~10s |
| `scripts/dns/conformance.sh` | DNS | Scheduled | ci | any | default | Script | ~120s |

### 9. Benchmarks

| Benchmark | Owner | Lane | Profile | Platform | Features | Est. Duration |
|-----------|-------|------|---------|----------|----------|---------------|
| `cache_bench` | DNS | Scheduled + Release | release | any | default | ~60s |
| `wire_bench` | DNS | Scheduled + Release | release | any | default | ~60s |
| `zone_bench` | DNS | Scheduled + Release | release | any | default | ~60s |
| `coalescer_bench` | DNS | Scheduled + Release | release | any | default | ~60s |
| `limits_bench` | DNS | Scheduled + Release | release | any | default | ~60s |

### 10. Property Tests

| Test | Owner | Lane | Profile | Platform | Features | Est. Duration |
|------|-------|------|---------|----------|----------|---------------|
| `property_tests` (DNS) | DNS | Main | ci | any | default | ~10s |
| `property_tests_common` (WAF) | WAF | Main | ci | any | default | ~10s |

### 11. Platform Qualification

| Job | Owner | Lane | Profile | Platform | Features | Serialization | Est. Duration |
|-----|-------|------|---------|----------|----------|---------------|---------------|
| `alpine-test` (build) | Platform | Scheduled | release | x86_64-linux-musl | default | Compile-only | ~5min |
| `alpine-test` (test) | Platform | Scheduled | release | x86_64-linux-musl | default | `--test-threads=1` | ~10min |
| `freebsd-test` (build) | Platform | Scheduled | release | x86_64-freebsd | default | Compile-only | ~5min |
| `freebsd-test` (test) | Platform | Scheduled | release | x86_64-freebsd | default | `--test-threads=1` | ~10min |
| `platform-compat` (5 targets) | Platform | Scheduled | ci | linux-gnu, musl, darwin, windows, freebsd | default | Compile-only | ~10min |

### 12. Safety Checks

| Tool | Owner | Lane | Profile | Platform | Features | Est. Duration | Notes |
|------|-------|------|---------|----------|----------|---------------|-------|
| `cargo miri test -p synvoid-utils` | Safety | Scheduled | nightly | native | default | ~120s | `continue-on-error: true` |

### 13. Dependency Audit

| Tool | Owner | Lane | Profile | Platform | Est. Duration | Notes |
|------|-------|------|---------|----------|---------------|-------|
| `cargo audit` | Security | Main | — | native | ~10s | Advisory database check |
| `cargo deny check` | Security | Main | — | native | ~30s | License, ban, source check |

### 14. Documentation Build

| Command | Owner | Lane | Profile | Platform | Est. Duration |
|---------|-------|------|---------|----------|---------------|
| `cargo doc --no-deps --release` | Documentation | Main | release | native | ~60s |

### 15. Failure Injection

| Test | Owner | Lane | Profile | Platform | Features | Serialization | Est. Duration |
|------|-------|------|---------|----------|----------|---------------|---------------|
| `failure_injection` | Architecture | PR | ci | any | default | None | ~8s |

## Lane Assignment Summary

### PR Fast Lane (<10 min target)

Runs on every pull request. Required for merge.

| Modality | Count | Total Est. Duration |
|----------|-------|---------------------|
| Formatting (`cargo fmt`) | 1 | <1s |
| Linting (`cargo clippy`) | 1 | ~75s |
| Core profile check | 1 | ~5s |
| Import boundary check | 1 | <1s |
| DNS unsafe grep | 1 | <1s |
| Security regression | 1 | ~450s (serial) |
| Static policy guards | 19 | ~60s |
| Composition / E2E tests | 10 | ~100s |
| Failure injection | 1 | ~8s |
| Per-crate: synvoid-upload | 1 | ~30s |
| Per-crate: synvoid-honeypot | 1 | ~120s |
| Per-crate: synvoid-tarpit | 1 | ~119s |
| Per-crate: synvoid-mesh | 1 | ~193s |
| **Total** | **~38 jobs** | **~12 min (parallelized)** |

**Not permitted:** Alpine/musl, FreeBSD VM, Miri, fuzz, outdated deps, full platform matrix, benchmarks, stress tests, release builds.

### Main Comprehensive Lane (<30 min target)

Runs on push to main. Full validation after merge.

| Modality | Count | Total Est. Duration |
|----------|-------|---------------------|
| Build matrix (8 targets) | 16 | ~15min |
| DNS full suite (blanket) | 5 | ~120s |
| Plugin runtime suite | 8 | ~180s |
| Profile matrix (5 checks) | 5 | ~25s |
| DNS integration suites | 34 | ~200s |
| DNS interop suites | 7 | ~60s |
| Property tests (DNS + WAF) | 2 | ~20s |
| Documentation build | 1 | ~60s |
| Dependency audit (2 tools) | 2 | ~40s |
| **Total** | **~80 jobs** | **~25 min (parallelized)** |

**Not permitted:** Alpine/musl, FreeBSD VM, Miri, fuzz, platform compat, outdated deps.

### Scheduled Qualification Lane (nightly, <60 min target)

Expensive qualification that does not block PR iteration.

| Modality | Count | Total Est. Duration |
|----------|-------|---------------------|
| Alpine/musl (build + test) | 2 | ~15min |
| FreeBSD VM (build + test) | 2 | ~15min |
| Platform compat (5 targets) | 5 | ~10min |
| Miri safety checks | 1 | ~120s |
| Fuzz smoke (17 targets) | 17 | ~8min |
| Stress tests | 3 | ~8min |
| DNS interop suites | 7 | ~60s |
| DNS stress scripts | 2 | ~6min |
| Outdated deps | 1 | ~30s |
| **Total** | **~40 jobs** | **~50 min (parallelized)** |

### Release Qualification Lane (tags, <60 min target)

Production artifact validation.

| Modality | Count | Total Est. Duration |
|----------|-------|---------------------|
| Build matrix (8 targets) | 16 | ~15min |
| Full test suite (default + mesh) | 4 | ~300s |
| Clippy (all-features) | 1 | ~100s |
| Benchmarks (5 suites) | 5 | ~300s |
| **Total** | **~26 jobs** | **~25 min (parallelized)** |

## Resource Class Mapping

### Standard Runner (2 vCPU, 7 GB RAM)

| Modalities |
|-----------|
| Formatting, linting, core profile check, import check, DNS unsafe grep |
| Static policy guards (all 19) |
| Composition / E2E tests (10) |
| Failure injection |
| Per-crate unit tests (upload, honeypot, tarpit, mesh) |
| Documentation build |
| Dependency audit |

### Large Runner (4+ vCPU, 16 GB RAM)

| Modalities | Reason |
|-----------|--------|
| Security regression (`--test-threads=1`) | Serial execution, high peak RSS (~2.7 GB) |
| DNS full test suite | 1101 tests, 1.2 GB RSS |
| Plugin runtime suite | 389 tests, 1.9 GB RSS (wasmtime) |
| DNS integration suites (34 binaries) | Compilation-dominated |
| Full build matrix (release builds) | Cross-compilation + linking |

### Special Runner

| Modalities | Requirement |
|-----------|-------------|
| FreeBSD VM | Dedicated FreeBSD VM (not container) |
| Alpine/musl | Alpine Linux container |
| Miri | Nightly Rust toolchain |
| Fuzz smoke | Nightly Rust + cargo-fuzz |
| Benchmarks | Release profile, stable timing environment |

### Memory-Critical Tests

| Test | Peak RSS | Mitigation |
|------|----------|------------|
| `security_regression` | ~2.7 GB | Serial execution prevents compounding |
| `synvoid-plugin-runtime` | ~1.9 GB | Wasmtime first-build; cached on subsequent runs |
| `synvoid-dns` (full suite) | ~1.3 GB | None needed |
| `synvoid-mesh` | ~1.2 GB | None needed |

## Exclusion Rules

### Must NOT Run in PR Lane

These modalities are explicitly excluded from the PR fast lane to preserve <10 min iteration time:

| Modality | Reason |
|----------|--------|
| Alpine/musl build + test | Expensive cross-compilation; portability is not a merge gate |
| FreeBSD VM build + test | Requires dedicated VM; 15+ min overhead |
| Miri safety checks | Nightly-only; non-deterministic; continue-on-error |
| Fuzz smoke tests (17 targets) | 8+ min total; parser robustness is not a merge gate |
| Outdated dependency reporting | Non-blocking informational check |
| Platform compatibility matrix | 5-target cross-check; portability is not a merge gate |
| Full profile matrix (5 checks) | Duplicates what PR and main lanes already prove |
| Benchmarks | Release profile; performance is not a merge gate |
| Stress tests | Resource-intensive; not relevant to code correctness |
| Full build matrix (8 targets) | Cross-platform builds are post-merge validation |
| DNS integration suites (34) | Covered by blanket `cargo test -p synvoid-dns` in affected selection |
| DNS interop suites | Protocol conformance is post-merge validation |
| Property tests (broader counts) | Broader generation counts run in main lane |
| Release profile tests | Release profile is reserved for release qualification |
| Documentation build | Post-merge validation only |

### Must NOT Run in Main Lane

| Modality | Reason |
|----------|--------|
| Alpine/musl (moved to scheduled) | Expensive container-based testing |
| FreeBSD VM (moved to scheduled) | Requires dedicated VM |
| Miri (moved to scheduled) | Nightly-only, non-blocking |
| Fuzz smoke (moved to scheduled) | Expensive, non-blocking |
| Platform compat (moved to scheduled) | Cross-target checks are qualification-only |
| Outdated deps (moved to scheduled) | Non-blocking informational |

### Must Run Serially

| Test | Reason |
|------|--------|
| `security_regression` | Global state contention; IPC key handling requires single-threaded execution |
| `dns_stress_resource_limits` | Resource limit tests are non-deterministic under parallelism |
| Alpine/musl test | Release profile on constrained container |
| FreeBSD test | Release profile on constrained VM |

## Ownership Summary

| Team | Modalities Owned | Lane(s) |
|------|-----------------|---------|
| Architecture | Static policy guards (19), failure injection | PR |
| Root | Composition / E2E tests (10) | PR, Main |
| Security | Security regression, fuzz smoke (17), dependency audit (2) | PR, Main, Scheduled |
| DNS | Per-crate unit tests (1101), DNS integration suites (34), DNS interop (7), DNS stress, benchmarks (5), property tests | PR, Main, Scheduled, Release |
| Plugin | Per-crate unit tests (389), plugin guard tests | PR |
| WAF | Per-crate unit tests, property tests | PR, Main |
| Mesh | Per-crate unit tests (884) | PR |
| IPC | Per-crate unit tests | PR |
| Honeypot | Per-crate unit tests (182) | PR |
| Tarpit | Per-crate unit tests (54) | PR |
| Platform | Per-crate unit tests, platform qualification (alpine, freebsd, compat) | PR, Scheduled |
| Upload | Per-crate unit tests | PR |
| Safety | Miri checks | Scheduled |
| Documentation | Documentation build | Main |
| CI Infrastructure | Formatting, linting, profile matrix | PR, Main, Scheduled |
| Maintenance | Outdated dependency reporting | Scheduled |

## Cross-References

- **CI lane policy**: `docs/testing/ci-lane-policy.md`
- **Feature/target matrix**: `docs/testing/feature-target-matrix.md`
- **CI performance baseline**: `docs/testing/ci-performance-baseline.md`
- **Test suite ownership**: `docs/testing/test-suite-ownership.md`
- **Root test ownership**: `docs/testing/root-test-ownership.md`
- **Architecture guard ownership**: `docs/testing/architecture-guard-ownership.md`
- **Cache policy**: `docs/testing/cache-policy.md`
- **Nextest policy**: `docs/testing/nextest-policy.md`
