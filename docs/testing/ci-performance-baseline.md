# CI Performance Baseline

## Environment
- Runner: Local development machine (not GitHub-hosted)
- OS: Linux (x86_64)
- Rust: stable
- Date: 2026-07-13

## Baseline Measurements

### Cold Cache / First Build

| Suite | Profile | Wall Time | Notes |
|-------|---------|-----------|-------|
| Root lib tests (898 tests) | release | 5.75s | 1 known failure: platform::sandbox::tests::test_basic_sandbox_succeeds_with_stub |
| DNS crate (1101 tests, 31 binaries) | release | 2m27s | All pass |
| Plugin runtime (389 tests) | release | 3m18s | All pass |
| Security regression (15 tests) | release | 1m22s | All pass |
| Guard suite subset (5 tests) | release | ~1.1s exec | ~10s compile on first run |
| Clippy (default features) | dev | 2.7s | Clean |
| Clippy (--all-features) | dev | 1m40s | FAILS: 24 eBPF compilation errors |
| Root full suite (--no-fail-fast) | release | >60min TIMEOUT | ~621 integration test binaries, compilation-dominated |

### Key Findings
- **Compilation is the dominant cost** — test execution is fast (5s for 898 lib tests)
- **Root crate produces ~621 integration test binaries** — linking is the bottleneck
- **CI profile now defined** — `inherits = "dev"`, `opt-level = 1`, `debug = "line-tables-only"`, `incremental = false`
- **--all-features is broken** — 24 eBPF compilation errors in synvoid-icmp-filter
- **1 known test failure** — platform sandbox stub test

### CI Profile (Added in Milestone A)
```toml
[profile.ci]
inherits = "dev"
opt-level = 1
debug = "line-tables-only"
incremental = false
panic = "unwind"
```

Expected improvement: opt-level=1 with no LTO and no codegen-units=1 should significantly reduce compile/link time while keeping test runtime reasonable.

## Current CI Topology

### Total Cargo Invocations: 135
### Qualification-Only Jobs Blocking PRs: 5 (alpine, freebsd, fuzz, platform-compat, profile-matrix)
### Duplicate Invocations: 32 (26 DNS + 6 plugin guard)

### Waste Summary
| Source | Redundant Invocations |
|--------|----------------------|
| DNS individually listed tests (blanket already covers) | 26 |
| Plugin guard tests (duplicated in guard-suite + plugin-runtime-guardrails) | 6 |
| Total recoverable | 32 (24% of all cargo invocations) |

## Milestone A Results

Measured 2026-07-13 on Linux x86_64, 16 cores, 16 GiB RAM, rustc 1.95.0.

### CI Profile Measurements (First Build, Cold Cache)

| Suite | Profile | Wall Time | Max RSS | Notes |
|-------|---------|-----------|---------|-------|
| Root lib tests (898 tests) | ci | 6s | 188 MB | 1 known failure: platform sandbox stub |
| DNS crate (1101 tests) | ci | 103s | 1,266 MB | All pass. 608 lib + 493 integration |
| Plugin runtime (389 tests) | ci | 294s | 1,897 MB | All pass. Includes first-build wasmtime compile |
| Security regression (15 tests) | ci | 452s | 2,737 MB | All pass. Includes first-build root crate compile |
| Clippy (default features) | dev | 74s | 2,023 MB | Clean |
| Guard suite (26 tests) | ci | ~2-13s each | — | All pass (see guard inventory below) |

**Note:** Plugin runtime and security regression wall times include first-build compilation of their respective crate dependencies. Subsequent runs with warm cache are significantly faster.

### Guard Binary Timing (CI Profile, Warm Cache)

| Guard | Tests | Wall Clock | Classification |
|-------|-------|-----------|----------------|
| root_facade_boundary_guard | 1 | 0.71s | static/source |
| admin_auth_boundary | 8 | 0.70s | runtime |
| unified_server_lifecycle_ownership_guard | 5 | 0.82s | static/source |
| background_task_ownership_guard | 38 | 1.02s | static/source |
| root_module_ledger_guard | 1 | 1.12s | static/source |
| root_dependency_ownership_guard | 3 | 1.28s | static/source |
| unified_worker_composition_root_guard | 28 | 1.37s | static/source |
| data_plane_composition_boundary_guard | 25 | 1.57s | static/source |
| supervisor_task_ownership_guard | 4 | 1.58s | static/source |
| admin_mutation_response_guard | 4 | 1.74s | static/source |
| threat_intel_consumer_actionability_guard | 17 | 1.91s | static/source |
| abi_memory_boundary_guard | 9 | 1.97s | static/source |
| unsafe_native_sandbox_language_guard | 1 | 1.97s | static/source |
| docs_path_reference_guard | 1 | 2.12s | static/source |
| mesh_task_ownership_guard | 164 | 2.80s | static/source |
| plugin_lifecycle_guard | 30 | 4.12s | static/source |
| security_observability_guard | 24 | 4.80s | static/source |
| plugin_signature_policy_guard | 12 | 4.88s | static/source |
| manifest_authority_load_path_guard | 5 | 5.23s | static/source |
| cli_command_dispatch_guard | 39 | 6.08s | static/source |
| mesh_id_boundary_guard | 5 | 6.36s | static/source |
| http_request_pipeline_boundary_guard | 9 | 6.38s | static/source |
| http3_waf_boundary_guard | 5 | 7.63s | static/source |
| worker_mesh_supervision_boundary_guard | 106 | 7.76s | static/source |
| request_path_capability_boundary_guard | 11 | 7.96s | static/source |
| failure_injection | 10 | 8.09s | runtime |
| plugin_capability_boundary_guard | 10 | 8.48s | static/source |
| manual_enforcement_provenance_guard | 12 | 8.59s | static/source |
| threat_intel_boundary_guard | 5 | 12.59s | static/source |

**Classification:** 26 static/source guards (read files, check imports/structure), 3 runtime guards (instantiate types, call functions).

### Before/After Comparison

| Metric | Before (Old ci.yml) | After (New Workflows) | Change |
|--------|---------------------|----------------------|--------|
| PR fast lane Cargo invocations | 135 | 45 | **-67%** |
| Total workflows (all lanes) | 1 monolithic | 4 targeted | Split |
| DNS Cargo invocations | 29 (26 redundant) | 1 (blanket) | **-28** |
| Plugin guard duplicates | 6 | 0 | **-6** |
| Total recoverable invocations | 32 | 0 | **Eliminated** |
| Profile for routine tests | --release | --profile ci | Faster compile |
| Qualification jobs on PR path | 5 | 0 | **-5** |
| PR concurrency cancellation | None | cancel-in-progress: true | **Added** |
| DNS crate wall time (release) | 147s | — | Baseline |
| DNS crate wall time (ci) | — | 103s | **-30%** |

### Impact Sources

| Source of Improvement | Estimated Impact |
|----------------------|-----------------|
| CI profile (no LTO, opt-level=1) | ~30% faster compile for DNS; similar expected for other crates |
| Moving qualification off PR path | 5 expensive jobs removed from PR critical path |
| DNS dedup (26→1 invocations) | 26 fewer Cargo invocations per comprehensive run |
| Plugin guard dedup (6→0) | 6 fewer Cargo invocations per comprehensive run |
| PR concurrency cancellation | Superseded pushes no longer consume runner minutes |

### Remaining Bottlenecks for Milestone B

- **Guard binary linking:** 26 sequential `cargo test --test` invocations each pay independent link costs (~2-13s each). Consolidating into fewer binaries would reduce total link time.
- **Root crate test binary count:** ~621 integration test binaries; linking dominates. nextest could parallelize execution.
- **Root full suite timeout:** >60min on first build due to compilation of 621 binaries. Warm-cache runs would be faster but remain expensive.
- **Plugin runtime first-build:** 4m52s for wasmtime compile. Subsequent runs cached but initial CI run is slow.
- **3 runtime guards:** `admin_auth_boundary`, `admin_mutation_blocklist`, `failure_injection` execute compiled code and cannot be consolidated with source-scanning guards.

## Milestone B Handoff Notes

### Slowest Test Binaries (CI Profile)

| Crate | Tests | Wall Time | Notes |
|-------|-------|-----------|-------|
| synvoid (root) lib | 898 | 6s | Fastest per-test |
| synvoid-dns lib | 608 | 5s | Fast |
| synvoid-mesh | 884 | 193s wall | Slow (compilation-dominated) |
| synvoid-honeypot | 182 | 120s wall | Slow (compilation-dominated) |
| synvoid-tarpit | 54 | 119s wall | Slow (compilation-dominated) |
| synvoid-plugin-runtime | 389 | 294s | Slowest (wasmtime first-build) |

### Tests Requiring `--test-threads=1`

| Suite | Lane | Reason |
|-------|------|--------|
| `security_regression` | PR, Release | Serial execution required |
| Full suite (nightly-qualification) | Scheduled | Release profile, serial |
| `dns_stress_resource_limits` | DNS-specific | Resource limit tests |

### Tests Using Global State / Scarce Resources

| Test File | Resource | Mitigation |
|-----------|----------|------------|
| `tests/e2e_process_test.rs` | 6 IPC binds + process IDs | Uses ephemeral ports (`:0`) |
| `tests/drain_e2e_test.rs` | 4 IPC binds + process IDs | Uses ephemeral ports |
| `tests/socket_handoff_test.rs` | 4 bind calls (Unix + TCP) | Uses ephemeral ports |
| `tests/ipc_test.rs` | 3 UnixListener binds | Uses temp paths |
| `tests/integration_test.rs` | 6 TCP binds | Uses ephemeral ports |
| `tests/mesh_http_framing.rs` | 1 TCP bind | Uses `127.0.0.1:0` |
| `crates/synvoid-dns/tests/transport_lifecycle.rs` | 1 UDP bind | Uses ephemeral port |

**No `lazy_static`, `Once`, or `static ref` found in tests.** All port bindings use ephemeral ports or temp paths, reducing collision risk.

### Architecture Guard Binary Inventory

**27 guard test files** in `tests/`:

**26 static/source guards** — read files, check imports/structure, no compiled code execution:
- Use `std::fs::read_to_string`, `include_str!`, `std::fs::read_dir`, or `strip_comments()` to scan source
- Check for forbidden tokens/imports/patterns in `.rs` or `.md` files
- Assert absence of violations
- Each pays independent link cost (~2-13s) for the test harness

**3 runtime guards** — instantiate types, call functions, test behavior:
- `admin_auth_boundary`: constructs `AdminActor`/`AdminMutationResult`, asserts behavioral invariants
- `admin_mutation_blocklist`: tests blocklist mutation behavior
- `failure_injection`: imports concrete subsystem types, injects failures, tests graceful degradation

### Current Guard Execution Structure

**26 sequential `cargo test --test` invocations** in pr-fast.yml guard-suite job, plus 1 separate `docs-link-guard` job. Each invocation pays independent compilation and link costs.

### Candidate Nextest Filters and Timeout Classes

**<1s (13 guards):** root_facade_boundary_guard, admin_auth_boundary, unified_server_lifecycle_ownership_guard, background_task_ownership_guard, root_module_ledger_guard, root_dependency_ownership_guard, unified_worker_composition_root_guard, data_plane_composition_boundary_guard, supervisor_task_ownership_guard, admin_mutation_response_guard, threat_intel_consumer_actionability_guard, abi_memory_boundary_guard, unsafe_native_sandbox_language_guard

**1–5s (5 guards):** docs_path_reference_guard, mesh_task_ownership_guard, plugin_lifecycle_guard, security_observability_guard, plugin_signature_policy_guard

**5–10s (11 guards):** manifest_authority_load_path_guard, cli_command_dispatch_guard, mesh_id_boundary_guard, http_request_pipeline_boundary_guard, http3_waf_boundary_guard, worker_mesh_supervision_boundary_guard, request_path_capability_boundary_guard, failure_injection, plugin_capability_boundary_guard, manual_enforcement_provenance_guard, threat_intel_boundary_guard

**>30s (full crate suites):** synvoid root lib (~6s), synvoid-config (~103s), synvoid-core (~103s), synvoid-mesh (~193s), synvoid-honeypot (~120s), synvoid-tarpit (~119s)

### Tests That Cannot Leave Release Mode

**None.** All `--release` usages are confined to:
- `main-comprehensive.yml` — release validation lane (intentional)
- `nightly-qualification.yml` — scheduled qualification (intentional)
- `release-qualification.yml` — release artifact validation (intentional)

No routine/PR test uses `--release`. The architecture correctly separates routine tests (CI profile) from production validation (release profile).

### Known Failures

| Test | Profile | Status | Notes |
|------|---------|--------|-------|
| `platform::sandbox::tests::test_basic_sandbox_succeeds_with_stub` | ci | FAILING | Pre-existing; assertion at `src/platform/sandbox.rs:1247` |

## Post-Milestone C Counts

After migrating 19 domain test files to owning crates (16 in initial pass + 3 in closure pass):

| Metric | Before (pre-Milestone A) | After Milestone A | After Milestone C |
|--------|--------------------------|-------------------|-------------------|
| Root integration test files | 43 | 43 | 26 |
| Root test functions | ~621 | ~621 | ~180 (estimated) |
| DNS test files at root | 5 | 5 | 0 (all in synvoid-dns) |
| WAF test files at root | 3 | 3 | 0 (all in synvoid-waf) |
| IPC test files at root | 2 | 2 | 0 (all in synvoid-ipc) |
| Mesh test files at root | 3 | 3 | 0 (all in synvoid-mesh) |
| Plugin-runtime test files at root | 2 | 2 | 0 (all in synvoid-plugin-runtime) |
| Platform test files at root | 1 | 1 | 0 (all in synvoid-platform) |
| Core test files at root | 0 | 0 | 0 (admin tests moved to synvoid-core) |
| Proxy test files at root | 1 (traffic_regression) | 1 | 1 (echo server only; proxy functions moved to synvoid-proxy) |

Feature/target matrix: see `docs/testing/feature-target-matrix.md`

### Timing Impact

Root test binary count reduced from ~43 to ~26 integration targets. Estimated compile/link savings:
- Each eliminated root integration target saves ~2-5s linking time
- Estimated total root compile reduction: ~40-80s on cold build
- Localized domain changes no longer rebuild unrelated root integration targets
- Per-crate test suites (synvoid-dns, synvoid-core, etc.) compile independently without root dependency graph

## Milestone E: Test-Level Efficiency (Gap Closure)

### DNS Fixture Deduplication

1,419 lines of duplicated test code removed across 16 DNS integration test files:

| File | Lines Removed |
|------|---------------|
| `authoritative_negative.rs` | 118 |
| `dns_interop_authoritative.rs` | 93 |
| `dns_interop_truncation.rs` | 76 |
| `dns_interop_transfers.rs` | 151 |
| `dns_interop_recursive.rs` | 137 |
| `dns_interop_update_notify.rs` | 120 |
| `dns_interop_dnssec.rs` | 185 |
| `control_plane_exclusion.rs` | 117 |
| `control_plane_cache_completion.rs` | 107 |
| `notify_behavior.rs` | 27 |
| `notify_scheduling_semantics.rs` | 31 |
| `update_authorized_semantics.rs` | 58 |
| `update_atomicity_rollback.rs` | 58 |
| `axfr_ixfr_transfer_semantics.rs` | 70 |
| `ixfr_record_delta.rs` | 24 |
| `control_plane_authorization.rs` | 47 |

### Nextest Groups

4 evidence-based test groups replacing broad pattern overrides:

| Group | Max Threads | Tests |
|-------|-------------|-------|
| `global-env` | 1 | security_regression, metrics_wiring |
| `process-spawn` | 2 | fault_injection |
| `network-heavy` | 4 | DNS integration tests |
| `fixed-resource` | 1 | Reserved (no current consumers) |

### Repetition Validation

5-run campaigns on touched suites — 0 flakes:

| Suite | Tests | Runs | Result |
|-------|-------|------|--------|
| security_regression | 15 | 5 | 5/5 pass |
| DNS interop (6 files) | 37 | 5 | 5/5 pass |
| DNS control plane (9 files) | 91 | 5 | 5/5 pass |

## Local Validation Baseline (2026-07-15)

Observed on local development machine, Linux x86_64. **Active rustc version: 1.97.0**.

| Check | Result | Notes |
|-------|--------|-------|
| Formatting (`cargo fmt --all -- --check`) | PASS | |
| Repo guards | 63 passed (8 binaries, 0.169s) | `cargo nextest run -p synvoid-repo-guards` |
| Root test ownership guard | 2 passed (0.00s) | |
| Selector tests (pytest) | 90 passed | `scripts/ci/select-affected.py` |
| xtask fast lane dry-run | 6 steps, all pass | |
| xtask comprehensive lane dry-run | 12 steps, all pass | |
| xtask guards lane dry-run | 16 steps, all pass | |

### xtask Lane Parity Corrections

The following corrections were applied to xtask lanes to achieve parity with CI workflows:

- **Fast lane clippy:** Removed `--all-features` to match PR workflow (`pr-fast.yml`), which does not enable all features due to `synvoid-icmp-filter` eBPF compilation failures.
- **Security lane:** Changed from `cargo test` to `cargo nextest run` with `--profile ci` to match the CI profile used in qualification workflows.
