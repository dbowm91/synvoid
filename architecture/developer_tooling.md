# Developer Tooling & Quality Infrastructure

## 1. Scope

This document indexes the non-runtime tooling: `tools/xtask`, `tools/synvoid-repo-guards`, `fuzz/`, `benches/` + `benchmarks/`, and `examples/`. The authoritative verification contract is `docs/testing/verification-contract.md` (frozen).

## 2. xtask (`tools/xtask`)

CI orchestration runner invoked as `cargo xtask …`:

| Command | Lanes |
|---------|-------|
| `verify` | 10 fail-fast steps: fmt → clippy (`--profile ci --all-targets -D warnings`) → dependency-policy (`cargo deny check`) → core compile → repo-guards → security regression (`-- --test-threads=1`) → root guard suite (`--features mesh`) → core admin tests → admin contract (`--features mesh,dns,icmp-filter`) → failure injection. This is the `ci` job; the blocking `dependency-security` job runs `cargo deny check` + `cargo audit` separately. |
| `verify-full` | fmt → clippy → feature-profile compiles (`--no-default-features` minimal, `mesh`, `dns`, `icmp-filter`, `mesh,dns`) → minimal-profile tests → full workspace nextest (`--exclude synvoid-fuzz`) → doctests (10 steps) |
| `verify-release` | Release qualification + package inspection; **never publishes**; fails on dirty tree |
| `standalone baseline` / `standalone consumer <crate>` | Regenerate candidate dependency evidence; packaged-crate consumer test outside the workspace (offline) |
| `icmp-qualify` / `eggbench-qualification` | Opt-in native qualification front-ends (see `tools/xtask/src/icmp_qualify.rs`) |
| `test package <name>` / `test guards` | Focused runs |

Options: `--dry-run`, `--json`, `--verbose`, `--allow-dirty`. Core types in `tools/xtask/src/report.rs`: `LaneReport`, `StepResult`, `StepStatus`; `CrateQualification` is a crate-internal enum in `tools/xtask/src/verify.rs`.

## 3. CI (`.github/workflows/ci.yml`)

Four jobs. `ci` and `dependency-security` run on every push/PR (and on the daily `0 6 * * *` schedule); the two native qualification jobs are `workflow_dispatch`-gated boolean inputs.

| Job | Trigger | What it runs |
|-----|---------|--------------|
| `ci` | push/PR/schedule/dispatch | `cargo xtask verify` |
| `dependency-security` | push/PR/schedule/dispatch | `cargo deny check` + `cargo audit` (blocking) |
| `sandbox-native-qualification` | dispatch only (`sandbox_native_qualification: true`) | Phase 94 Linux Landlock/seccomp probes + jail workload/isolation suites |
| `icmp-native-qualification` | dispatch only (`icmp_native_qualification: true`) | Phase 93 disposable Linux nftables qualification, two isolated passes |

Pinned third-party Actions are immutable commit SHAs; pinned verification tools are `nextest@0.9.140`, `cargo-deny@0.20.2`, `cargo-audit@0.22.2`.

## 4. Repo Guards (`tools/synvoid-repo-guards`)

Helper library for static architecture guard tests (no dependency on the root crate): recursive `.rs` collection, comment/string/`#[cfg(test)]` stripping, and a `Violations` accumulator. The guard suites live in `tools/synvoid-repo-guards/tests/` (25 files, run by the `repo-guards` verify step).

Guard coverage spans: cache/selector and CI policy, composition boundaries, config-model boundaries, crate-boundary reuse, dependency security, DNS dependency edges / firewall truthfulness / runtime-config ownership, DNSSEC keystore custody, Eggfetch lane freeze, honeypot application boundary, jail-runtime boundary, lifecycle ownership, mesh application-capability and mesh-protocol boundaries, module ownership (root dependency entitlements), negative fixtures, public-crate release policy, runtime-truthfulness closeout, standalone-candidate contract, TLS post-quantum truthfulness, workspace dependency policy, and YARA execution boundary.

Root `tests/` holds 58 integration/guard files. Every one must have an entry in `tests/OWNERSHIP.toml` or `root_test_ownership_guard` fails; `class = "domain"` entries are rejected (those tests belong in the owning crate's `tests/`). Notable root guards: `boundary_composition_guard`, `security_guard`, `facade_disposition_guard`, `root_facade_boundary_guard`, `platform_canonicalization_guard`, `mesh_id_boundary_guard`, `root_test_ownership_guard`.

## 5. Fuzzing (`fuzz/`)

21 cargo-fuzz targets, declared flat in `fuzz/*.rs` (not `fuzz/fuzz_targets/`) and registered as `[[bin]]` targets in `fuzz/Cargo.toml`. Nightly + cargo-fuzz required; authoritative inventory in [`ci_fuzz_failure_injection.md`](./ci_fuzz_failure_injection.md):

`admin_mutation_result_decode`, `blocklist_event_decode`, `blocklist_snapshot_decode`, `config_parse_validation`, `dns_message_decode`, `fuzz_attack_detection`, `fuzz_early_parse`, `fuzz_ipc`, `fuzz_protocol_proto_decode`, `fuzz_raft_commit_notification`, `fuzz_raft_response`, `fuzz_serialization`, `fuzz_serialization_new`, `http_chunked_framing`, `http_header_normalization`, `http_path_normalization`, `http_routing_matcher`, `jail_ipc_frame_decode`, `mesh_protocol_compressed_decode`, `parsed_query_parse`, `plugin_manifest`.

Smoke policy: `cargo +nightly fuzz run <target> -- -runs=1000`, manual only. Failure-injection seams: [`ci_fuzz_failure_injection.md`](./ci_fuzz_failure_injection.md).

## 6. Benchmarks

`benches/` holds 16 `.rs` files; the root `Cargo.toml` registers 12 `[[bench]]` targets (`bench_attack_detection`, `bench_attack_detection_wave10`, `bench_buffer_pool`, `bench_dns`, `bench_honeypot_persistence`, `bench_metrics_hotpath`, `bench_normalization`, `bench_proxy_cache`, `bench_proxy_headers`, `bench_ratelimit`, `bench_upstream_selection`, `bench_wasm`). `bench_broadcast.rs`, `bench_proxy_cache_wave10.rs`, `bench_routing.rs`, and the `run_benchmarks.rs` driver are files in that directory but are not registered `[[bench]]` targets; `bench_dns` is the only registered target gated on `required-features = ["dns"]`.

No benchmark runs in routine CI — `cargo xtask verify` and `verify-full` contain no bench step. Focused benches added by the perf campaign (`bench_upstream_selection`, `bench_metrics_hotpath`, `bench_buffer_pool`, `bench_honeypot_persistence`) are local-only runs. The transport comparison harness in `benchmarks/http_transport/` is manual-only and must never be compared across hosts.

## 7. Examples (`examples/`)

- `dynamic-plugin-example/` — loading a dynamic WASM plugin.
- `embedded-app-example/` — embedding SynVoid as a library.
- `dns/` + `build-waf-app.sh` — DNS usage and WAF app build script.

## 8. Related Docs

- `docs/testing/verification-contract.md`, `docs/testing/nextest-policy.md`, `docs/testing/root-test-ownership.md`
- [`root_module_ledger.md`](./root_module_ledger.md) (what the guards enforce)
- [`semver_stability_policy.md`](./semver_stability_policy.md)
