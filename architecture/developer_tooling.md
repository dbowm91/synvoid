# Developer Tooling & Quality Infrastructure

## 1. Scope

This document indexes the non-runtime tooling: `tools/xtask`, `tools/synvoid-repo-guards`, `fuzz/`, `crates/synvoid-testkit`, and `examples/`. The authoritative verification contract is `docs/testing/verification-contract.md` (frozen).

## 2. xtask (`tools/xtask`)

CI orchestration runner invoked as `cargo xtask …`:

| Command | Lanes |
|---------|-------|
| `verify` | fmt → clippy (`--profile ci --all-targets -D warnings`) → core compile → repo-guards → security regression → root guard suite → core admin tests → failure injection (fail-fast; this is exactly CI) |
| `verify-full` | fmt → clippy → feature-profile compiles (`mesh`, `dns`, `mesh,dns`) → full workspace nextest → doctests |
| `verify-release` | Release qualification + package inspection; **never publishes**; fails on dirty tree |
| `test package <name>` / `test guards` | Focused runs |

Options: `--dry-run`, `--json`, `--verbose`, `--allow-dirty`. Core types: `LaneReport`, `StepResult`, `StepStatus`, `CrateQualification`.

## 3. Repo Guards (`tools/synvoid-repo-guards`)

Helper library for static architecture guard tests (no dependency on the root crate): recursive `.rs` collection, comment/string/`#[cfg(test)]` stripping, and a `Violations` accumulator.

The actual guard suites live in root `tests/` (~12 files, 100+ tests), covering: ABI memory boundaries, admin mutation response shape, composition boundaries, CLI/admin validation, lifecycle/task ownership, mesh-ID enforcement boundary, plugin lifecycle, root facade boundaries, test ownership (`tests/OWNERSHIP.toml`), security invariants, and worker/mesh supervision boundaries.

## 4. Fuzzing (`fuzz/`)

17 cargo-fuzz targets (nightly + cargo-fuzz required):

`admin_mutation_result_decode`, `blocklist_event_decode`, `blocklist_snapshot_decode`, `dns_message_decode`, `fuzz_attack_detection`, `fuzz_early_parse`, `fuzz_ipc`, `fuzz_protocol_proto_decode`, `fuzz_raft_commit_notification`, `fuzz_raft_response`, `fuzz_serialization`, `fuzz_serialization_new`, `http_header_normalization`, `http_path_normalization`, `mesh_protocol_compressed_decode`, `parsed_query_parse`, `plugin_manifest`.

Smoke policy and failure-injection seams: [`ci_fuzz_failure_injection.md`](./ci_fuzz_failure_injection.md).

## 5. Testkit (`crates/synvoid-testkit`)

Shared test fixtures (temp config dirs, minimal config TOML, request builders, assertion macros). Deliberately limited to `synvoid-core` + `synvoid-config` deps. **Currently has zero consumers** — boundary policy documented in its README; retained pending removal decision.

## 6. Examples (`examples/`)

- `dynamic-plugin-example/` — loading a dynamic WASM plugin.
- `embedded-app-example/` — embedding SynVoid as a library.
- `dns/` + `build-waf-app.sh` — DNS usage and WAF app build script.

## 7. Related Docs

- `docs/testing/verification-contract.md`, `docs/testing/nextest-policy.md`, `docs/testing/root-test-ownership.md`
- [`root_module_ledger.md`](./root_module_ledger.md) (what the guards enforce)
- [`semver_stability_policy.md`](./semver_stability_policy.md)
