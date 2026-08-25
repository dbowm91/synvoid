# AGENTS.md

SynVoid is a high-performance WAF & reverse proxy in Rust with a mesh networking layer and multi-process architecture (Supervisor + UnifiedServerWorker data plane + CPU offload). 45-member Cargo workspace: root app, 37 `synvoid-*` crates under `crates/`, plus `pqc`, `admin-ui` (Yew/WASM via Trunk), `examples/*`, `fuzz`, `tools/{xtask,synvoid-repo-guards}`. Linux is the primary deployment target.

## Build & Setup

```bash
cargo build --release   # default features: socket-handoff, mesh, dns, erased_pool, swagger-ui
```

- **protoc is required**: the default `mesh` feature triggers protobuf codegen in `build.rs` (`tonic-prost-build`). Install `protobuf-compiler` (CI does) or builds fail confusingly.
- All feature profiles must compile: `cargo check --no-default-features [--features mesh | dns | mesh,dns]`.

## Verification

**Authority**: `docs/testing/verification-contract.md` (frozen contract). The single CI workflow (`.github/workflows/ci.yml`) runs exactly:

```bash
cargo xtask verify   # fmt → clippy --profile ci --all-targets -D warnings → core compile check → repo-guards → security regression → root guard suite → core admin tests → failure injection
```

xtask subcommands (options: `--dry-run`, `--json`, `--verbose`, `--allow-dirty`):

```bash
cargo xtask verify-full            # broader local: feature-profile compiles + one full workspace nextest run + doctests
cargo xtask verify-release         # release qualification + package inspection; NEVER publishes; fails on dirty tree
cargo xtask test package <name>    # e.g. cargo xtask test package synvoid-dns
cargo xtask test guards            # all architectural guard tests
```

Focused runs:

```bash
cargo test --lib <name>                          # unit test
cargo test --test <integration_name>             # root integration test
cargo nextest run --workspace --cargo-profile ci --profile ci --exclude synvoid-fuzz   # full suite
cargo test --workspace --doc --profile ci        # doctests (nextest doesn't run these)
cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci               # static repo guards
./scripts/verify_architecture.sh                 # local-only profile checks + guard suite
```

Testing quirks:

- Use `--profile ci` for routine testing (matches CI); `--release` only for release qualification.
- nextest is pinned (0.9.140) — see `docs/testing/nextest-policy.md`.
- `security_regression` must run single-threaded: `cargo test --test security_regression --profile ci -- --test-threads=1`.
- Some guard suites need features: `--test mesh_task_ownership_guard --features mesh,dns` (same for `worker_supervision_control_flow`, `composition_root_behavioral`).
- Stress/endurance suites are NOT in verify-full: `dns_stress`, `worker_supervision_control_flow -- --test-threads=1`, `fault_injection_test`.
- Fuzz smoke tests need nightly + cargo-fuzz: `cargo +nightly fuzz run <target> -- -runs=1000` (17 targets in `fuzz/fuzz_targets/`). See `architecture/ci_fuzz_failure_injection.md`.
- Publication is manual via `cargo publish` only — see `docs/releasing.md`.

## Test Placement Rules

- Every root `tests/*.rs` file MUST have an entry in `tests/OWNERSHIP.toml` or `root_test_ownership_guard` fails; `class = "domain"` entries are rejected — single-crate tests belong in the owning crate's `tests/`. Classification guide: `docs/testing/root-test-ownership.md`.
- Suites outside routine CI (run when touching those areas): DNS full/interop (`cargo test -p synvoid-dns --profile ci`, conformance via `./scripts/dns/conformance.sh`), plugin runtime (`plugin_failure_does_not_poison_manager`, `manifest_authority_wiring`), honeypot/tarpit (`--all-targets`), `admin_route_contract` (frontend/backend API alignment).

## Architecture Facts

- **Entry point**: `src/main.rs` → delegates to `src/commands/{plan,execute,runtime_launch}.rs`
- **Supervisor**: `src/supervisor/` — lifecycle, IPC, control-plane
- **Data plane**: `src/worker/unified_server/` — HTTP + WAF + proxy in ONE Tokio event loop; CPU offload in `src/worker/cpu_task/`
- **Process model**: Supervisor (1) → UnifiedServerWorker (1) + CpuWorker (1). Workers are NOT process-per-tenant. The `--worker` flag spawns a legacy `BaseWorkerProcess` unused for HTTP.
- **Mesh**: `crates/synvoid-mesh/src/mesh/` — DHT, transport, Raft, peer auth
- Many legacy root paths re-export crate contents for compat (e.g., `src/dns/mod.rs` re-exports `synvoid_dns::*`).

### Composition Boundary (guard-enforced)

Request-path code consumes **narrow traits**, never concrete infrastructure:

| Layer | May Own/Import |
|-------|---------------|
| Composition roots (`src/worker/unified_server/`, `src/supervisor/`, `src/server/`) | Concrete `BlockStore`, `ThreatIntelligenceManager`, mesh/DHT/Raft handles, IPC, config |
| Request path (`src/waf/`, `src/proxy/`, `src/http/`, `crates/synvoid-waf/`, `crates/synvoid-proxy/`) | Narrow traits (`BlockListStore`, `WafProcessor`), config snapshots, request context |
| Control-plane (`crates/synvoid-mesh/`, `crates/synvoid-block-store/`) | Full infrastructure internals |

To add a capability: define a narrow trait in `crates/synvoid-waf/src/traits.rs` or `crates/synvoid-core/`, implement on concrete type in a composition root, pass `Arc<dyn Trait>` to request-path modules.

Root-module ownership policy lives in `architecture/root_module_ledger.md` — prefer dedicated `synvoid-*` crates unless the ledger says `keep_app_root`.

## Stale Path Map (use the Correct path)

| Wrong | Correct |
|-------|---------|
| `src/http/client.rs` | `src/http_client/mod.rs` |
| `src/http/shared_handler.rs` | `crates/synvoid-http/src/shared_handler.rs` |
| `src/mesh/proxy.rs` | `crates/synvoid-mesh/src/mesh/proxy.rs` |
| `src/mesh/transport.rs` | `crates/synvoid-mesh/src/mesh/` (transport_core/ and transports/) |
| ConfigManager | `crates/synvoid-config/src/lib.rs:114` |
| `src/overseer/`, `src/master/` | `src/supervisor/` (consolidated) |
| `src/http3/server.rs` | `crates/synvoid-http3/src/server.rs` |
| `src/worker/mod.rs` (CPU offload) | `src/worker/cpu_task/` (split 2026-06) |
| `src/worker/unified_server.rs` | `src/worker/unified_server/` (split 2026-06) |
| `src/app_server/granian.rs` | `crates/synvoid-app-server/src/granian.rs` |
| `src/main.rs` (command dispatch) | `src/commands/plan.rs` + `execute.rs` + `runtime_launch.rs` |
| `src/tls/acme.rs`, `src/tls/acme_dns.rs` | `crates/synvoid-tls/src/acme*.rs` |
| `src/plugin/wasm_runtime.rs` | `crates/synvoid-plugin-runtime/src/wasm_runtime.rs` |
| `serialize_headers` (inline) | `crates/synvoid-plugin-runtime/src/abi_frame.rs` (canonical) |
| `src/plugin/instance_pool.rs` | `crates/synvoid-plugin-runtime/src/instance_pool.rs` |
| `src/config/admin.rs` | `crates/synvoid-config/src/admin.rs` |
| `src/admin/authority.rs` | `crates/synvoid-core/src/admin_mutation.rs` |
| `src/wasm_pow/` | `crates/synvoid-wasm-pow/` |
| `src/server/mod.rs` (monolithic) | `src/server/` (split: `startup_plan.rs`, `resources.rs`, `runtime_handles.rs`, `plugin_runtime.rs`) |
| `src/dns/*.rs` (legacy copies) | `crates/synvoid-dns/src/` (canonical) |

## Security Invariants (violations break guard tests)

- **Constant-time comparison**: use `subtle::ConstantTimeEq` for secrets, keys, MACs, auth tokens (PoW solution verification included). Private key files get mode `0o600`.
- **Overlong UTF-8**: WAF normalizer decodes overlong percent-encoded sequences (`%C0%BE` → `>`); sets `OVERLONG` flag on `NormalizationFlags`; `strict_normalization` rejects them. Tests: `test_overlong_*`, `test_waf_corpus_xss_invalid_utf8`.
- **Plugin lifecycle**: own hot-reload watchers with `PluginRuntimeOwner`; never `std::mem::forget`. Reload is prepare-then-commit with generation-aware atomic swaps — a failed reload must never replace a working plugin. File-based loading reads WASM bytes once (TOCTOU closure via `PreparedPluginLoad.wasm_bytes`).
- **SignedSandboxed plugins**: empty `binary_sha256`/`manifest_sha256` rejected in production.
- **Plugin ABI memory boundary**: guest pointer ops require `guest_alloc`/`guest_free` and `checked_guest_range` (no fixed-offset fallback). Frame serialization only via `abi_frame::serialize_headers_canonical` / `build_request_frame`.
- **Native extensions**: disabled by default; production load requires explicit risk acknowledgement + path allowlist. They are NOT sandboxed; retain the `Library` handle via `Arc` for the lifetime of derived values.

### Admin Control-Plane Authority

- Mutating endpoints return typed `AdminMutationResult` (`synvoid_core::admin_mutation`), attributed to an `AdminMutationAuthority` variant (compat paths use `CompatibilityLegacy`) — never generic `{"success": true}`.
- Block/unblock emits `AdminAuditEvent` via `state.audit.log_audit_event()`. Never store raw session tokens in audit logs (`AdminActor.session_id_hash` is hashed).
- Browser clients: HttpOnly session cookie + CSRF token; bearer token only for session exchange; WebSocket auth via session cookie only. Frontend treats 401/403 as session expiry.
- Admin responses carry `nosniff`, `X-Frame-Options: DENY`, CSP `frame-ancestors 'none'`, strict referrer policy.
- Mesh propagation is best-effort (`QueuedBestEffort`) — never promise delivery to all peers. Details: `architecture/admin_control_plane_authority.md`.

### Threat-Intel Enforcement

1. Raw lookups (`lookup_local_indicator*`, `lookup_threat_indicator_in_dht`) are diagnostic-only; enforcement uses `lookup_*_policy_strict`.
2. WAF reads BlockStore, not `ThreatIntelligenceManager` — mesh enforcement populates BlockStore.
3. New block-store writes use `block_ip_with_provenance` with `BlockProvenanceKind` (`LegacyUnknown` only for compat/tests/mocks).
4. Mesh-ID blocks are admin/control-plane only — `is_mesh_id_blocked()` must never appear in WAF/request/proxy/HTTP/3 code.
5. New consumers need `ThreatIntelConsumerKind::Enforcement` + `ThreatIntelConsumerAction::PermitAction` before mutating state.

## Serialization & Crypto Standards

- Postcard (not JSON) for distributed state; typed rkyv structs (`Archive`/`RkyvSerialize`/`RkyvDeserialize`), never `serde_json::Value`.
- Unix timestamps are u64 — use `synvoid_utils::{safe_unix_timestamp, current_timestamp}` (`crates/synvoid-utils/src/ip_utils.rs`) or `synvoid_core::time::{current_timestamp_secs, current_timestamp_millis}`; `.saturating_sub()` for durations.
- Base64: always `URL_SAFE_NO_PAD` for mesh/DHT data. Prefer pure-Rust deps over C bindings.

## Repo-Specific Pointers

- **Module overrides**: each subsystem dir has an `AGENTS.override.md` with extra rules — read before working there: `src/{waf,http,http3,http_client,proxy,config,admin,auth,platform,plugin,worker,tunnel,app_server,theme,static_files,serverless}/AGENTS.override.md` and `crates/synvoid-{dns,honeypot,tarpit}/AGENTS.override.md`.
- **Skills**: `.opencode/skills/<name>/SKILL.md` — 32 per-subsystem guides (names match subsystems, e.g. `dns_dnssec`, `serverless_wasm`, `ipc_hardening`, `raft_consensus`, `org_key_trust_chain`). Load before working in an unfamiliar subsystem.
- **Config paths**: `--config-path` takes the DIRECTORY containing `main.toml` + `sites/`, not the TOML file. Caveat: `--configtest` ignores `--config-path` and validates `./config/` relative to CWD.
- **Key docs**: `architecture/overview.md` (bird's eye), `architecture/http_request_pipeline.md`, `architecture/mesh_trust_domains.md`, `architecture/block_store.md`, `architecture/plugin_runtime_sandbox.md`, `architecture/root_module_ledger.md`, `architecture/worker_data_plane_composition_root.md`, `docs/RELEASE.md` + `docs/releasing.md`. `architecture/` (119 docs) and `plans/` are development artifacts; user/operator docs live in `docs/`.

## Known Issues

- `wasmtime` 40.0.4 arrives transitively via yara-x (YARA rule compilation only, not the wasm sandbox); direct wasmtime is patched to 42.0.2 via `[patch.crates-io]`. 13 advisory ignores in `deny.toml`, re-audit date 2026-10-01.
- `spin` idle instance eviction never cleans up old UUID entries.
- `synvoid-testkit` currently has zero consumers — boundary policy documented in its README.
