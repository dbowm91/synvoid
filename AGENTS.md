# AGENTS.md

SynVoid is a high-performance WAF & reverse proxy in Rust with a mesh networking layer and multi-process architecture (Supervisor + UnifiedServerWorker data plane + CPU offload). 49-member Cargo workspace: root app, 41 `synvoid-*` crates under `crates/` (Phase 28 adds `synvoid-native-extension`, Phase 29 adds `synvoid-jail-runtime`), plus `pqc`, `admin-ui` (Yew/WASM via Trunk), `examples/*`, `fuzz`, `tools/{xtask,synvoid-repo-guards}`. Linux is the primary deployment target.

## Build & Setup

```bash
cargo build --release   # default features: socket-handoff, mesh, dns, erased_pool, swagger-ui
```

- **protoc is required**: the default `mesh` feature triggers protobuf codegen in `build.rs` (`tonic-prost-build`). Install `protobuf-compiler` (CI does) or builds fail confusingly.
- All feature profiles must compile: `cargo check --no-default-features [--features mesh | dns | icmp-filter | mesh,dns]` (bounded Phase 05 matrix; full powerset intentionally not tested).
- `--no-default-features` is honestly minimal (Phase 25): the root `[dev-dependencies]` self-edge keeps `default-features = false`, mesh/dns absence branches execute under `cargo test --no-default-features` (see `minimal-tests` in `docs/testing/verification-contract.md`). Only `icmp-filter` was live before; now mesh/dns absence is live too. `tests/mesh_startup_rollback` needs `--features mesh` (`required-features`).

## Verification

**Authority**: `docs/testing/verification-contract.md` (frozen contract). The single CI workflow (`.github/workflows/ci.yml`) runs exactly:

```bash
cargo xtask verify   # fmt → clippy --profile ci --all-targets -D warnings → cargo deny check → core compile check → repo-guards → security regression → root guard suite → core admin tests → admin contract (mesh,dns,icmp-filter) → failure injection (+ blocking dependency-security CI job runs deny + audit; daily schedule)
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
- Fuzz smoke tests need nightly + cargo-fuzz: `cargo +nightly fuzz run <target> -- -runs=1000` (21 targets in `fuzz/`). See `architecture/ci_fuzz_failure_injection.md`.
- Publication is manual via `cargo publish` only — see `docs/releasing.md`.

## Test Placement Rules

- Every root `tests/*.rs` file MUST have an entry in `tests/OWNERSHIP.toml` or `root_test_ownership_guard` fails; `class = "domain"` entries are rejected — single-crate tests belong in the owning crate's `tests/`. Classification guide: `docs/testing/root-test-ownership.md`.
- Suites outside routine CI (run when touching those areas): DNS full/interop (`cargo test -p synvoid-dns --profile ci`, conformance via `./scripts/dns/conformance.sh`), plugin runtime (`plugin_failure_does_not_poison_manager`, `manifest_authority_wiring`), honeypot/tarpit (`--all-targets`). The admin contract (`admin_route_contract`, `admin_router_composition`, `admin_smoke_flow`) runs in routine CI with `--features mesh,dns,icmp-filter`; run `admin_route_contract` explicitly when touching frontend/backend API alignment.

## Architecture Facts

- **Entry point**: `src/main.rs` → delegates to `src/commands/{plan,execute,runtime_launch}.rs`
- **Supervisor**: `src/supervisor/` — lifecycle, IPC, control-plane
- **Data plane**: `src/worker/unified_server/` — HTTP + WAF + proxy in ONE Tokio event loop; CPU offload in `src/worker/cpu_task/`
- **Process model**: Supervisor (1) → N `UnifiedServerWorker` data-plane processes (`spawn_unified_server_workers(config.unified_server_workers)` in `src/supervisor/process.rs`; shipped `config/main.toml` sets `[defaults.worker_pool] workers = 4`, code default 1) + CpuWorker offload. Workers are NOT process-per-tenant. Note: the legacy `--worker` flag (`crates/synvoid-ipc/src/worker.rs` `BaseWorkerProcess`) has NO dispatch branch in `src/commands/plan.rs` and falls through to the default `RuntimeCommand::Supervisor`; HTTP serving uses `--unified-server-worker` / `--cpu-worker`.
- **Mesh**: `crates/synvoid-mesh/src/mesh/` — DHT, transport, Raft, peer auth. Low-capability wire/identity vocabulary lives in `crates/synvoid-mesh-protocol/` (Phase 27: constants, `HybridSignature` envelope, `ProtocolSigner` Ed25519 verification, replay protection, threat taxonomy, framing; `synvoid-mesh` depends downward and re-exports compat paths). Binding distributed-state contract: `architecture/distributed_state_contract.md` (authority taxonomy `DistributedNamespaceAuthority`, typed `QuorumUnavailable`/`CanonicalCommitted` outcomes, partition/rejoin tests in `crates/synvoid-mesh/tests/distributed_state_partition.rs`; MESH-15 closed as stale).
- Many legacy root paths re-export crate contents for compat (e.g., `src/dns/mod.rs` re-exports `synvoid_dns::*`). Binding facade policy: `architecture/facade_disposition_matrix.md` (Phase 03 retirement rules + per-facade canonical paths; `auth`/`cgi`/`challenge`/`filter`/`integrity`/`php`/`proxy_cache`/`upload` root paths removed).

### Composition Boundary (guard-enforced)

Request-path code consumes **narrow traits**, never concrete infrastructure:

| Layer | May Own/Import |
|-------|---------------|
| Composition roots (`src/worker/unified_server/`, `src/supervisor/`, `src/server/`) | Concrete `BlockStore`, `ThreatIntelligenceManager`, mesh/DHT/Raft handles, IPC, config |
| Request path (`src/waf/`, `src/proxy/`, `src/http/`, `crates/synvoid-waf/`, `crates/synvoid-proxy/`) | Narrow traits (`BlockListStore`, `WafProcessor`), config snapshots, request context; verification-only `synvoid-mesh-protocol` (Ed25519/threat value types, never full `synvoid-mesh`) |
| Control-plane (`crates/synvoid-mesh/`, `crates/synvoid-block-store/`) | Full infrastructure internals |

To add a capability: define a narrow trait in `crates/synvoid-waf/src/traits.rs` or `crates/synvoid-core/`, implement on concrete type in a composition root, pass `Arc<dyn Trait>` to request-path modules.

Root-module ownership policy lives in `architecture/root_module_ledger.md` — prefer dedicated `synvoid-*` crates unless the ledger says `keep_app_root`. Compatibility-facade dispositions (retain vs removed + canonical paths) live in `architecture/facade_disposition_matrix.md`.

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
| `crates/synvoid-plugin-runtime/src/unsafe_native_loader.rs` (impl) | `crates/synvoid-native-extension/src/loader.rs` (canonical; plugin-runtime path is a feature-gated facade, root `src/plugin/unsafe_native_loader.rs` is a pure shim) |
| `synvoid_plugin_runtime::unsafe_native_loader::{UnsafeNativeExtension, UnsafeNativePluginError}` (direct impl use) | `synvoid_native_extension::{UnsafeNativeExtension, UnsafeNativePluginError}` for loader internals; `PluginManager` consumes `NativeExtensionBackend`, never `Library` handles |
| `src/plugin/mod.rs` (PluginManager/Lifecycle) | `crates/synvoid-plugin-runtime/src/plugin_manager.rs` (canonical; root is facade + mesh adapter) |
| `serialize_headers` (inline) | `crates/synvoid-plugin-runtime/src/abi_frame.rs` (canonical) |
| `src/plugin/instance_pool.rs` | `crates/synvoid-plugin-runtime/src/instance_pool.rs` |
| `src/sandbox/wasm_service.rs`, `src/sandbox/yara_service.rs` (impl) | `crates/synvoid-jail-runtime/src/{wasm_service,yara_service}.rs` (canonical; root paths are pure facades; child sandbox entry in `sandbox_entry.rs`, headers in `headers.rs`, binaries `src/bin/synvoid-{wasm,yara}-jail.rs`) |
| `src/sandbox/mod.rs` (child entry) | `crates/synvoid-jail-runtime/src/sandbox_entry.rs` (canonical; root `mod.rs` retains only parent `JailClient` policy + `--wasm-jail`/`--yara-jail` forwarding shims) |
| `src/platform/sandbox.rs` (backends) | `crates/synvoid-platform/src/sandbox.rs` (canonical Landlock/Capsicum/Pledge/Job-Object/Seatbelt; root path is a pure facade) |
| `synvoid_ipc::JailSpawnSpec::current_exe` (compat) | `synvoid_ipc::{resolve_jail_binary, resolved_jail_spawn_spec, ensure_dedicated_jail_binaries_available}` (`crates/synvoid-ipc/src/jail_binary.rs`; exe-dir only, no CWD/PATH search) |
| `src/config/admin.rs` | `crates/synvoid-config/src/admin.rs` |
| `src/config/main.rs`, `src/config/site/*.rs` | `crates/synvoid-config/src/` (`main_config.rs`, `mesh.rs`, `site/` — root `src/config/` holds only `AGENTS.override.md`) |
| `src/proxy.rs` | `crates/synvoid-proxy/src/` (root `src/proxy/` files are re-export shims) |
| `src/admin/authority.rs` | `crates/synvoid-core/src/admin_mutation.rs` |
| `src/wasm_pow/` | `crates/synvoid-wasm-pow/` |
| `src/server/mod.rs` (monolithic) | `src/server/` (split: `startup_plan.rs`, `resources.rs`, `runtime_handles.rs`, `plugin_runtime.rs`, `service_assembly.rs`, `listener_tasks.rs`, `waf_handler.rs` — Phase 04: `run()` orchestrates narrow subsystem/family builders, no new crates) |
| `src/dns/*.rs` (legacy copies) | `crates/synvoid-dns/src/` (canonical) |
| `src/waf/attack_detection/*.rs` (impl) | `crates/synvoid-waf/src/attack_detection/` (root path is a re-export shim) |
| `src/admin/handlers/{logs,probes,stats,system}.rs`, `common.rs` DTOs, `auth.rs`, `rate_limit.rs` | `crates/synvoid-admin/src/` (canonical; root paths are facades + transport helpers) |
| `src/spin/*.rs`, `src/serverless/*.rs` (impl) | `crates/synvoid-plugin-runtime/src/spin/`, `crates/synvoid-serverless/src/` (root paths are re-export shims) |
| `src/proxy/*.rs`, `src/http3/*.rs` (impl) | `crates/synvoid-proxy/src/`, `crates/synvoid-http3/src/` (root paths are re-export shims) |
| `src/static_files/file_manager.rs` (impl) | `crates/synvoid-static-files/src/file_manager.rs` (canonical; root is pure facade; security via injected `FileManagerSecurityBackend`, adapter in `src/http/file_manager.rs`) |
| `crate::auth` / `synvoid::auth` (removed Phase 03) | `synvoid_auth` |
| `crate::cgi` (removed Phase 03) | `synvoid_app_handlers::cgi` |
| `crate::challenge` (removed Phase 03) | `synvoid_challenge` |
| `crate::filter` (removed Phase 03) | `synvoid_filter` |
| `crate::integrity` (removed Phase 03) | `synvoid_integrity` |
| `crate::php` (removed Phase 03) | `synvoid_app_handlers::php` |
| `crate::proxy_cache` (removed Phase 03) | `synvoid_proxy_cache` |
| `crate::upload` (removed Phase 03) | `synvoid_upload` |
| `synvoid_mesh::protocol::MeshMessageSigner` (verification-only use) | `synvoid_mesh_protocol::signer::{ProtocolSigner, verify_ed25519}` (runtime signing stays in `synvoid-mesh`) |
| `synvoid_mesh::protocol::{ThreatType, ThreatSeverity, ThreatIndicator}` (value types) | `synvoid_mesh_protocol::{ThreatType, ThreatSeverity, ThreatIndicator}` (`synvoid-mesh` re-exports for compat) |

## Security Invariants (violations break guard tests)

- **Constant-time comparison**: use `subtle::ConstantTimeEq` for secrets, keys, MACs, auth tokens (PoW solution verification included). Private key files get mode `0o600`.
- **Overlong UTF-8**: WAF normalizer decodes overlong percent-encoded sequences (`%C0%BE` → `>`); sets `OVERLONG` flag on `NormalizationFlags`; `strict_normalization` rejects them. Tests: `test_overlong_*`, `test_waf_corpus_xss_invalid_utf8`.
- **Plugin lifecycle**: own hot-reload watchers with `PluginRuntimeOwner`; never `std::mem::forget`. Reload is prepare-then-commit with generation-aware atomic swaps — a failed reload must never replace a working plugin. File-based loading reads WASM bytes once (TOCTOU closure via `PreparedPluginLoad.wasm_bytes`).
- **SignedSandboxed plugins**: empty `binary_sha256`/`manifest_sha256` rejected in production.
- **Plugin ABI memory boundary**: guest pointer ops require `guest_alloc`/`guest_free` and `checked_guest_range` (no fixed-offset fallback). Frame serialization only via `abi_frame::serialize_headers_canonical` / `build_request_frame`.
- **Native extensions**: capability-isolated in `crates/synvoid-native-extension` behind the `unsafe-native-extensions` compile feature (off by default) PLUS runtime gates (disabled by default; production load requires explicit risk acknowledgement + path allowlist). They are NOT sandboxed; `catch_unwind` catches Rust panics only, never native UB. The sandboxed runtime (`synvoid-plugin-runtime` default graph) links no `libloading`; `PluginManager` consumes the narrow `NativeExtensionBackend` trait, never `Library` handles; feature-disabled builds report `Unsupported`. Retain the `Library` handle via `Arc` (plus per-router keep-alives) for the lifetime of derived values.
- **Sandbox jail IPC** (dedicated `synvoid-wasm-jail` / `synvoid-yara-jail` binaries from `synvoid-jail-runtime`, legacy `--wasm-jail` / `--yara-jail` forwarding shims, spec `architecture/sandbox_jail_protocol.md`): parent-created stdio pipes only (no post-sandbox bind/connect); deterministic exe-dir binary resolution (no CWD/PATH/writable-dir search); versioned length-bounded typed protocol, no generic exec op; no secrets/payloads in argv/env; jail logs to stderr (stdout is framed IPC); `IsolationPolicy::Required` fails closed, never silently falls back; digest re-verified in jail (constant-time); hook-only capabilities inside the jail.

### Admin Control-Plane Authority

- Mutating endpoints return typed `AdminMutationResult` (`synvoid_core::admin_mutation`), attributed to an `AdminMutationAuthority` variant (compat paths use `CompatibilityLegacy`) — never generic `{"success": true}`. Canonical commits use `PropagationStatus::CanonicalCommitted`; quorum loss uses `PropagationStatus::QuorumUnavailable` (never success); best-effort gossip stays `QueuedBestEffort`.
- Block/unblock emits `AdminAuditEvent` via `state.audit.log_audit_event()`. Never store raw session tokens in audit logs (`AdminActor.session_id_hash` is hashed).
- Browser clients: HttpOnly session cookie + CSRF token; bearer token only for session exchange; WebSocket auth per connection (session cookie or bearer) at exactly `/api/ws/metrics` + `/api/ws/logs` (constants in `src/admin/ws/mod.rs`); no broad `/api/ws/` prefix bypass. Frontend treats 401/403 as session expiry. Logout is atomic: success/401-403 clears CSRF + unauthenticated; 5xx/network retains CSRF/auth for retry.
- Admin contract (Phase 05): every UI-consumed endpoint is checked against backend path + method in `tests/admin_route_contract.rs`; capabilities ↔ route families, discovery/OpenAPI consistency, and auth/middleware classification in `tests/admin_router_composition.rs`. Capability flags track features (`mesh_admin`→`mesh`, `dns_admin`→`dns`, `icmp_admin`→`icmp-filter`). Stale paths (`/system/master`, `/system/overseer`, `/config/overseer`, singular worker restart, `/api/logs/realtime`) must stay absent. Bounded feature matrix: minimal, `mesh`, `dns`, `icmp-filter`, `mesh,dns`.
- Admin responses carry `nosniff`, `X-Frame-Options: DENY`, CSP `frame-ancestors 'none'`, strict referrer policy.
- Mesh propagation is best-effort (`QueuedBestEffort`) — never promise delivery to all peers. Details: `architecture/admin_control_plane_authority.md`.

### Threat-Intel Enforcement

1. Raw lookups (`lookup_local_indicator*`, `lookup_threat_indicator_in_dht`) are diagnostic-only; enforcement uses `lookup_*_policy_strict`.
2. Worker admission reads BlockStore, not `ThreatIntelligenceManager` — mesh enforcement populates BlockStore; the WAF pipeline itself queries no block/threat state and mutates none.
3. New block-store writes use `block_ip_with_provenance` with `BlockProvenanceKind` (`LegacyUnknown` only for compat/tests/mocks).
4. Mesh-ID blocks are admin/control-plane only — `is_mesh_id_blocked()` must never appear in WAF/request/proxy/HTTP/3 code.
5. New consumers need `ThreatIntelConsumerKind::Enforcement` + `ThreatIntelConsumerAction::PermitAction` before mutating state.

## Serialization & Crypto Standards

- Postcard (not JSON) for distributed state; typed rkyv structs (`Archive`/`RkyvSerialize`/`RkyvDeserialize`), never `serde_json::Value`.
- Unix timestamps are u64 — use `synvoid_utils::{safe_unix_timestamp, current_timestamp}` (`crates/synvoid-utils/src/ip_utils.rs`) or `synvoid_core::time::{current_timestamp_secs, current_timestamp_millis}`; `.saturating_sub()` for durations.
- Base64: always `URL_SAFE_NO_PAD` for mesh/DHT data. Prefer pure-Rust deps over C bindings.

## Repo-Specific Pointers

- **Module overrides**: each subsystem dir has an `AGENTS.override.md` with extra rules — read before working there: `src/{waf,http,http3,http_client,proxy,config,admin,platform,plugin,worker,tunnel,app_server,theme,static_files,serverless}/AGENTS.override.md` and `crates/synvoid-{dns,honeypot,tarpit}/AGENTS.override.md`.
- **Skills**: `.opencode/skills/<name>/SKILL.md` — 37 per-subsystem guides (e.g. `dns_dnssec`, `serverless_wasm`, `ipc_hardening`, `raft_consensus`, `org_key_trust_chain`, `proxy_upstream`, `supervisor`, `worker_data_plane`, `config_system`, `admin_contract`). Load before working in an unfamiliar subsystem; cite canonical `crates/synvoid-*` paths, never root facades (see Stale Path Map); maintenance cadence in `architecture/agent_knowledge_maintenance.md`.
- **Config paths**: `--config-path` takes the DIRECTORY containing `main.toml` + `sites/`, not the TOML file. Caveat: `--configtest` ignores `--config-path` and validates `./config/` relative to CWD.
- **Key docs**: start at `architecture/overview.md` (verified module index), then use the Architecture Index below. User/operator docs live in `docs/`; `architecture/` (~135 docs) and `plans/` (completed-phase handoff history, retained as-is) are development artifacts.

## Architecture Index

Primary doc per subsystem (deep dives live beside each as `<topic>_deep_dive.md`; `_archived/` is historical):

| Subsystem | Primary doc(s) |
|-----------|----------------|
| Overview & module ownership | `overview.md`, `root_module_ledger.md`, `facade_disposition_matrix.md` (Phase 03), `request_path_capability_boundary.md` |
| Request pipeline (HTTP/1 + HTTP/3) | `http_request_pipeline.md`, `http_server.md`, `http_shared.md`, `http_ownership_convergence.md`, `http3_request_waf_boundary.md` |
| Worker data plane | `worker_data_plane_composition_root.md`, `worker_task_lifecycle.md`, `unified_server_startup.md` |
| Supervisor & process model | `supervisor.md`, `supervisor_lifecycle.md`, `process_lifecycle.md`, `cli_supervisor_command_dispatch.md` |
| WAF | `waf.md`, `waf_ownership_convergence.md`, `streaming.md`, `challenge.md`, `enforcement_decision_contract.md` |
| Proxy, upstream, cache, tunnels | `proxy.md`, `upstream.md`, `proxy_cache.md`, `tunnel_deep_dive.md` |
| Mesh, DHT, Raft, trust | `mesh.md`, `mesh_transport_lifecycle.md`, `mesh_trust_domains.md`, `block_store.md`, `distributed_state_contract.md` (binding, Phase 23) |
| Threat-intel enforcement | `threat_intel_consumer_actionability.md`, `manual_enforcement_ownership.md`, `admin_control_plane_authority.md` |
| DNS (`dns` feature) | `dns.md`, `dns_config_runtime_matrix.md`, `dns_zone_lifecycle.md`, `dns_operations_diagnostics.md` |
| Plugins, WASM, serverless | `plugin_runtime_sandbox.md`, `plugin_wasm.md`, `serverless.md`, `unsafe_native_extensions.md`, `sandbox_jail_protocol.md` |
| Admin UI/API & auth | `admin_deep_dive.md`, `auth.md`, `admin_ui.md`, `admin_root_ownership.md` (Phase 21 root-boundary matrix) |
| Config system | `config.md`, `core_types.md` |
| TLS, PQC, integrity | `tls.md`, `pqc.md`, `integrity.md` |
| Platform & sandboxing | `platform.md`, `layer_3_5_deep_dive.md`, `icmp_filter.md` |
| CI, fuzzing, releases | `ci_fuzz_failure_injection.md`, `developer_tooling.md`, `release_profile_matrix.md`, `semver_stability_policy.md` |
| Agent knowledge (skills/docs upkeep) | `agent_knowledge_maintenance.md` (audit checklist + 2026-09-11 findings) |
| Track 3 closure (Phase 24) | `track3_performance_report.md` (hot-path baselines), `crate_granularity_audit.md` (no merges; future candidates), `root_module_burndown_report.md` (zero `split_required`, re-verified) |

## Known Issues

- `wasmtime` 40.0.4 arrives transitively via `synvoid-yara` → `yara-x` (YARA execution boundary only, not the wasm sandbox; Phase 26: `synvoid-mesh` no longer links `yara-x`, `synvoid-upload` consumes it only via `synvoid-yara`); direct wasmtime is 42.0.2 via `[patch.crates-io]` (fixed for the 2026-04 advisories, but AFFECTED by RUSTSEC-2026-0269 with `wasmtime-wasi` unreachable — never call it patched for 0269; ≥46.0.3 upgrade blocked by bumpalo conflict, tracked separately from Phase 27 protocol extraction). 16 advisory ignores in `deny.toml` (mirrored in `.cargo/audit.toml`), re-audit tied to the wasmtime upgrade track. See `architecture/dependency_security_baseline_phase25.md`. YARA canonical paths: engine `crates/synvoid-yara/src/engine.rs`, jail `crates/synvoid-jail-runtime/src/yara_service.rs` (imports `synvoid-yara` directly, never `synvoid-upload`; root `src/sandbox/yara_service.rs` is a pure facade).
- macOS-only (BUG-002, `docs/testing/verification-contract.md` §14): `rkyv_derive` 0.7 (transitive via `lightningcss` → `parcel_sourcemap`, not SynVoid code) segfaults Apple clang 21 at link time — non-deterministic, retry often succeeds; Linux CI unaffected. Do not "fix" by touching the dependency chain.
