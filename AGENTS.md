# AGENTS.md

SynVoid is a high-performance WAF & reverse proxy in Rust with mesh networking and a multi-process architecture (Supervisor + UnifiedServerWorker data plane + CPU offload). 51-member Cargo workspace: root app, 43 `synvoid-*` crates under `crates/`, plus `pqc`, `admin-ui` (Yew/WASM via Trunk), `examples/*`, `fuzz`, `tools/{xtask,synvoid-repo-guards}`. Linux is the primary deployment target.

## Build & Setup

```bash
cargo build --release   # default features: socket-handoff, mesh, dns, erased_pool, swagger-ui
```

- **protoc is required**: the default `mesh` feature triggers protobuf codegen in `build.rs` (`tonic-prost-build`). Install `protobuf-compiler` (CI does) or builds fail confusingly.
- All feature profiles must compile: `cargo check --no-default-features [--features mesh | dns | icmp-filter | mesh,dns]` (bounded matrix; full powerset intentionally not tested).
- `--no-default-features` is honestly minimal: the root `[dev-dependencies]` self-edge keeps `default-features = false`, so mesh/dns absence branches execute under `cargo test --no-default-features`. `tests/mesh_startup_rollback` needs `--features mesh` (`required-features`).

## Verification

**Authority**: `docs/testing/verification-contract.md` (frozen). The single CI workflow (`.github/workflows/ci.yml`) runs `cargo xtask verify` plus a blocking `dependency-security` job (`cargo deny check` + `cargo audit`, also on a daily schedule):

```bash
cargo xtask verify   # fmt → clippy --profile ci --all-targets -D warnings → deny → core compile check → repo-guards → security regression → root guard suite → core admin tests → admin contract (mesh,dns,icmp-filter) → failure injection
```

```bash
cargo xtask verify-full            # broader local: feature-profile compiles + one full workspace nextest run + doctests
cargo xtask verify-release         # release qualification + package inspection; NEVER publishes; fails on dirty tree; checks jail binaries ship
cargo xtask test package <name>    # e.g. cargo xtask test package synvoid-dns
cargo xtask test guards            # all architectural guard tests
```

Focused runs:

```bash
cargo test --test <integration_name>             # root integration test
cargo nextest run --workspace --cargo-profile ci --profile ci --exclude synvoid-fuzz   # full suite
cargo test --workspace --doc --profile ci        # doctests (nextest doesn't run these)
```

Testing quirks:

- Use `--profile ci` for routine testing (matches CI); `--release` only for release qualification. nextest is pinned (0.9.140, see `docs/testing/nextest-policy.md`).
- `security_regression` must run single-threaded: `cargo test --test security_regression --profile ci -- --test-threads=1`.
- Root guard suites run with `--features mesh`; `composition_root_behavioral` is `#![cfg(feature = "mesh")]` (empty without it).
- Extended-timeout suites are outside routine verification; run directly: `cargo test -p synvoid-dns --test dns_stress --profile ci`, `cargo test --test worker_supervision_control_flow --profile ci -- --test-threads=1` (100s sleep body), `cargo test --test fault_injection_test --profile ci -- --ignored` (`#[ignore]`, needs built binary + ~20s).
- Fuzz smoke tests need nightly + cargo-fuzz: `cargo +nightly fuzz run <target> -- -runs=1000` (21 targets in `fuzz/`). Publication is manual via `cargo publish` only — see `docs/releasing.md`.

## Test Placement Rules

- Every root `tests/*.rs` file MUST have an entry in `tests/OWNERSHIP.toml` or `root_test_ownership_guard` fails; `class = "domain"` entries are rejected — single-crate tests belong in the owning crate's `tests/`. Guide: `docs/testing/root-test-ownership.md`.
- Run the admin contract explicitly when touching frontend/backend API alignment (`admin_route_contract`, `admin_router_composition`, `admin_smoke_flow` with `--features mesh,dns,icmp-filter`); DNS full/interop via `cargo test -p synvoid-dns --profile ci` plus `./scripts/dns/conformance.sh`.

## Architecture Facts

- **Entry point**: `src/main.rs` → `src/commands/{plan,execute,runtime_launch}.rs` (plan → execute → launch separation).
- **Supervisor**: `src/supervisor/` — lifecycle, IPC, control-plane. **Data plane**: `src/worker/unified_server/` — HTTP + WAF + proxy in ONE Tokio event loop; CPU offload in `src/worker/cpu_task/`.
- **Process model**: Supervisor (1) → N `UnifiedServerWorker` processes (`spawn_unified_server_workers` in `src/supervisor/process.rs`; shipped `config/main.toml` sets 4, code default 1) + CpuWorker offload. Workers are NOT process-per-tenant. Gotcha: the legacy `--worker` flag has NO dispatch branch in `src/commands/plan.rs` and falls through to Supervisor; HTTP serving uses `--unified-server-worker` / `--cpu-worker`.
- **Mesh**: `crates/synvoid-mesh/src/mesh/` — DHT, transport, Raft, peer auth. Verification-only wire/identity vocabulary lives in `crates/synvoid-mesh-protocol/` (`ProtocolSigner` Ed25519 verification, `HybridSignature`, replay protection, threat taxonomy; `synvoid-mesh` re-exports compat paths). Binding contract: `architecture/distributed_state_contract.md`.

### Composition Boundary (guard-enforced)

Request-path code consumes **narrow traits**, never concrete infrastructure:

| Layer | May Own/Import |
|-------|---------------|
| Composition roots (`src/worker/unified_server/`, `src/supervisor/`, `src/server/`) | Concrete `BlockStore`, `ThreatIntelligenceManager`, mesh/DHT/Raft handles, IPC, config |
| Request path (`src/waf/`, `src/proxy/`, `src/http/`, `crates/synvoid-waf/`, `crates/synvoid-proxy/`) | Narrow traits (`BlockListStore`, `WafProcessor`), config snapshots, request context; verification-only `synvoid-mesh-protocol`, never full `synvoid-mesh` |
| Control-plane (`crates/synvoid-mesh/`, `crates/synvoid-block-store/`) | Full infrastructure internals |

To add a capability: define a narrow trait in `crates/synvoid-waf/src/traits.rs` or `crates/synvoid-core/`, implement on the concrete type in a composition root, pass `Arc<dyn Trait>` to request-path modules. New crates only if `architecture/root_module_ledger.md` says so (default: dedicated `synvoid-*` crate).

### Facades: check `architecture/root_module_ledger.md` before choosing a home

Root `src/` paths are NOT all shims. `keep_app_root` modules (`admin`, `http`, `waf`, `plugin`, `sandbox`, `server`, `supervisor`, `worker`, `tls`, `tcp`, `udp`) legitimately own composition/adapters in root; reusable domain logic (detectors, parsers, handlers, DTOs) goes in the crate. Pure facades must not gain implementation. Binding dispositions: `architecture/facade_disposition_matrix.md`. Hottest confusions:

| Implement here (canonical) | Not here (facade/shim) |
|-------|---------|
| `crates/synvoid-plugin-runtime/src/{plugin_manager,wasm_runtime,instance_pool,abi_frame}.rs` | `src/plugin/` (root keeps composition + mesh-aware byte resolution only) |
| `crates/synvoid-native-extension/src/loader.rs` (+ `NativeExtensionBackend` trait, never `Library` handles) | `crates/synvoid-plugin-runtime/src/unsafe_native_loader.rs`, `src/plugin/unsafe_native_loader.rs` |
| `crates/synvoid-jail-runtime/src/{wasm_service,yara_service,sandbox_entry}.rs`; jail binaries in `crates/synvoid-jail-runtime/src/bin/` | `src/sandbox/` (parent `JailClient` policy + `--wasm-jail`/`--yara-jail` forwarding shims only) |
| `crates/synvoid-dnssec-keystore/src/{keystore,hsm}.rs` (`SealedSigningKey::sign()` + `KeyMetadata`, no raw private bytes) | `crates/synvoid-dns/src/{dnssec_key_mgmt,hsm}.rs` |
| `crates/synvoid-mesh-protocol::signer::{ProtocolSigner, verify_ed25519}` (verification-only) | `synvoid_mesh::protocol::MeshMessageSigner` |
| `crates/synvoid-config/src/` (`main_config.rs`, `mesh.rs`, `site/`, `admin.rs`) | `src/config/` (holds only `AGENTS.override.md` + compat shims) |
| `crates/synvoid-platform/src/sandbox.rs` (Landlock/Capsicum/Pledge/Job-Object/Seatbelt) | `src/platform/sandbox.rs` |
| `crates/synvoid-platform/src/{lib,fs,ipc,process,socket,socket_bind,service,unix,windows_impl,windows}.rs` (all OS primitives + backends; Phase 32 single owner) | `src/platform/` (pure alias facade; guard `platform_canonicalization_guard`) |
| Reusable logic in `crates/synvoid-{http,proxy,http3,dns,admin,waf}/` (e.g. `synvoid-http/src/shared_handler.rs`, `synvoid-waf/src/attack_detection/`) | `src/{http,proxy,http3,dns,admin,waf}` facades — but root composition/adapters there are legitimate (`WafCore`/`AppWaf`, HTTP dispatch adapters, admin router/middleware wiring stay root-owned per ledger) |
| `crates/synvoid-rate-limit/src/{window,contracts,slot}.rs` (`AtomicSlidingWindow`, neutral `RateLimitResult`/`IpRateLimiter`/`KeyedRateLimiter`/`RateLimitStats`, `ip_to_slot`) | `src/utils/ratelimit/` (compat re-export only), `src/waf/ratelimit/core.rs` window impl (moved to crate), `crates/synvoid-mesh/src/stubs.rs` WAF rate-limit stub (removed) |
| `crates/synvoid-upstream/src/tls_adapter.rs` (`upstream_tls_from_site_config` site→TLS) + `crates/synvoid-upstream/src/shared_state.rs` (checked layouts, versioned headers, typed counter slices; Phase 42) + `crates/synvoid-http/src/streaming_waf_body.rs` (`StreamingWafBody`; scanner from `synvoid_core::streaming_waf` via `synvoid_http::shared_handler`) (Phase 34) | `crates/synvoid-http-client/` (generic transport only: no `synvoid-config`/`synvoid-core`/`metrics` edges), `src/http_client/streaming_waf_body.rs` (shim now points at `synvoid-http`) |
| `synvoid_ipc::{resolve_jail_binary, resolved_jail_spawn_spec}` (exe-dir only, no CWD/PATH search) | `synvoid_ipc::JailSpawnSpec::current_exe` (compat) |
| `synvoid_core::admin_mutation` (`AdminMutationResult`) | `src/admin/authority.rs` |
| Removed root paths (use the crate): `crate::{auth,cgi,challenge,filter,integrity,php,proxy_cache,upload}` | — |

## Security Invariants (violations break guard tests)

- **Constant-time comparison**: `subtle::ConstantTimeEq` for secrets, keys, MACs, auth tokens (PoW verification included). DNSSEC private key files mode `0o600` (dirs `0700`, atomic write/rename, overly-permissive files refused on load).
- **Auth CPU isolation + persistence (Phase 43)**: no bcrypt on Tokio core threads — `synvoid-auth::PasswordCrypto` (bounded semaphore + `spawn_blocking`, overload `Busy` fails closed) and `synvoid-admin::{verify_admin_token_async, verify_dummy_admin_token_async}` (single verify + min-delay pad, never double bcrypt); no `RwLock<AuthStore>` held across bcrypt (snapshot → release → verify → reacquire + generation recheck). Auth store is atomic temp+fsync+rename with `0600`/`0700` from creation; corrupt/overly-permissive stores fail closed via `AuthManager::try_new` (never silent empty DB); login audit bounded at insertion (`MAX_LOGIN_LOGS = 1000`); Basic Auth is async-only with `BackendBusy` → 503 distinct from 401.
- **DNSSEC key custody** (guard `dnssec_keystore_boundary`): private-key/HSM authority lives in `crates/synvoid-dnssec-keystore/` only. Query/transport/resolver code must never touch `private_key` tokens or `cryptoki`; `cryptoki` is opt-in (`synvoid-dns/hsm`, root `dns-hsm`), off by default with no silent software fallback; mesh anchors are `KeyMetadata`-only.
- **Overlong UTF-8**: WAF normalizer decodes overlong percent-encoded sequences, sets `OVERLONG` on `NormalizationFlags`; `strict_normalization` rejects them.
- **Plugin lifecycle**: own hot-reload watchers with `PluginRuntimeOwner`, never `std::mem::forget`. Reload is prepare-then-commit — a failed reload must never replace a working plugin. Guest pointer ops require `guest_alloc`/`guest_free` + `checked_guest_range`; frame serialization only via `abi_frame::serialize_headers_canonical` / `build_request_frame`. Empty `binary_sha256`/`manifest_sha256` rejected in production.
- **Native extensions**: opt-in compile feature `unsafe-native-extensions` (off by default) PLUS runtime gates (disabled by default; production needs explicit risk acknowledgement + path allowlist). NOT sandboxed; `catch_unwind` catches Rust panics only. Retain the `Library` handle via `Arc` for the lifetime of derived values.
- **Sandbox jail IPC** (spec `architecture/sandbox_jail_protocol.md`): parent-created stdio pipes only; versioned length-bounded typed protocol, no generic exec op; no secrets in argv/env; jail logs to stderr (stdout is framed IPC); `IsolationPolicy::Required` fails closed; digest re-verified in jail (constant-time).

### Admin Control-Plane Authority

- Mutating endpoints return typed `AdminMutationResult`, never generic `{"success": true}`. Quorum loss is `PropagationStatus::QuorumUnavailable` (never success); mesh propagation is best-effort `QueuedBestEffort`. Block/unblock emits `AdminAuditEvent`; never store raw session tokens (`AdminActor.session_id_hash` is hashed).
- Browser clients: HttpOnly session cookie + CSRF token; bearer token only for session exchange; WebSocket auth per connection at exactly `/api/ws/metrics` + `/api/ws/logs` (constants in `src/admin/ws/mod.rs`). Frontend treats 401/403 as session expiry. Stale paths must stay absent: `/system/master`, `/system/overseer`, `/config/overseer`, singular worker restart, `/api/logs/realtime`.
- Details: `architecture/admin_control_plane_authority.md`.

### Threat-Intel Enforcement

1. Raw lookups (`lookup_local_indicator*`, `lookup_threat_indicator_in_dht`) are diagnostic-only; enforcement uses `lookup_*_policy_strict`.
2. Worker admission reads BlockStore, not `ThreatIntelligenceManager`; the WAF pipeline itself queries/mutates no block/threat state.
3. New block-store writes use `block_ip_with_provenance` with `BlockProvenanceKind` (`LegacyUnknown` only for compat/tests/mocks).
4. `is_mesh_id_blocked()` is admin/control-plane only — never in WAF/request/proxy/HTTP/3 code.
5. New consumers need `ThreatIntelConsumerKind::Enforcement` + `ThreatIntelConsumerAction::PermitAction` before mutating state.

## Serialization & Crypto Standards

- Postcard (not JSON) for distributed state; typed rkyv structs, never `serde_json::Value`.
- Unix timestamps are u64 — use `synvoid_utils::{safe_unix_timestamp, current_timestamp}` or `synvoid_core::time::{current_timestamp_secs, current_timestamp_millis}`; `.saturating_sub()` for durations.
- Base64: always `URL_SAFE_NO_PAD` for mesh/DHT data. Prefer pure-Rust deps over C bindings.

## Repo-Specific Pointers

- **Module overrides**: read `src/*/AGENTS.override.md` before working in a subsystem (`waf`, `http`, `http3`, `http_client`, `proxy`, `config`, `admin`, `platform`, `plugin`, `worker`, `tunnel`, `app_server`, `theme`, `static_files`, `serverless`) plus `crates/synvoid-{dns,honeypot,tarpit}/AGENTS.override.md`.
- **Skills**: `.opencode/skills/<name>/SKILL.md` — 42 per-subsystem guides (e.g. `dns_dnssec`, `ipc_hardening`, `raft_consensus`, `proxy_upstream`, `supervisor`, `worker_data_plane`, `config_system`, `admin_contract`, `waf_engine`, `block_store`, `tls_termination`, `plugin_runtime`, `auth`, `supply_chain`). Load before working in an unfamiliar subsystem; cite canonical `crates/synvoid-*` paths for domain logic (root `keep_app_root` composition paths stay valid for wiring).
- **Config paths**: `--config-path` takes the DIRECTORY containing `main.toml` + `sites/`, not the TOML file. Caveat: `--configtest` ignores `--config-path` and validates `./config/` relative to CWD.
- **Docs**: start at `architecture/overview.md` (verified module index + Documentation Map). `architecture/` holds binding design docs; `docs/` holds operator docs; `plans/` is retained phase-handoff history.
- **Architecture index** (binding docs by topic; historical closure reports are labeled as such in the overview Documentation Map and stay in place):
  - Composition/facades: `architecture/{root_module_ledger,facade_disposition_matrix,request_path_capability_boundary,root_dependency_ownership,crate_boundary_reuse_closeout}.md`
  - Admin authority: `architecture/{admin_control_plane_authority,admin_root_ownership,admin_contract_phase05_closeout}.md`
  - Threat-intel enforcement: `architecture/{threat_intel_consumer_actionability,manual_enforcement_ownership,enforcement_decision_contract}.md`
  - Mesh/distributed: `architecture/distributed_state_contract.md` (binding) + `mesh_{trust_domains,transport_lifecycle}.md`
  - Shared memory: `architecture/shared_memory_atomic_contract.md` (binding Phase 42 unsafe boundary: checked layouts, versioned headers, file hardening, typed counter slices)
  - Public libraries (Phase 47): `architecture/public_crate_release_policy.md` (binding semver/MSRV/support bar) + `architecture/public_crate_release_readiness_phase47.md` (only `synvoid-rate-limit` 0.1.0 promoted to class 3, MSRV 1.81; mesh-protocol/proxy-cache/keystore/platform/yara/http-client/utils/core stay internal with reasons) + `architecture/runtime_truthfulness_security_publication_closeout.md` (Phase 41–48 campaign closeout)
  - Supply chain: `architecture/dependency_security_baseline_phase25.md` (re-audit 2026-10-01)
  - Auth CPU + persistence (Phase 43): `architecture/auth.md` (+ `auth_deep_dive.md`)
  - Jail IPC: `architecture/sandbox_jail_protocol.md`; DNSSEC custody: `architecture/dnssec_keystore.md`
  - Sandbox truthfulness (Phase 46): `docs/SANDBOXING.md` (binding support tiers) + `architecture/platform.md` §2.6/§6; Linux Landlock is the production strict-isolation target, macOS Seatbelt is experimental deprecated `sandbox_init` (not App Sandbox), Windows is process-limits-only, Capsicum/Pledge have no numeric process limits; SBPL paths escaped/canonicalized, Strict fails closed
  - Knowledge maintenance: `architecture/agent_knowledge_maintenance.md` (last audit record + recurring checklist for future audits)

## Known Issues

- Perf campaign (Phases 49–57, closed 2026-09-21) set non-default semantics — do not "simplify" these: WAF detectors run inline on borrowed inputs (`check_request_sync`, no per-request `JoinSet`); `BufferPool::acquire(N)` is length-not-capacity, empty with `resize(0)` (`clear()` only zeroizes in place); `TeeBody` releases the governor exact-once on abandonment; one honeypot-runner instance is one lifecycle. Full record: `architecture/performance_optimization_closeout.md` + `performance_optimization_corrective_closeout.md`. New benches (`bench_upstream_selection`, `bench_metrics_hotpath`, `bench_buffer_pool`, `bench_honeypot_persistence`) are focused local runs only, never routine CI.
- YARA input is source-text-only (Phase 36): no compiled-artifact deserializers anywhere; mesh/jail/upload recompile approved source locally. Never add an advisory ignore for GHSA-2jx3-ff3v-j7jj; never call a capability-unreachable advisory "patched". `deny.toml` carries exactly 2 ignores (`RUSTSEC-2023-0071` rsa-via-yara-x, `RUSTSEC-2026-0235` rkyv-0.7-via-minify; re-audit 2026-10-01); `yara-x`/`minify-html` resolve via temporary manifest-only forks in `third-party/` (`[patch.crates-io]` must hold only those two entries).
- Fail-closed config (Phase 41): reduced-feature binaries reject capability-bearing sections (`[dns]`, `[mesh]`, `[tunnel.mesh]`, `[icmp_filter]`, even inert `enabled = false`); `validate()` bounds process counts and timeouts. Deferred DNS features (RPZ, prefetch, transfers, UPDATE/NOTIFY, EDNS padding, QNAME privacy, …) fail `DnsConfig::validate()` with typed `Unsupported` (Phase 45).
- macOS-only: `rkyv_derive` 0.7 (transitive via `lightningcss`, not SynVoid code) segfaults Apple clang 21 at link time — non-deterministic, retry often succeeds; Linux CI unaffected. Do not "fix" the dependency chain.
