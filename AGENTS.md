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
cargo xtask verify-release         # release qualification + package inspection; NEVER publishes; fails on dirty tree
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

### Facades: implement in the crate, never the root shim

Many root `src/` paths are pure re-export facades. Rule: if a `crates/synvoid-*` crate exists for the subsystem, implement there. Binding dispositions: `architecture/facade_disposition_matrix.md`. Hottest confusions:

| Implement here (canonical) | Not here (facade/shim) |
|-------|---------|
| `crates/synvoid-plugin-runtime/src/{plugin_manager,wasm_runtime,instance_pool,abi_frame}.rs` | `src/plugin/` |
| `crates/synvoid-native-extension/src/loader.rs` (+ `NativeExtensionBackend` trait, never `Library` handles) | `crates/synvoid-plugin-runtime/src/unsafe_native_loader.rs`, `src/plugin/unsafe_native_loader.rs` |
| `crates/synvoid-jail-runtime/src/{wasm_service,yara_service,sandbox_entry}.rs`; jail binaries in `crates/synvoid-jail-runtime/src/bin/` | `src/sandbox/` (parent `JailClient` policy + `--wasm-jail`/`--yara-jail` forwarding shims only) |
| `crates/synvoid-dnssec-keystore/src/{keystore,hsm}.rs` (`SealedSigningKey::sign()` + `KeyMetadata`, no raw private bytes) | `crates/synvoid-dns/src/{dnssec_key_mgmt,hsm}.rs` |
| `crates/synvoid-mesh-protocol::signer::{ProtocolSigner, verify_ed25519}` (verification-only) | `synvoid_mesh::protocol::MeshMessageSigner` |
| `crates/synvoid-config/src/` (`main_config.rs`, `mesh.rs`, `site/`, `admin.rs`) | `src/config/` (holds only `AGENTS.override.md`) |
| `crates/synvoid-platform/src/sandbox.rs` (Landlock/Capsicum/Pledge/Job-Object/Seatbelt) | `src/platform/sandbox.rs` |
| `crates/synvoid-platform/src/{lib,fs,ipc,process,socket,socket_bind,service,unix,windows_impl,windows}.rs` (all OS primitives + backends; Phase 32 single owner) | `src/platform/` (pure alias facade; guard `platform_canonicalization_guard`) |
| `crates/synvoid-http/src/shared_handler.rs`, `crates/synvoid-proxy/src/`, `crates/synvoid-http3/src/`, `crates/synvoid-dns/src/`, `crates/synvoid-admin/src/`, `crates/synvoid-waf/src/attack_detection/` | corresponding `src/{http,proxy,http3,dns,admin,waf}` paths |
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
- **Skills**: `.opencode/skills/<name>/SKILL.md` — 42 per-subsystem guides (e.g. `dns_dnssec`, `ipc_hardening`, `raft_consensus`, `proxy_upstream`, `supervisor`, `worker_data_plane`, `config_system`, `admin_contract`, `waf_engine`, `block_store`, `tls_termination`, `plugin_runtime`, `auth`, `supply_chain`). Load before working in an unfamiliar subsystem; cite canonical `crates/synvoid-*` paths, never root facades.
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

- Phase 49–55 (performance optimization campaign, 2026-09-21) is complete; Phases 56–57 corrective closure is complete. WAF detectors evaluate inline on borrowed inputs (`check_request_sync`; no per-request `JoinSet`); upstream selection is allocation-free predicate selection; `maybe_handle_buffered_request_waf_core` is the canonical buffered-WAF entry (public wrapper kept for compat); WASM telemetry uses one consolidated per-plugin counter registry; honeypot flushes run on bounded `spawn_blocking` with stateful `watch`-based drain-capable `shutdown()` (no lost wakeup; Phase 56) and runner-owned single maintenance lifecycle (no initial overlap, joined by `run()`); Phase 57 hardens the real `PortHoneypotRunner::run()/stop()` state machine with durable `watch` shutdown (no lost early stop) and separated `Idle/Running/Stopping/Stopped` ownership — `is_running()` true only while serving, one instance is one lifecycle (post-terminal `run()` starts nothing; re-enable constructs a new runner/writer), `stop()` stays sync and single-owns no concurrent writer drain for the active lifecycle; `TeeBody` enforces `min(reserved, max_size)` with immediate exact-once governor release on abandonment (Phase 56); `BufferPool`/`PooledBuf` pin length-not-capacity `acquire(N)` semantics (`resize(0)` to empty — `clear()` only zeroizes in place), exact soft accounting, capacity re-tiering, and global-origin spillback. Campaign evidence: `architecture/performance_optimization_closeout.md` (+ `performance_optimization_baseline.md`); corrective runtime/evidence record: `architecture/performance_optimization_corrective_closeout.md` (immutable requalification incl. WAF concurrency 1/8/32/128 from `015e790d` + bench-only patch, `015e790d` provenance correction, host vs `aarch64` target separation). New benches `bench_upstream_selection`, `bench_metrics_hotpath`, `bench_buffer_pool`, `bench_honeypot_persistence` (focused local runs only, never routine CI). Known cost: isolated single 10 KiB-body WAF latency regressed (lost intra-request parallelism, requalified ~102 µs → ~165-200 µs) while all concurrent batches improved; whole-stage offload deferred pending event-loop evidence.

- Phase 48 (runtime truthfulness/security/publication corrective closeout, 2026-09-19) is complete. The Phase 41–47 implementation plans and umbrella roadmap are historical records; future DNS expansion, dependency-fork removal, public-crate promotion, or eggfetch consolidation must use a new focused plan with fresh evidence.

- Phase 47 (public-crate release readiness, 2026-09-19): only `synvoid-rate-limit` 0.1.0 is externally supported (class 3, MSRV 1.81 with packaged-tarball evidence on that toolchain, `ip_to_slot` documented as implementation detail not a stable hash). `synvoid-mesh-protocol` (no wire-versioning/`non_exhaustive` policy), `synvoid-proxy-cache` (reverse-proxy object cache, NOT RFC 9111 — no ETag/304/Authorization subset defined), `synvoid-dnssec-keystore` (no public threat model/PKCS#11 CI; `rsa` carries RUSTSEC-2023-0071 unpatched), `synvoid-platform` (needs MSRV/semver/examples), `synvoid-yara` (temporary compat fork), `synvoid-http-client` (internal pending a fresh current-line eggfetch parity review; the Phase 47 0.1.4-era matrix is dated history, not current evidence — see `architecture/public_crate_release_readiness_phase47.md` + `plans/eggfetch_current_line_parity_review.md`), `synvoid-utils`/`synvoid-core` (permanently internal) all stay class 1/2 with no support promise; guard `public_crate_release_policy` pins the boundary. Binding docs: `architecture/public_crate_release_policy.md`, `architecture/public_crate_release_readiness_phase47.md`. `docs/releasing.md` §1a records the externally supported order (rate-limit only); root README has a Reusable libraries section.

- Phase 46 (platform sandbox truthfulness + macOS closure, 2026-09-19): SBPL literals escaped/canonicalized (`escape_sbpl_string_literal`, controls/non-UTF-8 rejected; `)` stays inside quotes); Basic is allow-default only (old contradictory allow+deny defaults removed); Strict is deny-default + `(allow process*)` + `(allow signal)` + explicit `(deny network*)` with no job-creation allow (bare `(allow process)` was an unbound variable caught natively); Seatbelt FFI uses a real error buffer freed via `sandbox_free_error`; capabilities are level-dependent and truthful (`process_limits` = numeric bounds only → false for Seatbelt/Capsicum/Pledge; Windows path flags false → Strict fails closed; Landlock probes the syscall ABI, Capsicum probes `cap_getmode` presence); macOS is experimental deprecated `sandbox_init` with native child-process tests (`sandbox_macos_enforcement`), Linux is the production strict target. Binding docs: `docs/SANDBOXING.md`, `architecture/platform.md` §2.6/§6.4. `macos-sandbox` reclassified Experimental (SECURITY/FEATURE_STATUS/release matrix).

- Phase 45 (DNS runtime contract + protocol completeness): `DnsConfig::validate()` is fail-closed for deferred DNS features — RPZ, prefetch, custom trust anchors, anycast, zone transfers (`allow_transfer` non-empty + knob deviations), dynamic UPDATE, NOTIFY, EDNS padding, QNAME privacy, firewall `default_action`/`max_rules`/`rebinding_protection` (while enabled), recursive `include_scope_in_response`, and invalid/empty encrypted-transport binds are rejected with typed `Unsupported { path }` errors; admin `PUT /config/dns` returns 400 on the same. Authoritative TCP and DoT serve persistent sequential connections (RFC 7766 reuse, no pipelining; 1000-query bound, permit held, graceful drain); recursive TCP stays single-query. `dns.doq.bind_address` is honored (IPv6-safe) — the old "hardcoded 0.0.0.0" matrix entry was stale. `examples/dns/transfer_primary.toml` is a deferred design reference (parses, fails validation). Binding docs: `architecture/dns.md` (Phase 45 section), `architecture/dns_config_runtime_matrix.md` (Phase 45 mapping), `architecture/dns_production_profiles.md` (transfer-primary demoted).

- Phase 44 (PQC dependency truth + KyberSlash closure, 2026-09-19): `synvoid-wasm-pow` migrated from draft-Kyber `pqc_kyber_edit` 0.7.2 to maintained final FIPS 203 ML-KEM-768 (`ml-kem` 0.3, RustCrypto; pure-Rust `no_std`+`alloc`, `zeroize` on drop, `rand_core` 0.10 adapter over `getrandom` 0.2/js). Draft and final encodings share sizes (1184/1088) but are NOT byte-compatible (proven by cross-impl mismatch); the old client silently fell back to X25519-only against the server's final ML-KEM (`aws-lc-rs` via `pqc`). Secrets are ephemeral per-session only (64-byte seed client-local, never wired/persisted) so no migration was needed. Evidence: NIST FIPS 203 KAT + round-trip/implicit-rejection/size tests in `crates/synvoid-wasm-pow/src/pqc.rs`, `cargo check --target wasm32-unknown-unknown`, `wasm-pack build` (278 KB). Guard: `pqc_backend_is_maintained_ml_kem`. Binding docs: `architecture/wasm_pow.md` (§4-6).
- Phase 43 (auth CPU + persistence hardening): `synvoid-auth::PasswordCrypto` bounds bcrypt (4 permits / 2s acquire, `spawn_blocking`, never with the store lock held; `AuthBackendBusy` fails closed); `BasicAuthManager` is async-only (`authenticate_request_async`, `BackendBusy` → 503); admin verification is single-bounded-bcrypt (`verify_admin_token_async` / `verify_dummy_admin_token_async` + 200ms pad, callers in `src/admin/` + `src/http/` are async); auth store is atomic temp+fsync+rename (`0600`/`0700` from creation, corrupt/overly-permissive → `try_new` error, production uses `try_new` via `assemble_auth_manager`); login audit capped at `MAX_LOGIN_LOGS = 1000` on insertion with expired-session pruning before snapshot. Binding details: `architecture/auth.md` (+ `auth_deep_dive.md`), skill `auth`.
- Phase 42 (shared-memory unsafe-boundary hardening, 2026-09-18): `synvoid-upstream::shared_state` is a checked unsafe boundary — `ConnectionTableLayout`/`RateLimitTableLayout` own all size/offset math (checked arithmetic, bounds, 512 MiB ceiling, release-mode alignment proofs); v1 magic+version headers with supervisor-owned truncate-before-spawn creation and validating `open_existing` (no worker opens these files today — unopened workers use process-local counters); files are 0600 under a 0700 runtime dir with symlink/non-regular rejection (`O_NOFOLLOW` on Unix); `SharedRateLimitTable::get_mmap()` is removed in favor of typed counter slices consumed via `SlottedIpRateLimiter::from_shared_table`. Binding contract: `architecture/shared_memory_atomic_contract.md`. Layout changed from the Phase 41 16-byte header to a 32-byte (connection) / 16-byte (rate-limit) versioned header — files are recreated per supervisor generation, never reused across binaries.
- Phase 41 (fail-closed config + process bounds, 2026-09-18): reduced-feature binaries reject capability-bearing sections (`[dns]`, `[mesh]`, `[tunnel.mesh]`, `[icmp_filter]`, even inert `enabled = false`) via a raw-TOML preflight in `MainConfig::from_toml_str()` — previously silently ignored. `MainConfig::validate()` now enforces process/supervisor bounds (legacy `1..=1024`, unified `1..=256` independent pools, warm/pre-spawn `<= max_workers`, timeouts `1..=86400`s, `control_api_addr` as `SocketAddr`); runtime derivations use `checked_add`/`checked_mul` (`worker_port_for_id`, shm constructors, supervisor `+10`). Mesh `restart_enabled = true` + non-default restart tuning rejected at config validation, before task construction. Binding contract: `architecture/config_feature_contract.md`; guard: `tests/config_capability_preflight_guard.rs`. Migration: rebuild with the feature or remove the section; admin process mutation returns 400 on invalid settings.
- Phase 40 (YARA-X 1.20 upgrade, 2026-09-18): `synvoid-yara` → `yara-x` 1.20.0 via the temporary manifest-only compat fork `third-party/yara-x-compat` (exact upstream 1.20.0 sources + the unreleased upstream PR #769 two-line delta: wasmtime 45.0.3 → 47.0.4; root `[patch.crates-io]` path override shared with the minify fork, no git source, `yara_fork_is_temporary_guard`-enforced). Transitive wasmtime is 47.0.4 (patched for RUSTSEC-2026-0222/-0269 and the 2026-04 batch); direct wasmtime stays 36.0.15 LTS from crates.io (supported through 2027-08-20, PATCHED for 0269); wasmtime 40.0.4 is gone with its 14 advisory ignores. `YARA_ENGINE_VERSION` is `yara-x/1.20` (upstream-removed `linkme` feature dropped); 1.15 artifacts reject deterministically. 2 advisory ignores remain in `deny.toml` (mirrored in `.cargo/audit.toml`): RUSTSEC-2023-0071 (`rsa` via yara-x `crypto`, no upstream fix) and RUSTSEC-2026-0235 (`rkyv` 0.7 via minify chain), expiring against current UTC date. Phase 39's minify fork is retained (upstream still 0.18.1). See `architecture/dependency_security_baseline_phase25.md` (§11 for Phase 40). Never describe a capability-unreachable advisory as patched.
- Phase 36 (YARA deserialization exposure closure, 2026-09-17): source text is now the only executable YARA input — `reload_with_compiled_rules`, `CompiledArtifact::{deserialize_verified,from_bytes_with_binding}`, mesh `local_compiled_rules`/`apply_compiled_rules`/`get_current_compiled_rules`, and `YaraRuleSourceType::CompiledBundle` are removed; upload/mesh/jail recompile approved source locally. GHSA-2jx3-ff3v-j7jj (yara-x <=1.18) has no remote path to any deserializer after this closure, and is additionally version-remediated by the Phase 40 engine upgrade to yara-x 1.20. Never add an advisory ignore for the GHSA to pretend an affected line is fine; never call an affected line "patched".
- macOS-only: `rkyv_derive` 0.7 (transitive via `lightningcss`, not SynVoid code) segfaults Apple clang 21 at link time — non-deterministic, retry often succeeds; Linux CI unaffected. Do not "fix" the dependency chain.
