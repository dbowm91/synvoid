# AGENTS.md

SynVoid is a high-performance WAF & reverse proxy in Rust with mesh networking and a multi-process architecture (Supervisor + UnifiedServerWorker data plane + CPU offload). 50-member Cargo workspace: root app, 42 `synvoid-*` crates under `crates/`, plus `pqc`, `admin-ui` (Yew/WASM via Trunk), `examples/*`, `fuzz`, `tools/{xtask,synvoid-repo-guards}`. Linux is the primary deployment target.

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
| `synvoid_ipc::{resolve_jail_binary, resolved_jail_spawn_spec}` (exe-dir only, no CWD/PATH search) | `synvoid_ipc::JailSpawnSpec::current_exe` (compat) |
| `synvoid_core::admin_mutation` (`AdminMutationResult`) | `src/admin/authority.rs` |
| Removed root paths (use the crate): `crate::{auth,cgi,challenge,filter,integrity,php,proxy_cache,upload}` | — |

## Security Invariants (violations break guard tests)

- **Constant-time comparison**: `subtle::ConstantTimeEq` for secrets, keys, MACs, auth tokens (PoW verification included). DNSSEC private key files mode `0o600` (dirs `0700`, atomic write/rename, overly-permissive files refused on load).
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
  - Composition/facades: `architecture/{root_module_ledger,facade_disposition_matrix,request_path_capability_boundary,root_dependency_ownership}.md`
  - Admin authority: `architecture/{admin_control_plane_authority,admin_root_ownership,admin_contract_phase05_closeout}.md`
  - Threat-intel enforcement: `architecture/{threat_intel_consumer_actionability,manual_enforcement_ownership,enforcement_decision_contract}.md`
  - Mesh/distributed: `architecture/distributed_state_contract.md` (binding) + `mesh_{trust_domains,transport_lifecycle}.md`
  - Supply chain: `architecture/dependency_security_baseline_phase25.md` (re-audit 2026-10-01)
  - Jail IPC: `architecture/sandbox_jail_protocol.md`; DNSSEC custody: `architecture/dnssec_keystore.md`
  - Knowledge maintenance: `architecture/agent_knowledge_maintenance.md` (last audit record + recurring checklist for future audits)

## Known Issues

- `wasmtime` 40.0.4 arrives transitively via `synvoid-yara` → `yara-x` (YARA boundary only, not the WASM sandbox); direct wasmtime is 42.0.2 via `[patch.crates-io]`. 42.0.2 is AFFECTED by RUSTSEC-2026-0269 (`wasmtime-wasi` unreachable — capability absence, not a patch); ≥46.0.3 upgrade blocked by a bumpalo conflict. 16 advisory ignores in `deny.toml` (mirrored in `.cargo/audit.toml`), expiring against current UTC date. See `architecture/dependency_security_baseline_phase25.md`. Never call 42.0.2 "patched" for 0269.
- macOS-only: `rkyv_derive` 0.7 (transitive via `lightningcss`, not SynVoid code) segfaults Apple clang 21 at link time — non-deterministic, retry often succeeds; Linux CI unaffected. Do not "fix" the dependency chain.
