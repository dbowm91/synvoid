# AGENTS.md

SynVoid is a high-performance WAF & reverse proxy in Rust with a mesh networking layer, multi-process architecture (Supervisor + UnifiedServerWorker + CPU offload), and 43 workspace members (34 dedicated `synvoid-*` library crates plus root, pqc, admin-ui, examples, and fuzz).

## Quick Commands

```bash
# Build (default features: mesh, dns, erased_pool, swagger-ui)
cargo build --release

# Format + lint (CI order: fmt → clippy)
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings

# Quick compile check
cargo test --lib --no-run

# Run a single test by name
cargo test --lib <test_name>
cargo test --test <integration_test_name>

# Full test suite (CI uses --release --no-fail-fast)
cargo test --release --no-fail-fast

# Security regression tests (must run single-threaded)
cargo test --test security_regression -- --test-threads=1

# Mesh/DNS features required for many tests
cargo test --test mesh_forced_cleanup --features mesh,dns
cargo test --test mesh_task_ownership_guard --features mesh,dns
cargo test --test worker_supervision_control_flow --features mesh,dns
cargo test --test composition_root_behavioral --features mesh,dns
cargo test --test mesh_http_framing --features mesh,dns

# Supervisor lifecycle (Phase 3)
cargo test --test supervisor_task_ownership_guard
cargo test -p synvoid supervisor::task_registry
cargo test -p synvoid supervisor::shutdown
```

## Feature Profiles

Default features: `socket-handoff`, `mesh`, `dns`, `erased_pool`, `swagger-ui`. Always verify all profiles compile:

```bash
cargo check --no-default-features          # Core
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns  # Full
```

## Guardrail Tests

These enforce architectural invariants. Run them after touching relevant areas:

```bash
cargo test --test data_plane_composition_boundary_guard  # Request-path vs composition-root
cargo test --test root_facade_boundary_guard             # Domain crates can't import root
cargo test --test root_module_ledger_guard               # Root modules must be in ledger
cargo test --test root_dependency_ownership_guard         # Root deps must have ownership entries
cargo test --test mesh_id_boundary_guard                 # Mesh-ID blocks: admin only, not WAF
cargo test --test threat_intel_boundary_guard            # Threat-intel consumer enforcement
cargo test --test threat_intel_consumer_actionability_guard
cargo test --test http3_waf_boundary_guard               # HTTP/3 WAF boundary
cargo test --test http_request_pipeline_boundary_guard   # HTTP pipeline stages
cargo test --test background_task_ownership_guard
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns
cargo test --test cli_command_dispatch_guard
cargo test --test manual_enforcement_provenance_guard
cargo test --test unified_server_lifecycle_ownership_guard  # 5 tests: mem::forget, reason comments, handles integrated, spawns registered, plugin owner lifetime
cargo test --test request_path_capability_boundary_guard  # Request-path capability boundary
cargo test --test admin_mutation_response_guard  # Mutating admin endpoints must return AdminMutationResult
cargo test --test admin_mutation_blocklist       # Blocklist mutation behavior tests
cargo test --test admin_auth_boundary            # Auth authority boundary tests
cargo test --test mesh_admin_edge_cases          # Mesh admin edge case tests
cargo test --test plugin_capability_boundary_guard  # Plugin sandbox capability gates, manifest parsing, mem::forget
cargo test --test plugin_failure_does_not_poison_manager  # Plugin failure isolation: one plugin's failure doesn't poison others
cargo test --test plugin_signature_policy_guard  # Plugin signature policy enforcement (includes Phase 2 strict verification)
cargo test --test manifest_authority_wiring        # Manifest-to-runtime authority differentiation (M1 Phase 01)
cargo test --test manifest_authority_load_path_guard  # All load paths use PreparedPluginLoad, not raw default_limits
cargo test --test docs_path_reference_guard  # Stale markdown link detection
cargo test --test failure_injection  # Failure-injection tests for lifecycle, convergence, plugin, startup
cargo test --test security_observability_guard  # Security observability invariants: metric labels, doc coverage, registry signals
cargo test --test unified_worker_composition_root_guard  # Composition root ≤80 lines
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns  # Mesh supervision structural invariants
cargo test --test mesh_task_ownership_guard --features mesh,dns  # Mesh task ownership and lifecycle invariants
```

## Critical Security Rules

- **Constant-time comparison**: Always use `subtle::ConstantTimeEq` for secrets, keys, MACs, auth tokens.
- **File permissions**: Set `0o600` on private key files.
- **Exception**: Simple `!=` is correct in `security_challenge.rs:196` — the expected solution is public, not a secret.
- **Plugin lifecycle**: Use `PluginRuntimeOwner` to own plugin hot-reload watchers. Never use `std::mem::forget`.
- **Signed byte loading**: File-based plugin loading reads WASM bytes once and instantiates from those verified bytes (TOCTOU closure). `PreparedPluginLoad.wasm_bytes` owns the verified bytes.
- **Strict SignedSandboxed**: Empty `binary_sha256` or `manifest_sha256` fields are rejected for `SignedSandboxed` in production.

## Admin Control-Plane Authority

- **Typed mutation results**: Mutating admin endpoints must return `AdminMutationResult` (from `synvoid_core::admin_mutation`), not generic `{"success": true}` JSON.
- **Authority classification**: Every mutation must be attributed to an `AdminMutationAuthority` variant. Compatibility paths must use `CompatibilityLegacy`, not silently default to admin authority.
- **Audit events**: Block/unblock operations emit `AdminAuditEvent` via `state.audit.log_audit_event()`.
- **Propagation semantics**: Mesh propagation is best-effort (`QueuedBestEffort`). Never promise delivery to all peers.
- **No raw session tokens**: `AdminActor.session_id_hash` must be hashed; never store raw tokens in audit logs.
- **Architecture doc**: `architecture/admin_control_plane_authority.md`

## Threat-Intel Enforcement Rules

1. **Never enforce from raw lookups** — `lookup_local_indicator()`, `lookup_local_indicator_by_ip()`, `lookup_threat_indicator_in_dht()` are diagnostic-only. Enforcement paths must use `lookup_*_policy_strict`.
2. **WAF reads BlockStore, not ThreatIntelligenceManager** — mesh enforcement populates BlockStore; WAF reads it.
3. **New block-store writes need meaningful provenance** — Use `block_ip_with_provenance` with `BlockProvenanceKind`. `LegacyUnknown` is only for backward compat, tests, and mocks.
4. **Mesh-ID blocks are admin/control-plane only** — `RequestContext` and `WafContext` lack mesh identity; `is_mesh_id_blocked()` must never appear in WAF/request/proxy/HTTP/3 code.
5. **New threat-intel consumers** must use `ThreatIntelConsumerKind::Enforcement` + `ThreatIntelConsumerAction::PermitAction` before mutating state.

## Composition Boundary

Request-path modules must consume **narrow traits**, not concrete infrastructure:

| Layer | May Own/Import |
|-------|---------------|
| Composition roots (`src/worker/unified_server/`, `src/supervisor/`, `src/server/`) | Concrete `BlockStore`, `ThreatIntelligenceManager`, mesh/DHT/Raft handles, IPC, config |
| Request path (`src/waf/`, `src/proxy/`, `src/http/`, `crates/synvoid-waf/`, `crates/synvoid-proxy/`) | Narrow traits (`BlockListStore`, `WafProcessor`), config snapshots, request context |
| Control-plane (`crates/synvoid-mesh/`, `crates/synvoid-block-store/`) | Full infrastructure internals |

**How to add a new capability safely:**
1. Define a narrow trait in `crates/synvoid-waf/src/traits.rs` or `crates/synvoid-core/`
2. Implement it on a concrete type in a composition root
3. Pass `Arc<dyn YourTrait>` to request-path modules
4. Never pass concrete types directly to request-path code

## Serialization & Crypto Standards

- **Postcard over JSON** for distributed state (DHT, Mesh, Persistence).
- **Typed structs** with `Archive`/`RkyvSerialize`/`RkyvDeserialize` — never `serde_json::Value`.
- **Unix timestamps (u64)** — use `crate::mesh::safe_unix_timestamp()` or `crate::utils::current_timestamp()`. Use `.saturating_sub()` for durations.
- **Base64**: Always `URL_SAFE_NO_PAD` for mesh/DHT data.
- **Pure Rust deps preferred** over C bindings where possible (confirmed: `libinjectionrs`, `bcrypt`).

## Known File Path Corrections

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
| `src/tls/acme.rs` | `crates/synvoid-tls/src/acme.rs` |
| `src/tls/acme_dns.rs` | `crates/synvoid-tls/src/acme_dns.rs` |
| `src/plugin/wasm_runtime.rs` | `crates/synvoid-plugin-runtime/src/wasm_runtime.rs` |
| `src/plugin/instance_pool.rs` | `crates/synvoid-plugin-runtime/src/instance_pool.rs` |
| `src/config/admin.rs` | `crates/synvoid-config/src/admin.rs` |
| `src/admin/authority.rs` | `crates/synvoid-core/src/admin_mutation.rs` |
| `src/wasm_pow/` | `crates/synvoid-wasm-pow/` |
| `src/server/mod.rs` (monolithic) | `src/server/` (split: `startup_plan.rs`, `resources.rs`, `runtime_handles.rs`, `plugin_runtime.rs`) |

## Module Overrides

Each subsystem has specialized `AGENTS.override.md` files. Load the relevant one when working in that area:

| Module | Path |
|--------|------|
| DNS/DNSSEC | `src/dns/AGENTS.override.md` |
| WAF | `src/waf/AGENTS.override.md` |
| HTTP Server | `src/http/AGENTS.override.md` |
| HTTP Client | `src/http_client/AGENTS.override.md` |
| HTTP/3 | `src/http3/AGENTS.override.md` |
| Plugin/WASM | `src/plugin/AGENTS.override.md` |
| Proxy | `src/proxy/AGENTS.override.md` |
| Config | `src/config/AGENTS.override.md` |
| Admin | `src/admin/AGENTS.override.md` |
| Auth | `src/auth/AGENTS.override.md` |
| Platform | `src/platform/AGENTS.override.md` |
| Worker | `src/worker/AGENTS.override.md` |
| Tunnel | `src/tunnel/AGENTS.override.md` |
| App Server | `src/app_server/AGENTS.override.md` |
| Theme | `src/theme/AGENTS.override.md` |
| Static Files | `src/static_files/AGENTS.override.md` |
| Serverless | `src/serverless/AGENTS.override.md` |

## CI, Fuzzing & Failure Injection

Phase 8 added profile CI, fuzz targets, failure-injection tests, and a docs link guard. Phase 11 fixed the CI workflow summary job (broken dynamic expressions prevented all jobs from running) and aligned `scripts/verify_architecture.sh` with the CI guard-suite (added missing `docs_path_reference_guard`). Phase 14 added 5 new parser boundary fuzz targets (16 total). See `architecture/ci_fuzz_failure_injection.md` for the full profile matrix and fuzz target inventory.

```bash
# Local verification script (profile checks + guard suite)
./scripts/verify_architecture.sh

# Docs path reference guard (catches stale markdown links)
cargo test --test docs_path_reference_guard

# Failure-injection tests
cargo test --test failure_injection

# Security observability guard (metric labels, doc coverage, registry signals)
cargo test --test security_observability_guard

# Fuzz smoke tests (requires nightly toolchain + cargo-fuzz)
cargo +nightly fuzz run dns_message_decode -- -runs=1000
cargo +nightly fuzz run plugin_manifest -- -runs=1000
cargo +nightly fuzz run http_path_normalization -- -runs=1000
cargo +nightly fuzz run fuzz_attack_detection -- -runs=1000
cargo +nightly fuzz run fuzz_early_parse -- -runs=1000
cargo +nightly fuzz run fuzz_ipc -- -runs=1000
cargo +nightly fuzz run blocklist_event_decode -- -runs=1000
cargo +nightly fuzz run blocklist_snapshot_decode -- -runs=1000
cargo +nightly fuzz run admin_mutation_result_decode -- -runs=1000
cargo +nightly fuzz run http_header_normalization -- -runs=1000
cargo +nightly fuzz run mesh_protocol_compressed_decode -- -runs=1000
```

## Architecture Quick Reference

The `architecture/` directory (87 docs) and `.opencode/skills/` directory contain detailed subsystem docs. Key entrypoints:

- **Entry point**: `src/main.rs` → delegates to `src/commands/` (plan/execute/runtime_launch)
- **Supervisor**: `src/supervisor/` — lifecycle, IPC, control-plane
- **Worker**: `src/worker/unified_server/` — data plane (HTTP + WAF + proxy in one Tokio event loop)
- **Mesh**: `crates/synvoid-mesh/src/mesh/` — DHT, transport, Raft, peer auth
- **WAF**: `crates/synvoid-waf/` — rule engine, attack detection
- **Proxy**: `crates/synvoid-proxy/` — routing, cache keys

**Process model**: Supervisor (1) → UnifiedServerWorker (1, single Tokio event loop) + CpuWorker (1, bounded transforms). Workers are NOT process-per-tenant. `--worker` flag spawns a legacy `BaseWorkerProcess` unused for HTTP.

**Root crate ownership**: tracked in `architecture/root_module_ledger.md`. Prefer dedicated `synvoid-*` crates over root `synvoid::` paths unless the ledger says `keep_app_root`.

### Key Architecture Documents

| Document | Description |
|----------|-------------|
| `architecture/overview.md` | Bird's eye view, process model, feature gates, module index |
| `architecture/plugin_runtime_sandbox.md` | Plugin trust tiers, manifest schema, default-deny capabilities, resource limits, signing policy, failure isolation |
| `architecture/root_module_ledger.md` | Root module ownership (keep_app_root / split_required / legacy) |
| `architecture/worker_data_plane_composition_root.md` | Composition boundary rules for request-path vs root |
| `architecture/http_request_pipeline.md` | 7-stage HTTP pipeline shared by HTTP/1 and HTTP/3 |
| `architecture/http3_request_waf_boundary.md` | HTTP/3 WAF composition boundary and guardrails |
| `architecture/mesh_trust_domains.md` | 7 trust domains, CanonicalTrustReader, trust invariants |
| `architecture/security_observability.md` | Security observability inventory, metric naming, structured logs, redaction rules, diagnostic-only vs enforcement | |
| `architecture/threat_intel_consumer_actionability.md` | 46 consumers classified by enforcement capability |
| `architecture/block_store.md` | BlockStore architecture, persistence, snapshot export, peer cursors, source-scoped ordering |
| `architecture/blocklist_reconciliation.md` | Offline-peer catchup, event log, peer cursors, snapshot fallback |
| `architecture/blocklist_remove_consistency.md` | LWW ordering, stale suppression, source-scoped ordering enhancements |
| `architecture/cli_supervisor_command_dispatch.md` | Typed command plan/execute/runtime-launch boundary |
| `architecture/mesh_transport_lifecycle.md` | 20-task mesh lifecycle state machine |
| `architecture/worker_task_lifecycle.md` | 40+ background tasks, shutdown ordering |
| `architecture/supervisor.md` | Process lifecycle, drain, gRPC control plane |
| `architecture/supervisor_lifecycle.md` | Task classes, shutdown cause taxonomy, drain report, Phase 3 hardening |
| `architecture/unified_server_startup.md` | UnifiedServer startup/resources/runtimeHandles split |
| `architecture/request_path_capability_boundary.md` | Request-path capability boundary, narrow traits, forbidden imports |
| `architecture/final_surface_audit.md` | Public surface classification, stability audit, CLI/admin/protocol inventory (Phase 10) |
| `architecture/release_hardening_report.md` | Release hardening checklist, guard results, profile checks, fuzz inventory (Phase 10) |
| `architecture/runtime_operations_drill.md` | Reproducible operator drill steps for runtime operations readiness (Phase 16) |
| `architecture/runtime_operations_drill_report.md` | Drill results, corrections applied, observability signals (Phase 16) |
| `architecture/semver_stability_policy.md` | Semver versioning, stability classifications, deprecation rules |

## Known Issues

- `src/admin/alerting/mod.rs:349` — Email alerting is a stub (logs, returns Ok).
- `spin` idle instance eviction never cleans up old UUID entries (plan DOC-L7).
- `wasmtime` 40.0.4 (via yara-x) has known CVEs but only used for YARA compilation, not wasm sandbox — mitigated by `[patch.crates-io]` for direct dep.
