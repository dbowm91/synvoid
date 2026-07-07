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

# DNS response encoder tests
cargo test -p synvoid-dns -- response_encoder

# DNS canonical query parser tests
cargo test -p synvoid-dns -- parsed_query

# DNS authoritative negative response tests
cargo test --test authoritative_negative

# DNS config fidelity tests (Phase 5 + Phase 2 closure)
cargo test -p synvoid-dns --test dns_config_fidelity
cargo test -p synvoid-dns --test dns_recursive_isolation

# DNS Phase 7 cache tests
cargo test -p synvoid-dns -- phase7_cache_tests
cargo test -p synvoid-dns -- recursive_cache
cargo test -p synvoid-dns -- cache

# DNS query coalescing tests (Phase 4)
cargo test -p synvoid-dns -- query_coalesce

# DNS Milestone 2 Phase 1 tests (transport lifecycle, bind fail-fast, shutdown, truncation)
cargo test -p synvoid-dns -- transport
cargo test -p synvoid-dns -- transport_lifecycle
cargo test -p synvoid-dns -- configured_bind_addr
cargo test -p synvoid-dns -- shutdown_runtime
cargo test -p synvoid-dns -- tcp_hard_limit
cargo test -p synvoid-dns -- truncation

# DNS Milestone 2 Phase 2 tests (config closure: open-resolver guard, NOTIMP, query timeout)
cargo test -p synvoid-dns -- query_timeout
cargo test -p synvoid-dns -- open_resolver
cargo test -p synvoid-dns --test dns_recursive_isolation -- open_resolver

# DNS coalescing tests
cargo test -p synvoid-dns --test transport_lifecycle -- coalescer

# DNS Milestone 3 Phase 1 tests (zone lifecycle, SOA validation, UPDATE/NOTIFY/AXFR/IXFR hardening)
cargo test -p synvoid-dns -- zone_lifecycle
cargo test -p synvoid-dns -- zone_health
cargo test -p synvoid-dns -- validate_single_soa
cargo test -p synvoid-dns -- normalize_origin
cargo test -p synvoid-dns -- serial_rfc1982
cargo test -p synvoid-dns -- update_metrics
cargo test -p synvoid-dns -- update_max_size
cargo test -p synvoid-dns -- notify_rate_limit
cargo test -p synvoid-dns -- notify_source_allowlist
cargo test -p synvoid-dns -- axfr_tcp_only
cargo test -p synvoid-dns -- axfr_disabled_by_default
cargo test -p synvoid-dns -- ixfr_history
cargo test -p synvoid-dns -- store_volatile
cargo test -p synvoid-dns -- store_atomic_write
cargo test -p synvoid-dns -- cache_invalidation_axfr

# DNS Milestone 3 Phase 3 tests (encrypted transport adapters: DoT, DoH, DoQ)
cargo test -p synvoid-dns --test encrypted_transport
cargo test -p synvoid-dns -- dot
cargo test -p synvoid-dns -- doh
cargo test -p synvoid-dns -- doq

# DNS Milestone 3 Phase 4 tests (recursive resolver isolation: ACL, circuit breaker, CD/AD, bailiwick, ECS, depth limits)
cargo test -p synvoid-dns --test dns_recursive_isolation
cargo test -p synvoid-dns -- recursive_cache

# DNS Milestone 3 Phase 5 verification gate tests
cargo test -p synvoid-dns --test verification_gate

# DNS Milestone 3 final validation hardening (live DNSSEC, TSIG fixtures, IXFR delta, UPDATE atomicity, NOTIFY scheduling, cache completion)
cargo test -p synvoid-dns --test dnssec_live_signing
cargo test -p synvoid-dns --test tsig_success_fixtures
cargo test -p synvoid-dns --test ixfr_record_delta
cargo test -p synvoid-dns --test update_atomicity_rollback
cargo test -p synvoid-dns --test notify_scheduling_semantics
cargo test -p synvoid-dns --test control_plane_cache_completion

# DNS Milestone 4 Phase 1 tests (observability and operations: metrics, health, structured logging)
cargo test -p synvoid-dns -- metrics
cargo test -p synvoid-dns -- health

# DNS config-runtime matrix
# See architecture/dns_config_runtime_matrix.md

# DNS Milestone 4 Phase 2 benchmarks (performance and load testing)
cargo bench -p synvoid-dns                                          # All benchmarks
cargo bench -p synvoid-dns --bench cache_bench                      # Cache operations
cargo bench -p synvoid-dns --bench wire_bench                       # Wire format parsing
cargo bench -p synvoid-dns --bench zone_bench                       # Zone operations
cargo bench -p synvoid-dns --bench coalescer_bench                  # Query coalescing
cargo bench -p synvoid-dns --bench limits_bench                     # Connection limits
cargo bench -p synvoid-dns --bench cache_bench -- --test            # Dry-run (compile check)

# DNS stress and resource limit tests (Workstream 7)
cargo test -p synvoid-dns --test dns_stress_resource_limits -- --test-threads=1
./scripts/dns/stress_tests.sh                                       # All stress tests
./scripts/dns/run_benchmarks.sh                                     # Full benchmark suite

# DNS interop & conformance tests
cargo test -p synvoid-dns --test dns_interop_authoritative
cargo test -p synvoid-dns --test dns_interop_truncation
cargo test -p synvoid-dns --test dns_interop_dnssec
cargo test -p synvoid-dns --test dns_interop_transfers
cargo test -p synvoid-dns --test dns_interop_update_notify
cargo test -p synvoid-dns --test dns_interop_encrypted
cargo test -p synvoid-dns --test dns_interop_recursive
./scripts/dns/conformance.sh

# Supervisor lifecycle (Phase 3)
cargo test --test supervisor_task_ownership_guard
cargo test -p synvoid supervisor::task_registry
cargo test -p synvoid supervisor::shutdown

# Plugin runtime tests (M2 Phase 06)
cargo test -p synvoid-plugin-runtime -- test_epoch_interrupted
cargo test -p synvoid-plugin-runtime -- test_state_model
cargo test -p synvoid-plugin-runtime -- test_epoch_incrementer
cargo test -p synvoid-plugin-runtime -- test_body_chunk_timeout
cargo test -p synvoid-plugin-runtime -- test_pool_metrics

# Plugin runtime tests (M2 Phase 07: Host API Sub-Capabilities)
cargo test -p synvoid-plugin-runtime -- test_mesh_policy
cargo test -p synvoid-plugin-runtime -- test_capabilities_mesh
cargo test -p synvoid-plugin-runtime -- test_capabilities_check_metrics
cargo test -p synvoid-plugin-runtime -- test_host_api_failure_class
cargo test -p synvoid-plugin-runtime -- test_manifest_toml_parses_mesh
cargo test -p synvoid-plugin-runtime -- test_signing_payload_includes
cargo test -p synvoid-plugin-runtime -- test_manifest_validate_trust

# Unsafe native extension tests (Phase 8)
cargo test -p synvoid-plugin-runtime -- unsafe_native
cargo test -p synvoid-plugin-runtime -- test_unsafe_native
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
cargo test --test abi_memory_boundary_guard  # ABI memory boundary hardening: GuestAbiPolicy, guest_alloc+guest_free required, single-frame allocation, checked arithmetic
cargo test --test plugin_lifecycle_guard  # Lifecycle state transitions, generation tracking, hot-reload gates, replace policy
cargo test --test unsafe_native_sandbox_language_guard  # Docs must not imply native plugins are sandboxed
cargo test -p synvoid-plugin-runtime -- test_plugin_failure       # Failure policy defaults and failure class classification
cargo test -p synvoid-plugin-runtime -- test_classify_failure     # Error-to-failure-class mapping
cargo test -p synvoid-plugin-runtime -- test_guard_               # Guard state, quarantine, blocking invoke
cargo test -p synvoid-plugin-runtime -- test_manager_             # Manager introspection (not-found cases)
cargo test -p synvoid-plugin-runtime -- test_require_any          # Capability matching
cargo test -p synvoid-plugin-runtime -- abi_frame    # ABI frame serialization: policy bounds, canonical header encoding, response validation, mutation policy
cargo test -p synvoid-plugin-runtime -- test_execution_interrupt_policy
cargo test -p synvoid-plugin-runtime -- test_host_call_budget
cargo test -p synvoid-plugin-runtime -- test_abi_error_codes
cargo test -p synvoid-plugin-runtime -- test_plugin_state_model
cargo test -p synvoid-plugin-runtime -- test_warmup_uses_provided_limits
cargo test -p synvoid-plugin-runtime -- test_record_pool_hit
cargo test -p synvoid-plugin-runtime -- test_wasm_plugin_metrics_new_fields
cargo test -p synvoid-plugin-runtime -- test_epoch_incrementer    # Epoch incrementer lifecycle ownership
cargo test -p synvoid-plugin-runtime -- test_body_chunk_timeout   # Body chunk timeout enforcement
cargo test -p synvoid-plugin-runtime -- test_pool_metrics         # Pool metrics semantic separation
cargo test -p synvoid-plugin-runtime -- test_mesh_policy          # Mesh sub-capability policy validation
cargo test -p synvoid-plugin-runtime -- test_capabilities_mesh    # Mesh sub-capability enforcement
cargo test -p synvoid-plugin-runtime -- test_capabilities_check_metrics  # Metrics sub-capability enforcement
cargo test -p synvoid-plugin-runtime -- test_host_api_failure_class     # HostApiFailureClass display
cargo test -p synvoid-plugin-runtime -- test_manifest_toml_parses_mesh  # TOML mesh sub-policy parsing
cargo test -p synvoid-plugin-runtime -- test_signing_payload_includes   # Signing payload covers sub-policies
cargo test -p synvoid-plugin-runtime -- test_manifest_validate_trust    # Trust consistency mesh sub-policy
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
- **Plugin ABI memory boundary**: `write_to_guest_memory` requires `guest_alloc`/`guest_free`. Fixed-offset 1024 fallback is removed. All guest pointer/length operations use `checked_guest_range`.
- **Plugin ABI frame serialization**: Use `abi_frame::serialize_headers_canonical` and `abi_frame::build_request_frame` — never ad-hoc header encoding. `SerializationFailureClass` classifies rejections for bounded metrics.
- **Unsafe native extensions**: Disabled by default. Production loading requires explicit risk acknowledgement, path allowlist, and optional SHA-256 hash verification. The `Library` handle is retained via `Arc` for the lifetime of any plugin-derived values. Native extensions are NOT sandboxed and have full process authority.
- **Plugin lifecycle**: Reload is prepare-then-commit with generation-aware atomic swaps. Failed reloads must never replace a working plugin. Hot reload waits for stable files and debounces watcher events. Lifecycle states and transitions are explicit and auditable.

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
| `serialize_headers` (inline in wasm_runtime.rs) | `crates/synvoid-plugin-runtime/src/abi_frame.rs` (canonical) |
| `src/plugin/instance_pool.rs` | `crates/synvoid-plugin-runtime/src/instance_pool.rs` |
| `src/config/admin.rs` | `crates/synvoid-config/src/admin.rs` |
| `src/admin/authority.rs` | `crates/synvoid-core/src/admin_mutation.rs` |
| `src/wasm_pow/` | `crates/synvoid-wasm-pow/` |
| `src/server/mod.rs` (monolithic) | `src/server/` (split: `startup_plan.rs`, `resources.rs`, `runtime_handles.rs`, `plugin_runtime.rs`) |
| `src/dns/*.rs` (legacy copies) | `crates/synvoid-dns/src/` (canonical). `src/dns/mod.rs` re-exports `synvoid_dns::*`. |

## Module Overrides

Each subsystem has specialized `AGENTS.override.md` files. Load the relevant one when working in that area:

| Module | Path |
|--------|------|
| DNS/DNSSEC | `crates/synvoid-dns/AGENTS.override.md` |
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
| `architecture/dns_config_runtime_matrix.md` | DNS config field inventory with runtime status, defaults, and wiring |

## Known Issues

- `src/admin/alerting/mod.rs:349` — Email alerting is a stub (logs, returns Ok).
- `spin` idle instance eviction never cleans up old UUID entries (plan DOC-L7).
- `wasmtime` 40.0.4 (via yara-x) has known CVEs but only used for YARA compilation, not wasm sandbox — mitigated by `[patch.crates-io]` for direct dep.

## Recent Completions

- **DNS Milestone 4 Deferral Closeout** — 8-workstream closeout. Remote CI status limitation documented (no status visibility through current connector for direct-push workflow runs); external live-wire checks explicitly deferred as operator-validated and `conformance.sh` rewritten to be honest about internal-vs-external scope. 32 unwired DnsMetrics methods + their backing fields removed (`metrics.rs` 1128→504 lines); 5 documented watchable metrics, 17 production-active wired methods, and 5 production-emitted `metrics::counter!` direct paths preserved. `cargo clippy -p synvoid-dns --all-targets -- -D warnings` brought from 63 errors to clean (10 `#[allow(too_many_arguments)]` for genuine large-fn sites, rest are real fixes). Local benchmark baseline captured: `benchmarks/dns/results/2026-07-07-baseline.md` (53 criterion `time: [...]` rows across 5 bench suites on i9-9900K, rustc 1.95.0). `architecture/dns_production_profiles.md` updated with explicit production-supported boundary section, Release Support Matrix table (8 profiles × 4 cols), DNSSEC Coverage Boundary sub-section, and encrypted/transfer profile scope clarifications. `architecture/dns_operations_diagnostics.md` updated to link to the matrix. All 5 DNS scripts verified by `bash -n`. Status: **Closed with accepted deferrals** (external DNSSEC tooling, external live-wire checks, remote CI status visibility). Total: 1101 tests passing in release mode. See `plans/dns_milestone_4_deferred_items_closeout_complete.md`.

- **DNS Milestone 4 Phase 4: Production Profile Release Gate** — 8 production profiles (4 production-supported, 2 beta, 1 experimental), safe defaults audit (60+ fields verified, 3 warnings), 5 hardened example configs in `examples/dns/`, release gate (781 tests: 607 unit + 174 integration across 14 suites), security review (all areas safe, bailiwick observability-only deferral), upgrade/restart behavior verified (zones config-only, keys persisted, cache cold-start). New files: `architecture/dns_production_profiles.md`, 5 example configs. Updated: `architecture/dns.md`, `.opencode/skills/dns_dnssec/SKILL.md`, `crates/synvoid-dns/AGENTS.override.md`. Total: 781 tests passing. See `plans/dns_milestone_4_phase_04_production_profile_release_gate.md`.

- **DNS Milestone 4 Verification Closure Pass** — 9-workstream audit & gap-fixes. CI now runs all 26 integration suites (was 18; 8 missing interop+stress suites added to `.github/workflows/ci.yml`). `DnsHealthChecker` wired into `DnsServer` with `Arc<>` field, `init_health_state()` and `health_checker()` accessors, all 20 setters called from startup/shutdown paths; 19 integration tests added (`health_integration.rs`). 5 documented-as-watchable metrics (`dns_active_tcp_connections`, `dns_recursive_circuit_breaker_opens_total`, `dns_encode_failures_total`, `dns_zone_reload_failures_total`, `dns_dnssec_signing_failures_total`) wired to runtime paths via new `EncodeReport::record_skip()` helper and inline `metrics::counter!` emissions; 5 metrics-wiring tests + 1 unit test. `scripts/dns/conformance.sh` rewritten with internal/external sections; docs clarified (7 internal suites). `RESULTS_TEMPLATE.md` updated with SHA/command/variance and current bench inventory. All 5 example configs corrected for field names, enum casing, table flattening; 5 parse tests added (`example_configs_parse.rs`). `dns_diagnostic_smoke.sh` checks for `dig` and warns about port 53. Total: 1101 DNS tests passing (608 lib + 493 integration across 31 suites). Milestone 4 ready for release. See `plans/dns_milestone_4_verification_closure_pass_complete.md`.

- **DNS Milestone 4 Phase 2: Performance and Load Testing** — 5 criterion benchmark suites (cache_bench, wire_bench, zone_bench, coalescer_bench, limits_bench) with parameterized scaling tests (1K/10K/100K capacity, 10/100/1000 records, multiple transport classes). 28 stress and resource-limit tests covering boundary validation, connection/query limit enforcement, guard drop semantics, graceful degradation activation/deactivation, cache capacity enforcement, large entry rejection, coalescer bounded handling, zone trie 10K insertions, memory stability through 100 insert-lookup-clear cycles, and deterministic rejection under overload. New scripts: `run_benchmarks.sh` (orchestration with env capture), `stress_tests.sh` (CI-safe), `benchmark_report.sh` (markdown report generator). Results template at `benchmarks/dns/RESULTS_TEMPLATE.md`. Total: 1029 DNS tests passing (607 lib + 422 integration). See `plans/dns_milestone_4_phase_02_performance_load_testing.md`.

- **DNS Milestone 4 Phase 1: Observability and Operations** — Metrics taxonomy overhaul (removed high-cardinality `top_queried_domains`/`top_blocked_domains`/`query_types`/`response_codes` HashMaps; added transport-labeled `dns_transport_queries`/`dns_transport_errors`, operation-labeled `dns_operation_counts`, zone metrics `dns_zones_loaded`/`dns_zone_reload_*`, recursive circuit breaker metrics, DNSSEC key rotation/signing failure metrics, control-plane authorization metrics for UPDATE/NOTIFY/AXFR/IXFR). All recursive counters now emit `metrics::counter!`. New `health.rs` module with `DnsHealthChecker` providing liveness/readiness status (Healthy/Degraded/NotReady) with zone, cache, DNSSEC, encrypted transport, and transfer/update health state. Structured logging added to `dot.rs` and `doh.rs` (previously zero logging) and enhanced in `transfer.rs`, `notify.rs`, `update.rs` with structured fields. New `architecture/dns_operations_diagnostics.md` operator guide with smoke tests, alerting matrix, and troubleshooting flowchart. New `scripts/dns_diagnostic_smoke.sh` smoke test script. Documentation updated: `architecture/dns.md`, `architecture/dns_config_runtime_matrix.md`, `dns_dnssec/SKILL.md`, `AGENTS.override.md`. Total: 1001 DNS tests passing (607 lib + 394 integration). See `plans/dns_milestone_4_phase_01_observability_operations.md`.

- **DNS Milestone 3 Final Validation Hardening** — 6 new integration test files (`dnssec_live_signing.rs`, `tsig_success_fixtures.rs`, `ixfr_record_delta.rs`, `update_atomicity_rollback.rs`, `notify_scheduling_semantics.rs`, `control_plane_cache_completion.rs`), 64 new tests covering DNSSEC live signing, TSIG sign+verify roundtrips, IXFR record-by-record deltas, UPDATE atomicity/rollback, NOTIFY scheduling/cache invalidation, and cache/coalescing exclusion completion. Production bug fix in `update.rs`: corrected `parse_rr_with_rdata()` (TTL+RDLENGTH bytes were included in rdata), `skip_rr_with_rdata()` (was not skipping full RR), and `check_prerequisite()` for `Exists`/`ExistsRRset` (inverted logic + unwrap on None). Documentation updated: `AGENTS.override.md`, `AGENTS.md`. Total: 1001 DNS tests passing. All deferrals locked down. See `plans/dns_milestone_3_final_validation_hardening.md`.

- **DNS Milestone 3 Tightening Follow-up** — 5 workstreams: deepened zone activation validation (17 `ZoneValidationError` variants covering label length, owner-within-zone, TTL bounds, MX/SRV priority, A/AAAA parse, CNAME exclusivity, NULL rejection, SOA field validation, target name validation), AXFR/IXFR response assertions (SOA-bracketed transfer, serial wraparound), UPDATE authorized semantics (add/delete/prerequisite/SOA protection/cache invalidation), NOTIFY behavior (TSIG enforcement, stale serial, unknown zone), DNSSEC known-vectors (key tag, DS digest, canonical rdata, response shape), control-plane exclusion proof (cache/coalescing bypass). 5 new integration test files: `axfr_ixfr_transfer_semantics.rs`, `notify_behavior.rs`, `update_authorized_semantics.rs`, `dnssec_known_vectors.rs`, `control_plane_exclusion.rs`. Documentation reconciled: `dns_zone_lifecycle.md`, `dns.md`, `AGENTS.override.md`, `dns_dnssec/SKILL.md`.
- **DNS Milestone 3 Corrective Semantics Pass** — 10 workstreams (CI hardening, failed-reload preservation, invalid-zone rejection, UPDATE/NOTIFY/AXFR/IXFR authorization, DNSSEC correctness, encrypted transport proof, recursive safety, verification-gate tests, documentation reconciliation, final verification). New production helpers: `Zone::validate_zone_for_activation()` (unified pre-publish gate: single apex SOA, normalized/printable origin, rejects control chars/NUL/whitespace/`\`/`/`), `DnsServer::replace_zone_with_validation()` (atomic swap-or-preserve, cache invalidation). Dynamic UPDATE re-validates post-mutation (RCODE NOTAUTH on SOA invariant violation). New test files: `control_plane_authorization.rs` (10 deny-by-default tests for UPDATE/NOTIFY/AXFR/IXFR), `verification_gate.rs` (strengthened with 5 atomic-swap/zone-validation behavior tests + 15 protocol-semantics tests across gates 7/8/9). CI now runs `encrypted_transport`, `verification_gate`, `control_plane_authorization` tests and `cargo check --all-features`. Deferred: DoQ experimental, persistent TCP pipelining, EDNS keepalive, NSEC3 closest-encloser proofs, external DNSSEC tooling, bailiwick enforcement. See `plans/dns_milestone_3_corrective_semantics_pass.md`.
- **DNS Milestone 2 Phase 2 Config Matrix Closure** — Matrix reconciliation (6 corrections: default_ttl, negative_cache_ttl, enable_graceful_degradation, doq.bind_address, serve_stale.max_stale_count, query_timeout_secs), serve-stale max_stale_count wiring, NOTIMP responses for disabled zone mutation (NOTIFY/UPDATE/AXFR/IXFR), query timeout wiring to HickoryResolver, open-resolver prevention guard, graceful degradation wiring, 48 integration tests passing. All items in `plans/dns_milestone_2_phase_02_config_matrix_closure.md` addressed.
- **DNS Phase 7 Cache Semantics & Invalidation** — Cache key redesign (qclass, DO bit, transport class, namespace), SOA-derived negative TTL, dynamic update cache invalidation, composite fingerprint keys, serve-stale max_stale_count wiring, cache metrics (stale/negative/invalidation/poisoned), 30 new tests, architecture docs updated. All items in `plans/dns_phase_07_cache_semantics_invalidation.md` addressed.
- **DNS Phase 5 Config-to-Runtime Fidelity** — serve_stale wiring, DNS64 exclude_aaaa_synthesis, 37 new tests (config fidelity + recursive isolation), config-runtime matrix document, deferred feature documentation. All items in `plans/dns_phase_05_config_runtime_fidelity.md` addressed.
- **Plugin M3 Phase 8** — Unsafe native extension production gate, FFI panic catching, hot-reload gating, world-writable path rejection, config migration, metrics, and 34 unit tests. All items in `plans/plugin_m3_phase_08_gap_fixes.md` are complete.
- **Plugin M3 Phase 9** — Lifecycle hardening: generation tracking, atomic reload pipeline, file stability detection, lifecycle state machine, operator APIs, and 44+ tests across guard files. All items in `plans/plugin_m3_phase_09_gap_fixes.md` are complete.
- **DNS Milestone 1 Corrective Pass** — Response flag semantics (RA=false authoritative, RD echoed), byte-size truncation, parser propagation (parse-once), authoritative NODATA/NXDOMAIN with SOA, encoder strictness (MX/CAA/TLSA validation, EncodeReport), query coalescing broadcast, runtime correctness (bind address, DNS64 pass-through, TCP guard). All phases (A–G) complete. See `plans/dns_milestone_1_corrective_pass.md`.
- **DNS Milestone 3 Phase 1** — Zone lifecycle management, SOA validation, dynamic update hardening (max size, metrics), NOTIFY rate limiting and source allowlist, AXFR TCP-only enforcement and disabled-by-default guard, IXFR history tracking, volatile/atomic store writes, and cache invalidation on AXFR. All items in `plans/dns_milestone_3_phase_01_zone_lifecycle.md` addressed.
- **DNS Milestone 3 Phase 5 Verification Gate** — 20 new verification gate tests covering zone lifecycle atomicity, DNSSEC type constants/NSEC/DNSKEY/RRSIG, encrypted transport config roundtrips, recursive resolver safety invariants, and cache isolation. All gate areas (2-6) verified. See `plans/dns_milestone_3_phase_05_verification_gate.md`.
