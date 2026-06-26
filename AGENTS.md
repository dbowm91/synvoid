# AGENTS.md

SynVoid is a high-performance WAF & reverse proxy in Rust with a mesh networking layer, multi-process architecture (Supervisor + UnifiedServerWorker + CPU offload), and 38 workspace members (31 dedicated `synvoid-*` library crates plus root, pqc, admin-ui, examples, and fuzz).

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
```

## Critical Security Rules

- **Constant-time comparison**: Always use `subtle::ConstantTimeEq` for secrets, keys, MACs, auth tokens.
- **File permissions**: Set `0o600` on private key files.
- **Exception**: Simple `!=` is correct in `security_challenge.rs:196` — the expected solution is public, not a secret.

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
| Composition roots (`src/worker/unified_server/`, `src/supervisor/`) | Concrete `BlockStore`, `ThreatIntelligenceManager`, mesh/DHT/Raft handles, IPC, config |
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
| `src/wasm_pow/` | `crates/synvoid-wasm-pow/` |

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

## Architecture Quick Reference

The `architecture/` directory (73 docs) and `.opencode/skills/` directory contain detailed subsystem docs. Key entrypoints:

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
| `architecture/root_module_ledger.md` | Root module ownership (keep_app_root / split_required / legacy) |
| `architecture/worker_data_plane_composition_root.md` | Composition boundary rules for request-path vs root |
| `architecture/http_request_pipeline.md` | 7-stage HTTP pipeline shared by HTTP/1 and HTTP/3 |
| `architecture/http3_request_waf_boundary.md` | HTTP/3 WAF composition boundary and guardrails |
| `architecture/mesh_trust_domains.md` | 7 trust domains, CanonicalTrustReader, trust invariants |
| `architecture/threat_intel_consumer_actionability.md` | 46 consumers classified by enforcement capability |
| `architecture/block_store.md` | BlockStore architecture, persistence, snapshot export |
| `architecture/cli_supervisor_command_dispatch.md` | Typed command plan/execute/runtime-launch boundary |
| `architecture/mesh_transport_lifecycle.md` | 20-task mesh lifecycle state machine |
| `architecture/worker_task_lifecycle.md` | 40+ background tasks, shutdown ordering |
| `architecture/supervisor.md` | Process lifecycle, drain, gRPC control plane |

## Known Issues

- `src/admin/alerting/mod.rs:349` — Email alerting is a stub (logs, returns Ok).
- `spin` idle instance eviction never cleans up old UUID entries (plan DOC-L7).
- `wasmtime` 40.0.4 (via yara-x) has known CVEs but only used for YARA compilation, not wasm sandbox — mitigated by `[patch.crates-io]` for direct dep.
