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

# Full test suite (CI uses --profile ci --no-fail-fast)
cargo test --profile ci --no-fail-fast

# Full test suite with nextest (preferred for CI — better concurrency and diagnostics)
cargo nextest run --workspace --cargo-profile ci --profile ci --exclude synvoid-fuzz
cargo test --workspace --doc --profile ci  # doctests (nextest doesn't run these)

# Repository guard tests (lightweight crate, no root dependency)
cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci

# Full test suite (release mode — only for release qualification)
cargo test --release --no-fail-fast

# Security regression tests (must run single-threaded; uses env var serialization guard)
cargo test --test security_regression -- --test-threads=1

# Root test ownership guard (enforces OWNERSHIP.toml manifest)
cargo test --test root_test_ownership_guard

# Mesh/DNS features required for many tests
cargo test --test mesh_task_ownership_guard --features mesh,dns
cargo test --test worker_supervision_control_flow --features mesh,dns
cargo test --test composition_root_behavioral --features mesh,dns

# Affected package tests (runs only packages changed since base ref)
bash scripts/test-affected.sh origin/main
bash scripts/test-affected.sh origin/main --dry-run  # preview only
bash scripts/test-affected.sh origin/main --full      # force full validation

# Affected package selector (standalone)
python3 scripts/ci/select-affected.py --base HEAD~1 --head HEAD --format text
python3 scripts/ci/select-affected.py --base HEAD~1 --head HEAD --format json --dry-run

# DNS full suite (all unit + integration tests)
cargo test -p synvoid-dns --profile ci

# DNS interop & conformance
cargo test -p synvoid-dns --test dns_interop_authoritative
cargo test -p synvoid-dns --test dns_interop_truncation
cargo test -p synvoid-dns --test dns_interop_dnssec
cargo test -p synvoid-dns --test dns_interop_transfers
cargo test -p synvoid-dns --test dns_interop_update_notify
cargo test -p synvoid-dns --test dns_interop_encrypted
cargo test -p synvoid-dns --test dns_interop_recursive
./scripts/dns/conformance.sh

# DNS benchmarks
cargo bench -p synvoid-dns

# Plugin runtime tests
cargo test -p synvoid-plugin-runtime

# Honeypot tests
cargo test -p synvoid-honeypot --all-targets

# Tarpit tests
cargo test -p synvoid-tarpit --all-targets
```

## CI Testing Infrastructure

SynVoid CI uses four validation lanes with a dedicated `[profile.ci]` for routine correctness testing. See `docs/testing/ci-lane-policy.md` for the full policy.

| Lane | Trigger | Purpose |
|------|---------|---------|
| PR Fast | Pull requests | Fast feedback (<10 min target) |
| Main Comprehensive | Push to main | Full validation after merge |
| Scheduled Qualification | Nightly 4 AM UTC | Expensive portability/safety checks |
| Release Qualification | Version tags / dispatch | Production artifact validation |

**CI profile** (routine tests): `cargo test --profile ci`
**Release profile** (production artifacts): `cargo test --release`

Key docs:
- `docs/testing/ci-performance-baseline.md` — Timing baseline and before/after results
- `docs/testing/test-suite-ownership.md` — Every test target's owner, lane, and profile
- `docs/testing/ci-lane-policy.md` — Four-lane CI policy and branch protection
- `docs/testing/cache-policy.md` — Cache architecture, layers, and invalidation rules

`testing/lanes.toml` — Machine-readable lane definitions consumed by xtask and CI.

## Test Orchestration (xtask)

```bash
cargo xtask test fast            # PR fast lane: fmt, clippy, guards, security, affected
cargo xtask test affected --base origin/main  # Affected package selection and testing
cargo xtask test package synvoid-dns  # Test a specific package
cargo xtask test guards          # All architectural guard tests
cargo xtask test security        # Security regression tests
cargo xtask test comprehensive   # Full workspace validation
cargo xtask test nightly-plan    # Print nightly qualification plan
cargo xtask test qualification   # Print release qualification plan
cargo xtask test release         # Print release validation (never substitutes CI profile)
cargo xtask test list            # List all available lanes
cargo xtask test explain fast    # Explain what a lane does

# Options:
#   --dry-run    Print commands without executing
#   --json       Machine-readable JSON output
#   --verbose    Detailed output
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
cargo test --test boundary_composition_guard     # Request-path vs composition-root, HTTP pipeline, HTTP/3 WAF, manifest authority
cargo test --test root_facade_boundary_guard     # Domain crates can't import root
cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci  # Static guards (lightweight, includes cache/selector)
cargo test --test mesh_id_boundary_guard         # Mesh-ID blocks: admin only, not WAF
cargo test --test security_guard                 # Threat-intel boundary, consumer actionability, security observability
cargo test --test lifecycle_task_guard           # Background task ownership, supervisor spawns, unified server lifecycle
cargo test --test cli_admin_guard                # CLI dispatch, enforcement provenance, worker composition root
cargo test --test plugin_guard                   # Plugin capability boundary, lifecycle, signature policy
cargo test --test admin_mutation_response_guard  # Mutating admin endpoints must return AdminMutationResult
cargo test --test abi_memory_boundary_guard      # ABI memory boundary hardening
cargo test --test failure_injection              # Failure-injection tests for lifecycle, convergence, plugin, startup
cargo test --test root_test_ownership_guard      # Enforces root test ownership manifest (OWNERSHIP.toml)
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns
cargo test --test mesh_task_ownership_guard --features mesh,dns
cargo test -p synvoid-plugin-runtime --test plugin_failure_does_not_poison_manager
cargo test -p synvoid-plugin-runtime --test manifest_authority_wiring
cargo test -p synvoid-tarpit --all-targets
cargo test -p synvoid-repo-guards -- ci_policy
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
| Honeypot | `crates/synvoid-honeypot/AGENTS.override.md` |
| Tarpit | `crates/synvoid-tarpit/AGENTS.override.md` |

## CI, Fuzzing & Failure Injection

Phase 8 added profile CI, fuzz targets, failure-injection tests, and a docs link guard. Phase 11 fixed the CI workflow summary job (broken dynamic expressions prevented all jobs from running) and aligned `scripts/verify_architecture.sh` with the CI guard-suite (added `docs_path_reference_guard`, now in `synvoid-repo-guards` crate). Phase 14 added 5 new parser boundary fuzz targets (17 total). Milestone D Phase 4 added dedicated tarpit and mesh CI jobs, fixed tarpit non-deterministic sentence generation and mesh Ed25519 test key generation. See `architecture/ci_fuzz_failure_injection.md` for the full profile matrix and fuzz target inventory.

```bash
# Local verification script (profile checks + guard suite)
./scripts/verify_architecture.sh

# Docs path reference guard (catches stale markdown links) — now in guard crate
cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci

# Failure-injection tests
cargo test --test failure_injection

# Security observability guard (metric labels, doc coverage, registry signals)
cargo test --test security_observability_guard

# Fuzz smoke tests (requires nightly toolchain + cargo-fuzz)
cargo +nightly fuzz run admin_mutation_result_decode -- -runs=1000
cargo +nightly fuzz run blocklist_event_decode -- -runs=1000
cargo +nightly fuzz run blocklist_snapshot_decode -- -runs=1000
cargo +nightly fuzz run dns_message_decode -- -runs=1000
cargo +nightly fuzz run fuzz_attack_detection -- -runs=1000
cargo +nightly fuzz run fuzz_early_parse -- -runs=1000
cargo +nightly fuzz run fuzz_ipc -- -runs=1000
cargo +nightly fuzz run fuzz_protocol_proto_decode -- -runs=1000
cargo +nightly fuzz run fuzz_raft_commit_notification -- -runs=1000
cargo +nightly fuzz run fuzz_raft_response -- -runs=1000
cargo +nightly fuzz run fuzz_serialization -- -runs=1000
cargo +nightly fuzz run fuzz_serialization_new -- -runs=1000
cargo +nightly fuzz run http_header_normalization -- -runs=1000
cargo +nightly fuzz run http_path_normalization -- -runs=1000
cargo +nightly fuzz run mesh_protocol_compressed_decode -- -runs=1000
cargo +nightly fuzz run parsed_query_parse -- -runs=1000
cargo +nightly fuzz run plugin_manifest -- -runs=1000
```

## Architecture Quick Reference

The `architecture/` directory (87 docs) and `.opencode/skills/` directory contain detailed subsystem docs. Key entrypoints:

- **Entry point**: `src/main.rs` → delegates to `src/commands/` (plan/execute/runtime_launch)
- **Supervisor**: `src/supervisor/` — lifecycle, IPC, control-plane
- **Worker**: `src/worker/unified_server/` — data plane (HTTP + WAF + proxy in one Tokio event loop)
- **Mesh**: `crates/synvoid-mesh/src/mesh/` — DHT, transport, Raft, peer auth
- **WAF**: `crates/synvoid-waf/` — rule engine, attack detection
- **Proxy**: `crates/synvoid-proxy/` — routing, cache keys
- **Tarpit**: `crates/synvoid-tarpit/` — anti-scraping tarpit, escaping, admission, budgets

**Process model**: Supervisor (1) → UnifiedServerWorker (1, single Tokio event loop) + CpuWorker (1, bounded transforms). Workers are NOT process-per-tenant. `--worker` flag spawns a legacy `BaseWorkerProcess` unused for HTTP.

**Root crate ownership**: tracked in `architecture/root_module_ledger.md`. Prefer dedicated `synvoid-*` crates over root `synvoid::` paths unless the ledger says `keep_app_root`.

### Key Architecture Documents

| Document | Description |
|----------|-------------|
| `architecture/overview.md` | Bird's eye view, process model, feature gates, module index |
| `architecture/plugin_runtime_sandbox.md` | Plugin trust tiers, manifest schema, default-deny capabilities, signing policy |
| `architecture/root_module_ledger.md` | Root module ownership (keep_app_root / split_required / legacy) |
| `architecture/worker_data_plane_composition_root.md` | Composition boundary rules for request-path vs root |
| `architecture/http_request_pipeline.md` | 7-stage HTTP pipeline shared by HTTP/1 and HTTP/3 |
| `architecture/mesh_trust_domains.md` | 7 trust domains, CanonicalTrustReader, trust invariants |
| `architecture/block_store.md` | BlockStore architecture, persistence, snapshot export, peer cursors |
| `architecture/dns_config_runtime_matrix.md` | DNS config field inventory with runtime status, defaults, and wiring |
| `architecture/release_profile_matrix.md` | Compilation profiles, feature gate classifications, platform coverage |
| `docs/RELEASE.md` | Release lifecycle, versioning policy, build profiles, hotfix, deprecation |

## Known Issues

- `src/admin/alerting/mod.rs:349` — Email alerting is a stub (logs, returns Ok).
- `spin` idle instance eviction never cleans up old UUID entries (plan DOC-L7).
- `wasmtime` 40.0.4 (via yara-x) has known CVEs but only used for YARA compilation, not wasm sandbox — mitigated by `[patch.crates-io]` for direct dep. 11 advisory ignores in `deny.toml` with re-audit dates 2026-10-01.
- `synvoid-testkit` has zero consumers — documented boundary policy in `crates/synvoid-testkit/README.md`

