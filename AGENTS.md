# AGENTS.md - Developer Guide for AI Agents

This is the **repository index** for AI agents working on the SynVoid codebase.

## Serialization and Timestamp Standards

We prefer **pure Rust dependencies** over those with C bindings where possible.

| Dependency | Purpose | Why Acceptable |
|------------|---------|----------------|
| **aws-lc-rs** | TLS/crypto | Amazon's Rust crypto, battle-tested |
| **libc** | Unix syscalls | Thin Rust bindings to kernel |
| **windows-sys** | Windows API | Thin Rust bindings to Win32 API |

Confirmed pure Rust: `libinjectionrs`, `bcrypt`

### Serialization and Timestamp Standards

1. **Prefer Postcard over JSON** for distributed state (DHT, Mesh, Persistence)
2. **Use Typed Structs** with `Archive`, `RkyvSerialize`, `RkyvDeserialize`, `Serialize`, `Deserialize` — never `serde_json::Value`
3. **Unix Timestamps (u64)** for all persisted/network timestamps. Use `crate::mesh::safe_unix_timestamp()` or `crate::utils::current_timestamp()`. Use `.saturating_sub()` for durations.
4. **Binary Signatures** operate on `&[u8]`. Use `MeshMessageSigner::sign/verify` with postcard for stable signable bytes.
5. **Base64 Encoding**: Always `URL_SAFE_NO_PAD` for mesh/DHT data.

### Security Patterns

- **Constant-Time Comparison**: Always use `subtle::ConstantTimeEq` for secrets, tokens, keys, MACs
- **Trusted Signer Default Deny**: Non-global nodes require valid trusted signer for threat messages
- **Genesis Key Default Deny**: Empty `authorized_genesis_keys` should deny by default
- **Edge Node PoW**: Both `pow_nonce` AND `pow_public_key` required together
- **File Permissions**: Set `0o600` on private key files

### Threat-Intel Enforcement Rules

When editing request/WAF paths or adding new threat-intel consumers:

1. **Never enforce from raw lookups** — `lookup_local_indicator()`, `lookup_local_indicator_by_ip()`, and `lookup_threat_indicator_in_dht()` are compatibility/debug APIs. They must not be consumed by enforcement paths.
2. **Use strict wrappers for enforcement** — `lookup_*_policy_strict` is mandatory for any code that makes enforcement decisions (block, rate-limit, WAF deny).
3. **Local-origin detection is first-party** — `announce_local_block`, `announce_local_rate_limit`, and similar local-origin calls are exempt from the enforcement gate because they represent first-party evidence, not remote advisory consumption.
4. **New threat types requiring enforcement** must use `ThreatIntelConsumerKind::Enforcement` and require `ThreatIntelConsumerAction::PermitAction` before mutating block-store, rate-limit, or WAF state.
5. **WAF request code consumes BlockStore**, not `ThreatIntelligenceManager` directly. This boundary is correct — mesh enforcement populates BlockStore, WAF reads it. Do not add raw advisory lookups to the request hot path.
6. **New block-store writes must set meaningful provenance** — Use `block_ip_with_provenance` with an appropriate `BlockProvenanceKind`. Do not use `LegacyUnknown` for new production enforcement paths unless compatibility requires it.
   - `ErasedBlockStore` now exposes `block_ip_with_provenance` for type-erased WAF paths.
   - `LegacyUnknown` is acceptable only for: serde/default backward compat, legacy `BlockEntry::new`/`BlockStore::block_ip` compatibility paths, tests, and mock/default trait implementations.
   - **Manual enforcement provenance**: Admin manual block writes use `AdminManual`, supervisor manual blocks use `SupervisorManual`, supervisor blocklist sync uses `SupervisorSync`. Manual/supervisor paths bypass threat-intel policy gates (authority from operator/control-plane). Do not use `LegacyUnknown` for new manual/supervisor writes. Admin/debug responses should expose provenance.
7. **Manual unban responses must reflect actual state mutation** — No admin unban path may report `success: true` without actually removing a block entry or explicitly documenting the no-op behavior. Use `unblock_ip()` or `unblock_mesh_id()` return value to determine success. For mesh-ID unban, call `unblock_mesh_id()` for the specific mesh ID (not the sentinel IP). Unban is local-only today; do not imply mesh propagation in responses. Mesh-ID blocks are first-class and concurrent — unblocking one mesh ID does not affect others.
8. **Mesh-ID blocks are control-plane/admin scoped only (Iteration 51, Outcome A)** — `RequestContext`, `WafContext`, and all WAF trait signatures lack a mesh identity field. External HTTP clients do not present mesh credentials. Therefore `is_mesh_id_blocked()` must never be called in WAF/request/proxy/HTTP/3 code. A mechanical guardrail test (`tests/mesh_id_boundary_guard.rs`) enforces this boundary. If request-path mesh-ID enforcement is desired in the future (Outcome B), a trusted `mesh_identity: Option<AuthenticatedMeshIdentity>` field must first be added to the request context and populated at a composition root without using untrusted HTTP headers.
9. **Consumer actionability audit (Iteration 54) + function-level guardrail (Iteration 55)** — Every threat-intel consumer is inventoried and classified in `architecture/threat_intel_consumer_actionability.md`. Enforcement consumers must use `evaluate_incoming_threat_policy` or `classify_consumer_action` with `PermitAction`. Raw lookup APIs (`lookup_local_indicator`, `lookup_local_indicator_by_ip`, `lookup_threat_indicator_in_dht`) are diagnostic-only and must not be consumed by enforcement paths. The `diagnostic_` prefix aliases (`diagnostic_lookup_local_indicator`, etc.) are provided for explicit diagnostic usage. `ShadowOnly` paths never mutate enforcement state. `LegacyUnknown` is not used for new threat-intel blocklist writes. Threat-intel enforcement uses `MeshThreatIntelPolicyGated` provenance. **Iteration 55**: `threat_intel.rs` is no longer globally allowlisted for raw lookups — the guardrail uses function-level allowlisting. Enforcement functions (`handle_incoming_threat`, `_after_policy_permit` helpers) are denylisted from raw lookups. Guardrail test: `tests/threat_intel_consumer_actionability_guard.rs`.

### When NOT to use Constant-Time Comparison

The `security_challenge.rs:196` uses simple `!=` comparison. This is CORRECT for puzzle verification because:
- The `expected_solution` is publicly known challenge data, not a secret
- Timing side-channels don't matter when verifying publicly-known values
- **Only use `ConstantTimeEq` for actual secrets**: keys, MACs, auth tokens, passwords

### Verification Commands

```bash
cargo test --lib --no-run    # Verify tests compile
cargo test --lib <test_name> # Run targeted test
cargo test --test integration_test
cargo test --test security_regression  # Security regression tests
cargo test --test http3_waf_boundary_guard  # HTTP/3 WAF boundary guard
cargo test --test threat_intel_boundary_guard  # Threat-intel boundary guard
cargo test --test mesh_id_boundary_guard  # Mesh-ID enforcement boundary guard
cargo test --test mesh_forced_cleanup --features mesh,dns  # includes iter77_* behavioral tests
cargo test --test background_task_ownership_guard
cargo test --test mesh_task_ownership_guard --features mesh,dns  # includes iter77_* guardrails
cargo test --test composition_root_behavioral --features mesh,dns  # composition-root behavioral tests (Phase 21-23)
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns
cargo test --test mesh_http_framing --features mesh,dns
cargo test -p synvoid-mesh --features mesh auxiliary  # mesh auxiliary task unit tests
cargo test --test mesh_lifecycle_tests         # Mesh lifecycle state machine and task group tests
cargo test --test mesh_startup_rollback        # Mesh startup rollback behavioral tests
cargo test --test worker_supervision_control_flow --features mesh,dns  # Worker supervision + mesh exit tests (146 tests: 84 original + 7 shutdown coordination + 58 behavioral)
cargo test -p synvoid --lib worker::mesh_supervision --features mesh
cargo test -p synvoid-mesh --features mesh lifecycle  # Mesh lifecycle unit tests
cargo test -p synvoid-mesh --features mesh task_group  # Mesh task group unit tests
cargo test -p synvoid-mesh --features mesh startup  # Mesh staged startup/rollback tests
cargo test -p synvoid-mesh --features mesh shutdown  # Mesh truthful shutdown report tests
cargo test -p synvoid-mesh --features mesh worker_integration  # Mesh worker integration tests
cargo test -p synvoid-mesh --features mesh dht_routing_initialization  # DHT routing initialization tests
cargo fmt && cargo clippy --lib -- -D warnings
```

### Architecture Profile Gates

SynVoid supports feature-gated profiles. Verify compilation for each profile:

```bash
# Core profile (minimal)
cargo check --no-default-features

# Mesh profile
cargo check --no-default-features --features mesh

# DNS profile
cargo check --no-default-features --features dns

# Full profile
cargo check --no-default-features --features mesh,dns
```

**Note**: All profiles compile successfully as of 2026-05-04:
- Core profile (`--no-default-features`) ✅
- Mesh profile (`--no-default-features --features mesh`) ✅
- DNS profile (`--no-default-features --features dns`) ✅
- Full profile (`--no-default-features --features mesh,dns`) ✅

## Root Crate Ownership

Root crate ownership is tracked in `architecture/root_module_ledger.md`. New domain code should prefer dedicated `synvoid-*` crates over root `synvoid::` compatibility paths unless the ledger marks the root module as `keep_app_root`.

The root facade boundary guard test prevents domain crates under `crates/` from importing the root `synvoid` crate:

```bash
cargo test --test root_facade_boundary_guard
```

## Known File Path Corrections

| Wrong Path | Correct Path |
|------------|--------------|
| `src/http/client.rs` | `src/http_client/mod.rs` |
| `src/http/shared_handler.rs` | `crates/synvoid-http/src/shared_handler.rs:304` (contains `collect_body_with_chunk_waf` and `stream_body_with_waf`) |
| `src/mesh/proxy.rs` | `crates/synvoid-mesh/src/mesh/proxy.rs` (mesh code extracted to crate; re-exported via `src/mesh/mod.rs`) |
| `src/mesh/transport.rs` | `crates/synvoid-mesh/src/mesh/` (now in transport_core/ and transports/ subdirectories) |
| `src/mesh/raft/state_machine.rs` | `crates/synvoid-mesh/src/mesh/raft/state_machine.rs` |
| ConfigManager location | `crates/synvoid-config/src/lib.rs:114` (not `main_config.rs`) |
| `src/overseer/`, `src/master/`, `src/startup/master.rs` | `src/supervisor/` (consolidated 2026) |
| `TunnelBackend` at `src/tunnel/upstream.rs` | `crates/synvoid-tunnel/src/router.rs:199` (moved to dedicated crate; re-exported via `src/tunnel/mod.rs`) |
| `architecture/tunnel.md` | Does not exist — tunnels documented in `networking_deep_dive.md` |
| `architecture/admin.md` | Does not exist — use `admin_deep_dive.md` |
| `architecture/manual_enforcement_ownership.md` | New — Iteration 42 admin/supervisor enforcement ownership audit |
| `src/worker/mod.rs` (CPU offload) | `src/worker/cpu_task/` (split 2026-06) — see `mod.rs`, `state.rs`, `metrics.rs`, `payload.rs`, `dispatch.rs`, `connection.rs`, `yara.rs` |
| `src/worker/unified_server.rs` (monolithic) | `src/worker/unified_server/` (split 2026-06) — see `state.rs`, `services.rs`, `init_apps.rs`, `init_waf.rs`, `init_mesh.rs`, `init_runtime.rs`, `init_config.rs`, `lifecycle.rs` |
| `src/app_server/granian.rs` | `crates/synvoid-app-server/src/granian.rs` |
| `DhtKeyPolicy` | `crates/synvoid-mesh/src/mesh/dht/key_policy.rs` (new module) |
| `SignedRaftAttestation` | `crates/synvoid-mesh/src/mesh/peer_auth.rs` (v2: binds to value digest via `value_hash`) |
| `ConsensusTransport` trait | `crates/synvoid-mesh/src/mesh/raft/consensus.rs` (new module) |
| `AuthorityFreshnessConfig` | `crates/synvoid-mesh/src/mesh/config.rs` (new struct) |
| `store_record(record, reputation, is_local_origin)` | Removed — use `store_local_record()` or `store_record_from_ingress()` |
| `handle_sync_response()` (unsigned sync path) | Removed — unsigned compat path now inline in `record_store_message.rs` using `store_record_from_ingress()` with `envelope_signature_valid=false` |
| `src/http3/server.rs` | `crates/synvoid-http3/src/server.rs` (moved to dedicated crate 2026-06) |
| `src/http3/server.rs` (Http3WafBackend trait) | `crates/synvoid-http3/src/lib.rs` (trait owns the WAF abstraction boundary) |
| `src/worker/unified_server/passthrough_validation.rs` | New module — TLS passthrough classification and validation (extracted from mod.rs) |
| `crates/synvoid-http-client/src/lib.rs` (monolithic pre-iter6) | Split into focused modules (client.rs, tls.rs, pool.rs, unix.rs, request.rs, response.rs) + erased_pool/streaming_waf_body; lib.rs is now thin public facade with re-exports only |
| `crates/synvoid-mesh/src/mesh/threat_intel_policy.rs` | Iteration 18 — threat-intel policy composition helper; Iteration 19 — first consumer migration via `ThreatIntelligenceManager::evaluate_indicator_actionability`; Iterations 20-21 injection + second read path; Iteration 22 — shared `is_policy_actionable` helper, policy-composed documented as preferred for new actionability-sensitive reads, raw as compatibility/diagnostic; Iteration 23 — call-graph reassessment selected Outcome A, pausing the track with raw lookups still compatibility/diagnostic; Iteration 24 — verification pass confirmed the helper and focused mesh checks; Iterations 25-26 — worker-root ownership plus an explicit root-side helper for constructing `ThreatIntelPolicyContext`; Iteration 28 — Supervisor exports `CanonicalTrustSnapshot` via IPC to workers, completing the export path; Iteration 33 — shadow/observability consumers (`ThreatIntelPolicyShadowDecision`, `ThreatIntelPolicyDecisionClass`, `ThreatIntelPolicyShadowDisagreement`), `evaluate_indicator_policy_shadow()`, admin endpoints for diagnostics and metrics; Iteration 34 — consumer enforcement migration (`classify_consumer_action`, strict lookup wrappers, enforcement gate in `handle_incoming_threat`), new re-exported types (`ThreatIntelConsumerKind`, `ThreatIntelConsumerAction`, `ThreatIntelDeferredMode`); Iteration 35 — `classify_consumer_action` now dispatches on `ThreatIntelDeferredMode` (FailOpenNoAction/FailClosedNoAction → SuppressAction, ShadowOnly → ShadowOnly for Deferred decisions) |
| `BlocklistEvent` type | `crates/synvoid-core/src/block_store.rs` (not a separate module) |
| `architecture/blocklist_reconciliation.md` | New — Iteration 48 offline-peer catchup architecture |
| `blocklist_target_state.json` | New — Iteration 52 persisted target state file |
| `architecture/threat_intel_consumer_actionability.md` | New — Iteration 54 consumer actionability inventory |
| `tests/threat_intel_consumer_actionability_guard.rs` | New — Iteration 54 consumer actionability guardrail test |
| `src/worker/task_registry.rs` | New — Iteration 61 worker task lifecycle management |
| `MeshTaskGroup` | `crates/synvoid-mesh/src/mesh/task_group.rs` (new module) |
| `MeshLifecycleState` | `crates/synvoid-mesh/src/mesh/lifecycle.rs` (new module) |
| `StagedPeerResource` | `crates/synvoid-mesh/src/mesh/lifecycle.rs` (Iteration 71, expanded Iteration 72) |
| `StagedTopologySnapshot` | `crates/synvoid-mesh/src/mesh/lifecycle.rs` (Iteration 72) |
| `PeerSessionTask` | `crates/synvoid-mesh/src/mesh/lifecycle.rs` (Iteration 72) — now has `generation` field wired from `stage.next_session_generation()` (Phase 18) |
| `PeerSessionExitReason` | `crates/synvoid-mesh/src/mesh/lifecycle.rs` (Iteration 73) |
| `PeerSessionExit` | `crates/synvoid-mesh/src/mesh/lifecycle.rs` (Iteration 73) |
| `DhtPeerSnapshot` | `crates/synvoid-mesh/src/mesh/lifecycle.rs` (Iteration 73, expanded Iteration 74 — all PeerContact fields; Iteration 75 — stores `pub contact: PeerContact` clone) |
| `DhtPeerMutation` | `crates/synvoid-mesh/src/mesh/lifecycle.rs` (Iteration 73, simplified Iteration 74: `Previous` replaces `Replaced`+`UpdatedInPlace`) |
| `FailedStartupResidue` | `crates/synvoid-mesh/src/mesh/lifecycle.rs` (Iteration 73) |
| `AuxiliaryTask` | `crates/synvoid-mesh/src/mesh/lifecycle.rs` (Iteration 73) |
| `AuxiliaryTaskExit` | `crates/synvoid-mesh/src/mesh/lifecycle.rs` (Iteration 74 — auxiliary task completion events) |
| `RecoveryVerification` | `crates/synvoid-mesh/src/mesh/lifecycle.rs` (Iteration 73) |
| `RecoveryReport` | `crates/synvoid-mesh/src/mesh/lifecycle.rs` (Iteration 74 — recovery accounting) |
| `RollbackReport` | `crates/synvoid-mesh/src/mesh/lifecycle.rs` (expanded Iteration 71) |
| `rollback_and_return()` | `crates/synvoid-mesh/src/mesh/transport.rs` (Iteration 71) |
| `verify_rollback_complete()` | `crates/synvoid-mesh/src/mesh/transport.rs` (Iteration 71) |
| `ManagedMeshService` | `crates/synvoid-mesh/src/mesh/worker_integration.rs` (new module) |
| `architecture/mesh_transport_lifecycle.md` | New — Iteration 68 mesh lifecycle task inventory |
| `PeerStreamDrainReport` | `crates/synvoid-mesh/src/mesh/lifecycle.rs` (Iteration 75 — stream drain statistics) |
| `restore_and_verify_peer_logical_state()` | `crates/synvoid-mesh/src/mesh/transport.rs` (Iteration 75 — combined restore + verify) |
| `stop_staged_peer_activity()` | `crates/synvoid-mesh/src/mesh/transport.rs` (Iteration 75 — teardown before restoration) |
| `PeerSessionStopOutcome` | `crates/synvoid-mesh/src/mesh/lifecycle.rs` (Iteration 76 — cooperative-drain vs forced-parent-abort classification) |
| `ForceRestoreError` | `crates/synvoid-mesh/src/mesh/dht/routing/bucket.rs` (Iteration 76 — safe DHT force restoration) |
| `ForceRestoreContactError` | `crates/synvoid-mesh/src/mesh/dht/routing/table.rs` (Iteration 76 — propagated from bucket layer) |
| `force_abort_peer_session()` | `crates/synvoid-mesh/src/mesh/transport.rs` (Iteration 77 — cooperative abort + await helper) |
| `classify_stream_join()` / `classify_forced_stream_join()` | `crates/synvoid-mesh/src/mesh/transport_peer.rs` (Iteration 77 — join result classification) |
| `read_exact_with_timeout()` | `crates/synvoid-mesh/src/mesh/transport_peer.rs` (Iteration 77 — deadline-aware reads) |
| `peer_stream_drain_timeout_secs` | Config (Iteration 77 — stream drain timeout, default 5s) |
| `max_concurrent_datagram_handlers` | Config (Iteration 77 — bounded datagram handler concurrency, default 32) |
| `extract_host_from_http` / `extract_path_from_http` / `extract_method_from_http` | Removed in Iteration 80 — use `ParsedHttpRequestMeta` instead |
| `src/worker/mesh_supervision.rs` | New — Iteration 82 worker mesh supervision policy, status, and decision types |
| `MeshSupervisionConfig` | `crates/synvoid-config/src/mesh.rs` (Iteration 84 — TOML-deserializable config for supervision policy) |
| `build_mesh_supervision_policy()` | `src/worker/mesh_supervision.rs` (Iteration 84 — derives policy from config) |
| `start_mesh_generation()` | `src/worker/mesh_supervision.rs` (Iteration 84 — async startup helper) |
| `MeshConfigurationInvariant(String)` | `src/worker/task_registry.rs` (Iteration 86 — `WorkerShutdownCause` variant for transport/policy config mismatches) |
| `validate_mesh_runtime_inputs()` | `src/worker/unified_server/init_mesh.rs` (Iteration 86 — validates mesh runtime configuration before construction) |
| `run_yara_broadcast_loop()` | `src/worker/unified_server/init_mesh.rs` (Iteration 86 — extracted YARA broadcast loop with deadline-bounded drain) |
| `MeshBackgroundTaskSpec` | `crates/synvoid-mesh/src/mesh/lifecycle.rs` (Iteration 86 — declarative spec for topology/DHT background tasks) |
| `build_background_tasks()` | `crates/synvoid-mesh/src/mesh/topology.rs` and `crates/synvoid-mesh/src/mesh/dht/routing/manager.rs` (Iteration 86 — replaces `start_background_tasks()`) |
| `register_background_specs()` | `crates/synvoid-mesh/src/mesh/task_group.rs` (Iteration 86 — registers background task specs after mesh startup) |
| `MeshGenerationSupport` | `src/worker/unified_server/mod.rs` (Iteration 87 — worker-owned support-generation type) |
| `TaskSubsetCleanupReport` | `src/worker/task_registry.rs` (Iteration 88 — task cleanup report with exits and not-found IDs) |
| `SupportStopContext` | `src/worker/unified_server/mod.rs` (Iteration 88 — context enum for stopping mesh support tasks) |
| `MeshSupportStopReport` | `src/worker/unified_server/mod.rs` (Iteration 88 — report from `stop_mesh_generation_support()`) |
| `stop_mesh_generation_support()` | `src/worker/unified_server/mod.rs` (Iteration 88 — cooperative then forced cleanup helper) |

## Data-Plane Composition Root Boundary

**Iteration 58**: Request-path modules must consume narrow traits/capabilities, not concrete infrastructure.
**Iteration 59**: Guardrail tightened with role-based file classification, three token groups, and scoped exceptions. WAF blocklist methods documented as no-op compatibility shims. `check_dht_threat_lookup()` and `get_threat_intel()` removed from `WafCore` (dead code).
**Iteration 60**: `src/worker/unified_server/` is actively scanned via `boundary_scan_roots()`, not broadly exempt. Unknown files under mixed-role directories fail closed (`Unclassified` role). Every boundary exception must be live-audited. Exception liveness test prevents stale exceptions from authorizing regressions.

### Allowed Dependency Directions

| Layer | May Own/Import |
|-------|---------------|
| **Composition roots** (`src/worker/unified_server/`, `src/server/mod.rs`, `src/supervisor/`, `src/main.rs`) | Concrete `BlockStore`, `ThreatIntelligenceManager`, mesh/DHT/Raft handles, IPC, metrics, config |
| **Request path** (`src/waf/`, `src/proxy/`, `src/http/`, `crates/synvoid-waf/`, `crates/synvoid-proxy/`, `crates/synvoid-http3/`, `crates/synvoid-http/`) | Narrow traits (`BlockListStore`, `WafProcessor`, `Http3RequestWaf`), config snapshots, request context |
| **Control-plane** (`crates/synvoid-mesh/`, `crates/synvoid-block-store/`) | Full infrastructure internals |

### Key Invariant

> Composition roots own concrete infrastructure; request-path modules consume capabilities.

### Guardrail Test

```bash
cargo test --test data_plane_composition_boundary_guard
```

The guardrail uses `BoundaryRole` enum to classify each file individually. `src/worker/unified_server/` files are classified per-file (most are `CompositionRoot`, `passthrough_validation.rs is `SharedTypes`). Unknown files under mixed-role directories fail closed (`Unclassified` role). Three token groups catch violations: `CONSTRUCTION_TOKENS` (constructors), `TYPE_IMPORT_TOKENS` (concrete type imports), `CONTROL_PLANE_OP_TOKENS` (blocklist/threat-intel operations). Pass-through types (`MeshTransportManager`, `MeshBackendPool`) have scoped `BoundaryException` entries with documented reasons. Exception liveness test ensures every exception corresponds to a live source occurrence.

### WAF Blocklist No-Op Shims

WAF blocklist methods (`check_early`, `block_ip_for_honeypot`, `block_ip_with_threat_intel`) are **API-compatibility shims** — they do not mutate block store state. Blocklist writes occur via dedicated local/control-plane enforcement paths. `check_dht_threat_lookup()` and `get_threat_intel()` were removed in Iteration 59 (dead code referencing concrete `ThreatIntelligenceManager` on request path).

### How to Add a New Capability Safely

1. Define a narrow trait in `crates/synvoid-waf/src/traits.rs` or `crates/synvoid-core/`
2. Implement the trait on a concrete type in a composition root
3. Pass `Arc<dyn YourTrait>` to request-path modules
4. Never pass the concrete type directly to request-path code

## Modular Agent Guidance

Agent guidance is **modularized** to reduce context pollution. Each module has its own `AGENTS.override.md` that contains specialized handling for that subsystem.

| Module | Override File | Purpose |
|--------|--------------|---------|
| DNS (DNSSEC, TSIG) | [`src/dns/AGENTS.override.md`](src/dns/AGENTS.override.md) | DNS server, DNSSEC, TSIG patterns |
| WAF (Rule Matching) | [`src/waf/AGENTS.override.md`](src/waf/AGENTS.override.md) | WAF engine, attack detection |
| HTTP Server | [`src/http/AGENTS.override.md`](src/http/AGENTS.override.md) | HTTP request handling |
| HTTP Client | [`src/http_client/AGENTS.override.md`](src/http_client/AGENTS.override.md) | Upstream proxy, connection pooling |
| HTTP/3 Server | [`src/http3/AGENTS.override.md`](src/http3/AGENTS.override.md) | HTTP/3 QUIC handling |
| Plugin/WASM | [`src/plugin/AGENTS.override.md`](src/plugin/AGENTS.override.md) | WASM plugin runtime |
| Upstream Proxy | [`src/proxy/AGENTS.override.md`](src/proxy/AGENTS.override.md) | Proxy routing, cache keys |
| Config | [`src/config/AGENTS.override.md`](src/config/AGENTS.override.md) | Configuration patterns |
| Admin API | [`src/admin/AGENTS.override.md`](src/admin/AGENTS.override.md) | Admin API patterns |
| Auth | [`src/auth/AGENTS.override.md`](src/auth/AGENTS.override.md) | Authentication patterns |
| Platform/Systems | [`src/platform/AGENTS.override.md`](src/platform/AGENTS.override.md) | Platform abstraction, IPC, sandboxing |
| Worker | [`src/worker/AGENTS.override.md`](src/worker/AGENTS.override.md) | UnifiedServerWorker, CpuWorker, CPU offload |
| Skills | [`skills/AGENTS.override.md`](skills/AGENTS.override.md) | Skill file documentation |

> **Note**: `crates/synvoid-mesh/src/mesh/transport_peer.rs` now contains the `PrefixReader` internal adapter (Iteration 80) for prefix-aware chunked parsing, used by `read_chunked_http_response_body()`. It also houses `HttpVersion`, `HttpResponseBodyEncoding`, `read_http_response_sequence()`, and `header_contains_token()`.

## Multi-Process Architecture

SynVoid uses a multi-process architecture designed for **high scalability (1M+ RPS)** with **millions of tenants**:

### Process Hierarchy

| Process | Flag | Purpose | Default Count |
|---------|------|---------|---------------|
| **Supervisor** | (default) | Manages worker lifecycle, upgrades, health monitoring, and control-plane APIs | 1 |
| **UnifiedServerWorker** | `--unified-server-worker` | Handles HTTP/HTTPS/HTTP3 + WAF + proxy | 1 |
| **CpuWorker** | `--cpu-worker` (`--static-worker` compat) | Bounded heavy transforms: minification, compression, image work, scans | 1 |
| **BaseWorkerProcess** | `--worker` | Legacy raw TCP/UDP proxy (deprecated, unused for HTTP) | configurable |

### UnifiedServerWorker: Latency-Sensitive Data Plane

**The unified worker uses a single Tokio async event loop** which is far more efficient than spawning multiple worker processes:

1. **Tokio's optimization**: Each unified worker runs a Tokio runtime; `worker_threads` controls async scheduling parallelism inside that process. Adding more unified workers is an advanced isolation choice, not the default scaling strategy.

2. **Millions of tenants**: We cannot use process-per-tenant isolation (too many processes). All tenants share the same async event loop with O(1) domain-based routing.

3. **Scaling approach**: Tune `tcp.worker_pool_size` for accept throughput and `worker_threads` for runtime parallelism. Use CPU offload workers for bounded heavy transforms. **Do NOT treat `unified_server_workers` as a general-purpose scaling knob**.

### BaseWorkerProcess (Legacy - Not Used for HTTP)

The `--worker` flag spawns `BaseWorkerProcess` which receives a dedicated port. However:
- **No HTTP handler exists** for this mode in `main.rs`
- The code path exists but is **never invoked** for normal HTTP traffic
- It may be current unified design or for raw TCP/UDP proxy scenarios
- The admin API `/system/workers/scale` only scales `BaseWorkerProcess` count
- **Requires investigation** to determine if it should be removed or completed

### Reference Documents

- [`docs/adr/ADR-003-unified-worker-process.md`](docs/adr/ADR-003-unified-worker-process.md) — ADR for unified worker architecture
- [`src/worker/unified_server/mod.rs`] — Main unified server implementation

## Key Codebase Facts

### Dependency Vulnerability Status

**Last Updated: 2026-05-25**

| Dependency | Version | Vulnerabilities | Status |
|------------|---------|-----------------|--------|
| **wasmtime** (direct) | 42.0.2 (patched) | 2 CRITICAL sandbox escapes, 8 MODERATE | ✅ Patched via `[patch.crates-io]` |
| **wasmtime** (via yara-x) | 40.0.4 | 2 CRITICAL, 8 MODERATE | ⚠️ Manageable - yara-x uses wasmtime for YARA compilation, not wasm sandbox |
| **yara-x** | 1.15.0 | None directly | ⚠️ Update blocked by minify-html/bumpalo conflict |
| **hickory-proto** | 0.26.1 | NSEC3 DoS, O(n²) compression | ✅ Patched (>=0.26.1) |
| **libcrux-ml-dsa** | 0.0.9 | AVX2 signature verification edge case | ✅ Patched (>=0.0.9) |

**Notes:**
- yara-x 1.16.0 is available but cannot be updated due to `bumpalo` version conflict between `wasmtime@43.0.1` (yara-x dep) and `oxc_allocator@0.95.0` (minify-html dep)
- The wasmtime vulnerabilities require aarch64 + Spectre mitigations disabled to exploit - default config is safe
- yara-x's wasmtime is used for YARA pattern compilation, NOT wasm sandbox execution, reducing attack surface

### Known Open Issues

| Bug ID | Location | Issue | Status |
|--------|----------|-------|--------|
| BUG-CORS-1 | `src/admin/mod.rs` | CORS config dropped (underscore prefix) — dead code removed, but nested `/api` routes may still lack CORS layer | Known - may be intentional (Admin API uses bearer tokens) |

## Known Deferred Items

These items require significant architectural work and are correctly deferred:

| ID | Issue | Reason |
|----|-------|--------|
| HTTP2-POOL | ErasedHttpClient HTTP/2 pooling | `Http2PooledConnection` is empty stub - hyper-util API requires background task management per connection |
| LEGACY-STORE | `RECORD_STORE_GLOBAL` removal | `RECORD_STORE_GLOBAL` is now legacy/fallback only — all production paths use explicit injection via `DataPlaneServices`. Removal requires threading injection through remaining callers. |

Detailed documentation lives in `skills/` directory. See [`skills/AGENTS.override.md`](skills/AGENTS.override.md) for the full index.

## Codebase Quick Reference

### Critical Security Functions
- **Constant-time comparison**: Always use `subtle::ConstantTimeEq` for secrets
- **File permissions**: Set `0o600` on private key files
- **CSRF validation**: Uses `ct_eq()` at `src/admin/state.rs:736`
- **Session ID comparison**: Not constant-time, but acceptable (high-entropy random 32-byte values)

### Module Key Facts
- **HTTP Client**: ownership details live in `src/http_client/AGENTS.override.md` and `architecture/http_shared.md`
- **MeshProxy**: `crates/synvoid-mesh/src/mesh/proxy.rs` - key routing component not in overview
- **BackendType**: `crates/synvoid-proxy/src/router.rs:66-78` has 11 variants
- **SAFE_HEADERS**: `crates/synvoid-proxy/src/cache.rs:104` has 28 headers
- **ConfigManager**: `crates/synvoid-config/src/lib.rs:114`
- **DhtSyncRequest**: `crates/synvoid-mesh/src/mesh/transport_dht.rs` - signed by default with a config-controlled unsigned compatibility fallback; node binding enforced in transport; envelope signature verifies `(request_id, node_id, local_root_hash, timestamp, nonce)`.
- **DhtSyncResponse**: `crates/synvoid-mesh/src/mesh/dht/record_store_message.rs` - signed: envelope signature verified, signer-to-node binding enforced, record-set digest checked, stores via `store_record_from_ingress()`. Unsigned compat: stores via `store_record_from_ingress()` with `envelope_signature_valid=false` and explicit warning log. Deprecated `handle_sync_response()` removed.
- **DhtAntiEntropyRequest**: `crates/synvoid-mesh/src/mesh/transport_peer.rs` - node binding enforced, `signer_public_key` now verified against authorized global node keys; **envelope signature also verified** (✅ MR-4 fixed). Both request and response verify envelope signatures via `verify_dht_anti_entropy_request_envelope_signature()` / `verify_dht_anti_entropy_response_envelope_signature()` in `dht/signed.rs`.
- **DhtRecordPush**: `crates/synvoid-mesh/src/mesh/dht/signed.rs` - signature field exists and is enforced; **envelope signature also verified** (✅ MR-4 fixed). Push ingress is governed by the canonical ingress gate when `DhtIngressPolicyContext` is configured (Iteration 14/15).
- **DhtKeyPolicyTable**: `crates/synvoid-mesh/src/mesh/dht/key_policy.rs` - centralizes key family authority policies for DHT ingress validation. Now has `classify_key_authority_with_canonical_reader()` (Iteration 11) that uses `CanonicalTrustReader` for canonical trust questions while preserving advisory DHT mechanics. **DnsZone** uses `RaftOrQuorumGlobal` authority with `remote_writes_allowed=false` — DNS zone records can only be written via Raft consensus or quorum attestation, not via direct DHT capability. Seam + adapter added in Iteration 13; carrier + attachment for direct client Push/Announce completed in Iteration 14 via `RecordStoreManager` (see `architecture/mesh_trust_domains.md`). Ingress gate is active for all configured Push/Announce paths; disabled context preserves legacy. **Track complete** (Iteration 15) — see `architecture/mesh_trust_domains.md`.
- **validate_dht_key_authority_for_ingress**: `crates/synvoid-mesh/src/mesh/dht/key_policy.rs` — adapter mapping `classify_key_authority_with_canonical_reader` decisions to `Result<(), DhtIngressPolicyError>` for ingress callers. Seam + adapter added in Iteration 13; carrier + attachment for direct Push/Announce completed in Iteration 14 via `DhtRecordIngressContext.policy_context` + `DhtIngressPolicyContext` (see `architecture/mesh_trust_domains.md`). Disabled context preserves legacy; configured context enforces accept/reject/defer for canonical-required keys. Only targeted direct-client Push/Announce ingress paths consult the gate (sync replay, local, quorum, Raft paths intentionally untouched). **Track complete** (Iteration 15).
- **DhtRecordIngressContext**: Fields are now private. Access via accessor methods: `peer_id()`, `source_node_id()`, `source_classification()`, `path()`, `requires_quorum_proof()`, `requires_trust_anchor()`, `is_immutable_key()`, `envelope_signature_valid()`, `timestamp()`, `request_id()`, `is_local_origin()`, `policy_context()`. Construction controlled via `new_local()`, `new_remote()`, and builder methods (including `with_policy_context`). Carries optional `DhtIngressPolicyContext` (seam+adapter in Iteration 13; carrier+attachment for direct Push/Announce wired in Iteration 14). Ingress gate is active for configured Push/Announce paths; disabled context preserves legacy. **Track complete** (Iteration 15) — see `architecture/mesh_trust_domains.md`.
- **verify_envelope_signer_binding()**: `crates/synvoid-mesh/src/mesh/dht/signed.rs` — enforces signer-to-node binding for all signed DHT messages on global nodes. `NodePublicKeyResolver` trait provides pluggable key resolution.
- **validate_peer_role()**: `crates/synvoid-mesh/src/mesh/peer_auth.rs:375` — validates node role claims. Now accepts `raft_attestation: Option<&SignedRaftAttestation>` and `allow_v1_raft_attestations: bool` parameters. Edge nodes can validate via value-bound Raft attestation in addition to the traditional quorum-signed org key path. When a `raft_attestation` is provided for an Edge node, it is used exclusively (no fallback to other paths).
- **SignedRaftAttestation**: `crates/synvoid-mesh/src/mesh/peer_auth.rs` - requires cryptographic proof, not just structural attestation. **v2 protocol** binds attestation to value digest (`value_hash` field in `RaftAttestation`, `protocol_version=2`). V1 attestations without `value_hash` are **rejected by default** unless `allow_v1_raft_attestations=true` is set in config.
- **ConsensusTransport**: `crates/synvoid-mesh/src/mesh/raft/consensus.rs` - decouples Raft consensus from mesh transport layer.
- **AuthorityFreshnessConfig**: `crates/synvoid-mesh/src/mesh/config.rs` - defines stale-state behavior for authority records.
- **DHT/Raft Boundary Integration**: ✅ **Complete** — All phases implemented. DHT ingress auth hardening (MR-4) resolved: envelope signatures verified on all DHT message types including `DhtSyncRequest`/`DhtSyncResponse`, `DhtAntiEntropyRequest`/response, and `DhtRecordPush`; signer-to-node binding enforced via `verify_envelope_signer_binding()`; `SignedRaftAttestation` v2 binds to value digest; `DnsZone` requires Raft/quorum (no direct DHT writes); `validate_peer_role()` accepts Raft attestation for Edge nodes; `store_record` is `pub(crate)` with `store_local_record` for local writes; deprecated `handle_sync_response()` removed — unsigned compat path inline uses `store_record_from_ingress()` with `envelope_signature_valid=false`. Canonical trust-domain seam (Iterations 7-15) complete: `CanonicalTrustReader` wired through peer auth, DHT key policy, and direct Push/Announce ingress; ingress gate active for configured paths. Advisory seam (`AdvisoryRecordSource` in `crates/synvoid-mesh/src/mesh/dht/advisory_source.rs`) introduced in Iteration 16 — read-only advisory DHT observations with record-store adapter; Iteration 17 hardened `RecordStoreAdvisorySource` with real-store tests (no service migration). Iteration 18: `evaluate_threat_intel_policy()` composes `AdvisoryRecordSource` + `CanonicalTrustReader` into explicit threat-intel policy decisions. Iteration 19: first consumer migration via `ThreatIntelligenceManager::evaluate_indicator_actionability` — method takes trait objects as parameters, tests cover all policy-composed and legacy paths. Injection seam completed (Iteration 20). Iteration 21: second consumer migration complete — `lookup_local_indicator_policy_composed` and `lookup_local_indicator_by_ip_policy_composed` added with full test coverage. Two threat-intel read paths now use the composed policy seam. Iteration 22: consolidated duplicate decision-to-actionability gating via shared `is_policy_actionable` helper; policy-composed methods documented as preferred for new reads; raw methods documented as compatibility/diagnostic. Iteration 23: call-graph reassessment selected Outcome A, pausing the track before proxy, YARA/WASM, routing, or enforcement hot paths. Iteration 24: verification pass confirmed the helper and focused mesh checks passed. Iterations 25-26 — worker-root ownership plus an explicit root-side helper for constructing `ThreatIntelPolicyContext`. Iteration 27 assessed canonical reader ownership; workers are data-planes without direct access to Raft/EdgeReplicaManager. **Iteration 28: Supervisor exports `CanonicalTrustSnapshot` via IPC to workers** — `EdgeReplicaManager::canonical_trust_snapshot()` produces the snapshot, Supervisor sends `CanonicalTrustSnapshotUpdate` IPC, workers store it and thread the reader into `build_threat_intel_policy_context` when available. **Iteration 31: Canonical snapshot freshness policy** — `CanonicalSnapshotFreshnessPolicy` and `classify_canonical_snapshot()` in `crates/synvoid-mesh/src/mesh/canonical.rs` classify snapshots as fresh (≤60s), stale-within-grace (≤5min), expired, invalid, or missing. `FreshnessBoundCanonicalReader` wrapper enforces freshness on `CanonicalTrustReader` trust decisions. Workers classify snapshot freshness before applying; expired/invalid snapshots are not applied. Default: fresh=60s, stale_grace=5min, stale_mode=FailOpenDefer. Config fields in `AuthorityFreshnessConfig`. 19 new tests covering the freshness matrix. **Iteration 32: Config wiring complete** — `From<&AuthorityFreshnessConfig> for CanonicalSnapshotFreshnessPolicy` conversion in `canonical.rs` with normalization (stale_grace clamped to fresh_max_age). Worker IPC handler reads config from `config.main.tunnel.mesh.authority_freshness` instead of hardcoded defaults. `FailClosedNotActionable` stale mode now installs `FreshnessBoundCanonicalReader` (returns `NotTrusted { ExpiredSnapshot }`) instead of clearing context. Malformed postcard payloads preserve previous valid snapshot/context. 10 new tests. No proxy/YARA/WASM/routing/WAF consumers were migrated in this pass. **Iteration 34: Consumer enforcement migration** — `classify_consumer_action()` classifies consumer intent (ShadowOnly/RawCompatibility/AdvisoryCache/Enforcement) into action (PermitAction/SuppressAction/ShadowOnly/RawCompatibilityOnly); strict lookup wrappers (`lookup_threat_indicator_policy_strict`, `lookup_local_indicator_policy_strict`, `lookup_local_indicator_by_ip_policy_strict`) return `None` when no policy context configured; `evaluate_incoming_threat_policy()` gates enforcement mutations in `handle_incoming_threat` — block_ip, rate limit, suspicious, and ip throttle apply only when policy returns `PermitAction`; when no policy context is configured, enforcement is suppressed by default. `apply_sync` and `handle_hot_threat_gossip` delegate to `handle_incoming_threat` and inherit the enforcement gate. New re-exported types: `ThreatIntelConsumerKind`, `ThreatIntelConsumerAction`, `ThreatIntelDeferredMode`. **Iteration 75**: DHT restoration uses `force_restore_contact()` unconditionally replacing existing contacts; `DhtPeerSnapshot` stores `pub contact: PeerContact` clone; `restore_and_verify_peer_logical_state()` combines restoration + verification; `rollback_and_return()` stores only unresolved peers in residue.
- **DNS Cookie Server**: `src/dns/cookie.rs` - fully wired via `validate_cookie()` in src/dns/server/query.rs:648-662
- **TunnelRouter**: `crates/synvoid-tunnel/src/router.rs:149` - active routing uses `resolve_tunnel_backend()` (TunnelBackend enum at line 199)
- **HickoryRecursor DNSSEC**: `src/dns/resolver.rs:693-702` - uses `ValidateWithStaticKey` when `enable_dnssec=true` (✅ FIXED)
- **HTTP/3 Body Collection**: `crates/synvoid-http3/src/server.rs` - ad-hoc implementation, not using shared_handler
- **BufferPool**: 4 tiers (small/medium/large/jumbo)
- **DataPlaneServicesBuilder**: `src/worker/unified_server/services.rs` - now requires `serverless_manager` in constructor; under mesh, `DataPlaneServices` carries optional `ThreatIntelPolicyContext` and a low-risk apply helper; a root-side helper can build the context from explicit handles; bootstrap leaves canonical as `None`; the Supervisor's `CanonicalTrustSnapshot` arrives via IPC after bootstrap and is applied through `update_threat_intel_policy_context()`; no global fallback in builder
- **WorkerTaskRegistry**: `src/worker/task_registry.rs` — worker-level task lifecycle management with `spawn_critical()`, `spawn_critical_result()`, `spawn_background()`, `spawn_one_shot()`, `child_token()`, `subscribe_exits()`, `shutdown_and_join()`; all spawned futures wrapped with `catch_unwind` for panic detection; immediate critical-task supervision via `broadcast::Receiver<NamedTaskExit>`; `TaskExitReason::UnexpectedCompletion` for pre-shutdown exits; `TaskId` for deduplication; metrics recorded in task wrappers with dedup via `reported_exits` map; integrated into unified-worker runtime (heartbeat, bandwidth persist, IPC loop, server run are registry-owned; Iteration 62–63); `shutdown_started_arc` shared flag (`Arc<AtomicBool>`) for UnexpectedCompletion detection; `begin_shutdown()` records intent without broadcast, `broadcast_shutdown()` sends cancel signal; `WorkerShutdownCause` enum for explicit shutdown classification (`ServerExitedUnexpectedly(NamedTaskExit)`, `ServerStoppedForShutdown`, `CriticalTaskExit`, `SupervisorShutdown`, `SupervisorDisconnected`, `RegistryExitChannelClosed`, `ExternalStop`, `RunningFlagCleared`, `WorkerResize{worker_threads}`, `MeshServiceExit(MeshTaskExit)`, `MeshRestartExhausted { attempts, last_error }`, `MeshConfigurationInvariant(String)`); `exit_code()` method derives process exit code (100 for resize, 1 for nonzero, 0 otherwise); `is_fatal_exit()` helper for fatality policy by task class and shutdown state; `IpcLoopError` for typed IPC loop failures; `LifecycleRequest` channel with oneshot acknowledgement for composition-root coordination (Iteration 65); subscription-before-spawn invariant (Phase 12); Iteration 66: `SupervisionOutcome` typed enum, cause-preserving helpers, `request_lifecycle_transition()`, corrected `should_notify_supervisor()` semantics; Iteration 67: lifecycle transition errors propagated with `?` (no more `let _ =`), supervision loop is side-effect free (selects causes only, no `state.running.stop()`), `begin_coordinated_shutdown()` helper enforces ordering: `begin_shutdown()` → lifecycle ack → stop signals; **Iteration 84**: `TaskClass::OneShot` variant for initialization-only tasks (`spawn_one_shot()`); one-shot clean completion is always expected (not fatal); used for optional mesh startup and DHT routing init
- **MeshTaskGroup**: `crates/synvoid-mesh/src/mesh/task_group.rs` — mesh-local task group managing critical/background/child tasks with unified shutdown propagation and exit reporting; uses `watch::Receiver<bool>` for cancellation, `broadcast::Sender<MeshTaskExit>` for exit events; `spawn_critical()`, `spawn_background()`, `spawn_child()` classify tasks; `begin_shutdown()` signals all; `join_all(timeout)` awaits with bounded timeout and aborts stragglers; `new_with_forward(exit_tx)` creates a group that forwards exit events to a stable broadcast sender on `MeshTransport` (Iteration 69); `new_with_forward_and_id_gen(exit_tx, id_gen)` variant also accepts a `MeshTaskIdGenerator` for globally unique task IDs (Iteration 70)
- **MeshTaskIdGenerator**: `crates/synvoid-mesh/src/mesh/lifecycle.rs` — provides globally unique task IDs across task-group generations. Each `MeshTransport` owns one `Arc<MeshTaskIdGenerator>` and passes it into every new `MeshTaskGroup` via `new_with_forward_and_id_gen()`. Ensures no two exit-channel events share the same ID during process lifetime (Iteration 70)
- **MeshTaskId**: `crates/synvoid-mesh/src/mesh/lifecycle.rs` — u64 task ID allocated via the global `MeshTaskIdGenerator` when available. Monotonically increasing, unique per `MeshTransport` instance lifetime (Iteration 70)
- **MeshLifecycleState**: `crates/synvoid-mesh/src/mesh/lifecycle.rs` — state machine (Stopped/Starting/Running/Stopping/Failed) with validated transitions; `can_start()` allows Stopped only (not Failed); `can_stop()` allows Running only; lifecycle operation lock serializes start/stop transitions to prevent concurrent mutations (Iteration 70)
- **MeshStartupStage**: `crates/synvoid-mesh/src/mesh/lifecycle.rs` — tracks all resources created during a single startup attempt. On success, `commit_startup()` transfers ownership to `MeshTransport` in this order: (1) install staged task group, (2) transition lifecycle to `Running`, (3) set `running_projection`, (4) mark committed. On failure, `rollback_and_return()` cleans up all staged resources (Iteration 70, commit ordering revised Iteration 71). `created_peers: Vec<StagedPeerResource>` tracks exact peer mutations; topology snapshots are stored inside `StagedPeerResource.previous_topology` (Iteration 72). **Hard-rejects non-empty old task group** (Iteration 73) — returns `LifecycleConflict` error, not a warning. **Phase 18**: `next_session_generation()` provides generation values wired to `PeerSessionTask.generation` and `StagedPeerResource.session_generation`.
- **MeshStartupPolicy**: `crates/synvoid-mesh/src/mesh/lifecycle.rs` — wired into `start_with_policy()` (Iteration 70). Controls whether bootstrap failures (seeds, peers, DHT) are fatal or produce a degraded startup report. Default policy makes all bootstrap failures non-fatal (degraded mode). **Iteration 87**: Now has `require_dht_initialization` field for controlling DHT routing initialization requirements
- **DhtRoutingManager**: `crates/synvoid-mesh/src/mesh/dht/routing/manager.rs` — orchestrates DHT queries, bootstrapping, and routing. **Iteration 87**: Initialization (routing table creation and seeding) is now part of the transactional `MeshStartupStage` rather than a separate worker-owned one-shot task. New methods: `is_initialized() -> bool` (returns whether routing table has been created and seeded), `add_peer_checked(node_id, contact)` (adds peer only if initialization is complete). The routing manager is now owned exclusively by `MeshTransport` and initialized during the transactional startup stage (Phase 5.5 in `run_startup_phases`).
- **MeshStartupReport**: `crates/synvoid-mesh/src/mesh/lifecycle.rs` — returned by `start_with_policy()`, contains `degraded_reasons`, `connected_seed_count`, `connected_configured_peer_count`, and `dht_bootstrapped` (Iteration 70). **Iteration 87**: Now has `dht_routing_initialized` field
- **MeshTaskExit**: `crates/synvoid-mesh/src/mesh/lifecycle.rs` — exit metadata with `MeshTaskClass` (CriticalService/RestartableBackground/BoundedChild/OneShotStartup), `MeshTaskExitReason` (CleanCompletion/Cancelled/UnexpectedCompletion/Error/Panic/Aborted); `is_fatal()` true for CriticalService with Error/Panic/UnexpectedCompletion
- **StagedPeerResource**: `crates/synvoid-mesh/src/mesh/lifecycle.rs` — tracks exact peer mutations during startup: `session_id`, `node_id`, `previous_topology: Option<StagedTopologySnapshot>`, `connection_inserted`, `session_task_id: Option<String>`, `dht_mutation: DhtPeerMutation`, `session_generation: u64` (Iterations 71–73).
- **DhtPeerSnapshot**: `crates/synvoid-mesh/src/mesh/lifecycle.rs` — complete snapshot of a DHT peer's routing state before mutation (Iteration 74, Phase 9–10). **Iteration 75**: Stores `pub contact: PeerContact` (a clone of the native `PeerContact`) instead of individual fields, eliminating field drift. Used by `restore_peer()` for lossless DHT restoration via `force_restore_contact()`. `peer_matches_snapshot()` verifies restoration correctness (Phase 11).
- **DhtPeerMutation**: `crates/synvoid-mesh/src/mesh/lifecycle.rs` — enum tracking DHT state mutation for staged peers (Iteration 73, simplified Iteration 74): `None` (no mutation), `Created` (new entry), `Previous(DhtPeerSnapshot)` (prior state existed — covers both replacement and in-place update, Iteration 74). Derived from pre-mutation snapshot comparison in `connect_to_peer`
- **FailedStartupResidue**: `crates/synvoid-mesh/src/mesh/lifecycle.rs` — retained on `MeshTransport` when rollback is incomplete (Iteration 73); consumed and cleared by `recover_failed_state()`. Contains `peers`, `generation`, `runtime_started`, `rollback_errors`
- **AuxiliaryTask**: `crates/synvoid-mesh/src/mesh/lifecycle.rs` — transport-owned auxiliary task (Iteration 73). `AuxiliaryTaskKind::PreflightRoute` for steady-state preflight. `AuxiliaryTaskKind::EdgeReplicaRefresh` for Raft commit notification refresh (Iteration 78). Tracked in `auxiliary_tasks: HashMap<MeshTaskId, AuxiliaryTask>`, aborted and awaited during shutdown/recovery. **Phase 14**: Auxiliary tasks are bound to peer sessions via `session_id` and cancelled during rollback via `cancel_auxiliary_tasks_for_sessions()` — ensures preflight queries do not outlive the peer sessions they were spawned for. **Iteration 78**: Auxiliary tasks are bound to peer sessions via `session_id` and cancelled during rollback via `cancel_auxiliary_tasks_for_sessions()` — ensures preflight queries do not outlive the peer sessions they were spawned for. Edge-replica refresh tasks capped at 8 concurrent (`MAX_CONCURRENT_EDGE_REPLICA_REFRESH`); excess tasks dropped (fire-and-forget). **Iteration 80**: `AuxiliaryRegistryEntry` enum with `Reserved` and `Running` variants used by `spawn_auxiliary_task()` for serialized registration; edge-replica refresh tasks deduplicated by `(namespace, key_id)` via `dedup_key` field on `AuxiliaryTask`. **Iteration 81**: `AuxiliaryRegistryEntry::Reserved` removed — only `Running` variant remains. `spawn_auxiliary_task()` rechecks lifecycle state under `auxiliary_submission_lock`. Shutdown and recovery acquire `auxiliary_submission_lock` before draining auxiliary registry. Lock ordering documented: `lifecycle_op` → `auxiliary_submission_lock` → `auxiliary_tasks`.
- **PeerSessionExitReason**: `crates/synvoid-mesh/src/mesh/lifecycle.rs` — exit classification for peer sessions (Iteration 73): `Clean`, `ConnectionClosed`, `Cancelled`, `Error(String)`, `Panic(String)`, `Aborted`
- **PeerSessionExit**: `crates/synvoid-mesh/src/mesh/lifecycle.rs` — session exit metadata with `session_id`, `node_id`, `reason: PeerSessionExitReason`, `generation: u64`, `stream_drain: PeerStreamDrainReport` (Iteration 73). Generation counter prevents stale completions from removing newer entries. **Session reaper implemented** — `spawn_session_reaper()` runs as a critical background task after lifecycle commit (Phases 15–18); receives `PeerSessionExit` events via `broadcast::Sender<PeerSessionExit>` channel; removes entries from `peer_sessions` when generation matches (or exit generation is 0); skips stale entries with debug logging. **Iteration 74**: cancellation-aware via `tokio::select!` with `session_reaper_shutdown` watch signal; handles awaited **outside** the `peer_sessions` lock (Phase 15); broadcast lag recovery scans for `is_finished()` handles (Phase 17)
- **session_exit_tx**: `crates/synvoid-mesh/src/mesh/transport.rs:194` — `broadcast::Sender<PeerSessionExit>` on `MeshTransport`, used by peer session tasks to signal exit metadata to the session reaper. Cloned into each session task's `tokio::spawn` closure. The reaper subscribes via `self.session_exit_tx.subscribe()` during lifecycle commit
- **restore_peer_logical_state()**: `crates/synvoid-mesh/src/mesh/transport.rs:3069` — shared helper for topology/DHT restoration (Iteration 74). Used by both `rollback_startup()` and `recover_failed_state()` to avoid duplicated logic. Restores topology via `restore_peer_state()` (native `PeerState`, not lossy conversion) and DHT via `restore_peer()` from `DhtPeerSnapshot`. Idempotent. **Iteration 75**: Combined into `restore_and_verify_peer_logical_state()` which adds verification in the same call.
- **spawn_auxiliary_reaper()**: `crates/synvoid-mesh/src/mesh/transport.rs:2957` — critical background task (Iteration 74, Phase 20–21) watching `auxiliary_exit_tx: broadcast::Sender<AuxiliaryTaskExit>` for auxiliary task completions; removes entries from `auxiliary_tasks` and awaits handles outside the lock; cancellation-aware via `session_reaper_shutdown` watch signal; broadcast lag recovery scans for finished handles
- **AuxiliaryTaskExit**: `crates/synvoid-mesh/src/mesh/lifecycle.rs:688` — exit event from auxiliary tasks (Iteration 74, Phase 20). Published to auxiliary reaper when an auxiliary task completes, triggering removal from the `auxiliary_tasks` registry.
- **RecoveryReport**: `crates/synvoid-mesh/src/mesh/lifecycle.rs:762` — internal recovery accounting struct (Iteration 74, Phase 35). Tracks `tasks_joined`, `sessions_joined`, `auxiliary_joined`, `topology_restored`, `dht_restored`, `errors`.
- **RecoveryVerification**: `crates/synvoid-mesh/src/mesh/lifecycle.rs` — post-recovery verification result (Iteration 73). Checks task group empty, sessions empty, auxiliary tasks empty, connections empty, residue cleared
- **restore_and_verify_peer_logical_state()**: `crates/synvoid-mesh/src/mesh/transport.rs` — combined restoration + verification helper (Iteration 75). Restores topology via `restore_peer_state()` (bidirectional `global_nodes` update) and DHT via `restore_peer()` (force-replacement), then verifies via `peer_matches_snapshot()`. Used by both `rollback_startup()` and `recover_failed_state()` for atomicity.
- **stop_staged_peer_activity()**: `crates/synvoid-mesh/src/mesh/transport.rs` — stops all peer sessions and auxiliary tasks before logical restoration (Iteration 75), preventing late writes from invalidating restored state.
- **PeerStreamDrainReport**: `crates/synvoid-mesh/src/mesh/transport.rs` — tracks stream drain statistics when a peer session exits (Iteration 75): `drained_streams`, `aborted_streams`, `timed_out_streams`.
- **max_concurrent_peer_streams**: Config field limiting concurrent per-stream handlers in `peer_message_loop()` (default 32, Iteration 75).
- **peer_message_timeout_secs**: Config field for per-stream handler timeout in `peer_message_loop()` (default 30s, Iteration 75).
- **RollbackReport**: `crates/synvoid-mesh/src/mesh/lifecycle.rs` — expanded rollback outcome with `clean`, `errors`, `tasks_joined`, `tasks_aborted`, `peer_connections_closed`, `topology_entries_restored`, `peer_sessions_drained`, `peer_sessions_aborted`, `peer_sessions_failed`, `unresolved_peers` (Iteration 75), `runtime_stopped` (Iteration 71)
- **MeshShutdownReport**: `crates/synvoid-mesh/src/mesh/lifecycle.rs` — returned by `shutdown_with_timeout()`, counts clean/failed/aborted tasks and peer-child drainage; extended fields (Iteration 69): `peers_at_shutdown_start`, `remaining_peers`, `drained_peer_sessions`, `aborted_peer_sessions`, `drained_handshake_children`, `aborted_handshake_children`; `drained_peer_children` and `aborted_peer_children` are populated from the accept loop report (Iteration 71); **`failed_peer_sessions: usize`** (Iteration 73) for panic/error exits; **`accept_loop_report: Option<MeshAcceptLoopReport>`** (Iteration 74) replaces separate count fields — `None` when stale or unavailable
- **StartupFailurePoint**: `crates/synvoid-mesh/src/mesh/transport.rs` — test-only enum (`#[cfg(test)]`) with 6 injection points: `AfterCriticalTasks`, `DuringSeedBootstrap`, `DuringPeerConnect`, `DuringDhtBootstrap`, `DuringRuntimeStart`, `BeforeLifecycleCommit`. Hook installed via `set_startup_failure_hook()`, checked at each phase in `start()`. `BeforeLifecycleCommit` renamed from `AfterLifecycleCommit` (Iteration 71).
- **ManagedMeshService**: `crates/synvoid-mesh/src/mesh/worker_integration.rs` — worker-facing trait: `subscribe_critical_exits()`, `start()`, `shutdown(timeout)`, `is_running()`; implemented for `Arc<MeshTransport>` behind `#[cfg(feature = "dns")]`; stable `subscribe_exits()` valid before `start()`, `is_running()` derives from `MeshLifecycleState` (Iteration 69); `start_with_policy()` is the primary API (Iteration 70), `start()` is a compatibility wrapper; `is_running()` no longer uses `blocking_lock()` on a Tokio mutex — reads from an `AtomicBool` projection (`running_projection`) updated by lifecycle transition helpers (Iteration 70)
- **MeshFailureCause**: `crates/synvoid-mesh/src/mesh/worker_integration.rs` — maps mesh task failures to worker shutdown causes: `CriticalServiceExit`, `StartupFailed`, `ShutdownTimeout`. **Iteration 85**: `MeshFailureCause` no longer implements `Debug`.
- **MeshTransport::shutdown_with_timeout()**: `crates/synvoid-mesh/src/mesh/transport.rs` — bounded shutdown with `MeshShutdownReport`; transitions through Stopping → Stopped; signals task group, closes QUIC connections, joins with timeout, aborts remnants
- **MeshTransport::subscribe_exits()**: `crates/synvoid-mesh/src/mesh/transport.rs` — returns `broadcast::Receiver<MeshTaskExit>` for worker integration
- **MeshTransport::start_with_policy()**: `crates/synvoid-mesh/src/mesh/transport.rs` — primary startup API (Iteration 70). Accepts `MeshStartupPolicy` controlling bootstrap failure severity. Returns `MeshStartupReport` with degraded-mode details. `start()` is a compatibility wrapper using default policy. Transitions through lifecycle stages: critical tasks → seed/peer/DHT bootstrap → runtime start → lifecycle commit. Uses `MeshStartupStage` for staged resource tracking with rollback on failure
- **MeshTransport::recover_failed_state()**: `crates/synvoid-mesh/src/mesh/transport.rs` — recovery from `Failed` state (Iteration 72, expanded Iteration 73, Iteration 74, 75). Acquires lifecycle lock, re-runs cleanup (task group shutdown, QUIC stop, connection close, session drain, auxiliary task cleanup, residue clearing), **applies retained `FailedStartupResidue` via `restore_and_verify_peer_logical_state()` before clearing** (Iteration 75), verifies no owned resources remain (task group empty, sessions empty, auxiliary tasks empty, connections empty, residue cleared), transitions to `Stopped`. `can_start()` does NOT allow `Failed` — this is the only recovery path. Full verification with `RecoveryVerification` (Iteration 73). Recovery outcomes tracked via `RecoveryReport` (Iteration 74).
- **rollback_and_return()**: `crates/synvoid-mesh/src/mesh/transport.rs` — centralizes rollback error propagation, constructing `StartupRollbackFailed` when cleanup is incomplete; calls `rollback_startup()` then `verify_rollback_complete()`; stores only unresolved peers in `FailedStartupResidue` (Iteration 75)
- **verify_rollback_complete()**: `crates/synvoid-mesh/src/mesh/transport.rs` — checks post-rollback invariants (e.g., no remaining connections, no orphaned topology entries) and reports issues (Iteration 71)
- **MeshAcceptLoop peer bounding**: `crates/synvoid-mesh/src/mesh/transport.rs` — uses `OwnedSemaphorePermit` + `JoinSet` to bound concurrent handshakes (`max_concurrent_handshakes`, default 32); rejects connections at capacity; drains children with 10s timeout on shutdown
- **MeshAcceptLoopReport**: `crates/synvoid-mesh/src/mesh/lifecycle.rs` — wired into mesh accept loop (Iteration 71). Accept loop tracks `drained_handshakes` and `aborted_handshakes` during shutdown; `rejected_at_capacity` remains untracked (always zero); `generation: u64` distinguishes reports across startup cycles, reset at each `start_with_policy()` (Iteration 72). Report stored in `MeshTransport::accept_loop_report`, read by `shutdown_with_timeout()` to populate `MeshShutdownReport`. **Iteration 74**: `MeshShutdownReport.accept_loop_report` is now `Option<MeshAcceptLoopReport>` — stale reports (generation mismatch or no prior startup) are `None` instead of separate count fields.
- **startup_generation**: `crates/synvoid-mesh/src/mesh/transport.rs:196` — `Arc<AtomicU64>` on `MeshTransport`, incremented at each `start_with_policy()` entry (Phase 19). Used to tag accept-loop reports and detect generation mismatches during shutdown. Accept-loop report generation is compared against `startup_generation` at shutdown time; mismatch is logged as a warning (Phase 19)
- **session_generation**: `crates/synvoid-mesh/src/mesh/transport.rs:199` — `Arc<AtomicU64>` on `MeshTransport`, one global session-generation domain (Iteration 74, Phase 25). All sessions (outbound and inbound) use this single counter for globally unique generation values, replacing split stage/zero counters.
- **Mesh handshake timeouts**: `crates/synvoid-mesh/src/mesh/transport.rs` — `accept_bi()`, length read, and hello payload read wrapped with `tokio::time::timeout(handshake_timeout_secs)` (default 10s)
- **Iteration 76: Forced-cleanup corrective pass**. **Part A — Always finalize `MeshTaskGroup`**: `rollback_startup()` and `recover_failed_state()` always call `MeshTaskGroup::join_all(remaining(deadline))`. The pre-fix call site did `if task_remaining.is_zero() { Vec::new() }`, leaving tasks orphaned in the registry. `join_all(Duration::ZERO)` takes the zero-budget branch internally (`handle.abort()` + `handle.await` + synthetic `Aborted` exit). **Part B — Cooperative session cancellation**: `PeerSessionTask` gains a `shutdown_tx: watch::Sender<bool>` field. `peer_message_loop` selects on the cooperative signal via `tokio::select! { biased; ... }` so the cancel branch wins the race against incoming events. Shared `stop_peer_session_task()` helper classifies cleanup as `PeerSessionStopOutcome::{Drained, ForcedParentAbort, Failed}`. `stop_staged_peer_activity()` always sends the cooperative signal before delegating to the helper. **`PeerSessionStopOutcome`**: `crates/synvoid-mesh/src/mesh/lifecycle.rs` — `Drained(PeerSessionExitReason)`, `ForcedParentAbort`, `Failed(String)` — discriminates cooperative-drain from forced parent-abort (which cannot prove the child stream-handler `JoinSet` was drained through the normal path). **Part C — Safe DHT force restoration**: `KBucket::force_replace` returns `Result<Option<PeerContact>, ForceRestoreError>` instead of `Option<PeerContact>`. A full bucket with an absent target fails closed with `BucketFullTargetAbsent` rather than silently evicting an unrelated contact. **`ForceRestoreError`**: `crates/synvoid-mesh/src/mesh/dht/routing/bucket.rs` — `BucketFullTargetAbsent` enum variant. **`ForceRestoreContactError`**: `crates/synvoid-mesh/src/mesh/dht/routing/table.rs` — `SameNodeId`, `BucketFullTargetAbsent` enum variants propagated from bucket layer. **Part D — DHT snapshot boundary**: `DhtPeerSnapshot` documented as a *logical* snapshot; `last_seen` is intentionally refreshed to `now()` during restore. **Part E — Refined stream timeout**: `peer_stream_total_timeout_secs` config field (default 0=disabled) added to both `crates/synvoid-mesh/src/mesh/config.rs::MeshConnectionConfig` and `crates/synvoid-config/src/mesh.rs::MeshConnectionConfig`; distinct from `peer_message_timeout_secs` (per-message read). `apply_read_timeouts` helper wraps each per-message read with `tokio::time::timeout`; `peer_message_loop` applies the optional total stream lifetime timeout at the JoinSet spawn level. **Guardrails**: `tests/mesh_forced_cleanup.rs` (new, 8 integration tests), `tests/mesh_task_ownership_guard.rs` (9 new `iter76_*` assertions), `tests/mesh_startup_rollback.rs` (8 new behavioral assertions), `tests/mesh_lifecycle_tests.rs` (1 cooperative-cancellation test).
- **Iteration 77: Nested-cleanup corrective pass**. **Part A — Deadline-aware stream drain**: `drain_peer_stream_handlers()` rewritten to use `tokio::time::timeout(left, handlers.join_next()).await` so no cooperative wait exceeds the supplied timeout; a hung stream handler can no longer block session finalization indefinitely. **Part B — Remove `apply_read_timeouts`**: The `apply_read_timeouts()` wrapper around the full `handle_peer_message()` future was removed — the configured read/framing timeout was misleadingly a total handler lifetime timeout. Per-message reads now use `read_exact_with_timeout()` directly. **Part C — Forced abort classification**: `stop_peer_session_task()` zero-budget branch now correctly returns `ForcedParentAbort` instead of `Failed("parent cancelled")`. **Part D — Rollback error accounting**: Rollback and recovery now record `ForcedParentAbort` and `Failed` outcomes as incomplete cleanup errors, preventing false clean lifecycle transitions. **Part E — Datagram handler ownership**: `start_datagram_handler()` owns incoming datagram handlers in a bounded `JoinSet` (`max_concurrent_datagram_handlers`, default 32) instead of bare `tokio::spawn()`, closing the last visible detached mesh task path. **New helpers**: `force_abort_peer_session()` (cooperative abort + await), `classify_stream_join()` / `classify_forced_stream_join()` (join result classification), `read_exact_with_timeout()` (deadline-aware reads). **New config**: `peer_stream_drain_timeout_secs` (stream drain timeout, default 10s), `max_concurrent_datagram_handlers` (bounded datagram handler concurrency). **Guardrails**: `tests/mesh_forced_cleanup.rs` (new `iter77_*` behavioral tests), `tests/mesh_task_ownership_guard.rs` (new `iter77_*` guardrails).
- **Iteration 78: HTTP framing and nested ownership corrective pass**. **Part A — HTTP-over-mesh framing contract**: A single QUIC bidirectional stream carries exactly one HTTP/1.x request and one HTTP/1.x response. Supported: headers terminated by `\r\n\r\n`, fixed-body with valid `Content-Length`. Unsupported/rejected: chunked Transfer-Encoding (returns 501), CONNECT/upgrade (returns 503), pipelined requests, ambiguous Content-Length. **`read_http_request_head()`**: `crates/synvoid-mesh/src/mesh/transport_peer.rs` — generic `AsyncRead` helper for testability; enforces remaining-capacity header cap, per-read idle timeout + total header framing deadline (`peer_http_header_total_timeout_secs`, default 30s), parses `Content-Length` (strict: conflicting values rejected, non-numeric rejected) and `Transfer-Encoding`. **`read_fixed_http_body()`**: reads exactly `content_length` bytes with idle + total body framing deadlines (`peer_http_body_total_timeout_secs`, default 60s); rejects premature EOF and body prefix exceeding declared length. **Config additions**: `peer_http_header_total_timeout_secs` (default 30), `max_peer_http_body_bytes` (default 65536), `peer_http_body_total_timeout_secs` (default 60), `peer_http_backend_idle_timeout_secs` (default 30). **Part B — Backend idle timeout**: `handle_http_proxy_stream()` backend response reads now use `peer_http_backend_idle_timeout_secs` to prevent a never-closing backend from pinning a stream. **Part C — Edge-replica notification ownership**: `RaftCommitNotification` handler no longer uses bare `tokio::spawn()`; edge-replica refresh tasks are registered in the auxiliary task registry as `AuxiliaryTaskKind::EdgeReplicaRefresh`, bounded and drained during shutdown/recovery. Edge-replica refresh tasks are capped at 8 concurrent (`MAX_CONCURRENT_EDGE_REPLICA_REFRESH`); excess tasks are dropped (fire-and-forget contract). **Edge-replica deduplication**: tasks are deduplicated by `(namespace, key_id)` via `dedup_key` field on `AuxiliaryTask` — prevents duplicate refresh tasks for the same key. **Part D — PeerSessionExit stream-drain diagnostics**: `PeerSessionExit` now carries `stream_drain: PeerStreamDrainReport` with drained/aborted/failed counts from the actual stream handler drain. `ChildTaskFailed` variant in `PeerSessionExitReason` surfaces non-zero drain failures. `MeshShutdownReport` carries `stream_handler_drain` aggregate field. `MeshTransport` tracks aggregate handler counters (`aggregate_handler_drained`, `aggregate_handler_aborted`, `aggregate_handler_failed`). **Part E — Test visibility**: `stop_peer_session_task_for_test` is `pub` (not `#[cfg(test)]`) so integration tests can call it directly. **Config validation**: `max_peer_http_header_bytes >= 4` enforced at runtime; serde tests (`http_framing_config_defaults`) verify default values. **Tests**: `tests/mesh_http_framing.rs` (13 tests for header/body framing, EOF, limits, timeouts, chunked rejection), `iter78_drain_stream_handlers_real` in `tests/mesh_forced_cleanup.rs` (real JoinSet drain), 23 new guardrail assertions in `tests/mesh_task_ownership_guard.rs`.
- **Iteration 79: HTTP response framing and auxiliary ownership corrective pass**. **Parts A-B — Backend HTTP response framing**: `FramedHttpResponseHead` parsed response head (`status_code`, `content_length`, `chunked`, `connection_close`). `HttpResponseFramingError` typed errors for backend response framing. `read_http_response_head()` generic async reader with idle/total timeouts. `read_fixed_http_response_body()` reads exact Content-Length bytes. `read_chunked_http_response_body()` uses `PrefixReader` to consume `body_prefix` bytes before socket reads, then parses chunked Transfer-Encoding with trailer support. Takes `reader: R` (owned) instead of `reader: &mut R`. Replaced EOF-only backend response loop with proper HTTP/1.1 framing. **Parts C-D — Request metadata parsing**: `ParsedHttpRequestMeta` header-only metadata extraction (method, target, host, upgrade flags). Binary request bodies no longer affect host/path extraction. Upgrade detection uses exact parsed header names/tokens. **Parts E-F — Auxiliary task ownership**: `spawn_auxiliary_task()` shared helper wraps future with `AuxiliaryTaskExit` publication, dedup, and capacity gating. Edge-replica refresh tasks publish `AuxiliaryTaskExit` on completion. **Part G — Test-only API surface**: `stop_peer_session_task_for_test` adapter removed entirely — module-local tests now call the private `stop_peer_session_task()` directly. `drain_peer_stream_handlers_for_test` and `drain_datagram_handlers_for_test` remain `pub(crate)`.
- **HttpResponseFramingError**: `crates/synvoid-mesh/src/mesh/transport_peer.rs` — typed errors for backend response framing. Includes `ResponseBodyPrefixExceedsContentLength` variant (Iteration 80) for body prefix exceeding declared Content-Length. **Iteration 81**: Added `TrailerTooLarge { limit, observed }` variant for independent trailer byte accounting.
- **FramedHttpResponseHead**: `crates/synvoid-mesh/src/mesh/transport_peer.rs` — parsed response head with `status_code`, `content_length`, `chunked`, `connection_close`.
- **ParsedHttpRequestMeta**: `crates/synvoid-mesh/src/mesh/transport_peer.rs` — header-only request metadata (`method`, `target`, `host`, upgrade flags).
- **spawn_auxiliary_task()**: `crates/synvoid-mesh/src/mesh/transport.rs:2846` — shared helper for auxiliary task registration with `AuxiliaryTaskExit` publication, dedup, and capacity gating. Uses `auxiliary_submission_lock` for serialized registration. Gated start pattern: future waits oneshot before executing. **Iteration 81**: Lifecycle state rechecked under `auxiliary_submission_lock`; `Reserved` variant removed. Returns `Result<MeshTaskId, SpawnAuxiliaryError>` with typed rejection diagnostics. Shutdown and recovery acquire `auxiliary_submission_lock` before draining.
- **PrefixReader**: `crates/synvoid-mesh/src/mesh/transport_peer.rs` — internal adapter for prefix-aware chunked parsing (Iteration 80). Consumes `body_prefix` bytes before socket reads for chunked Transfer-Encoding response body parsing. **Iteration 81**: `read_byte_with_timeout` no longer wraps in an unnecessary loop.
- **HttpVersion**: `crates/synvoid-mesh/src/mesh/transport_peer.rs` — HTTP response version enum with `Http10` and `Http11` variants (Iteration 80).
- **HttpResponseBodyEncoding**: `crates/synvoid-mesh/src/mesh/transport_peer.rs` — encoding metadata enum with `None`, `FixedLength`, `Chunked`, and `CloseDelimited` variants (Iteration 80).
- **read_http_response_sequence()**: `crates/synvoid-mesh/src/mesh/transport_peer.rs` — consumes informational (1xx) responses until final response (Iteration 80). **Iteration 81**: Rewritten with one persistent `Vec<u8>` buffer using `try_parse_http_response_head()` — partial final heads after informational responses are preserved.
- **header_contains_token()**: `crates/synvoid-mesh/src/mesh/transport_peer.rs` — case-insensitive token check for comma-separated headers (Iteration 80).
- **AuxiliaryRegistryEntry**: `crates/synvoid-mesh/src/mesh/transport.rs` — `Running` variant only for auxiliary task registry serialized registration (Iteration 81, `Reserved` removed).
- **SpawnAuxiliaryError**: `crates/synvoid-mesh/src/mesh/lifecycle.rs` — typed rejection error for `spawn_auxiliary_task` (Iteration 81, Phase 25). Variants: `LifecycleNotRunning(MeshTransportState)`, `CapacityExceeded`.
- **auxiliary_submission_lock**: `crates/synvoid-mesh/src/mesh/transport.rs` — serializes auxiliary task registration to prevent concurrent submission races (Iteration 80). **Iteration 81**: Shutdown and recovery acquire this lock before draining auxiliary registry. Lock ordering: `lifecycle_op` → `auxiliary_submission_lock` → `auxiliary_tasks`.
- **try_parse_http_response_head()**: `crates/synvoid-mesh/src/mesh/transport_peer.rs` — pure buffer-oriented response head parser taking `&[u8]`, returns `Option<(FramedHttpResponseHead, usize)>` (Iteration 81). Used by both `read_http_response_head()` and `read_http_response_sequence()`.
- **parse_http_response_status_line()**: `crates/synvoid-mesh/src/mesh/transport_peer.rs` — strict status-line parser validating version (HTTP/1.0/1.1) and 3-digit status code in 100..=599 (Iteration 81).
- **read_close_delimited_http_response_body()**: `crates/synvoid-mesh/src/mesh/transport_peer.rs` — extracted close-delimited body reader with both idle and total deadline enforcement (Iteration 81).
- **auxiliary_submission_allowed()**: `crates/synvoid-mesh/src/mesh/lifecycle.rs` — checks `MeshTransportState` + `AuxiliaryTaskKind` to determine if submission is allowed (Iteration 81).
- **MeshTransportState**: `crates/synvoid-mesh/src/mesh/lifecycle.rs` — simple enum for auxiliary submission eligibility checks (Iteration 81).
- **SupervisionOutcome**: `src/worker/task_registry.rs` — typed enum (`Lifecycle { event, accepted }` | `DirectCause(WorkerShutdownCause)`) returned by the supervision loop, preserving direct shutdown causes without converting to fake lifecycle events; supervision loop is side-effect free (Iteration 67)
- **map_task_exit_to_shutdown_cause()**: `src/worker/task_registry.rs` — maps fatal `NamedTaskExit` to `WorkerShutdownCause` (server_run -> ServerExitedUnexpectedly, others -> CriticalTaskExit)
- **map_exit_recv_error_to_shutdown_cause()**: `src/worker/task_registry.rs` — maps broadcast `RecvError` to cause (Lagged -> RegistryExitChannelClosed, Closed -> RegistryExitChannelClosed if not shutting down)
- **map_lifecycle_channel_closed()**: `src/worker/task_registry.rs` — maps lifecycle channel closure to cause (active -> RegistryExitChannelClosed, shutting down -> None)
- **request_lifecycle_transition()**: `src/worker/unified_server/lifecycle.rs` — sends lifecycle event with oneshot acknowledgement, returns `IpcLoopError` on channel closure or dropped ack
- **ManagedService trait**: `src/worker/task_registry.rs` — `name()`, `shutdown()`, `join()` contract for long-lived services
- **MeshSupervisionPolicy**: `src/worker/mesh_supervision.rs` — worker-level mesh supervision policy with `required()` and `optional()` presets; controls startup/critical/restartable failure actions, restart budget, and readiness requirements. Now has `allow_degraded_readiness` field (required defaults `false`, optional defaults `true`). **Iteration 84**: Policy is now config-driven via `MeshSupervisionConfig` in config crate; `build_mesh_supervision_policy()` derives `MeshSupervisionPolicy` from TOML config; disabled mesh creates no pipeline (no observer, coordinator, startup task, or decision channel); `RestartMesh` decision treated as error (restart disabled by default). **Iteration 85**: Disabled mesh is construction-free (no topology, routing, transport, DNS, YARA, or DHT runtime objects created). Policy is `Option<MeshSupervisionPolicy>` — `None` for disabled, no required fallback. `restart_enabled` is overridden to `false` (restart not implemented). `RestartMesh` is unreachable in production policy. `MeshFailureCause` no longer implements `Debug`. **Iteration 86**: `build_mesh_supervision_policy()` returns `Result<Option<MeshSupervisionPolicy>, String>` — rejects `restart_enabled = true` with an error (restart is not implemented and must not be configured).
- **MeshSupervisionConfig**: `crates/synvoid-config/src/mesh.rs` — TOML-deserializable config struct for worker-level mesh supervision. Fields: `required`, `restart_enabled`, `restart_limit`, `restart_window_secs`, `restart_backoff_initial_secs`, `restart_backoff_max_secs`, `allow_degraded_readiness`. Defaults: `required=true`, `restart_enabled=false`, `allow_degraded_readiness=false` (Iteration 84). **Iteration 85**: `restart_enabled` is overridden to `false` at policy-build time with a warning — restart is not implemented. **Iteration 86**: `restart_enabled = true` is now rejected with an error (not just overridden)
- **build_mesh_supervision_policy()**: `src/worker/mesh_supervision.rs` — derives `MeshSupervisionPolicy` from `MeshSupervisionConfig` + `mesh_enabled` flag. Returns `None` when mesh is disabled (no pipeline created). Restart is disabled by default (`restart_enabled=false` → `restart_limit=0`); `RestartMesh` action is treated as `ShutdownWorker` when restart is not enabled (Iteration 84). **Iteration 85**: `restart_enabled` is overridden to `false` at build time regardless of config (restart not implemented); policy never produces `RestartMesh`; guard test proves this invariant. **Iteration 86**: Returns `Result<Option<MeshSupervisionPolicy>, String>` — rejects `restart_enabled = true` with an error (restart is not implemented and must not be configured)
- **start_mesh_generation()**: `src/worker/mesh_supervision.rs` — async helper for awaiting mesh startup. Composes `transport.start()`; returns `Result<(), MeshFailureCause>`. Caller is responsible for transitioning `WorkerMeshStatus` before/after this call (facts only, no status mutation). Required mesh startup is awaited inline before worker ready signal; optional mesh starts async (Iteration 84). **Iteration 85**: No status transitions — runtime helper returns facts only
- **OneShot task class**: `src/worker/task_registry.rs` — `TaskClass::OneShot` variant added for tasks that run once during initialization and complete. Not restarted, dropped after completion (Iteration 84)
- **MeshGenerationSupport**: `src/worker/unified_server/mod.rs` — worker-owned support-generation type with `generation`, `task_ids`, and `cancel_tx`. `empty(generation)` creates a bundle with no tasks. `register_mesh_generation_support()` returns `Result<MeshGenerationSupport, WorkerShutdownCause>`. Generation-specific cancellation via watch channel (Iteration 87). When optional mesh degrades via `MarkDegraded`, the supervision loop calls `active_mesh_support.take()` to cancel and clear the generation's DNS/YARA support tasks without stopping unrelated worker tasks. Cancel is idempotent via watch channel (Iteration 87, Phase 12)
- **MeshSupportTasks**: `src/worker/unified_server/mod.rs` — support infrastructure for mesh (DNS verification, YARA broadcast). **Iteration 87**: No longer carries `dht_routing_manager` — routing manager is now owned exclusively by `MeshTransport` and initialized during the transactional startup stage. **Iteration 88**: YARA bridge task removed — `run_yara_broadcast_loop()` accepts worker and generation shutdown receivers directly.
- **TaskSubsetCleanupReport**: `src/worker/task_registry.rs` — report returned by `shutdown_and_join_tasks()` with exit metadata for all matched tasks and IDs not found. Contains `exits: Vec<NamedTaskExit>` and `not_found_ids: Vec<String>` (Iteration 88).
- **SupportStopContext**: `src/worker/unified_server/mod.rs` — enum classifying the context for stopping mesh support tasks. Variants: `OptionalMeshDegraded`, `WorkerShutdown`, `StartupRollback` (Iteration 88).
- **MeshSupportStopReport**: `src/worker/unified_server/mod.rs` — report returned by `stop_mesh_generation_support()` with DNS and YARA cancellation results, task join outcomes, and elapsed duration (Iteration 88). **Iteration 90**: Now includes `not_found: usize` field for task IDs not found in registry; `clean()` returns `false` when `not_found > 0`.
- **stop_mesh_generation_support()**: `src/worker/unified_server/mod.rs` — async helper performing cooperative then forced cleanup of mesh support tasks (DNS verification, YARA broadcast). Accepts `SupportStopContext`, returns `MeshSupportStopReport` (Iteration 88). Now public API for integration testing (Iteration 89).
- **MeshInit::disabled()**: `src/worker/unified_server/init_mesh.rs` — canonical constructor returning no runtime resources (all fields `None`/empty). Used when mesh config is absent or `enabled = false`. No topology, routing, transport, DNS, YARA, or DHT runtime objects are created. (Iteration 85)
- **validate_mesh_runtime_inputs()**: `src/worker/unified_server/init_mesh.rs` — validates mesh runtime configuration before constructing transport/topology/DHT objects. Called during mesh init to catch configuration invariant violations early (Iteration 86)
- **MeshConfigurationInvariant(String)**: `src/worker/task_registry.rs` — variant on `WorkerShutdownCause` for transport/policy configuration mismatches detected during init validation (Iteration 86)
- **run_yara_broadcast_loop()**: `src/worker/unified_server/init_mesh.rs` — extracted YARA broadcast loop with deadline-bounded drain and `YaraBroadcastReport` return type. Replaces inline YARA broadcast logic; bounded drain ensures no hung YARA operations block worker shutdown (Iteration 86)
- **YaraBroadcastReport**: `src/worker/unified_server/init_mesh.rs` — return type from YARA broadcast loop with `dropped` field and metrics counters: `yara_mesh_broadcast_submitted_total`, `yara_mesh_broadcast_completed_total`, `yara_mesh_broadcast_failed_total`, `yara_mesh_broadcast_aborted_total`, `yara_mesh_broadcast_dropped_total` (Iteration 87)
- **MeshBackgroundTaskSpec**: `crates/synvoid-mesh/src/mesh/lifecycle.rs` — declarative specification for mesh background tasks (topology and DHT maintenance). Replaces imperative `start_background_tasks()` methods with a data-driven approach. Each spec describes a task that should be registered with `MeshTaskGroup` after mesh startup. The future is fully constructed by the component builder and captures the lifecycle-owned shutdown receiver (Iteration 86, updated Iteration 87)
- **build_background_tasks()**: Implemented on both `MeshTopology` and `DhtRoutingManager` — returns `Vec<MeshBackgroundTaskSpec>` describing tasks to be registered after mesh startup. Replaces `start_background_tasks()` which previously spawned tasks during construction. Background tasks are now registered via `MeshTaskGroup::register_background_specs()` (Iteration 86)
- **WorkerMeshPhase**: `src/worker/mesh_supervision.rs` — worker-observed mesh phase (Disabled/Starting/Running/Degraded/Restarting/Failed/Stopping/Stopped), separate from transport's internal MeshLifecycleState; transition helpers: `transition_starting()`, `transition_running()`, `transition_degraded()`, `transition_restarting()`, `transition_failed()`, `transition_stopping()`, `transition_stopped()`, `record_exit()`
- **decide_mesh_action()**: `src/worker/mesh_supervision.rs` — pure classifier mapping (policy, phase, event, shutdown_intent) to MeshSupervisorDecision (NoAction/MarkDegraded/RestartMesh/ShutdownWorker); takes `WorkerMeshPhase` instead of `&WorkerMeshStatus`; applies event-level status transitions before policy classification
- **mesh_failure_to_worker_cause()**: `src/worker/mesh_supervision.rs` — exhaustive conversion from `MeshFailureCause` to `WorkerShutdownCause` that preserves typed cause information
- **merge_worker_shutdown_cause()**: `src/worker/mesh_supervision.rs` — priority-based cause merging for shutdown accumulation
- **MeshSupervisionCoordinator**: `src/worker/mesh_supervision.rs` — receives MeshSupervisionEvents from observer, consults policy, produces MeshSupervisorDecisions for composition root
- **RestartBudget**: `src/worker/mesh_supervision.rs` — bounded restart tracking with sliding window expiry
- **MeshShutdownDisposition**: `src/worker/mesh_supervision.rs` — classifies MeshShutdownReport into Clean/ForcedButComplete/Incomplete
- **Supervision pipeline**: Uses `state.mesh_status.clone()` (single authoritative allocation). Coordinator applies event transitions before policy decisions. Readiness gate checks `allow_degraded_readiness`. **Iteration 84**: Policy is config-driven via `MeshSupervisionConfig`; disabled mesh creates no pipeline
- **Mesh startup (worker supervision)**: No outer `tokio::time::timeout()` wrapping `start_with_policy()`. Cancellation-safe via mesh-internal stage deadlines
- **Shutdown (worker supervision)**: Uses real deadline (`shutdown_deadline = shutdown_started_at + drain_timeout`) via `remaining_budget()` closure, not `state.start_time.elapsed()`. Incomplete mesh shutdown accumulates into final cause via `merge_worker_shutdown_cause()`
- **Mesh status transitions (worker supervision)**: Phase 22 records Stopping before mesh shutdown, Stopped/Failed after
- **ThreatFeedClient lifecycle**: `src/waf/threat_intel/feed_client.rs` — uses `select!` with `shutdown_tx` watch channel; `is_running()` checks `!handle.is_finished()` (Iteration 62); `join_with_timeout()` provides bounded join with abort (Iteration 62)
- **build_default_serverless_manager()**: `src/worker/unified_server/init_apps.rs` - helper function consolidating global plugin manager fallback logic
- **RECORD_STORE_GLOBAL**: `crates/synvoid-mesh/src/mesh/mod.rs:180` - **legacy/fallback only** — all production paths use explicit injection via `DataPlaneServices.record_store`
- **Mesh trust domains**: `architecture/mesh_trust_domains.md` — trust-domain classification (transport, advisory_dht, canonical, identity, policy, services, compat), invariants, import rules, review checklist. **Canonical seam** (`CanonicalTrustReader` in `crates/synvoid-mesh/src/mesh/canonical.rs`): Iteration 8 seam implemented; Iteration 9 consumer migration (`validate_peer_canonical_status` in `peer_auth.rs`); Iteration 10 test hardening + rustdoc. **DHT ingress gate**: Iteration 11 reader-backed key policy (`classify_key_authority_with_canonical_reader`); Iteration 12 ingress adapter (`validate_dht_key_authority_for_ingress`); Iteration 13 `DhtIngressPolicyContext` seam; Iteration 14 carrier wired for Push/Announce via `RecordStoreManager`; **Iteration 15: track complete** — ingress gate active for configured Push/Announce paths, disabled context preserves legacy, sync/replay/local/quorum/Raft paths intentionally untouched. **Iteration 16: AdvisoryRecordSource seam** — `AdvisoryRecordSource` trait + `RecordStoreAdvisorySource` adapter + `StaticAdvisoryRecordSource` test source in `crates/synvoid-mesh/src/mesh/dht/advisory_source.rs`. **Iteration 17: Advisory source hardening** — `RecordStoreAdvisorySource` has focused real-store tests (present/missing/expired/prefix); no service consumer migration; architecture note updated. **Iteration 18: Policy composition helper** — `evaluate_threat_intel_policy()` in `crates/synvoid-mesh/src/mesh/threat_intel_policy.rs` composes `AdvisoryRecordSource` + `CanonicalTrustReader` into explicit threat-intel policy decisions (Actionable/AdvisoryOnly/NotActionable/Deferred). Tests cover all advisory + canonical state combinations. **Iteration 19: First consumer migration** — `ThreatIntelligenceManager::evaluate_indicator_actionability` wraps the policy helper, taking trait objects as parameters. Tests cover all policy-composed and legacy paths. No proxy, YARA/WASM, or routing consumers migrated. Iteration 23 reassessed the track and selected Outcome A, pausing the threat-intel migration before broader proxy/YARA/WASM/routing or enforcement consumers. **Iteration 20: Injection seam completed** — `ThreatIntelligenceManager` accepts optional `ThreatIntelPolicyContext` via `set_policy_context()`. Configured context enables composed policy evaluation (`evaluate_indicator_actionability_configured()`, `lookup_threat_indicator_policy_composed()`); unconfigured falls back to legacy raw lookups. Injection seam complete. Iteration 21 added the second composed read path (`lookup_local_indicator_policy_composed` + IP wrapper). Iteration 22 consolidated gating into the shared `is_policy_actionable` helper. Iteration 23 reassessed the track and selected Outcome A, leaving the two composed read paths staged and raw lookups compatibility/diagnostic only. Iteration 25 adds worker-root ownership of optional `ThreatIntelPolicyContext` via `DataPlaneServices`; a root-side helper constructs it from explicit canonical/advisory handles. Iteration 27 assessed canonical reader ownership; workers are data-planes without direct access to Raft/EdgeReplicaManager. **Iteration 28: Supervisor exports `CanonicalTrustSnapshot` via IPC to workers** — `EdgeReplicaManager::canonical_trust_snapshot()` produces the snapshot, Supervisor sends `CanonicalTrustSnapshotUpdate` IPC, workers store it and thread the reader into `build_threat_intel_policy_context` when available. No proxy/YARA/WASM/routing/WAF consumers were migrated. **Iteration 34: Consumer enforcement migration** — `classify_consumer_action()` classifies consumer intent (ShadowOnly/RawCompatibility/AdvisoryCache/Enforcement) into action (PermitAction/SuppressAction/ShadowOnly/RawCompatibilityOnly); strict lookup wrappers (`lookup_threat_indicator_policy_strict`, `lookup_local_indicator_policy_strict`, `lookup_local_indicator_by_ip_policy_strict`) return `None` when no policy context configured; `evaluate_incoming_threat_policy()` gates enforcement mutations in `handle_incoming_threat` — block_ip, rate limit, suspicious, and ip throttle apply only when policy returns `PermitAction`; when no policy context is configured, enforcement is suppressed by default. `apply_sync` and `handle_hot_threat_gossip` delegate to `handle_incoming_threat` and inherit the enforcement gate. New re-exported types: `ThreatIntelConsumerKind`, `ThreatIntelConsumerAction`, `ThreatIntelDeferredMode`. **Iteration 35**: Enforcement semantic cleanup — `IncomingThreatPolicyGate` carries action + decision, suppression metrics classified by policy outcome, `AsnBlock` observational relabel, `ThreatIntelDeferredMode` dispatch, mutation helper preconditions, raw consumer audit complete.
- **classify_passthrough_sites()**: `src/worker/unified_server/passthrough_validation.rs` - pure classification function for TLS passthrough sites (no I/O, no side effects)
- **evaluate_threat_intel_policy()**: `crates/synvoid-mesh/src/mesh/threat_intel_policy.rs` — pure composition helper combining `AdvisoryRecordSource` + `CanonicalTrustReader` into explicit threat-intel policy decisions (Actionable/AdvisoryOnly/NotActionable/Deferred). Tests cover all advisory + canonical state combinations. Outcome A keeps the helper staged; no broader proxy, YARA/WASM, or routing consumers were migrated. **Iteration 33**: Shadow/observability consumers added — `ThreatIntelPolicyShadowDecision` DTO, `ThreatIntelPolicyDecisionClass` enum, `ThreatIntelPolicyShadowDisagreement` enum, and helpers (`classify_threat_intel_policy_decision`, `threat_intel_policy_shadow_decision`, `classify_shadow_disagreement`). `ThreatIntelligenceManager::evaluate_indicator_policy_shadow()` provides shadow evaluation with metrics counters. Admin endpoints: `GET /mesh/threat-intel/policy-shadow` and `GET /mesh/threat-intel/policy-shadow/stats`. **Shadow/observability only — no enforcement behavior changed.** **Iteration 34: Consumer enforcement migration** — `classify_consumer_action()` classifies consumer intent (ShadowOnly/RawCompatibility/AdvisoryCache/Enforcement) into action (PermitAction/SuppressAction/ShadowOnly/RawCompatibilityOnly); strict lookup wrappers (`lookup_threat_indicator_policy_strict`, `lookup_local_indicator_policy_strict`, `lookup_local_indicator_by_ip_policy_strict`) return `None` when no policy context configured; `evaluate_incoming_threat_policy()` gates enforcement mutations in `handle_incoming_threat` — block_ip, rate limit, suspicious, and ip throttle apply only when policy returns `PermitAction`; when no policy context is configured, enforcement is suppressed by default. `apply_sync` and `handle_hot_threat_gossip` delegate to `handle_incoming_threat` and inherit the enforcement gate. New re-exported types: `ThreatIntelConsumerKind`, `ThreatIntelConsumerAction`, `ThreatIntelDeferredMode`.
- **handle_incoming_threat()**: `crates/synvoid-mesh/src/mesh/threat_intel.rs:1226` — main entry point for mesh-sourced threat indicators. Enforcement mutations (block_ip, rate limit, suspicious, ip throttle) are gated by `evaluate_incoming_threat_policy()` and only apply when policy returns `PermitAction`; when no policy context is configured, enforcement is suppressed by default (Iteration 34). `apply_sync` and `handle_hot_threat_gossip` both delegate to `handle_incoming_threat` and therefore inherit the enforcement gate. **Iteration 35**: `evaluate_incoming_threat_policy()` now returns `IncomingThreatPolicyGate` (carrying both action and decision); suppression metrics classified by actual policy outcome (advisory-only, not-actionable, deferred, not-configured); `AsnBlock` is observational only (no enforcement gate, no block-store mutation); `ThreatIntelDeferredMode` dispatches to correct action (FailOpenNoAction/FailClosedNoAction → SuppressAction, ShadowOnly → ShadowOnly); private mutation helpers (`apply_rate_limit_mesh_action`, `apply_suspicious_mesh_action`) have documented preconditions requiring PermitAction.
- **ThreatIntelPolicyContext**: `crates/synvoid-mesh/src/mesh/threat_intel.rs` — injection carrier holding `Arc<dyn CanonicalTrustReader>` + `Arc<dyn AdvisoryRecordSource>`. Optional field on `ThreatIntelligenceManager` (default `None`), and now also carried at the worker root via `DataPlaneServices` with a low-risk apply helper. The Supervisor exports a bounded `CanonicalTrustSnapshot` (via `EdgeReplicaManager::canonical_trust_snapshot()`) that implements `CanonicalTrustReader`, and sends it to workers via `CanonicalTrustSnapshotUpdate` IPC. Workers receive and store the snapshot; the snapshot reader is applied to the policy context through `DataPlaneServices::update_threat_intel_policy_context()` in the IPC message loop, not during bootstrap. Methods: `set_policy_context()`, `evaluate_indicator_actionability_configured()`, `lookup_threat_indicator_policy_composed()`, `lookup_local_indicator_policy_composed()`, `lookup_local_indicator_by_ip_policy_composed()`, `lookup_threat_indicator_policy_strict()`, `lookup_local_indicator_policy_strict()`, `lookup_local_indicator_by_ip_policy_strict()`. When configured, both DHT and local composed lookups gate on `Actionable` (via shared `is_policy_actionable` helper post-Iteration 22); raw lookup paths remain for compatibility/diagnostics. Strict wrappers return `None` when no policy context configured (unlike legacy composed which falls back to raw). Iteration 23 paused the track with no additional consumer migration. Iteration 24 verified the helper and focused mesh checks. Iterations 25-26 added worker-root ownership via `DataPlaneServices` and a root-side helper for constructing the context. Iteration 27 assessed canonical reader ownership; workers are data-planes without direct access to Raft/EdgeReplicaManager. **Iteration 28: Supervisor exports `CanonicalTrustSnapshot` via IPC to workers**, completing the export path. **Iteration 31**: Freshness policy now applied during IPC snapshot updates — `classify_canonical_snapshot()` checks snapshot age before `FreshnessBoundCanonicalReader` wraps the reader for policy context construction; expired/invalid/stale+defer snapshots result in no canonical reader in the policy context. **Iteration 32**: Worker IPC handler reads freshness config from `config.main.tunnel.mesh.authority_freshness` instead of hardcoded defaults. `FailClosedNotActionable` stale mode installs `FreshnessBoundCanonicalReader` (fail-closed semantics) instead of clearing context. Malformed postcard payloads preserve previous valid snapshot/context. No proxy/YARA/WASM/routing/WAF consumers were migrated. **Iteration 33: Shadow/observability consumers** — `ThreatIntelPolicyShadowDecision` DTO, `ThreatIntelPolicyDecisionClass` enum, `ThreatIntelPolicyShadowDisagreement` enum, and helpers (`classify_threat_intel_policy_decision`, `threat_intel_policy_shadow_decision`, `classify_shadow_disagreement`) in `crates/synvoid-mesh/src/mesh/threat_intel_policy.rs`. `ThreatIntelligenceManager::evaluate_indicator_policy_shadow()` provides shadow evaluation with metrics counters. Admin diagnostic endpoint `GET /mesh/threat-intel/policy-shadow` and metrics summary `GET /mesh/threat-intel/policy-shadow/stats`. **Shadow/observability only — no enforcement behavior changed.** Raw lookup APIs remain compatibility/diagnostic paths. No proxy/YARA/WASM/routing/WAF consumers migrated. **Iteration 34: Consumer enforcement migration** — `classify_consumer_action()` classifies consumer intent (ShadowOnly/RawCompatibility/AdvisoryCache/Enforcement) into action (PermitAction/SuppressAction/ShadowOnly/RawCompatibilityOnly); strict lookup wrappers (`lookup_threat_indicator_policy_strict`, `lookup_local_indicator_policy_strict`, `lookup_local_indicator_by_ip_policy_strict`) return `None` when no policy context configured; `evaluate_incoming_threat_policy()` gates enforcement mutations in `handle_incoming_threat` — block_ip, rate limit, suspicious, and ip throttle apply only when policy returns `PermitAction`; when no policy context is configured, enforcement is suppressed by default. `apply_sync` and `handle_hot_threat_gossip` delegate to `handle_incoming_threat` and inherit the enforcement gate. New re-exported types: `ThreatIntelConsumerKind`, `ThreatIntelConsumerAction`, `ThreatIntelDeferredMode`.
- **bypass_sites_without_rate_limit**: renamed from `rate_limited_bypass_sites`; sites in this set bypass WAF without rate limiting
- **site_has_rate_limit()**: `src/worker/unified_server/passthrough_validation.rs` - pure helper that checks whether a site has rate limit configuration
- **evaluate_passthrough_policy()**: `src/worker/unified_server/passthrough_validation.rs` - pure function returning `PassthroughPolicyEvaluation`; computes per-site violations (`PassthroughPolicyViolation` enum) without I/O
- **validate_tls_passthrough_waf_policy()**: `src/worker/unified_server/passthrough_validation.rs` - returns `Result<(), String>`; logs warnings/errors and emits metrics for misconfigured sites. Gated by `security.strict_tls_passthrough_policy` (default false)
- **BlockStore counter correctness**: `block_ip`/`block_ip_with_provenance`/`add_block` only increment `total_entries` on new key insertion, not on overwrite. Overwrites update the entry without changing the count.
- **BlockStore::new** auto-calls `migrate_legacy_sentinel_entries()` during initialization.
- **`block_mesh_id_with_provenance` deadlock fix**: Now drops the shard lock before calling `trigger_persist()` (previously held the lock across the persist call).
- **BlocklistEvent / BlocklistOperation**: Types in `synvoid-core::block_store` for mesh-wide block/unblock propagation. Admin ban/unban handlers emit structured `BlocklistEvent` debug logs. Admin unban also calls `announce_local_unblock()` to gossip `BlocklistEventGossip` to mesh peers. Supervisor pushes `BlocklistEventUpdate` IPC to workers. Supports distributed fields: `event_id`, `source_node`, `ttl_secs`, `version`. Apply pipeline uses FIFO dedup (`SeenEventCache`) and per-target stale suppression (`TargetStateCache`). See `architecture/blocklist_remove_consistency.md`.
- **Blocklist target state persistence** (Iteration 52, provenance cleanup Iteration 53): Per-target stale suppression (`TargetStateCache`) now survives restarts via `blocklist_target_state.json` persistence file using `BlocklistTargetStateRecord` type. Config fields: `BlocklistLimitsConfig::target_state_persist` (bool), `target_state_max_records` (usize), `target_state_ttl_secs` (u64). Event-ID dedupe (`SeenEventCache`) remains in-memory only — no persistence. Target state is loaded on `BlockStore::new()` and written on mutations. Bounded by `target_state_max_records` with oldest-first eviction. Persisted records now preserve `source_node` and `BlockProvenance` metadata from event apply and direct block APIs; direct unblock paths without explicit provenance use a documented compatibility default. Stale events do not overwrite existing target-state provenance/source.
- **BlocklistEventLog** (Iteration 48, cursor fix Iteration 49): Bounded in-memory event log (10,000 events default) in `BlockStore` for offline-peer catchup. Reconnecting peers request events via `BlocklistCatchupRequest`/`BlocklistCatchupResponse` mesh messages. History gaps detected via `snapshot_required`. Supervisor retains separate IPC event log (1,000 events) for worker replay on reconnect. `BlocklistEventCursor.since_sequence: Option<u64>` — `None` replays from oldest retained event (including sequence 0); `Some(n)` returns events with sequence `> n` (exclusive). See `architecture/blocklist_reconciliation.md`.
- **Blocklist Snapshot Fallback** (Iteration 56, pagination cleanup Iteration 57): When a reconnecting peer's catchup history exceeds event-log retention (`snapshot_required=true`), a paged snapshot transfer converges the peer's local BlockStore. `BlocklistSnapshotRequest`/`BlocklistSnapshotResponse` wire messages (proto 181/182) carry IP blocks, mesh-ID blocks, and target-state records with provenance. `BlockStore::export_blocklist_snapshot()` produces paged chunks with unified pagination across all item types (IP blocks, mesh-ID blocks, and target-state records sorted by `(kind, site_scope, identifier)`). `BlockStore::apply_blocklist_snapshot()` applies with LWW/stale suppression. Snapshot is control-plane-only, not Raft-backed, not request-path dependent. Conservative merge semantics: adds/updates entries without deleting absent entries. `max_items` bounds the total record count per response page. Target-state records are not duplicated across pages. `snapshot_complete` is true iff `!has_more` (independent of target-state presence). Snapshot block apply preserves original `blocked_at` timestamps for correct LWW ordering. Transport guards against `has_more=true` with missing `next_page_token`. See `architecture/blocklist_reconciliation.md`.
- **BlocklistEventUpdate IPC** (Iteration 50): Carries full `BlocklistEvent` JSON including `BlockProvenance`. After Iteration 50, admin `ban_ip`/`ban_mesh_id` also broadcast events to workers. `BlockEntryData`/`MeshBlockEntryData` now include optional `provenance_kind`/`provenance_source` fields. `ipc_data_to_provenance()` helper converts IPC strings back to typed `BlockProvenance`. See `architecture/blocklist_provenance_preservation.md`.

### Root Dependency Ownership
- Root-level direct dependencies are declared in `Cargo.toml` under `[dependencies]`. See `Cargo.toml` for the current inventory.

### Process Architecture
- **Supervisor** manages lifecycle, consolidates Supervisor
- **UnifiedServerWorker** uses single Tokio event loop (NOT process-per-tenant)
- **CPU affinity** is Linux-only, logs warning on other platforms
- **Default entry point** is `run_supervisor_mode()` via `src/main.rs`
- **Mesh control plane** runs in Supervisor process, not worker (workers get intelligence via IPC)

### Granian Integration
- **Granian IS integrated** - `crates/synvoid-app-server/src/granian.rs` with full process management, auto-install, admin API
- NOT a separate process type - runs within the Supervisor architecture

### Implementation Notes
- **StallPermit**: Use `StallPermit::try_new(max_stalled)` for all WAF stall paths — never manually call `record_stall_start`/`record_stall_end`. Drop releases the active slot; completed sleeps call `record_stall_timeout()` explicitly.
- **PeakEwma weighting**: Slow-moving (90% to old value) is intentional for connection stability
- **BUG-ROUTER-1**: Hardcoded port 80 is in `Default` impl only, actual usage uses configured port - NOT a bug
- **Spin header serialization**: Uses JSON (SpinRuntime::serialize_headers_spin), not binary like raw WASM
- **Spin idle instance eviction**: `instances` HashMap keyed by UUID grows indefinitely — old entries never cleaned up (plan DOC-L7)
- **Email alerting is a stub**: `send_email_internal()` at `src/admin/alerting/mod.rs:349-373` logs message then returns `Ok(())` without sending
- **Audit log redundant permissions**: `src/admin/audit.rs:131-139` re-applies permissions on every write — already set in `with_audit_dir()`

## Architecture Documents

The `architecture/` directory contains detailed design documents. Key canonical references:

| Topic | Primary Doc | Deep Dive |
|-------|-------------|-----------|
| Mesh networking | `mesh.md` | `mesh_trust_domains.md` |
| DNS server/resolver | `dns.md` | `dns_deep_dive.md` |
| HTTP server | `http_server.md` | — |
| HTTP client/pool | `http_shared.md` | — |
| WAF engine | `waf.md` | `waf_deep_dive.md` |
| Proxy/routing | `proxy.md` | `proxy_deep_dive.md` |
| Config management | `config.md` | `config_deep_dive.md` |
| Plugin/WASM runtime | `plugin_wasm.md` | — |
| Serverless | `serverless.md` | — |
| Spin runtime | `spin.md` | — |
| Admin/auth | `admin_deep_dive.md` | — |
| Platform/sandboxing | `platform.md` | `platform_deep_dive.md` |
| Threat-intel audit | `threat_intel_request_waf_audit.md` | — |
| HTTP/3 WAF boundary | `http3_request_waf_boundary.md` | — |
| Blocklist reconciliation | `blocklist_reconciliation.md` | `blocklist_remove_consistency.md` |
| Blocklist provenance | `blocklist_reconciliation.md` | `blocklist_provenance_preservation.md` |
| Data-plane composition root | `worker_data_plane_composition_root.md` | — |
| Worker task lifecycle | `worker_task_lifecycle.md` | — |
| Mesh transport lifecycle | `mesh_transport_lifecycle.md` | — |

## Skills Directory

The `skills/` directory contains detailed documentation for various subsystems:

| Skill | Purpose |
|-------|---------|
| `admin_api.md` | Admin API patterns |
| `admin_ui.md` | Admin UI patterns |
| `behavioral_intel.md` | Behavioral intelligence |
| `buffer_pool.md` | Sharded mutex buffer pool (replaces TreiberStack with ABA-safe implementation) |
| `crypto_dependencies.md` | Cryptographic dependency analysis |
| `dht_persistence.md` | DHT neighborhood persistence |
| `dht_scoping.md` | DHT site isolation and scoping patterns |
| `dns_dnssec.md` | DNS and DNSSEC patterns |
| `ebpf_blocking.md` | eBPF-based traffic blocking |
| `erased_http_client.md` | ErasedHttpClient streaming pool patterns |
| `h3_proxy.md` | HTTP/3 QUIC proxy patterns |
| `hickory_migration.md` | Hickory DNS resolver migration |
| `httpserver.md` | HTTP server architecture |
| `hybrid_post_quantum.md` | Post-quantum signature implementation |
| `implementation_patterns.md` | Common implementation patterns (semaphore, debounce, atomic writes) |
| `ipc_hardening.md` | IPC signing, replay protection, and authentication patterns |
| `org_key_trust_chain.md` | Organization key trust chain |
| `raft_consensus.md` | Raft consensus integration for global control plane |
| `rule_feed_persistence.md` | Rule feed persistence patterns |
| `sandboxing.md` | OS sandboxing (Windows/macOS/Linux/BSD) |
| `security_patterns.md` | Critical security fixes, constant-time comparison, path traversal, XSS prevention |
| `serverless_wasm.md` | Serverless WASM patterns |
| `spin_wasm.md` | Spin WASM runtime |
| `static_files.md` | Static file serving patterns |
| `streaming_waf.md` | Streaming WAF engine patterns |
| `supply_chain_hashes.md` | Supply chain security with pip --require-hashes |
| `synvoid_mesh.md` | Mesh networking patterns (Iterations 68–88) |
| `threat_feed_production.md` | Production and signing of threat intel feeds |
| `topology_visualizer.md` | Topology visualizer API |
| `waf_bot_detection.md` | WAF bot detection patterns |
| `windows_service.md` | Windows service integration |
