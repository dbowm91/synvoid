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

## Known File Path Corrections

| Wrong Path | Correct Path |
|------------|--------------|
| `src/http/client.rs` | `src/http_client/mod.rs` |
| `src/http/shared_handler.rs` | `src/http/server.rs:4662` (contains `collect_body_with_chunk_waf` and `stream_body_with_waf`) |
| `src/mesh/proxy.rs` | `crates/synvoid-mesh/src/mesh/proxy.rs` (mesh code extracted to crate; re-exported via `src/mesh/mod.rs`) |
| `src/mesh/transport.rs` | `crates/synvoid-mesh/src/mesh/` (now in transport_core/ and transports/ subdirectories) |
| `src/mesh/raft/state_machine.rs` | `crates/synvoid-mesh/src/mesh/raft/state_machine.rs` |
| ConfigManager location | `crates/synvoid-config/src/lib.rs:113` (not `main_config.rs`) |
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
| BUG-CORS-1 | `src/admin/mod.rs:860` | CORS config dropped (underscore prefix) | Known - may be intentional (Admin API uses bearer tokens) |

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
- **BackendType**: `src/router.rs:65-77` has 11 variants
- **SAFE_HEADERS**: `src/proxy/cache.rs:97-126` has 28 headers
- **ConfigManager**: `crates/synvoid-config/src/lib.rs:113`
- **DhtSyncRequest**: `crates/synvoid-mesh/src/mesh/transport_dht.rs` - signed by default with a config-controlled unsigned compatibility fallback; node binding enforced in transport; envelope signature verifies `(request_id, node_id, local_root_hash, timestamp, nonce)`.
- **DhtSyncResponse**: `crates/synvoid-mesh/src/mesh/dht/record_store_message.rs` - signed: envelope signature verified, signer-to-node binding enforced, record-set digest checked, stores via `store_record_from_ingress()`. Unsigned compat: stores via `store_record_from_ingress()` with `envelope_signature_valid=false` and explicit warning log. Deprecated `handle_sync_response()` removed.
- **DhtAntiEntropyRequest**: `crates/synvoid-mesh/src/mesh/transport_peer.rs` - node binding enforced, `signer_public_key` now verified against authorized global node keys; **envelope signature also verified** (✅ MR-4 fixed). Both request and response verify envelope signatures via `verify_dht_anti_entropy_request_envelope_signature()` / `verify_dht_anti_entropy_response_envelope_signature()` in `dht/signed.rs`.
- **DhtRecordPush**: `crates/synvoid-mesh/src/mesh/dht/signed.rs` - signature field exists and is enforced; **envelope signature also verified** (✅ MR-4 fixed). Push ingress is governed by the canonical ingress gate when `DhtIngressPolicyContext` is configured (Iteration 14/15).
- **DhtKeyPolicyTable**: `crates/synvoid-mesh/src/mesh/dht/key_policy.rs` - centralizes key family authority policies for DHT ingress validation. Now has `classify_key_authority_with_canonical_reader()` (Iteration 11) that uses `CanonicalTrustReader` for canonical trust questions while preserving advisory DHT mechanics. **DnsZone** uses `RaftOrQuorumGlobal` authority with `remote_writes_allowed=false` — DNS zone records can only be written via Raft consensus or quorum attestation, not via direct DHT capability. Seam + adapter added in Iteration 13; carrier + attachment for direct client Push/Announce completed in Iteration 14 via `RecordStoreManager` (see `architecture/mesh_trust_domains.md`). Ingress gate is active for all configured Push/Announce paths; disabled context preserves legacy. **Track complete** (Iteration 15) — see `architecture/mesh_trust_domains.md`.
- **validate_dht_key_authority_for_ingress**: `crates/synvoid-mesh/src/mesh/dht/key_policy.rs` — adapter mapping `classify_key_authority_with_canonical_reader` decisions to `Result<(), DhtIngressPolicyError>` for ingress callers. Seam + adapter added in Iteration 13; carrier + attachment for direct Push/Announce completed in Iteration 14 via `DhtRecordIngressContext.policy_context` + `DhtIngressPolicyContext` (see `architecture/mesh_trust_domains.md`). Disabled context preserves legacy; configured context enforces accept/reject/defer for canonical-required keys. Only targeted direct-client Push/Announce ingress paths consult the gate (sync replay, local, quorum, Raft paths intentionally untouched). **Track complete** (Iteration 15).
- **DhtRecordIngressContext**: Fields are now private. Access via accessor methods: `peer_id()`, `source_node_id()`, `source_classification()`, `path()`, `requires_quorum_proof()`, `requires_trust_anchor()`, `is_immutable_key()`, `envelope_signature_valid()`, `timestamp()`, `request_id()`, `is_local_origin()`, `policy_context()`. Construction controlled via `new_local()`, `new_remote()`, and builder methods (including `with_policy_context`). Carries optional `DhtIngressPolicyContext` (seam+adapter in Iteration 13; carrier+attachment for direct Push/Announce wired in Iteration 14). Ingress gate is active for configured Push/Announce paths; disabled context preserves legacy. **Track complete** (Iteration 15) — see `architecture/mesh_trust_domains.md`.
- **verify_envelope_signer_binding()**: `crates/synvoid-mesh/src/mesh/dht/signed.rs` — enforces signer-to-node binding for all signed DHT messages on global nodes. `NodePublicKeyResolver` trait provides pluggable key resolution.
- **validate_peer_role()**: `crates/synvoid-mesh/src/mesh/peer_auth.rs:372` — validates node role claims. Now accepts `raft_attestation: Option<&SignedRaftAttestation>` and `allow_v1_raft_attestations: bool` parameters. Edge nodes can validate via value-bound Raft attestation in addition to the traditional quorum-signed org key path. When a `raft_attestation` is provided for an Edge node, it is used exclusively (no fallback to other paths).
- **SignedRaftAttestation**: `crates/synvoid-mesh/src/mesh/peer_auth.rs` - requires cryptographic proof, not just structural attestation. **v2 protocol** binds attestation to value digest (`value_hash` field in `RaftAttestation`, `protocol_version=2`). V1 attestations without `value_hash` are **rejected by default** unless `allow_v1_raft_attestations=true` is set in config.
- **ConsensusTransport**: `crates/synvoid-mesh/src/mesh/raft/consensus.rs` - decouples Raft consensus from mesh transport layer.
- **AuthorityFreshnessConfig**: `crates/synvoid-mesh/src/mesh/config.rs` - defines stale-state behavior for authority records.
- **DHT/Raft Boundary Integration**: ✅ **Complete** — All phases implemented. DHT ingress auth hardening (MR-4) resolved: envelope signatures verified on all DHT message types including `DhtSyncRequest`/`DhtSyncResponse`, `DhtAntiEntropyRequest`/response, and `DhtRecordPush`; signer-to-node binding enforced via `verify_envelope_signer_binding()`; `SignedRaftAttestation` v2 binds to value digest; `DnsZone` requires Raft/quorum (no direct DHT writes); `validate_peer_role()` accepts Raft attestation for Edge nodes; `store_record` is `pub(crate)` with `store_local_record` for local writes; deprecated `handle_sync_response()` removed — unsigned compat path inline uses `store_record_from_ingress()` with `envelope_signature_valid=false`. Canonical trust-domain seam (Iterations 7-15) complete: `CanonicalTrustReader` wired through peer auth, DHT key policy, and direct Push/Announce ingress; ingress gate active for configured paths. Advisory seam (`AdvisoryRecordSource` in `crates/synvoid-mesh/src/mesh/dht/advisory_source.rs`) introduced in Iteration 16 — read-only advisory DHT observations with record-store adapter; Iteration 17 hardened `RecordStoreAdvisorySource` with real-store tests (no service migration). Iteration 18: `evaluate_threat_intel_policy()` composes `AdvisoryRecordSource` + `CanonicalTrustReader` into explicit threat-intel policy decisions. Iteration 19: first consumer migration via `ThreatIntelligenceManager::evaluate_indicator_actionability` — method takes trait objects as parameters, tests cover all policy-composed and legacy paths. Injection seam completed (Iteration 20). Iteration 21: second consumer migration complete — `lookup_local_indicator_policy_composed` and `lookup_local_indicator_by_ip_policy_composed` added with full test coverage. Two threat-intel read paths now use the composed policy seam. Iteration 22: consolidated duplicate decision-to-actionability gating via shared `is_policy_actionable` helper; policy-composed methods documented as preferred for new reads; raw methods documented as compatibility/diagnostic. Iteration 23: call-graph reassessment selected Outcome A, pausing the track before proxy, YARA/WASM, routing, or enforcement hot paths. Iteration 24: verification pass confirmed the helper and focused mesh checks passed. Iterations 25-26 — worker-root ownership plus an explicit root-side helper for constructing `ThreatIntelPolicyContext`. Iteration 27 assessed canonical reader ownership; workers are data-planes without direct access to Raft/EdgeReplicaManager. **Iteration 28: Supervisor exports `CanonicalTrustSnapshot` via IPC to workers** — `EdgeReplicaManager::canonical_trust_snapshot()` produces the snapshot, Supervisor sends `CanonicalTrustSnapshotUpdate` IPC, workers store it and thread the reader into `build_threat_intel_policy_context` when available. **Iteration 31: Canonical snapshot freshness policy** — `CanonicalSnapshotFreshnessPolicy` and `classify_canonical_snapshot()` in `crates/synvoid-mesh/src/mesh/canonical.rs` classify snapshots as fresh (≤60s), stale-within-grace (≤5min), expired, invalid, or missing. `FreshnessBoundCanonicalReader` wrapper enforces freshness on `CanonicalTrustReader` trust decisions. Workers classify snapshot freshness before applying; expired/invalid snapshots are not applied. Default: fresh=60s, stale_grace=5min, stale_mode=FailOpenDefer. Config fields in `AuthorityFreshnessConfig`. 19 new tests covering the freshness matrix. **Iteration 32: Config wiring complete** — `From<&AuthorityFreshnessConfig> for CanonicalSnapshotFreshnessPolicy` conversion in `canonical.rs` with normalization (stale_grace clamped to fresh_max_age). Worker IPC handler reads config from `config.main.tunnel.mesh.authority_freshness` instead of hardcoded defaults. `FailClosedNotActionable` stale mode now installs `FreshnessBoundCanonicalReader` (returns `NotTrusted { ExpiredSnapshot }`) instead of clearing context. Malformed postcard payloads preserve previous valid snapshot/context. 10 new tests. No proxy/YARA/WASM/routing/WAF consumers were migrated in this pass. **Iteration 34: Consumer enforcement migration** — `classify_consumer_action()` classifies consumer intent (ShadowOnly/RawCompatibility/AdvisoryCache/Enforcement) into action (PermitAction/SuppressAction/ShadowOnly/RawCompatibilityOnly); strict lookup wrappers (`lookup_threat_indicator_policy_strict`, `lookup_local_indicator_policy_strict`, `lookup_local_indicator_by_ip_policy_strict`) return `None` when no policy context configured; `evaluate_incoming_threat_policy()` gates enforcement mutations in `handle_incoming_threat` — block_ip, rate limit, suspicious, and ip throttle apply only when policy returns `PermitAction`; when no policy context is configured, enforcement is suppressed by default. `apply_sync` and `handle_hot_threat_gossip` delegate to `handle_incoming_threat` and inherit the enforcement gate. New re-exported types: `ThreatIntelConsumerKind`, `ThreatIntelConsumerAction`, `ThreatIntelDeferredMode`.
- **DNS Cookie Server**: `src/dns/cookie.rs` - fully wired via `validate_cookie()` in query.rs:645-662
- **TunnelRouter**: `crates/synvoid-tunnel/src/router.rs:149` - active routing uses `resolve_tunnel_backend()` (TunnelBackend enum at line 199)
- **HickoryRecursor DNSSEC**: `src/dns/resolver.rs:693-702` - uses `ValidateWithStaticKey` when `enable_dnssec=true` (✅ FIXED)
- **HTTP/3 Body Collection**: `crates/synvoid-http3/src/server.rs` - ad-hoc implementation, not using shared_handler
- **BufferPool**: 4 tiers (small/medium/large/jumbo)
- **DataPlaneServicesBuilder**: `src/worker/unified_server/services.rs` - now requires `serverless_manager` in constructor; under mesh, `DataPlaneServices` carries optional `ThreatIntelPolicyContext` and a low-risk apply helper; a root-side helper can build the context from explicit handles; bootstrap leaves canonical as `None`; the Supervisor's `CanonicalTrustSnapshot` arrives via IPC after bootstrap and is applied through `update_threat_intel_policy_context()`; no global fallback in builder
- **build_default_serverless_manager()**: `src/worker/unified_server/init_apps.rs` - helper function consolidating global plugin manager fallback logic
- **RECORD_STORE_GLOBAL**: `crates/synvoid-mesh/src/mesh/mod.rs:161` - **legacy/fallback only** — all production paths use explicit injection via `DataPlaneServices.record_store`
- **Mesh trust domains**: `architecture/mesh_trust_domains.md` — trust-domain classification (transport, advisory_dht, canonical, identity, policy, services, compat), invariants, import rules, review checklist. **Canonical seam** (`CanonicalTrustReader` in `crates/synvoid-mesh/src/mesh/canonical.rs`): Iteration 8 seam implemented; Iteration 9 consumer migration (`validate_peer_canonical_status` in `peer_auth.rs`); Iteration 10 test hardening + rustdoc. **DHT ingress gate**: Iteration 11 reader-backed key policy (`classify_key_authority_with_canonical_reader`); Iteration 12 ingress adapter (`validate_dht_key_authority_for_ingress`); Iteration 13 `DhtIngressPolicyContext` seam; Iteration 14 carrier wired for Push/Announce via `RecordStoreManager`; **Iteration 15: track complete** — ingress gate active for configured Push/Announce paths, disabled context preserves legacy, sync/replay/local/quorum/Raft paths intentionally untouched. **Iteration 16: AdvisoryRecordSource seam** — `AdvisoryRecordSource` trait + `RecordStoreAdvisorySource` adapter + `StaticAdvisoryRecordSource` test source in `crates/synvoid-mesh/src/mesh/dht/advisory_source.rs`. **Iteration 17: Advisory source hardening** — `RecordStoreAdvisorySource` has focused real-store tests (present/missing/expired/prefix); no service consumer migration; architecture note updated. **Iteration 18: Policy composition helper** — `evaluate_threat_intel_policy()` in `crates/synvoid-mesh/src/mesh/threat_intel_policy.rs` composes `AdvisoryRecordSource` + `CanonicalTrustReader` into explicit threat-intel policy decisions (Actionable/AdvisoryOnly/NotActionable/Deferred). Tests cover all advisory + canonical state combinations. **Iteration 19: First consumer migration** — `ThreatIntelligenceManager::evaluate_indicator_actionability` wraps the policy helper, taking trait objects as parameters. Tests cover all policy-composed and legacy paths. No proxy, YARA/WASM, or routing consumers migrated. Iteration 23 reassessed the track and selected Outcome A, pausing the threat-intel migration before broader proxy/YARA/WASM/routing or enforcement consumers. **Iteration 20: Injection seam completed** — `ThreatIntelligenceManager` accepts optional `ThreatIntelPolicyContext` via `set_policy_context()`. Configured context enables composed policy evaluation (`evaluate_indicator_actionability_configured()`, `lookup_threat_indicator_policy_composed()`); unconfigured falls back to legacy raw lookups. Injection seam complete. Iteration 21 added the second composed read path (`lookup_local_indicator_policy_composed` + IP wrapper). Iteration 22 consolidated gating into the shared `is_policy_actionable` helper. Iteration 23 reassessed the track and selected Outcome A, leaving the two composed read paths staged and raw lookups compatibility/diagnostic only. Iteration 25 adds worker-root ownership of optional `ThreatIntelPolicyContext` via `DataPlaneServices`; a root-side helper constructs it from explicit canonical/advisory handles. Iteration 27 assessed canonical reader ownership; workers are data-planes without direct access to Raft/EdgeReplicaManager. **Iteration 28: Supervisor exports `CanonicalTrustSnapshot` via IPC to workers** — `EdgeReplicaManager::canonical_trust_snapshot()` produces the snapshot, Supervisor sends `CanonicalTrustSnapshotUpdate` IPC, workers store it and thread the reader into `build_threat_intel_policy_context` when available. No proxy/YARA/WASM/routing/WAF consumers were migrated. **Iteration 34: Consumer enforcement migration** — `classify_consumer_action()` classifies consumer intent (ShadowOnly/RawCompatibility/AdvisoryCache/Enforcement) into action (PermitAction/SuppressAction/ShadowOnly/RawCompatibilityOnly); strict lookup wrappers (`lookup_threat_indicator_policy_strict`, `lookup_local_indicator_policy_strict`, `lookup_local_indicator_by_ip_policy_strict`) return `None` when no policy context configured; `evaluate_incoming_threat_policy()` gates enforcement mutations in `handle_incoming_threat` — block_ip, rate limit, suspicious, and ip throttle apply only when policy returns `PermitAction`; when no policy context is configured, enforcement is suppressed by default. `apply_sync` and `handle_hot_threat_gossip` delegate to `handle_incoming_threat` and inherit the enforcement gate. New re-exported types: `ThreatIntelConsumerKind`, `ThreatIntelConsumerAction`, `ThreatIntelDeferredMode`. **Iteration 35**: Enforcement semantic cleanup — `IncomingThreatPolicyGate` carries action + decision, suppression metrics classified by policy outcome, `AsnBlock` observational relabel, `ThreatIntelDeferredMode` dispatch, mutation helper preconditions, raw consumer audit complete.
- **classify_passthrough_sites()**: `src/worker/unified_server/passthrough_validation.rs` - pure classification function for TLS passthrough sites (no I/O, no side effects)
- **evaluate_threat_intel_policy()**: `crates/synvoid-mesh/src/mesh/threat_intel_policy.rs` — pure composition helper combining `AdvisoryRecordSource` + `CanonicalTrustReader` into explicit threat-intel policy decisions (Actionable/AdvisoryOnly/NotActionable/Deferred). Tests cover all advisory + canonical state combinations. Outcome A keeps the helper staged; no broader proxy, YARA/WASM, or routing consumers were migrated. **Iteration 33**: Shadow/observability consumers added — `ThreatIntelPolicyShadowDecision` DTO, `ThreatIntelPolicyDecisionClass` enum, `ThreatIntelPolicyShadowDisagreement` enum, and helpers (`classify_threat_intel_policy_decision`, `threat_intel_policy_shadow_decision`, `classify_shadow_disagreement`). `ThreatIntelligenceManager::evaluate_indicator_policy_shadow()` provides shadow evaluation with metrics counters. Admin endpoints: `GET /mesh/threat-intel/policy-shadow` and `GET /mesh/threat-intel/policy-shadow/stats`. **Shadow/observability only — no enforcement behavior changed.** **Iteration 34: Consumer enforcement migration** — `classify_consumer_action()` classifies consumer intent (ShadowOnly/RawCompatibility/AdvisoryCache/Enforcement) into action (PermitAction/SuppressAction/ShadowOnly/RawCompatibilityOnly); strict lookup wrappers (`lookup_threat_indicator_policy_strict`, `lookup_local_indicator_policy_strict`, `lookup_local_indicator_by_ip_policy_strict`) return `None` when no policy context configured; `evaluate_incoming_threat_policy()` gates enforcement mutations in `handle_incoming_threat` — block_ip, rate limit, suspicious, and ip throttle apply only when policy returns `PermitAction`; when no policy context is configured, enforcement is suppressed by default. `apply_sync` and `handle_hot_threat_gossip` delegate to `handle_incoming_threat` and inherit the enforcement gate. New re-exported types: `ThreatIntelConsumerKind`, `ThreatIntelConsumerAction`, `ThreatIntelDeferredMode`.
- **handle_incoming_threat()**: `crates/synvoid-mesh/src/mesh/threat_intel.rs:1115` — main entry point for mesh-sourced threat indicators. Enforcement mutations (block_ip, rate limit, suspicious, ip throttle) are gated by `evaluate_incoming_threat_policy()` and only apply when policy returns `PermitAction`; when no policy context is configured, enforcement is suppressed by default (Iteration 34). `apply_sync` and `handle_hot_threat_gossip` both delegate to `handle_incoming_threat` and therefore inherit the enforcement gate. **Iteration 35**: `evaluate_incoming_threat_policy()` now returns `IncomingThreatPolicyGate` (carrying both action and decision); suppression metrics classified by actual policy outcome (advisory-only, not-actionable, deferred, not-configured); `AsnBlock` is observational only (no enforcement gate, no block-store mutation); `ThreatIntelDeferredMode` dispatches to correct action (FailOpenNoAction/FailClosedNoAction → SuppressAction, ShadowOnly → ShadowOnly); private mutation helpers (`apply_rate_limit_mesh_action`, `apply_suspicious_mesh_action`) have documented preconditions requiring PermitAction.
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
- Reference `plans/root_dependency_ownership.md` for the ownership inventory of all root-level direct dependencies.

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
| `synvoid_mesh.md` | Mesh networking patterns |
| `threat_feed_production.md` | Production and signing of threat intel feeds |
| `topology_visualizer.md` | Topology visualizer API |
| `waf_bot_detection.md` | WAF bot detection patterns |
| `windows_service.md` | Windows service integration |
