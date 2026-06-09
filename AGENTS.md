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
| `src/mesh/proxy.rs:1485` | `src/mesh/transport.rs:986` + `src/config/site/misc.rs:37` |
| `src/mesh/raft/state_machine.rs:166-172` (quorum verify) | `src/mesh/dht/signed.rs:874-1092` |
| ConfigManager location | `crates/synvoid-config/src/lib.rs:113` (not `main_config.rs`) |
| `src/overseer/`, `src/master/`, `src/startup/master.rs` | `src/supervisor/` (consolidated 2026) |
| `TunnelBackend` at `src/tunnel/upstream.rs` | `TunnelBackend` at `src/tunnel/router.rs:200` (removed from upstream.rs) |
| `architecture/tunnel.md` | Does not exist — tunnels documented in `networking_deep_dive.md` |
| `architecture/admin.md` | Does not exist — use `admin_deep_dive.md` |
| `src/worker/mod.rs` (CPU offload) | `src/worker/cpu_task/` (split 2026-06) — see `mod.rs`, `state.rs`, `metrics.rs`, `payload.rs`, `dispatch.rs`, `connection.rs`, `yara.rs` |
| `src/worker/unified_server.rs` (monolithic) | `src/worker/unified_server/` (split 2026-06) — see `state.rs`, `init_apps.rs`, `init_waf.rs`, `init_mesh.rs`, `init_runtime.rs`, `init_config.rs`, `lifecycle.rs` |
| `DhtKeyPolicy` | `crates/synvoid-mesh/src/mesh/dht/key_policy.rs` (new module) |
| `SignedRaftAttestation` | `crates/synvoid-mesh/src/mesh/peer_auth.rs` (v2: binds to value digest via `value_hash`) |
| `ConsensusTransport` trait | `crates/synvoid-mesh/src/mesh/raft/consensus.rs` (new module) |
| `AuthorityFreshnessConfig` | `crates/synvoid-mesh/src/mesh/config.rs` (new struct) |

## Modular Agent Guidance

Agent guidance is **modularized** to reduce context pollution. Each module has its own `AGENTS.override.md` that contains specialized handling for that subsystem.

| Module | Override File | Purpose |
|--------|--------------|---------|
| Mesh (DHT, Raft, Network) | [`src/mesh/AGENTS.override.md`](src/mesh/AGENTS.override.md) | DHT, Raft, mesh networking patterns |
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
| Deferred Items | [`skills/deferred_items_knowledge.md`](skills/deferred_items_knowledge.md) | Context on incremental deferred item implementation |
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
- [`src/worker/unified_server.rs`] — Main unified server implementation

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
| MESH-14 | Source Node ID Binding Validation | Partial validation exists (node_id bound to TLS), but no TLS cert chain validation for global nodes - requires PKI hierarchy, trust model changes |
| HTTP2-POOL | ErasedHttpClient HTTP/2 pooling | `Http2PooledConnection` is empty stub - hyper-util API requires background task management per connection |
| MR-4 | DHT ingress auth hardening | ✅ Resolved: `DhtAntiEntropyRequest` and response now verify envelope signatures; `DhtRecordPush` envelope signature enforced; `SignedRaftAttestation` v2 binds to value digest; `DnsZone` requires Raft/quorum (no direct DHT writes); `store_record` is `pub(crate)` with `store_local_record` for local writes. Breaking protocol changes completed. |

Detailed documentation lives in `skills/` directory. See [`skills/AGENTS.override.md`](skills/AGENTS.override.md) for the full index.

The consolidated implementation plan is at [`plans/plan.md`](plans/plan.md).

## Codebase Quick Reference

### Critical Security Functions
- **Constant-time comparison**: Always use `subtle::ConstantTimeEq` for secrets
- **File permissions**: Set `0o600` on private key files
- **CSRF validation**: Uses `ct_eq()` at `src/admin/state.rs:736`
- **Session ID comparison**: Not constant-time, but acceptable (high-entropy random 32-byte values)

### Module Key Facts
- **MeshProxy**: `src/mesh/proxy.rs:63` (1994 lines) - key routing component not in overview
- **BackendType**: `src/router.rs:65-77` has 11 variants
- **SAFE_HEADERS**: `src/proxy/cache.rs:97-126` has 28 headers
- **ConfigManager**: `crates/synvoid-config/src/lib.rs:113`
- **DhtSyncRequest**: `src/mesh/transport_dht.rs:308-380` - signed by default with a config-controlled unsigned compatibility fallback; node binding is enforced in transport.
- **DhtAntiEntropyRequest**: `src/mesh/transport_peer.rs:738-751` - node binding enforced, `signer_public_key` now verified against authorized global node keys; **envelope signature also verified** (✅ MR-4 fixed). Both request and response verify envelope signatures via `verify_dht_anti_entropy_request_envelope_signature()` / `verify_dht_anti_entropy_response_envelope_signature()` in `dht/signed.rs`.
- **DhtRecordPush**: `src/mesh/dht/signed.rs:44-47` - signature field exists and is enforced; **envelope signature also verified** (✅ MR-4 fixed).
- **DhtKeyPolicyTable**: `crates/synvoid-mesh/src/mesh/dht/key_policy.rs` - centralizes key family authority policies for DHT ingress validation. **DnsZone** uses `RaftOrQuorumGlobal` authority with `remote_writes_allowed=false` — DNS zone records can only be written via Raft consensus or quorum attestation, not via direct DHT capability.
- **SignedRaftAttestation**: `crates/synvoid-mesh/src/mesh/peer_auth.rs` - requires cryptographic proof, not just structural attestation. **v2 protocol** binds attestation to value digest (`value_hash` field in `RaftAttestation`, `protocol_version=2`); v1 compat preserved for attestations without value_hash.
- **ConsensusTransport**: `crates/synvoid-mesh/src/mesh/raft/consensus.rs` - decouples Raft consensus from mesh transport layer.
- **AuthorityFreshnessConfig**: `crates/synvoid-mesh/src/mesh/config.rs` - defines stale-state behavior for authority records.
- **DNS Cookie Server**: `src/dns/cookie.rs` - fully wired via `validate_cookie()` in query.rs:645-662
- **TunnelRouter**: `src/tunnel/router.rs:200` - active routing uses `resolve_tunnel_backend()` (TunnelBackend struct removed)
- **HickoryRecursor DNSSEC**: `src/dns/resolver.rs:693-702` - uses `ValidateWithStaticKey` when `enable_dnssec=true` (✅ FIXED)
- **HTTP/3 Body Collection**: `src/http3/server.rs:340-398` - ad-hoc implementation, not using shared_handler
- **BufferPool**: 4 tiers (small/medium/large/jumbo)

### Process Architecture
- **Supervisor** manages lifecycle, consolidates Supervisor
- **UnifiedServerWorker** uses single Tokio event loop (NOT process-per-tenant)
- **CPU affinity** is Linux-only, logs warning on other platforms
- **Default entry point** is `run_supervisor_mode()` via `src/main.rs`
- **Mesh control plane** runs in Supervisor process, not worker (workers get intelligence via IPC)

### Granian Integration
- **Granian IS integrated** - `src/app_server/granian.rs` (1047 lines) with full process management, auto-install, admin API
- NOT a separate process type - runs within the Supervisor architecture

### Implementation Notes
- **PeakEwma weighting**: Slow-moving (90% to old value) is intentional for connection stability
- **BUG-ROUTER-1**: Hardcoded port 80 is in `Default` impl only, actual usage uses configured port - NOT a bug
- **Spin header serialization**: Uses JSON (SpinRuntime::serialize_headers_spin), not binary like raw WASM
- **Spin idle instance eviction**: `instances` HashMap keyed by UUID grows indefinitely — old entries never cleaned up (plan DOC-L7)
- **Email alerting is a stub**: `send_email_internal()` at `src/admin/alerting/mod.rs:349-373` logs message then returns `Ok(())` without sending
- **Audit log redundant permissions**: `src/admin/audit.rs:131-139` re-applies permissions on every write — already set in `with_audit_dir()`

## Skills Directory

The `skills/` directory contains detailed documentation for various subsystems:

| Skill | Purpose |
|-------|---------|
| `admin_api.md` | Admin API patterns |
| `admin_ui.md` | Admin UI patterns |
| `behavioral_intel.md` | Behavioral intelligence |
| `buffer_pool.md` | Sharded mutex buffer pool (replaces TreiberStack with ABA-safe implementation) |
| `crypto_dependencies.md` | Cryptographic dependency analysis |
| `deferred_items_knowledge.md` | Context on incremental deferred item implementation |
| `dht_persistence.md` | DHT neighborhood persistence |
| `dht_scoping.md` | DHT site isolation and scoping patterns |
| `dns_dnssec.md` | DNS and DNSSEC patterns |
| `ebpf_blocking.md` | eBPF-based traffic blocking |
| `erased_http_client.md` | ErasedHttpClient streaming pool patterns |
| `extension_runtime.md` | ExtensionRuntime trait and registry for worker lifecycle management |
| `fastcgi_streaming.md` | FastCGI streaming client patterns |
| `h3_proxy.md` | HTTP/3 QUIC proxy patterns |
| `hickory_migration.md` | Hickory DNS resolver migration |
| `honeypot.md` | Honeypot detection and response |
| `httpserver.md` | HTTP server architecture |
| `hybrid_post_quantum.md` | Post-quantum signature implementation |
| `implementation_patterns.md` | Common implementation patterns (semaphore, debounce, atomic writes) |
| `ipc_hardening.md` | IPC signing, replay protection, and authentication patterns |
| `org_key_trust_chain.md` | Organization key trust chain |
| `performance_patterns.md` | Performance optimization patterns |
| `quorum_manager_fix.md` | Quorum Manager race condition fix (historical) |
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
| `wasm_components.md` | WASM component model patterns |
| `windows_service.md` | Windows service integration |
