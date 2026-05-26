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
| **Supervisor** | (default) | Manages master lifecycle, upgrades, health monitoring; consolidates legacy Overseer and Master | 1 |
| **Master** | `--master` | Spawns/manages workers, handles IPC, runs admin API | 1 |
| **UnifiedServerWorker** | `--unified-server-worker` | Handles HTTP/HTTPS/HTTP3 + WAF + proxy | 1 |
| **StaticWorker** | `--static-worker` | CSS/JS minification, compression | 1 |
| **BaseWorkerProcess** | `--worker` | Legacy raw TCP/UDP proxy (deprecated, unused for HTTP) | configurable |

### UnifiedServerWorker: Single Process for HTTP/HTTPS/HTTP3

**The unified worker uses a single Tokio async event loop** which is far more efficient than spawning multiple worker processes:

1. **Tokio's optimization**: A single Tokio runtime with `worker_threads` equal to CPU cores handles all cores efficiently via cooperative scheduling. Adding more worker processes adds process isolation overhead but NOT throughput.

2. **Millions of tenants**: We cannot use process-per-tenant isolation (too many processes). All tenants share the same async event loop with O(1) domain-based routing.

3. **Scaling approach**: For scaling, tune `tcp.worker_pool_size` (connection accepting threads) or use async primitives within the existing event loop. **Do NOT increase `unified_server_workers` for scaling purposes** — this only affects the number of Tokio runtime threads.

### BaseWorkerProcess (Legacy - Not Used for HTTP)

The `--worker` flag spawns `BaseWorkerProcess` which receives a dedicated port. However:
- **No HTTP handler exists** for this mode in `main.rs`
- The code path exists but is **never invoked** for normal HTTP traffic
- It may be legacy pre-unified design or for raw TCP/UDP proxy scenarios
- The admin API `/system/workers/scale` only scales `BaseWorkerProcess` count
- **Requires investigation** to determine if it should be removed or completed

### Reference Documents

- [`docs/adr/ADR-003-unified-worker-process.md`](docs/adr/ADR-003-unified-worker-process.md) — ADR for unified worker architecture
- [`src/worker/unified_server.rs`] — Main unified server implementation

## Key Codebase Facts

### Security-Critical Bugs (Known)

| Bug ID | Location | Issue | Status |
|--------|----------|-------|--------|
| BUG-L3 | `src/mesh/ml_kem_key_exchange.rs:204-265` | ML-KEM key exchange proof-of-possession | FIXED |
| BUG-ROUTER-1 | `src/router.rs:1318` | Hardcoded port 80 instead of configured port | FIXED |

### Known Implementation Issues

| Issue | Location | Impact | Status |
|-------|----------|--------|--------|
| `use_erased_client` hardcoded to `false` | `src/http/server.rs:3305` | ErasedHttpClient now uses conditional logic based on `body_buffering_policy.should_stream()` | FIXED |
| HTTP/2 available but not enforced | `src/http_client/mod.rs:893` | `is_http2 = true` hardcoded in `send_request_erased_streaming`, infrastructure exists and uses `http2_only(false)` allowing HTTP/2 | Known |
| DNS Cookie Server not integrated | `src/dns/cookie.rs`, `src/dns/server/mod.rs` | Complete implementation exists but not wired in | Known |
| Capsicum `limit_fd()` dead code | `src/platform/sandbox.rs:516-528` → FIXED | Method removed - dead code eliminated | FIXED |

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

### Verified "Already Fixed" Items

These items were identified in reviews and have been fixed:
- LocationMatcher `current_depth()` stub removed (`src/location_matcher.rs:191-195` - only `is_empty()` and `len()` exist; no stub was ever present)
- Audit log file permissions (`src/admin/audit.rs:76` - permissions set in `log()` method)
- StreamingWafCore trailing window logic (`src/waf/attack_detection/streaming.rs:129-134` - correct sliding window)
- gRPC uptime calculation (`src/supervisor/api.rs:55` - returns elapsed time)
- CSRF validation constant-time comparison (`src/admin/state.rs:736` - uses `ct_eq()`)
- macOS sandbox feature gate exists (`Cargo.toml:38` - just needs enabling)
- BUG-L1 verify_hybrid() fail-safe (`src/mesh/ml_dsa.rs:217` - returns true when ML-DSA absent, fail-safe behavior confirmed)
- BUG-PL-1 Master mode CLI flag (`src/main.rs:27` - --master flag now functional for legacy Overseer->Master hierarchy)
- BUG-PROXY-1 retry_config applied (`src/proxy/mod.rs:303` - uses parameter value not None)
- allowed_dht_prefixes propagated to pooled instances (`src/serverless/instance_pool.rs:190`, `src/plugin/instance_pool.rs:186`)
- UpstreamPool active health checks (`src/upstream/pool.rs:751-779` - start_health_check method)
- BUG-L3 ML-KEM proof-of-possession (`src/mesh/ml_kem_key_exchange.rs:204-265` - confirm_key now verifies client can decapsulate)
- SiteConnectionLimiter unused params (`src/waf/traffic_shaper/limiter.rs:312-323` - `_max_connections` etc. never used) - **NOTE:** This bug still exists and needs fixing - see `plans/plan.md`
- DnsConfig.validate() now called in MainConfig::validate() (`crates/synvoid-config/src/main_config.rs:192-203`) - **FIXED**

## Known Deferred Items

Some items are intentionally deferred due to architectural complexity:

| ID | Issue | Reason |
|----|-------|--------|
| MESH-14 | No Source Node ID Binding Validation in All Ingress Paths | Requires fundamental changes to bind node_id to TLS/cert identity |
| MESH-15 | Quorum Deadlock Risk During Partition | Raft implementation incomplete, requires Raft migration |
| APP-15 | FastCGI Response NOT Truly Streamed | Buffers entire stdout; architectural change needed |
| SUP-1 | gRPC Control Plane TLS | Intentional - localhost IPC doesn't need TLS |

Detailed documentation lives in `skills/` directory. See [`skills/AGENTS.override.md`](skills/AGENTS.override.md) for the full index.

## Codebase Quick Reference

### Critical Security Functions
- **Constant-time comparison**: Always use `subtle::ConstantTimeEq` for secrets
- **File permissions**: Set `0o600` on private key files
- **CSRF validation**: Uses `ct_eq()` at `src/admin/state.rs:736`

### Module Key Facts
- **MeshProxy**: `src/mesh/proxy.rs:63` (1994 lines) - key routing component not in overview
- **BackendType**: `src/router.rs:65-77` has 11 variants
- **SAFE_HEADERS**: `src/proxy/cache.rs:97-126` has 28 headers
- **ConfigManager**: `crates/synvoid-config/src/lib.rs:113`

### Process Architecture
- **Supervisor** manages lifecycle, consolidates Overseer + Master
- **UnifiedServerWorker** uses single Tokio event loop (NOT process-per-tenant)
- **CPU affinity** is Linux-only, logs warning on other platforms
- **Default entry point** is `run_supervisor_mode()` via `src/main.rs:538-547`; `--master` flag routes to `run_master_mode()`

### Granian Integration
- **Granian IS integrated** - `src/app_server/granian.rs` (1047 lines) with full process management, auto-install, admin API
- NOT a separate process type - runs within the Supervisor/Master architecture

### Supervisor Migration (Planned)
- See `plans/plan.md` for consolidated action plan
- Migration to consolidate Overseer/Master into Supervisor (~8 days sequential work)
- All other plan items can be executed in parallel with migration waves

## Skills Directory

The `skills/` directory contains detailed documentation for various subsystems:

| Skill | Purpose |
|-------|---------|
| `security_patterns.md` | Critical security fixes, constant-time comparison, path traversal, XSS prevention |
| `streaming_waf.md` | Streaming WAF engine patterns |
| `dht_persistence.md` | DHT neighborhood persistence |
| `hybrid_post_quantum.md` | Post-quantum signature implementation |
| `spin_wasm.md` | Spin WASM runtime |
| `serverless_wasm.md` | Serverless WASM patterns |
| `synvoid_mesh.md` | Mesh networking patterns |
| `topology_visualizer.md` | Topology visualizer API |
| `behavioral_intel.md` | Behavioral intelligence |
| `performance_patterns.md` | Performance optimization patterns |
| `admin_api.md` | Admin API patterns |
| `dns_dnssec.md` | DNS and DNSSEC patterns |
| `wasm_components.md` | WASM component model patterns |
| `dht_scoping.md` | DHT site isolation and scoping patterns |
| `threat_feed_production.md` | Production and signing of threat intel feeds |
| `raft_consensus.md` | Raft consensus integration for global control plane |
| `sandboxing.md` | OS sandboxing (Windows/macOS/Linux/BSD) |
| `ipc_hardening.md` | IPC signing, replay protection, and authentication patterns |
| `deferred_items_knowledge.md` | Context on incremental deferred item implementation |
| `buffer_pool.md` | Sharded mutex buffer pool (replaces TreiberStack with ABA-safe implementation) |
| `extension_runtime.md` | ExtensionRuntime trait and registry for worker lifecycle management |
| `quorum_manager_fix.md` | Quorum Manager race condition fix with Raft oneshot completion |
| `supply_chain_hashes.md` | Supply chain security with pip --require-hashes |
| `erased_http_client.md` | ErasedHttpClient Phase 9 incomplete integration |