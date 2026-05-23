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
| `src/http/shared_handler.rs` | `src/http/server.rs:4532` (contains `collect_body_with_chunk_waf` and `stream_body_with_waf`) |
| `src/mesh/proxy.rs:1485` | `src/mesh/transport.rs:986` + `src/config/site/misc.rs:37` |
| `src/mesh/raft/state_machine.rs:166-172` (quorum verify) | `src/mesh/dht/signed.rs:860-934` |
| `tests/security_regression.rs` | `tests/security_regression.rs` — Security regression tests for header sanitization |
| `src/mesh/dht/quorum.rs:339-386` | Quorum Manager race condition - ✅ FIXED: Uses oneshot channel with Result tracking |
| `src/mesh/dht/record_store_message.rs:1319-1345` | check_quorum_completion treats failed Raft writes as timeout - MESH-11 ✅ FIXED |
| `src/supervisor/api.rs:114-129` | gRPC server binds to localhost only for local IPC - TLS not required |
| `src/fastcgi/mod.rs:132-164` | FastCGI buffered response - known limitation, true streaming requires architectural change |
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

## Implementation Planning

When working on large implementation plans:

### Wave-Based Execution

Large plans should be organized into **waves** that can execute in parallel:
- **Wave 1**: Critical items with no dependencies (security fixes, compile blockers)
- **Wave 2**: Items depending on Wave 1 completion
- **Wave 3**: Items that can run parallel to other waves (e.g., WAF streaming optimization)
- **Wave 4+**: Remaining items organized by priority

### Verification Approach

1. **Batch file reads** with subagents to preserve context window (4-5 files per agent)
2. **Verify file references** before adding to plan — subagents catch discrepancies
3. **Use explore agents** for codebase verification tasks
4. **Cross-reference** with actual code when discrepancies found

### Key Discrepancies to Watch For

| Planned Reference | Actual Location | Issue |
|-------------------|-----------------|-------|
| `src/http/shared_handler.rs` | `src/http/server.rs:4532` | Function is in server.rs, not shared_handler |
| `src/mesh/raft/state_machine.rs:166-172` | `src/mesh/dht/signed.rs:860-934` | Quorum verification is in signed.rs, not state_machine |

### Lessons Learned (2026-05-23)

1. **Process hierarchy is three-tier in traditional mode** - The codebase supports two deployment models:
   - **Consolidated (recommended)**: Supervisor → Workers directly
   - **Traditional (legacy)**: Overseer → Master → Workers
   The Master process still exists via `--master` flag and is managed by Overseer.

2. **Config field propagation** - When adding new fields to config structs, ensure they propagate through all layers (SiteAppServerConfig → AppServerConfig → GranianConfig). Missing propagation caused require_hashes to not work.

3. **Dead code detection** - When code blocks are duplicated with no intervening return/break, check if second block is unreachable dead code. The second GLOBAL_EDGE block in `peer_auth.rs` was identical to the first and unreachable.

4. **gRPC server has no TLS** - `src/supervisor/api.rs:114-129` uses plaintext gRPC. Claims of "protected by TLS" in docs are inaccurate. This is intentional for localhost IPC - not a bug.

5. **SAFE_HEADERS count is 28** - `src/proxy/cache.rs:97-126` has 28 headers, not 27 or 29.

6. **Plugin instance pool bugs** - `src/plugin/instance_pool.rs` had two bugs that are now fixed:
   - `prepare_for_request()` didn't reset `body_receiver` - caused streaming failures on pooled instances
   - `warmup()` only linked `abort` and `check_timeout` - missing 5 functions: `get_env`, `synvoid_read_body_chunk`, `mesh_query_dht`, `mesh_check_threat`, `mesh_emit_event`

7. **Spin find_route uses longest-prefix-match** - `src/spin/runtime.rs:271-285` collects all route matches and returns the longest prefix match.

8. **WAF fast-path bypass** - `src/waf/attack_detection/mod.rs:425-435` had early return when fast-path was safe, but request smuggling patterns were NOT in fast_path_patterns. Fixed by adding smuggling indicators (`transfer-encoding`, `content-length`) and expanding patterns from 13 to 38.

9. **Flood protector not integrated** - `src/waf/mod.rs:438-508` flood_protector existed but was NOT called during request pipeline. Now integrated into `check_request_full()` pipeline.

10. **DHT ingress verification gaps** - `src/mesh/dht/signed.rs:42-48` documents unverified paths: DhtSyncRequest, DhtAntiEntropyRequest, DhtRecordPush, DhtRecordCommit, QuorumStoreRequest, QuorumSignatureResp. Known architectural limitation.

11. **Spin routing IS integrated** - Spin routing is integrated into HTTP dispatch at `src/http/server.rs:2417-2489`. When `BackendType::Spin` is configured, requests go through `SpinHttpHandler`. Spin requires manual app registration via Admin API.

12. **CPU affinity pinning is Linux-only, not automatic** - `src/worker/unified_server.rs:205-208` shows CPU affinity only works on Linux. On macOS/BSD it logs a warning but does nothing. Must be explicitly configured via `cpu_affinity` parameter, not automatic.

13. **macOS Seatbelt sandbox is planned, not implemented** - `src/platform/sandbox.rs` does not have a `macos-sandbox` feature gate. The seatbelt implementation is planned but not yet implemented.

14. **ConfigManager is in synvoid-config crate** - `ConfigManager` is at `crates/synvoid-config/src/lib.rs:113`, not in `main_config.rs`.

15. **MeshProxy is a key routing component** - `src/mesh/proxy.rs:63` (1996 lines) handles backend routing via mesh but wasn't documented in architecture overview.

## Skills Reference

Detailed documentation lives in `skills/` directory. See [`skills/AGENTS.override.md`](skills/AGENTS.override.md) for the full index.
