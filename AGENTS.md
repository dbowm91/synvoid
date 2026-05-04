# AGENTS.md - Developer Guide for AI Agents

This is the **repository index** for AI agents working on the MaluWAF codebase.

## Modular Agent Guidance

Agent guidance is **modularized** to reduce context pollution. Each module has its own `AGENTS.override.md` that contains specialized handling for that subsystem.

| Module | Override File | Purpose |
|--------|--------------|---------|
| Mesh (DHT, Raft, Network) | [`src/mesh/AGENTS.override.md`](src/mesh/AGENTS.override.md) | DHT, Raft, mesh networking patterns |
| DNS (DNSSEC, TSIG) | [`src/dns/AGENTS.override.md`](src/dns/AGENTS.override.md) | DNS server, DNSSEC, TSIG patterns |
| WAF (Rule Matching) | [`src/waf/AGENTS.override.md`](src/waf/AGENTS.override.md) | WAF engine, attack detection |
| HTTP Server | [`src/http/AGENTS.override.md`](src/http/AGENTS.override.md) | HTTP request handling |
| HTTP/3 Server | [`src/http3/AGENTS.override.md`](src/http3/AGENTS.override.md) | HTTP/3 QUIC handling |
| Plugin/WASM | [`src/plugin/AGENTS.override.md`](src/plugin/AGENTS.override.md) | WASM plugin runtime |
| Upstream Proxy | [`src/proxy/AGENTS.override.md`](src/proxy/AGENTS.override.md) | Proxy routing, cache keys |
| Config | [`src/config/AGENTS.override.md`](src/config/AGENTS.override.md) | Configuration patterns |
| Admin API | [`src/admin/AGENTS.override.md`](src/admin/AGENTS.override.md) | Admin API patterns |
| Auth | [`src/auth/AGENTS.override.md`](src/auth/AGENTS.override.md) | Authentication patterns |
| Platform/Systems | [`src/platform/AGENTS.override.md`](src/platform/AGENTS.override.md) | Platform abstraction, IPC, sandboxing |
| Deferred Items | [`skills/deferred_items_knowledge.md`](skills/deferred_items_knowledge.md) | Context on incremental deferred item implementation |
| Skills | [`skills/AGENTS.override.md`](skills/AGENTS.override.md) | Skill file documentation |

## Project Overview

MaluWAF is a WAF (Web Application Firewall) with a multi-process architecture:
- **Overseer** (`src/overseer/`): Manages master process lifecycle, upgrades, health monitoring
- **Master** (`src/master/`): Parent process that spawns/manages workers, handles IPC
- **Worker** (`src/worker/`): Handles HTTP requests and communicates via IPC

### Architecture Documents

Key reference documents in `architecture/` directory:
- [`architecture/overview.md`](architecture/overview.md) — Module categorization and layer overview
- [`architecture/deep_dive_review.md`](architecture/deep_dive_review.md) — Layer 1-3 and 7 deep dive (IPC, WAF, Proxy, Foundation)
- [`architecture/layer_3_5_deep_dive.md`](architecture/layer_3_5_deep_dive.md) — Layer 3 & 5 deep dive (Proxy & Mesh, PQC, Trust Models)

### Scalability Target

MaluWAF is designed for **high scalability** with targets well in excess of **1000K requests/second** (1 million RPS).

This has several implications:
- **Every allocation matters**: At 1000K rps, even small per-request allocations compound to millions/sec
- **Avoid O(n) operations in hot paths**: Linear searches, repeated string conversions, unnecessary clones
- **Prefer O(1) lookups**: HashMap/HashSet over Vec iteration for any frequency
- **Reuse buffers**: Thread-local buffers, object pools, moka caches instead of per-request allocations
- **Lazy evaluation**: Only compute what's needed; defer expensive operations until confirmed necessary

### Hot Path Locations

The following code paths execute on every request and must be optimized:
- `src/waf/attack_detection/` — WAF rule matching (runs per-request on all inputs)
- `src/mesh/proxy.rs` — Mesh proxy routing, caching, provider selection
- `src/http/server.rs` — HTTP request handling and dispatch
- `src/http3/server.rs` — HTTP/3 QUIC request handling and proxying
- `src/proxy/mod.rs` — Upstream proxy, cookie/cache key construction
- `src/plugin/wasm_runtime.rs` — WASM plugin filter/transform per request

## General Conventions

### Dependency Policy

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

### Verification Commands

```bash
cargo test --lib --no-run    # Verify tests compile
cargo test --lib <test_name> # Run targeted test
cargo test --test integration_test
cargo test --test security_regression  # Security regression tests
cargo fmt && cargo clippy --lib -- -D warnings
```

### Architecture Profile Gates

MaluWAF supports feature-gated profiles. Verify compilation for each profile:

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
| `src/mesh/proxy.rs:1485` | `src/mesh/transport.rs:986` + `src/config/site/misc.rs:37` |

## Multi-Process Architecture

MaluWAF uses a multi-process architecture designed for **high scalability (1M+ RPS)** with **millions of tenants**:

### Process Hierarchy

| Process | Flag | Purpose | Default Count |
|---------|------|---------|---------------|
| **Overseer** | (default) | Manages master lifecycle, upgrades, health monitoring | 1 |
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

## Skills Reference

Detailed documentation lives in `skills/` directory. See [`skills/AGENTS.override.md`](skills/AGENTS.override.md) for the full index.
