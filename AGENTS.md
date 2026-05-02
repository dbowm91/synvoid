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

**Note**: Core/mesh/dns profiles currently have compilation errors (~220/85/264 errors). These are being tracked in `plans/plan.md` section 4.2 (Architecture Gates).

## Known File Path Corrections

| Wrong Path | Correct Path |
|------------|--------------|
| `src/http/client.rs` | `src/http_client/mod.rs` |
| `src/mesh/proxy.rs:1485` | `src/mesh/transport.rs:986` + `src/config/site/misc.rs:37` |

## Implementation Wave Organization

When implementing work from `plans/plan.md`, follow this wave structure:

| Wave | Items | Parallel Tracks | Key Dependency |
|------|-------|----------------|---------------|
| **0** | Architecture Gates (4.2) | No | Must lead - blocks all compilation |
| **1** | Socket/PID Hardening, Sandbox Hardening, IPC Signing Hardening | **Yes** (3 tracks) | After Wave 0 |
| **2** | IPC Consolidation, Buffer Pool Audit, Architecture Profiles, Control Plane Boundaries | Partial | IPC Consolidation depends on IPC Signing Hardening |
| **3** | WAF Entrypoint Matrix, Traffic Entrypoint Matrix, HTTP Server Pipeline Split | **Yes** | After Wave 0 |
| **4** | Plugin Isolation, Config Reload Contract, Runtime Ownership Inventory | **Yes** | After Wave 0 |
| **5** | Systems-Layer CI, Platform Support Matrix, Platform Firewall | **Yes** | After Wave 0 |
| **6** | Worker Runtime Split, Singleton Inventory | No | Worker Runtime Split depends on Singleton Inventory |

**Max Parallelism**: After Wave 0 completes, 10+ independent tracks can run in parallel.

See `plans/plan.md` for detailed actionable items within each wave.

## Skills Reference

Detailed documentation lives in `skills/` directory. See [`skills/AGENTS.override.md`](skills/AGENTS.override.md) for the full index.
