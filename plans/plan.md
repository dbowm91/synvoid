# MaluWAF Implementation Plan

**Status**: All Wave 1-5 Items Complete
**Last Updated**: 2026-04-29
**Verification Completed**: 2026-04-29 (Wave 5)

---

## Overview

All implementation waves (1-5) are **COMPLETE**.

**Wave 1-5 Implementation Summary:**
- Wave 1: Codebase Health & Testing Foundations (W1.1-W1.3)
- Wave 2: Performance & Scalability (W2.1-W2.4)
- Wave 3: Multi-Tenancy & Plugins (W3.1-W3.2)
- Wave 4: Security & Resilience (W4.1-W4.2)
- **Wave 5: OS Foundations & Core Optimization (W5.1-W5.3) [COMPLETE]**

---

## Active Plan: Wave 5 - OS Foundations & Core Optimization

| # | Task | Description | Status |
|---|------|-------------|--------|
| **W5.1** | **Windows Sandboxing** | Implement Job Objects and Process Mitigation Policies for OS-level confinement on Windows. | **COMPLETE** |
| **W5.2** | **macOS Sandboxing** | Implement `Sandbox.kext` (Scheme-based profiles) for macOS parity. | **COMPLETE** |
| **W5.3** | **Lock-Free BufferPool** | Replace sharded Mutexes with Thread-Local caches and Global Lock-Free Shards (Treiber stacks). | **COMPLETE** |

### W5.1: Windows Sandboxing (COMPLETE)
- Implemented `WindowsSandbox` using Windows Job Objects
- `CreateJobObjectW` for memory limits (256MB process, 512MB job)
- `KillOnJobClose` for automatic cleanup on parent exit
- DEP and ASLR mitigation policies via `SetProcessMitigationPolicy`
- `AssignProcessToJobObject` to apply sandbox to current process

### W5.2: macOS Sandboxing (COMPLETE)
- Implemented `SeatbeltSandbox` using macOS sandbox_init
- Dynamic Scheme profile generation based on `SandboxPaths`
- Basic mode: deny default, allow file-read* for allowed paths
- Strict mode: deny default, allow process/signal/job-creation only
- Requires `macos-sandbox` feature for actual enforcement

### W5.3: Lock-Free BufferPool (COMPLETE)
- `TreiberStack`: Lock-free stack using compare-and-swap
- `ThreadLocalCache`: 16 buffers per tier, zero atomic overhead in common case
- `TierArena`: Per-tier arena wrapping TreiberStack
- Hot path: `acquire` checks TLS cache first; `release` pushes to TLS first
- Backward compatible API - all 26 existing tests pass

---

## Recently Completed Items

| # | Issue | Fix | Date |
|---|-------|-----|------|
| P1.8 | `proxy_cache` not wired in `MeshProxy::route_request()` | Wired cache lookup/insert in `proxy_to_peer_with_fallback()` at `src/mesh/proxy.rs:1169-1259`. Added cache key builder, `is_cacheable_method`, `should_bypass_cache`, `is_response_cacheable`, `get_cache_max_age` helpers. | 2026-04-28 |
| P11.1 | Spin WASM HTTP routing not integrated | Added `BackendType::Spin` to router.rs, `spin_app_name` to RouteTarget, `BackendConfig::Spin` to config/site/backend.rs, and HTTP dispatch in server.rs at lines 1961-2048. | 2026-04-28 |
| P7A | WireGuard mesh transport enum not fully removed | Removed deprecated `WireGuard` variant from `MeshTransportPreference` in `src/mesh/config.rs:616-620`. Cleaned up `src/mesh/backend.rs:354-357` and `src/mesh/protocol.rs:1181-1185`. | 2026-04-28 |
| D1 | dashmap 5.5.3 → 7.0.0-rc2 | Updated version in Cargo.toml. Verified compilation. | 2026-04-28 |
| W1.1 | Strategic metrics module split | Split `src/metrics/mod.rs` into `src/metrics/payloads.rs` (structs) and `src/metrics/collection.rs` (atomic counters). Re-exports maintained for public API compatibility. | 2026-04-28 |
| W1.2 | Continuous fuzzing integration | Added `fuzz/fuzz_early_parse.rs` and `fuzz/fuzz_protocol_proto_decode.rs` targets to fuzz/Cargo.toml. | 2026-04-28 |
| W1.3 | E2E fault injection test | Added test simulating worker crash mid-request in `tests/integration_test.rs` for Overseer recovery verification. | 2026-04-28 |
| W2.1 | Zero-copy HTTP proxying | Implemented streaming body pipe for large responses (>1MB) in `src/http/server.rs` to reduce allocations at 500K RPS. | 2026-04-28 |
| W2.2 | HTTP/3 zero-copy proxying | Applied streaming body optimization to QUIC proxy paths in `src/http3/server.rs`. | 2026-04-28 |
| W2.3 | DHT routing LRU cache | Added moka-based LRU cache to `RoutingTable::find_closest` for O(1) hot path lookups. | 2026-04-28 |
| W2.4 | QUIC stream pooling | Implemented `StreamPool` in `src/tunnel/quic/client.rs` to reuse streams per peer instead of opening/closing per message. | 2026-04-28 |
| W3.1 | Site isolation audit | Audited `ratelimit.rs`, `rule_feed.rs`, and `WorkerMetrics` - found already properly isolated per site. | 2026-04-28 |
| W3.2 | WASM Component Model support | Created `src/plugin/plugin.wit` WIT file, added `load_component` implementation using wasmtime Component API. | 2026-04-28 |
| W4.1 | Automated threat feed ingestion | Created `src/waf/threat_intel/feed_client.rs` with Ed25519 signature verification and background fetch task. | 2026-04-28 |
| W4.2 | Threat feed DHT distribution | Added `ThreatFeedUpdate` IPC message, `broadcast_threat_feed_update`, and `publish_feed_indicator_to_dht` using SiteScoped keys. | 2026-04-28 |

---

## Deferred Items

These items are intentionally deferred and do not block the current release:

| # | Issue | Reason |
|---|-------|--------|
| D7 | God module splits | Skipped: module splits of 10k+ lines introduce too much regression risk for automated agents; keeping intact to ensure no capability reversions |

---

## Recently Fixed Items

| # | Issue | Fix | Date |
|---|-------|-----|------|
| D11 | DNS TSIG timing side channel | Replaced XOR loop with `subtle::ConstantTimeEq::ct_eq()` at `src/dns/tsig.rs:237-240` | 2026-04-28 |

---

## Removed Items (Verified False/Invalid)

| # | Original Claim | Resolution |
|---|----------------|------------|
| ~~P0.10~~ | Rate Limit Bypass via WASM Filters | **REMOVED**: Wrong file references. Actual execution order (rate limit → WASM) is correct. WASM-blocked requests consuming rate limit quota is intended DDoS protection behavior. |
| ~~P0.11~~ | AxumDynamic WAF Bypass | **REMOVED**: False claim. AxumDynamic dispatch is inside the `WafDecision::Pass` branch — WAF checks ARE applied. |

---

## Key Codebase Facts

- **Architecture**: Overseer → Master → Workers (Unix domain socket IPC)
- **Mesh types**: `MeshBackend`, `MeshBackendPool` in `src/mesh/backend.rs`
- **Base64**: `get_public_key()` uses `URL_SAFE_NO_PAD`; any decoder using `STANDARD` is wrong for mesh/DHT keys
- **Serialization**: Use `crate::serialization::serialize/deserialize` (Postcard) for binary; JSON only for admin API
- **Timestamps**: Use `u64` via `crate::mesh::safe_unix_timestamp()` or `crate::utils::current_timestamp()`
- **WireGuard**: MESH transport deprecated/non-functional (slated for removal in P7A). VPN tunnel (`src/tunnel/wireguard/`) is separate and working.

---

## Verification Commands

```bash
# Verify tests compile (cargo check does NOT compile test code)
cargo test --lib --no-run

# Run targeted tests
cargo test --lib <test_name>
cargo test --test integration_test

# Format and lint
cargo fmt
cargo clippy -- -D warnings

# Feature-specific checks
cargo check --features dns
cargo check --features post-quantum
```

---

## Historical Context

All waves 1-4 were implemented and verified between 2026-04-27 and 2026-04-28. The full history of completed items is maintained in AGENTS.md under "Recently Completed Items."
