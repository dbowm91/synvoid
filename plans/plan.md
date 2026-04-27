# MaluWAF Implementation Plan

**Status**: Active - Implementation Phase
**Last Updated**: 2026-04-27
**Verification Completed**: 2026-04-27

## Current Wave Status

### Wave 1.1: Streaming WAF Engine (2026-04-27)
- **Status**: COMPLETED

### Wave 1.2: DHT Neighborhood Persistence (2026-04-27)
- **Status**: COMPLETED

### Wave 2.1: Hybrid Post-Quantum Mesh Signatures (2026-04-27)
- **Status**: COMPLETED

### Wave 2.2: Windows Service & DX (2026-04-27)
- **Status**: COMPLETED

### Wave 3.1: Federated Behavioral Intelligence (2026-04-27)
- **Status**: COMPLETED

### Wave 3.2: Real-time Topology Visualizer (2026-04-27)
- **Status**: COMPLETED

---

## Implementation Phases

These phases identify which items can be executed in parallel by different agents.

### Phase 1: Critical Security (Sequential Start, then parallelize)

**Critical fixes that must be completed first before other work:**

| # | Issue | Files | Est. Time | Dependencies |
|---|-------|-------|-----------|--------------|
| P0.5 | Time-based challenge verification bypass | `src/mesh/security_challenge.rs:159-190` | 2h | None |
| P0.6 | Pass-over fallback signing violation | `src/mesh/passover_key_exchange.rs:469-534` | 1h | None |
| P0.7 | RecordStoreManager clone empty | `src/mesh/dht/record_store.rs:468-519` | 2h | None |

*After completing P0.5, P0.6, P0.7, these can run in parallel:*
| P0.1 | WASM `table_growing` unbounded | `src/plugin/wasm_runtime.rs:319-326` | 1-2h | P0.5 |
| P0.2 | WASM pool DHT prefix leakage | `src/plugin/instance_pool.rs:148-159` | 2-3h | P0.5 |
| P0.3 | Threat intel signer bypass | `src/mesh/threat_intel.rs:1606-1621` | 30m | P0.5 |
| P0.4 | Serverless ignore limits | `src/serverless/manager.rs:479-491,506-518` | 30-60m | P0.5 |
| P0.8 | Severity-aware threat broadcast | `src/mesh/threat_intel.rs:1507-1535` | 1h | P0.5, P0.6 |
| P0.9 | Threat duplicate detection key mismatch | `src/mesh/threat_intel.rs:831,1066,1165` | 1h | P0.8 |
| P0.10 | Rate Limit Bypass via WASM Filters | `src/worker/unified_server.rs:1431,2317-2347` | 2-3h | P0.1 |
| P0.11 | AxumDynamic WAF Bypass | `src/http/server.rs:1702-1741` | 1-2h | P0.10 |
| P0.12 | YARA trusted_signer global bypass | `src/mesh/yara_rules.rs:942-954,1761-1812` | 2h | P0.5 |

### Phase 2: High Priority Functional (Parallel)

These items can all be worked on in parallel after Phase 1 completes:

| # | Issue | Files | Est. Time | Can Parallelize With |
|---|-------|-------|-----------|---------------------|
| P1.1 | BackendType::Mesh Not Integrated | `src/router.rs:65,504,748`, `src/http/server.rs`, `src/mesh/proxy.rs` | 3-4h | All |
| P1.2 | HTTP Client Cache Undersized | `src/http/client.rs` | 1h | All |
| P1.3 | No Upstream Load Balancing | `src/http/server.rs`, `src/mesh/proxy.rs` | 2-3h | All |
| P1.4 | Message Cache Severely Undersized | `src/mesh/transport.rs:239-244` | 2h | All |
| P1.5 | Unbounded Proxy Task Spawn | `src/mesh/proxy.rs:962-997` | 2h | All |
| P1.6 | WASM instance pooling bypass | `src/plugin/wasm_runtime.rs` | 2-3h | All |
| P1.7 | Enforce `edge_only` flag | `src/mesh/proxy.rs:1485` | 1h | All |
| P1.8 | Wire `proxy_cache` in MeshProxy | `src/mesh/proxy.rs:72,333,356,1281-1289` | 2h | All |
| P1.9 | WAF double normalization | `src/waf/attack_detection/{sqli,xss,ssti}.rs` | 2h | All |
| P1.10 | Mesh provider_stats lock contention | `src/mesh/proxy.rs` | 1h | All |
| P1.11 | Sync-on-join YARA/threat intel | `src/mesh/transport_connection.rs:212-253` | 2h | All |
| P1.12 | ServerlessInvokeResponse handling | `src/mesh/transport_peer.rs` | 2h | All |
| P1.13 | Add ServerlessInvokeRequest sender | New `src/mesh/transport_serverless.rs` | 3h | P1.12 |
| P1.14 | Initialize WasmDistManager | `src/mesh/transport.rs` | 1h | P1.1 |

### Phase 3: Performance & Code Quality (Parallel)

These can run in parallel with Phase 2 or after:

| # | Issue | Files | Est. Time | Can Parallelize With |
|---|-------|-------|-----------|---------------------|
| P2.1 | Per-request allocations | Multiple | 1-2 weeks | All |
| P2.2 | Cache key 5 sequential `replace()` calls | `src/proxy_cache/key.rs` | 1h | All |
| P2.3 | O(n²) weighted_shuffle_providers | `src/mesh/proxy.rs` | 15min | All |
| P2.4 | serde_json → postcard in hot paths | Multiple | 2-3h | All |
| P2.5 | HashMap allocation in entropy calc | `src/waf/attack_detection/mod.rs` | 30min | All |
| P2.6 | Linear search in open_redirect | `src/waf/attack_detection/open_redirect.rs` | 1h | All |
| P2.7 | WASM linker recreation per request | `src/plugin/wasm_runtime.rs` | 1h | All |
| P2.8 | sorted_runtimes() re-sorts every request | `src/plugin/wasm_runtime.rs` | 30min | All |
| P2.9 | WASM per-runtime request/env cloning | `src/plugin/wasm_runtime.rs` | 15min | All |
| P2.10 | HTTP server per-request allocations | `src/http/server.rs`, `src/http3/server.rs` | 1h | All |
| 3.1.1-5 | Dead Code Removal | Multiple | 4-6h | All |
| 3.2.1-5 | Fix `#![allow(dead_code)]` | Multiple | 2-3h | All |
| 3.3.1-6 | Feature Flag Cleanup | Multiple | 2-3h | All |
| 3.4.1 | ConnectionTokenGuard Fix | `src/http/server.rs:53,62` | 1-2h | All |
| P10.1 | WAF Unicode bypass | `src/waf/attack_detection/normalizer.rs:44-57` | 1-2 days | All |
| P10.2 | Admin Regex DoS | `src/admin/handlers/config.rs:497-509` | 2-4h | All |
| P10.3 | IPC key env fallback | `src/process/manager.rs:343-376` | 2-4h | All |
| P10.4 | DNS TSIG timing side channel | `src/dns/tsig.rs:237-244` | 30min | All |
| P10.5 | IPC path traversal | `src/process/ipc.rs:979-1010` | 1-2h | All |
| P10.6 | Nonce cache O(n) | `src/process/ipc_signed.rs:24-59` | 3-4h | All |
| P10.7 | Header filtering gap QUIC | `src/mesh/proxy.rs` | 2h | All |
| P10.8 | Circuit breaker hardcoded | `src/mesh/proxy.rs` | 2h | All |
| P10.9 | Await-holding-lock deadlock | `src/mesh/proxy.rs` | 2h | All |
| P10.10 | DNS cache validation unused | `src/dns/cache.rs:587-596` | 8-10h | All |

### Phase 4: Admin API & Documentation (Parallel)

| # | Issue | Files | Priority | Can Parallelize With |
|---|-------|-------|----------|---------------------|
| P4.1 | Swagger UI | `src/admin/mod.rs` | LOW | All |
| P4.2 | API Discovery Endpoint | New `src/admin/handlers/api_discovery.rs` | MEDIUM | All |
| P4.3 | Rule Feed Sensitive Field Masking | `src/admin/handlers/config.rs:2195-2203` | HIGH | All |
| P4.4 | YARA Feed Sensitive Field Masking | `src/admin/handlers/config.rs` | HIGH | All |
| P4.5 | Overseer Config Bug | `src/startup/master.rs:156-160` | HIGH | All |
| P4.6 | DNS Admin UI Enhancement | `admin-ui/src/pages/dns.rs` | MEDIUM | All |
| P4.7 | Honeypot Port Hot-Reload | New `src/honeypot_port/controller.rs` | MEDIUM | All |
| P4.8 | Behavioral Intelligence Admin Endpoint | New `src/admin/handlers/behavioral_intel.rs` | MEDIUM | All |
| P5.1-14 | Documentation Creation | docs/ | MEDIUM | All |
| P6.1-8 | Testing Improvements | Multiple | HIGH/CRITICAL | All |
| P7.1-5 | Dependency Updates | Cargo.toml | MEDIUM | All |

### Phase 5: New Features (Sequential after mesh works)

| # | Issue | Files | Est. Time | Dependencies |
|---|-------|-------|-----------|--------------|
| P8.1-5 | Spin WASM Runtime Support | Multiple | ~1300 lines | P1.1, P1.6 |
| P9.1-4 | Serverless Standalone Enhancements | Multiple | ~1 week | P1.12, P1.13 |

---

## Implementation Waves

The remaining work is organized into waves that can be executed in parallel by different agents.

### Wave P0: Critical Security Fixes

These items must be completed before any other work. They fix active security vulnerabilities.

| # | Issue | Description | Files | Est. Time | Priority |
|---|-------|-------------|-------|-----------|----------|
| P0.1 | WASM `table_growing` unbounded | Returns `Ok(true)` unconditionally, no limit enforcement | `src/plugin/wasm_runtime.rs:319-326` | 1-2h | CRITICAL |
| P0.2 | WASM pool DHT prefix leakage | `allowed_dht_prefixes` not reset in `prepare_for_request()` | `src/plugin/instance_pool.rs:148-159` | 2-3h | CRITICAL |
| P0.3 | Threat intel signer bypass | Empty `trusted_signers` allows any non-global signer. Condition `!is_global() && !is_empty()` skips check when list is empty. Anyone can send threats as non-global when list is empty | `src/mesh/threat_intel.rs:1606-1621` | 30m | CRITICAL |
| P0.4 | Serverless ignore limits | `_limits` created but never passed to `load_plugin()` | `src/serverless/manager.rs:479-491,506-518` | 30-60m | CRITICAL |
| P0.5 | Time-based challenge verification bypass | `_solution` parameter ignored - function just marks challenge as verified without checking solution | `src/mesh/security_challenge.rs:159-190` | 2h | CRITICAL |
| P0.6 | Pass-over fallback signing violation | Global signs as origin when origin unreachable | `src/mesh/passover_key_exchange.rs:469-534` | 1h | CRITICAL |
| P0.7 | RecordStoreManager clone empty | Uses `ShardedRecordStore::new()` instead of clone | `src/mesh/dht/record_store.rs:468-519` | 2h | CRITICAL |
| P0.8 | Severity-aware threat broadcast | CRITICAL/HIGH should broadcast to 100% peers | `src/mesh/threat_intel.rs:1507-1535` | 1h | CRITICAL |
| P0.9 | Threat duplicate detection key mismatch | Incoming mesh threats stored at raw key `"1.2.3.4"` via `indicator.indicator_value.clone()` at line 831. Local threats stored at complex key `"threat_indicator:1.2.3.4:IpBlock"` via `make_indicator_key()`. Duplicate detection fails for cross-origin threats | `src/mesh/threat_intel.rs:831,1066,1165` | 1h | CRITICAL |
| P0.10 | Rate Limit Bypass via WASM Filters | WASM filters execute AFTER rate limit is counted in `handle_request()` at line 1431, but filters also execute after rate limit in unified_server.rs at 2317-2347. Attacker can exhaust rate limit budget with a single request that gets blocked | `src/worker/unified_server.rs:1431,2317-2347` | 2-3h | CRITICAL |
| P0.11 | AxumDynamic WAF Bypass | Returns early at line 1728, skips WASM filters | `src/worker/unified_server.rs:1702-1741` | 1-2h | CRITICAL |
| P0.12 | YARA trusted_signer global bypass | At line 942, condition `!trusted_signers.is_empty()` means global nodes only bypass when list is empty. Should use `!self.node_role.is_global() && !trusted_signers.is_empty()` like threat intel does, so global nodes always bypass regardless of list state | `src/mesh/yara_rules.rs:942-954,1761-1812` | 2h | CRITICAL |

### Wave P1: High Priority Functional Fixes

These items fix significant functionality gaps or performance issues that impact 500K rps scalability.

| # | Issue | Description | Files | Est. Time | Priority |
|---|-------|-------------|-------|-----------|----------|
| P1.1 | BackendType::Mesh Not Integrated | `BackendType::Mesh` defined in router.rs:65 and assigned in 9+ places (line 504, 748, etc) but never dispatched in http/server.rs handler. `mesh_backend_pool` exists (server/mod.rs:66) but not wired to request handling. Also: `is_serverless_origin()` is defined but never called | `src/router.rs:65,504,748`, `src/http/server.rs`, `src/mesh/proxy.rs` | 3-4h | HIGH |
| P1.2 | HTTP Client Cache Undersized | 100 entries too small at 500K rps | `src/http/client.rs` | 1h | HIGH |
| P1.3 | No Upstream Load Balancing | `UpstreamPool` exists but unwired | `src/http/server.rs`, `src/mesh/proxy.rs` | 2-3h | HIGH |
| P1.4 | Message Cache Severely Undersized | 10K at 500K rps = ~1sec dedup window | `src/mesh/transport.rs:239-244` | 2h | HIGH |
| P1.5 | Unbounded Proxy Task Spawn | 500K rps × 10 providers = 5M concurrent tasks | `src/mesh/proxy.rs:962-997` | 2h | HIGH |
| P1.6 | WASM instance pooling bypass | `transform_response`/`invoke_handler` bypass pool | `src/plugin/wasm_runtime.rs` | 2-3h | HIGH |
| P1.7 | Enforce `edge_only` flag | Add role check before applying image poisoning | `src/mesh/proxy.rs:1485` | 1h | HIGH |
| P1.8 | Wire `proxy_cache` in MeshProxy | `proxy_cache: Arc<RwLock<Option<ProxyCache>>>` exists at proxy.rs:72, initialized at 333, setter at 356, but never used in `route_request()`. Need: `CacheKeyBuilder` field, cache key construction, `should_cache_response()` helper, `build_cached_response()` helper, and `transform_response()` should use `get_proxy_cache_preferences_for_site()` instead of direct DHT lookup | `src/mesh/proxy.rs:72,333,356,1281-1289` | 2h | HIGH |
| P1.9 | WAF double normalization | Normalizes twice for sqli/xss/ssti | `src/waf/attack_detection/{sqli,xss,ssti}.rs` | 2h | HIGH |
| P1.10 | Mesh provider_stats lock contention | RwLock→DashMap eliminates 5M+ locks/sec | `src/mesh/proxy.rs` | 1h | HIGH |
| P1.11 | Sync-on-join YARA/threat intel | New peers don't receive current YARA/threat intel state on connection. Need to call sync method in `dht_on_peer_connected()` at line 212-253 when peer connects | `src/mesh/transport_connection.rs:212-253` | 2h | HIGH |
| P1.12 | ServerlessInvokeResponse handling | Need to verify handler returns result, call site sends response - check transport_peer.rs for the ServerlessInvokeResponse handling pattern | `src/mesh/transport_peer.rs` | 2h | HIGH |
| P1.13 | Add ServerlessInvokeRequest sender | Construct and send signed requests | New `src/mesh/transport_serverless.rs` | 3h | HIGH |
| P1.14 | Initialize WasmDistManager | Call `set_global_wasm_dist_manager()` during mesh init | `src/mesh/transport.rs` | 1h | HIGH |

### Wave P2: Performance Optimizations

Performance improvements targeting 500K rps scalability goal.

| # | Issue | Description | Files | Est. Time | Priority |
|---|-------|-------------|-------|-----------|----------|
| P2.1 | Per-request allocations | `format!()`, `HashMap::new()`, `to_lowercase()` in hot paths | Multiple | 1-2 weeks | MEDIUM |
| P2.2 | Cache key 5 sequential `replace()` calls | String processing overhead | `src/proxy_cache/key.rs` | 1h | MEDIUM |
| P2.3 | O(n²) weighted_shuffle_providers | Uses `swap_remove` causing O(n²) | `src/mesh/proxy.rs` | 15min | MEDIUM |
| P2.4 | serde_json → postcard in hot paths | Binary serialization for DHT/mesh | Multiple | 2-3h | MEDIUM |
| P2.5 | HashMap allocation in entropy calc | `calculate_string_entropy` allocates HashMap | `src/waf/attack_detection/mod.rs` | 30min | MEDIUM |
| P2.6 | Linear search in open_redirect | `redirect_param_patterns` uses linear search | `src/waf/attack_detection/open_redirect.rs` | 1h | MEDIUM |
| P2.7 | WASM linker recreation per request | Creates new linker each request | `src/plugin/wasm_runtime.rs` | 1h | MEDIUM |
| P2.8 | sorted_runtimes() re-sorts every request | Unnecessary sorting on each call | `src/plugin/wasm_runtime.rs` | 30min | MEDIUM |
| P2.9 | WASM per-runtime request/env cloning | Clones env on every request | `src/plugin/wasm_runtime.rs` | 15min | MEDIUM |
| P2.10 | HTTP server per-request allocations | Server and HTTP3 request handling | `src/http/server.rs`, `src/http3/server.rs` | 1h | MEDIUM |

---

## Key Codebase Facts

| # | Issue | Reason | Status |
|---|-------|--------|--------|
| D1 | dashmap 5.5.3 → 7.0.0-rc2 | Await stable release | DEFERRED |
| D2 | notify 6.0.0 → 9.0.0-rc.3 | Consider v8.x first | DEFERRED |
| D3 | O(k×n) DHT lookup complexity | Deferred until 10x/100x scale | DEFERRED |
| D4 | Hardcoded quorum timeout (10s) | Reasonable default | DEFERRED |
| D5 | Veto abuse score unused | Not currently observed | DEFERRED |
| D6 | ArcStr duplication cleanup | `utils.rs` vs `protocol.rs` | DEFERRED |
| D7 | God module splits | metrics/mod.rs (2086), mesh/transport.rs (3291), http/server.rs (4211) | DEFERRED |
| D8 | WASM component support | ABI incompatible with current runtime | DEFERRED |
| D9 | Site scope in DHT key | Multi-tenant future release | DEFERRED |

---

## Security Notes

1. **WireGuard transport**: Deprecated, falls back to QUIC transport. Code remains for future potential rewrite but is non-functional in current release.
2. **Reserved protocol modules**: Multiple modules with `SAFETY_REASON` comments marking them as reserved for future protocol handling expansion.

---

## Key Codebase Facts

- **Architecture**: Overseer → Master → Workers (Unix domain socket IPC)
- **Mesh types**: `MeshBackend`, `MeshBackendPool` in `src/mesh/backend.rs`
- **Base64**: `get_public_key()` uses `URL_SAFE_NO_PAD`; any decoder using `STANDARD` is wrong
- **Serialization**: Use `crate::serialization::serialize/deserialize` (Postcard) for binary
- **Timestamps**: Use `u64` via `crate::mesh::safe_unix_timestamp()` or `crate::utils::current_timestamp()`

---

## Verification Commands

```bash
# Verify tests compile (not just cargo check)
cargo test --lib --no-run

# Run targeted tests
cargo test --lib <test_name>
cargo test --test integration_test

# Format and lint
cargo fmt
cargo clippy -- -D warnings
```