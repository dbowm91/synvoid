# MaluWAF Implementation Plan

**Status**: Active
**Last Updated**: 2026-04-25
**Based on**: Consolidated review of plans 2-19

## Overview

This plan consolidates all actionable items from 18 plan files into a unified implementation roadmap organized into **7 waves** based on dependencies and parallelization opportunities.

**Target**: Support 500K+ requests/second with proper WAF enforcement

---

## Critical Items (Implement First - Before Any Wave)

### C1: MeshBackendPool Not Wired to HTTP [CRITICAL]
- **Problem**: `MeshBackendPool` exists but never used in HTTP/TLS request handling
- **Files**: `src/unified_server.rs`, `src/server/mod.rs`, `src/router.rs`, `src/http/server.rs`, `src/tls/server.rs`
- **Action**: Add `BackendType::Mesh` variant OR `mesh_routing_enabled` field to SiteConfig; wire mesh_backend_pool through UnifiedServerWorkerState
- **Verification**: Integration test that configures site for mesh routing and verifies request flows through `MeshProxy::route_request()`

### C2: Role Validation Logic Bug [CRITICAL - plan3:1.1]
- **Problem**: Composite roles GLOBAL_EDGE and EDGE_ORIGIN bypass security checks
- **Files**: `src/mesh/peer_auth.rs:136-178`
- **Action**: Reorder validation checks to handle composite roles FIRST; add explicit tests for EDGE_ORIGIN validation
- **Estimated**: 4-6 hours

### C3: DNS Mesh Mode Only Enforcement [CRITICAL - plan3:1.2]
- **Problem**: Edge nodes bind DNS sockets and respond to queries when restricted to global nodes only. Config `dns_mesh_mode_only` exists in `src/mesh/config.rs:1009-1010` but enforcement may be incomplete.
- **Files**: `src/mesh/protocol.rs:1115-1128`, `src/dns/server/startup.rs`, `src/dns/server/query.rs`
- **Action**: Verify enforcement in `MeshTransport::can_serve_dns()` at line 1128; add enforcement check before DNS socket binding in `start_standard_mode()`; add check in `resolve_from_mesh()` if missing
- **Verification**: Edge node with `dns_mesh_mode_only=true` should NOT bind DNS sockets

### C4: Base64 Encoding Inconsistency [CRITICAL - plan17:1]
- **Problem**: Threat intel uses `STANDARD` decoder but `get_public_key()` returns `URL_SAFE_NO_PAD`, breaking DHT sync
- **Files**: `src/mesh/threat_intel.rs:1231,1268`, `src/mesh/yara_rules.rs:530-533,622-625,1785,1914`
- **Action**: Change `STANDARD` decoder to `URL_SAFE_NO_PAD`; fix `check_trusted_signer()` parameter; align YARA DHT storage
- **Estimated**: 1-2 hours

### C5: Content-Length DoS Prevention [HIGH - plan14:1]
- **Problem**: `accumulated.reserve(cl)` without validation allows memory exhaustion
- **Files**: `src/http/shared_handler.rs:342-344`, `src/http/server.rs:976-990`
- **Action**: Add validation BEFORE reserve call; check if `cl > max_body_size` before `accumulated.reserve(cl)`; return 414 if exceeded
- **Verification**: 10MB body succeeds, 11MB body rejected

### C6: Rule Feed Placeholder Fail-Closed [HIGH - plan14:2]
- **Problem**: Placeholder key causes random key generation, silently failing signature verification
- **Files**: `src/waf/rule_feed.rs:320-353,374-405`
- **Action**: `panic!()` with clear error message when placeholder key detected; explain how to configure valid key
- **Verification**: Process exits with non-zero status on placeholder key

### C7: ThreatAnnounce Trusted Signer Verification Gap [P0 - plan17:3]
- **Problem**: `ThreatAnnounce` handling only verifies Ed25519 signature but does NOT check `trusted_signers` list
- **Files**: `src/mesh/threat_intel.rs:1576-1590`
- **Action**: After signature verification, check if `!is_global_node()` and `trusted_signers` is not empty; verify signer is in list

### C8: PoW Verification Bypasses Signature Check [HIGH - plan3:2.2]
- **Problem**: When PoW verified for GLOBAL_EDGE node, function returns early without signature verification
- **Files**: `src/mesh/peer_auth.rs:226-232`
- **Action**: Don't bypass signature verification after PoW verification; require signature regardless of PoW for composite roles with GLOBAL

### C9: DHT Quorum Missing Authorization [HIGH - plan3:2.4]
- **Problem**: `handle_quorum_store_request()` only verifies signature cryptographic validity, NOT that signer is in authorized global node list
- **Files**: `src/mesh/dht/record_store_message.rs:686-701`, `src/mesh/dht/quorum.rs`
- **Action**: Add authorization check after signature_valid check; verify `record.signer_public_key` is in authorized keys

---

## Wave 1: Critical Security & Stability

| Item | Description | Files | Effort |
|------|-------------|-------|--------|
| 1.1 | Wire MeshBackendPool into HTTP | `unified_server.rs`, `server/mod.rs`, `router.rs`, `http/server.rs`, `tls/server.rs` | High |
| 1.2 | Add Bounded Retry Timeout to route_request() | `mesh/proxy.rs` | Medium |
| 1.3 | Fix SSRF Domain Name Validation | `mesh/transport_peer.rs` | Medium |
| 1.4 | Fix Role Validation Composite Roles | `mesh/peer_auth.rs` | Medium |
| 1.5 | DNS Mesh Mode Enforcement | `dns/server/startup.rs`, `dns/server/query.rs` | Medium |
| 1.6 | Content-Length DoS Fix | `http/shared_handler.rs` | Low |
| 1.7 | Rule Feed Fail-Closed | `waf/rule_feed.rs` | Low |
| 1.8 | WebSocket Token in URL Fix | `admin/ws/mod.rs`, `admin-ui/...`, `admin/middleware.rs` | Medium |
| 1.9 | CSRF Validation Logic Fix | `admin/middleware.rs` | Medium |
| 1.10 | Base64 Encoding Fix | `threat_intel.rs`, `yara_rules.rs` | Low |
| 1.11 | Trusted Signer Verification | `threat_intel.rs` | Low |
| 1.12 | Capability Attestation Blocked by is_privileged() | `mesh/dht/record_store_crud.rs` | Medium |
| 1.13 | Attestation Revocation Not Checked | `mesh/peer_auth.rs` | Medium |
| 1.14 | Stale Cache Refresh Mechanism | `mesh/proxy.rs` | Medium |

**Wave 1 Parallelization**: Items 1.2-1.14 are independent and can run in parallel after 1.1 (MeshBackendPool wiring is prerequisite for some mesh proxy work).

---

## Wave 2: Performance Hot Path

| Item | Description | Files | Effort |
|------|-------------|-------|--------|
| 2.1 | PooledBuf.expect() Panic Safety | `buffer/pool.rs:377,381,434` | Low (30 min) |
| 2.2 | Remove Nested spawn_blocking Anti-Pattern | `worker/mod.rs:197-232,243-279` | Medium |
| 2.3 | IPC Pool DashMap Migration | `process/ipc_pool.rs` | Medium |
| 2.4 | ProcessManager Atomic Scalars | `process/manager.rs` | Low |
| 2.5 | Double-Lowercasing Elimination | `waf/attack_detection/detector_common.rs` | Low |
| 2.6 | DhtRateLimiter O(n) Cleanup | `mesh/dht/mod.rs` | Medium |
| 2.7 | Add Body Size Limit to Mesh Proxy | `mesh/proxy.rs` | Low |
| 2.8 | Replace RwLock<HashMap> with DashMap for active_connections | `mesh/proxy.rs` | Medium |
| 2.9 | Add Moka Bounds to WHITELIST_REGEX_CACHE | `mesh/proxy.rs`, `http/server.rs`, `mesh/config.rs` | Medium |
| 2.10 | Optimize weighted_shuffle_providers to O(n) | `mesh/proxy.rs` | Medium |
| 2.11 | Moka Cache entry_count() Bug with Weigher+TTL | `dns/cache.rs`, `proxy_cache/store.rs`, `mesh/proxy.rs` | Low |
| 2.12 | Route Cache Memory - No Size-Based Eviction | `mesh/topology.rs` | Medium |

**Wave 2 Parallelization**: All items independent; can run fully in parallel.

---

## Wave 3: Mesh & Serverless Core

| Item | Description | Files | Effort |
|------|-------------|-------|--------|
| 3.1 | WasmDistManager Enable | `mesh/wasm_dist.rs` | High |
| 3.2 | ServerlessInvokeRequest Handler | `mesh/transport_peer.rs` | Medium |
| 3.3 | find_origin_by_mesh_id() Implementation | `mesh/topology.rs:688` | Medium |
| 3.4 | mesh_id Field in RegisteredOriginNode | `dns/mesh_sync/mod.rs`, `dns/mesh_sync/registration.rs` | Medium |
| 3.5 | mesh_emit_event Bridge to publish_event() | `plugin/wasm_runtime.rs:753-760` | Medium |
| 3.6 | YARA Fanout Broadcast | `mesh/yara_rules.rs`, `mesh/config.rs` | Medium |
| 3.7 | edge_only Flag Handling | `mesh/proxy.rs:1565-1640` | Low |
| 3.8 | fetch_cached_config Fallback | `mesh/transports/manager.rs:857-987` | Medium |
| 3.9 | Add Version/Checksum to FunctionDefinition | `config/serverless.rs` | Medium |
| 3.10 | reload_function to ServerlessManager | `serverless/manager.rs` | Medium |
| 3.11 | DHT Record Watcher/Notification System | `mesh/dht/record_store.rs` | High |
| 3.12 | Background Event Consumer Loop | `serverless/manager.rs` | Medium |
| 3.13 | Timer/Scheduled Event Support | `serverless/scheduler.rs` (new) | High |
| 3.14 | Storage Host Functions to WASM Runtime | `plugin/wasm_runtime.rs` | High |
| 3.15 | announce_serverless() Version/Checksum Fix | `mesh/transport.rs:700-743` | Low |
| 3.16 | Wire Up get_proxy_cache_preferences_for_site() | `mesh/proxy.rs:1262-1273` | Low |
| 3.17 | Add Warning for Silent Publish Skip | `admin/handlers/sites.rs:202,352` | Low |
| 3.18 | SiteConfigSync Wrong JSON Path | `admin/state.rs:514` | Low |

**Wave 3 Dependencies**:
- 3.1 depends on 3.3, 3.4
- 3.5 depends on 3.11
- 3.9-3.10 depend on 3.4
- 3.12 depends on 3.11
- 3.14 depends on 3.13

---

## Wave 4: Web Stack & Plugins

| Item | Description | Files | Effort |
|------|-------------|-------|--------|
| 4.1 | Eliminate env.clone() Per Plugin | `plugin/wasm_runtime.rs`, `plugin/mod.rs` | Low |
| 4.2 | Serverless Pre-Warming Fix | `serverless/manager.rs:364-368` | Low (add `.initialize()` call) |
| 4.3 | Pooled Instance Memory Limiter | `plugin/wasm_runtime.rs:1006-1015` | Low |
| 4.4 | Request Body Loss in AxumDynamic [CRITICAL] | `http/server.rs:1725` | High |
| 4.5 | Directory Viewer Theme Enhancement | `http/directory_viewer.rs` | Low |
| 4.6 | WASI Support Wiring | `plugin/wasm_runtime.rs`, `serverless/instance_pool.rs`, `serverless/manager.rs` | Medium |
| 4.7 | WasmApp Backend Type | `router.rs`, `config/site/backend.rs` | Medium |
| 4.8 | State Leakage in Pooled Instances | `plugin/instance_pool.rs`, `plugin/wasm_runtime.rs` | High |
| 4.9 | Header Serialization Optimization | `plugin/wasm_runtime.rs` | Medium |
| 4.10 | Enable Pooling for transform_response/invoke_handler | `plugin/wasm_runtime.rs` | Medium |
| 4.11 | Library Lifecycle Not Managed | `plugin/mod.rs` | Medium |
| 4.12 | No destroy_router Called | `plugin/mod.rs` | Low |
| 4.13 | No Load Balancing for Mesh Serverless | `http/server.rs`, `mesh/transport.rs` | Medium |
| 4.14 | No Cryptographic Caller Verification | `mesh/protocol.rs`, `serverless/manager.rs` | High |
| 4.15 | TOCTOU in DHT Query Host Function | `plugin/wasm_runtime.rs:618-672` | Medium |
| 4.16 | QUIC Connection Pooling for Mesh Proxy | `mesh/transport.rs` | High |
| 4.17 | Scale-Down Bug - Wrong Instance Indices | `serverless/instance_pool.rs:328-337` | Low |
| 4.18 | InstancePoolMode Dead Code | `serverless/instance_pool.rs` | Low |
| 4.19 | Per-Plugin on_error Config Unused | `config/plugins.rs`, `plugin/wasm_runtime.rs` | Low |
| 4.20 | Fix SiteConfigSync Wrong JSON Path | `admin/state.rs:514` | Low |

**Wave 4 Parallelization**: 4.1-4.3, 4.5, 4.7 independent; 4.4 depends on Wave 1; 4.6 depends on 4.7; 4.8 is separate security concern.

---

## Wave 5: Admin & API

| Item | Description | Files | Effort |
|------|-------------|-------|--------|
| 5.1 | utoipa 4->5 Upgrade | `Cargo.toml` | Low |
| 5.2 | Swagger/ReDoc Integration | `admin/mod.rs` | Medium |
| 5.3 | Path Duplication Fix (166 paths, 20 files) | 20 handler files | High |
| 5.4 | RuleFeed/YaraFeed Config Handlers | `admin/handlers/config.rs`, `admin/handlers/rule_feed.rs` | Medium |
| 5.5 | Persistence Config Bug Fix | `worker_pool/shared_state.rs:53` | Low |
| 5.6 | ICMP Filter UI Enhancement | `admin-ui/src/pages/icmp.rs`, `icmp_filter/config.rs` | Medium |
| 5.7 | Remove duplicate components() | `admin/openapi.rs:44-46` | Low |
| 5.8 | Security Annotations for Public Endpoints | `admin/openapi.rs` | Medium |
| 5.9 | Worker Health Matrix View | `admin-ui/src/pages/workers.rs` | Medium |
| 5.10 | Batch Restart Operations | `admin/handlers/system.rs`, `process/manager.rs` | Medium |
| 5.11 | Per-Worker Metrics Additions | `process/ipc.rs:1271-1292` | Medium |
| 5.12 | Overseer Status Real IPC | `overseer/process.rs`, `admin/handlers/system.rs` | High |
| 5.13 | Config Rollback/History Endpoints | `admin/handlers/config.rs` | High |
| 5.14 | Config Validation/Preview/Diff UI | `admin-ui/src/pages/settings.rs` | Medium |
| 5.15 | Serverless/Honeypot/Static Config Handlers | Various | Medium |
| 5.16 | 20 Missing DefaultsConfig Sub-configs | `admin/handlers/config.rs` | Medium |
| 5.17 | MetricsConfig/TokioConfig Handlers | `admin/handlers/config.rs` | Low |

**Wave 5 Parallelization**: Items 5.1-5.8 independent; 5.9-5.17 can parallelize after 5.1-5.3.

---

## Wave 6: Integration & Testing

| Item | Description | Files | Effort |
|------|-------------|-------|--------|
| 6.1 | DashMap Deadlock Fix in SlidingWindowLimiter | `waf/ratelimit/sliding.rs` | Low |
| 6.2 | copy_bidirectional Deadlock Fix | `streaming/bidirectional.rs` | Low |
| 6.3 | Token Bucket Timing Fix | `waf/traffic_shaper/bucket.rs` | Low |
| 6.4 | FD Passing Tests as Integration Tests | `process/socket_fd.rs` | Low |
| 6.5 | Glob Pattern Test Hang Investigation | `location_matcher/` | Low |
| 6.6 | ProcessManager Unit Tests | `process/manager.rs` | Medium |
| 6.7 | WorkerPool Unit Tests | `worker_pool/mod.rs` | Medium |
| 6.8 | Health Monitoring Loop Tests | `tests/health_checker_test.rs` | Medium |
| 6.9 | Master IPC Accept Loop Tests | `tests/e2e_process_test.rs` | Medium |
| 6.10 | Full Upgrade IPC Flow Tests | `tests/upgrade_flow_test.rs` | Medium |
| 6.11 | Honeypot Integration Test Coverage | `tests/honeypot_integration_test.rs` (new) | Medium |
| 6.12 | 80+ Documentation Discrepancies | 12 doc files | High |

**Wave 6 Parallelization**: 6.1-6.5 independent; 6.6-6.11 depend on code being stable from Waves 1-5; 6.12 runs in parallel with everything.

---

## Wave 7: Cross-Platform & Advanced

| Item | Description | Files | Effort |
|------|-------------|-------|--------|
| 7.1 | pqc_kyber -> pqc_kyber_edit | `wasm_pow/Cargo.toml`, `wasm_pow/src/pqc.rs` | Low |
| 7.2 | hickory-recursor 0.26 Migration | `Cargo.toml`, `dns/resolver.rs`, `dns/recursive.rs` | High (3-5 days) |
| 7.3 | Honeypot Graceful Shutdown | `honeypot_port/runner.rs`, `worker/unified_server.rs` | Medium |
| 7.4 | Fire-and-Forget Storage Tasks Fix | `honeypot_port/runner.rs` | Low |
| 7.5 | DomainBlock/UrlBlock/CertBlock Implementation | `dns/firewall.rs`, `mesh/threat_intel.rs` | High |
| 7.6 | BSD Service Management (rc.d) | `platform/service/stub_service.rs` | Medium |
| 7.7 | Zero-Copy I/O for macOS/FreeBSD | `zero_copy.rs` | Medium |
| 7.8 | macOS TUN Interface (utun) | `tunnel/wireguard/tun.rs` | High |
| 7.9 | Windows Improvements | `platform/windows_impl.rs` | Medium |
| 7.10 | BSD Sandbox (Capsicum) | `platform/sandbox.rs`, new files | High |
| 7.11 | Org Key Trust Chain | `mesh/organization.rs`, `mesh/org_key_manager.rs`, etc. | Very High (4-5 weeks) |
| 7.12 | Unified Honeypot Manager | `honeypot/unified.rs` (new) | High |
| 7.13 | Site Scope Enforcement + Domain Allocation | Multiple files | High |
| 7.14 | Standalone Mode Catch-Up Mechanism | `mesh/threat_intel.rs` | Medium |

**Wave 7 Parallelization**: 7.1-7.5 independent; 7.6-7.10 platform-specific (can parallelize across platforms); 7.11-7.14 large efforts.

---

## Configuration Options to Add

### mesh.config
```toml
[mesh.proxy]
request_timeout_secs = 30
policy_cache_ttl_secs = 3600
stale_cache_ttl_secs = 60
whitelist_regex_cache_size = 1000
whitelist_regex_cache_ttl_secs = 3600

[mesh.yara_rules]
fanout_factor = 0.5
re_announce_interval_secs = 3600
```

### limits.config
```toml
[limits.upstream]
min_pool_size = 10
max_pool_size = 1000
dynamic_pool_sizing = false
```

### serverless.config
```toml
[serverless]
enabled = true
default_memory_mb = 64
default_cpu_fuel = 1000000
default_timeout_seconds = 30
default_min_instances = 1
default_max_instances = 10
default_idle_timeout_seconds = 300
event_consumer_interval_secs = 1
pool_stats_broadcast_interval_secs = 10
storage_namespace_isolation = true
```

---

## Dependencies Summary

| Item | Dependencies |
|------|--------------|
| Wave 1 (all) | Critical fixes - no code deps, implement first |
| Wave 2 (all) | Independent - can parallelize |
| 3.1 (WasmDistManager) | 3.3, 3.4 |
| 3.5 (mesh_emit_event bridge) | 3.11 (DHT watcher) |
| 3.9-3.10 | 3.4 |
| 3.12 | 3.11 |
| 3.14 | 3.13 |
| 4.4 (Request Body Loss) | Wave 1 completion |
| 4.6 (WASI support) | 4.7 |
| 4.13-4.16 (Mesh Serverless) | Wave 3 core |
| 5.9-5.17 | 5.1-5.3 |
| 6.6-6.11 | Waves 1-5 stable code |
| 7.11 (Org Key) | Most other work complete |

---

## Implementation Priority Summary

| Priority | Item | Wave | Effort |
|----------|------|------|--------|
| P0 | MeshBackendPool wiring | 1 | High |
| P0 | Role validation fix | 1 | Medium |
| P0 | DNS mesh mode enforcement | 1 | Medium |
| P0 | Base64 encoding fix | 1 | Low |
| P0 | Content-Length DoS fix | 1 | Low |
| P0 | Rule feed fail-closed | 1 | Low |
| P0 | ThreatAnnounce trusted signer | 1 | Low |
| P0 | PoW bypasses signature | 1 | Low |
| P0 | DHT quorum auth check | 1 | Medium |
| P1 | Double-lowercasing elimination | 2 | Low |
| P1 | WasmDistManager enable | 3 | High |
| P1 | ServerlessInvokeRequest handler | 3 | Medium |
| P1 | YARA fanout broadcast | 3 | Medium |
| P1 | State leakage in pooled instances | 4 | High |
| P1 | Request body loss fix | 4 | High |
| P2 | Admin panel improvements | 5 | Medium |
| P2 | OpenAPI/Swagger integration | 5 | Medium |
| P2 | Test coverage gaps | 6 | Medium |
| P3 | Cross-platform support | 7 | High |
| P3 | Org key trust chain | 7 | Very High |

---

## Files Summary by Wave

| Wave | Files (approx) | Lines (est) |
|------|---------------|-------------|
| Critical | ~15 | ~400 |
| 1 | ~20 | ~800 |
| 2 | ~12 | ~600 |
| 3 | ~18 | ~1500 |
| 4 | ~15 | ~1000 |
| 5 | ~30 | ~800 |
| 6 | ~25 | ~600 |
| 7 | ~25 | ~2500 |

**Total estimated**: ~90 unique files, ~7200 lines across all waves

---

## Appendix: Original Plan File References

| Plan | Focus | Key Items |
|------|-------|-----------|
| plan2.md | Reverse Proxy & WAF | 10 items (mesh proxy, upstream pool) |
| plan3.md | Mesh & DHT Architecture | 12 items (security, quorum, validation) |
| plan4.md | Plugin Architecture | 17 items (WASM, pooling, lifecycle) |
| plan5.md | Web App Stack | 6 phases (WASI, WasmApp backend) |
| plan6.md | Serverless Architecture | 25 items (events, versioning, storage) |
| plan7.md | Edge Node Caching | 10 items (edge_only, fallback, socket) |
| plan8.md | YARA Rules Distribution | 10 items (fanout, re-announce) |
| plan9.md | OpenAPI Implementation | 7 phases (Swagger, path fix) |
| plan10.md | Admin Panel | 12 items (config handlers, UI) |
| plan11.md | Dependency Security | 8 items (deny.toml, hickory migration) |
| plan12.md | Documentation | 80+ discrepancies (12 files) |
| plan13.md | Code Quality | 8 items (performance hot path) |
| plan14.md | Security Audit | 10 items (DoS, CSRF, path traversal) |
| plan15.md | Performance | 4 items (double-lowercasing) |
| plan16.md | Test Coverage | 9 ignored tests + gaps |
| plan17.md | Honeypot/Threat Intel | 9 items (base64, DomainBlock) |
| plan18.md | Cross-Platform | 6 issues (BSD, macOS, Windows) |
| plan19.md | Org Key Trust Chain | 9 phases (hierarchical trust) |
