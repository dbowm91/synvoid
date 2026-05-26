# SynVoid Architecture Review - Consolidated Implementation Plan

**Generated:** 2026-05-26
**Source:** 4 batches covering 16 modules (app_handlers, dns, worker, process_lifecycle, networking, routing, plugin, waf, layer_3_5, mesh, admin, proxy, platform, config, cleanup)

---

## Executive Summary

This plan consolidates findings from architecture reviews across all SynVoid modules. It identifies critical bugs, documentation fixes, and implementation improvements organized into logical waves for parallel execution.

### Critical Bugs (Fix First - Wave 1)

| ID | Module | Issue | Location | Severity |
|----|--------|-------|----------|----------|
| BUG-PL-1 | Process Lifecycle | Missing `--master` CLI flag - Overseer cannot spawn Master | `src/main.rs:21-192` | **CRITICAL** |
| BUG-ROUTER-1 | Routing | Hardcoded port 80 instead of configured port | `src/router.rs:1318` | **CRITICAL** |
| BUG-PLUGIN-1 | Plugin/WASM | DHT prefix examples completely wrong (security risk) | `architecture/plugin_deep_dive.md:87-88` | **CRITICAL** |
| BUG-L1 | Layer 3.5 | `verify_hybrid()` returns false when ML-DSA absent | `src/mesh/ml_dsa.rs:206-218` | **CRITICAL** |

---

## Wave 1: Critical Bugs

### 1.1 BUG-PL-1: Missing --master CLI Flag
**STATUS: ALREADY FIXED** (verified 2026-05-26)

The `--master` flag is properly implemented at `src/main.rs:526-528`:
- `Args` struct has `#[arg(long)] master: bool` field
- `run_master_mode()` is correctly wired at line 528

---

### 1.2 BUG-ROUTER-1: Hardcoded Port 80

**Issue:** `update_sites` uses hardcoded `80` instead of configured port.

**Location:** `src/router.rs:1318`

**Fix Required:**
- Replace hardcoded `80` with `main_config.server.port`

**Verification:**
```bash
grep -n "to_socket_addr(80)" src/router.rs
```

---

### 1.2 BUG-ROUTER-1: Hardcoded Port 80

**Issue:** `update_sites` uses hardcoded `80` instead of configured port.

**Location:** `src/router.rs:1318`

**Fix Required:**
- Replace hardcoded `80` with `main_config.server.port`

**Verification:**
```bash
grep -n "update_sites" src/router.rs
```

---

### 1.3 BUG-PLUGIN-1: DHT Prefix Examples Wrong

**Issue:** Document shows `route:`, `cert:`, `config:`, `serverless:` but actual code uses `threat_indicator:`, `yara_rule:`, `yara_rules_manifest:`, `edge_attestation:`, `dns_zone:`, `dns_record:`, `dns_domain_reg:`.

**Location:** `architecture/plugin_deep_dive.md:87-88`

**Fix Required:**
- Update DHT prefix examples to match actual implementation in `src/plugin/instance_pool.rs` and `src/serverless/instance_pool.rs`

---

### 1.4 BUG-L1: verify_hybrid() Fail-Safe Design
**STATUS: ALREADY FIXED** (verified 2026-05-26)

At `src/mesh/ml_dsa.rs:206-218`, the function correctly returns `true` when `signature.has_ml_dsa()` is false (line 217), providing fail-safe behavior.

AGENTS.md already correctly notes this as "FIXED".

---

## Wave 2: Configuration Consistency

### 2.1 WAF: ConnectionLimiter Default Inconsistency
**STATUS: Clarification Needed**

At `src/waf/traffic_shaper/limiter.rs:65`: `effective_max_per_site.unwrap_or(10000)` - this is a local method default, not the struct default.

Actual `ConnectionLimitsConfig` defaults (from `crates/synvoid-config/src/traffic.rs:167-176`):
- `max_connections`: 1000
- `max_connections_per_ip`: 10
- `connection_queue_size`: 100
- `connection_burst`: 5

**Clarification:** The 10000 may be an intentional override for site-level limits. Verify if this is correct or needs adjustment.

---

### 2.2 WAF: SiteConnectionLimiter Unused Parameters

**Issue:** `_max_connections`, `_max_connections_per_ip`, `_queue_size`, `_burst` are unused.

**Location:** `src/waf/traffic_shaper/limiter.rs:312-323`

**Fix Required:**
- Either implement these parameters or remove them

---

### 2.3 DNS: Cookie Server Not Integrated
**STATUS: Already documented in Known Incomplete Items (see below)**

The DNS Cookie Server implementation exists but is not integrated. See "Known Incomplete Items" section below.

---

### 2.4 DNS: DnsConfig.validate() Incomplete

**Issue:** Missing calls to `zones.validate()`, `settings.validate()`, `dnssec.validate()`, `recursive.validate()`.

**Location:** `crates/synvoid-config/src/dns/mod.rs:174-205`

**Fix Required:**
- Add missing sub-config validation calls

---

## Wave 3: Line Reference Corrections & Documentation Fixes

### 3.1 Process Lifecycle: Documentation Fixes

| # | Issue | Location | Fix |
|---|-------|----------|-----|
| 1 | CPU affinity is automatic, not explicit | `architecture/process_lifecycle.md:47` | Update to state it's automatic based on worker ID |
| 2 | Wrong reuse_port line reference | `architecture/process_lifecycle.md:46` | Reference correct location |
| 3 | Worker types undocumented | `architecture/process_lifecycle.md` | Document UnifiedServerWorker, StaticWorker, legacy Worker |

**Location:** `src/process/manager.rs:666-668` (CPU affinity auto behavior)

---

### 3.2 App Handlers: Documentation Fixes

| # | Issue | Location | Fix |
|---|-------|----------|-----|
| 1 | WasmHandler doesn't exist | `architecture/app_handlers.md:58` | Replace with `SpinHttpHandler` |
| 2 | FastCGI "streaming" claim is false | `architecture/app_handlers.md` | Remove streaming claim; document buffering |
| 3 | Static File Handler misleading | `architecture/app_handlers.md` | Clarify delegation to StaticWorker via IPC |
| 4 | Generic WASM "Instance Pooling" vague | `architecture/app_handlers.md` | Specify which backends support pooling |
| 5 | Generic WASM "Mesh Distribution" unverified | `architecture/app_handlers.md` | Clarify scope (Serverless, not generic WASM) |

---

### 3.3 DNS: Documentation Fixes

| # | Issue | Location | Fix |
|---|-------|----------|-----|
| 1 | AXFR "Missing record types" section wrong | `architecture/dns_deep_dive.md:77-85` | Remove incorrect section (ALL types implemented at `src/dns/transfer.rs:829-1028`) |
| 2 | Query Flow Reference Error | `architecture/dns_deep_dive.md` | Replace `from_config` with `new()` constructor |
| 3 | Missing store.rs in Key Files table | `architecture/dns_deep_dive.md` | Add `store.rs` to table |

---

### 3.4 Worker: Documentation Fixes

| # | Issue | Location | Fix |
|---|-------|----------|-----|
| 1 | WAF Pipeline "Challenge" stage not separate | `architecture/worker_architecture.md:27-34` | Update to reflect inline challenge logic |
| 2 | Health monitoring overstated | `architecture/worker_architecture.md` | Correct to passive-first approach |
| 3 | HTTP/2 disabled but documented as supported | `src/http_client/mod.rs:890` | Update to reflect disabled state |

---

### 3.5 Layer 3.5: Documentation Fixes

| # | Issue | Location | Fix |
|---|-------|----------|-----|
| 1 | Stale reference to X25519Kyber768Draft00 | `architecture/layer_3_5_deep_dive.md:10` | Update to only mention X25519MLKEM768 |
| 2 | HybridSignature byte layout wrong | `src/mesh/hybrid_signature.rs:17` | Update doc from "concatenation" to struct fields |

---

### 3.6 Mesh: Documentation Fixes

| # | Issue | Location | Fix |
|---|-------|----------|-----|
| 1 | Stale quorum verification reference | `architecture/mesh_deep_dive.md` | Change `src/mesh/raft/state_machine.rs:166-172` → `src/mesh/dht/signed.rs:860-934` |

---

### 3.7 Admin: Documentation Fixes

| # | Issue | Location | Fix |
|---|-------|----------|-----|
| 1 | Overseer→Supervisor rename | `architecture/admin_deep_dive.md:231,753` | Replace all "Overseer" with "Supervisor" |
| 2 | Handler count wrong | `architecture/admin_deep_dive.md:179` | Change "28 handlers" → "26+ handlers" |
| 3 | Line number reference wrong | `architecture/admin_deep_dive.md:259` | Change `src/admin/state.rs:254-264` → `src/admin/state.rs:257-267` |

---

### 3.8 WAF: Line Reference Corrections

| # | Issue | Location | Fix |
|---|-------|----------|-----|
| 1 | Multiple line reference errors | `src/waf/mod.rs:264→293`, `src/waf/attack_detection/detector_common.rs:484-512→442-517` | Update references |

---

### 3.9 Networking: Documentation Fixes

| # | Issue | Location | Fix |
|---|-------|----------|-----|
| 1 | HTTP/2 client config inconsistency | `src/http_client/mod.rs:374,420,644,893` | Clarify `is_http2 = true` vs `.http2_only(false)` |
| 2 | AcmeDnsChallenge line reference wrong | `architecture/networking_deep_dive.md:40` | Update reference |
| 3 | Shared Handler claim needs clarification | `architecture/networking_deep_dive.md:11` | Explain H1/H2 have separate implementations |

---

### 3.10 Routing: Documentation Fixes

| # | Issue | Location | Fix |
|---|-------|----------|-----|
| 1 | PeakEwma missing from docs | `architecture/routing_deep_dive.md:55` | Document algorithm at `src/upstream/pool.rs:48-57` |
| 2 | AxumDynamic backend type undocumented | `architecture/routing_deep_dive.md:38-46` | Add to backend types list |
| 3 | QuicTunnel URL parsing inconsistent | `src/router.rs:556-570 vs 858-872` | Unify parsing between location and site levels |
| 4 | "(Granian)" branding outdated | `src/router.rs:71` | Remove or clarify |
| 5 | Spin backend type undocumented | `src/router.rs:76` | Document Spin backend |

---

### 3.11 Platform: Documentation Fixes

| # | Issue | Location | Fix |
|---|-------|----------|-----|
| 1 | Missing fs.rs in Platform Module Table | `architecture/platform_deep_dive.md:17-25` | Add entry |
| 2 | Message Category Documentation incomplete | `architecture/platform_deep_dive.md:89-108` | Add AppServer variants, correct names |
| 3 | Process Module Table missing files | `architecture/platform_deep_dive.md:73-87` | Add `ipc_transport.rs`, `ipc_pool.rs`, `ipc_rate_limit.rs`, `socket_path.rs`, `ipc_windows.rs` |
| 4 | RuleFeedManager reference stale | `architecture/platform_deep_dive.md:201-220` | Likely renamed to `ThreatFeedManager` |
| 5 | Line offset error | `architecture/platform_deep_dive.md:224` | Change `279-302` → `278-302` |

---

### 3.12 Config: Documentation Fixes

| # | Issue | Location | Fix |
|---|-------|----------|-----|
| 1 | ConfigManager line numbers wrong | `architecture/config_deep_dive.md` | Change "113-233" → "113-241" |
| 2 | Process hierarchy not updated | `architecture/config_deep_dive.md` | Document Supervisor + Master + UnifiedServerWorker |
| 3 | Missing asn_scraping in DefaultsConfig | `crates/synvoid-config/src/defaults.rs:49` | Add `asn_scraping: AsnScrapingConfig` |

---

## Wave 4: Completeness & Implementation Improvements

### 4.1 Plugin: Completeness

| # | Issue | Location | Fix |
|---|-------|----------|-----|
| 1 | Warmup stub functions claim wrong | `architecture/plugin_deep_dive.md:107` | `guest_alloc` is NOT a stub - rewrite "all 7" claim |
| 2 | PooledInstance::prepare_for_request mismatch | `architecture/plugin_deep_dive.md:106` | Only `WasmPooledInstance` resets body_receiver |
| 3 | Missing guest_alloc in Host Functions Table | `architecture/plugin_deep_dive.md:71-78` | Add to table |

---

### 4.2 Proxy: Implementation Decisions Needed

| # | Issue | Location | Fix |
|---|-------|----------|-----|
| 1 | HTTP/2 dead code - decision needed | `http_client/mod.rs:890`, `http_client/erased_pool.rs:199-215` | Either implement HTTP/2 pooling or confirm removal |
| 2 | UpstreamClientRegistry unused | `proxy/client_registry.rs` | Either integrate into `ProxyServer` or deprecate |
| 3 | Missing ProxyHeadersConfig in send_single_request | `proxy/mod.rs:1225` | Pass custom proxy headers config |

---

### 4.3 Mesh: Edge Node & Raft Documentation

| # | Issue | Location | Fix |
|---|-------|----------|-----|
| 1 | Edge Node PoW Authentication undocumented | `src/mesh/peer_auth.rs:355-368` | Document PoW alternative to Org Key certs |
| 2 | Hierarchical Routing module unused | `src/mesh/hierarchical_routing.rs:2-9` | Add "[RESERVED - Not Active]" indicator |
| 3 | Raft scope namespace list missing | `src/mesh/raft/mod.rs:13-14` | Add explicit namespace list |

---

### 4.4 Config: Implementation Fixes

| # | Issue | Location | Fix |
|---|-------|----------|-----|
| 1 | Field type mismatches | `main_config.rs:51-53`, `lib.rs:76-78` | Should use `MainIpFeedConfig`, `MainRuleFeedConfig`, `MainYaraRuleFeedConfig` |
| 2 | Feature-gated fields undocumented | `crates/synvoid-config/src/lib.rs` | Add `#[cfg(feature = "...")]` annotations |
| 3 | Admin token generation weak | `crates/synvoid-config/src/admin.rs:190-204` | Add uppercase characters |

---

## Wave 5: Compilation Cleanup

### 5.1 Wave 5.1: Clippy -D Warnings (2 items confirmed)

| # | Crate | Issue | Location | Fix |
|---|-------|-------|----------|-----|
| 1 | cloakrs | collapsible match | `cloak/src/jpeg_transcoder/header.rs:290` | Remove braces from `0xDD` match arm |
| 2 | synvoid-config | needless borrow | `crates/synvoid-config/src/mesh.rs:656` | Change `ref genesis_config` to `genesis_config` |

**Already Fixed:**
- `app_server.rs:5` - No `utoipa::ToSchema` import present
- `mesh.rs:12` - `POW_CACHE_TTL_SECS` constant not present in this crate
- `icmp_filter.rs:88-92` - `#[derive(Default)]` already correct
- `http/server.rs:3302` - Already simplified to `let use_erased_client = false;`

---

### 5.2 Wave 5.2: Test Compilation (~150 errors)

| # | Category | Location | Fix |
|---|----------|----------|-----|
| 1 | AttackDetection API mismatch (~144 errors) | `src/waf/attack_detection/mod.rs:254`, `tests/integration_test.rs:4666+` | Add `client_ip: IpAddr` as first arg; add `.await` |
| 2 | Missing struct fields | `src/worker/unified_server.rs:1884-1941`, `tests/integration_test.rs:45-60,139-159` | Add `cpu_affinity`, `total_workers`, `restart_backoff_max_secs`, etc. |
| 3 | Wrong import | `tests/integration_test.rs` | Update `WhitelistConfig` to `crate::config::SiteWhitelistConfig` |
| 4 | Missing Debug impl | `src/http_client/` | Add `#[derive(Debug)]` to `Http1PooledConnection` |

---

### 5.3 Wave 5.3: Warnings (~60+ items)

| Category | Count | Example Files |
|----------|-------|---------------|
| Unused imports | ~40 | `src/admin/handlers/alerting.rs`, `src/http/server.rs`, `src/proxy/executor.rs`, etc. |
| Dead code | ~15 | `admin/handlers/config.rs`, `http/server.rs`, `Http2PooledConnection`, etc. |
| Deprecated API | 5 | `Nonce::from_slice` → `Nonce::from_bytes` |

---

### 5.4 Wave 5.4: Formatting (3 files)

- `src/mesh/dht/quorum.rs`
- `src/mesh/raft/mod.rs`
- `src/mesh/raft/network.rs`

---

## Deferred Items (Preserved from Previous Plan)

| ID | Issue | Location | Reason |
|----|-------|----------|--------|
| APP-15 | FastCGI Response NOT Truly Streamed | `src/fastcgi/mod.rs:132-164` | Buffers entire stdout; architectural change needed |
| SUP-1 | gRPC Control Plane TLS | `src/supervisor/api.rs:114-129` | Intentional - localhost IPC doesn't need TLS |

---

## Known Incomplete Items (Not Bugs)

| Item | Location | Issue |
|------|----------|-------|
| ErasedHttpClient Phase 9 | `src/http/server.rs:3302` | `use_erased_client` hardcoded to `false` |
| HTTP/2 disabled | `src/http_client/mod.rs:890` | `is_http2 = false`, infrastructure exists but unused |
| Minification unused | `src/static_files/mod.rs:134-136` | Params silently ignored |
| Spin instance reuse | `src/spin/runtime.rs:260` | Per-request instantiation overhead |
| GOST DS digest | `src/dns/dnssec_validation.rs:260` | Returns error "not yet supported" |

---

## Dependencies & Parallelization

### Critical Bugs (Wave 1) - BUG-ROUTER-1 Only Remains
```
BUG-ROUTER-1 (hardcoded port 80) --> Wave 2, 3, 4, 5
```
**BUG-PL-1** and **BUG-L1** are already fixed.

### Wave 2-5: Can Execute in Parallel
All waves 2-5 can execute **in parallel** since they are independent:
- Wave 2: Config consistency (WAF, DNS)
- Wave 3: Documentation fixes (multiple docs)
- Wave 4: Completeness improvements (plugin, proxy, mesh, config)
- Wave 5: Compilation cleanup (clippy, warnings, formatting)

### Sub-Agent Parallelization Strategy
Within each wave, items can be parallelized by module:

| Module Group | Items | Sub-Agent Tasks |
|-------------|-------|-----------------|
| **Config/DNS** | 2.2, 2.4, 3.3, 3.12 | 1 agent |
| **WAF** | 2.1, 2.2, 3.8 | 1 agent |
| **Process/App/Worker** | 3.1, 3.2, 3.4 | 1 agent |
| **Layer 3.5/Mesh** | 3.5, 3.6, 4.3 | 1 agent |
| **Admin/Routing** | 3.7, 3.10, 4.2 | 1 agent |
| **Platform/Plugin** | 3.11, 4.1 | 1 agent |
| **Cleanup** | Wave 5 | 1 agent |

**Total: 7 sub-agents can work in parallel**

---

## Verification Commands

```bash
# All profiles should compile
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns

# Clippy lint
cargo fmt && cargo clippy --lib -- -D warnings

# Test compilation
cargo test --lib --no-run

# Security regression tests
cargo test --test security_regression
```

---

## Appendix A: File Changes Summary

| File | Changes Needed | Status |
|------|----------------|--------|
| `src/router.rs` | Fix hardcoded port 80, unify QuicTunnel parsing | **NEEDS FIX** |
| `src/main.rs` | --master CLI flag | ✅ Already fixed |
| `src/mesh/ml_dsa.rs` | verify_hybrid fail-safe | ✅ Already fixed |
| `architecture/plugin_deep_dive.md` | Fix DHT prefix examples (SECURITY) | **NEEDS FIX** |
| `architecture/process_lifecycle.md` | CPU affinity, worker types, Overseer→Supervisor | Needs fix |
| `architecture/app_handlers.md` | SpinHttpHandler, FastCGI, WASM | Needs fix |
| `architecture/dns_deep_dive.md` | Remove incorrect AXFR section | Needs fix |
| `architecture/worker_architecture.md` | WAF pipeline, health monitoring | Needs fix |
| `architecture/layer_3_5_deep_dive.md` | KEM algorithm, HybridSignature | Needs fix |
| `architecture/mesh_deep_dive.md` | Quorum verification reference | Needs fix |
| `architecture/admin_deep_dive.md` | Overseer→Supervisor rename | Needs fix |
| `architecture/networking_deep_dive.md` | HTTP/2, AcmeDnsChallenge | Needs fix |
| `architecture/routing_deep_dive.md` | PeakEwma, AxumDynamic, Spin | Needs fix |
| `architecture/platform_deep_dive.md` | Missing files, message categories | Needs fix |
| `architecture/config_deep_dive.md` | ConfigManager lines, process hierarchy | Needs fix |
| `src/waf/traffic_shaper/limiter.rs` | ConnectionLimiter defaults, unused params | Clarification |
| `crates/synvoid-config/src/dns/mod.rs` | DnsConfig.validate() - add recursive | Needs fix |
| `cloak/src/jpeg_transcoder/header.rs` | Remove braces from 0xDD match | Needs fix |
| `crates/synvoid-config/src/mesh.rs` | Remove needless borrow | Needs fix |

---

*Last Updated: 2026-05-26*
