# MaluWAF Consolidated Remediation Plan

> Generated: 2026-03-31
> Consolidated from 28 individual plan files
> Complements: `AGENTS.md` (codebase conventions, known patterns)

---

## Executive Summary

This plan consolidates **180+ improvement items** across 11 domains into a structured execution roadmap organized by priority and dependency. Items are grouped into **waves** that can be executed in parallel by sub-agents.

| Wave | Focus | Items | Est. Effort | Parallel Agents |
|------|-------|-------|-------------|-----------------|
| Wave 0 | Critical Security & Correctness | 25 | 8-12 days | 5 |
| Wave 1 | High-Priority Security & Correctness | 35 | 10-15 days | 7 |
| Wave 2 | Performance Optimization | 25 | 8-12 days | 5 |
| Wave 3 | Feature Additions | 30 | 15-25 days | 6 |
| Wave 4 | Code Quality & Cleanup | 20 | 5-8 days | 4 |
| Wave 5 | Documentation & Testing | 15 | 3-5 days | 3 |

**Total sequential: 49-77 days**
**Total with parallelization: 20-35 days**

---

## Domain Index

| Domain | Source Plans | Key Items |
|--------|-------------|-----------|
| Security (Critical) | plan5, plan_waf4, plan_tls2, plan_mesh3, plan_mesh4 | WAF body bypass, cert verification, trust model, domain verification |
| DNS/DNSSEC | plan_dns1-4 | Wire format, response semantics, validation, scalability |
| WAF/Proxy | plan_waf1-4, plan3 | Check paths, normalization, caching, multi-worker |
| Mesh/DHT | plan5, plan_mesh3-4 | Trust model, PoW, capability enforcement, scalability |
| Honeypot/Threat Intel | plan_honeypot2-3 | Mesh sharing, standalone mode, DHT bridge |
| TLS | plan_tls2 | PQ verification, cert validation, key strength |
| YARA/Upload | plan_yara2-3 | Mesh distribution, upload scanning, security |
| Plugins/WASM | plan_wasm2-3, plan_plugins2 | Instance pooling, observability, per-site assignment |
| Serverless | plan_serverless, plan_serverless2 | Multi-runtime (WASM/Deno/Native), instance pools |
| Admin Panel | plan4, plan5 | CSRF, config schema, file splits |
| Cache/Edge | plan_cache2-3 | Image poison DHT publishing, non-mesh fallback |

---

## Wave 0: Critical Security & Correctness (P0)

**These items must be addressed before any other wave.** Each sub-wave can run in parallel.

### Wave 0A: WAF & Proxy Critical Fixes

**0A.1 Buffer Request Body Before WAF Inspection** (plan_waf4 C1, plan5 C1)
- **Files:** `src/http/server.rs:454,664`
- **Problem:** Body is dropped before WAF check — all POST/PUT/PATCH body attacks bypass detection
- **Fix:** Collect body into `Bytes` with size limit before `check_request_full()`, pass through
- **Effort:** 0.5 days

**0A.2 Unify WAF Check Paths — Eliminate `check_waf()` Bypass** (plan3 1.1, plan_waf2 2.2)
- **Files:** `src/proxy.rs:546-706`
- **Problem:** `ProxyServer::check_waf()` skips all 16 attack detection modules
- **Fix:** Replace inline `check_waf()` with delegation to `WafCore::check_request_full()`
- **Effort:** 1 day

**0A.3 Fix Thread-Local WAF State** (plan3 1.3, plan_waf2 2.1, plan_yara2 H5)
- **Files:** `src/waf/mod.rs:75-98`
- **Problem:** `thread_local!` for `THREAT_INTEL` and `YARA_RULES` unreliable with tokio work-stealing
- **Fix:** Replace with `OnceLock<Arc<...>>` or store on worker state
- **Effort:** 1-2 days

**0A.4 Move Whitelist Check to First Position** (plan_waf4 2.1, plan_waf1 1.2)
- **Files:** `src/waf/mod.rs:839-898`
- **Problem:** Whitelist check is at position 8, after 7 expensive checks
- **Fix:** Move to first position in `check_request_full()`
- **Effort:** 0.25 days

### Wave 0B: DNSSEC Wire Format Correctness

**0B.1 Fix DNSKEY RDATA Encoding** (plan_dns4 1.1, plan5 C3)
- **Files:** `src/dns/server/dnssec_impl.rs:52,62`
- **Problem:** Encodes raw public key only, missing flags/protocol/algorithm
- **Fix:** Use `compute_dnskey()` which produces correct RDATA
- **Effort:** 0.5 days

**0B.2 Fix CDNSKEY RDATA Encoding** (plan_dns4 1.2)
- **Files:** `src/dns/server/dnssec_impl.rs:176`
- **Problem:** Same bug as DNSKEY
- **Fix:** Apply same fix as 0B.1
- **Effort:** 0.25 days

**0B.3 Fix RRSIG to Sign Entire RRsets** (plan_dns4 1.3, plan5 C4)
- **Files:** `src/dns/dnssec.rs:335-377`, `src/dns/server/response.rs:226`, `src/dns/server/dnssec_impl.rs:520`
- **Problem:** Signs individual records instead of entire RRset (RFC 4034 violation)
- **Fix:** Build concatenated canonical RDATA for all records, sign once
- **Effort:** 1-2 days

**0B.4 Fix RRSIG 64-bit Timestamps to 32-bit** (plan5 C3)
- **Files:** `src/dns/dnssec_signing.rs:51-56`, `src/dns/server/dnssec_impl.rs:533-535`
- **Problem:** RRSIG inception/expiration written as 64-bit instead of 32-bit
- **Fix:** Cast to `u32` before `to_be_bytes()`
- **Effort:** 0.25 days

**0B.5 Fix NSEC3 Hash Off-by-One** (plan5 C4)
- **Files:** `src/dns/dnssec_signing.rs:172-211`
- **Problem:** Initial hash starts with raw name bytes instead of name||salt
- **Fix:** First iteration must hash `name || salt`
- **Effort:** 0.5 days

**0B.6 Fix DNSKEY RRset Signed by KSK** (plan_dns3 1.4, plan_dns4 1.4)
- **Files:** `src/dns/dnssec.rs:321`
- **Problem:** DNSKEY RRset signed by ZSK instead of KSK
- **Fix:** Remove DNSKEY from ZSK signing list, add separate KSK signing method
- **Effort:** 0.5 days

### Wave 0C: Mesh Trust Model

**0C.1 Enforce Global Node Authentication on All Transports** (plan_mesh3 C1-C3)
- **Files:** `src/mesh/transports/wireguard.rs:258,261`, `src/mesh/discovery.rs:332,335`
- **Problem:** WireGuard and Discovery trust claimed role without `global_node_key` verification
- **Fix:** Extract shared `validate_peer_role()` function, apply to all transports
- **Effort:** 1 day

**0C.2 Fix gRPC Key Exchange — Proxy to Origin** (plan_mesh4 1.1)
- **Files:** `src/mesh/passover_key_exchange.rs:331-408`
- **Problem:** gRPC handler signs locally with origin's key instead of proxying
- **Fix:** Forward request to origin node via mesh datagram
- **Effort:** 1 day

**0C.3 Hard-Fail Node ID Verification** (plan_mesh4 1.2)
- **Files:** `src/mesh/transport.rs:1244-1268`
- **Problem:** Missing `public_key` only logs warning, skips verification
- **Fix:** Return `AuthFailed` error when `public_key` is missing
- **Effort:** 0.25 days

**0C.4 Enforce Mutual TLS in QUIC** (plan_mesh4 1.3)
- **Files:** `src/mesh/cert.rs:306-382`
- **Problem:** `enforce_mutual_tls` defaults to true but uses `with_no_client_auth()`
- **Fix:** Use `with_client_cert_verifier()` when mTLS enabled
- **Effort:** 1 day

### Wave 0D: Domain Verification & Certificate Security

**0D.1 Fix Domain Verification Bypasses** (plan_dns4 Phase 2)
- **Files:** `src/mesh/transport_dns.rs:1065-1133`
- **Problem:** TXT, OAuth, and signed challenge verification all return `true` unconditionally
- **Fix:** Implement real DNS TXT lookup, Ed25519 signature verification
- **Effort:** 2-3 days

**0D.2 Fix Mesh Certificate Verification** (plan_tls2 Phase 1)
- **Files:** `src/mesh/cert.rs:553-592`
- **Problem:** Compares subject name strings instead of verifying cryptographic chain
- **Fix:** Use `RootCertStore` + `WebPkiServerVerifier` for proper X.509 validation
- **Effort:** 1 day

**0D.3 Fix IPC Key File TOCTOU Race** (plan5 H11)
- **Files:** `src/process/manager.rs:558-578`
- **Problem:** Creates file then sets permissions — TOCTOU window
- **Fix:** Use `OpenOptions::new().create_new(true).mode(0o600)`
- **Effort:** 0.25 days

### Wave 0E: NoVerifier & TLS Client Security

**0E.1 Fix NoVerifier to Only Skip Hostname Check** (plan5 C2)
- **Files:** `src/http_client/mod.rs:258-306`
- **Problem:** `NoVerifier` disables full signature verification, not just hostname
- **Fix:** Implement `ServerCertVerifier` that validates chain but skips hostname
- **Effort:** 1 day

**0E.2 Harden NoVerifier with Audit Logging** (plan_waf2 2.3)
- **Files:** `src/http_client/mod.rs:258-306`
- **Problem:** Silently accepts all certificates without logging
- **Fix:** Log per-connection warning at WARN level, enforce `skip_verify_reason`
- **Effort:** 0.5 days

**0E.3 Fix PBKDF2 Static Salt** (plan_mesh4 1.4)
- **Files:** `src/mesh/config_identity.rs:255`
- **Problem:** Hardcoded salt enables rainbow table attacks
- **Fix:** Generate random 16-byte salt, store alongside ciphertext
- **Effort:** 0.5 days

---

## Wave 1: High-Priority Security & Correctness (P1)

### Wave 1A: WAF & Proxy Security

**1A.1 Fix SSRF Octal/Decimal IP Bypass** (plan5 H1, plan_waf4 6.1)
- **Files:** `src/waf/attack_detection/ssrf.rs:42-59`
- **Problem:** Octal (`0177.0.0.1`) and decimal (`2130706433`) IP representations bypass private IP detection
- **Fix:** Add `parse_ipv4_flexible()` that normalizes all representations
- **Effort:** 0.5 days

**1A.2 Fix Path Traversal in `sanitize_request_path`** (plan5 H2)
- **Files:** `src/proxy.rs:110-159`
- **Problem:** Does not handle `..` traversal
- **Fix:** Resolve path segments properly, handle double-encoding
- **Effort:** 0.5 days

**1A.3 Fix Trust Anchor `is_trusted()` — Exclude Pending State** (plan5 H4)
- **Files:** `src/dns/trust_anchor.rs:137-142`
- **Problem:** Includes `Pending` state as trusted (RFC 5011 violation)
- **Fix:** Only `Valid` state should be trusted
- **Effort:** 0.25 days

**1A.4 Persist Trust Anchor State Transitions** (plan5 H5)
- **Files:** `src/dns/trust_anchor.rs:404-585`
- **Problem:** State changes never persisted to disk
- **Fix:** Add `save_anchors()` calls after state modifications
- **Effort:** 0.5 days

**1A.5 Add SOA to NXDOMAIN Authority Section** (plan5 H6)
- **Files:** `src/dns/server/query.rs:931-1035`
- **Problem:** NXDOMAIN responses missing SOA record
- **Fix:** Append SOA to authority section per RFC 1035
- **Effort:** 0.5 days

### Wave 1B: DNS Response Correctness

**1B.1 Fix AD Flag Semantics** (plan_dns3 1.1)
- **Files:** `src/dns/server/response.rs:24-31`
- **Problem:** AD flag set when ZSK exists, not when RRSIGs were actually produced
- **Fix:** Track `any_rrsig_appended` and set AD only when signatures were produced
- **Effort:** 0.5 days

**1B.2 Wire DNSSEC into Mesh Resolution Path** (plan_dns3 1.2, plan_dns4 1.5)
- **Files:** `src/dns/server/query.rs:817-834`
- **Problem:** Mesh resolution always passes `zsk: None`
- **Fix:** Look up zone's ZSK before building response
- **Effort:** 0.5 days

**1B.3 Add DNSSEC to NXDOMAIN Responses** (plan_dns3 1.3)
- **Files:** `src/dns/server/query.rs:4-49`
- **Problem:** `build_simple_nxdomain_response` has no DNSSEC, no OPT, AD always false
- **Fix:** Add NSEC/NSEC3 proof, OPT record with DO bit echo
- **Effort:** 0.5 days

**1B.4 Fix `build_forward_headers` Not Called** (plan5 H3)
- **Files:** `src/tls/server.rs:716-758`
- **Problem:** Upstream requests never get `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto`
- **Fix:** Call `build_forward_headers()` in all proxy paths
- **Effort:** 0.5 days

### Wave 1C: Admin & Config Security

**1C.1 Wire Up CSRF Token Validation** (plan5 H8, plan4 1.2)
- **Files:** `src/admin/state.rs:498-534`
- **Problem:** CSRF tokens generated but never validated
- **Fix:** Add CSRF middleware to state-changing endpoints (PUT/POST/DELETE)
- **Effort:** 1 day

**1C.2 Fix Admin Config Race Condition** (plan5 H7)
- **Files:** `src/admin/handlers/config.rs:1346-1371`
- **Problem:** `update_overseer_config` reads TOML from disk after in-memory update, overwriting fields
- **Fix:** Use in-memory config as source of truth, serialize full config to disk
- **Effort:** 0.5 days

**1C.3 Fix Plaintext Token Migration** (plan4 1.1, deferred 2.3)
- **Files:** `src/admin/auth.rs:24-34`
- **Problem:** Returns `false` with no migration path for legacy plaintext tokens
- **Fix:** Add `hash-admin-token` CLI subcommand, migration endpoint
- **Effort:** 0.5 days

**1C.4 Reload and Broadcast After `import_config`** (plan5 M6)
- **Files:** `src/admin/handlers/config.rs:1208-1241`
- **Problem:** Imported config written to disk but not reloaded or broadcast
- **Fix:** Reload into memory and broadcast to workers after write
- **Effort:** 0.25 days

**1C.5 Skip Worker Broadcast on Partial Reload Failure** (plan5 M7)
- **Files:** `src/admin/handlers/config.rs:1076-1079`
- **Problem:** Workers receive broadcast even when config reload partially fails
- **Fix:** Only broadcast if all reloads succeed
- **Effort:** 0.25 days

### Wave 1D: Mesh & DHT Security

**1D.1 Sign Domain Registration DHT Records** (plan_dns4 2.4)
- **Files:** `src/mesh/dht/record_store_dns.rs:36-44`
- **Problem:** Domain registration records created with empty signature
- **Fix:** Sign records using `RecordSigner` before storing
- **Effort:** 0.5 days

**1D.2 Fix Sequence Number Mismatch** (plan_dns4 2.5)
- **Files:** `src/mesh/dht/record_store_crud.rs:158`, `record_store_dns.rs:163`
- **Problem:** Signing uses sequence 1, verification uses 0
- **Fix:** Align to use sequence 0 everywhere
- **Effort:** 0.25 days

**1D.3 Fix `request_id.split('-')` Parsing** (plan_dns4 2.6)
- **Files:** `src/dns/mesh_sync/verification.rs:672,721`
- **Problem:** Breaks on domains with hyphens
- **Fix:** Use `rsplitn(3, '-')` to parse from end
- **Effort:** 0.25 days

**1D.4 Increase PoW Difficulty from 16 to 24 Bits** (plan5 M9, plan_mesh3 2.2)
- **Files:** `src/mesh/dht/routing/node_id.rs:10`
- **Problem:** 16-bit PoW trivially solvable (~6ms)
- **Fix:** Increase to 24 bits, fix bit-level verification
- **Effort:** 0.5 days

**1D.5 Add PoW Verification to `try_insert`** (plan5 H9)
- **Files:** `src/mesh/dht/routing/table.rs:207-216`
- **Problem:** `try_insert` bypasses PoW verification
- **Fix:** Add same PoW check as `insert()`
- **Effort:** 0.25 days

### Wave 1E: Honeypot & Threat Intel Critical Fixes

**1E.1 Wire Threat Message Dispatch in Transport** (plan_honeypot3 1.1)
- **Files:** `src/mesh/transport_peer.rs:848`
- **Problem:** All threat messages fall through to catch-all, `handle_mesh_message()` never called
- **Fix:** Add match arms for `ThreatAnnounce`, `ThreatSyncRequest`, `ThreatSyncResponse`, `ThreatAcknowledgement`
- **Effort:** 0.5 days

**1E.2 Fix `start_background_tasks()` No-Op** (plan_honeypot2 C1, plan_honeypot3 1.2)
- **Files:** `src/mesh/threat_intel.rs:1007-1044`
- **Problem:** `if let Some(message) = None::<MeshMessage>` always None
- **Fix:** Implement real periodic broadcast, sync, cleanup tasks
- **Effort:** 1 day

**1E.3 Handle `ThreatSyncResponse`** (plan_honeypot2 C2, plan_honeypot3 1.3)
- **Files:** `src/mesh/threat_intel.rs:889-1005`
- **Problem:** Responses silently discarded
- **Fix:** Add handler arm, apply indicators via `apply_sync()`
- **Effort:** 0.5 days

**1E.4 Fix `create_threat_announce()` Race Condition** (plan_honeypot3 M1, 1.4)
- **Files:** `src/mesh/threat_intel.rs:791-794`
- **Problem:** Between read-lock clone and write-lock clear, indicators can be lost
- **Fix:** Use `std::mem::take()` for atomic drain
- **Effort:** 0.25 days

**1E.5 Wire Port Honeypot to Run** (plan_honeypot3 C4, Phase 2)
- **Files:** `src/worker/unified_server.rs`
- **Problem:** `PortHoneypotRunner::new()` never called
- **Fix:** Add standalone initialization path, wire into admin state
- **Effort:** 1 day

### Wave 1F: YARA Mesh Distribution

**1F.1 Wire YARA Rules Manager to Transport** (plan_yara2 C1, plan_yara3 1.1)
- **Files:** `src/mesh/yara_rules.rs:96`, `src/worker/unified_server.rs`
- **Problem:** `mesh_sender` never set, all broadcasts silently dropped
- **Fix:** Create mpsc channel, call `set_mesh_sender()`, spawn forwarder task
- **Effort:** 0.5 days

**1F.2 Add YARA Message Handlers to Transport** (plan_yara2 C2, plan_yara3 1.2)
- **Files:** `src/mesh/transport_peer.rs:848`
- **Problem:** All 6 YARA message types silently dropped
- **Fix:** Add match arms dispatching to `YaraRulesManager::handle_mesh_message()`
- **Effort:** 0.5 days

**1F.3 Create UploadValidator During Worker Init** (plan_yara2 C3, plan_yara3 2.1)
- **Files:** `src/upload/mod.rs:75`, `src/worker/unified_server.rs`
- **Problem:** `UploadValidator` never instantiated
- **Fix:** Create during worker startup, store in worker state
- **Effort:** 0.5 days

### Wave 1G: IPC & Process Management

**1G.1 Fix `ConnectionPermit::Drop` Underflow** (plan5 M14)
- **Files:** `src/process/ipc_pool.rs:126-130`
- **Problem:** `fetch_sub` can underflow
- **Fix:** Use `fetch_update` with `checked_sub`
- **Effort:** 0.25 days

**1G.2 Add Vec Length Limits to Message Validation** (plan5 8.1)
- **Files:** `src/process/ipc.rs:680-996`
- **Problem:** No maximum length checks for Vec fields
- **Fix:** Add `MAX_BLOCKLIST_ENTRIES`, `MAX_RULE_PATTERNS` limits
- **Effort:** 0.5 days

**1G.3 Fix `blocking_send` in Health Check Context** (plan5 8.2)
- **Files:** `src/process/manager.rs:1112-1119`
- **Problem:** `blocking_send` can deadlock in async context
- **Fix:** Replace with `try_send`, log dropped events via metrics
- **Effort:** 0.25 days

**1G.4 Fix Unified Server Worker Restart Lacks Backoff** (plan5 M15)
- **Files:** `src/process/manager.rs:1377-1444`
- **Problem:** No exponential backoff on restart
- **Fix:** Add backoff similar to `handle_failure_restarts()`
- **Effort:** 0.5 days

---

## Wave 2: Performance Optimization (P1)

### Wave 2A: WAF Hot-Path Performance

**2A.1 Normalize Input Once, Share Across Detectors** (plan_waf2 1.1)
- **Files:** `src/waf/attack_detection/normalizer.rs`, `src/waf/attack_detection/mod.rs`
- **Problem:** Input normalized 12+ times per request (once per detector)
- **Fix:** Normalize once at top of `AttackDetector::check_request()`, pass `NormalizedInputs`
- **Effort:** 2-3 days

**2A.2 Add Pre-Allocated Buffer Pool for Normalization** (plan_waf2 1.2)
- **Files:** `src/waf/attack_detection/normalizer.rs`
- **Problem:** Allocates new `String` + `Vec<char>` on every call
- **Fix:** Thread-local buffer pool, reuse across calls
- **Effort:** 1 day

**2A.3 Add Request Body Size Limit Before WAF Inspection** (plan_waf2 1.3)
- **Files:** `src/waf/mod.rs`
- **Problem:** 10MB POST body could cause 1GB of allocations through 100x output ratio
- **Fix:** Enforce configurable body size limit before WAF
- **Effort:** 0.5 days

**2A.4 Move ASN Cleanup Off Hot Path** (plan3 3.1, plan_waf4 2.3)
- **Files:** `src/waf/mod.rs:855`
- **Problem:** `cleanup_unique_ips()` called on every request (O(n) retain)
- **Fix:** Move to background task running every 60 seconds
- **Effort:** 0.25 days

**2A.5 Replace AttackDetector RwLock with ArcSwap** (plan_waf2 4.1, plan_waf4 2.2)
- **Files:** `src/waf/mod.rs:1075`
- **Problem:** RwLock held for entire attack detection pass
- **Fix:** Use `ArcSwapOption` for lock-free reads
- **Effort:** 0.5 days

**2A.6 Unify Global Rate Limit Checks** (plan_waf4 2.4)
- **Files:** `src/waf/mod.rs:907,925`
- **Problem:** Two separate global resource acquisitions per request
- **Fix:** Combine into single `check_global_combined()` method
- **Effort:** 0.5 days

### Wave 2B: DNS Scalability

**2B.1 Make Firewall Evaluation Take `&self`** (plan_dns4 3.1)
- **Files:** `src/dns/firewall.rs`, `src/dns/server/startup.rs:303,635`
- **Problem:** `evaluate_query` takes `&mut self`, write lock per query
- **Fix:** Move `cleanup_expired_rules()` to periodic task, change to `&self`
- **Effort:** 0.5 days

**2B.2 Fix Cache `get()` Write Lock** (plan_dns3 3.3, plan_dns4 3.2)
- **Files:** `src/dns/cache.rs:234`
- **Problem:** `get()` acquires write lock because `LruCache::get()` mutates LRU order
- **Fix:** Replace with `moka::sync::Cache` for lock-free reads
- **Effort:** 1-2 days

**2B.3 Add Domain→Edge Node Index** (plan_dns4 3.3)
- **Files:** `src/dns/mesh_sync/mod.rs`
- **Problem:** O(N*D) scan per geo query
- **Fix:** Add reverse index `domain_to_edge_index: HashMap<String, Vec<String>>`
- **Effort:** 0.5 days

**2B.4 Shard the Zone Store** (plan_dns3 3.1)
- **Files:** `src/dns/server/mod.rs:476`
- **Problem:** Single `RwLock<HashMap>` for all zones
- **Fix:** Use `Vec<RwLock<HashMap>>` with 64 shards
- **Effort:** 2-3 days

### Wave 2C: Mesh & Transport Performance

**2C.1 Make Broadcast Sends Concurrent** (plan_mesh3 4.1)
- **Files:** `src/mesh/transport.rs:1795-1842`, `src/mesh/transports/wireguard.rs:509-522`
- **Problem:** Sequential `for peer in peers { send().await }`
- **Fix:** Use `FuturesUnordered` for concurrent fan-out
- **Effort:** 1 day

**2C.2 Replace `get_random_peers` with Reservoir Sampling** (plan_mesh3 4.2)
- **Files:** `src/mesh/topology.rs:685-695`
- **Problem:** O(N) full-shuffle allocating Vec of all peers
- **Fix:** Reservoir sampling, O(N) time, O(k) space
- **Effort:** 0.5 days

**2C.3 Fix DHT Rate Limiter Lock Contention** (plan_mesh4 3.3)
- **Files:** `src/mesh/dht/mod.rs:42-84`
- **Problem:** Write lock on every request, O(n) retain on every call
- **Fix:** Use `DashMap` for per-peer sharding, run cleanup on timer
- **Effort:** 0.5 days

**2C.4 Buffered Header Parsing from QUIC Streams** (plan_waf4 3.1)
- **Files:** `src/mesh/transport.rs:1910-1944`
- **Problem:** Reads headers one byte at a time (~1000 async reads per response)
- **Fix:** Read into 4KB buffer, parse from accumulated buffer
- **Effort:** 1 day

**2C.5 Early Return on Route Query Completion** (plan_waf4 3.3)
- **Files:** `src/mesh/transport.rs:1556`
- **Problem:** Sleeps full `query_timeout_ms` even when all responses arrive early
- **Fix:** Use `tokio::select!` to return when all expected responses arrive
- **Effort:** 0.5 days

### Wave 2D: Proxy & Cache Performance

**2D.1 Cache Upstream TLS Clients by Config Hash** (plan_waf3 2.1, plan_waf4 1.2)
- **Files:** `src/http/server.rs:1132-1144`, `src/http_client/mod.rs`
- **Problem:** `create_upstream_client()` called per request for custom TLS config
- **Fix:** Maintain `DashMap` keyed by TLS config hash
- **Effort:** 0.5 days

**2D.2 Eliminate Redundant Body Copy in Mesh Proxy Path** (plan_waf4 1.3)
- **Files:** `src/mesh/proxy.rs:714`, `src/mesh/transport.rs:1894`
- **Problem:** Body collected into `Bytes`, then re-collected from `Full<Bytes>` wrapper
- **Fix:** Pass `Bytes` directly as parameter
- **Effort:** 1 day

**2D.3 Parallel Mesh Config Fetch** (plan_waf4 3.2)
- **Files:** `src/http/server.rs:1215-1348`
- **Problem:** 3 sequential `.await` calls for minification, image protection, compression
- **Fix:** Use `tokio::join!` for parallel fetch
- **Effort:** 0.25 days

**2D.4 Replace `try_lock` with Concurrent Cache** (plan_waf4 3.4)
- **Files:** `src/mesh/proxy.rs:417,430`
- **Problem:** `try_lock()` on `Mutex<LruCache>` returns miss under contention
- **Fix:** Replace with `moka::sync::Cache`
- **Effort:** 1 day

**2D.5 Add Byte-Size Limit to Transform Cache** (plan_waf4 3.5)
- **Files:** `src/mesh/proxy.rs:154-159`
- **Problem:** Only entry-count limit, large responses dominate memory
- **Fix:** Add `max_total_bytes` limit with size-based eviction
- **Effort:** 0.5 days

### Wave 2E: Rate Limiter Optimization

**2E.1 Optimize Rate Limiter Background Cleanup** (plan_waf2 4.2)
- **Files:** `src/waf/ratelimit/core.rs:498-507`
- **Problem:** `decay_all()` iterates all 65,536 slots regardless of activity
- **Fix:** Use generation counter instead of decay
- **Effort:** 1-2 days

**2E.2 Eliminate HashMap Clone in Tracker Persistence** (plan_waf2 4.3)
- **Files:** `src/waf/probe_tracker.rs:387`, `src/waf/violation_tracker.rs:227`
- **Problem:** Full HashMap clone on every event
- **Fix:** Use double-buffer pattern with `std::mem::swap`
- **Effort:** 1 day

---

## Wave 3: Feature Additions (P2)

### Wave 3A: Multi-Worker Horizontal Scaling

**3A.1 Extend ProcessManager to Support Multiple Workers** (plan_waf3 1.1)
- **Files:** `src/process/manager.rs:732`
- **Problem:** Only one unified server worker spawned
- **Fix:** Add `spawn_unified_server_workers(count)`, track per-worker metrics
- **Effort:** 2-3 days

**3A.2 Add Worker Count Configuration** (plan_waf3 1.2)
- **Files:** `src/config/main.rs`
- **Fix:** Add `worker_count` config field, auto-detect CPU cores
- **Effort:** 0.5 days

**3A.3 Add Connection Semaphore to HTTP Server** (plan_waf4 5.1)
- **Files:** `src/http/server.rs`
- **Problem:** No application-level connection limit
- **Fix:** Add `tokio::sync::Semaphore` limiting concurrent connections
- **Effort:** 0.5 days

### Wave 3B: WASM Plugin Improvements

**3B.1 WASM Filter Instance Pooling** (plan_wasm3 Phase 1)
- **Files:** `src/plugin/wasm_runtime.rs`, new `src/plugin/instance_pool.rs`
- **Problem:** Fresh Store+Instance per request, full instantiation cost each time
- **Fix:** Tiered execution model with pooled instances, Store reset between requests
- **Effort:** 2-3 days

**3B.2 WASM Filter Observability** (plan_wasm3 Phase 2)
- **Files:** `src/plugin/metrics.rs` (new)
- **Problem:** Zero metrics for WASM plugin execution
- **Fix:** Per-plugin metrics: invocations, decisions, durations, errors, fuel consumed
- **Effort:** 1 day

**3B.3 WASM Filter Reliability and Security** (plan_wasm3 Phase 3)
- **Files:** `src/plugin/mod.rs`, `src/plugin/wasm_runtime.rs`
- **Problem:** Fail-open policy not configurable, all plugins run on all sites
- **Fix:** Per-plugin error policy, per-site plugin selection, plugin ordering
- **Effort:** 1-2 days

**3B.4 Per-Site WASM Plugin Assignment** (plan_wasm2 Phase 2)
- **Files:** `src/config/site.rs`, `src/http/server.rs:1017`
- **Problem:** All loaded WASM plugins run on every request to every site
- **Fix:** Add `wasm_plugins: Option<Vec<String>>` to site proxy config
- **Effort:** 0.5 days

### Wave 3C: Backend Dispatch Wiring

**3C.1 Static File Dispatch** (plan_plugins2 1.2)
- **Files:** `src/http/server.rs`
- **Problem:** `StaticFileHandler` never invoked in request dispatch
- **Fix:** Add dispatch branch for `BackendType::Static`
- **Effort:** 0.5 days

**3C.2 FastCGI/PHP/CGI Dispatch** (plan_plugins2 1.3-1.5)
- **Files:** `src/http/server.rs`
- **Problem:** FastCGI, PHP, CGI backends exist but never dispatched
- **Fix:** Add dispatch methods for each backend type
- **Effort:** 1-2 days

**3C.3 Granian AppServer Dispatch** (plan_plugins2 1.6)
- **Files:** `src/http/server.rs`, `src/app_server/granian.rs`
- **Problem:** Granian supervisor exists but requests not forwarded
- **Fix:** Add `forward_request()` method, dispatch in request handler
- **Effort:** 0.5 days

**3C.4 Location-Level Backend Routing** (plan_plugins2 3.1)
- **Files:** `src/router.rs`
- **Problem:** Location-level backends ignored
- **Fix:** Enhance `route_to_target()` to check location backends
- **Effort:** 0.5 days

### Wave 3D: Serverless Functions

**3D.1 Serverless Configuration & ABI** (plan_serverless Phase 1, plan_wasm3 Phase 4)
- **Files:** `src/config/serverless.rs` (new), `src/plugin/wasm_runtime.rs`
- **Fix:** Add `ServerlessConfig`, `FunctionDefinition`, `handle_request` WASM ABI
- **Effort:** 1-2 days

**3D.2 Serverless Instance Pool** (plan_serverless Phase 2)
- **Files:** `src/serverless/instance_pool.rs` (new)
- **Fix:** Pre-warmed instance pool with min/max instances, idle eviction, autoscaler
- **Effort:** 2-3 days

**3D.3 Serverless HTTP Integration** (plan_serverless Phase 3)
- **Files:** `src/http/server.rs`, `src/serverless/manager.rs`
- **Fix:** Add `handle_serverless_function()` dispatch, initialize manager in worker
- **Effort:** 1 day

**3D.4 Deno Runtime** (plan_serverless2 Phase 3)
- **Files:** `src/plugin/deno_runtime.rs` (new), `src/plugin/deno_pool.rs` (new)
- **Fix:** V8 isolate pool with warm instances, JS guest interface, sandbox constraints
- **Effort:** 3 days

**3D.5 Native Runtime** (plan_serverless2 Phase 4)
- **Files:** `src/plugin/native_serverless.rs` (new)
- **Fix:** Shared library FFI loader with ABI validation
- **Effort:** 1 day

### Wave 3E: Mesh & DHT Hardening

**3E.1 Implement TOFU Certificate Pinning for Seed Nodes** (plan_mesh3 2.1)
- **Files:** `src/mesh/discovery.rs`, `src/mesh/config.rs`
- **Fix:** Store seed cert fingerprint on first connection, verify on subsequent connections
- **Effort:** 1 day

**3E.2 Enforce MeshCapabilities** (plan_mesh3 3.1-3.2)
- **Files:** `src/mesh/transport_routing.rs`, `src/mesh/protocol.rs`
- **Problem:** `can_route` and `can_proxy` are advisory only
- **Fix:** Enforce in route handling, remove unused `can_proxy`
- **Effort:** 0.5 days

**3E.3 Gate DNS Server on Global Role** (plan_mesh3 3.3)
- **Files:** `src/server/mod.rs`
- **Fix:** Refuse DNS server startup for non-global mesh nodes
- **Effort:** 0.25 days

**3E.4 Fix All 17 Exact Role Comparisons** (plan_mesh3 3.4)
- **Files:** Multiple (see plan_mesh3 3.4 table)
- **Problem:** `== MeshNodeRole::Global` rejects composite roles
- **Fix:** Replace all with `is_global()` / `!is_global()`
- **Effort:** 0.5 days

**3E.5 Add Network Partition Detection** (plan_mesh3 5.1)
- **Files:** `src/mesh/topology.rs:1671`, `src/mesh/transport.rs`
- **Problem:** `check_network_partition()` exists but never called
- **Fix:** Wire into maintenance loop
- **Effort:** 0.5 days

### Wave 3F: Honeypot & Threat Intel Features

**3F.1 Add Multi-Hop Threat Gossip** (plan_honeypot2 1.3)
- **Files:** `src/mesh/protocol.rs`, `src/mesh/threat_intel.rs`
- **Problem:** `ThreatAnnounce` is one-hop only
- **Fix:** Add hop-count and seen-node tracking, re-broadcast with limits
- **Effort:** 1 day

**3F.2 Sign Honeypot Indicators** (plan_honeypot2 1.4, plan_honeypot3 3.2)
- **Files:** `src/mesh/threat_intel.rs:306-307`
- **Problem:** Indicators created with empty signature
- **Fix:** Sign individual indicators when signer available
- **Effort:** 0.5 days

**3F.3 Bridge Threat Intelligence with DHT** (plan_honeypot2 Phase 3)
- **Files:** `src/mesh/dht/keys.rs`, `src/mesh/threat_intel.rs`
- **Fix:** Add `DhtKey::ThreatIndicator`, dual-path publishing (fast + persistent)
- **Effort:** 1-2 days

**3F.4 Add Standalone Honeypot Config** (plan_honeypot3 2.1)
- **Files:** `src/config/main.rs`, new `src/config/honeypot_port.rs`
- **Fix:** Add `[honeypot_port]` config section, standalone initialization path
- **Effort:** 0.5 days

### Wave 3G: YARA & Upload Security

**3G.1 Add Periodic YARA Sync Task** (plan_yara2 H2, plan_yara3 1.3)
- **Files:** `src/worker/unified_server.rs`
- **Problem:** `sync_interval_secs` configured but no background task
- **Fix:** Spawn periodic sync task targeting global nodes
- **Effort:** 0.5 days

**3G.2 Add Signature Verification to Mesh-Distributed Rules** (plan_yara2 H1, plan_yara3 3.1)
- **Files:** `src/mesh/yara_rules.rs:505-533`
- **Problem:** `signature`/`signer_public_key` fields ignored
- **Fix:** Verify Ed25519 signatures before applying rules
- **Effort:** 1 day

**3G.3 Enforce YARA Scan Timeout** (plan_yara2 H3, plan_yara3 3.2)
- **Files:** `src/upload/yara_scanner.rs`
- **Problem:** `yara_timeout_ms` configured but never enforced
- **Fix:** Wrap scanning in `tokio::time::timeout` + `spawn_blocking`
- **Effort:** 0.5 days

**3G.4 Connect MalwareScanner to UploadValidator** (plan_yara2 H4, plan_yara3 3.3)
- **Files:** `src/upload/mod.rs`, `src/upload/malware_scanner.rs`
- **Problem:** Native detectors bypassed
- **Fix:** Use `MalwareScanner::with_yara()` as single entry point
- **Effort:** 0.5 days

**3G.5 Insert Upload Validation Into Request Pipeline** (plan_yara2 2.2, plan_yara3 2.2)
- **Files:** `src/tls/server.rs`, `src/upload/mod.rs`
- **Fix:** Detect upload content types, route through `UploadValidator`
- **Effort:** 1-2 days

### Wave 3H: TLS Post-Quantum Hardening

**3H.1 Wire Up `prefer_post_quantum` Config** (plan_tls2 Phase 2)
- **Files:** `src/tls/cert_resolver.rs:213-272`
- **Problem:** Config field defined but ignored
- **Fix:** Log PQ preference status, emit metrics counter
- **Effort:** 0.25 days

**3H.2 Verify PQ at Startup** (plan_tls2 Phase 3)
- **Files:** `src/tls/server.rs`, `src/http_client/mod.rs`, `src/tunnel/quic/tls.rs`
- **Fix:** Add PQ verification log to all TLS paths
- **Effort:** 0.5 days

**3H.3 Implement Key Strength Validation** (plan_tls2 Phase 5)
- **Files:** `src/tls/cert_resolver.rs:125-170`
- **Problem:** `validate_key_strength()` is no-op
- **Fix:** Inspect certificate public key algorithm and bit length
- **Effort:** 0.5 days

### Wave 3I: Edge Node Caching & Image Poison

**3I.1 Register DHT Key Types for Transforms** (plan_cache2 1.1-1.6)
- **Files:** `src/mesh/dht/keys.rs`
- **Fix:** Add `UpstreamImageProtection`, `UpstreamCompression`, `UpstreamMinification` variants
- **Effort:** 0.5 days

**3I.2 Origin Publishes Transform Configs to DHT** (plan_cache2 Phase 2)
- **Files:** `src/mesh/transport.rs`
- **Fix:** Add `publish_upstream_transform_configs()`, call from announce/init/reload
- **Effort:** 1 day

**3I.3 Non-Mesh Fallback in HTTP Server** (plan_cache2 Phase 3)
- **Files:** `src/http/server.rs:1215-1349`
- **Problem:** Entire transform block gated behind `mesh_transport.is_some()`
- **Fix:** Add else branch using `SiteImagePoisonConfig` directly
- **Effort:** 0.5 days

**3I.4 Fix Whitelist Semantics** (plan_cache2 Phase 4)
- **Files:** `src/mesh/proxy.rs:1101-1111`
- **Problem:** Matches against `upstream_id` instead of request path
- **Fix:** Change to match against `request_path`
- **Effort:** 0.25 days

---

## Wave 4: Code Quality & Cleanup (P2)

### Wave 4A: Dead Code Removal

**4A.1 Delete Orphaned DNS Files** (plan_dns3 2.1, plan_dns4 5.1)
- **Files:** `src/dns/dnssec_handler.rs` (446 lines, never compiled)
- **Effort:** 0.25 days

**4A.2 Remove Dead `HoneypotThreatPublisher`** (plan_honeypot2 1.6, plan_honeypot3 3.1)
- **Files:** `src/honeypot_port/threat_intel.rs:254-293`
- **Effort:** 0.25 days

**4A.3 Remove Dead DHT YARA Keys** (plan_yara3 4.3)
- **Files:** `src/mesh/dht/keys.rs`, `src/mesh/dht/signed.rs`
- **Effort:** 0.25 days

**4A.4 Remove Redundant Target Structs** (plan_wasm2 1.4)
- **Files:** `src/router.rs:65-100` (5 unused structs)
- **Effort:** 0.25 days

**4A.5 Delete `build_dnssec_response()` Dead Copies** (plan_dns3 1.5)
- **Files:** `src/dns/server/dnssec_impl.rs:562`, `src/dns/dnssec_handler.rs:396`
- **Effort:** 0.25 days

**4A.6 Remove Dead `sign_record()` Function** (plan5 5.6, plan_dns4 5.2)
- **Files:** `src/dns/dnssec_signing.rs:286-301`
- **Problem:** Signs empty RDATA
- **Effort:** 0.25 days

### Wave 4B: Code Deduplication

**4B.1 Deduplicate `is_newer_version()`** (plan_yara2 M1, plan_yara3 4.1)
- **Files:** `src/mesh/yara_rules.rs:478`, `src/upload/yara_rule_feed.rs`
- **Fix:** Extract to `src/utils.rs`
- **Effort:** 0.25 days

**4B.2 Replace Custom `base64_decode`** (plan_yara2 M2, plan_yara3 4.2)
- **Files:** `src/upload/yara_rule_feed.rs:404-446`
- **Fix:** Use `base64` crate (already a dependency)
- **Effort:** 0.25 days

**4B.3 Deduplicate Hop-by-Hop Header Infrastructure** (plan3 3.4)
- **Files:** `src/proxy.rs:31-84`
- **Problem:** Three derived sets from same source
- **Fix:** Merge into single lazy init tuple
- **Effort:** 0.25 days

**4B.4 Deduplicate `get_cache_max_age` Methods** (plan3 4.1, plan5 9.9)
- **Files:** `src/proxy.rs:1001-1037, 1123-1158`
- **Problem:** Near-identical functions (~55 lines duplicated)
- **Fix:** Extract shared helper
- **Effort:** 0.25 days

**4B.5 Consolidate Duplicate `WARNED_UNSIGNED` Statics** (plan5 8.7)
- **Files:** `src/process/ipc_transport.rs:332,378,408`
- **Fix:** Use single `OnceLock<()>`
- **Effort:** 0.25 days

### Wave 4C: Module-Level Suppression Cleanup

**4C.1 Remove Module-Level Allow Suppressions** (plan5 9.1)
- **Files:** `src/waf/probe_tracker.rs:1`, `src/tls/server.rs:1`, `src/mesh/config.rs:1`, `src/admin/handlers/common.rs:1`
- **Effort:** 0.5 days

**4C.2 Clean Up `#[allow(dead_code)]` Annotations** (plan2 Phase 3)
- **Files:** ~70 files, ~83 annotations
- **Target:** Reduce to <60
- **Effort:** 2-3 days

### Wave 4D: Upload Security Enhancements

**4D.1 Add Filename Validation** (plan_yara2 M3, plan_yara3 5.1)
- **Files:** `src/upload/mod.rs`
- **Fix:** Reject null bytes, path traversal, reserved names, empty filenames
- **Effort:** 0.5 days

**4D.2 Add Content-Disposition Header Parsing** (plan_yara2 M4, plan_yara3 5.2)
- **Files:** `src/upload/mod.rs`
- **Fix:** Parse and validate filename from multipart headers
- **Effort:** 0.5 days

**4D.3 Pre-Compile Image Protection Regexes** (plan_waf4 5.4)
- **Files:** `src/http/server.rs:1277`
- **Problem:** Regex compiled per-request
- **Fix:** Compile once at config load
- **Effort:** 0.25 days

**4D.4 Pre-Clean Domains at Config Load** (plan_waf4 5.3)
- **Files:** `src/router.rs:540-555`
- **Problem:** `clean_domain()` allocates per request
- **Fix:** Clean and cache at config load time
- **Effort:** 0.5 days

### Wave 4E: Miscellaneous Fixes

**4E.1 Fix `is_retryable_status` Default Behavior** (plan5 M10)
- **Files:** `src/proxy.rs:1284-1289`
- **Problem:** Returns false with empty config
- **Fix:** Default to retry 502, 503, 504
- **Effort:** 0.25 days

**4E.2 Validate X-Forwarded-For Against Trusted Proxies** (plan5 M11)
- **Files:** `src/proxy.rs:1520-1530`
- **Problem:** Accepts untrusted client input
- **Fix:** Only trust from known proxy IPs
- **Effort:** 0.5 days

**4E.3 Clear Only Domain-Specific ACME Challenges** (plan5 M13)
- **Files:** `src/tls/acme.rs:279`
- **Problem:** Clears ALL domain challenges on issuance
- **Fix:** `retain(|domain, _| domain != &completed_domain)`
- **Effort:** 0.25 days

**4E.4 Fix `AnnounceAction::from_u8` Unknown Fallback** (plan5 7.3)
- **Files:** `src/mesh/protocol_types.rs:396-405`
- **Problem:** Defaults to `Add` for unknown values
- **Fix:** Return error for unknown values
- **Effort:** 0.25 days

**4E.5 Fix `RouteQueryResult::is_expired` Logic** (plan5 7.4)
- **Files:** `src/mesh/protocol_types.rs:408-411`
- **Problem:** Uses `all` instead of `any`
- **Fix:** Expired if ANY provider has expired
- **Effort:** 0.25 days

**4E.6 Fix `encode_with_length` Error Handling** (plan5 7.5)
- **Files:** `src/mesh/protocol_message.rs:117-124`
- **Problem:** Silently returns empty Vec on error
- **Fix:** Propagate encoding errors
- **Effort:** 0.25 days

**4E.7 Add Size Limit to `pending_announces` Vec** (plan5 7.8)
- **Files:** `src/mesh/dht/record_store.rs:79`
- **Fix:** Add max capacity, drop oldest when full
- **Effort:** 0.25 days

**4E.8 Fix `handle_minify_client_connection` Thread-per-Connection** (plan5 9.10)
- **Files:** `src/worker/mod.rs:487-506`
- **Problem:** `std::thread::spawn` per connection
- **Fix:** Use tokio task or thread pool
- **Effort:** 0.25 days

**4E.9 Fix `run_worker` 100ms Poll Interval** (plan5 9.11)
- **Files:** `src/worker/mod.rs:322-328`
- **Problem:** Polls every 100ms
- **Fix:** Use `tokio::select!` with shutdown channel
- **Effort:** 0.25 days

**4E.10 Fix Token Bucket Sub-Second Granularity** (plan5 9.12)
- **Files:** `src/process/ipc_rate_limit.rs:130-138`
- **Fix:** Use sub-second precision for token refill
- **Effort:** 0.25 days

---

## Wave 5: Documentation & Testing (P2)

### Wave 5A: Documentation

**5A.1 Update AGENTS.md** (plan3 4.2, plan4 6.1)
- **Fix:** Remove stale references, update module sizes, verify current state
- **Effort:** 0.5 days

**5A.2 Fix Documentation ABI Mismatch** (plan_wasm3 7.1)
- **Files:** `docs/PLUGINS.md`
- **Problem:** Describes completely different config format and ABI
- **Fix:** Rewrite to match actual implementation
- **Effort:** 0.5 days

**5A.3 Add Serverless Documentation** (plan_wasm3 7.2-7.5)
- **Files:** `docs/SERVERLESS.md` (new), `docs/WASM-ABI.md` (new)
- **Effort:** 0.5 days

**5A.4 Generate Config Schema from Struct** (plan5 6.1)
- **Files:** `src/admin/handlers/config.rs:65-983`
- **Problem:** 920-line hardcoded schema
- **Fix:** Use `schemars` or `utoipa` derive-based approach
- **Effort:** 1-2 days

### Wave 5B: Testing

**5B.1 Add Missing Integration Tests**
- WAF body inspection through proxy path
- DNSSEC signed zone validation
- Mesh threat propagation end-to-end
- Upload scanning end-to-end
- Serverless function invocation
- **Effort:** 2-3 days

**5B.2 Add Benchmarks**
- WAF check latency breakdown
- DNS cache performance
- WASM filter pooled vs fresh
- Broadcast latency at scale
- **Effort:** 1-2 days

**5B.3 Add Unit Tests for Critical Fixes**
- Atomic counter safety
- Thread-local → OnceLock migration
- Signature verification paths
- **Effort:** 1-2 days

---

## Parallelization Strategy

### Wave Execution Model

```
Wave 0 (Critical) ──────────────────────────────────────────────────────────────
  ├── 0A: WAF/Proxy Critical    ── Agent A
  ├── 0B: DNSSEC Wire Format    ── Agent B
  ├── 0C: Mesh Trust Model      ── Agent C
  ├── 0D: Domain Verification   ── Agent D
  └── 0E: NoVerifier/TLS        ── Agent E

Wave 1 (High Security) ─────────────────────────────────────────────────────────
  ├── 1A: WAF/Proxy Security    ── Agent A
  ├── 1B: DNS Response Correct  ── Agent B
  ├── 1C: Admin/Config Security ── Agent C
  ├── 1D: Mesh/DHT Security     ── Agent D
  ├── 1E: Honeypot/Threat Intel ── Agent E
  ├── 1F: YARA Mesh Distribution ── Agent F
  └── 1G: IPC/Process Mgmt      ── Agent G

Wave 2 (Performance) ───────────────────────────────────────────────────────────
  ├── 2A: WAF Hot-Path          ── Agent A
  ├── 2B: DNS Scalability       ── Agent B
  ├── 2C: Mesh/Transport Perf   ── Agent C
  ├── 2D: Proxy/Cache Perf      ── Agent D
  └── 2E: Rate Limiter Opt      ── Agent E

Wave 3 (Features) ──────────────────────────────────────────────────────────────
  ├── 3A: Multi-Worker Scaling  ── Agent A
  ├── 3B: WASM Plugin Improv    ── Agent B
  ├── 3C: Backend Dispatch      ── Agent C
  ├── 3D: Serverless Functions  ── Agent D
  ├── 3E: Mesh/DHT Hardening    ── Agent E
  ├── 3F: Honeypot Features     ── Agent F
  ├── 3G: YARA/Upload Security  ── Agent G
  ├── 3H: TLS PQ Hardening      ── Agent H
  └── 3I: Edge Caching/Image    ── Agent I

Wave 4 (Code Quality) ──────────────────────────────────────────────────────────
  ├── 4A: Dead Code Removal     ── Agent A
  ├── 4B: Code Deduplication    ── Agent B
  ├── 4C: Module Suppressions   ── Agent C
  ├── 4D: Upload Security Enh   ── Agent D
  └── 4E: Miscellaneous Fixes   ── Agent E

Wave 5 (Docs & Testing) ────────────────────────────────────────────────────────
  ├── 5A: Documentation         ── Agent A
  ├── 5B: Integration Tests     ── Agent B
  └── 5C: Benchmarks/Unit Tests ── Agent C
```

### Cross-Wave Dependencies

| Wave | Depends On | Notes |
|------|-----------|-------|
| Wave 1 | Wave 0 complete | All critical security fixes must land first |
| Wave 2 | Wave 0 (partial) | Performance items don't block on Wave 1 |
| Wave 3 | Wave 2 (partial) | Features can start once critical paths are stable |
| Wave 4 | None | Code quality can run in parallel with any wave |
| Wave 5 | Wave 4 | Documentation depends on final code state |

### Recommended Execution Order

1. **Wave 0** (all sub-waves parallel) — 8-12 days wall-clock
2. **Wave 1** (all sub-waves parallel) — 10-15 days wall-clock
3. **Wave 2 + Wave 4** (parallel) — 8-12 days wall-clock
4. **Wave 3** (all sub-waves parallel) — 15-25 days wall-clock
5. **Wave 5** (all sub-waves parallel) — 3-5 days wall-clock

**Total with parallelization: ~44-69 days → 20-35 days with 5-9 agents**

---

## Testing Strategy

| Wave | Test Type | Validation |
|------|-----------|------------|
| 0 | Integration + Manual | WAF blocks body attacks, DNSSEC validates, mesh auth enforced |
| 1 | Integration | CSRF enforced, trust anchors persist, threat intel propagates |
| 2 | Benchmark | QPS/latency improvement, lock contention reduced |
| 3 | Integration + E2E | Multi-worker scaling, serverless invocation, upload scanning |
| 4 | Clippy | No dead code warnings, no module-level suppressions |
| 5 | Full Suite | `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` |

### Verification Commands

After implementing each wave:

```bash
# Compile check
cargo check

# Test compilation (includes #[cfg(test)] code)
cargo test --lib --no-run

# Run relevant tests
cargo test --test integration_test
cargo test --test dns_integration_test  # DNS waves
cargo test --test ipc_test              # IPC items

# Full test suite
cargo test

# Lint and format
cargo fmt --check && cargo clippy -- -D warnings
```

---

## Risk Mitigation

| Risk | Wave | Mitigation |
|------|------|------------|
| DNSSEC wire format fix breaks existing signatures | 0B | All existing signatures already invalid (64-bit timestamps) |
| Thread-local removal breaks callers | 0A | Use `OnceLock` for global access, same function signatures |
| Mesh trust model changes break existing deployments | 0C | Global nodes already set `global_node_key`; edge nodes don't claim global |
| Domain verification rejects legitimate registrations | 0D | Add `verification_bypass: true` config flag for staged rollout |
| Cache replacement breaks TTL/serve-stale | 2B | Run full test suite, verify serve-stale still works |
| Serverless instance pool memory pressure | 3D | Configurable `max_instances`, idle eviction |
| Multi-worker introduces race conditions | 3A | Extensive integration testing with SO_REUSEPORT |
| Breaking changes to `MeshMessage::ThreatAnnounce` | 3F | Add new fields with defaults, backward-compatible deserialization |

---

## Success Criteria

- [x] All critical security bypasses closed (Wave 0)
- [ ] All high-severity correctness issues fixed (Wave 1)
- [ ] Performance hot paths optimized with measurable improvement (Wave 2)
- [ ] Feature additions complete with tests (Wave 3)
- [ ] Dead code reduced, clippy clean, no module-level suppressions (Wave 4)
- [ ] Documentation accurate, integration tests pass (Wave 5)
- [x] `cargo test` passes
- [x] `cargo clippy -- -D warnings` passes
- [x] `cargo fmt --check` passes

---

## Relationship to Prior Plans

This consolidated plan replaces the following individual plans:

| Original Plan | Status | Mapped To |
|--------------|--------|-----------|
| `plan2.md` | Merged | Wave 0A, 2A, 4B, 4C |
| `plan3.md` | Merged | Wave 0A, 1A, 2A, 2D, 4B |
| `plan4.md` | Merged | Wave 1C, 3D, 4A, 5A |
| `plan5.md` | Merged | All waves (comprehensive) |
| `plan_dns1.md` | Merged | Wave 2B |
| `plan_dns2.md` | Merged | Wave 2B, 3E |
| `plan_dns3.md` | Merged | Wave 0B, 1B, 2B, 4A |
| `plan_dns4.md` | Merged | Wave 0B, 0D, 1B, 1D, 2B, 4A |
| `plan_honeypot2.md` | Merged | Wave 1E, 3F |
| `plan_honeypot3.md` | Merged | Wave 1E, 3F |
| `plan_mesh3.md` | Merged | Wave 0C, 1D, 3E |
| `plan_mesh4.md` | Merged | Wave 0C, 3E |
| `plan_plugins.md` | Merged | Wave 3C, 3D |
| `plan_plugins2.md` | Merged | Wave 3C |
| `plan_serverless.md` | Merged | Wave 3D |
| `plan_serverless2.md` | Merged | Wave 3D |
| `plan_tls2.md` | Merged | Wave 0E, 3H |
| `plan_waf1.md` | Merged | Wave 2A, 2D, 2E |
| `plan_waf2.md` | Merged | Wave 0A, 2A, 2E |
| `plan_waf3.md` | Merged | Wave 2D, 3A |
| `plan_waf4.md` | Merged | Wave 0A, 2A, 2C, 2D |
| `plan_wasm2.md` | Merged | Wave 3B, 3C, 3D |
| `plan_wasm3.md` | Merged | Wave 3B, 3D |
| `plan_yara2.md` | Merged | Wave 1F, 3G |
| `plan_yara3.md` | Merged | Wave 1F, 3G, 4D |
| `plan_cache2.md` | Merged | Wave 3I |
| `plan_cache3.md` | Merged | Wave 3I |
| `deferred.md` | Merged | Wave 1C, 3B, 3E |

All items from the original plans have been reviewed, deduplicated, and incorporated into this consolidated plan. Items that overlap across multiple plans have been merged into single entries with cross-references.

---

## Notes

- **2026-03-31**: Wave 1 completed - High-priority security and correctness fixes:
  - 1A.1: Fixed SSRF octal/decimal IP bypass with parse_ipv4_flexible()
  - 1A.2: Fixed path traversal in sanitize_request_path with proper .. handling
  - 1A.3: Fixed is_trusted() to only return true for Valid state (not Pending)
  - 1B.4: Fixed build_forward_headers now called in TLS server proxy path
  - 1C.1: Added CSRF middleware with token validation
  - 1C.4: Added reload and broadcast after import_config
  - 1C.5: Skip worker broadcast on partial reload failure
  - 1D.4: Increased PoW difficulty from 16 to 24 bits
  - 1D.5: Added PoW verification to try_insert
  - 1G.1: Fixed ConnectionPermit::Drop underflow with fetch_update

- **2026-03-31**: Wave 0 completed - All critical security fixes implemented:
  - 0A.2: Removed dead code `check_waf()` from proxy.rs
  - 0A.4: Whitelist already at position 1 (no change needed)
  - 0C.1: Global node auth enforced via `role.is_global()` checks (already in place)
  - 0C.3: Hard-fail on missing public_key in node ID verification
  - 0C.4: Added `enforce_mutual_tls` parameter to QUIC mesh server config
  - 0E.2: NoVerifier now logs per-connection and validates certificate chain
  - 0E.3: PBKDF2 now uses random 16-byte salt
  - 0C.2: gRPC key exchange proxies to origin node via mesh
  - 0D.1: Domain verification uses real DNS TXT lookups, rejects unsigned challenges
  - 0D.2: Mesh certificate verification uses proper X.509 chain validation

- This plan is organized by **priority and dependency**, not by domain. Critical security fixes come first regardless of which subsystem they affect.
- Each wave is designed to be **independently testable** — you can run the full test suite after any wave.
- **Parallelization is the key to reducing wall-clock time.** With 5-9 sub-agents, the total effort can be reduced from 49-77 days to 20-35 days.
- The `AGENTS.md` file should be updated as waves are completed, particularly the "Known Bugs" and "Architecture Pattern" sections.
- Items marked as "Deferred" in the original `deferred.md` have been incorporated into the appropriate waves with their original priority preserved.
