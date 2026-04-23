# MaluWAF Improvement Plan - Deep Dive Review

**Last updated**: 2026-04-23
**Status**: PLANNING (Not Started)

---

## Overview

This document consolidates findings from a comprehensive codebase review and identifies areas for improvement. Based on the deep dive analysis, each major subsystem has been examined for code quality, architecture, performance, and enhancement opportunities.

### Recent Security Fixes (Already Completed in plan.md)

Recent work has already addressed several security issues:

| Security Fix | Status |
|--------------|--------|
| DHT Record Signature Requirement | ✅ Complete |
| Health Check Timestamp Validation | ✅ Complete |
| ACME Challenge HMAC Verification | ✅ Complete |
| Edge Node PoW Required | ✅ Complete |
| PID Mismatch Rejection | ✅ Complete |
| DHT Announce Record Limit | ✅ Complete |
| DHT get_by_prefix Pagination | ✅ Complete |

These are already implemented and documented in `plans/plan.md`.

---

## 1. WAF Core - Attack Detection

### Current State

The WAF implements 13+ attack detection types using libinjection and pattern matching:

| Detection Type | File | Method |
|----------------|------|--------|
| SQL Injection | `src/waf/attack_detection/sqli.rs` | libinjection |
| XSS | `src/waf/attack_detection/xss.rs` | libinjection |
| SSRF | `src/waf/attack_detection/ssrf.rs` | URL validation |
| Path Traversal | `src/waf/attack_detection/path_traversal.rs` | Pattern matching |
| Command Injection | `src/waf/attack_detection/cmd_injection.rs` | Pattern matching |
| Request Smuggling | `src/waf/attack_detection/smuggling.rs` | HTTP parsing |
| SSTI | `src/waf/attack_detection/ssti.rs` | Template injection |
| RFI | `src/waf/attack_detection/rfi.rs` | Pattern matching |
| XXE | `src/waf/attack_detection/xxe.rs` | XML parsing |
| LDAP Injection | `src/waf/attack_detection/ldap.rs` | Pattern matching |
| XPath | `src/waf/attack_detection/xpath.rs` | Pattern matching |
| Open Redirect | `src/waf/attack_detection/open_redirect.rs` | Validation |

### Hot Path Performance

The WAF runs 20+ checks per request in sequential chain (`src/waf/mod.rs:921-988`):
```
check_request_full:
├── Whitelist → Threat level → ASN tracker → Rate limit
├── IP feed → DHT threat → Endpoint block → Suspicious words
├── Honeypot → Bot protection → Attack pattern (12+ detectors)
└── Challenge check
```

### Findings & Potential Improvements

| Area | Current | Potential Improvement |
|------|---------|---------------------|
| **Rule Engine** | Embedded rule feeds | External rule sources, live updates from mesh |
| **Detection Patterns** | libinjection + regex | ML-based anomaly detection? |
| **Rate Limiting** | In-memory atomic | Distributed rate limiting across mesh |
| **Bot Detection** | CSS/JS challenges | Browser fingerprinting integration |
| **Threat Intel** | Per-IP blocking | Per-session, per-account blocking |

### Implementation Considerations

1. **External Rule Feeds**: Currently rules are embedded. Could integrate with:
   - OWASP ModSecurity Core Rule Set (CRS)
   - Community-contributed rule feeds via mesh DHT
   - Commercial threat intel APIs

2. **Distributed Rate Limiting**: Current in-memory limiting doesn't work across multiple WAF instances. Could implement:
   - Redis-backed rate limiting
   - Mesh-based rate limit sync (per-edge aggregation)

3. **ML-Based Detection**: Current signature-based detection can't detect novel attacks. Could add:
   - Request pattern clustering
   - Anomaly scoring with TensorFlow/ONNX

---

## 2. Mesh Network - DHT & P2P

### Current State

DHT implementation uses gossip-based approach (not full Kademlia):

| Key Pattern | Type | TTL |
|------------|------|-----|
| `verified_upstream:{id}` | VerifiedUpstream | 30 days |
| `upstream:{id}` | Upstream | 5 min |
| `threat_indicator:{ip}:{type}` | ThreatIntel | Re-announced |
| `yara_rule:{hash}` | YARARule | 24 hours |
| `yara_rules_manifest:{node}` | Manifest | 24 hours |
| `node_capability:{node}:{cap}` | Capability | 5 min |

### DHT Storage

- **Implementation**: 64-sharded `ShardedRecordStore` with DJB2 hashing
- **Persistence**: SQLite-backed store with `INSERT OR REPLACE` + atomic rename (safe for crashes)
- **Authorization**: Capability-based write via `CapabilityAccessVerifier` (yara_rules requires "waf" capability, threat_intel requires "threat_intel" capability)
- **Signature Verification**: Ed25519 signatures on YARA rules, threat indicators, and VerifiedUpstream records

### QUIC Transport

- **File**: `src/mesh/transport.rs` (3124 lines)
- **Stream Multiplexing**: Multiple sites via single QUIC connection
- **Peer Discovery**: Single-hop gossip (not recursive Kademlia)

### Findings & Potential Improvements

| Area | Current | Potential Improvement |
|------|---------|---------------------|
| **DHT Protocol** | Single-hop gossip | Full Kademlia DHT? |
| **Peer Discovery** | Centralized global nodes | Hybrid discovery |
| **Threat Intel** | Best-effort propagation | Guaranteed delivery |
| **YARA Distribution** | DHT-based | HTTP-based bulk transfer |
| **Upstream Routing** | Domain-based | Geo-aware routing |

### Implementation Considerations

1. **Full Kademlia DHT**: Current single-hop gossip limits scalability. Could implement:
   - Recursive Kademlia routing
   - Bucket-based peer management
   - Parallel lookups

2. **Geo-Aware Routing**: Currently upstream selection is random weighted. Could add:
   - MaxMindDB integration for client geoIP
   - Latency-based upstream selection
   - Geographic diversity scoring

---

## 3. DNS/DNSSEC - Server & Validation

### Current State

DNS server with full DNSSEC support:

| Component | File |
|-----------|------|
| Query handling | `src/dns/server/query.rs` |
| Zone storage | `src/dns/server/sharded_store.rs` |
| DNSSEC signing | `src/dns/server/dnssec_impl.rs` |
| Trust anchors | `src/dns/trust_anchor.rs` (RFC 5011) |

### Providers

- **Recursive** (with DNSSEC validation)
- **Google** (forwarding)
- **Cloudflare** (forwarding)
- **System** (system resolver)
- **Custom** (custom upstream IPs)

### DoH/DoQ

- **DoH**: `src/dns/doh.rs`
- **DoQ**: `src/dns/doq.rs`

### Findings & Potential Improvements

| Area | Current | Potential Improvement |
|------|---------|---------------------|
| **Zone Storage** | In-memory + SQLite | Database-backed (PostgreSQL)? |
| **DNSSEC** | Manual key management | Automated KSK rollover |
| **Anycast** | Basic implementation | Full anycast with health checking |
| **Resolver** | Single instance | Distributed resolver cluster |

### Implementation Considerations

1. **Database Zone Storage**: Current in-memory + SQLite limits complex zone operations. Could migrate to:
   - PostgreSQL for zone data
   - Redis for hot cache
   - MySQL for zone transfers

2. **DNSSEC Automation**: Current manual key rollover. Could implement:
   - Automated ZSK rollover (daily)
   - Automated KSK rollover (quarterly)
   - Key ceremony scheduling

---

## 4. Process Architecture - Multi-Process Model

### Current State

Overseer → Master → Worker model:

| Process | File | Role |
|----------|------|------|
| **Overseer** | `src/overseer/` | Lifecycle, upgrades, health |
| **Master** | `src/master/` | Worker spawning, config |
| **Worker** | `src/worker/` | UnifiedServer, HTTP handling |

### IPC System

- **Message enum**: `src/process/ipc.rs` (1884 lines)
- **Transport**: Unix domain sockets
- **Framing**: Custom message framing

### Findings & Potential Improvements

| Area | Current | Potential Improvement |
|------|---------|---------------------|
| **IPC** | Unix sockets | Shared memory for large data |
| **Process Model** | Static worker count | Dynamic scaling |
| **Health Monitoring** | Basic heartbeat | Detailed metrics |
| **Rolling Updates** | Socket handoff | Live migration |

### Implementation Considerations

1. **Shared Memory IPC**: Current socket-based IPC has overhead. Could use:
   - `unix.socket` with `SCM_RIGHTS` for zero-copy
   - Shared memory rings for large payloads
   - Memory-mapped files for bulk transfer

2. **Dynamic Worker Scaling**: Current static worker count. Could implement:
   - CPU-based scaling
   - Request-based scaling
   - Latency-based autoscaling

---

## 5. HTTP/TLS Server - Request Pipeline

### Current State

15-phase request pipeline (`src/http/server.rs`):

```
1. Connection management
2. IP extraction (X-Forwarded-For)
3. Internal endpoints
4. Mesh key exchange
5. Connection limiting
6. Bandwidth limiting
7. WebSocket upgrade
8. Request parsing
9. WAF early decision
10. Body collection
11. Honeypot/challenge
12. Routing & site resolution
13. WAF full check
14. WAF decision
15. Backend dispatch
```

### TLS/ACME

- **TLS**: rustls-native-certs
- **ACME**: instant-acme for Let's Encrypt
- **HTTP/3**: QUIC-based

### Findings & Potential Improvements

| Area | Current | Potential Improvement |
|------|---------|---------------------|
| **HTTP/2** | Basic support | Full multiplex debugging |
| **HTTP/3** | QUIC 0-RTT | 0-RTT state management |
| **TLS 1.3** | Post-quantum optional | Hybrid PQ classical |
| **ACME** | HTTP-01 fully integrated | DNS-01 feature-gated, full DNS-01 for wildcard certs |

### Implementation Considerations

1. **HTTP/2 Debugging**: Current limited HTTP/2 multiplexing visibility. Could add:
   - Stream state tracking
   - Window management metrics
   - Priority frame handling

2. **Hybrid PQ/Classical TLS**: Current optional PQ. Could mandate:
   - X25519Kyber768Draft00 as default
   - Classical fallback for compatibility

3. **DNS-01 ACME**: Currently feature-gated behind `dns` feature. Already works for zones configured in MaluWAF. Enhancement would be external DNS provider integration (Route53, Cloudflare API).

---

## 6. Proxy/Caching - Reverse Proxy

### Current State

| Module | File | Purpose |
|--------|------|---------|
| Proxy logic | `src/proxy/mod.rs` | Main proxy |
| Headers | `src/proxy/headers.rs` | Filtering |
| Retry | `src/proxy/retry.rs` | Retry logic |
| Upstream | `src/upstream/pool.rs` | Backend pool |
| Cache | `src/proxy_cache/` | moka-based |

### Caching Features

- **Backend**: moka::Cache (O(1) lookups)
- **TTL**: Configurable per-site
- **Stale-while-revalidate**: Supported

### Findings & Potential Improvements

| Area | Current | Potential Improvement |
|------|---------|---------------------|
| **Cache Backend** | In-memory (moka) | Redis distributed cache |
| **Upstream Selection** | Weighted random | Least connections, least latency |
| **Retry Strategy** | Simple backoff | Exponential with jitter |
| **Connection Pool** | Per-site | Per-origin pooling |

### Implementation Considerations

1. **Redis Cache**: Current in-memory caching doesn't share across workers. Could add:
   - Redis-backed response cache
   - Varnish-style ESI support
   - Cache tag-based invalidation

2. **Advanced Upstream Selection**: Current weighted random. Could implement:
   - Least connections algorithm
   - Least latency (active health + RTT)
   - IP hash (session affinity)

---

## 7. Performance - 500K+ RPS Target

### Current Optimizations

| Area | File | Optimization |
|------|------|--------------|
| WAF detection | `src/waf/mod.rs` | Hash lookups (O(1)) |
| Cache | `src/proxy_cache/` | moka::Cache |
| Rate limiting | `src/waf/ratelimit/` | Lock-free atoms |
| Input normalization | `src/waf/probe_tracker.rs` | Pre-computed |
| Buffer management | `src/buffer/` | Zero-copy pools |

### Findings & Potential Improvements

| Area | Current | Potential Improvement |
|------|---------|---------------------|
| **SIMD** | Not used | Accelerate detection |
| **Allocator** | System allocator | Custom pool allocator |
| **Lock-Free** | Atomic, RwLock | seqlock, RCU |
| **JIT** | Not used | Hot path JIT compilation |

### Implementation Considerations

1. **SIMD加速**: Could accelerate pattern matching with:
   - `std::arch` for hot paths
   - `regex` crate with SIMD
   - `libinjection` SIMD variants

2. **Custom Allocator**: Could reduce allocation overhead with:
   - Pool-based allocator for requests
   - Slab allocator for WAF rules
   - Bump allocator for short-lived data

---

## 8. Admin API - REST & Observability

### Current State

| Category | Count | Endpoints |
|----------|-------|----------|
| Stats | 10+ | `/api/stats/*` |
| Sites | 15+ | `/api/sites/*` |
| Config | 30+ | `/api/config/*` |
| Mesh | 15+ | `/api/mesh/*` |
| **Total** | 150+ | All categories |

### Observability

- **Metrics**: Prometheus integration
- **Logging**: Structured JSON + syslog
- **WebSocket**: Real-time feeds

### Findings & Potential Improvements

| Area | Current | Potential Improvement |
|------|---------|---------------------|
| **API Security** | Bearer token | OAuth 2.0 integration |
| **Rate Limiting** | None | Per-client API limits |
| **Metrics** | Prometheus | OpenTelemetry export |
| **Tracing** | Logs only | Distributed tracing (Jaeger) |

### Implementation Considerations

1. **OAuth 2.0 for Admin**: Could integrate:
   - Client credentials flow
   - Refresh token rotation
   - Scope-based authorization

2. **Distributed Tracing**: Current logging only. Could add:
   - OpenTelemetry integration
   - Jaeger/Zipkin export
   - Trace-based debugging

---

## 9. Test Infrastructure - Quality Assurance

### Current Tests

| Type | Location | Count |
|------|----------|-------|
| Integration | `tests/integration_test.rs` | 242+ |
| Unit | `#[cfg(test)]` in source | Varies |
| Benchmarks | `benches/bench_*.rs` | 4 |

### Running Tests

```bash
cargo test --test integration_test  # Fast (~5s)
cargo test --lib                   # Unit tests
cargo test                        # Full suite (~3-5 min)
```

### Findings & Potential Improvements

| Area | Current | Potential Improvement |
|------|---------|---------------------|
| **Coverage** | Partial | Comprehensive coverage |
| **Property Tests** | None | proptest-based |
| **Fuzzing** | libfuzzer-sys | Full corpus |
| **Load Testing** | None | k6/Locust scripts |

### Implementation Considerations

1. **Property-Based Testing**: Could add with proptest:
   - HTTP request generation
   - Response validation
   - Attack pattern fuzzing

2. **Load Testing**: Current benchmarks only. Could add:
   - k6 script for realistic load
   - Locust-based distributed testing
   - Chaos engineering (kill random workers)

---

## 10. Code Quality & Technical Debt

### Current Strengths

- **Clean compilation**: `cargo check` passes without errors
- **Clippy clean**: `cargo clippy -- -D warnings` passes
- **Test coverage**: 242+ integration tests
- **Type safety**: Strong typing throughout, uses thiserror for error enums
- **Documentation**: AGENTS.md provides developer context

### Areas for Improvement

| Area | Current | Potential Improvement |
|------|---------|---------------------|
| **Error Handling** | Mix of thiserror, anyhow, custom | Unified error strategy |
| **Configuration** | TOML parsing | Schema validation with JSON Schema |
| **Feature Flags** | Multiple features | Feature flag documentation |
| **Documentation** | AGENTS.md + docs/ | Swagger API docs |

### Implementation Considerations

1. **Feature Flag Documentation**: Currently features are defined in Cargo.toml but not documented. Could add:
   - `docs/FEATURE_FLAGS.md` with each flag purpose
   - Which features are required for specific deployments
   - Performance implications of each feature

2. **Configuration Schema**: Currently TOMLparsed directly. Could add:
   - JSON Schema for validation
   - Schema generation from code
   - Config diff/merge tooling

---

## 11. Summary - Where the Project Excels

Understanding what's already strong helps focus improvement efforts:

### Already Strong Areas

1. **Architecture**: Well-designed multi-process model with clear separation
2. **Security**: Recent security fixes (in plan.md) address critical issues
3. **Performance**: Hash-based lookups, lock-free rate limiting, moka caching
4. **Mesh Design**: Capability-based auth, signature verification, DHT limits
5. **DNSSEC**: Full RFC 5011 trust anchor implementation
6. **Testing**: 242+ integration tests, benchmarks
7. **Observability**: Prometheus metrics, structured logging

### Areas Requiring Most Attention

For multi-node WAF deployments, the highest-impact gaps are:

1. **Distributed caching** - Workers don't share cache
2. **Distributed rate limiting** - Each worker has independent limits
3. **Observability** - Distributed tracing would help debugging

These are priority items because they limit the "mesh as CDN" use case.

---

## 12. Priority Action Items

Based on the deep dive analysis, here are prioritized improvement categories:

### High Priority

| # | Area | Rationale |
|----|------|----------|
| 1 | **Distributed Rate Limiting** | Request rate is core WAF function, current in-memory model limits multi-node deployments |
| 2 | **Redis Cache Integration** | Response caching critical at scale, in-memory doesn't share across workers |
| 3 | **HTTP/2 Multiplex Visibility** | Debugging HTTP/2 issues is difficult without visibility |
| 4 | **Geo-Aware Routing** | Mesh can route based on client geography |

### Medium Priority

| # | Area | Rationale |
|----|------|----------|
| 5 | **DNSSEC Automation** | Manual key rollover risk, automation reduces operational risk |
| 6 | **Database Zone Storage** | Complex zone operations need database |
| 7 | **OAuth 2.0 Admin API** | Security improvements for multi-team deployments |
| 8 | **Distributed Tracing** | Debugging distributed systems without tracing is painful |

### Low Priority / Experimental

| # | Area | Rationale |
|----|------|----------|
| 9 | **ML-Based Detection** | Novel attack detection, high complexity |
| 10 | **Full Kademlia DHT** | Mesh scales better, but complexity is high |
| 11 | **Custom Allocator** | Performance tuning, measure first |
| 12 | **SIMD Acceleration** | Premature optimization, measure first |

---

## Estimated Effort

For planning purposes, rough estimates:

| Item | Complexity | Estimate |
|------|------------|----------|
| Distributed Rate Limiting | Medium | 2-3 weeks |
| Redis Cache Integration | Medium | 2 weeks |
| HTTP/2 Visibility | Low | 1 week |
| Geo-Aware Routing | Medium | 2 weeks |
| DNSSEC Automation | Medium | 2-3 weeks |
| Database Zone Storage | High | 3-4 weeks |
| OAuth 2.0 Admin | Medium | 2 weeks |
| Distributed Tracing | Medium | 2-3 weeks |

---

## Related Documentation

- `AGENTS.md` - Developer guide for AI agents
- `skills/malu_mesh.md` - Mesh network detailed architecture
- `docs/DNS_DNSSEC.md` - DNS and DNSSEC architecture
- `docs/DNSSEC_TRUST_ANCHOR.md` - RFC 5011 trust anchor
- `docs/THREAT_INTEL.md` - Threat intelligence documentation

---

## Next Steps

1. **Review this plan** - Identify highest-impact items
2. **Prioritize** - Select items for first implementation wave
3. **Create subtasks** - Break down into manageable units
4. **Assign** - Task subagents or developers to implement

---

## Notes

- All items are suggestions for improvement, not mandatory
- Measure before optimizing - use benchmarks to validate
- Security items should be prioritized
- Some items may have dependencies on others