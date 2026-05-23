# SynVoid Architecture Review - Implementation Plan

**Generated:** 2026-05-23
**Last Updated:** 2026-05-23 (pruned - completed items removed)
**Source:** batch1-4 consolidated reviews covering DNS, WAF, Layer 3.5, Admin API, Mesh, Process Lifecycle, Config, App Handlers, Routing, Plugin/WASM, Worker, Proxy, Platform, Networking, HTTP/Proxy, Config/Admin, Core/Overview

---

## Overview

This plan consolidates findings from 4 batches of architecture reviews across 16 modules. It has been pruned to remove all completed items.

### Summary Statistics (Remaining Items)

| Category | Count | Status |
|----------|-------|--------|
| **Completed Fixes** | 2 | MESH-14 (binding validation), MESH-15 (deadlock/sync fixes) |
| **Deferred Items** | 2 | APP-15, SUP-1 |
| **Incomplete but Working** | 7 | Known limitations |
| **High Priority (Needs Work)** | 1 | DNS Cookie Server integration |
| **Documentation Only** | 3 | Already documented, no action needed |

---

## Deferred Items (Architectural Complexity)

These items require significant architectural changes and are intentionally deferred:

| ID | Issue | Location | Reason | Status |
|----|-------|----------|--------|--------|
| MESH-14 | No Source Node ID Binding Validation in All Ingress Paths | `src/mesh/transport_peer.rs:1288-1303` | Added `validate_peer_node_id_binding()` helper and applied to 5 ingress paths | **FIXED** - 2026-05-23 |
| MESH-15 | Quorum Deadlock Risk During Partition | `src/mesh/raft/instance.rs:225-235` | RwLock deadlock was overstated (RwLock allows concurrent readers); fixed `get_last_log_index()` and inverted sync logic | **FIXED** - 2026-05-23 |
| APP-15 | FastCGI Response NOT Truly Streamed | `src/fastcgi/mod.rs:132-164` | Buffers entire stdout; true streaming requires architectural change | Deferred - Architectural |
| SUP-1 | gRPC Control Plane TLS | `src/supervisor/api.rs:114-129` | Intentional - localhost IPC doesn't need TLS | Working As Designed |

---

## Known Incomplete Items (Not Bugs)

These are known limitations documented for future agents:

| Item | Location | Issue | Notes |
|------|----------|-------|-------|
| ErasedHttpClient Phase 9 | `src/http/server.rs:3302` | `use_erased_client` hardcoded to `false` | Phase 9 integration never completed |
| HTTP/2 disabled | `src/http_client/mod.rs:890` | `is_http2 = false`, no ALPN configured | Infrastructure exists but unused |
| DNS Cookie Server | `src/dns/cookie.rs` + `src/dns/server/mod.rs` | Complete RFC 7873 implementation exists but NOT integrated | DnsServer lacks cookie_server field |
| Minification unused | `src/static_files/mod.rs:134-136` | `new_with_minifier()` accepts minifier params but silently ignores them | Struct doesn't store these fields |
| Spin instance reuse | `src/spin/runtime.rs:260` | Only `compiled_runtimes` cached, NOT `SpinAppInstance` | Per-request instantiation overhead |
| GOST DS digest | `src/dns/dnssec_validation.rs:260` | Returns error "GOST R 34.11-94 not yet supported" | Requires gost94 crate |
| BackendType not documented | `src/router.rs:65-77` | 11 variants exist but not fully documented in architecture docs | Lower priority |

---

## High Priority: DNS Cookie Server Integration

### DNS - Complete Cookie Server Integration

**Location:** `src/dns/cookie.rs` (standalone 141 lines), `src/dns/server/mod.rs`

**Status:** IMPLEMENTATION EXISTS, NOT INTEGRATED

**Issue:** `DnsCookieServer` is a complete, RFC 7873 compliant implementation:
- SHA-256 cookie generation with 8-byte cookie size
- 16-byte truncated secret (per RFC 7873 Section 5.4)
- Constant-time comparison via `subtle::ConstantTimeEq`
- LRU cache for cookie entry tracking
- `generate_server_cookie()`, `validate_cookie()`, `create_response_cookie()`, `should_require_cookie()`

However, `DnsServer` struct does NOT have a `cookie_server` field, and these methods are never called during query processing.

**Fix Required:**
1. Add `cookie_server: Arc<DnsCookieServer>` field to `DnsServer` struct
2. Instantiate in `DnsServer::new()`
3. Wire into query processing flow to generate/validate cookies

**Source:** batch1_dns_review

---

## Documentation Items (No Action Needed)

These items are already correctly documented:

| Item | Status | Verification |
|------|--------|--------------|
| GeoIP Country Blocking | Actually ASN-based | `AsnTracker` is distributed scraper detection, not country blocking - correctly documented |
| Raft Documentation | Already updated | Raft implemented in `src/mesh/raft/`, architecture docs reflect this |
| MeshProxy in Overview | PRESENT | `architecture/overview.md:209,324` - documented as key routing component |
| Missing Modules | ALL PRESENT | All 8 modules (icmp_filter, serverless, spin, wasm_pow, tarpit, honeypot_port, plugin, sandbox) present in overview |
| Config MainConfig Fields | ACCURATE | Diagram at `architecture/config_deep_dive.md:45-67` matches actual struct |
| PQC Feature Flags | CLARIFIED | `post-quantum`, `pqc-mesh`, `verify-pq` documented in `architecture/networking_deep_dive.md` |
| CPU Affinity Linux-only | DOCUMENTED | `src/worker/unified_server.rs:205-208` logs warning on non-Linux |

---

## Verification Commands

```bash
# All profiles should compile
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns

# Security regression tests
cargo test --test security_regression

# Lint
cargo fmt && cargo clippy --lib -- -D warnings
```

---

## Appendix A: Consolidated Lessons Learned (2026-05-23)

These lessons should be incorporated into future agent work:

1. **Process hierarchy is three-tier in traditional mode** - Consolidated (recommended): Supervisor → Workers; Traditional (legacy): Overseer → Master → Workers

2. **Config field propagation** - When adding new fields to config structs, ensure they propagate through all layers

3. **Dead code detection** - When code blocks are duplicated with no intervening return/break, check if second block is unreachable

4. **gRPC server has no TLS** - `src/supervisor/api.rs:114-129` uses plaintext gRPC intentionally for localhost IPC

5. **SAFE_HEADERS count is 28** - `src/proxy/cache.rs:97-126`

6. **Spin routing uses longest-prefix-match** - `src/spin/runtime.rs:271-285`

7. **CPU affinity pinning is Linux-only** - Must be explicitly configured via `cpu_affinity` parameter

8. **macOS Seatbelt sandbox requires feature flag** - Enable the `macos-sandbox` feature for actual enforcement

9. **ConfigManager is in synvoid-config crate** - `crates/synvoid-config/src/lib.rs:113`

10. **MeshProxy is a key routing component** - `src/mesh/proxy.rs:63` (1994 lines)

11. **ErasedHttpClient integration is incomplete** - `use_erased_client` is hardcoded to `false`. Phase 9 integration was never completed

12. **AXFR transfer complete** - `build_axfr_record()` at `src/dns/transfer.rs:829-1028` now handles all record types

13. **Plan verification is essential** - Always verify items against codebase before marking as needing work

14. **current_depth() doesn't exist** - `src/location_matcher.rs:191-195` only has `is_empty()` and `len()`

15. **BackendType enum variants** - `src/router.rs:65-77` has 11 variants

16. **Spin cold-start overhead** - `src/spin/runtime.rs:260` creates new `SpinAppInstance` per request

17. **UpstreamPool vs FastCgiPool health checks** - UpstreamPool now has active health checks at `src/upstream/pool.rs:751-779`

18. **HTTP/2 hardcoded disabled** - `src/http_client/mod.rs:890` has `is_http2 = false`

19. **DHT prefixes propagated** - Both instance pools now properly propagate `allowed_dht_prefixes`

20. **Retry config fixed** - `src/proxy/mod.rs:303` now uses parameter value directly

21. **BUG-L3 ML-KEM proof-of-possession FIXED** - `confirm_key()` now verifies client can decapsulate before confirming

---

*Last Updated: 2026-05-23*