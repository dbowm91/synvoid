# Architecture Review Plan

Generated: 2026-05-26
Purpose: Review each architecture document, verify claims against code, identify improvements and bugs, and prune stale content.

**Status**: ITERATIVE - Periodically updated as issues are discovered and fixed

> This plan uses iterative improvement: items are marked complete when verified fixed, deferred if minor, and known issues are documented for future attention.

## In Progress

| # | Item | Module | Status |
|---|------|--------|--------|
| 1 | Fix DOC-SEC-1: DHT prefix examples in plugin_deep_dive.md | Plugin | ✅ Completed |
| 2 | Fix BUG-L1: verify_hybrid() fail-safe in ml_dsa.rs | Layer 3.5 | ✅ Completed |
| 3 | Fix BUG-PL-1: add --master CLI flag in main.rs | Process | ✅ Completed |
| 4 | Fix X25519Kyber768Draft00 → X25519MLKEM768 | Layer 3.5 | ✅ Completed |
| 5 | Update Overseer terminology in admin_deep_dive.md | Admin | ✅ Completed |
| 6 | Update process_lifecycle.md (CPU affinity, reuse_port refs) | Process | ✅ Completed |
| 7 | Fix WasmHandler → SpinHttpHandler in app_handlers.md | App Handlers | ✅ Completed |
| 8 | Fix FastCGI streaming claim in app_handlers.md | App Handlers | ✅ Completed |
| 9 | Fix AXFR missing record types section in dns_deep_dive.md | DNS | ✅ Completed |
| 10 | Fix Lease→increment_connections, add BackendTypes, PeakEwma | Routing | ✅ Completed |
| 11 | Clarify GeoIP usage in waf_deep_dive.md | WAF | ✅ Completed |
| 12 | Add fs.rs to platform_deep_dive.md module table | Platform | ✅ Completed |
| 13 | Fix ConfigManager line numbers in config_deep_dive.md | Config | ✅ Completed |
| 14 | Clarify HTTP/2 limitation, handler separation in networking_deep_dive.md | Networking | ✅ Completed |

## Excluded Documents
- `review_plan.md` - This file (generated fresh)
- `deep_dive_review.md` - General review methodology (not module-specific)
- `overview.md` - General overview (not a discrete module)

## Modules Reviewed

| # | Document | Module | Status | Output File |
|---|----------|--------|--------|-------------|
| 1 | `admin_deep_dive.md` | Admin API | ✅ Complete | plans/admin_review_plan.md |
| 2 | `app_handlers.md` | App Handlers | ✅ Complete | plans/app_handlers_review_plan.md |
| 3 | `config_deep_dive.md` | Configuration | ✅ Complete | plans/config_review_plan.md |
| 4 | `dns_deep_dive.md` | DNS | ✅ Complete | plans/dns_review_plan.md |
| 5 | `layer_3_5_deep_dive.md` | Layer 3.5 | ✅ Complete | plans/layer_3_5_review_plan.md |
| 6 | `mesh_deep_dive.md` | Mesh Networking | ✅ Complete | plans/mesh_review_plan.md |
| 7 | `networking_deep_dive.md` | Networking | ✅ Complete | plans/networking_review_plan.md |
| 8 | `platform_deep_dive.md` | Platform | ✅ Complete | plans/platform_review_plan.md |
| 9 | `plugin_deep_dive.md` | Plugin/WASM | ✅ Complete | plans/plugin_review_plan.md |
| 10 | `process_lifecycle.md` | Process Lifecycle | ✅ Complete | plans/process_lifecycle_review_plan.md |
| 11 | `proxy_deep_dive.md` | Proxy | ✅ Complete | plans/proxy_review_plan.md |
| 12 | `routing_deep_dive.md` | Routing | ✅ Complete | plans/routing_review_plan.md |
| 13 | `waf_deep_dive.md` | WAF | ✅ Complete | plans/waf_review_plan.md |
| 14 | `worker_architecture.md` | Worker Architecture | ✅ Complete | plans/worker_review_plan.md |

---

## Stale Items Summary (Cross-Module)

The following stale items were identified across architecture documents. Items marked ✅ are verified fixed:

| Document | Stale Item | Status |
|----------|------------|--------|
| admin_deep_dive.md | Overseer references should be "Supervisor" | ✅ Fixed |
| admin_deep_dive.md | Line number references off by 3-10 lines | ⚠️ Deferred - minor cosmetic |
| app_handlers.md | FastCGI "response streaming" claim contradicts APP-15 | ✅ Fixed |
| app_handlers.md | "WasmHandler" doesn't exist (SpinHttpHandler is at that line) | ✅ Fixed |
| app_handlers.md | Generic WASM mesh distribution claim unverified | ✅ Fixed |
| config_deep_dive.md | ConfigManager line numbers incorrect | ✅ Fixed |
| config_deep_dive.md | Type naming mismatches | ⚠️ Deferred |
| dns_deep_dive.md | AXFR "Missing record types" section is WRONG | ✅ Fixed |
| dns_deep_dive.md | DnsCookieServer created but not integrated | ⚠️ Known deferred - DNS-COOKIE |
| dns_deep_dive.md | Query coalescing line references wrong | ✅ Fixed |
| layer_3_5_deep_dive.md | X25519Kyber768Draft00 mentioned but only X25519MLKEM768 exists | ✅ Fixed |
| layer_3_5_deep_dive.md | verify_hybrid() returns false without ML-DSA (BUG-L1) | ✅ Fixed |
| mesh_deep_dive.md | quorum verification reference wrong file | ⚠️ Reference not found in current doc |
| networking_deep_dive.md | "Shared Handler" claim inaccurate | ✅ Fixed |
| networking_deep_dive.md | HTTP/2 client configuration inconsistent | ✅ Fixed |
| platform_deep_dive.md | fs.rs missing from module table | ✅ Fixed |
| platform_deep_dive.md | Several process module files undocumented | ⚠️ Deferred |
| plugin_deep_dive.md | DHT prefix examples completely wrong (87-88) | ✅ Fixed |
| plugin_deep_dive.md | Warmup stub function description misleading | ✅ Fixed |
| process_lifecycle.md | Overseer Cannot Spawn Master (--master flag missing) | ✅ Fixed (flag added) |
| process_lifecycle.md | CPU affinity documentation wrong | ✅ Fixed |
| proxy_deep_dive.md | HTTP/2 connection multiplexing not implemented | ✅ Fixed |
| proxy_deep_dive.md | ErasedHttpClient Phase 9 incomplete | ⚠️ Known deferred - PQC-PHASE9 |
| routing_deep_dive.md | "Lease" concept doesn't exist | ✅ Fixed |
| routing_deep_dive.md | Missing BackendType variants | ✅ Fixed |
| waf_deep_dive.md | Line references off by ~50 lines | ✅ Fixed |
| waf_deep_dive.md | GeoIP "not fully implemented" misleading | ✅ Fixed |
| worker_architecture.md | WAF pipeline "Challenge" stage not separate | ✅ Fixed |
| worker_architecture.md | Health monitoring overstated | ✅ Fixed |

---

## Critical Bugs Identified

| Bug ID | Module | Description | Location | Status |
|--------|--------|-------------|----------|--------|
| BUG-L1 | Layer 3.5 | verify_hybrid() returns false without ML-DSA, not fail-safe | src/mesh/ml_dsa.rs:217 | ✅ FIXED |
| BUG-PL-1 | Process | Overseer cannot spawn Master (--master flag missing) | src/main.rs:27 (added) | ✅ FIXED |
| BUG-PL-2 | Process | Legacy mode not selectable (only Supervisor mode functional) | main.rs | ⚠️ Legacy code preserved |
| DOC-SEC-1 | Plugin | DHT prefix examples completely wrong | architecture/plugin_deep_dive.md:87-88 | ✅ FIXED |

---

## Known Issues Deferred

| Issue | Module | Description |
|-------|--------|-------------|
| APP-15 | FastCGI | Response NOT truly streamed (buffers entire stdout) |
| DNS-COOKIE | DNS | DNS Cookie Server not integrated |
| HTTP2-DISABLED | HTTP Client | HTTP/2 infrastructure exists but disabled |
| PQC-PHASE9 | HTTP Server | ErasedHttpClient Phase 9 incomplete |

---

## Next Steps

1. ✅ **Completed**: Fixed critical documentation error in plugin_deep_dive.md (DHT prefix examples)
2. ✅ **Completed**: Fixed BUG-L1 (verify_hybrid fail-safe) and BUG-PL-1 (Overseer spawn issue)
3. ✅ **Completed**: Updated stale line references and terminology across docs
4. ⚠️ **Deferred**: Remaining items marked deferred in Stale Items table above