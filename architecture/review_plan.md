# Architecture Review Plan

Generated: 2026-05-26
Purpose: Review each architecture document, verify claims against code, identify improvements and bugs, and prune stale content.

**Status**: IN PROGRESS - Working through waves

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

The following stale items were identified across architecture documents:

| Document | Stale Item | Action Required |
|----------|------------|-----------------|
| admin_deep_dive.md | Overseer references should be "Supervisor" | Update terminology |
| admin_deep_dive.md | Line number references off by 3-10 lines | Fix line refs |
| app_handlers.md | FastCGI "response streaming" claim contradicts APP-15 | Remove/update claim |
| app_handlers.md | "WasmHandler" doesn't exist (SpinHttpHandler is at that line) | Fix reference |
| app_handlers.md | Generic WASM mesh distribution claim unverified | Clarify scope |
| config_deep_dive.md | ConfigManager line numbers incorrect (113-233 vs 113-241) | Fix line refs |
| config_deep_dive.md | Type naming mismatches (IpFeedConfig vs MainIpFeedConfig) | Unify naming |
| dns_deep_dive.md | AXFR "Missing record types" section is WRONG - all implemented | Remove section |
| dns_deep_dive.md | DnsCookieServer created but not integrated | Document as deferred |
| dns_deep_dive.md | Query coalescing line references wrong | Fix line refs |
| layer_3_5_deep_dive.md | X25519Kyber768Draft00 mentioned but only X25519MLKEM768 exists | Fix algorithm name |
| layer_3_5_deep_dive.md | verify_hybrid() returns false without ML-DSA (BUG-L1) | Code fix needed |
| mesh_deep_dive.md | quorum verification reference wrong file (state_machine vs signed.rs) | Fix file ref |
| networking_deep_dive.md | "Shared Handler" claim inaccurate (separate implementations) | Clarify |
| networking_deep_dive.md | HTTP/2 client configuration inconsistent | Document as known issue |
| platform_deep_dive.md | fs.rs missing from module table | Add to docs |
| platform_deep_dive.md | Several process module files undocumented | Add to docs |
| plugin_deep_dive.md | DHT prefix examples completely wrong (87-88) | FIX IMMEDIATELY |
| plugin_deep_dive.md | Warmup stub function description misleading | Clarify |
| process_lifecycle.md | Overseer Cannot Spawn Master (--master flag missing) | Document as legacy |
| process_lifecycle.md | CPU affinity documentation wrong (it's automatic, not manual) | Fix claim |
| proxy_deep_dive.md | HTTP/2 connection multiplexing not implemented | Document as known issue |
| proxy_deep_dive.md | ErasedHttpClient Phase 9 incomplete | Document as deferred |
| routing_deep_dive.md | "Lease" concept doesn't exist | Remove terminology |
| routing_deep_dive.md | Missing BackendType variants (AxumDynamic, Spin, Cgi) | Add to docs |
| waf_deep_dive.md | Line references off by ~50 lines | Fix line refs |
| waf_deep_dive.md | GeoIP "not fully implemented" misleading (ASN lookup uses it) | Clarify |
| worker_architecture.md | WAF pipeline "Challenge" stage not separate (inline in bot protection) | Clarify flow |
| worker_architecture.md | Health monitoring overstated (primarily passive) | Clarify |

---

## Critical Bugs Identified

| Bug ID | Module | Description | Location |
|--------|--------|-------------|----------|
| BUG-L1 | Layer 3.5 | verify_hybrid() returns false without ML-DSA, not fail-safe | src/mesh/ml_dsa.rs:217 |
| BUG-PL-1 | Process | Overseer cannot spawn Master (--master flag missing in main.rs) | src/main.rs, src/overseer/spawn.rs:84 |
| BUG-PL-2 | Process | Legacy mode not selectable (only Supervisor mode functional) | main.rs |
| DOC-SEC-1 | Plugin | DHT prefix examples completely wrong (security misconfig risk) | architecture/plugin_deep_dive.md:87-88 |

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

1. **Immediate**: Fix critical documentation error in plugin_deep_dive.md (DHT prefix examples)
2. **High Priority**: Address BUG-L1 (verify_hybrid fail-safe) and BUG-PL-1 (Overseer spawn issue)
3. **Medium Priority**: Update stale line references and terminology across docs
4. **Low Priority**: Add missing module files to documentation tables