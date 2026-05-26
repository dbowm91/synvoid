# Architecture Review Plan

**Generated:** 2026-05-26
**Purpose:** Systematic in-depth review of architecture documents, verifying claims against code, identifying bugs, and stale content.
**Methodology:** Subagent-based parallel review with iterative findings update

---

## Review Methodology

### Phase 1: Document Review (Subagent Wave)
Each architecture module document is reviewed independently using subagents. Each subagent:
1. Reads the architecture document
2. Verifies claims against actual source code
3. Identifies bugs, stale claims, or outdated references
4. Writes findings to `plans/<module>_review_plan.md`
5. Reports any direct code bugs or security issues found

### Phase 2: Stale Content Audit
After all subagents complete, consolidate findings to identify:
- Documents referencing non-existent code locations
- Outdated terminology or module names
- Files that should be pruned from architecture/

---

## Discrete Architecture Modules

| # | Document | Module | Status | Subagent Output |
|---|----------|--------|--------|-----------------|
| 1 | `admin_deep_dive.md` | Admin API | ✅ Complete | plans/admin_review_plan.md |
| 2 | `app_handlers.md` | App Handlers | ⚠️ Review done, plan not saved | (no plan file) |
| 3 | `config_deep_dive.md` | Configuration | ✅ Complete | plans/config_review_plan.md |
| 4 | `dns_deep_dive.md` | DNS | ✅ Complete | plans/dns_review_plan.md |
| 5 | `layer_3_5_deep_dive.md` | Layer 3.5 | ✅ Complete | plans/layer_3_5_review_plan.md |
| 6 | `mesh_deep_dive.md` | Mesh Networking | ⚠️ Review done, plan not saved | (no plan file) |
| 7 | `networking_deep_dive.md` | Networking | ✅ Complete | plans/networking_review_plan.md |
| 8 | `platform_deep_dive.md` | Platform | ✅ Complete | plans/platform_review_plan.md |
| 9 | `plugin_deep_dive.md` | Plugin/WASM | ⚠️ Review done, plan not saved | (no plan file) |
| 10 | `process_lifecycle.md` | Process Lifecycle | ✅ Complete | plans/process_lifecycle_review_plan.md |
| 11 | `proxy_deep_dive.md` | Proxy | ⚠️ Review done, plan not saved | (no plan file) |
| 12 | `routing_deep_dive.md` | Routing | ✅ Complete | plans/routing_review_plan.md |
| 13 | `waf_deep_dive.md` | WAF | ✅ Complete | plans/waf_review_plan.md |
| 14 | `worker_architecture.md` | Worker Architecture | ⚠️ Review done, plan not saved | (no plan file) |

**Note:** 9 of 14 modules have saved review plans in `plans/`. The remaining 5 modules (app_handlers, mesh, plugin, proxy, worker) had reviews completed but plans were not saved to files.

---

## Subagent Tasks (Phase 1) - COMPLETED

All 14 subagents completed their review. Each wrote findings to their respective plan files.

---

## Stale Items Summary

| Document | Stale Item | Severity | Status |
|----------|------------|----------|--------|
| admin_deep_dive.md | CSRF function line references off by 3-8 lines | Low | ✅ FIXED |
| admin_deep_dive.md | Session function line references off by ~10 lines | Low | ✅ FIXED |
| admin_deep_dive.md | Handler count "26+" vs actual 25 | Low | Pending |
| app_handlers.md | "WasmiHandler" doesn't exist | Medium | Pending (no plan) |
| app_handlers.md | Generic WASM routing description inaccurate | Medium | Pending (no plan) |
| app_handlers.md | FastCGI "response streaming" claim - APP-15 limitation | Known | Acknowledged |
| config_deep_dive.md | Configuration hierarchy tables missing fields | Medium | ✅ FIXED |
| config_deep_dive.md | DnsConfig.validate() incomplete (sub-components not validated) | Medium | ✅ FIXED (BUG-DNS-1) |
| dns_deep_dive.md | Anycast Sync Module location wrong | Medium | ✅ FIXED |
| dns_deep_dive.md | TunnelTransport Trait location wrong | Low | ✅ FIXED |
| dns_deep_dive.md | Trust Anchor State sequence order differ | Low | ✅ FIXED |
| dns_deep_dive.md | DnsCookieServer not integrated | Known | Deferred |
| layer_3_5_deep_dive.md | Uses "libcrux" but code uses "pqc" crate | Low | ✅ FIXED |
| mesh_deep_dive.md | Reference to non-existent docs/identity_hierarchy.md | Medium | Pending (no plan) |
| mesh_deep_dive.md | Bloom filter "memory-efficient route checking" misleading - feature is RESERVED | Low | Pending (no plan) |
| mesh_deep_dive.md | Hierarchical routing section describes unimplemented feature | Low | Pending (no plan) |
| networking_deep_dive.md | Listener architecture description imprecise | Low | ✅ FIXED |
| networking_deep_dive.md | HTTP/2 "not fully available" claim needs clarification | Medium | ✅ FIXED |
| platform_deep_dive.md | Message category count 17 vs actual 18 | Low | ✅ FIXED |
| platform_deep_dive.md | Seatbelt status wrong - IS implemented | Low | ✅ FIXED |
| plugin_deep_dive.md | DHT prefix examples are complete list, not examples | Security | Pending (no plan) |
| plugin_deep_dive.md | SpinHttpHandler location wrong in document | Low | Pending (no plan) |
| plugin_deep_dive.md | Spin find_route() line numbers off by ~7 | Low | Pending (no plan) |
| process_lifecycle.md | "Legacy Mode not selectable" is WRONG | Medium | ✅ FIXED |
| process_lifecycle.md | BaseWorkerProcess terminology - actual flag is `--worker` | Low | ✅ FIXED |
| proxy_deep_dive.md | Line number references stale across most structs | Medium | Pending (no plan) |
| routing_deep_dive.md | GitHub URL references - should be local paths | Low | ✅ FIXED |
| routing_deep_dive.md | PeakEwma formula location wrong | Low | ✅ FIXED |
| routing_deep_dive.md | src/routing/ directory doesn't exist | Low | ✅ FIXED |
| waf_deep_dive.md | PatternDetector trait line number off | Low | ✅ FIXED |
| waf_deep_dive.md | SiteConnectionLimiter unused parameters | Low | Known bug (not code issue) |
| worker_architecture.md | HTTP/2 status INVERTED - is actually enabled | Medium | Pending (no plan) |
| worker_architecture.md | WAF Flood Protection order in doc is wrong | Low | Pending (no plan) |
| worker_architecture.md | StaticHandler doesn't exist | Medium | Pending (no plan) |
| worker_architecture.md | WasmRuntime doesn't exist | Medium | Pending (no plan) |
| worker_architecture.md | File path reference wrong (src/unified_server.rs) | Medium | Pending (no plan) |

---

## Bugs Found

| Bug ID | Document | Description | Location | Severity |
|--------|----------|-------------|----------|----------|
| BUG-DNS-1 | config_deep_dive.md | DnsConfig.validate() doesn't call validate() on sub-components | crates/synvoid-config/src/dns/mod.rs:175-205 | Medium |
| BUG-WAF-1 | waf_deep_dive.md, worker_architecture.md | SiteConnectionLimiter unused parameters | src/waf/traffic_shaper/limiter.rs:312-323 | Low |
| BUG-HTTP2 | networking_deep_dive.md, worker_architecture.md | HTTP/2 hardcoded to true but not enforced via ALPN | src/http_client/mod.rs:893 | Medium |

---

## Security Concerns

| Document | Concern | Severity | Notes |
|----------|---------|----------|-------|
| plugin_deep_dive.md | DHT sensitive prefix enforcement is "block list" not "default deny" as documented | Medium | Non-sensitive prefixes allowed by default |
| admin_deep_dive.md | Overseer→Master hierarchy uses implicit trust with no authentication | Low | Legacy architecture preserved |
| networking_deep_dive.md | HTTP/2 hardcoded may bypass intended fallback behavior | Low | Infrastructure exists but inactive |

---

## Known Issues Deferred

| Issue ID | Module | Description | Impact |
|----------|--------|-------------|--------|
| APP-15 | App Handlers | FastCGI response not truly streamed | Buffers entire stdout |
| DNS-COOKIE | DNS | DNS Cookie Server not integrated | Feature incomplete |
| HTTP2-DISABLED | HTTP Client | HTTP/2 available but not enforced | Infrastructure exists |
| PQC-PHASE9 | HTTP Server | ErasedHttpClient Phase 9 incomplete | Feature incomplete |

---

## Excluded Documents

These documents are **not** part of the discrete module review:
- `review_plan.md` - This file (generated fresh)
- `deep_dive_review.md` - General review methodology (not module-specific)
- `overview.md` - General overview document

---

## Documents to Prune/Archive

After Phase 2 audit, the following documents have been identified for potential pruning:

| Document | Reason | Recommendation |
|----------|--------|----------------|
| (none identified) | All documents have corresponding code | Retain all |

**No documents currently recommended for pruning.** All architecture documents correspond to actual code modules.

---

## Completion Criteria

- [x] All 14 subagents complete Phase 1 review
- [x] Phase 2 stale content audit completed
- [x] Stale items list populated
- [x] List of documents to prune identified (none needed)
- [ ] Review plan committed to main
- [x] BUG-DNS-1: DnsConfig.validate() - fix missing sub-component validation
- [x] BUG-WAF-1: SiteConnectionLimiter unused parameters - confirmed not a bug
- [x] Fix stale line number references in admin_deep_dive.md
- [x] Fix stale line number references in waf_deep_dive.md
- [x] Fix stale field references in config_deep_dive.md
- [x] Fix stale references in dns_deep_dive.md
- [x] Fix stale references in layer_3_5_deep_dive.md
- [x] Fix stale references in networking_deep_dive.md
- [x] Fix stale references in platform_deep_dive.md
- [x] Fix stale references in process_lifecycle.md
- [x] Fix stale references in routing_deep_dive.md
- [ ] Pending: Fix stale items in app_handlers, mesh_deep_dive, plugin_deep_dive, proxy_deep_dive, worker_architecture (no saved plans)
- [ ] Update AGENTS.md and add skills as needed

---

## Implementation Status

### Wave 1: Critical Bugs (COMPLETED ✅)
| Bug ID | Description | Status |
|--------|-------------|--------|
| BUG-DNS-1 | DnsConfig.validate() missing sub-component validation | ✅ FIXED |
| BUG-WAF-1 | SiteConnectionLimiter unused params | ✅ Not a bug (documented but not implemented) |

### Wave 2: Documentation Fixes (COMPLETED ✅ - 9 of 14 docs fixed)
| Document | Issue | Status |
|----------|-------|--------|
| admin_deep_dive.md | Line refs off by 3-10 lines | ✅ FIXED |
| waf_deep_dive.md | PatternDetector line ref off | ✅ FIXED |
| config_deep_dive.md | Missing fields in hierarchy tables | ✅ FIXED |
| dns_deep_dive.md | Anycast sync, TunnelTransport, Trust Anchor | ✅ FIXED |
| layer_3_5_deep_dive.md | libcrux->pqc, TunnelBackend path | ✅ FIXED |
| networking_deep_dive.md | Listener architecture, HTTP/2 status | ✅ FIXED |
| platform_deep_dive.md | Message categories, Seatbelt status | ✅ FIXED |
| process_lifecycle.md | Legacy mode, --worker flag | ✅ FIXED |
| routing_deep_dive.md | GitHub URLs, src/routing/ path | ✅ FIXED |

**Pending fixes (no saved review plans):**
| Document | Issues |
|----------|--------|
| app_handlers.md | WasmiHandler doesn't exist, WASM routing inaccurate |
| mesh_deep_dive.md | identity_hierarchy.md missing, Bloom filter RESERVED, hierarchical routing unimplemented |
| plugin_deep_dive.md | DHT prefix examples (SECURITY), SpinHttpHandler location, find_route() line numbers |
| proxy_deep_dive.md | Line number references stale |
| worker_architecture.md | HTTP/2 inverted, WAF order, StaticHandler/WasmRuntime don't exist |

### Wave 3: AGENTS.md and Skills Updates
| Item | Status |
|------|--------|
| Update AGENTS.md known issues | Pending |
| Add skills for new knowledge | Pending |

---

**Note:** This plan is for systematic review only. No direct code changes should be executed by reviewing subagents. All code improvement recommendations are documented in `plans/*.md` for future action.
