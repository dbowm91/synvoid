# Architecture Review Plan

**Generated:** 2026-05-26
**Purpose:** Systematically review each architecture document, verify claims against code, identify improvements and bugs, and prune stale content.
**Status:** SUBAGENTS COMPLETED - Consolidation in progress

---

## Overview

This plan orchestrates parallel subagent reviews of 14 discrete architecture modules. Each subagent:
1. Reads their assigned architecture document
2. Verifies claims against actual source code
3. Identifies discrepancies, bugs, and improvements
4. Writes a detailed improvement plan to `plans/<module>_review_plan.md`

---

## Architecture Documents Reviewed (14 Modules)

| # | Document | Module | Output File | Status |
|---|----------|--------|-------------|--------|
| 1 | `admin_deep_dive.md` | Admin API | `plans/admin_review_plan.md` | ✅ Complete |
| 2 | `app_handlers.md` | App Handlers | `plans/app_handlers_review_plan.md` | ✅ Complete |
| 3 | `config_deep_dive.md` | Configuration | `plans/config_review_plan.md` | ✅ Complete |
| 4 | `dns_deep_dive.md` | DNS | `plans/dns_review_plan.md` | ⚠️ Empty result |
| 5 | `layer_3_5_deep_dive.md` | Layer 3.5 (TLS/Crypto) | `plans/layer_3_5_review_plan.md` | ✅ Complete |
| 6 | `mesh_deep_dive.md` | Mesh Networking | `plans/mesh_review_plan.md` | ✅ Complete |
| 7 | `networking_deep_dive.md` | Networking | `plans/networking_review_plan.md` | ✅ Complete |
| 8 | `platform_deep_dive.md` | Platform | `plans/platform_review_plan.md` | ✅ Complete |
| 9 | `plugin_deep_dive.md` | Plugin/WASM | `plans/plugin_review_plan.md` | ✅ Complete |
| 10 | `process_lifecycle.md` | Process Lifecycle | `plans/process_lifecycle_review_plan.md` | ✅ Complete |
| 11 | `proxy_deep_dive.md` | Proxy | `plans/proxy_review_plan.md` | ✅ Complete |
| 12 | `routing_deep_dive.md` | Routing | `plans/routing_review_plan.md` | ✅ Complete |
| 13 | `waf_deep_dive.md` | WAF | `plans/waf_review_plan.md` | ✅ Complete |
| 14 | `worker_architecture.md` | Worker Architecture | `plans/worker_review_plan.md` | ⚠️ Empty result |

---

## Excluded Documents

| Document | Reason |
|----------|--------|
| `review_plan.md` | This file (generated fresh) |
| `deep_dive_review.md` | General review methodology, not module-specific |
| `overview.md` | General overview (not a discrete module) |

---

## Subagent Execution Summary

### Phase 1: Parallel Module Reviews (All Complete)

12 of 14 subagents completed successfully. 2 returned empty results (DNS, Worker).

---

## Stale Files to PRUNE

### Plans Directory

| File | Reason to Prune |
|------|-----------------|
| `plans/plan.md` | Contains "Completed" status - superseded by this document |

### Architecture Directory

| File | Reason |
|------|--------|
| (none identified) | All architecture docs are current |

---

## Key Findings Summary

### Critical Documentation Errors Found

| Module | Issue | Severity |
|--------|-------|----------|
| **Admin** | CORS claimed not implemented but `create_cors_layer()` exists at `src/admin/mod.rs:50-97` | High |
| **Admin** | Overseer endpoints called "legacy" but fully functional | Medium |
| **App Handlers** | Granian/Python support documented but NOT implemented | High |
| **App Handlers** | CGI handler completely missing from documentation | Medium |
| **Platform** | macOS Seatbelt claimed "not yet implemented" but fully implemented (feature-gated) | High |
| **Platform** | CPU affinity diagram says "automatic" but only assigned when `--cpu-affinity` flag passed | Medium |
| **Process** | `--master` CLI flag claimed missing but exists at `src/main.rs:35` | Medium |
| **Proxy** | `use_erased_client = false` hardcoded - ErasedHttpClient Phase 9 incomplete | Known |
| **Networking** | `collect_body_with_chunk_waf` line number in AGENTS.md is 4662, not 4532 | Low |

### Verified Correct (Previously Fixed)

| Document | Issue | Status |
|----------|-------|--------|
| `plugin_deep_dive.md` | DHT prefix examples (BUG-DOC-SEC-1) | ✅ Fixed |
| `layer_3_5_deep_dive.md` | X25519MLKEM768 naming | ✅ Fixed |
| `routing_deep_dive.md` | BackendType 11 variants | ✅ Correct |
| `proxy_deep_dive.md` | Retry config properly applied | ✅ Fixed |
| `waf_deep_dive.md` | StreamingWafCore trailing window | ✅ Correct |

### Known Deferred Issues (Documented in AGENTS.md)

| Issue | Module | Description |
|-------|--------|-------------|
| APP-15 | FastCGI | Response NOT truly streamed (buffers entire stdout) |
| DNS-COOKIE | DNS | DNS Cookie Server not integrated |
| PQC-PHASE9 | Proxy | ErasedHttpClient Phase 9 incomplete |
| MESH-14 | Mesh | No Source Node ID Binding Validation in All Ingress Paths |
| MESH-15 | Mesh | Quorum Deadlock Risk During Partition |

---

## Plans Directory Contents

```
plans/
├── admin_review_plan.md          ✅ (8823 bytes)
├── app_handlers_review_plan.md   ✅ (10867 bytes)
├── config_review_plan.md         ✅ (8803 bytes)
├── dns_review_plan.md            ⚠️ (empty - needs re-review)
├── layer_3_5_review_plan.md      ✅ (7987 bytes)
├── mesh_review_plan.md           ✅ (7506 bytes)
├── migration.md                  📌 (keep - active plan)
├── networking_review_plan.md      ✅ (11469 bytes)
├── plan.md                      🗑️ (PRUNE - stale)
├── platform_review_plan.md       ✅ (10741 bytes)
├── plugin_review_plan.md         ✅ (12905 bytes)
├── process_lifecycle_review_plan.md ✅ (12549 bytes)
├── proxy_review_plan.md          ✅ (9751 bytes)
├── routing_review_plan.md        ✅ (6791 bytes)
├── waf_review_plan.md            ✅ (9162 bytes)
└── worker_review_plan.md         ⚠️ (empty - needs re-review)
```

---

## Next Steps

1. **Re-review DNS module** - Subagent returned empty result
2. **Re-review Worker Architecture module** - Subagent returned empty result
3. **Prune stale files:**
   - Delete `plans/plan.md`
4. **Commit to main:**
   - `architecture/review_plan.md` (this file)
   - All `plans/*_review_plan.md` files
   - Remove `plans/plan.md`

---

## Verification Commands

After reviews complete, verify architecture consistency:

```bash
# Verify all profiles still compile
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns

# Run tests
cargo test --lib --no-run
```

---

## Cross-Reference Checks (Verified)

Critical references that were verified during review:

| Reference | Expected Location | Status |
|-----------|-------------------|--------|
| ConfigManager | `crates/synvoid-config/src/lib.rs:113` | ✅ Correct |
| BackendType enum | `src/router.rs:66-77` (11 variants) | ✅ Correct |
| StreamingWafCore | `src/waf/attack_detection/streaming.rs:129-134` | ✅ Correct |
| Quorum verification | `src/mesh/dht/signed.rs:860-934` | ✅ Correct |
| `collect_body_with_chunk_waf` | `src/http/server.rs:4662` | ⚠️ AGENTS.md says 4532 |

---

(End of file)