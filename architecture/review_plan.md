# Architecture Review Plan

**Generated:** 2026-05-26
**Last Updated:** 2026-05-26 (wave 2 implementation)
**Status:** INCOMPLETE - Wave 2 implementation in progress
**Purpose:** Systematically review architecture documents, verify claims against code, identify improvements and bugs, prune stale content.

---

## Overview

This plan orchestrates parallel subagent reviews of 14 discrete architecture modules. Each subagent:
1. Reads their assigned architecture document in `architecture/`
2. Verifies claims against actual source code in `src/`
3. Identifies discrepancies, bugs, and improvements
4. Writes a detailed improvement plan to `plans/<module>_review_plan.md`

---

## Architecture Documents (14 Modules)

| # | Document | Subagent Task | Output File |
|---|----------|---------------|-------------|
| 1 | `admin_deep_dive.md` | Review Admin API architecture | `plans/admin_review_plan.md` |
| 2 | `app_handlers.md` | Review App Handlers architecture | `plans/app_handlers_review_plan.md` |
| 3 | `config_deep_dive.md` | Review Configuration architecture | `plans/config_review_plan.md` |
| 4 | `dns_deep_dive.md` | Review DNS architecture | `plans/dns_review_plan.md` |
| 5 | `layer_3_5_deep_dive.md` | Review Layer 3.5 (TLS/Crypto) architecture | `plans/layer_3_5_review_plan.md` |
| 6 | `mesh_deep_dive.md` | Review Mesh Networking architecture | `plans/mesh_review_plan.md` |
| 7 | `networking_deep_dive.md` | Review Networking architecture | `plans/networking_review_plan.md` |
| 8 | `platform_deep_dive.md` | Review Platform architecture | `plans/platform_review_plan.md` |
| 9 | `plugin_deep_dive.md` | Review Plugin/WASM architecture | `plans/plugin_review_plan.md` |
| 10 | `process_lifecycle.md` | Review Process Lifecycle architecture | `plans/process_lifecycle_review_plan.md` |
| 11 | `proxy_deep_dive.md` | Review Proxy architecture | `plans/proxy_review_plan.md` |
| 12 | `routing_deep_dive.md` | Review Routing architecture | `plans/routing_review_plan.md` |
| 13 | `waf_deep_dive.md` | Review WAF architecture | `plans/waf_review_plan.md` |
| 14 | `worker_architecture.md` | Review Worker Architecture | `plans/worker_review_plan.md` |

---

## Excluded Documents

| Document | Reason |
|----------|--------|
| `review_plan.md` | This file (generated fresh) |
| `deep_dive_review.md` | General review methodology, not module-specific |
| `overview.md` | General overview (not a discrete module) |

---

## Stale Files to PRUNE

### Plans Directory

| File | Reason to Prune |
|------|-----------------|
| `plans/plan.md` | Outdated - superseded by this review plan; no longer relevant |

### Architecture Directory

| File | Reason |
|------|--------|
| (none identified) | All architecture docs are current as of review |

---

## Review Methodology

For each module, the subagent must:

1. **Read the architecture document** from `architecture/<doc>.md`
2. **Verify claims against source code**:
   - Module locations (file paths and line numbers)
   - Feature availability (feature gates, cfg attributes)
   - Implementation status (documented vs actual)
   - Security patterns (constant-time comparison, etc.)
   - Enum variants and struct definitions
3. **Cross-reference with AGENTS.md** for known issues
4. **Write improvement plan** to `plans/<module>_review_plan.md` containing:
   - Verified correct items
   - Discrepancies found
   - Bugs identified (with severity)
   - Suggested improvements (NOT direct code changes)

---

## Subagent Execution

Launch 14 parallel subagents, one per module. Each subagent should:
- Use the `explore` agent for research
- Focus on verifying specific claims in the assigned document
- Write findings to the specified output file in `plans/`

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

## Cross-Reference Checklist

Subagents should verify these known references:

| Reference | Expected Location | Status |
|-----------|-------------------|--------|
| ConfigManager | `crates/synvoid-config/src/lib.rs:113` | To verify |
| BackendType enum | `src/router.rs:66-77` (11 variants) | To verify |
| StreamingWafCore | `src/waf/attack_detection/streaming.rs:129-134` | To verify |
| Quorum verification | `src/mesh/dht/signed.rs:860-934` | To verify |
| `collect_body_with_chunk_waf` | `src/http/server.rs:4662` | To verify |

---

(End of file)