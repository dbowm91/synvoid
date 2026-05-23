# Architecture Review Plan

Generated: 2026-05-23
Purpose: Review each architecture document, verify claims against code, and identify improvements and bugs.

**Status**: INCOMPLETE - Iterative improvement in progress

## Wave Progress

| Wave | Description | Status |
|------|-------------|--------|
| 1 | Fix CRITICAL bugs from review plans | ✅ COMPLETED |
| 2 | Fix HIGH priority improvements | ✅ COMPLETED |
| 3 | Fix MEDIUM priority items | ✅ COMPLETED |
| 4 | Fix LOW priority items and doc updates | ✅ COMPLETED |
| 5 | Update AGENTS.override.md and skills | ✅ COMPLETED |

### Completed Fixes (Wave 1 - CRITICAL Bugs)

- ✅ Audit log file permissions (`src/admin/audit.rs`)
- ✅ WAF trailing window logic (`src/waf/attack_detection/streaming.rs`)
- ✅ Proxy retry config propagation (`src/proxy/mod.rs`)
- ✅ LocationMatcher current_depth() stub removed
- ✅ Plugin DHT prefix propagation (pooled instances)

### Completed Fixes (Wave 2 - HIGH Priority)

- ✅ CORS middleware documentation fixed (no layer exists - intentional)
- ✅ Proxy TypedConnectionPool plaintext consistency
- ✅ Mesh 0-RTT documentation corrected
- ✅ Mesh DHT verification gaps documented
- ✅ Config sites hierarchy fixed
- ✅ WAF JS Challenge documentation fixed

### Completed Fixes (Wave 3 - MEDIUM Priority)

- ✅ Session timing normalization for admin auth
- ✅ ConfigManager domain lookup and reload fixes
- ✅ Serverless WASM Engine pooling
- ✅ Health check TCP mode URL parsing
- ✅ ML-KEM key freshness tracking
- ✅ Spin supervisor dead code removed

### Completed Fixes (Wave 4 - LOW Priority)

- ✅ Platform startup flow documentation
- ✅ gRPC uptime_secs tracking
- ✅ Routing reverse-domain documentation
- ✅ ACME DNS-01 documentation
- ✅ Upstream TypedConnectionPool plaintext consistency
- ✅ Various other documentation updates

## Excluded Documents
- `review_plan.md` - This file (generated fresh)
- `deep_dive_review.md` - General review methodology (not module-specific)
- `overview.md` - General overview (not a discrete module)

## Modules to Review

| # | Document | Module | Subagent |
|---|----------|--------|----------|
| 1 | `admin_deep_dive.md` | Admin API | admin_review |
| 2 | `app_handlers.md` | App Handlers | app_handlers_review |
| 3 | `config_deep_dive.md` | Configuration | config_review |
| 4 | `dns_deep_dive.md` | DNS | dns_review |
| 5 | `layer_3_5_deep_dive.md` | Layer 3.5 | layer_3_5_review |
| 6 | `mesh_deep_dive.md` | Mesh Networking | mesh_review |
| 7 | `networking_deep_dive.md` | Networking | networking_review |
| 8 | `platform_deep_dive.md` | Platform | platform_review |
| 9 | `plugin_deep_dive.md` | Plugin/WASM | plugin_review |
| 10 | `process_lifecycle.md` | Process Lifecycle | process_lifecycle_review |
| 11 | `proxy_deep_dive.md` | Proxy | proxy_review |
| 12 | `routing_deep_dive.md` | Routing | routing_review |
| 13 | `waf_deep_dive.md` | WAF | waf_review |
| 14 | `worker_architecture.md` | Worker Architecture | worker_review |

---

## Review Instructions for Subagents

Each subagent should:

1. **Read the architecture document** fully
2. **Identify claims** - statements about how the system works, data structures, protocols, etc.
3. **Verify claims against code** - locate the relevant source files and confirm the claims are accurate
4. **Interrogate for improvements** - look for:
   - Suboptimal implementations
   - Missing features described in docs but not implemented
   - Performance concerns
   - Security issues
   - Race conditions or concurrency bugs
5. **Interrogate for bugs** - look for:
   - Edge cases not handled
   - Error handling gaps
   - Memory leaks or resource exhaustion
   - Protocol violations
   - API contract violations

## Output Format

Each subagent writes their findings to `plans/<module_name>_review_plan.md` with this structure:

```markdown
# <Module> Architecture Review Plan

## Document
- Source: architecture/<module>_deep_dive.md (or appropriate filename)

## Claims Verified ✓ / Issues Found ✗

### Claim 1: [description]
- **Status**: Verified / Not Verified / Partially Verified
- **Code Location**: path/to/file.rs:line
- **Finding**: [details]

## Improvement Plan

### High Priority
1. [issue and recommended fix]

### Medium Priority
1. [issue and recommended fix]

## Bug Report

### Critical
1. [bug description and location]

### Minor
1. [bug description and location]
```

---

## Subagent Launch Commands

The following subagents will be launched in parallel:

```
admin_review:         Review admin_deep_dive.md
app_handlers_review:  Review app_handlers.md
config_review:        Review config_deep_dive.md
dns_review:           Review dns_deep_dive.md
layer_3_5_review:     Review layer_3_5_deep_dive.md
mesh_review:          Review mesh_deep_dive.md
networking_review:    Review networking_deep_dive.md
platform_review:      Review platform_deep_dive.md
plugin_review:        Review plugin_deep_dive.md
process_review:       Review process_lifecycle.md
proxy_review:         Review proxy_deep_dive.md
routing_review:      Review routing_deep_dive.md
waf_review:          Review waf_deep_dive.md
worker_review:       Review worker_architecture.md
```