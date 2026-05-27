# Architecture Review Plan

**Generated:** 2026-05-27
**Status:** INCOMPLETE
**Purpose:** Systematically review architecture documents, verify claims against code, identify improvements and bugs, prune stale content.

---

## Overview

This plan orchestrates parallel subagent reviews of discrete architecture modules. Each subagent:
1. Reads their assigned architecture document in `architecture/`
2. Verifies claims against actual source code in `src/`
3. Identifies discrepancies, bugs, and improvements
4. Writes a detailed improvement plan to `plans/<module>_review_plan.md`

---

## Phase 1: Architecture Modules to Review (17 Modules)

| # | Document | Subagent Task | Output File |
|---|----------|---------------|-------------|
| 1 | `admin_deep_dive.md` | Review Admin API architecture | `plans/admin_review_plan.md` |
| 2 | `app_handlers.md` | Review App Handlers architecture | `plans/app_handlers_review_plan.md` |
| 3 | `auth.md` | Review Authentication architecture | `plans/auth_review_plan.md` |
| 4 | `config.md` + `config_deep_dive.md` | Review Configuration architecture | `plans/config_review_plan.md` |
| 5 | `dns.md` + `dns_deep_dive.md` | Review DNS architecture | `plans/dns_review_plan.md` |
| 6 | `http_server.md` + `http_shared.md` | Review HTTP Server architecture | `plans/http_server_review_plan.md` |
| 7 | `layer_3_5_deep_dive.md` | Review Layer 3.5 (TLS/Crypto) architecture | `plans/layer_3_5_review_plan.md` |
| 8 | `mesh.md` + `mesh_deep_dive.md` | Review Mesh Networking architecture | `plans/mesh_review_plan.md` |
| 9 | `networking_deep_dive.md` | Review Networking architecture | `plans/networking_review_plan.md` |
| 10 | `platform.md` + `platform_deep_dive.md` | Review Platform architecture | `plans/platform_review_plan.md` |
| 11 | `plugin_wasm.md` + `plugin_deep_dive.md` | Review Plugin/WASM architecture | `plans/plugin_review_plan.md` |
| 12 | `process_lifecycle.md` | Review Process Lifecycle architecture | `plans/process_lifecycle_review_plan.md` |
| 13 | `proxy.md` + `proxy_deep_dive.md` | Review Proxy architecture | `plans/proxy_review_plan.md` |
| 14 | `routing_deep_dive.md` | Review Routing architecture | `plans/routing_review_plan.md` |
| 15 | `serverless.md` | Review Serverless architecture | `plans/serverless_review_plan.md` |
| 16 | `spin.md` | Review Spin WASM runtime | `plans/spin_review_plan.md` |
| 17 | `waf.md` + `waf_deep_dive.md` | Review WAF architecture | `plans/waf_review_plan.md` |
| 18 | `worker_architecture.md` | Review Worker Architecture | `plans/worker_review_plan.md` |

---

## Excluded Documents

| Document | Reason |
|----------|--------|
| `review_plan.md` | This file itself (generated fresh) |
| `deep_dive_review.md` | General review methodology, not module-specific |
| `overview.md` | General overview (not a discrete module) |
| `supervisor.md` | Leadership process, stable - minimal review needed |
| `ipc_process.md` | Low-level IPC mechanics, stable |
| `tunnel.md` | Deprecated/tunnel backend removed |
| `tls.md` | Handled under layer_3_5_deep_dive.md |

---

## Phase 2: Subagent Review Instructions

Each subagent must perform a **systematic code review** covering:

### 2.1 Source Code Verification
- Locate and verify all file paths and line numbers cited in the document
- Verify enum variants (e.g., `BackendType` has 11 variants at `src/router.rs:66-77`)
- Verify struct definitions, method signatures, and feature gates
- Verify feature availability (`#[cfg(feature = "...")]` attributes)

### 2.2 Implementation Status Check
- Compare documented behavior with actual implementation
- Identify stub functions vs. complete implementations
- Verify feature completeness (what's claimed vs. what's there)

### 2.3 Security Pattern Audit
- Check constant-time comparisons for secrets (keys, MACs, tokens)
- Verify file permissions on private key files
- Verify authorized genesis keys default deny
- Check PoW requirements for edge nodes

### 2.4 Cross-Reference with AGENTS.md
- Check known bugs in AGENTS.md for relevant module
- Verify bug fixes are still in place
- Check dependency vulnerability status

### 2.5 Improvement Discovery
- Identify API inconsistencies
- Identify missing error handling
- Identify performance concerns
- Identify dead code or unused functions
- Identify outdated documentation

### 2.6 Output Format
Write improvement plan to `plans/<module>_review_plan.md` containing:

```markdown
# <Module> Review Plan

## Verified Correct Items
- [item]: [verification result]

## Discrepancies Found
- [item]: [expected vs actual]

## Bugs Identified
- [severity]: [description] (location)

## Suggested Improvements
- [category]: [description]
```

---

## Phase 3: Stale Content Pruning

### 3.1 Check for Stale Architecture Files

Identify files that are:
- Superceded by deeper-dive documents (e.g., `dns.md` superceded by `dns_deep_dive.md`)
- Referencing Removed Code (e.g., `tunnel.md` references `TunnelBackend` which was removed)
- Outdated architecture decisions not reflected in code
- Duplicate content covered by other documents

### 3.2 Identify Stale References

Subagents should flag:
- File paths that no longer exist
- Struct/enum names that have changed
- Feature flags that were renamed or removed
- Configuration keys that are no longer used

### 3.3 Prune Commands (to be executed after review)

```bash
# Remove identified stale files from architecture/
git rm architecture/<stale_file>.md

# Update any index files if they exist
```

---

## Phase 4: Subagent Launch

Launch 18 parallel subagents, one per module. Each subagent should:
- Use the `explore` agent for research
- Use the `general` agent for deep review and writing
- Focus on verifying specific claims in the assigned document
- Cross-reference with `AGENTS.md` known bugs section
- Write findings to the specified output file in `plans/`

---

## Phase 5: Verification

After all reviews complete:

```bash
# Verify all profiles still compile
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns    # NOTE: Pre-existing error (dns feature + mesh config mismatch)
cargo check --no-default-features --features mesh,dns

# Run tests
cargo test --lib --no-run
```

**Note on DNS profile**: There is a pre-existing compilation error in `--features dns` mode at `src/server/mod.rs:311,318` where `MainTunnelConfig` lacks a `.mesh` field. This is unrelated to the review process and existed before this review cycle.

---

## Completed Review Plans

All 18 module review plans have been completed and are available in `plans/`:

| Module | Review Plan | Status |
|--------|-------------|--------|
| Admin API | `plans/admin_review_plan.md` | ✅ Complete |
| App Handlers | `plans/app_handlers_review_plan.md` | ✅ Complete |
| Auth | `plans/auth_review_plan.md` | ✅ Complete |
| Config | `plans/config_review_plan.md` | ✅ Complete |
| DNS | `plans/dns_review_plan.md` | ✅ Complete |
| HTTP Server | `plans/http_server_review_plan.md` | ✅ Complete |
| Layer 3.5 | `plans/layer_3_5_review_plan.md` | ✅ Complete |
| Mesh | `plans/mesh_review_plan.md` | ✅ Complete |
| Networking | `plans/networking_review_plan.md` | ✅ Complete |
| Platform | `plans/platform_review_plan.md` | ✅ Complete |
| Plugin/WASM | `plans/plugin_review_plan.md` | ✅ Complete |
| Process Lifecycle | `plans/process_lifecycle_review_plan.md` | ✅ Complete |
| Proxy | `plans/proxy_review_plan.md` | ✅ Complete |
| Routing | `plans/routing_review_plan.md` | ✅ Complete |
| Serverless | `plans/serverless_review_plan.md` | ✅ Complete |
| Spin WASM | `plans/spin_review_plan.md` | ✅ Complete |
| WAF | `plans/waf_review_plan.md` | ✅ Complete |
| Worker | `plans/worker_review_plan.md` | ✅ Complete |

---

## Implemented Fixes (Phase 4)

The following fixes have been implemented based on review findings:

| Bug ID | Description | Status |
|--------|-------------|--------|
| BUG-L3 | ML-KEM proof-of-possession verification added to `confirm_key()` | ✅ FIXED |
| BUG-SPIN-1 | Race condition fixed in `get_or_create_instance()` (write lock first) | ✅ FIXED |
| BUG-AUTH-1/2 | Username validation added (max length, control chars) | ✅ FIXED |
| BUG-DNS-2 | Documentation updated - ECDSA NOT implemented (only Ed25519/RSA) | ✅ FIXED |
| BUG-PL-4 | AGENTS.override.md updated - `is_admin_required_for_tun` correctly returns false for Unix | ✅ FIXED |

---

## Remaining Work

The following items from review plans were identified but not yet implemented:

### HIGH Priority

| Item | Description | Review Plan |
|------|-------------|-------------|
| BUG-DNS-1 | HickoryRecursor DNSSEC Policy always SecurityUnaware even when `enable_dnssec=true` | `plans/dns_review_plan.md` |
| BUG-DNS-4 | HickoryResolver always returns `is_dnssec_validated: false` | `plans/dns_review_plan.md` |

### MEDIUM Priority

| Item | Description | Review Plan |
|------|-------------|-------------|
| BUG-DNS-3 | QueryCoalescer `max_wait_ms` parameter unused (DNS-2) | `plans/dns_review_plan.md` |
| BUG-HTTP-2 | HTTP/3 body collection inconsistent with HTTP/1.1 (no `collect_body_with_chunk_waf`) | `plans/http_server_review_plan.md` |
| BUG-PL-3 | Windows socket FD passing returns NotSupported (should document as known limitation) | `plans/platform_review_plan.md` |
| IMPROVE-1 | Consolidate HTTP/3 body collection with HTTP/1.1 streaming WAF | `plans/http_server_review_plan.md` |

### LOW Priority (Documentation/Enhancement)

| Item | Description | Review Plan |
|------|-------------|-------------|
| IMP-1 | Update `calculate_backoff` documentation (retry.rs vs doc) | `plans/proxy_review_plan.md` |
| IMP-2 | Update HTTP/2 status documentation (now configurable via `with_http2()`) | `plans/proxy_review_plan.md` |
| IMP-3 | Add `supports_seatbelt()` method to Platform enum | `plans/platform_review_plan.md` |
| BUG-SL-1 | `handle_serverless_function` only available with `mesh` feature (document limitation) | `plans/serverless_review_plan.md` |
| BUG-R2 | Inconsistent port resolution between methods in router.rs | `plans/routing_review_plan.md` |
| Various | Line number corrections in architecture documents | Multiple review plans |

---

## Known Limitations (Not Planned for Fix)

These items are documented limitations that are intentional or require architectural changes:

| Item | Description | Review Plan |
|------|-------------|-------------|
| HTTP2-POOL | HTTP/2 pooled connections not implemented (stub only) - requires hyper-util API redesign | `plans/plan.md` |
| SiteConnectionLimiter | Dead code - struct defined but never instantiated | `plans/waf_review_plan.md` |
| BUG-HTTP-4 | `request_body_size` double assignment in body collection | `plans/http_server_review_plan.md` |
| BUG-PROXY-1 | Latency EWMA weighting direction ambiguity (documentation vs implementation) | `plans/proxy_review_plan.md` |

---

## Cross-Reference Checklist

Subagents should verify these known references from AGENTS.md:

| Reference | Expected Location |
|-----------|-------------------|
| ConfigManager | `crates/synvoid-config/src/lib.rs:113` |
| BackendType enum | `src/router.rs:66-77` (11 variants) |
| StreamingWafCore | `src/waf/attack_detection/streaming.rs:129-134` |
| Quorum verification | `src/mesh/dht/signed.rs:860-934` |
| `collect_body_with_chunk_waf` | `src/http/server.rs:4662` |
| MeshProxy key routing | `src/mesh/proxy.rs:63` |
| MeshRaftNetwork::send_raw retry | `src/mesh/raft/network.rs:53-91` |
| DnsConfig.validate() | `crates/synvoid-config/src/main_config.rs:192-203` |

---

## Known Bugs from AGENTS.md (Verify Still Present/Fixed)

| Bug ID | Location | Issue | Status |
|--------|----------|-------|--------|
| BUG-L3 | `src/mesh/ml_kem_key_exchange.rs:204-265` | ML-KEM key exchange proof-of-possession | ✅ FIXED (025582ee) |
| BUG-ROUTER-1 | `src/router.rs:1318` | Hardcoded port 80 | ✅ FIXED (per review) |
| BUG-CORS-1 | `src/admin/mod.rs:860` | CORS config dropped | Known - may be intentional |
| HTTP2-POOL | `src/http_client/mod.rs:893` | HTTP/2 pooling incomplete | DEFERRED |

---

## Phase 6: Commit

After all subagents complete and stale items are identified:

1. Add all new review plan files: `git add plans/*_review_plan.md`
2. Remove stale architecture files if any identified
3. Commit with message: `Review: Add comprehensive architecture review plans`
4. Push to main

**Status**: ✅ Phase 6 completed (commit 025582ee)

---

(End of file)
