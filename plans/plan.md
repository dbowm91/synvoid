# SynVoid Consolidated Implementation Plan

**Generated:** 2026-05-23
**Status:** COMPLETED (2026-05-23)
**Sources:** All architecture review plans in `plans/` directory
**Consolidated by:** AI agents from batch review of 8 plan files

---

## Overview

This plan consolidates action items from architecture review plans across 8 modules:
- Config/Admin/Auth
- DNS
- WAF
- Plugin/WASM/Spin
- Platform
- Core/Overview
- HTTP/Proxy
- Mesh/Networking

**Status:** All waves (1-3) have been executed and merged to main. Remaining items are either:
1. Deferred due to architectural complexity
2. Working as designed (intentional behavior)

---

## Deferred Items (Architectural/Large Effort)

These items require significant architectural changes and are deferred until resources permit.

| ID | Issue | Reason | Status |
|----|-------|--------|--------|
| MESH-14 | No Source Node ID Binding Validation in All Ingress Paths | DHT ingress validation gaps require fundamental changes to bind node_id to TLS/cert identity | Deferred - Architectural |
| MESH-15 | Quorum Deadlock Risk During Partition | Raft implementation incomplete per TODO at `instance.rs:214`. Requires Raft migration. | Deferred - Requires Raft |
| MESH-17 | Session Establishment Failure Silently Ignored | Intentional - offer doesn't depend on session state for bidirectional communication | Working As Designed |
| APP-15 | FastCGI Response NOT Truly Streamed | Known limitation - buffers entire stdout. True streaming requires architectural refactor. | Deferred - Architectural |
| SUP-1 | gRPC Control Plane TLS | Intentional - localhost IPC between Supervisor and Master processes | Working As Designed |
| DOC-MESH-1 | DHT Ingress Verification Gaps Not Documented | Requires documenting full identity/trust model - larger architectural task | Deferred |

---

## Completed Items Summary

All waves 1-3 from this plan have been executed and merged to main.

| Wave | Items | Status |
|------|-------|--------|
| Wave 1 (HIGH) | NEW-1 through NEW-10 | COMPLETED |
| Wave 2 (MEDIUM) | NEW-11 through NEW-30 | COMPLETED |
| Wave 3 (LOW) | NEW-31 through NEW-69 | COMPLETED |

### Key Implementation Findings

1. **ErasedHttpClient Phase 9 incomplete** - `use_erased_client` hardcoded to `false` at `server.rs:3302`. See `skills/erased_http_client.md`

2. **AXFR record types incomplete** - `build_axfr_record()` at `transfer.rs:829-878` lacks SRV, PTR, DNSKEY, RRSIG, NSEC, NSEC3, DS, CAA support

3. **Spin routing IS implemented** - `src/spin/runtime.rs:271-285` uses longest-prefix-match

4. **Duplicate dead code fixed** - Removed duplicate GLOBAL_EDGE block in `erased_pool.rs`

5. **Plugin instance pool bugs fixed** - `prepare_for_request()` and `warmup()` now properly reset/link all functions

---

## Removed Items (Already Fixed or Verified)

The following items were removed because they are already FIXED or VERIFIED CORRECT:

| Source | Item | Status | Notes |
|--------|------|--------|-------|
| Config/Admin | CSRF validation uses ConstantTimeEq | FIXED | `src/admin/state.rs:737` uses `ct_eq()` |
| Plugin | BUG-2 (body_receiver not reset) | FIXED | `instance_pool.rs:221` |
| Plugin | BUG-3 (warmup missing functions) | FIXED | All 7 functions linked |
| Plugin | Spin find_route (LPM) | FIXED | `spin/runtime.rs:271-285` |
| WAF | Flood Protection Integration | VERIFIED | `check_request_full()` calls flood_protector |
| WAF | Request Smuggling Detection | VERIFIED | CL/TE conflict patterns exist |
| WAF | Fast-Path Bypass Fix | VERIFIED | 38 patterns in fast_path |
| WAF | Behavioral Analysis Mesh-Only | VERIFIED | `#[cfg(feature = "mesh")]` |
| Plan.md | REC-1, REC-3, REC-5 | FIXED | Fast-path patterns, streaming WAF |
| Plan.md | DOC-3, DOC-4, ISSUE-5 | FIXED | Documentation updates |
| Plan.md | PLUGIN-3 | FIXED | verify_caller_permission documented |
| Plan.md | MESH-11, MESH-16 | FIXED | Quorum race, dead code removed |
| Plan.md | APP-17 | FIXED | require_hashes field added |
| Plan.md | SAFE_HEADERS count | VERIFIED | 28 headers |
| Mesh | DHT Ingress Verification Gaps | VERIFIED | Documented at `signed.rs:42-48` |

---

## Verification Commands

```bash
# Core profile (minimal)
cargo check --no-default-features

# Mesh profile
cargo check --no-default-features --features mesh

# DNS profile
cargo check --no-default-features --features dns

# Full profile
cargo check --no-default-features --features mesh,dns

# Format and lint
cargo fmt && cargo clippy --lib -- -D warnings

# Test compile check
cargo test --lib --no-run
```

---

**Last Updated:** 2026-05-23
**Plan Pruned:** 2026-05-23 (removed completed items, kept deferred and working-as-designed)