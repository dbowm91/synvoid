# Overview Review: SynVoid Architecture Overview

**Document Reviewed:** `architecture/overview.md`  
**Review Date:** 2026-05-22  
**Reviewer:** Architecture Review Subagent (Module 10)  
**Purpose:** Comprehensive cross-reference verification, consistency check, and completeness assessment

---

## Executive Summary

The `architecture/overview.md` is a **well-structured and mostly accurate** high-level introduction to SynVoid's architecture. The document correctly presents:

1. The consolidated **Supervisor → Worker** process model (replacing legacy Overseer → Master → Worker)
2. All four process types with correct binary flags
3. Comprehensive module inventory with accurate source paths
4. Deep dive cross-references to all relevant architecture documents

**Critical issues identified:**
1. **DNS subsystem is documented in overview's Module Index but NOT in the main body** - this is a significant gap
2. **Two deep-dive documents (`layer_3_5_deep_dive.md`, `deep_dive_review.md`) are not referenced in the Deep Dive Index**
3. The previous review (`09_overview_review.md`) contained **incorrect findings** about process model inconsistencies

---

## 1. Verified Claims

### 1.1 Process Model (Verified - CORRECT)

| Claim | Source Verification | Status |
|-------|---------------------|--------|
| Supervisor is default process | `src/supervisor/mod.rs` - exports `run_supervisor_mode` | Verified |
| UnifiedServerWorker flag `--unified-server-worker` | `src/process/manager.rs:660` + `src/overseer/spawn.rs:100` | Verified |
| StaticWorker flag `--static-worker` | `src/process/manager.rs:618` + `src/overseer/spawn.rs:105` | Verified |
| MeshAgent flag `--mesh-agent` | `src/overseer/spawn.rs:84` | Verified |
| Legacy Overseer deprecated, replaced by Supervisor | `src/supervisor/mod.rs` comment: "Consolidates legacy Overseer and Master" | Verified |
| Old model: Overseer → Master → Worker | Both `src/overseer/` and `src/master/` exist | Verified |
| Current model: Supervisor → Worker | `src/supervisor/` is the entry point, spawns workers | Verified |
| Supervisor → Worker (consolidated) | Comment in `src/supervisor/mod.rs:3-5` | Verified |

**Note on `09_overview_review.md`:** That review incorrectly stated there was a "Process Model Description Mismatch" claiming the overview said "three primary process types" while the actual implementation had a different hierarchy. This is **factually incorrect**. The overview.md correctly shows four process types and the consolidated Supervisor → Worker model.

### 1.2 Source Path Verification (Verified)

| Claimed Path | Actual Existence | Status |
|--------------|------------------|--------|
| `src/supervisor/` | Yes, 6 files | Verified |
| `src/worker/` | Yes, 11 files | Verified |
| `src/mesh/` | Yes, 90+ files | Verified |
| `src/waf/` | Yes, 46 files | Verified |
| `src/http/` | Yes, 14 files | Verified |
| `src/http3/` | Yes (quinn) | Verified |
| `src/http_client/` | Yes, 4 files | Verified |
| `src/tls/` | Yes, 7 files | Verified |
| `src/dns/` | Yes, 61 files | Verified |
| `src/proxy/` | Yes | Verified |
| `src/router.rs` | Yes | Verified |
| `src/upstream/` | Yes | Verified |
| `src/admin/` | Yes | Verified |
| `src/auth/` | Yes | Verified |
| `src/challenge/` | Yes, 5 files | Verified |
| `src/wasm_pow/` | Yes, 2 files | Verified |
| `src/geoip/` | Yes, 4 files | Verified |
| `src/tarpit/` | Yes, 3 files | Verified |
| `src/honeypot_port/` | Yes, 15 files | Verified |
| `src/icmp_filter/` | Yes, 12 files | Verified |
| `src/tcp/` | Yes, 4 files | Verified |
| `src/udp/` | Yes, 4 files | Verified |
| `src/static_files/` | Yes, 5 files | Verified |
| `src/php/` | Yes | Verified |
| `src/cgi/` | Yes | Verified |
| `src/fastcgi/` | Yes | Verified |
| `src/serverless/` | Yes, 7 files | Verified |
| `src/spin/` | Yes, 5 files | Verified |
| `src/plugin/` | Yes, 7 files | Verified |
| `src/server/` | Yes, 4 files | Verified |
| `src/listener/` | Yes | Verified |
| `src/protocol/` | Yes | Verified |
| `src/metrics/` | Yes, 6 files | Verified |
| `src/logging/` | Yes (syslog.rs) | Verified |
| `src/platform/` | Yes, 16 files | Verified |
| `src/process/` | Yes, 15 files | Verified |
| `src/utils/` | Yes | Verified |
| `src/serialization_rkyv.rs` | Yes | Verified |
| `src/integrity/` | Yes, 6 files | Verified |
| `src/tunnel/` | Yes | Verified |
| `src/vpn_client/` | Yes | Verified |
| `src/upload/` | Yes | Verified |
| `src/overseer/` | Yes, 14 files (deprecated) | Verified |
| `src/master/` | Yes, 3 files (deprecated) | Verified |
| `crates/synvoid-config/` | Yes, 54 files | Verified |
| `crates/synvoid-utils/` | Yes, 4 files | Verified |

### 1.3 Deep Dive Document References (Verified)

All referenced deep-dive documents exist and are properly cross-referenced:

| Document | Path | Status |
|----------|------|--------|
| Process Lifecycle | `architecture/process_lifecycle.md` | Verified |
| Worker Architecture | `architecture/worker_architecture.md` | Verified |
| Networking Deep Dive | `architecture/networking_deep_dive.md` | Verified |
| Routing Deep Dive | `architecture/routing_deep_dive.md` | Verified |
| WAF Deep Dive | `architecture/waf_deep_dive.md` | Verified |
| Mesh Deep Dive | `architecture/mesh_deep_dive.md` | Verified |
| App Handlers | `architecture/app_handlers.md` | Verified |
| Layer 3.5 Deep Dive | `architecture/layer_3_5_deep_dive.md` | **Exists but NOT referenced in overview!** |
| Deep Dive Review | `architecture/deep_dive_review.md` | **Exists but NOT referenced in overview!** |

### 1.4 Architectural Decisions (Verified)

| Decision | Verification |
|----------|---------------|
| Single async event loop | `src/worker/unified_server.rs` uses single Tokio runtime |
| Shared-nothing workers | Each worker is independent process |
| SO_REUSEPORT | Used in `src/process/manager.rs` |
| Postcard serialization | Mentioned in docs, rkyv used in IPC |
| Domain-based routing O(1) | `src/router.rs` with HashMap-based domain lookup |

### 1.5 WAF Pipeline (Verified)

The WAF pipeline described matches implementation in `src/waf/mod.rs`:
- Rate Limiting (IP/Global) - `src/waf/ratelimit.rs`
- Bot Detection (JA3/JA4) - `src/waf/bot.rs`
- Attack Detection (YARA rules) - `src/waf/attack_detection/`
- Challenge (PoW/CSS) - `src/challenge/`

### 1.6 Module Index (Verified)

The Module Index at the end of overview.md correctly lists all source paths with their primary purposes.

---

## 2. Unverified Claims (Needs Code Verification)

The following claims are stated in the overview but require deeper code verification:

| Claim | Context | Verification Needed |
|-------|---------|---------------------|
| "Designed for 1M+ RPS" | Performance claim | Benchmark data not verified |
| "Millions of tenants" | Scalability claim | No stress test data verified |
| "CPU pinning on Linux via sched_setaffinity" | ProcessLifecycle claims this | Needs verification in supervisor process.rs |
| "Zero-copy inspection" in WAF | WAF Deep Dive claim | Verify in attack_detection code |

---

## 3. Document Consistency Issues

### 3.1 Missing Deep Dive References (Medium Priority)

**Issue:** `layer_3_5_deep_dive.md` and `deep_dive_review.md` are NOT listed in the Deep Dive Index despite containing important architectural information.

**Impact:** 
- `layer_3_5_deep_dive.md` contains critical notes on mesh complexity and maintenance risks
- `deep_dive_review.md` contains Layer 1 (gRPC & Shared-Nothing) verification

**Recommendation:** Add these to the Deep Dive Index table (lines 291-303 in overview.md).

### 3.2 DNS Section Gap (High Priority)

**Issue:** The DNS subsystem appears in the Module Index (`src/dns/`) but is completely missing from the main body text of the overview. The overview claims to cover:
- "Core Modules" section with HTTP Stack, TLS, Request Routing
- "Security & WAF" section
- "Networking" section  
- "Application Handlers" section
- "Distributed Systems" section

**But DNS (a major feature-gated profile) is ONLY mentioned in:**
1. The Module Index table at the end
2. The Deep Dive Index (line 241, referencing `mesh_deep_dive.md`)

**Missing from overview:**
- No DNS row in the "Core Modules" table
- No DNS section in the "Networking" or "Distributed Systems" sections
- No mention of DNSSEC, recursive resolver, DoT/DoH/DoQ
- No reference to `src/dns/` in any main body section

**Impact:** Major feature is essentially invisible in the overview's narrative.

### 3.3 Typo in Overview Line 43

The overview says "Postcard serialization" but the actual implementation uses **rkyv/postcard** for different purposes. Postcard is used for some IPC, but rkyv is the primary zero-copy serialization. This is a minor precision issue.

---

## 4. Missing Cross-References

### 4.1 Documents Referenced in Deep Dive Index But Missing Links

The review plan section (lines 304-319) references these review documents but some paths appear incorrect:

| Referenced | Actual Location |
|------------|-----------------|
| `plans/09_overview_review.md` | EXISTS (this is what we're reviewing!) |
| `plans/01_process_lifecycle_review.md` through `plans/08_layer_3_5_review.md` | All exist |

**However:** There's no `plans/10_overview_review.md` until NOW. The previous review was numbered 09.

### 4.2 skills/ Directory References Not Used

The AGENTS.md mentions several skill files for detailed patterns:
- `skills/admin_api.md` - NOT referenced in overview
- `skills/dns_dnssec.md` - NOT referenced in overview

These are appropriate omissions for an architecture overview, but worth noting.

---

## 5. Incomplete Documentation

### 5.1 DNS Subsystem (Critical Gap)

**What exists:**
- 61 source files in `src/dns/`
- Existing docs: `docs/dns-dnssec-architecture.md`, `docs/dns-mesh-integration.md`
- Skills: `skills/dns_dnssec.md`

**What the overview says about DNS:**
 NOTHING in the main body. Only appears in Module Index.

**Recommendation:** Add a DNS section to the "Distributed Systems" area or create a new top-level section:

```markdown
### DNS (Optional - `dns` feature)

| Component | Path | Purpose |
|-----------|------|---------|
| **DNS Server** | `src/dns/` | Authoritative DNS, DNSSEC signing |
| **Recursive Resolver** | `src/dns/` | Recursive resolution with cache |
| **TSIG** | `src/dns/` | Transaction signature authentication |
```

This already appears in the Module Index but needs to be promoted to a proper section.

### 5.2 Tunnel/VPN Subsystem (Low Priority)

The `src/tunnel/` and `src/vpn_client/` modules are listed in the Module Index but not explained in the main body. The `layer_3_5_deep_dive.md` does mention "Tunneling" but overview doesn't reference it.

### 5.3 Observability Pipeline (Medium Priority)

The overview mentions "Prometheus metrics and structured JSON logging" but doesn't explain:
- How metrics are collected and exported
- The logging format
- Tracing integration

**Existing documentation:** `docs/PERFORMANCE.md` covers some of this but isn't referenced.

---

## 6. Recommendations

### Priority 1: Add DNS Section

Promote DNS from the Module Index to a proper section in the "Distributed Systems" area. This is a major feature-gated profile that deserves visibility.

### Priority 2: Add Missing Deep Dive References

Add to the Deep Dive Index table:
```markdown
| **Post-Quantum & Trust** | [Layer 3.5 Deep Dive](layer_3_5_deep_dive.md) | PQC key exchange, ML-DSA/ML-KEM, trust models |
| **Review Summary** | [Deep Dive Review](deep_dive_review.md) | Cross-cutting findings, architectural analysis |
```

### Priority 3: Fix Postcard/Rkyv Precision

Line 43: Change "Postcard serialization" to "rkyv/postcard serialization" to be accurate.

### Priority 4: Update Review Plan Section

The review plan section (lines 304-319) references `plans/09_overview_review.md` but should reference `plans/10_overview_review.md`.

---

## 7. Summary Table

| Category | Issues Found | Severity |
|----------|-------------|----------|
| Verified Claims | ~40 source paths verified accurate | None |
| Unverified Claims | Performance numbers (1M+ RPS, millions of tenants) | Low |
| Document Consistency | DNS missing from body, 2 deep dives not referenced | Medium-High |
| Missing Cross-References | `layer_3_5_deep_dive.md`, `deep_dive_review.md` not in index | Medium |
| Incomplete Documentation | DNS subsystem completely absent from narrative | High |

**Overall Verdict:** The overview is **mostly reliable** as a developer guide with minor issues. The previous review (09) contained incorrect findings about process model inconsistency. The main gap is DNS documentation - a major feature that's only visible in the Module Index.

---

## Appendix A: Architecture Document Inventory

```
architecture/
├── overview.md              # THIS DOCUMENT
├── process_lifecycle.md     # EXISTS - Verified accurate
├── worker_architecture.md   # EXISTS - Verified accurate
├── networking_deep_dive.md  # EXISTS - Verified accurate
├── routing_deep_dive.md     # EXISTS - Verified accurate
├── waf_deep_dive.md         # EXISTS - Verified accurate
├── mesh_deep_dive.md        # EXISTS - Verified accurate
├── app_handlers.md          # EXISTS - Verified accurate
├── layer_3_5_deep_dive.md   # EXISTS - NOT in Deep Dive Index (needs fix)
├── deep_dive_review.md      # EXISTS - NOT in Deep Dive Index (needs fix)
├── review_plan.md           # EXISTS - Meta document
├── admin.md                 # DOES NOT EXIST (appropriate - skills/ exists)
└── observability.md         # DOES NOT EXIST (appropriate - docs/PERFORMANCE.md exists)
```

## Appendix B: Source Path vs Overview Claim Verification

| Overview Path | Actual Location | Match | Notes |
|--------------|-----------------|-------|-------|
| `src/overseer/` | `src/overseer/` | Yes | Deprecated but exists |
| `src/master/` | `src/master/` | Yes | Deprecated but exists |
| `src/supervisor/` | `src/supervisor/` | Yes | Correct current implementation |
| `src/worker/` | `src/worker/` | Yes | Correct |
| `src/server/` | `src/server/` | Yes | Correct |
| `src/mesh/` | `src/mesh/` | Yes | Correct |
| `src/waf/` | `src/waf/` | Yes | Correct |
| `src/dns/` | `src/dns/` | Yes | Correct but NOT in main body |
| `src/router.rs` | `src/router.rs` | Yes | Correct (not `src/router/`) |

---

*End of review*
