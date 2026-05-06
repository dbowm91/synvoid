# Overview Review: SynVoid Architectural Overview

**Document Reviewed:** `architecture/overview.md`  
**Review Date:** 2026-05-06  
**Reviewer:** Architecture Review Subagent (Module 9)  
**Purpose:** Verify consistency, accuracy, and completeness for new developer onboarding

---

## Executive Summary

The `architecture/overview.md` provides a reasonable high-level introduction to SynVoid's architecture but has **significant gaps** that undermine its reliability as a developer guide. Critical issues include:

1. **Two missing referenced documents** (`admin.md`, `observability.md`)
2. **DNS subsystem entirely absent** despite being a major feature-gated profile
3. **Source path inconsistencies** between documentation and actual codebase
4. **Multiple cross-references to non-existent files**

---

## 1. Verified Cross-References

The following links point to documents that **exist and are accurate**:

| Reference | Target | Status |
|-----------|--------|--------|
| `process_lifecycle.md` | `architecture/process_lifecycle.md` | Verified |
| `worker_architecture.md` | `architecture/worker_architecture.md` | Verified |
| `networking_deep_dive.md` | `architecture/networking_deep_dive.md` | Verified |
| `routing_deep_dive.md` | `architecture/routing_deep_dive.md` | Verified |
| `waf_deep_dive.md` | `architecture/waf_deep_dive.md` | Verified |
| `mesh_deep_dive.md` | `architecture/mesh_deep_dive.md` | Verified |
| `app_handlers.md` | `architecture/app_handlers.md` | Verified |

**Source paths in the Detailed Component Documentation Index table:**

| Component | Claimed Path | Actual Path | Status |
|-----------|-------------|-------------|--------|
| Process Lifecycle | `src/overseer/`, `src/master/` | `src/overseer/` present, `src/master/` present | Verified |
| Unified Worker | `src/worker/`, `src/server/` | `src/worker/` present, `src/server/` present | Verified |
| Networking | `src/listener/`, `src/http/`, `src/http3/` | All exist | Verified |
| Security | `src/waf/`, `src/filter/`, `src/challenge/` | All exist | Verified |
| Mesh | `src/mesh/` | present | Verified |
| Routing | `src/router/`, `src/upstream/` | `src/router.rs` exists, `src/upstream/` exists | Verified |
| App Handlers | `src/static_files/`, `src/php/`, `src/serverless/` | All exist | Verified |

---

## 2. Outdated / Non-Existent References

### 2.1 Missing Documents (Critical)

| Referenced File | Status | Actual Location |
|-----------------|--------|-----------------|
| `admin.md` | Does NOT exist | Admin API: `skills/admin_api.md`, `skills/admin_ui.md`, `docs/ADMIN_UI.md` |
| `observability.md` | Does NOT exist | Metrics/Logging: `docs/PERFORMANCE.md`, `docs/ARCHITECTURE.md` |

**Impact:** New developers clicking these links will encounter 404 errors, breaking their onboarding experience.

### 2.2 Source Path Inconsistencies (Medium)

| Document | Claimed Path | Actual Path | Issue |
|----------|-------------|-------------|-------|
| `process_lifecycle.md` (Master key logic) | `src/startup/master.rs` | `src/master/mod.rs` | Line 29 of `process_lifecycle.md` references `src/startup/master.rs` which does not exist |

---

## 3. Missing Documentation

### 3.1 DNS Subsystem (Critical Gap)

The overview **does not mention the DNS subsystem at all**, despite:

- DNS being a **first-class feature-gated profile** (`--features dns`)
- `AGENTS.md` explicitly references `src/dns/AGENTS.override.md` for DNS patterns
- `src/dns/` contains **57 Rust files** implementing:
  - Authoritative DNS server
  - Recursive resolver (Hickory)
  - DNSSEC validation and signing
  - RFC 5011 trust anchor management
  - TSIG authentication
  - DNS-over-TLS (DoT), DNS-over-HTTPS (DoH), DNS-over-QUIC (DoQ)
  - Mesh-integrated DNS (anycast, DHT sync)

**Existing DNS documentation:**
- `docs/dns-dnssec-architecture.md`
- `docs/dns-mesh-integration.md`
- `docs/RFC5011_TRUST_ANCHOR.md`
- `skills/dns_dnssec.md`

**Recommendation:** Add a new section to the overview:
```
### 8. DNS Server & DNSSEC
- **[DNS Server & DNSSEC](dns_deep_dive.md)**: Authoritative DNS, recursive resolver, DNSSEC, DoT/DoH/DoQ
```
And create `architecture/dns_deep_dive.md` cross-referencing the existing `docs/` files.

### 3.2 Tunnel/Proxy Subsystem (Medium)

The `src/tunnel/` module (containing `proxy.rs` and `router.rs`) is not documented in the overview. This subsystem handles QUIC tunnels and is mentioned in `routing_deep_dive.md` as a backend type ("QuicTunnel").

### 3.3 Observability Details (Medium)

The overview mentions "Prometheus metrics and structured JSON logging" but:
- No architecture document details the observability pipeline
- No `observability.md` exists in `architecture/`
- Logging format, metrics exporters, and tracing are undocumented architecturally

### 3.4 Configuration System (Low)

The `src/config/` module is not documented, despite being a core subsystem that all developers need to understand.

---

## 4. Inconsistencies

### 4.1 Deep Dive Documents Not Referenced

The architecture folder contains two documents the overview does not mention:

| Document | Purpose | Missing From Overview |
|----------|---------|----------------------|
| `layer_3_5_deep_dive.md` | Cross-cutting PQC, trust models, peer communication | Yes |
| `deep_dive_review.md` | Review of layers 1, 2, 3, 7 | Yes |

These are advanced documents, but they contain architectural decisions new developers should be aware of (e.g., "mesh complexity is the greatest long-term maintenance risk").

### 4.2 Process Model Description Mismatch

**Overview says:**
> "The system is organized around three primary process types"

**Actual implementation (from `process_lifecycle.md`):**
- Overseer (1 per deployment)
- Master (1 per instance)  
- **Two worker types**: UnifiedServerWorker + StaticWorker

The overview's "Bird's Eye View" section 1 correctly lists "Process Lifecycle & Execution Model" but the summary table in section 1.1 only mentions Unified Server Worker, not Static Worker.

### 4.3 WAF Key Logic Paths

The `waf_deep_dive.md` references `src/waf/`, `src/filter/`, `src/challenge/`. While these directories exist, the actual WAF core logic is at `src/waf/attack_detection/` and `src/waf/core.rs`. This is a minor precision issue.

---

## 5. Completeness Assessment

### What the Overview Covers Well:

| Subsystem | Coverage | Notes |
|-----------|----------|-------|
| Process Model | Good | Overseer -> Master -> Worker hierarchy explained |
| Worker/Unified Server | Good | Protocol support, event loop, components |
| Networking | Good | HTTP/1, HTTP/2, HTTP/3, TLS, PQC |
| Routing | Good | Matching hierarchy, upstream types, load balancing |
| WAF | Good | Protection layers, attack detection, bot detection |
| Mesh | Good | DHT, QUIC, threat intelligence, collective defense |
| App Handlers | Good | Static files, PHP-FPM, Granian, WASM |

### What the Overview Misses:

| Subsystem | Severity | Impact |
|-----------|----------|--------|
| DNS/DNSSEC | Critical | Major feature completely undocumented |
| Observability | Medium | Developers cannot understand metrics/logging |
| Tunnel/Proxy | Low | Edge case but may be needed by some developers |
| Configuration | Low | Hot-reload, validation not explained |
| Plugins/WASM ABI | Low | `docs/WASM-ABI.md` exists but not referenced |

---

## 6. Recommendations

### Priority 1: Fix Broken Links

Update paths in overview.md:

```markdown
# Change these lines in overview.md:
- **[Admin API & UI](admin.md)** -> **[Admin API & UI](../skills/admin_ui.md)**
- **[Metrics & Logging](observability.md)** -> **[Metrics & Logging](../docs/PERFORMANCE.md)**
```

### Priority 2: Add DNS Section

Add DNS to the Bird's Eye View and Detailed Component Index:

```markdown
### 8. DNS Server & DNSSEC
- **[DNS Server & DNSSEC](dns_deep_dive.md)**: Authoritative DNS, recursive resolver, DNSSEC validation, DoT/DoH/DoQ
```

Create `architecture/dns_deep_dive.md` that cross-references existing `docs/` files.

### Priority 3: Fix Source Path Error

In `process_lifecycle.md` line 29:
- Change: `src/startup/master.rs`
- To: `src/master/mod.rs`

### Priority 4: Add Missing References

Add `layer_3_5_deep_dive.md` and `deep_dive_review.md` to overview as "Advanced Topics" or cross-reference them where relevant (e.g., Mesh section mentions complexity).

---

## 7. Summary Table

| Category | Issues Found | Critical |
|----------|-------------|----------|
| Verified Cross-References | 7/9 accurate | N/A |
| Outdated/Non-existent References | 2 broken links, 1 wrong path | Yes |
| Missing Documentation | DNS subsystem, observability details, tunnel subsystem | Yes |
| Inconsistencies | 2 deep dives not referenced, process model imprecision | Medium |
| Completeness | Covers core subsystems but misses DNS | Yes |

**Overall Verdict:** The overview is **partially reliable** as a developer guide. It covers the core subsystems accurately but fails to mention DNS entirely, has broken internal links, and lacks references to advanced but important cross-cutting concerns documented in `layer_3_5_deep_dive.md` and `deep_dive_review.md`.

---

## Appendix: File Inventory

### Architecture Documents Inventory

```
architecture/
├── overview.md              # This document
├── process_lifecycle.md     # Exists
├── worker_architecture.md   # Exists
├── networking_deep_dive.md  # Exists
├── routing_deep_dive.md     # Exists
├── waf_deep_dive.md         # Exists
├── mesh_deep_dive.md        # Exists
├── app_handlers.md          # Exists
├── layer_3_5_deep_dive.md   # Exists (not referenced in overview)
├── deep_dive_review.md      # Exists (not referenced in overview)
├── review_plan.md           # Exists (meta-doc)
├── admin.md                 # MISSING
└── observability.md         # MISSING
```

### Source Paths Referenced in Overview vs Actual

| Overview Path | Actual Location | Match |
|--------------|-----------------|-------|
| `src/overseer/` | `src/overseer/` | Yes |
| `src/master/` | `src/master/` | Yes |
| `src/startup/master.rs` | `src/master/mod.rs` | No |
| `src/worker/` | `src/worker/` | Yes |
| `src/server/` | `src/server/` | Yes |
| `src/listener/` | `src/listener/` | Yes |
| `src/http/` | `src/http/` | Yes |
| `src/http3/` | `src/http3/` | Yes |
| `src/waf/` | `src/waf/` | Yes |
| `src/filter/` | `src/filter/` | Yes |
| `src/challenge/` | `src/challenge/` | Yes |
| `src/mesh/` | `src/mesh/` | Yes |
| `src/router/` | `src/router.rs` | Yes (slight name difference) |
| `src/upstream/` | `src/upstream/` | Yes |
| `src/static_files/` | `src/static_files/` | Yes |
| `src/php/` | `src/php/` | Yes |
| `src/serverless/` | `src/serverless/` | Yes |
| `src/dns/` | `src/dns/` | Yes (exists but NOT referenced in overview!) |
