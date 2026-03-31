# Deferred Items from plan.md

> Last updated: 2026-03-31
> Based on review of current codebase state

---

## Phase 2: Security Fixes

### 2.3 Plaintext Token Handling

`src/admin/auth.rs:25-31` — currently returns `false` and logs an error. No migration implemented.

| # | Task | File |
|---|------|------|
| 1 | Implement plaintext token migration OR return clear error | `src/admin/auth.rs` |

**Status**: Not started

---

### 2.5 Audit Unsafe Code Blocks ⏸ DEFERRED

82 unsafe blocks need safety review. Key areas:
- Plugin loading (`src/plugin/axum_loader.rs:106`)
- TLS verification bypass
- Daemonization (`src/main.rs:666`)
- Zero-copy sendfile (`src/zero_copy.rs:61`)

**Status**: Deferred (requires significant time investment)

---

### 2.6 Upgrade LightningCSS ⏸ DEFERRED

Using alpha `lightningcss` 1.0.0-alpha.71. Update to stable if available.

**Status**: Deferred (waiting on stable release)

---

## Phase 5: Code Quality — Clippy & File Splits

### 5.2 Split Oversized Files (target: <1,500 lines each)

| File | Current Lines | Split Strategy | Status |
|------|---------------|----------------|--------|
| `src/admin/handlers/config.rs` | 2,168 | → `config_site.rs`, `config_dns.rs`, `config_global.rs` | ⏸ Deferred |
| `src/http/server.rs` | 2,105 | → `server_connection.rs`, `server_routing.rs`, `server_error.rs` | ⏸ Deferred |
| `src/process/manager.rs` | 2,050 | → `manager_spawn.rs`, `manager_lifecycle.rs`, `manager_ipc.rs` | ⏸ Deferred |

**Status**: Deferred (splitting fights the codegen/structure)

---

### 5.5 Clean Up `#[allow(dead_code)]`

Original target: ~58 annotations.

**Current state**: 83 annotations (not 120 as previously stated). Many have explanatory comments for future use cases.

**Status**: Partial (83 remaining, may be acceptable)

---

## Phase 8: DNS — Mesh Integration

### 8.1 Mesh DNS Signing (NOT DONE - verification complete)

The plan says tasks 3-4 are deferred:
- `derive_dns_signing_key()` exists in `src/dns/mesh_sync/mod.rs:376` ✅
- `MeshSigningKey` struct exists at line 352 ✅
- BUT `resolve_from_mesh` does NOT pass signing context to `build_response`
- `build_response` in `src/dns/server/response.rs:10` uses `ZoneSigningKey`, not `MeshSigningKey`

| # | Task | File |
|---|------|------|
| 1 | Pass mesh signing context to resolve_from_mesh caller | `src/dns/server/query.rs` |
| 2 | Update build_response to accept MeshSigningKey | `src/dns/server/response.rs` |

**Status**: Not started

---

### 8.4 Anycast Node Authentication (depends on 8.2)

`src/dns/mesh_sync/dht.rs:118` has placeholder code that warns "No record verifier available, cannot verify anycast node signature".

| # | Task | File |
|---|------|------|
| 1 | Implement record verifier for anycast DHT records | `src/dns/mesh_sync/verification.rs` |
| 2 | Verify publisher is global node | `src/dns/mesh_sync/dht.rs` |

**Status**: Not started

---

### 8.6 Global Node-Based Recursive Resolution ✅ DONE

`src/dns/resolver_global.rs` exists (GlobalNodeResolver) and is wired into recursive server at `src/dns/recursive.rs:112-121`.

**Status**: Done

---

### 8.7 Unified DNSSEC Architecture

- `DnsSecValidator` trait exists at `src/dns/dnssec_validation.rs:352`
- `MeshTrustAnchorAdapter` exists at line 389
- `MeshDnsSecValidator` exists at `src/dns/mesh_dnssec.rs:25` (separate implementation, not wired as `DnsSecValidator`)

**Status**: Partial (trait exists, but mesh validator not integrated into recursive server as trait impl)

---

### 8.8 Formalize Global Node CA

- `ca_mode` config flag exists in `src/mesh/config.rs:1271`
- CRL generation exists in `src/mesh/cert.rs:693`
- Root CA certificate export endpoint not implemented

| # | Task | File |
|---|------|------|
| 1 | Add root CA certificate export endpoint | `src/admin/handlers/mesh.rs` |

**Status**: Partial (CA mode + CRL done, endpoint missing)

---

### 8.10 QNAME Minimization ⏸ DEFERRED

External dependency on hickory-resolver RFC 7816 support.

**Status**: Deferred (external dependency)

---

## Phase 10: Admin Panel — Missing Pages & UX

### 10.4 Usability Improvements — Keyboard Shortcuts ⏸ DEFERRED

| # | Task | Status |
|---|------|--------|
| 8 | Keyboard shortcuts (Ctrl+S, Ctrl+R, Esc) | ⏸ Deferred |

**Status**: Deferred (low priority)

---

### 10.6 Dynamic Form Generator (Long-term)

Build `DynamicForm` component that fetches `/api/config/schema` and renders forms automatically.

**Status**: Long-term backlog

---

### 10.7 Accessibility & i18n (Long-term)

ARIA labels, keyboard navigation, screen-reader text, i18n framework, RTL support, WCAG AA contrast.

**Status**: Long-term backlog

---

## Summary

| Category | Items | Status |
|----------|-------|--------|
| Security | 3 | 1 not started, 2 deferred |
| Code Quality | 2 | 1 partial (83 vs target 58), 1 deferred |
| DNS Mesh | 4 | 2 need verification, 1 partial, 1 deferred |
| Admin UX | 3 | 1 deferred, 2 long-term |
| **Total** | **12** | |

---

## Verification Needed

1. **8.1 (Mesh DNS Signing)** — Does `resolve_from_mesh` pass signing context to `build_response`?
2. **8.6 (Global Node Recursive)** — Is `GlobalNodeResolver` wired into recursive server?
3. **8.7 (Unified DNSSEC)** — Is `DnsSecValidator` trait used throughout?

Run verification commands:
```bash
# 8.1
rg 'MeshSigningKey|derive_dns_signing' src/dns/server/query.rs

# 8.6  
rg 'GlobalNodeResolver|resolver_global' src/dns/recursive.rs

# 8.7
rg 'DnsSecValidator' src/dns/recursive.rs src/dns/server/mod.rs
```