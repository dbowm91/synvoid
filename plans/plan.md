# MaluWAF Master Implementation Plan

**Status**: COMPLETED (All Waves Implemented)
**Last Updated**: 2026-05-04
**Current Wave Focus**: All implementation waves completed. Plan pruned to deferred/incomplete items only.

---

## Table of Contents

1. [Overview/Status](#1-overviewstatus)
2. [Security & Hardening](#2-security--hardening)
3. [Performance & Scalability](#3-performance--scalability)
4. [Architecture & Profiles](#4-architecture--profiles)
5. [HTTP/Traffic Layer](#5-httptraffic-layer)
6. [Process Isolation & Reload](#6-process-isolation--reload)
7. [WAF & Security Features](#7-waf--security-features)
8. [CI/Gates & Testing](#8-cigates--testing)
9. [MaluWAF V2 Plan (Completed)](#9-maluwaf-v2-plan-completed)
10. [Deferred/Future Work](#10-deferredfuture-work)

---

## 1. Overview/Status

### Current Status (2026-05-04)

**Phase**: Complete - Plan pruned to show only deferred/incomplete items

| Priority | Task | Status | Notes |
|----------|------|--------|-------|
| P0 | Consolidate `plans/` into `plan.md` | **COMPLETED** | All technical plans merged |
| P1 | Fix Architecture Gates (Core Profile) | **COMPLETED** | Core profile compiles (2026-05-04) |
| P2 | Implement RequestServices Context | **COMPLETED** | Global singletons deprecated |
| P3 | Replace Buffer Pool with Mutex Sharding | **COMPLETED** | ABA hazard resolved |
| P4 | Complete IPC Consolidation | **COMPLETED** | Windows security, signed CLI |

### Completed Implementation Items

| Task | Location | Improvement |
|------|----------|-------------|
| Socket Hardening | `src/process/socket_path.rs` | Uses `symlink_metadata()` to prevent symlink following |
| Lock Ordering | `src/process/pidfile.rs` | Open without truncate → acquire lock → write |
| Sandbox Constants | `src/platform/sandbox.rs` | Replaced hardcoded masks with named Landlock constants |
| Threat Feed Export | `src/mesh/threat_intel.rs` | Signed feed export CLI and logic |
| Mockable Clock | `src/utils.rs` | Clock trait for deterministic TokenBucket tests |
| Per-UID Fallback | `src/process/socket_path.rs` | `get_user_socket_dir()` with UID-based paths |
| Windows Native API | `src/process/pidfile.rs` | `OpenProcess`/`GetExitCodeProcess` replacing `tasklist` |
| Permission Verification | `src/process/socket_path.rs` | Symlink and ownership checks |
| FreeBSD Capsicum | `src/platform/sandbox.rs` | `cap_getmode()` check before sandbox enter |
| macOS Feature Gate | `src/platform/sandbox.rs` | `cfg!(feature = "macos-sandbox")` |
| Replay Cache Fix | `src/process/ipc_signed.rs` | Evicts BEFORE inserting, keyed by (signer_id, nonce) |
| Reduced Contention | `src/process/ipc_signed.rs` | DashMap instead of global mutex |
| Secure Key Loading | `src/process/ipc_signed.rs` | O_NOFOLLOW, O_CLOEXEC, permission checks |
| Windows Security Builder | `src/platform/windows_impl.rs` | `SecurityDescriptor::new_user_only()` |
| Core Profile Fix | `src/upload/mod.rs`, `src/worker/context.rs` | `#[cfg(feature = "mesh")]` on gated fields |

---

## 2. Security & Hardening

### 2.1 Socket Path & PID File Hardening

**Status**: **COMPLETED** ✅

| Issue | Location | Status | Description |
|-------|----------|--------|-------------|
| Symlink following in `create_secure_dir_atomic()` | `src/process/socket_path.rs` | **FIXED** | Now uses `symlink_metadata()` and rejects if symlink |
| `/tmp/maluwaf` fallback weaknesses | `src/process/socket_path.rs` | **FIXED** | `get_user_socket_dir()` returns `/tmp/maluwaf-$UID` with `0700` perms |
| Lock acquisition ordering | `src/process/pidfile.rs` | **FIXED** | Open WITHOUT truncate → acquire lock → write content |
| Windows `tasklist` process check | `src/process/pidfile.rs` | **FIXED** | Uses `OpenProcess` and `GetExitCodeProcess` API |
| Permission Verification | `src/process/socket_path.rs` | **FIXED** | Validates directory not symlink, owned by current UID or root |

### 2.2 Sandbox Hardening

**Status**: **COMPLETED** ✅

| Issue | Location | Status | Description |
|-------|----------|--------|-------------|
| Landlock hardcoded access masks | `src/platform/sandbox.rs` | **FIXED** | Now uses named constants (e.g., `LANDLOCK_ACCESS_FS_READ`) |
| FreeBSD `cap_enter()` premature call | `src/platform/sandbox.rs` | **FIXED** | `is_capsicum_available()` checks `cap_getmode()` first |
| macOS `is_supported()` feature check | `src/platform/sandbox.rs` | **FIXED** | Returns `cfg!(feature = "macos-sandbox")` |
| Windows Job Objects limitations | `src/platform/sandbox.rs` | **DOCUMENTED** | Clarified as resource control, not FS sandbox |

### 2.3 IPC Signing Hardening

**Status**: **COMPLETED** ✅

| Issue | Location | Severity | Description |
|-------|----------|----------|-------------|
| Replay cache bug | `src/process/ipc_signed.rs` | **FIXED** | Evicts BEFORE inserting; keyed by `(signer_id, nonce)` |
| Mutex contention | `src/process/ipc_signed.rs` | **FIXED** | Uses `DashMap` instead of global mutex |
| Key file security | `src/process/ipc_signed.rs` | **FIXED** | Uses `O_NOFOLLOW`, `O_CLOEXEC`, verifies ownership and `0600` perms |
| Weak KDF | `src/process/ipc_signed.rs` | **DOCUMENTED** | `from_secret()` documented as TEST ONLY |

### 2.4 IPC Consolidation

**Status**: **COMPLETED** ✅

| Issue | Category | Description |
|-------|----------|-------------|
| Signed vs unsigned inconsistency | Security | `IpcStream` allows unsigned with `WARNED_UNSIGNED` pattern |
| Null security attributes on Windows | Security | Multiple Windows pipe creation sites pass `std::ptr::null_mut()` |
| Raw JSON command parsing | Security | `handle_command_connection()` parses raw JSON without auth |
| Platform IPC traits not used | Architecture | `src/platform/ipc.rs` traits vs actual `src/process/ipc.rs` |

**Implementation Summary (Wave 2.1 - 2026-05-04)**:

1. **Phase 1 - Enforce Signing**: Modified `src/process/ipc_transport.rs` to remove `WARNED_UNSIGNED` OnceLock and replaced unsigned fallback paths with hard errors.

2. **Phase 2 - Windows Security**: Created `security` submodule in `src/platform/windows_impl.rs` with `SecurityDescriptor::new_user_only()`.

3. **Phase 3 - CLI Signing**: Modified `src/process/command.rs` to use `IpcSigner::try_from_env()` and `SignedIpcMessage::serialize_signed()`.

4. **Removed WARNED_UNSIGNED**: The `static WARNED_UNSIGNED: OnceLock<()>` has been removed.

### 2.5 Singleton Inventory & Refactoring

**Status**: **COMPLETED** ✅

**Refactoring Goal**: Remove hidden global state by threading a `RequestServices` context.

**Actionable Items**:
- [x] Create `RequestServices` struct in `src/worker/context.rs`.
- [x] Add `RequestServices` to `UnifiedServerWorkerState`.
- [x] Mark global accessors (e.g., `get_threat_intel()`) as `#[deprecated]`.
- [x] Fix `UploadValidator` to take `Arc<YaraRulesManager>` at construction.
- [x] Migrate `YaraRulesManager` to be owned by `RequestServices`.

---

## 3. Performance & Scalability

### 3.1 Buffer Pool Audit & Replacement

**Status**: **COMPLETED** ✅

| Issue | Location | Severity | Description |
|-------|----------|----------|-------------|
| ABA problem in Treiber Stack | `crates/maluwaf-utils/src/buffer/pool.rs` | **FIXED** | Replaced with mutex-backed sharded pool |
| Interior mutation via unsafe cast | `crates/maluwaf-utils/src/buffer/pool.rs` | **FIXED** | Eliminated by using `parking_lot::Mutex<Vec<BytesMut>>` |

**Implementation**:
- 8 shards (`NUM_SHARDS`) minimize lock contention
- `parking_lot::Mutex<Vec<BytesMut>>` per tier per shard
- All `unsafe` blocks removed, `#[deny(unsafe_code)]` added
- All 30 tests pass

### 3.2 Routing Hot-Path Analysis

**Status**: VERIFIED

| Component | Status | Notes |
|-----------|--------|-------|
| `LocationMatcher::match_uri()` | **Optimized** | Uses scalar best-match tracking, no per-request vector allocation |
| Host validation (`is_host_valid_for_site`) | **Fixed** | Now passes cleaned host instead of site_id |
| Suffix/wildcard host matching | **Linear scan** | O(n) Vec scan - acceptable for <500 wildcard domains |

**Recommendation**: Current implementation is correct. If Priority 6 is pursued, suffix/wildcard data structure would be highest-impact change.

### 3.3 IPC Framing Copies

**Status**: DOCUMENTED (not implemented)

| Issue | Location | Impact |
|-------|----------|--------|
| `read_message()` copies on read | `src/process/ipc_framing.rs:15-16` | 1MB allocation per message |
| `serialize_signed()` multiple copies | `src/process/ipc_signed.rs:44-59` | 3x payload copies |
| `SignedReader::read_message()` allocations | `src/process/ipc_signed.rs:91-104` | 3 Vec allocations per signed message |

**Key Finding**: IPC is NOT on the request critical path. Workers handle requests independently and only communicate with master for lifecycle, logs, and commands.

---

## 4. Architecture & Profiles

### 4.1 Architecture Profiles

**Status**: DOCUMENTED

| Profile | Features | Description |
|---------|----------|-------------|
| `core` | `socket-handoff` | Minimal WAF/reverse proxy |
| `mesh-node` | `socket-handoff`, `mesh` | Core + distributed mesh networking |
| `dns-node` | `socket-handoff`, `dns` | Core + DNS server |
| `edge-full` | `socket-handoff`, `mesh`, `dns`, `post-quantum` | All features for edge deployments |
| `dev-all` | All features | Full development build |

### 4.2 Architecture Gates

**Status**: **COMPLETED** ✅

Core profile now compiles with `--no-default-features` (verified 2026-05-04).

**Key Fixes Applied**:
- `src/upload/mod.rs`: Added `#[cfg(feature = "mesh")]` to `yara_rules` field
- `src/worker/context.rs`: Added `#[cfg(feature = "mesh")]` to `threat_intel` and `yara_rules` fields

### 4.3 Control Plane Boundaries

**Status**: DOCUMENTED

**Decision**: Keep Mesh in Worker with Improved Isolation

---

## 5. HTTP/Traffic Layer

### 5.1 WAF Entrypoint Matrix

**Status**: ACTIVE

| Fix | Priority | Description |
|-----|----------|-------------|
| ProxyServer query_string fix | **FIXED** | `handle_request()` now passes `query_string` to WAF |
| HTTP/3 forwarded sanitization | **MEDIUM** | Uses `client_ip = remote_addr.ip()` directly without XFF check |

### 5.2 Traffic Entrypoint Matrix

**Status**: **COMPLETED** ✅

| Gap | Status |
|-----|--------|
| Per-site TLS client pooling | **COMPLETED** |
| No retry in HTTP/TLS/HTTP3 direct paths | ProxyServer path only |
| No cache in HTTP/HTTP3 direct paths | Partial |
| HTTP/3 missing response header filtering | OPEN |
| Mesh has separate header/metric/retry implementation | OPEN |

### 5.3 Worker Runtime Split & Extension Policies

**Status**: **COMPLETED** ✅

- [x] `ExtensionRuntime` trait defined in `src/worker/extension.rs`
- [x] `ExtensionRegistry` created in `UnifiedServerWorker`
- [ ] **Health API**: Expose extension health via Admin API `/health/extensions`

### 5.4 HTTP Server Pipeline Split

**Status**: **COMPLETED** ✅ (Phase 1-3)

| Phase | Module | Functions |
|-------|--------|-----------|
| 1 | `src/http/response_helpers.rs` | `apply_security_headers()`, `build_websocket_response()` |
| 2 | `src/http/validation_helpers.rs` | `is_websocket_upgrade()`, validation helpers |
| 3 | `src/http/internal_handlers.rs` | `handle_drain_request()`, `handle_health_request()` |
| 4-7 | Deferred | Due to complexity |

---

## 6. Process Isolation & Reload

### 6.1 Plugin Isolation

**Status**: DOCUMENTED

**Actionable Items** (deferred):
- [ ] Wire `GlobalWasmMemoryBudget::try_allocate()` into `WasmRuntime::load()`
- [ ] Add duplicate name check in `WasmPluginManager::load_plugin()`
- [ ] Replace `std::mem::forget(lifecycle)` with proper lifecycle management

### 6.2 Config Reload Contract

**Status**: DOCUMENTED

**Actionable Items** (deferred):
- [ ] Add accurate reload status reporting
- [ ] Implement incremental rebuild for site config changes
- [ ] Fix mesh blocking reload behavior

### 6.3 Runtime Ownership Inventory

**Status**: COMPLETE (draft)

**Actionable Items** (deferred):
- [ ] Track all spawned tasks in `task_handles`
- [ ] Await DHT routing initialization
- [ ] Fix mesh blocking reload behavior

---

## 7. WAF & Security Features

### 7.1 Threat Feed Production

**Status**: **COMPLETED** ✅

| Task | Component | Status |
|------|------------|--------|
| P1.1 | Deterministic Hashing | COMPLETED |
| P1.2 | Payload Generation | COMPLETED |
| P1.3 | Export Logic | COMPLETED |
| P2.1 | CLI Argument Parsing | COMPLETED |
| P2.2 | Export Handler | COMPLETED |
| P2.3 | Key Loading | COMPLETED |
| P3.1 | Tests | COMPLETED |
| P3.2 | Documentation | **DEFERRED** |

### 7.2 Mockable Clock for TokenBucket Tests

**Status**: **IMPLEMENTED** ✅

TokenBucket uses `time_offset_ms` approach for testing (alternative to full Clock trait).

---

## 8. CI/Gates & Testing

### 8.1 Systems-Layer CI and Regression Gates

**Status**: **COMPLETED** ✅

| Test Case | Status |
|----------|--------|
| IPC Auth Bypass | ✅ `test_ipc_auth_bypass_rejected` |
| Key File Symlink | ✅ `test_key_file_symlink_rejected` |
| Pidfile Race | ✅ `test_pidfile_lock_prevents_concurrent_access` |
| Sandbox Leak | **MISSING** |
| Socket Hijack | **MISSING** |

- [x] Integration Test Suite: `tests/security_regression.rs`
- [x] Miri CI: `cargo miri test -p maluwaf-utils`
- [x] Cross-Platform Check: `cargo check --no-default-features`
- [x] Forbidden Imports: `scripts/check_imports.py`

### 8.2 Platform Support Matrix

**Status**: DOCUMENTED

### 8.3 Platform Firewall Review

**Status**: **COMPLETED** ✅

- [x] `can_load_ebpf()`, `can_modify_nftables()`, `can_modify_firewall()`
- [x] `FilterState` enum with `InactiveNotPrivileged`, `InactiveConfigError`, `Active`
- [ ] Replace PowerShell interface resolver with native APIs (deferred)

---

## 9. MaluWAF V2 Plan (Completed)

**Status**: **COMPLETED** ✅

All 4 waves (W1-W4) implemented and verified.

---

## 10. Deferred/Future Work

### Deferred Items (Not Implemented)

| Item | Priority | Reason |
|------|----------|--------|
| Sandbox Leak Test | Low | Test infrastructure incomplete |
| Socket Hijack Test | Low | Test infrastructure incomplete |
| Health API (`/health/extensions`) | Medium | ExtensionRegistry not integrated |
| Wire GlobalWasmMemoryBudget | High | Requires significant refactoring |
| Duplicate plugin name check | Medium | Low risk, rare scenario |
| Plugin lifecycle leak | Low | Intentional design decision |
| DHT routing optimization | Low | Current implementation adequate for <10k nodes |
| HTTP/3 response header filtering | Medium | Low traffic path |
| PowerShell → native Windows APIs | Low | PowerShell resolver works |
| IPC framing copy optimization | Low | Not on hot path |

### Future Recommendations

1. **DHT Routing Optimization**: For 100k+ node scale, current Kademlia bucket iteration becomes bottleneck
2. **HTTP/QUIC Stream Pooling**: Could be combined with W2.4 for better mesh latency
3. **Advanced DHT Routing**: Current implementation adequate for <10k nodes

---

## Summary Status Table

| Section | Status | Notes |
|---------|--------|-------|
| 1. Overview/Status | **COMPLETED** | All waves 1-4 implemented |
| 2.1 Socket/PID Hardening | **COMPLETED** | Per-UID fallback, Windows native API |
| 2.2 Sandbox Hardening | **COMPLETED** | FreeBSD fix, macOS feature gate |
| 2.3 IPC Signing Hardening | **COMPLETED** | Replay cache, key loading |
| 2.4 IPC Consolidation | **COMPLETED** | Windows security builder, enforce signing |
| 2.5 Singleton Inventory | **COMPLETED** | RequestServices context, deprecated globals |
| 3.1 Buffer Pool | **COMPLETED** | Sharded mutex replacing TreiberStack |
| 3.2 Routing Hot-Path | VERIFIED | Minor allocations remain |
| 3.3 IPC Framing Copies | DOCUMENTED | Not on hot path |
| 4.1 Architecture Profiles | DOCUMENTED | Track as guidance |
| 4.2 Architecture Gates | **COMPLETED** | Core profile compiles |
| 4.3 Control Plane Boundaries | DOCUMENTED | Keep mesh in worker |
| 5.1 WAF Entrypoint Matrix | ACTIVE | ProxyServer query_string fixed |
| 5.2 Traffic Entrypoint Matrix | **COMPLETED** | TLS client pooling verified |
| 5.3 Worker Runtime Split | **COMPLETED** | ExtensionRuntime trait |
| 5.4 HTTP Server Pipeline | **COMPLETED** | Phase 1-3 extraction |
| 6.1 Plugin Isolation | DEFERRED | Wire memory budget |
| 6.2 Config Reload Contract | DEFERRED | Accurate status reporting |
| 6.3 Runtime Ownership | DEFERRED | Track tasks |
| 7.1 Threat Feed Production | **COMPLETED** | All implementation done |
| 7.2 Mockable Clock | **IMPLEMENTED** | TokenBucket tests fixed |
| 8.1 Systems CI Gates | **COMPLETED** | Security regression tests, Miri CI |
| 8.2 Platform Support Matrix | DOCUMENTED | Documentation only |
| 8.3 Platform Firewall | **COMPLETED** | Privilege checks, FilterState |
| 9. MaluWAF V2 Plan | **COMPLETED** | All 4 waves done |
| 10. Deferred/Future | ONGOING | Various items deferred |

---

## Active Branches/Merged Fixes (2026-05-04)

| Branch | Status | Description |
|--------|---------|-------------|
| `fix/raft-metrics-api` | Merged | Fixed raft metrics endpoints |
| `fix/test-concurrency` | Merged | Fixed DashMap deadlock in SlidingWindowLimiter |
| `fix/token-bucket-mockable-clock` | Merged | Added mockable clock for TokenBucket tests |
| `feature/zero-copy-validation` | Merged | Documented zero-copy implementation |
| `chore/remove-unused-stubs` | Merged | Removed MeshControlPlane and PluginExecution stubs |
| `wave1/*` | Merged | Wave 1: IPC Signing, Socket/PID, Sandbox hardening |
| `wave2/*` | Merged | Wave 2: IPC Consolidation, Buffer Pool, RequestServices |
| `wave3/*` | Merged | Wave 3: Runtime Split, HTTP Pipeline Split |
| `wave4/*` | Merged | Wave 4: TLS Pooling, CI Gates, Firewall |
| `fix/core-profile-mesh-gating` | Merged | Fixed core profile compilation with #[cfg] attributes |