# Platform Module Architecture Review - Improvement Plan

**Review Date:** 2026-05-26
**Reviewer:** Claude Code
**Document Reviewed:** `architecture/platform_deep_dive.md`

---

## Executive Summary

The platform module architecture document is largely accurate but has several discrepancies, stale claims, and missing documentation details. Most issues are minor informational gaps, but one security-related issue and one potential bug were identified.

---

## 1. Stale Claims & Incorrect Documentation

### 1.1 macOS Seatbelt Sandbox Status (SECURITY - Incomplete Documentation)

| Aspect | Documented | Actual |
|--------|-----------|--------|
| **Location** | `architecture/platform_deep_dive.md:371-373` | `src/platform/sandbox.rs:1022-1205` |
| **Status claim** | "Seatbelt sandbox for macOS is **planned but not yet implemented** (`src/platform/sandbox.rs`)" | **Implemented but feature-gated** - requires `macos-sandbox` Cargo feature to be enabled at compile time |
| **Implementation** | (claimed not implemented) | `SeatbeltSandbox` struct with profile compilation and `sandbox_init()` FFI call exists at lines 1027-1204 |

**Root Cause:** The documentation incorrectly states macOS Seatbelt is "planned but not yet implemented" when it is actually fully implemented but gated behind the `macos-sandbox` feature flag in `Cargo.toml:38`.

**Discrepancy Impact:** Users may incorrectly believe macOS sandboxing is unavailable when it is actually supported if compiled with the feature flag.

**Required Fix:** Update line 373 from:
> "Seatbelt sandbox for macOS is **planned but not yet implemented** (`src/platform/sandbox.rs`). Other platforms use Landlock (Linux), Capsicum (FreeBSD), or Pledge+Unveil (OpenBSD)."

To something like:
> "Seatbelt sandbox for macOS is **implemented but disabled by default** - requires the `macos-sandbox` Cargo feature to be enabled at compile time. Related: `src/platform/sandbox.rs:1022-1205` with feature gate at line 1037."

---

### 1.2 CPU Affinity Documentation (Stale Diagram Claim)

| Aspect | Documented | Actual |
|--------|-----------|--------|
| **Location** | `architecture/platform_deep_dive.md:261` (Consolidated Mode diagram) | `src/worker/unified_server.rs:183-204` |
| **Claim** | "UnifiedServerWorker ... (tokio async loop, CPU-affinity pinned)" | CPU affinity is **Linux-only** - implemented via `#[cfg(target_os = "linux")]` at lines 184-204 |
| **Platform note** | None in diagram | FreeBSD/macOS/other Unix: logs info message at line 207, does not set affinity |

**Discrepancy Impact:** Users on non-Linux Unix platforms may expect CPU affinity pinning that does not actually occur.

**Required Fix:** Add "(Linux-only)" to the CPU affinity diagram note, or add a footnote explaining platform limitations.

---

### 1.3 Windows Sandbox - Missing Mitigation Policies

| Aspect | Documented | Actual |
|--------|-----------|--------|
| **Location** | `architecture/platform_deep_dive.md:64` | `src/platform/sandbox.rs:925-958` |
| **Claim** | "Windows: **Job Objects + DACL**" | Additionally includes **DEP** (Data Execution Prevention) and **ASLR** (Address Space Layout Randomization) mitigation policies via `SetProcessMitigationPolicy` |
| **Implementation** | Job Objects + DACL | Job Objects + DACL + DEP + ASLR |

**Discrepancy Impact:** Low - documentation is correct but incomplete (omits DEP/ASLR).

**Required Fix:** Update line 64 from:
> "Windows | **Job Objects + DACL** | Process memory limits, file security descriptors"

To:
> "Windows | **Job Objects + DACL + DEP + ASLR** | Process memory limits, file security descriptors, DEP, ASLR"

---

### 1.4 Message Enum Category Count

| Aspect | Documented | Actual |
|--------|-----------|--------|
| **Location** | `architecture/platform_deep_dive.md:94`, lines 96-112 | `src/process/ipc.rs` (Message enum) |
| **Claim** | "The `Message` enum is organized into **17 categories**" | Unable to verify exact count without exhaustive enum reading - **requires verification** |

**Action Required:** Recount Message enum variants and verify category groupings match documentation.

---

## 2. Missing Documentation

### 2.1 Missing `service/` Subdirectory

| Aspect | Missing | Found |
|--------|---------|-------|
| **Location** | `architecture/platform_deep_dive.md:15-27` (Key Files table) | `src/platform/service/` directory with `mod.rs`, `stub_service.rs`, `windows_service.rs` |
| **Impact** | Service control module not documented | Windows service integration exists (stub for non-Windows) |

**Required Fix:** Add `service/` to Key Files table:
> "| `service/` | Windows service integration (stub for non-Windows) |"

---

### 2.2 Missing `windows/` Subdirectory

| Aspect | Missing | Found |
|--------|---------|-------|
| **Location** | `architecture/platform_deep_dive.md:15-27` (Key Files table) | `src/platform/windows/` directory with `firewall.rs`, `interface_resolver.rs`, `wintun.rs` |
| **Impact** | Windows-specific networking modules not documented | Windows TUN, firewall, interface resolver exist |

**Required Fix:** Add `windows/` subdir to Key Files table, or clarify that `windows_impl.rs` is the parent module.

---

### 2.3 Missing `ipc_framing.rs` MAX_MESSAGE_SIZE Reference

| Aspect | Documented | Actual |
|--------|-----------|--------|
| **Location** | `architecture/platform_deep_dive.md:118` | `src/process/ipc_signed.rs:53` and `src/process/ipc_framing.rs:6` |
| **Claim** | "MAX_MESSAGE_SIZE: 1 MiB" | Actually defined as `MAX_IPC_MESSAGE_SIZE: usize = 1024 * 1024` (1 MiB) in ipc_signed.rs:53, re-exported via ipc_framing.rs:6 |

**No discrepancy** - but source reference should be added for traceability.

---

## 3. Platform Capability Inconsistencies

### 3.1 `supports_pf()` Not Documented

| Aspect | Actual | Missing |
|--------|--------|---------|
| **Location** | `src/platform/mod.rs:137-142` | Not mentioned in Platform Abstraction Pattern table (lines 37-41) |
| **Function** | `supports_pf()` returns true for macOS, FreeBSD, OpenBSD, NetBSD | pf (packet filter) support query missing from documentation |

**Recommendation:** Add `platform().supports_pf()` to the Platform Abstraction Pattern example if packet filter support is architecturally significant.

---

### 3.2 `supports_ebpf()` Not Documented

| Aspect | Actual | Missing |
|--------|--------|---------|
| **Location** | `src/platform/mod.rs:129-131` | Not mentioned in Platform Abstraction Pattern |
| **Function** | `supports_ebtp()` returns true for Linux only | eBPF support query missing from documentation |

**Note:** This may be intentional if eBPF is internal-only.

---

## 4. Code Bugs & Security Issues

### 4.1 (LOW) Capsicum Sandbox `limit_fd()` Dead Code

| Aspect | Details |
|--------|---------|
| **Location** | `src/platform/sandbox.rs:516-528` |
| **Issue** | `CapsicumSandbox::limit_fd()` method is defined but never called in `apply()` |
| **Impact** | The Capsicum backend enters sandbox mode but does not actually limit any file descriptors - it only enters capsicum mode without applying FD rights |
| **Code** | `apply()` at lines 532-558 calls `self.enter_sandbox()?` but never calls `limit_fd()` |

**Recommendation:** Either implement FD rights limiting in Capsicum backend or remove the unused `limit_fd()` method to avoid confusion.

---

### 4.2 (INFORMATIONAL) FreeBSD Capsicum Missing Path Allowlists

| Aspect | Details |
|--------|---------|
| **Location** | `src/platform/sandbox.rs:573-582` |
| **Issue** | `CapsicumSandbox::capabilities()` returns `read_path_allowlist: false, write_path_allowlist: false` but the documentation at `platform_deep_dive.md:61` describes Capsicum as having "FD rights limiting, process limits" - path allowlists are not a Capsicum feature |
| **Impact** | No issue - documentation and code are correct |

Capsicum operates on file descriptors, not paths. This is accurate.

---

## 5. Source-to-Document Line Reference Corrections

| Document Line | Claim | Actual Source | Notes |
|--------------|-------|---------------|-------|
| 26 | `fs.rs` | `src/platform/fs.rs` | **CORRECT** - module exists and is exported at `src/platform/mod.rs:1,8` |
| 229 | `src/startup/master.rs:278-302` | `src/startup/master.rs:278-302` | **CORRECT** - critical architectural requirement comment block |
| 367 | `src/startup/master.rs:278-302` | Same | **CORRECT** - same block referenced for enforcement |
| 173 | gRPC port 50051 default | `crates/synvoid-config/src/process.rs:184` | **CORRECT** - default defined as `"127.0.0.1:50051"` |

---

## 6. Verification Checklist

| Item | Status | Notes |
|------|--------|-------|
| `fs.rs` module exists | ✅ VERIFIED | `src/platform/fs.rs` exists, 275 lines |
| `service/` module exists | ✅ VERIFIED | `src/platform/service/mod.rs` with stub/window_service |
| Seatbelt implemented | ✅ VERIFIED (gated) | Feature-gated at `macos-sandbox` |
| Linux Landlock | ✅ VERIFIED | `sandbox.rs:266-485` |
| FreeBSD Capsicum | ✅ VERIFIED (with bug) | `sandbox.rs:487-584` - `limit_fd()` unused |
| OpenBSD Pledge | ✅ VERIFIED | `sandbox.rs:586-701` |
| Windows Job Objects | ✅ VERIFIED | `sandbox.rs:703-1020` with DEP/ASLR |
| CPU affinity Linux-only | ✅ VERIFIED | `unified_server.rs:183-204`, logs warning on other unix |
| IPC signed format | ✅ VERIFIED | `ipc_signed.rs:49-53` with correct overhead calculation |
| Nonce replay protection | ✅ VERIFIED | `ipc_signed.rs:66-98` using DashMap |
| 60-second replay window | ✅ VERIFIED | `ipc_signed.rs:70` |

---

## 7. Summary of Required Changes

### High Priority
1. **Fix macOS Seatbelt status** - Line 373 incorrectly states "not yet implemented" when it's feature-gated implemented
2. **Add CPU affinity platform caveat** - Line 261 diagram claims CPU-affinity pinned without noting Linux-only nature

### Medium Priority
3. **Update Windows sandbox description** - Line 64 omits DEP/ASLR mitigation policies
4. **Add `service/` to Key Files table** - Module is undocumented
5. **Count Message enum categories** - 17 categories claim needs verification
6. **Add source references** - Traceability for MAX_MESSAGE_SIZE and other constants

### Low Priority
7. **Consider documenting `supports_pf()`** - If architecturally relevant
8. **Fix Capsicum `limit_fd()` dead code** - Either implement or remove

---

## 8. Recommendations

1. **Update the architecture document** with corrections listed in Section 7
2. **Add source comments** to key implementation points for better traceability
3. **Verify Message enum category count** via exhaustive reading of `src/process/ipc.rs`
4. **Consider adding feature matrix** in sandbox section showing which features are compile-time gated vs runtime supported

---

*End of Review Plan*
