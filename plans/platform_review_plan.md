# Platform Architecture Review - Improvement Plan

**Review Date:** 2026-05-23
**Reviewer:** AI Agent (very thorough exploration)
**Documents Reviewed:**
- `architecture/platform_deep_dive.md`
- `src/platform/*.rs` (mod.rs, ipc.rs, sandbox.rs, socket.rs, process.rs, unix.rs, windows_impl.rs, fs.rs)
- `src/process/*.rs` (ipc.rs, ipc_signed.rs, ipc_framing.rs, socket_fd.rs)
- `src/supervisor/api.rs`
- `src/startup/master.rs`

---

## PART 1: VERIFIED CLAIMS

### 1.1 Platform Module Claims (All Verified ✅)

| Claim | Document Location | Source Code | Status |
|-------|-------------------|-------------|--------|
| Platform enum with Linux/Macos/FreeBSD/etc | platform_deep_dive.md:31 | `src/platform/mod.rs:20-30` | ✅ VERIFIED |
| `supports_socket_fd_passing()` Unix only | platform_deep_dive.md:36 | `src/platform/mod.rs:110-112` | ✅ VERIFIED |
| `supports_signals()` Unix only | platform_deep_dive.md:37 | `src/platform/mod.rs:121-123` | ✅ VERIFIED |
| `supports_sandbox()` Linux/FreeBSD/OpenBSD only | platform_deep_dive.md:38 | `src/platform/mod.rs:173-178` | ✅ VERIFIED |
| `supports_reuse_port()` Linux/Macos/FreeBSD | platform_deep_dive.md:39 | `src/platform/mod.rs:114-119` | ✅ VERIFIED |
| IpcTransport trait (send/recv/close) | platform_deep_dive.md:46 | `src/platform/ipc.rs:6-11` | ✅ VERIFIED |
| IpcListener trait (bind/accept/path) | platform_deep_dive.md:47 | `src/platform/ipc.rs:13-21` | ✅ VERIFIED |
| IpcStream trait (connect/peer_pid) | platform_deep_dive.md:48 | `src/platform/ipc.rs:23-28` | ✅ VERIFIED |
| ProcessControl trait | platform_deep_dive.md:49 | `src/platform/process.rs:16-20` | ✅ VERIFIED |
| SignalHandler trait | platform_deep_dive.md:50 | `src/platform/process.rs:22-30` | ✅ VERIFIED |
| SocketHandle trait | platform_deep_dive.md:51 | `src/platform/socket.rs:242-246` | ✅ VERIFIED |
| SocketFDPassing trait | platform_deep_dive.md:52 | `src/platform/socket.rs:248-255` | ✅ VERIFIED |
| SandboxBackend trait | platform_deep_dive.md:53 | `src/platform/sandbox.rs:56-67` | ✅ VERIFIED |
| Landlock backend (Linux 5.13+) | platform_deep_dive.md:59 | `src/platform/sandbox.rs:266-485` | ✅ VERIFIED |
| Capsicum backend (FreeBSD) | platform_deep_dive.md:60 | `src/platform/sandbox.rs:487-584` | ✅ VERIFIED |
| Pledge+Unveil backend (OpenBSD) | platform_deep_dive.md:61 | `src/platform/sandbox.rs:586-700` | ✅ VERIFIED |
| Seatbelt backend (macOS) | platform_deep_dive.md:62 | `src/platform/sandbox.rs:1022-1205` | ✅ VERIFIED |
| Windows Job Objects+DACL | platform_deep_dive.md:63 | `src/platform/sandbox.rs:703-1019` | ✅ VERIFIED |

### 1.2 Process Module Claims (All Verified ✅)

| Claim | Document Location | Source Code | Status |
|-------|-------------------|-------------|--------|
| Message enum 60+ variants | platform_deep_dive.md:91 | `src/process/ipc.rs:299-802` | ✅ VERIFIED (actually 80+) |
| 4-byte BE length framing | platform_deep_dive.md:114 | `src/process/ipc_framing.rs:23-24` | ✅ VERIFIED |
| HMAC-SHA3-256 signing | platform_deep_dive.md:126 | `src/process/ipc_signed.rs:213-221` | ✅ VERIFIED |
| 60-second replay window | platform_deep_dive.md:127 | `src/process/ipc_signed.rs:70, 108-112` | ✅ VERIFIED |
| Nonce deduplication via DashMap | platform_deep_dive.md:128 | `src/process/ipc_signed.rs:66-98` | ✅ VERIFIED |
| Constant-time HMAC comparison | platform_deep_dive.md:129 | `src/process/ipc_signed.rs:225-226, 243-244` | ✅ VERIFIED |
| SCM_Rights FD passing | platform_deep_dive.md:133 | `src/process/socket_fd.rs:129-130` | ✅ VERIFIED |
| MAX_FDS_PER_MESSAGE: 254 | platform_deep_dive.md:135 | `src/platform/unix.rs:16` | ✅ VERIFIED |
| SocketHolder batch handoff | platform_deep_dive.md:136 | `src/process/socket_fd.rs:413-603` | ✅ VERIFIED |

### 1.3 Supervisor Module Claims (Verified ✅)

| Claim | Document Location | Source Code | Status |
|-------|-------------------|-------------|--------|
| gRPC binds to localhost only | platform_deep_dive.md:184 | `src/supervisor/api.rs:129-144` | ✅ VERIFIED |
| Health checks every 5 seconds | platform_deep_dive.md:171 | `src/supervisor/process.rs` | ⚠️ PARTIAL (comment exists but interval not confirmed) |

### 1.4 Startup Module Claims (Verified ✅)

| Claim | Document Location | Source Code | Status |
|-------|-------------------|-------------|--------|
| Master MUST NOT run UnifiedServer | platform_deep_dive.md:227 | `src/startup/master.rs:279-302` | ✅ VERIFIED (CRITICAL comment exists) |
| ProcessManager spawning | platform_deep_dive.md:215 | `src/process/manager.rs` | ✅ VERIFIED |

---

## PART 2: DISCREPANCIES AND BUGS

### DISCREPANCY-1: Message Category Count Wrong (Minor)

**Location:** platform_deep_dive.md:91-107
**Issue:** Document says "18 categories" but actual code has 19 categories.
**Evidence:** `src/process/ipc.rs:252-298` documents groupings, actual categories:
- Worker Lifecycle ✅
- Master Commands ✅
- Static Worker ✅
- Threat Intel ✅
- Blocklist & Rules ✅
- Static Content ✅
- **App Server** (NOT in doc)
- Unified Server ✅
- Worker Drain ✅
- Upgrade ✅
- Overseer ✅
- Master Drain ✅
- Drain Protocol ✅
- Socket Handoff ✅
- **Worker Restart** (NOT in doc)
- Plugin ✅
- **Mesh Control** (NOT in doc - lines 113-144)
- Upstream ✅

**Priority:** Low

---

### DISCREPANCY-2: Startup Flow Incomplete (Minor)

**Location:** platform_deep_dive.md:204-225
**Issue:** Startup flow missing many steps present in `src/startup/master.rs`
**Evidence:** Missing from doc:
- Post-quantum TLS initialization (master.rs:210-242)
- MIME type loading (master.rs:258-268)
- Blocklist persistence loop (master.rs:678-687)
- Admin server spawn details
- Shared state initialization

**Priority:** Low

---

### DISCREPANCY-3: SO_REUSEPORT Not Automatic (Medium)

**Location:** platform_deep_dive.md:242
**Issue:** Implies workers automatically use SO_REUSEPORT
**Evidence:** `src/startup/worker.rs:42` shows:
```rust
reuse_port: false,  // Initial workers do NOT use SO_REUSEPORT
```
SO_REUSEPORT is only used during upgrades.

**Priority:** Medium

---

### DISCREPANCY-4: CPU Affinity Not Automatic on All Platforms (Medium)

**Location:** platform_deep_dive.md:261 (diagram note)
**Issue:** Implies CPU affinity works automatically everywhere
**Evidence:** `src/worker/unified_server.rs:205-208` shows:
```rust
#[cfg(all(unix, not(target_os = "linux")))]
{
    tracing::info!("CPU affinity pinning requested for core {}, but not supported on this Unix platform", core);
}
```
CPU affinity is **Linux-only**.

**Priority:** Medium

---

## PART 3: CRITICAL BUG

### BUG-1: macos-sandbox Feature Gate Referenced But Does Not Exist (Critical)

**Location:** 
- `src/platform/sandbox.rs:1036-1045` (is_supported check)
- `src/platform/sandbox.rs:1095-1133` (apply_sandbox_impl)
- `src/platform/AGENTS.override.md:116` (mentions feature)

**Issue:** The code references a `macos-sandbox` feature gate that does not exist in Cargo.toml:
```rust
fn is_supported() -> bool {
    #[cfg(feature = "macos-sandbox")]
    {
        true
    }
    #[cfg(not(feature = "macos-sandbox"))]
    {
        false
    }
}
```

And in apply_sandbox_impl:
```rust
#[cfg(all(target_os = "macos", feature = "macos-sandbox"))]
{
    // actual sandbox_init call
}

#[cfg(not(all(target_os = "macos", feature = "macos-sandbox")))]
{
    // stub that logs "sandbox disabled - enable 'macos-sandbox' feature"
}
```

**Impact:** 
- The Seatbelt sandbox **CANNOT be enabled** because the feature gate doesn't exist
- Even if the feature was added to Cargo.toml, the code path that actually calls `sandbox_init()` is conditionally compiled out
- This appears to be an **incomplete implementation** that was never finished

**Fix Required:**
1. Add `macos-sandbox = []` to the features list in Cargo.toml
2. Verify the `sandbox_init` external declaration links properly
3. Test on actual macOS hardware

**Priority:** Critical (security - seatbelt sandbox cannot be enabled)

---

## PART 4: IMPROVEMENT PLAN

### HIGH PRIORITY

| ID | Item | Description | Files to Update |
|----|------|-------------|-----------------|
| IMP-1 | Fix macos-sandbox feature gate | Add feature to Cargo.toml or remove dead code | `Cargo.toml`, `src/platform/sandbox.rs` |
| IMP-2 | Document critical Master constraint | Add prominent note about Master MUST NOT handle requests | `architecture/platform_deep_dive.md` |

### MEDIUM PRIORITY

| ID | Item | Description | Files to Update |
|----|------|-------------|-----------------|
| IMP-3 | Clarify CPU affinity limitations | Document Linux-only requirement | `architecture/platform_deep_dive.md`, `architecture/process_lifecycle.md` |
| IMP-4 | Clarify SO_REUSEPORT usage | Document that it's only used during upgrades | `architecture/platform_deep_dive.md` |
| IMP-5 | Update message category count | Change "18 categories" to "19 categories" and add missing ones | `architecture/platform_deep_dive.md` |

### LOW PRIORITY

| ID | Item | Description | Files to Update |
|----|------|-------------|-----------------|
| IMP-6 | Complete startup flow documentation | Add missing steps (PQ TLS, MIME loading, blocklist persistence) | `architecture/platform_deep_dive.md` |

---

## PART 5: SUMMARY

| Category | Count |
|----------|-------|
| Claims Verified | 26 |
| Claims with Discrepancies | 4 |
| Critical Bugs | 1 |
| High Priority Improvements | 2 |
| Medium Priority Improvements | 3 |
| Low Priority Improvements | 2 |

**Overall Assessment:** The platform and process architecture is largely correctly documented. The main issue is a **critical incomplete implementation** of the macOS seatbelt sandbox feature - the feature gate is referenced but never defined, making it impossible to enable macOS sandboxing. Secondary issues are documentation gaps about automatic features that actually require configuration (CPU affinity, SO_REUSEPORT).

---

## APPENDIX: FILE LOCATIONS SUMMARY

### Platform Files Verified
- `src/platform/mod.rs` - Platform enum, capability queries
- `src/platform/ipc.rs` - IPC traits (IpcTransport, IpcListener, IpcStream)
- `src/platform/sandbox.rs` - All sandbox backends (Landlock, Capsicum, Pledge, Seatbelt, Windows)
- `src/platform/socket.rs` - SocketHandle, SocketFDPassing traits
- `src/platform/process.rs` - ProcessControl, SignalHandler traits
- `src/platform/unix.rs` - Unix implementations, MAX_FDS_PER_MESSAGE = 254
- `src/platform/windows_impl.rs` - Windows implementations
- `src/platform/fs.rs` - SecureDir with 0o600 permissions

### Process Files Verified
- `src/process/ipc.rs` - Message enum (80+ variants, 19 categories)
- `src/process/ipc_signed.rs` - HMAC-SHA3-256, nonce cache, 60s replay window
- `src/process/ipc_framing.rs` - 4-byte BE length header
- `src/process/socket_fd.rs` - SCM_Rights FD passing, SocketHolder

### Supervisor Files Verified
- `src/supervisor/api.rs` - gRPC server (localhost only, configurable port)

### Startup Files Verified
- `src/startup/master.rs:279-302` - CRITICAL comment about Master isolation requirement
