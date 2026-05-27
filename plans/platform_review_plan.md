# Platform Architecture Review Plan

## Overview

Reviewed `architecture/platform.md` (690 lines) and `architecture/platform_deep_dive.md` (417 lines) against actual source code in `src/platform/`.

---

## Verified Correct Items

### Directory Structure ✅
All files match documentation:
- `src/platform/mod.rs` - Platform enum, capability queries, re-exports
- `src/platform/fs.rs` - SecureDir, PlatformPaths, permissions
- `src/platform/ipc.rs` - IpcTransport, IpcListener, IpcStream traits
- `src/platform/process.rs` - Signal, ProcessControl, SignalHandler traits
- `src/platform/socket.rs` - SocketHandle, SocketFDPassing, owned types
- `src/platform/sandbox.rs` - SandboxBackend trait, ProcessSandbox, all backends
- `src/platform/unix.rs` - Unix IPC, socket FD passing, signal handling
- `src/platform/windows_impl.rs` - Windows IPC, socket handoff, signal handling
- `src/platform/windows.rs` - Stub module (1 line)
- `src/platform/windows/` - firewall.rs, interface_resolver.rs, wintun.rs
- `src/platform/service/mod.rs` - ServiceControl trait, re-exports
- `src/platform/service/stub_service.rs` - UnixServiceManager (Linux systemd + BSD rc.d)
- `src/platform/service/windows_service.rs` - WindowsServiceManager

### Platform Enum ✅
`Platform` enum in `mod.rs:20-30` matches documentation exactly:
- Linux, LinuxMusl, Macos, FreeBSD, OpenBSD, NetBSD, Windows, Unknown

### Capability Methods ✅
All capability methods verified in `mod.rs:83-194`:
- `is_unix()`, `is_linux()`, `is_bsd()` - correct
- `supports_socket_fd_passing()` - correct (Unix only)
- `supports_signals()` - correct (Unix only)
- `supports_sandbox()` - correct (Linux/FreeBSD/OpenBSD only)
- `is_admin_required_for_tun()` - correct (false for Unix, true for Windows/Unknown)

### IPC Traits ✅
`ipc.rs:6-28` matches documentation:
- `IpcTransport`, `IpcListener`, `IpcStream` traits correctly defined
- Platform re-exports: UnixIpcListener/UnixIpcStream (unix.rs), WindowsIpcListener/WindowsIpcStream (windows_impl.rs)

### Process/Signal ✅
`process.rs:6-14` Signal enum matches exactly:
- Terminate, Interrupt, Reload, Status, User1, User2

### Sandbox Backends ✅
All four backends implemented in `sandbox.rs`:
- Linux Landlock: lines 266-485
- FreeBSD Capsicum: lines 487-569
- OpenBSD Pledge: lines 571-686
- Windows Job Objects: lines 688-1005
- macOS Seatbelt: lines 1007-1190 (feature-gated)

### Service Management ✅
- `stub_service.rs:58-541` - UnixServiceManager with systemd and BSD rc.d support
- `windows_service.rs:111-299` - WindowsServiceManager with sc.exe integration

### Socket FD Passing ✅
- `unix.rs:71-154` - UnixSocketFDPassing with SCM_RIGHTS (254 max FDs)
- `windows_impl.rs:71-99` - WindowsSocketFDPassing (stub - returns NotSupported, notes port-swap alternative)

### SecurityDescriptor ✅
`windows_impl.rs:617-816` - SecurityDescriptor::new_user_only() creates restrictive DACL for named pipes

---

## Discrepancies Found

### 1. Missing `supports_seatbelt()` method
**Documentation**: `platform.md:53` lists `supports_seatbelt()` as a capability query
**Actual**: No such method exists in `mod.rs` - the method is referenced in `platform_deep_dive.md:66` as "query via `platform().supports_seatbelt()`"

**Severity**: Low (documentation issue only - seatbelt is feature-gated anyway)

### 2. PlatformPaths documention mismatch
**Documentation**: `platform.md:79` lists `master_socket_path()`, `unified_worker_socket_path()`, `static_worker_socket_path()`
**Actual**: `fs.rs:214-229` implements all three correctly

**Verdict**: Verified correct

### 3. `is_admin_required_for_tun()` stub status
**AGENTS.override.md:115-126** says the function is a stub returning `true` for ALL platforms
**Actual**: `mod.rs:166-176` returns `false` for Unix platforms

**Verdict**: AGENTS.override.md is outdated. The implementation is correct (returns false for Unix, true for Windows/Unknown). AGENTS.md:163 correctly notes "Fixed - now returns `false` for Unix platforms, `true` for Windows".

### 4. IPC path documentation
**Documentation**: `platform.md:68-69` shows IPC path via XDG_RUNTIME_DIR
**Actual**: `ipc.rs:112-116` uses `PlatformPaths::ipc_path()` which follows XDG conventions correctly

**Verdict**: Verified correct

---

## Bugs Identified

### BUG-PL-2: Outdated AGENTS.override.md
**Severity**: Low (documentation only)
**Location**: `src/platform/AGENTS.override.md:115-126`
**Issue**: States `is_admin_required_for_tun()` is a stub returning `true` for all platforms, but actual implementation correctly returns `false` for Unix.
**Fix**: Update AGENTS.override.md to reflect actual implementation.

### BUG-PL-3: WindowsSocketFDPassing not functional
**Severity**: Medium
**Location**: `src/platform/windows_impl.rs:71-99`
**Issue**: `WindowsSocketFDPassing::send_sockets()` and `recv_sockets()` return `NotSupported` error. The implementation notes "Use port-swap upgrade mode instead" but there's no actual socket handoff mechanism for Windows.
**Documentation says**: "Windows: WSADuplicateSocketW for socket duplication"
**Actual**: Only `duplicate_socket_for_child()` and `create_socket_from_duplicate()` exist for serializing/deserializing socket info, but no actual FD passing mechanism is wired into `WindowsSocketFDPassing`.

**Fix**: Either implement proper Windows socket passing or update documentation to clarify Windows uses port-swap for zero-downtime upgrades.

### BUG-PL-4: macOS Seatbelt implementation incomplete
**Severity**: Low (documented as feature-gated)
**Location**: `src/platform/sandbox.rs:1007-1190`
**Issue**: Seatbelt implementation compiles profile strings but `is_supported()` returns false unless `macos-sandbox` feature is enabled. The profile compilation works but sandbox enforcement is disabled by default.
**Note**: `sandbox.rs:1082-1109` shows the actual `sandbox_init()` call is cfg-gated behind `macos-sandbox` feature.

---

## Suggested Improvements

### IMPROVE-1: Add `supports_seatbelt()` method
**Severity**: Low
**Location**: `src/platform/mod.rs`
**Suggestion**: Add a `supports_seatbelt()` method to `Platform` enum for symmetry with other platform queries. Currently referenced in documentation but doesn't exist.

```rust
pub fn supports_seatbelt(&self) -> bool {
    matches!(self, Platform::Macos)
}
```

### IMPROVE-2: Document Windows socket handoff limitation
**Severity**: Low
**Location**: `architecture/platform.md`
**Suggestion**: The document states "Windows: `WSADuplicateSocketW` for socket duplication across processes" but Windows implementation returns NotSupported. Update documentation to clarify Windows uses port-swap upgrade mode.

### IMPROVE-3: Verify systemd service installation
**Location**: `src/platform/service/stub_service.rs:379-421`
**Note**: The Linux service installer writes a unit file but doesn't check if systemd is actually running (doesn't use `systemctl --user` for user services). Works for system services but may fail silently for user-mode services.

### IMPROVE-4: Signal::Status duplicate mapping
**Location**: `src/platform/unix.rs:326`
**Note**: Both `Signal::Status` and `Signal::User2` map to `SIGUSR2`. This is documented in `platform.md:124` but could cause confusion. No bug - intentional design.

---

## Cross-Reference with AGENTS.md

| Item | AGENTS.md Status | Actual Status |
|------|------------------|---------------|
| is_admin_required_for_tun stub | FIXED 2026-05-27 | ✅ Correct - returns false for Unix, true for Windows |
| macOS sandbox feature gate | Known - just needs enabling | ✅ Correct - feature gate at sandbox.rs:1037 |
| Landlock kernel 5.13+ check | Not mentioned | ✅ Implemented at sandbox.rs:309-324 |
| Capsicum cap_getmode() | Not mentioned | ✅ Implemented at sandbox.rs:502-506 |
| Windows Job Objects memory limits | Not mentioned | ✅ 256MB process / 512MB job at sandbox.rs:865-866 |

---

## Summary

The Platform module implementation is **largely correct** with minor documentation discrepancies. The core architecture matches the design documents. Key findings:

1. **All file paths and structures verified** - no missing files
2. **Core APIs match documentation** - Platform enum, traits, backends all correct
3. **AGENTS.override.md is outdated** - needs update for `is_admin_required_for_tun`
4. **Windows socket FD passing not implemented** - documented but returns NotSupported
5. **No security bugs found** - constant-time patterns, permission settings, DACLs all properly implemented