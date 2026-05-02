# Platform Support Matrix

**Status**: Inventory Complete
**Last Updated**: 2026-05-02

## Overview

This document inventories platform-specific code in MaluWAF and documents what's supported vs. what needs fixing. The repository claims support for Linux, generic Unix, Windows, macOS, FreeBSD, OpenBSD, and other fallbacks, but the implementation is uneven.

---

## Issues Found

### Critical: Unconditional Unix Imports

These files import Unix-specific or `nix` crates unconditionally (at module scope), causing compilation failures on Windows:

| File | Issue | Line |
|------|-------|------|
| `src/process/pidfile.rs` | `use nix::fcntl::{flock, FlockArg}` is unconditional | 3 |
| `src/process/pidfile.rs` | `use std::os::unix::io::AsRawFd` is unconditional | 7 |
| `src/platform/unix.rs` | `use nix::sys::socket::{...}` is unconditional | 8 |

### Critical: Incorrect Return Types on Windows

| File | Issue | Line |
|------|-------|------|
| `src/process/ipc_transport.rs:164` | `local_addr()` returns `tokio::net::unix::SocketAddr` on Windows | 164 |

The Windows implementation of `IpcListener::local_addr()` returns an error but declares return type `tokio::net::unix::SocketAddr` which doesn't exist on Windows.

---

## Platform Support Table

| Component | Linux | Linux (musl) | macOS | FreeBSD | OpenBSD | Windows | Other Unix |
|-----------|-------|--------------|-------|---------|---------|---------|------------|
| **Process Management** | | | | | | | |
| PID file management | Supported | Supported | Supported | Supported | Supported | Supported | Stub |
| Process supervision | Supported | Supported | Supported | Supported | Supported | Supported | Stub |
| Signal handling | Supported | Supported | Supported | Supported | Supported | Partial¹ | Stub |
| Daemonization | Supported | Supported | Supported | Supported | Supported | No² | Stub |
| **IPC** | | | | | | | |
| Unix domain sockets | Supported | Supported | Supported | Supported | Supported | N/A | N/A |
| Named pipes | N/A | N/A | N/A | N/A | N/A | Supported | N/A |
| Signed IPC | Supported | Supported | Supported | Supported | Supported | Supported | Stub |
| FD passing | Supported | Supported | Supported | Supported | Supported | No³ | Stub |
| **Socket Handoff** | | | | | | | |
| Socket FD passing (Unix) | Supported | Supported | Supported | Supported | Supported | N/A | N/A |
| Socket duplication (Win) | N/A | N/A | N/A | N/A | N/A | Supported⁴ | N/A |
| SO_REUSEPORT | Supported | Supported | Supported | Supported | No | N/A | No |
| **Sandboxing** | | | | | | | |
| Landlock (Linux 5.13+) | Supported | Supported | N/A | N/A | N/A | N/A | N/A |
| Capsicum (FreeBSD) | N/A | N/A | N/A | Supported | N/A | N/A | N/A |
| Pledge (OpenBSD) | N/A | N/A | N/A | N/A | Supported | N/A | N/A |
| Seatbelt (macOS) | N/A | N/A | Supported⁵ | N/A | N/A | N/A | N/A |
| Job Objects (Windows) | N/A | N/A | N/A | N/A | N/A | Supported | N/A |
| **Firewall/Filtering** | | | | | | | |
| nftables | Supported | Supported | No | No | No | No | No |
| pf (Packet Filter) | No | No | Supported | Supported | Supported | No | Stub |
| Windows Firewall | N/A | N/A | N/A | N/A | N/A | Supported | N/A |
| **Zero-Copy** | | | | | | | |
| splice()/vmsplice() | Supported | Supported | No | No | No | N/A | No |
| tokio-zero-copy | Supported | Supported | Supported | Supported | Supported | Supported | Supported |
| **Service Installation** | | | | | | | |
| systemd unit | Supported | Supported | No | No | No | No | No |
| Windows Service | N/A | N/A | N/A | N/A | N/A | Supported | N/A |
| launchd | No | No | Supported | No | No | No | No |
| **Tests** | | | | | | | |
| Socket handoff test | Supported | Supported | Supported | Supported | Unknown | No | No |
| Fault injection test | Supported | Supported | Supported | Unknown | Unknown | No | No |

**Notes:**
1. Windows only supports Terminate and Interrupt signals
2. Daemonization not supported on Windows (use Windows Service instead)
3. FD passing uses stub on Windows (WSADuplicateSocket not fully implemented)
4. Windows uses `WSADuplicateSocket` for socket handoff to child processes
5. macOS Seatbelt requires `macos-sandbox` feature flag

---

## Files with Conditional Compilation

### Properly Configured Files

| File | Pattern |
|------|---------|
| `src/platform/mod.rs` | `#[cfg(unix)]` / `#[cfg(windows)]` for platform-specific exports |
| `src/platform/socket.rs` | `#[cfg(unix)]` / `#[cfg(windows)]` for `OwnedTcpListener/Stream` |
| `src/platform/sandbox.rs` | `#[cfg(target_os = "...")]` for backend selection |
| `src/process/ipc_transport.rs` | `#[cfg(unix)]` / `#[cfg(windows)]` for listener/stream variants |
| `src/platform/windows_impl.rs` | Windows-specific implementations |
| `src/overseer/process.rs` | `#[cfg(unix)]` for signal handling |

### Files with Issues

| File | Issue |
|------|-------|
| `src/process/pidfile.rs` | Unconditional `nix::fcntl::{flock, FlockArg}` import at line 3 |
| `src/process/pidfile.rs` | Unconditional `std::os::unix::io::AsRawFd` import at line 7 |
| `src/platform/unix.rs` | Unconditional `nix::sys::socket` imports at line 8 |

---

## `cargo check --no-default-features` Results

The baseline check without default features reveals:

- **215 errors** related to feature-gated imports (`mesh`, `dns` features)
- These are expected since features are disabled
- The actual platform-specific compilation issues are hidden by feature flags

To properly check platform code, features must be enabled:
```bash
cargo check  # Works on macOS
```

---

## Items Needing Fixes

### Priority 1: Critical Compilation Barriers

1. **`src/process/pidfile.rs`**
   - Move `nix::fcntl::{flock, FlockArg}` import inside `#[cfg(unix)]` blocks
   - Move `std::os::unix::io::AsRawFd` import inside `#[cfg(unix)]` blocks
   - The `OverseerLockFile::acquire()` uses `flock` unconditionally and must be guarded

2. **`src/process/ipc_transport.rs:164`**
   - Change Windows `local_addr()` return type from `tokio::net::unix::SocketAddr` to a platform-agnostic type or remove the method on Windows

3. **`src/platform/unix.rs`**
   - The entire file is `#[cfg(unix)]` but `nix` imports at top level will fail on Windows
   - These imports need to be conditionally compiled or the module structure needs adjustment

### Priority 2: Missing Implementations

1. **Windows FD passing** - `WindowsSocketFDPassing::send_sockets/recv_sockets` return `NotSupported`
2. **macOS launchd** - No service definition for macOS
3. **Other BSDs** - NetBSD has no platform-specific code (uses stubs)

### Priority 3: Partially Implemented

1. **macOS sandbox** - Requires `macos-sandbox` feature flag; stub logs instead of enforcing
2. **Windows signal handling** - Only supports terminate/interrupt

---

## Summary

**Well Supported:**
- Linux (all features)
- Windows (core functionality, some limitations in IPC)
- macOS (most features, sandbox needs feature flag)

**Partially Supported:**
- FreeBSD (sandbox works, but FD passing is stub)
- OpenBSD (sandbox works, reuse_port not supported)

**Poorly Supported:**
- NetBSD (no platform-specific code, uses stubs for everything)
- Other Unix (falls through to stubs)

**Critical Fixes Needed Before Windows/macOS/Other Unix Support:**
1. Fix unconditional Unix imports in `pidfile.rs`
2. Fix incorrect return type in `ipc_transport.rs`
3. Audit `platform/unix.rs` for proper conditional compilation