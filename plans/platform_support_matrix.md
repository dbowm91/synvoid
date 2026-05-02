# CI Verification Commands

This file documents the commands that should run in CI to catch systems-layer regressions.
See the "Verification Commands" section at the end of this document.

# Platform Support Matrix

**Status**: Active
**Last Updated**: 2026-05-02

## Overview

MaluWAF targets multi-platform support with a primary focus on Linux for production deployments. macOS and Windows are supported for development and non-critical workloads. BSD variants have partial support.

---

## Production Platforms

| Platform | Support Level | Notes |
|----------|--------------|-------|
| Linux (glibc) | **Full** | Primary target. All features supported. |
| Linux (musl) | **Full** | Static binary builds. All features supported. |

## Development / Secondary Platforms

| Platform | Support Level | Notes |
|----------|--------------|-------|
| macOS | **Good** | Most features work. No `SO_REUSEPORT` on older versions. Sandbox needs feature flag. |
| Windows | **Partial** | Core HTTP/WAF works. No Unix domain sockets (uses named pipes). No `flock`-based locking. |
| FreeBSD | **Partial** | Capsicum sandbox works. Most Unix features work. |
| OpenBSD | **Partial** | Pledge sandbox works. No `SO_REUSEPORT`. |

## Capability Matrix

| Capability | Linux | macOS | Windows | FreeBSD | OpenBSD |
|-----------|-------|-------|---------|---------|---------|
| **Process Management** | | | | | |
| PID file management | Yes | Yes | Yes | Yes | Yes |
| Process supervision | Yes | Yes | Yes | Yes | Yes |
| Signal handling | Full | Full | Partial (TERM/INT only) | Full | Full |
| Daemonization | Yes | Yes | No (use Windows Service) | Yes | Yes |
| Overseer lock file | Yes | Yes | Stub (returns error) | Yes | Yes |
| **IPC** | | | | | |
| Unix domain sockets | Yes | Yes | N/A | Yes | Yes |
| Named pipes | N/A | N/A | Yes | N/A | N/A |
| Signed IPC | Yes | Yes | Yes | Yes | Yes |
| FD passing | Yes | Yes | No | Yes | Yes |
| **Socket Handoff** | | | | | |
| Socket FD passing | Yes | Yes | N/A | Yes | Yes |
| Socket duplication | N/A | N/A | Partial (WSADuplicateSocket) | N/A | N/A |
| `SO_REUSEPORT` | Yes | Yes | No | No | No |
| Port-swap upgrade | Yes | Yes | Yes | Yes | Yes |
| **Sandboxing** | | | | | |
| Landlock (Linux 5.13+) | Yes | N/A | N/A | N/A | N/A |
| Capsicum | N/A | N/A | N/A | Yes | N/A |
| Pledge | N/A | N/A | N/A | N/A | Yes |
| Seatbelt (macOS) | N/A | Yes (feature flag) | N/A | N/A | N/A |
| Job Objects | N/A | N/A | Yes | N/A | N/A |
| **Firewall / Filtering** | | | | | |
| nftables | Yes | No | No | No | No |
| pf | No | Yes | No | Yes | Yes |
| Windows Firewall | N/A | N/A | Yes | N/A | N/A |
| **Zero-Copy I/O** | | | | | |
| `splice()`/`vmsplice()` | Yes | No | N/A | No | No |
| `tokio-zero-copy` | Yes | Yes | Yes | Yes | Yes |
| **Service Installation** | | | | | |
| systemd unit | Yes | No | No | No | No |
| Windows Service | N/A | N/A | Yes | N/A | N/A |
| launchd | No | Yes | No | No | No |

---

## Known Limitations

### Windows

- **No `flock`**: The `OverseerLockFile` uses Unix `flock()` for inter-process locking. On Windows, `acquire()` returns an error. Overseer coordination should use alternative mechanisms.
- **No Unix domain sockets**: IPC uses Windows named pipes instead. Socket paths are translated to `\\.\pipe\<name>` format.
- **No FD passing**: `send_sockets`/`recv_sockets` return `NotSupported`. Use port-swap upgrade mode instead of socket handoff.
- **Limited signal handling**: Only `Terminate` and `Interrupt` signals are supported via `taskkill`/Ctrl+C.
- **No daemonization**: Use Windows Service infrastructure instead.

### macOS

- **Sandbox requires feature flag**: The `macos-sandbox` Cargo feature must be enabled for Seatbelt enforcement.
- **`SO_REUSEPORT`**: Available on macOS but may behave differently than Linux in edge cases.

### FreeBSD / OpenBSD

- **No `SO_REUSEPORT`**: Not supported on FreeBSD/OpenBSD. Port-swap upgrade mode works as a fallback.
- **NetBSD**: No platform-specific code; falls through to generic Unix stubs.

---

## Conditional Compilation Patterns

### Platform-specific imports

```rust
#[cfg(unix)]
use nix::fcntl::{flock, FlockArg};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;
```

### Platform-specific function bodies

```rust
#[cfg(unix)]
pub fn try_acquire(&mut self, ...) { /* flock-based */ }

#[cfg(windows)]
pub fn try_acquire(&mut self, ...) { /* exclusive file create */ }

#[cfg(not(any(unix, windows)))]
pub fn try_acquire(&mut self, ...) { /* O_EXCL fallback */ }
```

### Platform-specific modules

```rust
#[cfg(unix)]
mod unix_impl;

#[cfg(windows)]
mod windows_impl;
```

## Files with Platform Guards

| File | Pattern |
|------|---------|
| `src/process/pidfile.rs` | `#[cfg(unix)]` on flock/AsRawFd imports; `#[cfg(unix)]`/`#[cfg(not(unix))]` on `OverseerLockFile` |
| `src/overseer/process.rs` | `#[cfg(unix)]` on nix imports and `attempt_recovery()` |
| `src/platform/mod.rs` | `#[cfg(unix)]`/`#[cfg(windows)]` for platform-specific exports |
| `src/platform/socket.rs` | `#[cfg(unix)]`/`#[cfg(windows)]` for `OwnedTcpListener/Stream` |
| `src/platform/sandbox.rs` | `#[cfg(target_os = "...")]` for backend selection |
| `src/platform/windows_impl.rs` | Entire file is Windows-specific |
| `src/process/ipc_transport.rs` | `#[cfg(unix)]`/`#[cfg(windows)]` for listener/stream variants |

---

## windows-sys Feature Flags

The `windows-sys` crate requires explicit feature flags for each API namespace used:

| Feature | APIs Used |
|---------|-----------|
| `Win32_Foundation` | `CloseHandle`, `GetLastError`, `HANDLE`, `BOOL`, `FILE_FLAG_OVERLAPPED`, `ERROR_PIPE_CONNECTED`, `WAIT_TIMEOUT` |
| `Win32_System_LibraryLoader` | Module loading |
| `Win32_System_Pipes` | `CreateNamedPipeW`, `ConnectNamedPipe`, `PIPE_ACCESS_DUPLEX`, `PIPE_TYPE_MESSAGE`, `PIPE_READMODE_MESSAGE`, `PIPE_WAIT` |
| `Win32_System_Threading` | `CreateJobObjectW`, `SetInformationJobObject`, `OpenProcess`, `TerminateProcess`, `WaitForSingleObject`, `GetCurrentProcess`, `AssignProcessToJobObject` |
| `Win32_System_Console` | `SetConsoleCtrlHandler`, `CTRL_C_EVENT`, `CTRL_BREAK_EVENT`, `CTRL_CLOSE_EVENT` |
| `Win32_Networking_WinSock` | `WSADuplicateSocketW`, `WSASocketW`, `closesocket`, `WSAPROTOCOL_INFOW`, `INVALID_SOCKET` |
| `Win32_Security` | `AllocateAndInitializeSid`, `CheckTokenMembership`, `FreeSid`, admin group SID constants |

---

## Verification Commands

This section lists the CI verification commands that should be run to catch systems-layer regressions.

### Linux (Baseline)

These commands form the core regression gate for the primary platform:

```bash
cargo test --lib --no-run
cargo test --lib process
cargo test --lib platform
cargo test --lib buffer
cargo test --test ipc_test
cargo test --test process_lifecycle_test
cargo fmt --check
cargo clippy --lib -- -D warnings
```

### Cross-Platform Compilation

Document as CI jobs or manual verification for each target:

```bash
# Linux with all features
cargo check --target x86_64-unknown-linux-gnu --all-features

# macOS no-default features  
cargo check --target x86_64-apple-darwin --no-default-features

# Windows no-default features
cargo check --target x86_64-pc-windows-msvc --no-default-features
```

### Feature-Specific Checks

```bash
# Socket handoff feature
cargo check --no-default-features --features socket-handoff

# Mesh feature
cargo check --no-default-features --features mesh

# DNS feature
cargo check --no-default-features --features dns
```

### Security Regression Tests

The following tests verify security-critical behavior and should always pass:

| Test Pattern | Security Issue |
|--------------|----------------|
| `test_oversized_rejected_*` | Oversized message rejection |
| `test_unsigned_message_rejected_*` | Unsigned IPC rejection |
| `test_*symlink*rejected` | Symlink-based attacks |
| `test_strict_sandbox_*` | Sandbox strict mode validation |
| `test_buffer_pool_stress_*` | Buffer pool integrity under load |

Run regression tests:
```bash
cargo test --lib ipc_signed 2>&1 | grep -E "test.*unsigned|test.*oversized"
cargo test --lib buffer::pool 2>&1 | grep -E "test.*stress"
```

### Existing Test Coverage

The following security regression tests already exist in the codebase:

- **IPC signed/unsigned**: `src/process/ipc_signed.rs` - Tests for oversized rejection, unsigned message rejection
- **Buffer pool stress**: `src/buffer/pool.rs` - `test_stress_multithread_acquire_release`, `test_stress_random_sizes_bounded_capacity`
- **Raft oversized**: `src/mesh/raft/regression_tests.rs` - `test_in_progress_snapshot_rejects_oversized`
- **Socket path symlink**: `src/process/socket_path.rs` - Symlink check in `create_secure_dir_atomic`
- **Key file symlink**: `src/process/manager.rs` - `create_new` prevents symlink attacks in `write_ipc_key_to_tempfile`

Missing tests that should be added:
- `test_key_file_symlink_rejected` - Verify key file cannot be created over a symlink
- `test_runtime_dir_symlink_rejected` - Verify runtime dir cannot be a symlink
- `test_strict_sandbox_fails_on_unsupported` - Verify strict mode fails gracefully on platforms without full sandbox support

### CI Integration

These commands should be integrated into `.github/workflows/ci.yml`:

1. **Platform-specific test jobs** for Linux baseline tests
2. **Cross-compilation check matrix** for macOS/Windows
3. **Feature flag combinations** for optional features
4. **Security regression filters** to highlight failures

The existing `platform-compat` job already covers cross-target compilation checks.
