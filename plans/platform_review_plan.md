# Platform Architecture Review Plan

## Verified Correct

- **Platform Module File Structure**: All files in `src/platform/` match documentation:
  - `mod.rs` - Platform enum detection, capability queries ✅
  - `ipc.rs` - IPC traits (IpcTransport, IpcListener, IpcStream) ✅
  - `sandbox.rs` - Multi-backend sandboxing (Landlock, Capsicum, Pledge, Seatbelt, Job Objects) ✅
  - `socket.rs` - Socket creation, FD passing, owned wrappers ✅
  - `process.rs` - Process control traits, signal handling ✅
  - `unix.rs` - Unix-specific implementations (UnixDomain sockets, signals, daemonization) ✅
  - `windows_impl.rs` - Windows IPC via named pipes ✅
  - `fs.rs` - Filesystem operations with sandbox integration ✅

- **Platform Enum**: `Platform` enum (Linux, LinuxMusl, Macos, FreeBSD, OpenBSD, NetBSD, Windows, Unknown) - matches line 21-30 in `src/platform/mod.rs` ✅

- **Feature Gates via Boolean Queries**: `supports_socket_fd_passing()`, `supports_signals()`, `supports_sandbox()`, `supports_reuse_port()` - all implemented in `src/platform/mod.rs:110-178` ✅

- **macOS Seatbelt**: Implemented at `src/platform/sandbox.rs:1007-1190`, disabled by default, requires `macos-sandbox` Cargo feature (line 1022, 1036-1044) - matches documentation at line 375 ✅

- **Sandbox Backends**:
  - Linux (5.13+): Landlock - `sandbox.rs:266-485` ✅
  - FreeBSD: Capsicum - `sandbox.rs:487-569` ✅
  - OpenBSD: Pledge + Unveil - `sandbox.rs:571-686` ✅
  - Windows: Job Objects + DACL - `sandbox.rs:688-1005` ✅

- **Process Module File Structure**: All files present and documented:
  - `ipc.rs` - Message enum with validation ✅
  - `ipc_framing.rs` - Length-prefixed framing (4-byte BE length header) ✅
  - `ipc_signed.rs` - HMAC-SHA3-256 signing with replay protection ✅
  - `socket_fd.rs` - Unix FD passing via SCM_Rights ✅

- **IPC Framing Protocol**: `4-byte length (BE) + serialized Message`, `MAX_MESSAGE_SIZE: 1 MiB` - `src/process/ipc_framing.rs:6` ✅

- **Signed IPC Format**: `[4-byte length][8-byte timestamp][16-byte nonce][32-byte HMAC][payload]` - `src/process/ipc_signed.rs:52` (`SIGNED_MESSAGE_OVERHEAD = 4 + 8 + 16 + 32`) ✅

- **Security Features**:
  - HMAC-SHA3-256 authentication - `ipc_signed.rs:213-220` ✅
  - Timestamp validation (60-second replay window) - `ipc_signed.rs:108-112` ✅
  - Nonce deduplication via DashMap - `ipc_signed.rs:66-70` ✅
  - Constant-time HMAC comparison via `subtle::ConstantTimeEq` - `ipc_signed.rs:225-226, 243-244` ✅

- **Socket FD Passing (Unix)**: `MAX_FDS_PER_MESSAGE: 254` - `src/platform/unix.rs:16`, `src/process/socket_fd.rs:18` ✅

- **Supervisor Module File Structure**: All files present:
  - `process.rs` - `SupervisorProcess` struct, `run_supervisor_mode()` ✅
  - `api.rs` - gRPC control plane server ✅
  - `state.rs` - `SupervisorState` ✅

- **gRPC Control Plane API**: GetStatus, ReloadConfig, Stop, BlockIp, UnblockIp - `src/supervisor/api.rs:33-127` ✅

- **gRPC binds to localhost only**: `src/process/manager.rs:81` default `127.0.0.1:50051` - matches documentation ✅

- **Health checks and zombie reaping (every 5 seconds)**: `src/supervisor/process.rs:141` ✅

- **Startup flow**: Master must NOT run UnifiedServer inline - documented at `src/startup/master.rs:278-302` with explicit CRITICAL architectural requirement comment ✅

- **SocketInfo struct**: `src/platform/socket.rs:23-30` defines `SocketInfo { handle, port, socket_type }` ✅

- **Message validation**: String length limits (`MAX_STRING_LENGTH: 64 * 1024`) and path traversal checks (`..` detection) - `src/process/ipc.rs:804-805, 856-861` ✅

- **IPC rate limiting**: Token bucket rate limiting (global + per-worker) - `src/process/ipc_rate_limit.rs` ✅

- **ConfigManager location**: `crates/synvoid-config/src/lib.rs:113` - verified ✅

## Discrepancies Found

1. **Message Category Count**: Documentation (`platform_deep_dive.md:96`) states "17 categories" but actual implementation has **18 categories** in `src/process/ipc.rs:1552-1571`. The undocumented category is `Upstream` (line 1570) which handles `UpstreamGlobalStats` and `GlobalUpstreamStatsBroadcast` messages.

2. **Socket Handle terminology**: Documentation refers to `SocketHandle` trait, but actual platform abstraction uses `UnixSocketHandle` (`src/platform/unix.rs:22-69`) and `PlatformSocketHandle` (`src/platform/socket.rs:258-265`). The trait exists (`src/platform/socket.rs:242-246`) but implementations are platform-specific wrappers.

3. **IpcTransport trait visibility**: Documentation lists `IpcTransport` as a key trait, but `src/platform/ipc.rs:6-11` defines it while actual implementation on `UnixIpcStream` (`src/platform/unix.rs:282-300`) does not explicitly impl the trait - it is only used as a bound for `IpcStream`.

4. **Supervisor health check timing**: Documentation (`platform_deep_dive.md:175`) states "every 5 seconds" which matches `src/supervisor/process.rs:141`, but the documentation does not mention that this same interval handles both health checks AND zombie reaping.

5. **OverseerLockFile and Pidfile**: Documentation (`platform_deep_dive.md:89`) mentions "overseer lock file" for PID file management, but actual implementation in `src/process/pidfile.rs:63` exports `OverseerLockFile` - the naming is preserved.

## Bugs Identified

**Low Severity:**
- `is_admin_required_for_tun()` stub implementation: `src/platform/mod.rs:166-171` returns `true` for all platforms including non-Windows. This appears to be a placeholder/stub. While it matches the documentation pattern (boolean query), the implementation does not actually check platform-specific requirements.

**Not a bug (documentation mismatch resolved):**
- Capsicum `limit_fd()` dead code: AGENTS.md notes this as "FIXED" - method removed from `src/platform/sandbox.rs`. The documentation at `platform_deep_dive.md:63` does not mention this method, so no discrepancy.

## Suggested Improvements

1. **Documentation - Message Categories**: Update `platform_deep_dive.md:96` to state "18 categories" instead of "17 categories", and add the `Upstream` category to the list (items 1-17 listed, missing Upstream for `UpstreamGlobalStats`, `GlobalUpstreamStatsBroadcast`).

2. **Documentation - Supervisor IPC**: Add clarification that `SupervisorProcess` handles both worker messages AND admin commands via its IPC listener (line 168-189 in `src/supervisor/process.rs`).

3. **Platform Capability Query**: Consider adding `supports_seatbelt()` to the Platform enum for symmetry with other capability queries, even if it just returns `matches!(self, Platform::Macos)`.

4. **Code - is_admin_required_for_tun()**: The stub implementation at `src/platform/mod.rs:166-171` returns `true` for ALL platforms. This should either:
   - Be implemented properly per-platform, or
   - Document that admin requirements for TUN are platform-dependent and not fully implemented

5. **Documentation - Startup Flow Comments**: The CRITICAL comment at `src/startup/master.rs:278-302` is excellent. Consider adding similar enforcement comments to `src/supervisor/process.rs:48-166` where the Supervisor run loop is defined.

6. **Process Architecture Clarity**: The difference between "Consolidated Mode" and "Traditional Mode" (legacy) in the architecture diagrams could be more clearly distinguished - specifically which processes are involved in each mode.

7. **Documentation - Platform Specifics**: Add a note that `peer_pid()` in `src/platform/unix.rs:313-315` currently returns `None` for Unix IPC streams (not implemented), while the documentation suggests it provides peer PID detection.

8. **IPC Transport Trait**: Consider whether `IpcTransport` should be explicitly implemented on `UnixIpcStream` for consistency and documentation purposes, rather than being implicit via method bounds.

9. **Health Check Interval Documentation**: The exact behavior at `src/supervisor/process.rs:141` (checking health AND reaping zombies in same 5-second interval) could be documented more explicitly.
