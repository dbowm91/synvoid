# IPC Consolidation Inventory

**Priority**: 2
**Status**: Inventory Complete - Implementation Pending

## 1. IPC Entry Point Inventory

### 1.1 Worker Control IPC (Master ↔ Worker)

| File | Type | Signing | Framing | Platform | Notes |
|------|------|---------|----------|----------|-------|
| `src/process/ipc_transport.rs` | `IpcStream` | Optional (`enforce_signing` flag) | Length-prefixed JSON | Unix/Windows | Async, tokio-based |
| `src/process/ipc.rs` | `IpcStream` (sync) | Optional, None by default | Length-prefixed JSON | Unix/Windows | Sync, std-based |
| `src/master/ipc.rs` | `handle_worker_connection()` | Configurable via `ipc_enforce_signing` | Uses `IpcStream` | Unix/Windows | Main worker connection handler |

**Behavior**:
- `ipc_transport.rs` warns once via `WARNED_UNSIGNED` static when signing is not enforced but a signer is not provided
- Worker connection rejects if `enforce_signing=true` and no session key is configured (see `src/master/ipc.rs:319-331`)
- `enforce_signing` defaults to `true` (see `src/config/security.rs:5-7`)

### 1.2 Master Command IPC (CLI → Master)

| File | Type | Signing | Framing | Platform | Notes |
|------|------|---------|----------|----------|-------|
| `src/startup/master.rs:802` | `handle_command_connection()` | **NONE** | Raw length-prefixed JSON | Windows | Uses `serde_json::from_slice` directly |
| `src/master/windows.rs:145` | `handle_command_connection()` | **NONE** | Raw length-prefixed JSON | Windows | Duplicates above, identical logic |
| `src/process/ipc_transport.rs` | `IpcStream` | Optional | Length-prefixed JSON | Unix | Not used for commands |

**Issue**: Both command handlers read raw JSON and execute privileged operations (Stop, ReloadConfig) without authentication.

### 1.3 Socket Handoff

| File | Type | Signing | Framing | Platform | Notes |
|------|------|---------|----------|----------|-------|
| `src/process/ipc.rs` | `Message::SocketHandoff*` variants | Via `IpcStream` | Part of Message enum | Unix/Windows | Uses `WindowsSocketInfo` for protocol transfer |
| `src/platform/unix.rs` | `UnixSocketFDPassing` | N/A | SCM_RIGHTS | Unix | FD passing via `sendmsg`/`recvmsg` |
| `src/platform/windows_impl.rs` | `WindowsSocketFDPassing` | N/A | WSADuplicateSocketW | Windows | Stub - returns `NotSupported` |

### 1.4 Status Queries

| File | Type | Signing | Notes |
|------|------|---------|-------|
| `src/process/ipc.rs` | `MasterStatus`, `Message::OverseerGetStatus`, etc. | Via `IpcStream` | Status is returned via standard IPC |
| `src/startup/master.rs:220` | CLI status command | **NONE** | Raw JSON response |

### 1.5 Legacy/Platform-Specific

| File | Type | Platform | Notes |
|------|------|----------|-------|
| `src/process/ipc_windows.rs` | `create_named_pipe_server`, `accept_pipe_connection`, etc. | Windows | Duplicate Windows pipe creation logic |
| `src/platform/ipc.rs` | `IpcListener`, `IpcStream` traits + stub implementations | Cross-platform | Abstract traits with platform implementations |
| `src/platform/unix.rs` | `UnixIpcListener`, `UnixIpcStream` | Unix | Trait implementations |
| `src/platform/windows_impl.rs` | `WindowsIpcListener`, `WindowsIpcStream` | Windows | Trait implementations, overlaps with `ipc_windows.rs` |
| `src/master/windows.rs:13` | `windows_ipc_accept_loop()` | Windows | Accept loop for worker connections |

## 2. IPC Path Analysis

### 2.1 File-to-Path Mapping

```
src/process/ipc.rs (1330 lines)
├── Message enum (all IPC message types)
├── IpcStream (sync) - blocking, std threads
├── WindowsIpcListener (sync) - Windows named pipe listener
└── Helper functions (get_ipc_path, connect_to_master)

src/process/ipc_transport.rs (562 lines)
├── IpcStream (async) - tokio-based
├── IpcListener (async) - tokio-based
├── IpcEndpoint - endpoint abstraction
└── Signed/unsigned sending via WARNED_UNSIGNED pattern

src/process/ipc_windows.rs (113 lines)
├── create_named_pipe_server()
├── accept_pipe_connection()
├── connect_to_named_pipe()
└── pipe_name helpers

src/master/ipc.rs (556 lines)
└── handle_worker_connection() - main worker IPC handler
    ├── Enforces signing if configured
    ├── Validates peer PID (Linux SO_PEERCRED)
    └── Handles all Message types

src/master/windows.rs (241 lines)
├── windows_ipc_accept_loop() - worker accept loop
├── windows_command_pipe_listener() - command accept loop
└── handle_command_connection() - RAW JSON parsing

src/startup/master.rs (906 lines)
└── handle_command_connection() - RAW JSON parsing (duplicates windows.rs)

src/platform/ipc.rs (116 lines)
├── IpcTransport trait
├── IpcListener trait
└── IpcStream trait + platform re-exports

src/platform/unix.rs (436 lines)
├── UnixIpcListener / UnixIpcStream
└── UnixSocketFDPassing for FD handoff

src/platform/windows_impl.rs (617 lines)
├── WindowsIpcListener / WindowsIpcStream
├── WindowsSocketFDPassing (stub)
└── duplicate_socket_for_child(), etc.
```

### 2.2 Framing Implementation

**Primary framing**: `src/process/ipc_framing.rs`
- `write_message_sync()` / `write_message()` - async and sync
- `read_message_sync()` / `read_message()` - length-prefixed (4-byte length prefix + JSON)
- `MAX_MESSAGE_SIZE`: 1MB
- Default buffer: 64KB

**Signing implementation**: `src/process/ipc_signed.rs`
- HMAC-SHA3-256 (32 bytes)
- Timestamp + nonce + HMAC header (56 bytes total overhead)
- Replay protection via global nonce cache (10,000 entry max, 60-second window)
- `SignedIpcMessage::serialize_signed()` / `deserialize_signed()`
- `SignedWriter<T>` / `SignedReader<T>` streaming variants

## 3. Issues Identified

### 3.1 Signed vs Unsigned Inconsistency

**Problem**: `IpcStream` in `ipc_transport.rs` allows unsigned communication but warns via `OnceLock`:

```rust
// src/process/ipc_transport.rs:335-337
WARNED_UNSIGNED.get_or_init(|| {
    tracing::warn!("Using unsigned IPC communication - this is insecure for production deployments");
});
```

**Locations with unsigned IPC**:
1. `IpcStream::from_unix_stream()` - `enforce_signing: false` (line 179)
2. `IpcStream::from_named_pipe()` - `enforce_signing: false` (line 216)
3. `IpcStream::connect()` on Windows - `signer: None, enforce_signing: false` (line 277)
4. `IpcStream::connect()` on Unix - creates unsiged stream (line 250)

**Risk**: Workers or processes may connect without signing even when `ipc_enforce_signing` is true in config.

### 3.2 Null Security Attributes on Windows

**Problem**: Multiple Windows pipe creation sites pass `std::ptr::null_mut()` as the security attributes (5th parameter to `CreateNamedPipeW`):

| File | Line | Context |
|------|------|---------|
| `src/process/ipc.rs` | 1377 | `WindowsIpcListener::bind()` |
| `src/process/ipc.rs` | 1424 | `WindowsIpcListener::accept()` |
| `src/process/ipc_windows.rs` | 33 | `create_named_pipe_server()` |
| `src/platform/windows_impl.rs` | 219 | `create_named_pipe()` |
| `src/master/windows.rs` | 35, 102 | `windows_ipc_accept_loop()` + command listener |
| `src/startup/master.rs` | 374 | Command pipe listener |

**Risk**: Named pipes may be accessible to other users on the system when they should be restricted to the current user/Administrator.

### 3.3 Raw JSON Command Parsing

**Problem**: `handle_command_connection()` in both `src/master/windows.rs` and `src/startup/master.rs` parses raw JSON:

```rust
// src/startup/master.rs:832
let command: crate::process::MasterCommand = match serde_json::from_slice(&json_buf) {
```

**Issues**:
1. Duplicated logic in two files
2. No authentication or signing required
3. Commands like `Stop { graceful: bool }` and `ReloadConfig` are privileged
4. Uses length check only (max 1MB) - no signature verification

### 3.4 Platform IPC Traits Not Used for Master/Worker IPC

**Problem**: `src/platform/ipc.rs` defines `IpcListener` and `IpcStream` traits, but the actual master/worker communication uses `src/process/ipc.rs` and `src/process/ipc_transport.rs` directly.

**Result**: Two different IPC abstractions that don't share code.

### 3.5 WindowsIpcListener Duplication

**Problem**: `WindowsIpcListener` exists in both:
- `src/process/ipc.rs` (line 1340) - used by `src/startup/master.rs`
- `src/platform/windows_impl.rs` (line 191) - trait implementation

Both create named pipes with the same parameters.

### 3.6 Enforce Signing Logic Incomplete

**Problem**: `ipc_enforce_signing` is checked in `handle_worker_connection()` but the actual `IpcStream` is passed in already-constructed. The enforcement happens after connection but before message handling:

```rust
// src/master/ipc.rs:319-331
if enforce_signing {
    if session_key.is_none() {
        tracing::error!("IPC signing is enforced but no session key configured - rejecting worker connection");
        // ... sends error and returns
    }
}
```

But there's no check that the connection was actually signed - a worker could connect unsigned and pass this check if `session_key` happens to be `Some`.

## 4. Canonical Implementation Approach

### 4.1 Pick One IPC Stack

**Recommended**: `src/process/ipc_transport.rs` + `ipc_framing.rs` + `ipc_signed.rs`

**Rationale**:
- Already has async support (required for tokio runtime)
- Has framing layer
- Has signing layer with replay protection
- Covers both Unix sockets and Windows named pipes

**Action items**:
1. Deprecate `IpcStream` in `src/process/ipc.rs` (sync version) - keep for static workers only
2. Move `WindowsIpcListener` from `src/process/ipc.rs` to `src/process/ipc_transport.rs`
3. Remove `src/process/ipc_windows.rs` - duplicate functionality
4. Keep platform traits in `src/platform/ipc.rs` but mark as internal - don't use for master/worker IPC

### 4.2 Make Signing Enforcement Fail-Closed

**Changes needed**:

1. Add `is_signed()` check to `handle_worker_connection()`:
```rust
// After session key check in src/master/ipc.rs
if enforce_signing && !ipc.is_signed() {
    tracing::error!("IPC signing is enforced but worker connected without signing");
    return;
}
```

2. Remove `WARNED_UNSIGNED` pattern - replace with error when `enforce_signing=true`:
```rust
// In ipc_transport.rs send/recv methods
if self.enforce_signing && self.signer.is_none() {
    return Err(io::Error::other("IPC signing enforced but no signer configured"));
}
```

3. Remove unsigned `connect()` variants that don't require signing:
   - Rename `connect()` to `connect_unsigned_for_test()` 
   - Add `connect_signed()` as the only production path

### 4.3 Secure Windows Named Pipes

**Changes needed**:

1. Create a helper to build a proper security descriptor:
```rust
// src/process/ipc_windows.rs or new file
fn create_ipc_security_descriptor() -> windows_sys::Win32::Security::PSECURITY_DESCRIPTOR {
    // Build SD that allows:
    // - Current user (GetCurrentUser SID)
    // - Administrators
    // - SYSTEM
    // Deny everyone else
}
```

2. Replace all `std::ptr::null_mut()` security attribute uses:
```rust
let security_descriptor = create_ipc_security_descriptor();
let security_attributes = SECURITY_ATTRIBUTES {
    nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
    lpSecurityDescriptor: security_descriptor,
    bInheritHandle: false,
};
```

3. For command pipes (privileged operations), use more restrictive ACLs.

### 4.4 Replace Raw JSON Command Handling

**Changes needed**:

1. Use `ipc_transport.rs` for command connections:
   - Create command endpoint in `IpcEndpoint::commands()`
   - Use `connect_with_signer()` / `connect_signed()`
   - Reject unsigned connections

2. Replace raw JSON parsing with `Message` deserialization:
```rust
// Instead of serde_json::from_slice(&json_buf)
// Use the framed/signed recv() path
let command: MasterCommand = match ipc.recv().await {
    Ok(Some(cmd)) => cmd,
    _ => return,
};
```

3. Merge duplicate `handle_command_connection()` implementations into one.

### 4.5 Bind IPC Identity to OS Identity

**Linux**:
- `SO_PEERCRED` is already used to get peer PID (see `ipc_transport.rs:431-464`)
- Extend to check UID matches expected master/worker relationship

**Windows**:
- Use `ImpersonateNamedPipeClient` after connection to get client identity
- Or set explicit ACLs on pipe creation that restrict access

**macOS/BSD**:
- Document limitation that peer credential checks are not available
- Require signing as compensating control

### 4.6 Test Hooks Explicit

**Changes needed**:

1. Rename unsigned connect functions:
   - `connect()` → `connect_for_testing()`
   - `from_unix_stream()` → `from_unix_stream_unsigned()`

2. Add explicit constructors for signed:
   - `from_unix_stream_signed(stream, signer)` - already exists

3. Add compile-time or configuration enforcement that privileged paths cannot use unsigned.

## 5. Implementation Phases

### Phase 1: Inventory and Planning (DONE)
- Document all IPC entry points
- Identify issues
- This document

### Phase 2: Enforce Signing by Default
- Make `enforce_signing=true` the default
- Fail closed when enforcement is on but no signer
- Remove `WARNED_UNSIGNED` lazy static pattern

### Phase 3: Windows Security
- Create security descriptor builder
- Replace null security attributes
- Test pipe ACLs

### Phase 4: Consolidate IPC Stack
- Remove `ipc_windows.rs` duplicate code
- Move `WindowsIpcListener` to `ipc_transport.rs`
- Remove sync `IpcStream` from main paths (keep for static workers)

### Phase 5: Command Auth
- Use signed IPC for commands
- Remove raw JSON parsing
- Require same-user or admin credential check

## 6. Testing Requirements

### 6.1 Existing Tests
- 1729 library tests pass
- 0 test failures

### 6.2 Required New Tests
- Unsigned worker/master message is rejected when `enforce_signing=true`
- Signed message succeeds with valid key
- Command `Stop`/`ReloadConfig` is rejected without auth
- Wrong HMAC key fails verification
- Replay with duplicate nonce fails
- Windows named pipe ACL creation compiles and works
- Unix peer credential check (on Linux)

## 7. Items Not Fully Implemented

1. **Windows security descriptor helper** - Not built yet; requires `windows_sys` Security API calls
2. **Command IPC migration** - Raw JSON parsing still in place; needs signed IPC migration
3. **Per-signer/per-channel replay cache** - Currently global cache in `ipc_signed.rs`
4. **macOS/BSD peer credential support** - Limited or no support on these platforms
5. **Symlink/permission checks on key files** - Only basic hex parsing implemented

## 8. References

- Plan: `plans/plan.md` Priority 2 section (line 2735)
- Signing: `src/process/ipc_signed.rs`
- Framing: `src/process/ipc_framing.rs`
- Async transport: `src/process/ipc_transport.rs`
- Config: `src/config/security.rs` (`ipc_enforce_signing`)
- Worker handler: `src/master/ipc.rs` (`handle_worker_connection`)