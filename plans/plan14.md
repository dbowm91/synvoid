# Codebase Cleanup & Stub Removal - Implementation Plan

**Last updated**: 2026-04-23
**Status**: PENDING

## Overview

This plan addresses removing dead code stubs and improving code quality across the codebase. The investigation found:

- **No TODOs/FIXMEs** in codebase
- **Intentional placeholder keys** - security measures, already complete
- **Dead code stubs** - can be removed
- **Live stubs** - required for compilation or functional fallbacks
- **HTTP/3 gaps** - backend proxying incomplete

---

## Investigation Summary

### Items Reviewed

| Category | Status | Action Required |
|----------|--------|---------------|
| Windows platform stub | Required | Keep, add docs |
| Socket FD passing stubs | Keep | Defensive code |
| Sandbox stubs | Keep | Functional fallback |
| Process/IPC stubs | **Dead code** | Remove |
| Service module | **Dead code** | Remove |
| HTTP/3 handler | Documentation | Can remove file |
| HTTP/3 backend proxying | **Incomplete** | Implement |
| Placeholder keys | **Complete** | No action |

---

## Implementation Plan

### Phase 1: Remove Dead Code Stubs (Low Effort)

#### Task 1.1: Remove StubProcessControl / StubSignalHandler

**Location**: `src/platform/process.rs`

**Problem**: These stubs are compiled only for `#[cfg(not(any(unix, windows)))]` - exotic platforms. No exotic platforms are supported. The real implementations are:
- Unix: `UnixProcessControl`, `UnixSignalHandler`
- Windows: `WindowsProcessControl`, `WindowsSignalHandler`

**Code to remove** (lines 42-87):
```rust
#[cfg(not(any(unix, windows)))]
pub use stub::StubProcessControl as PlatformProcessControl;
#[cfg(not(any(unix, windows)))]
pub use stub::StubSignalHandler as PlatformSignalHandler;

#[cfg(not(any(unix, windows)))]
mod stub { ... }  // Lines 47-87
```

**Dead code evidence**:
- Zero call sites in codebase
- Only compiled for unsupported platforms

**Action**: Remove lines 42-87 from `src/platform/process.rs`.

**File changes**:
```rust
// REMOVE from process.rs:
mod stub {
    pub struct StubProcessControl;
    pub struct StubSignalHandler;
    // ... implementations
}
```

#### Task 1.2: Remove StubIpcListener / StubIpcStream

**Location**: `src/platform/ipc.rs`

**Code to remove** (lines 40-109):
```rust
#[cfg(not(any(unix, windows)))]
pub use stub::StubIpcListener as PlatformIpcListener;
#[cfg(not(any(unix, windows)))]
pub use stub::StubIpcStream as PlatformIpcStream;

#[cfg(not(any(unix, windows)))]
mod stub { ... }  // Lines 45-109
```

**Problem**: Actual IPC uses `src/process/ipc_transport.rs` with tokio primitives directly. This stub module is not used.

**Dead code evidence**:
- Zero call sites
- Real IPC uses `tokio::net::{UnixListener, UnixStream}` on Unix
- Real IPC uses `tokio::net::windows::named_pipe` on Windows

**Action**: Remove lines 40-109 from `src/platform/ipc.rs`.

#### Task 1.3: Remove Service Module

**Location**: `src/platform/service/`

**Problem**: `service_manager()` function never called. The entire module is dead code.

**Dead code evidence**:
- Zero grep results for `service_manager` call sites
- No imports of `ServiceControl` trait

**Action**: Remove directory `src/platform/service/` entirely.

---

### Phase 2: Windows Stub Documentation (Low Effort)

#### Task 2.1: Add Module Documentation to windows.rs

**Location**: `src/platform/windows.rs`

**Problem**: Contains only `// Windows platform support (stub)` - doesn't explain architecture.

**Current true implementation** in `windows_impl.rs`:
- `WindowsSocketHandle` / `WindowsSocketFDPassing` - Socket handling
- Named pipe IPC
- Process control via `taskkill`
- Wintun TUN driver integration

**Required for cargo fmt**: Stub file must exist for module resolution.

**Action**: Update stub to document architecture:

```rust
//! Windows platform support.
//!
//! This module satisfies Rust module resolution requirements. The actual implementation
//! is in windows_impl.rs (conditionally compiled via #[cfg(windows)]).
//!
//! Implemented features:
//! - Socket handling via Windows Sockets API
//! - Named pipe IPC
//! - Process control via taskkill
//! - Wintun TUN driver support (windows/wintun.rs)
```

---

### Phase 3: HTTP/3 Backend Proxying (Medium Effort)

#### Task 3.1: Implement Backend Routing in HTTP/3

**Location**: `src/http3/server.rs` (around line 473)

**Current state**: Returns placeholder response at lines 473-476:
```rust
let body = format!(
    "HTTP/3 proxied to {} - path: {}",
    route_target.upstream, path
);
```

**What's missing**: Connection to actual backends:
- PHP-FPM
- FastCGI
- Static files
- Upstream HTTP
- WASM/Serverless

**Implementation approach**: Mirror `src/http/server.rs` backend detection and dispatch pattern.

**Key functions to replicate**:
```rust
// From http/server.rs:
- handle_php_fpm_request()
- handle_static_file_request()
- handle_upstream_proxy_request()
- handle_serverless_request()
```

**Estimated effort**: 50-100 lines of code to add full backend support.

#### Task 3.2: Remove Unused stub Handler File

**Location**: `src/http3/handler.rs`

**Problem**: Stub functions never called - real impl in `server.rs`.

**Action**: Remove file and its module declaration in `http3/mod.rs`:

```rust
// REMOVE from mod.rs:
// pub mod handler;
// pub use handler::*;
```

---

### Phase 4: No Actions Required (Documentation)

The following items are **complete** and require no changes:

#### Placeholder Keys - Intentional Security Measures

| Item | Status | Notes |
|------|--------|-------|
| `DEFAULT_EMBEDDED_PUBLIC_KEY_PLACEHOLDER` | Complete | Warning at startup, generates random fallback |
| `TOKEN_PLACEHOLDER` | Complete | CLI template - use `--generatenewtoken` |
| `token_placeholder` validation | Complete | Release build error |

#### Live Stubs - Required

| Item | Status | Notes |
|------|--------|-------|
| `StubSocketFDPassing` | Keep | Defensive - exotic platform fallbacks |
| `StubSandbox` | Keep | Functional when sandbox disabled |

---

## File Changes Summary

| File | Change | Priority |
|------|-------|---------|
| `src/platform/process.rs` | Remove `mod stub` block | High |
| `src/platform/ipc.rs` | Remove `mod stub` block | High |
| `src/platform/service/` | Remove directory | High |
| `src/platform/windows.rs` | Add documentation | Low |
| `src/http3/server.rs` | Implement backend proxying | Medium |
| `src/http3/handler.rs` | Remove file | Low |
| `src/http3/mod.rs` | Remove handler export | Low |

---

## Testing Checklist

- [ ] `cargo check` passes after stub removal
- [ ] `cargo clippy --lib -- -D warnings` passes
- [ ] HTTP/3 backend proxying works for PHP-FPM
- [ ] HTTP/3 backend proxying works for static files
- [ ] HTTP/3 backend proxying works for upstream
- [ ] Integration tests pass

---

## Dependencies

- Existing backend handling in `src/http/server.rs` (patterns to mirror)
- HTTP/3 infrastructure in `src/http3/server.rs`
- No new external dependencies required

---

## Risk Assessment

| Risk | Mitigation |
|------|----------|
| Breaking compilation | Keep required stubs; verify with `cargo check` before commits |
| Platform support regression | Only remove code for unsupported exotic platforms |
| HTTP/3 backend gaps | Mirror existing patterns from http/server.rs |
| Breaking mesh compatibility | None - these are internal changes |

---

## Defer to Future Plans

The following items are out of scope for this cleanup plan:

1. **Full Windows feature parity** - Beyond stub cleanup; would require significant work
2. **HTTP/3 HTTP/2 feature parity** - Backend proxy is priority; QUIC protocol complete
3. **BSD/eBPF sandbox** - Exotic platform support not planned