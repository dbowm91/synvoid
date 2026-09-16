# Platform Module Architecture

## 1. Purpose and Responsibility

The Platform subsystem provides a unified abstraction layer over operating system functionality, enabling SynVoid to operate consistently across different operating systems while leveraging platform-specific features where beneficial.

**Canonical location:** `crates/synvoid-platform/src/` (the `synvoid-platform` crate).
`src/platform/mod.rs` is a compatibility facade of module aliases plus historical
top-level re-exports; it contains no implementations (enforced by
`tests/platform_canonicalization_guard.rs`). New code must import
`synvoid_platform` directly — never `crate::platform` outside the facade, and
never the root path from domain crates.

**Core Responsibilities:**
- OS detection and capability enumeration (`Platform` enum)
- Platform-specific implementations for: sockets, IPC, process control, signals, sandboxing, service management, filesystem paths
- Sandbox enforcement using OS-native mechanisms (Landlock, Capsicum, Pledge, Seatbelt, Windows Job Objects)
- Service lifecycle management (systemd, BSD rc.d, Windows Services)
- WireGuard and TUN device support

### 1.1 Ownership and disposition (Phase 32)

Phase 32 made `synvoid-platform` the single compiled owner of reusable
OS/platform primitives and deleted the parallel implementation copies that
used to live under `src/platform/`. Every pair below was classified before
cutover; the crate copy won in all duplicate cases (porting the newest fixes
from either side), and no SynVoid application policy moved into the crate.

| Area | Crate (`synvoid-platform`) | Root (`src/platform/`) | Disposition |
|------|---------------------------|------------------------|-------------|
| `ipc.rs` (traits, stubs, `get_default_ipc_path`) | canonical | deleted | byte/semantic duplicate → crate canonical, root is a module alias |
| `process.rs` (`Signal`, traits, stubs, `terminate_process`, `is_process_running`) | canonical | deleted | duplicate → crate canonical (nix stays a unix-only crate dep) |
| `socket.rs` (owned types, traits, `SocketInfo`, `create_listening_socket*`) | canonical | deleted | duplicate → crate canonical; local `bind_tcp_reuse`/`bind_udp_reuse` copies collapsed onto `socket_bind` |
| `socket_bind.rs` (`bind_tcp_reuse`, `bind_udp_reuse`) | canonical (unchanged owner) | n/a (root re-exports via `socket`) | dedup target; broader reuse-port cfg list wins (see §12) |
| `service/` (`ServiceControl`, systemd/rc.d/`sc` managers) | canonical (with root's newer rc.conf warning logs) | deleted | duplicate → crate canonical; SynVoid default identity stays as data, no new policy |
| `unix.rs` (SCM_RIGHTS, Unix IPC, signals via nix, daemonize) | canonical (compiled via `mod unix`) | deleted | duplicate → crate canonical; `std::mem::take` handler drain kept |
| `windows_impl.rs` (named pipes, Job Objects, Ctrl handler) | canonical (compiled via `mod windows_impl`) | deleted | duplicate → crate canonical; saturating timeout clamp kept |
| `windows.rs` + `windows/` (firewall, interface resolver, Wintun) | canonical, now wired (`pub mod windows` + submodule declarations) | deleted | stale/dormant → activated; previously uncompiled on all targets and unresolvable on Windows |
| `sandbox.rs` + backends | canonical (unchanged since Phase 29) | already a facade; file deleted, alias kept | no change |
| `fs.rs` (`SecureDir`, `PlatformPaths`, permission helpers) | canonical (unchanged owner) | already re-exported; unchanged | extended with `for_app` (Part D), no path changes for `new()` |
| Supervisor/worker policy, app metrics, runtime wiring | n/a (never moves here) | stays in `supervisor/`, `worker/`, `startup/` | genuine application composition, root-owned by policy |

Dependency rules enforced at the boundary (see crate `Cargo.toml`):

- OS syscall wrappers own target-scoped deps: `nix` + `daemonize2` (unix),
  `windows-sys` + `libloading` + `zip` (Windows Wintun only), `tokio` `rt`+`signal`
  (unix/Windows signal listeners), `synvoid-utils` (shared `RunningFlag`; acyclic).
- Metrics emission stays at the caller — no `synvoid-metrics` edge.
- No `synvoid-config`, root `synvoid`, or broad metrics edges.
- `synvoid-ipc` stays above `synvoid-platform`; the crate must not depend on it,
  not even as a dev-dependency (the old `socket_handoff_test.rs` use was rewritten).

## 2. Key Submodules and Responsibilities

### 2.1 Crate layout (`crates/synvoid-platform/src/lib.rs`)

**Public modules:**

```rust
pub mod fs;           // Filesystem paths with security
pub mod ipc;          // Inter-process communication
pub mod process;      // Process control and signals
pub mod sandbox;      // Process sandboxing
pub mod service;      // Service management
pub mod socket;       // Socket abstractions with FD passing
pub mod socket_bind;  // SO_REUSEADDR/REUSEPORT bind helpers

#[cfg(unix)]
mod unix;             // Unix backends (private; reachable via Platform* aliases)
#[cfg(windows)]
mod windows_impl;     // Windows backends (private; reachable via Platform* aliases)
#[cfg(windows)]
pub mod windows;      // Operator helpers: firewall, interface_resolver, wintun
```

Public traits/types are reachable through stable module paths (e.g.
`synvoid_platform::ipc::PlatformIpcListener`) or top-level re-exports. Raw OS
implementation modules stay private; the crate does not expose raw
implementation details merely because the sources became canonical.

**Platform Detection:**
```rust
pub enum Platform {
    Linux,
    LinuxMusl,
    Macos,
    FreeBSD,
    OpenBSD,
    NetBSD,
    Windows,
    Unknown,
}
```

**Capability Queries:**
| Method | Purpose |
|--------|---------|
| `is_unix()` | Unix-like platform detection |
| `is_linux()` | Linux kernel detection |
| `supports_socket_fd_passing()` | SCM_RIGHTS support |
| `supports_reuse_port()` | SO_REUSEPORT support |
| `supports_signals()` | Signal handling support |
| `supports_daemonize()` | Background daemonization |
| `supports_ebpf()` | eBPF-based filtering |
| `supports_nftables()` | nftables firewall |
| `supports_pf()` | BSD packet filter |
| `supports_tun()` | TUN device support |
| `supports_wireguard_userspace()` | Userspace WireGuard |
| `supports_wireguard_kernel()` | Kernel WireGuard |
| `supports_sandbox()` | OS sandboxing available |
| `is_admin_required_for_tun()` | TUN requires elevation |

### 2.2 `fs.rs` - Filesystem Abstraction

**Types:**
- `SecureDir` - Directory with secure permissions (0o700 on Unix)
- `PlatformPaths` - Platform-aware directory paths following XDG conventions

**Directory Layout by Platform:**

| Platform | Data | Config | Log | Cache | Runtime |
|----------|------|--------|-----|-------|---------|
| Linux/Musl | `/var/lib/synvoid` | `/etc/synvoid` | `/var/log/synvoid` | `/var/cache/synvoid` | `/run/synvoid` |
| macOS | `~/.local/share/synvoid` | `~/.config/synvoid` | `~/.local/log/synvoid` | `~/.cache/synvoid` | `$TMPDIR/synvoid-runtime` |
| BSD | `/var/db/synvoid` | `/usr/local/etc/synvoid` | `/var/log/synvoid` | `/var/cache/synvoid` | `/var/run/synvoid` |
| Windows | `%PROGRAMDATA%\synvoid` | `%PROGRAMDATA%\synvoid\config` | `%PROGRAMDATA%\synvoid\logs` | `%LOCALAPPDATA%\synvoid\cache` | `%LOCALAPPDATA%\synvoid\runtime` |

**Types:**
- `SecureDir` - Directory with secure permissions (0o700 on Unix)
- `PlatformPaths` - Platform-aware directory paths; `new()` is the historical
  SynVoid layout, `for_app(id)` is the application-neutral constructor

**Key Methods:**
- `PlatformPaths::new()` - Historical SynVoid paths; equivalent to `for_app("synvoid")`; deployment paths must not change
- `PlatformPaths::for_app(app)` - Validated application-neutral layout (`InvalidAppId` on separators/traversal)
- `PlatformPaths::with_base(path)` - SynVoid-compatible test helper with custom base directory (deterministic)
- `validate_app_id(app)` - Standalone identifier check (`[A-Za-z0-9._-]`, non-empty, ≤64 bytes, not `.`/`..`)
- `ensure_all()` - Create all required directories
- Generic primitives: `ipc_path(name)`, `*_dir()`, `*_shm_path()`, `panic_log_path(name)`
- SynVoid-specific helpers (interpolate the owning app id, byte-identical for `new()`): `pid_file()`, `socket_path()`, `supervisor_socket_path()`, `cpu_worker_socket_path()`, `unified_worker_socket_path(id)`
- `PlatformError::InvalidAppId(String)` - Rejection reason for bad application identifiers

**Utility Functions:**
- `set_file_permissions(path, read_only)` - Set 0o400/0o600 on Unix
- `set_dir_permissions(path, private)` - Set 0o700/0o755 on Unix

### 2.3 `ipc.rs` - Inter-Process Communication

**Traits:**
```rust
pub trait IpcTransport: Send {
    fn send(&mut self, data: &[u8]) -> io::Result<()>;
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()>;
    fn close(&mut self) -> io::Result<()>;
}

pub trait IpcListener: Send {
    type Stream: IpcTransport;
    fn bind(path: &Path) -> Result<Self, PlatformError>;
    fn accept(&self) -> Result<Self::Stream, PlatformError>;
    fn path(&self) -> &Path;
}

pub trait IpcStream: IpcTransport {
    fn connect(path: &Path) -> Result<Self, PlatformError>;
    fn peer_pid(&self) -> Option<u32>;
}
```

**Platform Implementations:**
- Unix: `UnixIpcListener`, `UnixIpcStream` using Unix domain sockets
- Windows: `WindowsIpcListener`, `WindowsIpcStream` using Named Pipes
- Stub: `StubIpcListener`, `StubIpcStream` for unsupported platforms

### 2.4 `process.rs` - Process Control

**Signal Enum:**
```rust
pub enum Signal {
    Terminate,  // SIGTERM / Ctrl+C
    Interrupt,   // SIGINT / Ctrl+Break
    Reload,      // SIGHUP
    Status,      // SIGUSR2
    User1,       // SIGUSR1
    User2,       // SIGUSR2 (also Status)
}
```

**Traits:**
```rust
pub trait ProcessControl: Send + Sync {
    fn send_signal(&self, pid: u32, signal: Signal) -> Result<(), PlatformError>;
    fn is_process_running(&self, pid: u32) -> bool;
    fn daemonize(&self, pid_file: Option<&Path>) -> Result<(), PlatformError>;
}

pub trait SignalHandler: Send + Sync {
    fn register(&mut self, signal: Signal, handler: Box<dyn Fn() + Send + Sync>) -> Result<(), PlatformError>;
    fn start_listening(&mut self);
    fn stop_listening(&mut self);
}
```

**Platform Implementations:**
- Unix: `UnixProcessControl` (signals via `nix`, daemonize via `daemonize2`)
- Windows: `WindowsProcessControl` (graceful terminate with Ctrl+C, then force kill)
- Stub: `StubProcessControl`, `StubSignalHandler`

**Utility Functions:**
- `terminate_process(child, graceful, timeout_secs)` - Graceful or force termination
- `is_process_running(pid)` - Check process existence

### 2.5 `socket.rs` - Socket Abstractions

**Types:**
```rust
pub enum SocketType { Tcp, Udp }

pub struct SocketInfo {
    pub handle: RawFd,      // Unix: RawFd
    pub handle: RawSocket,  // Windows: RawSocket
    pub port: u16,
    pub socket_type: SocketType,
}

pub struct OwnedTcpListener(std::net::TcpListener);
pub struct OwnedTcpStream(std::net::TcpStream);
```

**Traits:**
```rust
pub trait SocketHandle: Send + Sync {
    fn as_tcp_listener(&self) -> io::Result<TcpListener>;
    fn as_tcp_stream(&self) -> io::Result<TcpStream>;
    fn close(&mut self) -> io::Result<()>;
}

pub trait SocketFDPassing: Send + Sync {
    type Handle: SocketHandle;
    fn new() -> Self;
    fn connect(&mut self, path: &Path) -> io::Result<()>;
    fn send_sockets(&self, handles: &[Self::Handle]) -> Result<(), SocketHandoffError>;
    fn recv_sockets(&self, max_count: usize) -> Result<Vec<Self::Handle>, SocketHandoffError>;
}
```

**Socket Handoff Errors:**
- `CreateFailed`, `BindFailed`, `ListenFailed`, `SetOptFailed`
- `SendFailed`, `RecvFailed`, `NoSocketsReceived`, `TooManySockets`
- `NotConnected`, `NotSupported`, `IpcError`

**Functions:**
- `create_listening_socket(port, reuse_port)` - IPv4 TCP listener
- `create_listening_socket_v6(port, reuse_port)` - IPv6 TCP listener
- `bind_tcp_reuse(addr)` - Reuse address and port
- `bind_udp_reuse(addr)` - UDP with reuse

### 2.6 `sandbox.rs` - Process Sandboxing

**Sandbox Levels:**
```rust
pub enum SandboxLevel {
    Off,    // No sandboxing
    Basic,  // Minimal restrictions
    Strict, // Full path allowlisting
}
```

**Capabilities:**
```rust
pub struct SandboxCapabilities {
    pub read_path_allowlist: bool,
    pub write_path_allowlist: bool,
    pub deny_paths: bool,
    pub process_limits: bool,
    pub network_restrictions: bool,
    pub child_process_restrictions: bool,
}
```

**SandboxBackend Trait:**
```rust
pub trait SandboxBackend: Send + Sync {
    fn apply(&self, read_paths: &[&Path], write_paths: &[&Path], denied_paths: &[&Path]) -> Result<(), SandboxError>;
    fn is_supported(&self) -> bool;
    fn feature_name(&self) -> &'static str;
    fn level(&self) -> SandboxLevel;
    fn capabilities(&self) -> SandboxCapabilities;
}
```

**ProcessSandbox:**
```rust
pub struct ProcessSandbox {
    backend: Box<dyn SandboxBackend>,
}

impl ProcessSandbox {
    pub fn new(level: SandboxLevel) -> Self;
    pub fn with_paths(level: SandboxLevel, paths: SandboxPaths) -> Result<Self, SandboxError>;
    pub fn is_supported(&self) -> bool;
    pub fn level(&self) -> SandboxLevel;
    pub fn feature_name(&self) -> &'static str;
    pub fn capabilities(&self) -> SandboxCapabilities;
}
```

**SandboxPaths Builder:**
```rust
pub struct SandboxPaths {
    read_paths: Vec<PathBuf>,
    write_paths: Vec<PathBuf>,
    no_access_paths: Vec<PathBuf>,
}

impl SandboxPaths {
    pub fn new() -> Self;
    pub fn add_read_path(mut self, path: impl Into<PathBuf>) -> Self;
    pub fn add_write_path(mut self, path: impl Into<PathBuf>) -> Self;
    pub fn add_no_access_path(mut self, path: impl Into<PathBuf>) -> Self;
}
```

**Backend Implementations:**

| Platform | Backend | Features |
|----------|---------|----------|
| Linux (kernel 5.13+) | `LandlockSandbox` | Path allowlisting, read/write/fs |
| FreeBSD | `CapsicumSandbox` | Process limits, network restrictions |
| OpenBSD | `PledgeSandbox` | Promise-based restrictions, unveil for paths |
| macOS | `SeatbeltSandbox` | Sandhook profiles, feature-gated |
| Windows | `WindowsSandbox` | Job Objects, mitigation policies |
| Unsupported | `StubSandbox` | Logs warning, no enforcement |

**Landlock Constants (Linux):**
```
LANDLOCK_ACCESS_FS_READ_FILE, READ_DIR
LANDLOCK_ACCESS_FS_WRITE_FILE, REMOVE_DIR, REMOVE_FILE, MAKE_CHAR, MAKE_DIR, MAKE_REG, MAKE_SOCK, MAKE_FIFO, MAKE_BLOCK, MAKE_SYM
LANDLOCK_ACCESS_FS_EXECUTE
```

### 2.7 `service/` - Service Management

**ServiceConfig:**
```rust
pub struct ServiceConfig {
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub auto_start: bool,
    pub binary_path: Option<PathBuf>,
}
```

**ServiceControl Trait:**
```rust
pub trait ServiceControl: Send + Sync {
    fn install(&self, config: &ServiceConfig) -> Result<(), PlatformError>;
    fn uninstall(&self, name: &str) -> Result<(), PlatformError>;
    fn start(&self, name: &str) -> Result<(), PlatformError>;
    fn stop(&self, name: &str) -> Result<(), PlatformError>;
    fn status(&self, name: &str) -> Result<ServiceState, PlatformError>;
    fn is_installed(&self, name: &str) -> bool;
}
```

**Platform Implementations:**

| Platform | Implementation | Notes |
|----------|---------------|-------|
| Linux (systemd) | `UnixServiceManager` | systemd unit files, systemctl |
| BSD (FreeBSD/OpenBSD) | `UnixServiceManager` | rc.d scripts, service/rcctl commands |
| Windows | `WindowsServiceManager` | `sc create/start/stop/delete/query` |
| macOS / other | `UnixServiceManager` | install/start return `NotSupported`; status reports `Stopped` |

`ServiceConfig::new(name)` takes the service identity explicitly; the
`Default` impl and install templates carry the historical SynVoid identity for
operator compatibility. New applications should construct the config
explicitly rather than relying on the defaults.

**BSD rc.d Script Features:**
- Uses `/usr/sbin/daemon` for backgrounding
- PID file management
- Graceful stop with SIGTERM, force kill after 5 seconds
- `rc.conf` or `rc.conf.d` enablement

## 3. Major Data Structures

### 3.1 Platform Enum
```rust
pub enum Platform {
    Linux,       // glibc
    LinuxMusl,   // Alpine/musl
    Macos,       // macOS
    FreeBSD,     // FreeBSD
    OpenBSD,     // OpenBSD
    NetBSD,      // NetBSD
    Windows,     // Windows (msvc)
    Unknown,     // Fallback
}
```

### 3.2 PlatformError
```rust
pub enum PlatformError {
    NotSupported(String),  // Feature not available
    InvalidAppId(String),  // Application id rejected by validate_app_id (Phase 32)
    Io(std::io::Error),    // I/O errors
    Socket(String),        // Socket errors
    Ipc(String),           // IPC errors
}
```

### 3.3 SocketHandle / SocketFDPassing
Platform-specific handles for cross-process socket transfer via SCM_RIGHTS (Unix) or WSADuplicateSocket (Windows).

### 3.4 SecurityDescriptor (Windows)
Used for creating restrictive DACLs on named pipes:
- Gets current user SID
- Builds DACL with only current user access
- Applied via `SetNamedSecurityInfoW`

## 4. Key APIs and Entry Points

### 4.1 Platform Detection
```rust
Platform::current() -> Platform
platform() -> Platform
is_socket_fd_passing_supported() -> bool
is_reuse_port_supported() -> bool
is_signals_supported() -> bool
is_daemonize_supported() -> bool
is_tun_supported() -> bool
is_wireguard_userspace_supported() -> bool
is_wireguard_kernel_supported() -> bool
is_admin_required_for_tun() -> bool
is_sandbox_supported() -> bool
```

### 4.2 Process Creation and Control
```rust
// Process spawning
terminate_process(child: &mut Child, graceful: bool, timeout_secs: u64) -> io::Result<()>
is_process_running(pid: u32) -> bool

// Using trait objects
use synvoid_platform::process::{PlatformProcessControl, PlatformSignalHandler, ProcessControl, Signal, SignalHandler};
let process_control = PlatformProcessControl;
process_control.send_signal(pid, Signal::Terminate)?;
let running = process_control.is_process_running(pid);
process_control.daemonize(Some(pid_file_path))?;

// Signal handling
let mut handler = PlatformSignalHandler::new();
handler.register(Signal::Terminate, Box::new(|| { /* cleanup */ }))?;
handler.start_listening();
```

### 4.3 Socket Creation with Platform Abstraction
```rust
use synvoid_platform::socket::{create_listening_socket, raw_fd_to_tcp_listener, OwnedTcpListener};

fn create_server(port: u16, reuse_port: bool) -> Result<OwnedTcpListener, PlatformError> {
    let info = create_listening_socket(port, reuse_port)?;
    // info.handle is RawFd on Unix, RawSocket on Windows
    // Use unsafe: raw_fd_to_tcp_listener(fd) or raw_socket_to_tcp_listener(socket)
    unsafe { Ok(raw_fd_to_tcp_listener(info.handle)) }
}
```

### 4.4 IPC Setup
```rust
use synvoid_platform::fs::PlatformPaths;
use synvoid_platform::ipc::{PlatformIpcListener, PlatformIpcStream};

let paths = PlatformPaths::new();
let listener = PlatformIpcListener::bind(&paths.supervisor_socket_path())?;
let stream = PlatformIpcStream::connect(&paths.supervisor_socket_path())?;
```

### 4.5 Sandbox Application
```rust
use synvoid_platform::sandbox::{ProcessSandbox, SandboxLevel, SandboxPaths};

let sandbox = ProcessSandbox::with_paths(
    SandboxLevel::Strict,
    SandboxPaths::new()
        .add_read_path("/var/lib/synvoid")
        .add_write_path("/var/log/synvoid")
        .add_no_access_path("/etc/synvoid/secrets"),
)?;
```

## 5. OS Abstraction Layer

### 5.1 Conditional Compilation Strategy

The crate uses `#[cfg(...)]` to include platform-specific backends, and the
root facade re-exports them as module aliases:

```rust
// In crates/synvoid-platform/src/lib.rs
#[cfg(unix)]
mod unix;            // private backend module
#[cfg(windows)]
mod windows_impl;    // private backend module
#[cfg(windows)]
pub mod windows;     // operator helpers (firewall, interface_resolver, wintun)

// In src/platform/mod.rs (facade: aliases only, no implementations)
pub use synvoid_platform::ipc;
pub use synvoid_platform::socket;
// … plus historical top-level names (SocketHandoffError, Platform, …)
```

### 5.2 Cross-Platform Trait Pattern

Traits define the interface, with platform-specific implementations:

```rust
// In crates/synvoid-platform/src/process.rs
#[cfg(unix)]
pub use crate::unix::UnixProcessControl as PlatformProcessControl;

#[cfg(windows)]
pub use crate::windows_impl::WindowsProcessControl as PlatformProcessControl;

#[cfg(not(any(unix, windows)))]
pub use stub::StubProcessControl as PlatformProcessControl;
```

### 5.3 Capability-Based Feature Detection

Instead of just checking platform, capabilities are queried at runtime:

```rust
if Platform::current().supports_sandbox() {
    // Use Landlock/Capsicum/Pledge/Seatbelt
} else {
    // Fall back to stub or alternative
}
```

## 6. Sandbox Implementation

### 6.1 Landlock (Linux)

**Kernel Requirement:** 5.13+

**Implementation Details:**
- Uses `libc::syscall()` directly (not exposed in standard libc bindings)
- `LANDLOCK_CREATE_RULESET` - Creates ruleset with filesystem access mask
- `LANDLOCK_ADD_RULE` - Adds path beneath rules with allowed access
- `LANDLOCK_RESTRICT_SELF` - Applies ruleset to current process

**Access Flags:**
```rust
const LANDLOCK_ACCESS_FS_READ: u64 = READ_FILE | READ_DIR
const LANDLOCK_ACCESS_FS_WRITE: u64 = WRITE_FILE | REMOVE_DIR | REMOVE_FILE | MAKE_*
const LANDLOCK_ACCESS_FS_ALL: u64 = READ | WRITE | EXECUTE
```

**Path Handling:**
- Opens file to get directory fd
- Uses `O_PATH` or regular open for ruleset insertion
- Supports readonly, read-write, and no-access restrictions

### 6.2 Capsicum (FreeBSD)

**Implementation:**
- Calls `cap_getmode()` to check if kernel supports capsicum
- `cap_enter()` enters capability mode
- No per-path allowlisting (capabilities are broad)

**Capabilities:**
- Process limits
- Network restrictions
- Child process restrictions

### 6.3 Pledge (OpenBSD)

**Two-Phase Sandboxing:**
1. `pledge()` - Restricts system call access
2. `unveil()` - Specifies allowed file paths and permissions

**Promises:** stdio, rpath, wpath, fattr, etc.

### 6.4 Seatbelt (macOS)

**Feature-Gated:** Requires `macos-sandbox` Cargo feature

**Profile Compilation:**
```
(version 1)
(deny default)
(allow process)
(allow signal)
(allow job-creation)
(allow file-read* (subpath "/path"))
(allow file-write* (subpath "/path"))
```

**Sandbox Init:** Uses `sandbox_init()` C function via extern

### 6.5 Windows Job Objects

**Three-Layer Approach:**
1. **Job Object** - Process group limit (256MB process, 512MB job memory)
2. **Mitigation Policies** - DEP, ASLR enablement
3. **Security Descriptors** - File DACL restrictions (Strict level only)

**Configuration:**
```rust
JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    limits_flags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
               | JOB_OBJECT_LIMIT_PROCESS_MEMORY
               | JOB_OBJECT_LIMIT_JOB_MEMORY,
    process_memory_limit: 256 * 1024 * 1024,
    job_memory_limit: 512 * 1024 * 1024,
}
```

## 7. Platform-Specific Code (Unix/Windows)

### 7.1 Unix Implementation (`unix.rs`)

**Socket FD Passing:**
- Uses `nix::sys::socket` for socket operations
- `ControlMessage::ScmRights(&fds)` for sending file descriptors
- Max 254 FDs per message (SCM_MAX_FD from kernel)
- `UnixSocketHandle` wraps RawFd with ownership semantics

**IPC:**
- `UnixListener` / `UnixStream` from `std::os::unix::net`
- Path: `$XDG_RUNTIME_DIR/synvoid-*`
- Non-blocking mode enabled

**Process Control:**
- Signals via `nix::sys::signal::kill()`
- Daemonization via `daemonize2` crate

**Signal Handling:**
- Uses `tokio::signal::unix::SignalKind`
- Spawns async task per signal
- Supports: terminate, interrupt, user1, user2

### 7.2 Windows Implementation (`windows_impl.rs`)

**Socket Handling:**
- `RawSocket` instead of `RawFd`
- `WSADuplicateSocketW` for socket duplication across processes
- `WSASocketW` with `WSA_FLAG_NO_HANDLE_INHERIT` for recreation
- **Note:** The `SocketFDPassing` trait returns `NotSupported` on Windows because Windows uses `WSADuplicateSocketW`-based handoff via `Message::WindowsSocketInfo` instead. Port-swap mode is the default for Windows and handles socket handoff differently.

**IPC:**
- Named Pipes: `\\.\pipe\synvoid-*`
- `CreateNamedPipeW` with overlapping I/O
- `ConnectNamedPipe` for accept

**Process Control:**
- `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION`
- Graceful shutdown via `taskkill /PID pid /T` (sends Ctrl+C)
- Force terminate after timeout

**Security:**
- `SecurityDescriptor::new_user_only()` creates restrictive DACL
- SID lookup via `LookupAccountNameW`
- DACL built with `LocalAlloc` for ACE

**Console Control Handler:**
- `SetConsoleCtrlHandler` registers Ctrl+C/Break handler
- Static `CURRENT_HANDLER` stores handler context
- Maps Windows events to Signal enum

## 8. Feature Gates

### 8.1 Cargo Feature Flags

| Feature | Module | Description |
|---------|--------|-------------|
| `macos-sandbox` | `sandbox/darwin` | Enable Seatbelt sandbox on macOS |

### 8.2 Target-Specific Compilation

**Automatically enabled based on target OS:**
- `target_os = "linux"` - Landlock backend
- `target_os = "freebsd"` - Capsicum backend
- `target_os = "openbsd"` - Pledge backend
- `target_os = "macos"` - Seatbelt backend (requires feature)
- `target_os = "windows"` - Windows Job Objects backend

### 8.3 Stub Backends

Platforms without native sandbox support automatically use `StubSandbox`:
- Logs warning when sandbox is requested
- Provides no actual enforcement
- Allows build to succeed on unsupported platforms

## 9. Directory Structure

> **Canonical location:** `crates/synvoid-platform/src/` (the `synvoid-platform` crate).
> `src/platform/` holds only `mod.rs` (module aliases + top-level re-exports) and
> `AGENTS.override.md` — no implementations (see `facade_disposition_matrix.md` §5
> and the `platform_canonicalization_guard`).

```
crates/synvoid-platform/
├── Cargo.toml            # target-gated nix/daemonize2/tokio/windows-sys/libloading/zip + synvoid-utils
├── src/
│   ├── lib.rs            # Platform enum, PlatformError, module wiring
│   ├── fs.rs             # SecureDir, PlatformPaths (new/for_app/with_base), permissions
│   ├── ipc.rs            # IpcTransport, IpcListener, IpcStream traits + Platform* aliases
│   ├── process.rs        # Signal, ProcessControl, SignalHandler traits + aliases + helpers
│   ├── socket.rs         # SocketHandle, SocketFDPassing, owned types, handoff helpers
│   ├── socket_bind.rs    # Canonical bind_tcp_reuse / bind_udp_reuse
│   ├── sandbox.rs        # SandboxBackend trait, ProcessSandbox, OS backends
│   ├── unix.rs           # Unix backends (private module)
│   ├── windows_impl.rs   # Windows backends (private module)
│   ├── windows.rs        # Operator helpers root (cfg windows)
│   ├── windows/
│   │   ├── firewall.rs       # Windows Firewall API via netsh
│   │   ├── interface_resolver.rs
│   │   └── wintun.rs         # Wintun VPN driver integration (+ non-Windows stub)
│   └── service/
│       ├── mod.rs            # cfg-gated re-exports
│       ├── stub_service.rs   # Unix/Linux service management (systemd, rc.d)
│       └── windows_service.rs # Windows Service implementation (sc.exe)
└── tests/
    ├── socket_handoff_test.rs # IPC bind/connect round-trip, SCM_RIGHTS paths, reuse binds
    ├── platform_paths_test.rs # new()/for_app() parity, id validation, traversal rejection
    └── platform_core_test.rs  # detection, process, sockets, permissions, sandbox fail-closed
```

## 10. Integration Points

### 10.1 Supervisor/Master Architecture
- Uses `PlatformPaths` for runtime directory management
- Uses `PlatformProcessControl` for worker process management
- Uses `PlatformSignalHandler` for signal handling

### 10.2 IPC for Multi-Process Communication
- Master/Worker communication via Unix domain sockets
- Socket FD passing for zero-copy handoff of accept()ed sockets

### 10.3 Sandbox in Worker Processes
- `ProcessSandbox::with_paths()` called during worker initialization
- Applied before processing any tenant traffic

### 10.4 Service Management
- `UnixServiceManager` for Linux/FreeBSD/OpenBSD daemons
- `WindowsService` for Windows server deployments

## 11. Security Considerations

### 11.1 Secure Directory Permissions
- `SecureDir` creates directories with 0o700 (owner-only) on Unix
- `set_file_permissions()` sets 0o400 (readonly) or 0o600 (owner read/write)

### 11.2 TUN Device Access Control
- `is_admin_required_for_tun()` returns `false` for Unix (no admin needed)
- Returns `true` for Windows and Unknown platforms

### 11.3 Windows Named Pipe Security
- `SecurityDescriptor::new_user_only()` creates DACL allowing only current user
- Prevents other users from accessing IPC pipes

### 11.4 Sandbox Enforcement Failures
- `SandboxLevel::Strict` requires backend with `can_enforce_strict() == true`
- Returns `SandboxError::InsufficientCapabilities` if backend lacks read path allowlist

## 12. Phase 32 Canonicalization Notes (2026-09-16)

- Single owner: generic platform traits/types/backends compile exactly once,
  under `crates/synvoid-platform`. `src/platform/` is a pure alias facade;
  `tests/platform_canonicalization_guard.rs` fails any redefinition or any
  non-`pub use` item under `src/platform/`.
- Dormant modules activated: `ipc`, `process`, `socket`, `service`, `unix`,
  `windows_impl` are now wired from `lib.rs`; `windows/` submodules are
  declared (they previously compiled nowhere, and the old root `windows.rs`
  stub meant `windows::wintun` could not have resolved on Windows).
- `socket.rs` no longer defines its own `bind_tcp_reuse`/`bind_udp_reuse`; both
  re-export `socket_bind`. Behavioral note: the surviving implementation sets
  `SO_REUSEPORT` wherever the toolchain reports support (including NetBSD /
  OpenBSD), while the deleted copy only did so on Linux/musl/macOS/FreeBSD.
- Paths: `PlatformPaths::new()` output is byte-identical to before (guarded by
  `platform_paths_test::test_new_matches_for_app_synvoid` and the historical
  -name test). `for_app` generalizes the layout; `InvalidAppId` rejects
  separators/traversal; `with_base` stays deterministic for tests.
- No cycles: the crate depends on `synvoid-utils` (leaf, acyclic) plus
  target-gated OS deps only. The former `synvoid-ipc` dev-dependency was
  removed when the handoff test was rewritten against the crate surface.
- Rejected alternatives: deleting the crate copies and keeping root canonical;
  moving supervisor/application policy into the crate; adding `synvoid-config`
  / metrics edges; per-file feature gates (dependency cost is negligible).
