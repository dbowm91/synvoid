# Platform Module Architecture

## 1. Purpose and Responsibility

The Platform module (`src/platform/`) provides a unified abstraction layer over operating system functionality, enabling SynVoid to operate consistently across different operating systems while leveraging platform-specific features where beneficial.

**Core Responsibilities:**
- OS detection and capability enumeration (`Platform` enum)
- Platform-specific implementations for: sockets, IPC, process control, signals, sandboxing, service management, filesystem paths
- Sandbox enforcement using OS-native mechanisms (Landlock, Capsicum, Pledge, Seatbelt, Windows Job Objects)
- Service lifecycle management (systemd, BSD rc.d, Windows Services)
- WireGuard and TUN device support

## 2. Key Submodules and Responsibilities

### 2.1 `mod.rs` (Main Module)

**Public Exports:**
```rust
pub mod fs;           // Filesystem paths with security
pub mod ipc;          // Inter-process communication
pub mod process;      // Process control and signals
pub mod sandbox;      // Process sandboxing
pub mod service;      // Service management
pub mod socket;       // Socket abstractions with FD passing
```

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

**Key Methods:**
- `PlatformPaths::new()` - Create with platform defaults
- `PlatformPaths::with_base(path)` - Create with custom base directory
- `ensure_all()` - Create all required directories
- `pid_file()`, `socket_path()`, `ipc_path()`, `master_socket_path()`, `unified_worker_socket_path()`, `panic_log_path()`

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
| Windows | `WindowsService` | Windows Service API |
| macOS | `UnixServiceManager` | launchd (plist files) |

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
let process_control: Box<dyn ProcessControl> = Box::new(PlatformProcessControl::new());
process_control.send_signal(pid, Signal::Terminate)?;
process_control.is_process_running(pid)?;
process_control.daemonize(Some(pid_file_path))?;

// Signal handling
let mut handler: Box<dyn SignalHandler> = Box::new(PlatformSignalHandler::new());
handler.register(Signal::Terminate, Box::new(|| { /* cleanup */ }))?;
handler.start_listening();
```

### 4.3 Socket Creation with Platform Abstraction
```rust
use crate::platform::socket::{create_listening_socket, OwnedTcpListener};

fn create_server(port: u16, reuse_port: bool) -> Result<OwnedTcpListener, PlatformError> {
    let info = create_listening_socket(port, reuse_port)?;
    // info.handle is RawFd on Unix, RawSocket on Windows
    // Use unsafe: raw_fd_to_tcp_listener(fd) or raw_socket_to_tcp_listener(socket)
    unsafe { Ok(raw_fd_to_tcp_listener(info.handle)) }
}
```

### 4.4 IPC Setup
```rust
use crate::platform::ipc::{PlatformIpcListener, PlatformIpcStream};
use crate::platform::get_default_ipc_path;

let path = get_default_ipc_path("synvoid-master");
let listener = PlatformIpcListener::bind(&path)?;
let stream = PlatformIpcStream::connect(&path)?;
```

### 4.5 Sandbox Application
```rust
use crate::platform::sandbox::{ProcessSandbox, SandboxLevel, SandboxPaths};

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

The module uses `#[cfg(...)]` extensively to include platform-specific code:

```rust
// In mod.rs
#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::*;

#[cfg(windows)]
mod windows_impl;
#[cfg(windows)]
pub use windows_impl::*;

#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
pub use windows::wintun;
```

### 5.2 Cross-Platform Trait Pattern

Traits define the interface, with platform-specific implementations:

```rust
// In process.rs
#[cfg(unix)]
pub use super::unix::UnixProcessControl as PlatformProcessControl;

#[cfg(windows)]
pub use super::windows_impl::WindowsProcessControl as PlatformProcessControl;

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

```
src/platform/
├── mod.rs              # Main module, Platform enum, re-exports
├── fs.rs               # SecureDir, PlatformPaths, permissions
├── ipc.rs              # IpcTransport, IpcListener, IpcStream traits
├── process.rs          # Signal, ProcessControl, SignalHandler traits
├── socket.rs           # SocketHandle, SocketFDPassing, owned types
├── sandbox.rs          # SandboxBackend trait, ProcessSandbox, backends
├── unix.rs             # Unix-specific implementations
├── windows_impl.rs     # Windows-specific implementations
├── windows.rs          # Stub module
├── windows/
│   ├── firewall.rs     # Windows Firewall API (if present)
│   ├── interface_resolver.rs
│   └── wintun.rs       # Wintun VPN driver integration
└── service/
    ├── mod.rs          # ServiceControl trait, re-exports
    ├── stub_service.rs # Unix/Linux service management (systemd, rc.d)
    └── windows_service.rs # Windows Service implementation
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
