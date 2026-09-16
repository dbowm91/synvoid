//! Compatibility facade over `synvoid-platform` (Phase 32).
//!
//! `crates/synvoid-platform` is the single compiled owner of reusable
//! OS/platform primitives: detection, filesystem paths, IPC transports,
//! process control, sockets, service management, and sandbox backends.
//! This module contains no implementations; it only re-exports the crate —
//! both as module aliases (so existing `crate::platform::<module>::` paths
//! keep resolving) and as the historical top-level names.
//!
//! New code must import `synvoid_platform` directly for Platform,
//! PlatformError, PlatformPaths, SecureDir, and the convenience functions.

pub use synvoid_platform::fs;
pub use synvoid_platform::fs::{PlatformPaths, SecureDir};
pub use synvoid_platform::ipc;
pub use synvoid_platform::ipc::{IpcListener, IpcStream, IpcTransport};
pub use synvoid_platform::process;
pub use synvoid_platform::process::{ProcessControl, SignalHandler};
pub use synvoid_platform::sandbox;
pub use synvoid_platform::sandbox::{
    ProcessSandbox, SandboxBackend, SandboxCapabilities, SandboxError, SandboxLevel, SandboxPaths,
    StubSandbox,
};
pub use synvoid_platform::service;
pub use synvoid_platform::service::{ServiceConfig, ServiceControl, ServiceState};
pub use synvoid_platform::socket;
pub use synvoid_platform::socket::{
    OwnedTcpListener, OwnedTcpStream, SocketFDPassing, SocketHandle, SocketHandoffError,
};

#[cfg(windows)]
pub use synvoid_platform::windows;
#[cfg(windows)]
pub use synvoid_platform::windows::wintun;

pub use synvoid_platform::{
    is_admin_required_for_tun, is_daemonize_supported, is_reuse_port_supported,
    is_sandbox_supported, is_signals_supported, is_socket_fd_passing_supported, is_tun_supported,
    is_wireguard_kernel_supported, is_wireguard_userspace_supported, platform, Platform,
    PlatformError,
};
