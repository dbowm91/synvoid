//! Compatibility facade for `synvoid-platform`.
//!
//! Core platform detection, filesystem utilities, and convenience functions are
//! re-exported from the dedicated `synvoid-platform` crate. Root-owned modules
//! below contain platform-specific composition code that depends on root
//! infrastructure (nix, tokio, metrics) and cannot be extracted to the crate.
//!
//! New code should import `synvoid_platform` directly for Platform, PlatformError,
//! PlatformPaths, SecureDir, and the convenience functions.

pub mod ipc;
pub mod process;
pub mod sandbox;
pub mod service;
pub mod socket;

pub use ipc::{IpcListener, IpcStream, IpcTransport};
pub use process::{ProcessControl, SignalHandler};
pub use sandbox::{
    ProcessSandbox, SandboxBackend, SandboxCapabilities, SandboxError, SandboxLevel, SandboxPaths,
    StubSandbox,
};
pub use service::{ServiceConfig, ServiceControl, ServiceState};
pub use socket::{
    OwnedTcpListener, OwnedTcpStream, SocketFDPassing, SocketHandle, SocketHandoffError,
};

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

pub use synvoid_platform::fs;
pub use synvoid_platform::fs::{PlatformPaths, SecureDir};
pub use synvoid_platform::{
    is_admin_required_for_tun, is_daemonize_supported, is_reuse_port_supported,
    is_sandbox_supported, is_signals_supported, is_socket_fd_passing_supported, is_tun_supported,
    is_wireguard_kernel_supported, is_wireguard_userspace_supported, platform, Platform,
    PlatformError,
};
