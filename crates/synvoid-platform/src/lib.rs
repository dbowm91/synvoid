//! Platform detection, filesystem utilities, and sandbox primitives.
//!
//! Canonical owner (Phase 32) of reusable OS/platform primitives: platform
//! detection, filesystem paths, IPC transports, process control, sockets,
//! service management, and sandbox backends. The root `src/platform/` module
//! is a compatibility facade over this crate; new code must import
//! `synvoid_platform` directly.
//!
//! Dependency policy (Phase 32, Part C):
//! - OS syscall wrappers own target-scoped deps (`nix`, `daemonize2` on unix;
//!   `windows-sys`, `libloading`, `zip` for Wintun on Windows).
//! - Metrics emission stays at the caller; this crate never depends on
//!   `synvoid-metrics`.
//! - SynVoid configuration types never become dependencies of this crate.
//! - `synvoid-ipc` remains above `synvoid-platform`; this crate must never
//!   depend on it (not even as a dev-dependency).

pub mod fs;
pub mod ipc;
pub mod process;
pub mod sandbox;
pub mod service;
pub mod socket;
pub mod socket_bind;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows_impl;

/// Windows operator helpers (firewall, interface resolution, Wintun loader).
/// Gated on Windows to match the historical root `src/platform/windows/`
/// surface; the `wintun` submodule also carries a non-Windows stub.
#[cfg(windows)]
pub mod windows;

pub use fs::{PlatformPaths, SecureDir};
pub use sandbox::{
    ProcessSandbox, SandboxBackend, SandboxCapabilities, SandboxError, SandboxLevel, SandboxPaths,
    StubSandbox,
};
pub use socket_bind::{bind_tcp_reuse, bind_udp_reuse, is_reuse_port_available};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl Platform {
    pub fn current() -> Self {
        #[cfg(all(target_os = "linux", target_env = "musl"))]
        {
            Platform::LinuxMusl
        }

        #[cfg(all(target_os = "linux", not(target_env = "musl")))]
        {
            Platform::Linux
        }

        #[cfg(target_os = "macos")]
        {
            Platform::Macos
        }

        #[cfg(target_os = "freebsd")]
        {
            Platform::FreeBSD
        }

        #[cfg(target_os = "openbsd")]
        {
            Platform::OpenBSD
        }

        #[cfg(target_os = "netbsd")]
        {
            Platform::NetBSD
        }

        #[cfg(target_os = "windows")]
        {
            Platform::Windows
        }

        #[cfg(not(any(
            all(target_os = "linux", target_env = "musl"),
            all(target_os = "linux", not(target_env = "musl")),
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "windows"
        )))]
        {
            Platform::Unknown
        }
    }

    pub fn is_unix(&self) -> bool {
        matches!(
            self,
            Platform::Linux
                | Platform::LinuxMusl
                | Platform::Macos
                | Platform::FreeBSD
                | Platform::OpenBSD
                | Platform::NetBSD
        )
    }

    pub fn is_linux(&self) -> bool {
        matches!(self, Platform::Linux | Platform::LinuxMusl)
    }

    pub fn is_musl(&self) -> bool {
        matches!(self, Platform::LinuxMusl)
    }

    pub fn is_bsd(&self) -> bool {
        matches!(
            self,
            Platform::FreeBSD | Platform::OpenBSD | Platform::NetBSD
        )
    }

    pub fn supports_socket_fd_passing(&self) -> bool {
        self.is_unix()
    }

    pub fn supports_reuse_port(&self) -> bool {
        matches!(
            self,
            Platform::Linux | Platform::LinuxMusl | Platform::Macos | Platform::FreeBSD
        )
    }

    pub fn supports_signals(&self) -> bool {
        self.is_unix()
    }

    pub fn supports_daemonize(&self) -> bool {
        self.is_unix()
    }

    pub fn supports_ebpf(&self) -> bool {
        matches!(self, Platform::Linux)
    }

    pub fn supports_nftables(&self) -> bool {
        matches!(self, Platform::Linux | Platform::LinuxMusl)
    }

    pub fn supports_pf(&self) -> bool {
        matches!(
            self,
            Platform::Macos | Platform::FreeBSD | Platform::OpenBSD | Platform::NetBSD
        )
    }

    pub fn supports_tun(&self) -> bool {
        match self {
            Platform::Linux | Platform::LinuxMusl | Platform::Macos => true,
            Platform::FreeBSD | Platform::OpenBSD | Platform::NetBSD => true,
            Platform::Windows => true,
            Platform::Unknown => false,
        }
    }

    pub fn supports_wireguard_userspace(&self) -> bool {
        match self {
            Platform::Linux | Platform::LinuxMusl | Platform::Macos => true,
            Platform::FreeBSD | Platform::OpenBSD | Platform::NetBSD => true,
            Platform::Windows => true,
            Platform::Unknown => false,
        }
    }

    pub fn supports_wireguard_kernel(&self) -> bool {
        matches!(self, Platform::Linux | Platform::LinuxMusl)
    }

    pub fn is_admin_required_for_tun(&self) -> bool {
        match self {
            Platform::Windows | Platform::Unknown => true,
            Platform::Linux
            | Platform::LinuxMusl
            | Platform::Macos
            | Platform::FreeBSD
            | Platform::OpenBSD
            | Platform::NetBSD => false,
        }
    }

    pub fn supports_sandbox(&self) -> bool {
        matches!(
            self,
            Platform::Linux | Platform::LinuxMusl | Platform::FreeBSD | Platform::OpenBSD
        )
    }

    pub fn libc_name(&self) -> &'static str {
        match self {
            Platform::Linux => "glibc",
            Platform::LinuxMusl => "musl",
            Platform::Macos => "system",
            Platform::FreeBSD | Platform::OpenBSD | Platform::NetBSD => "system",
            Platform::Windows => "msvc",
            Platform::Unknown => "unknown",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    #[error("Feature not supported on this platform: {0}")]
    NotSupported(String),

    #[error("Invalid application identifier for path construction: {0}")]
    InvalidAppId(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Socket error: {0}")]
    Socket(String),

    #[error("IPC error: {0}")]
    Ipc(String),
}

pub fn platform() -> Platform {
    Platform::current()
}

pub fn is_socket_fd_passing_supported() -> bool {
    platform().supports_socket_fd_passing()
}

pub fn is_reuse_port_supported() -> bool {
    platform().supports_reuse_port()
}

pub fn is_signals_supported() -> bool {
    platform().supports_signals()
}

pub fn is_daemonize_supported() -> bool {
    platform().supports_daemonize()
}

pub fn is_tun_supported() -> bool {
    platform().supports_tun()
}

pub fn is_wireguard_userspace_supported() -> bool {
    platform().supports_wireguard_userspace()
}

pub fn is_wireguard_kernel_supported() -> bool {
    platform().supports_wireguard_kernel()
}

pub fn is_admin_required_for_tun() -> bool {
    platform().is_admin_required_for_tun()
}

pub fn is_sandbox_supported() -> bool {
    platform().supports_sandbox()
}
