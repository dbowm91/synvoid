pub mod fs;
pub mod ipc;
pub mod process;
pub mod sandbox;
pub mod service;
pub mod socket;

pub use fs::{PlatformPaths, SecureDir};
pub use ipc::{IpcListener, IpcStream, IpcTransport};
pub use process::{ProcessControl, SignalHandler};
pub use sandbox::{
    ProcessSandbox, SandboxBackend, SandboxError, SandboxLevel, SandboxPaths, StubSandbox,
};
pub use service::{ServiceConfig, ServiceControl, ServiceState};
pub use socket::{
    OwnedTcpListener, OwnedTcpStream, SocketFDPassing, SocketHandle, SocketHandoffError,
};

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
            Platform::Windows => true,
            _ => true,
        }
    }

    pub fn supports_sandbox(&self) -> bool {
        matches!(self, Platform::Linux | Platform::LinuxMusl)
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

#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    #[error("Feature not supported on this platform: {0}")]
    NotSupported(String),

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
