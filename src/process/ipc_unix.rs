//! Unix socket-based IPC backend.
//!
//! This implementation uses Unix domain sockets for inter-process communication
//! between the master process and worker processes. It provides reliable, local-only
//! communication with minimal overhead.
//!
//! Signal handling note: We use Unix signals (SIGTERM, SIGUSR1, SIGUSR2) in addition to
//! socket-based IPC because:
//! 1. Signals work even if the socket layer is blocked/unresponsive
//! 2. They provide a fallback mechanism for critical commands like shutdown
//! 3. They allow for immediate termination without waiting for socket acknowledgment

use std::io;
use std::path::Path;

use super::ipc_backend::{IpcBackend, IpcConnection};

pub struct UnixIpcBackend {
    listener: std::os::unix::net::UnixListener,
}

impl UnixIpcBackend {
    pub fn new(listener: std::os::unix::net::UnixListener) -> Self {
        Self { listener }
    }
}

impl IpcBackend for UnixIpcBackend {
    fn connect(_path: &Path) -> io::Result<Self>
    where
        Self: Sized,
    {
        // For client connections, we don't use this backend directly
        // Instead, the existing IpcStream in ipc.rs handles client connections
        Err(io::Error::new(
            io::ErrorKind::Other,
            "Use IpcStream for client connections",
        ))
    }

    fn listen(path: &Path) -> io::Result<Self>
    where
        Self: Sized,
    {
        use std::os::unix::net::UnixListener;

        if path.exists() {
            std::fs::remove_file(path)?;
        }

        let listener = UnixListener::bind(path)?;
        listener.set_nonblocking(true)?;
        Ok(Self::new(listener))
    }

    fn accept(&self) -> io::Result<IpcConnection> {
        match self.listener.accept() {
            Ok((stream, _)) => Ok(IpcConnection::new(stream)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no pending connections",
            )),
            Err(e) => Err(e),
        }
    }

    fn platform_name(&self) -> &'static str {
        "unix"
    }
}
