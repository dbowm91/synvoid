#![allow(dead_code)]

use std::io;
use std::net::{TcpListener, TcpStream};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::io::{FromRawFd, RawFd};

#[cfg(windows)]
use std::os::windows::io::{FromRawSocket, RawSocket};

use super::PlatformError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    Tcp,
    Udp,
}

#[derive(Debug, Clone)]
pub struct SocketInfo {
    #[cfg(unix)]
    pub handle: RawFd,
    #[cfg(windows)]
    pub handle: RawSocket,
    pub port: u16,
    pub socket_type: SocketType,
}

#[cfg(unix)]
pub struct OwnedTcpListener(std::net::TcpListener);

#[cfg(unix)]
impl OwnedTcpListener {
    /// Takes ownership of a raw file descriptor and wraps it in an OwnedTcpListener.
    ///
    /// # Safety
    /// The caller must not use the file descriptor after this call, and must ensure
    /// that the descriptor is a valid TCP socket that will not be used elsewhere.
    /// The OwnedTcpListener takes ownership and will close the descriptor on drop.
    pub unsafe fn from_raw_fd(fd: RawFd) -> Self {
        unsafe { Self(std::net::TcpListener::from_raw_fd(fd)) }
    }

    /// Creates a new OwnedTcpListener from a duplicated file descriptor.
    /// This is the safe way to create an OwnedTcpListener from an existing fd.
    pub fn try_from_dup(fd: RawFd) -> io::Result<Self> {
        let fd_dup = nix::unistd::dup(fd).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        // SAFETY: fd_dup is a valid file descriptor from dup()
        Ok(unsafe { Self::from_raw_fd(fd_dup) })
    }

    pub fn into_inner(self) -> std::net::TcpListener {
        self.0
    }

    pub fn as_tcp_listener(&self) -> &std::net::TcpListener {
        &self.0
    }

    pub fn as_tcp_listener_mut(&mut self) -> &mut std::net::TcpListener {
        &mut self.0
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.0.set_nonblocking(nonblocking)
    }
}

#[cfg(unix)]
impl From<OwnedTcpListener> for std::net::TcpListener {
    fn from(owned: OwnedTcpListener) -> Self {
        owned.0
    }
}

#[cfg(unix)]
pub struct OwnedTcpStream(std::net::TcpStream);

#[cfg(unix)]
impl OwnedTcpStream {
    /// Takes ownership of a raw file descriptor and wraps it in an OwnedTcpStream.
    ///
    /// # Safety
    /// The caller must not use the file descriptor after this call, and must ensure
    /// that the descriptor is a valid TCP socket that will not be used elsewhere.
    /// The OwnedTcpStream takes ownership and will close the descriptor on drop.
    pub unsafe fn from_raw_fd(fd: RawFd) -> Self {
        unsafe { Self(std::net::TcpStream::from_raw_fd(fd)) }
    }

    /// Creates a new OwnedTcpStream from a duplicated file descriptor.
    /// This is the safe way to create an OwnedTcpStream from an existing fd.
    pub fn try_from_dup(fd: RawFd) -> io::Result<Self> {
        let fd_dup = nix::unistd::dup(fd).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        // SAFETY: fd_dup is a valid file descriptor from dup()
        Ok(unsafe { Self::from_raw_fd(fd_dup) })
    }

    pub fn into_inner(self) -> std::net::TcpStream {
        self.0
    }

    pub fn as_tcp_stream(&self) -> &std::net::TcpStream {
        &self.0
    }

    pub fn as_tcp_stream_mut(&mut self) -> &mut std::net::TcpStream {
        &mut self.0
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.0.set_nonblocking(nonblocking)
    }
}

#[cfg(unix)]
impl From<OwnedTcpStream> for std::net::TcpStream {
    fn from(owned: OwnedTcpStream) -> Self {
        owned.0
    }
}

#[cfg(windows)]
pub struct OwnedTcpListener(std::net::TcpListener);

#[cfg(windows)]
impl OwnedTcpListener {
    /// Takes ownership of a raw socket and wraps it in an OwnedTcpListener.
    ///
    /// # Safety
    /// The caller must not use the socket after this call, and must ensure
    /// that the socket is a valid TCP socket that will not be used elsewhere.
    /// The OwnedTcpListener takes ownership and will close the socket on drop.
    pub unsafe fn from_raw_socket(socket: RawSocket) -> Self {
        Self(std::net::TcpListener::from_raw_socket(socket))
    }

    pub fn into_inner(self) -> std::net::TcpListener {
        self.0
    }

    pub fn as_tcp_listener(&self) -> &std::net::TcpListener {
        &self.0
    }

    pub fn as_tcp_listener_mut(&mut self) -> &mut std::net::TcpListener {
        &mut self.0
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.0.set_nonblocking(nonblocking)
    }
}

#[cfg(windows)]
impl From<OwnedTcpListener> for std::net::TcpListener {
    fn from(owned: OwnedTcpListener) -> Self {
        owned.0
    }
}

#[cfg(windows)]
pub struct OwnedTcpStream(std::net::TcpStream);

#[cfg(windows)]
impl OwnedTcpStream {
    /// Takes ownership of a raw socket and wraps it in an OwnedTcpStream.
    ///
    /// # Safety
    /// The caller must not use the socket after this call, and must ensure
    /// that the socket is a valid TCP socket that will not be used elsewhere.
    /// The OwnedTcpStream takes ownership and will close the socket on drop.
    pub unsafe fn from_raw_socket(socket: RawSocket) -> Self {
        Self(std::net::TcpStream::from_raw_socket(socket))
    }

    pub fn into_inner(self) -> std::net::TcpStream {
        self.0
    }

    pub fn as_tcp_stream(&self) -> &std::net::TcpStream {
        &self.0
    }

    pub fn as_tcp_stream_mut(&mut self) -> &mut std::net::TcpStream {
        &mut self.0
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.0.set_nonblocking(nonblocking)
    }
}

#[cfg(windows)]
impl From<OwnedTcpStream> for std::net::TcpStream {
    fn from(owned: OwnedTcpStream) -> Self {
        owned.0
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SocketHandoffError {
    #[error("Failed to create socket: {0}")]
    CreateFailed(io::Error),

    #[error("Failed to bind socket: {0}")]
    BindFailed(io::Error),

    #[error("Failed to listen on socket: {0}")]
    ListenFailed(io::Error),

    #[error("Failed to set socket options: {0}")]
    SetOptFailed(io::Error),

    #[error("Failed to send socket: {0}")]
    SendFailed(io::Error),

    #[error("Failed to receive socket: {0}")]
    RecvFailed(io::Error),

    #[error("No sockets received")]
    NoSocketsReceived,

    #[error("Too many sockets: got {got}, max {max}")]
    TooManySockets { got: usize, max: usize },

    #[error("Socket not connected")]
    NotConnected,

    #[error("Feature not supported on this platform: {0}")]
    NotSupported(String),

    #[error("IPC error: {0}")]
    IpcError(String),
}

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

#[cfg(unix)]
pub use super::unix::UnixSocketFDPassing as PlatformSocketFDPassing;
#[cfg(unix)]
pub use super::unix::UnixSocketHandle as PlatformSocketHandle;

#[cfg(windows)]
pub use super::windows_impl::WindowsSocketFDPassing as PlatformSocketFDPassing;
#[cfg(windows)]
pub use super::windows_impl::WindowsSocketHandle as PlatformSocketHandle;

#[cfg(not(any(unix, windows)))]
pub struct StubSocketFDPassing;

#[cfg(not(any(unix, windows)))]
impl SocketFDPassing for StubSocketFDPassing {
    type Handle = StubSocketHandle;

    fn new() -> Self {
        Self
    }
    fn connect(&mut self, _path: &Path) -> io::Result<()> {
        Ok(())
    }
    fn send_sockets(&self, _handles: &[Self::Handle]) -> Result<(), SocketHandoffError> {
        Err(SocketHandoffError::NotSupported(
            "Socket FD passing not supported".into(),
        ))
    }
    fn recv_sockets(&self, _max_count: usize) -> Result<Vec<Self::Handle>, SocketHandoffError> {
        Err(SocketHandoffError::NotSupported(
            "Socket FD passing not supported".into(),
        ))
    }
}

#[cfg(not(any(unix, windows)))]
pub struct StubSocketHandle;

#[cfg(not(any(unix, windows)))]
impl SocketHandle for StubSocketHandle {
    fn as_tcp_listener(&self) -> io::Result<TcpListener> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Not implemented",
        ))
    }
    fn as_tcp_stream(&self) -> io::Result<TcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Not implemented",
        ))
    }
    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn create_listening_socket(port: u16, reuse_port: bool) -> Result<SocketInfo, PlatformError> {
    #[cfg(unix)]
    {
        super::unix::create_listening_socket_unix(port, reuse_port)
    }

    #[cfg(windows)]
    {
        super::windows_impl::create_listening_socket_windows(port)
    }

    #[cfg(not(any(unix, windows)))]
    {
        Err(PlatformError::NotSupported(
            "Socket creation not supported".into(),
        ))
    }
}

pub fn create_listening_socket_v6(
    port: u16,
    reuse_port: bool,
) -> Result<SocketInfo, PlatformError> {
    #[cfg(unix)]
    {
        super::unix::create_listening_socket_v6_unix(port, reuse_port)
    }

    #[cfg(windows)]
    {
        super::windows_impl::create_listening_socket_v6_windows(port)
    }

    #[cfg(not(any(unix, windows)))]
    {
        Err(PlatformError::NotSupported(
            "Socket creation not supported".into(),
        ))
    }
}

pub fn is_reuse_port_available() -> bool {
    crate::platform::is_reuse_port_supported()
}
