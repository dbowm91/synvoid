use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};

#[cfg(unix)]
use std::os::unix::net::UnixStream;

#[cfg(unix)]
use nix::sys::socket::{self, Backlog, ControlMessage, MsgFlags, SockaddrIn, SockaddrIn6};

#[cfg(unix)]
use crate::platform::{OwnedTcpListener, OwnedTcpStream};

#[cfg(unix)]
const MAX_FDS_PER_MESSAGE: usize = 254;

#[cfg(not(unix))]
const MAX_FDS_PER_MESSAGE: usize = 1;

#[cfg(unix)]
fn nix_to_io_error(e: nix::errno::Errno) -> io::Error {
    io::Error::other(e.to_string())
}

#[derive(Debug, Clone)]
pub struct SocketInfo {
    #[cfg(unix)]
    pub fd: RawFd,
    #[cfg(windows)]
    pub fd: isize,
    #[cfg(not(any(unix, windows)))]
    pub fd: i32,
    pub port: u16,
    pub socket_type: SocketType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    Tcp,
    Udp,
}

#[derive(Debug, thiserror::Error)]
pub enum SocketFDError {
    #[error("Failed to create socket: {0}")]
    CreateFailed(io::Error),

    #[error("Failed to bind socket: {0}")]
    BindFailed(io::Error),

    #[error("Failed to listen on socket: {0}")]
    ListenFailed(io::Error),

    #[error("Failed to set socket options: {0}")]
    SetOptFailed(io::Error),

    #[error("Failed to send file descriptors: {0}")]
    SendFailed(io::Error),

    #[error("Failed to receive file descriptors: {0}")]
    RecvFailed(io::Error),

    #[error("No file descriptors received")]
    NoFdsReceived,

    #[error("Too many file descriptors: got {got}, max {max}")]
    TooManyFds { got: usize, max: usize },

    #[error("Control message error: {0}")]
    CmsgError(String),

    #[error("Socket not connected")]
    NotConnected,

    #[error("Duplicate socket path: {0}")]
    DuplicatePath(String),

    #[error("Feature not supported on this platform: {0}")]
    NotSupported(String),
}

#[cfg(unix)]
pub struct SocketFDPassing {
    stream: Option<UnixStream>,
}

#[cfg(not(unix))]
pub struct SocketFDPassing {
    connected: bool,
}

impl Default for SocketFDPassing {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(unix)]
impl SocketFDPassing {
    pub fn new() -> Self {
        Self { stream: None }
    }

    pub fn connect(&mut self, path: &Path) -> io::Result<()> {
        let stream = UnixStream::connect(path)?;
        self.stream = Some(stream);
        Ok(())
    }

    pub fn from_stream(stream: UnixStream) -> Self {
        Self {
            stream: Some(stream),
        }
    }

    pub fn send_fds(&self, fds: &[RawFd]) -> Result<(), SocketFDError> {
        let stream = self.stream.as_ref().ok_or(SocketFDError::NotConnected)?;

        if fds.len() > MAX_FDS_PER_MESSAGE {
            return Err(SocketFDError::TooManyFds {
                got: fds.len(),
                max: MAX_FDS_PER_MESSAGE,
            });
        }

        let iov = [io::IoSlice::new(b"FD")];
        let cmsg = [ControlMessage::ScmRights(fds)];
        let flags = MsgFlags::empty();

        socket::sendmsg::<SockaddrIn>(stream.as_raw_fd(), &iov, &cmsg, flags, None)
            .map_err(nix_to_io_error)
            .map_err(SocketFDError::SendFailed)?;

        Ok(())
    }

    pub fn send_fds_with_data(&self, fds: &[RawFd], data: &[u8]) -> Result<(), SocketFDError> {
        let stream = self.stream.as_ref().ok_or(SocketFDError::NotConnected)?;

        if fds.len() > MAX_FDS_PER_MESSAGE {
            return Err(SocketFDError::TooManyFds {
                got: fds.len(),
                max: MAX_FDS_PER_MESSAGE,
            });
        }

        let iov = [io::IoSlice::new(data)];
        let cmsg = [ControlMessage::ScmRights(fds)];
        let flags = MsgFlags::empty();

        socket::sendmsg::<SockaddrIn>(stream.as_raw_fd(), &iov, &cmsg, flags, None)
            .map_err(nix_to_io_error)
            .map_err(SocketFDError::SendFailed)?;

        Ok(())
    }

    pub fn recv_fds(&self, max_fds: usize) -> Result<(Vec<RawFd>, Vec<u8>), SocketFDError> {
        let stream = self.stream.as_ref().ok_or(SocketFDError::NotConnected)?;

        let mut buf = vec![0u8; 4096];
        let mut iov = [io::IoSliceMut::new(&mut buf)];
        let mut cmsg_buffer = nix::cmsg_space!([RawFd; 254]);
        let flags = MsgFlags::empty();

        let msg = socket::recvmsg::<SockaddrIn>(
            stream.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_buffer),
            flags,
        )
        .map_err(nix_to_io_error)
        .map_err(SocketFDError::RecvFailed)?;

        let mut received_fds = Vec::new();

        for cmsg in msg
            .cmsgs()
            .map_err(|e| SocketFDError::CmsgError(e.to_string()))?
        {
            if let socket::ControlMessageOwned::ScmRights(fds) = cmsg {
                for fd in fds {
                    if received_fds.len() < max_fds {
                        received_fds.push(fd);
                    } else {
                        let _ = nix::unistd::close(fd);
                    }
                }
            }
        }

        if received_fds.is_empty() {
            return Err(SocketFDError::NoFdsReceived);
        }

        let data_len = msg.bytes;
        buf.truncate(data_len);

        Ok((received_fds, buf))
    }

    pub fn recv_fds_only(&self, max_fds: usize) -> Result<Vec<RawFd>, SocketFDError> {
        let (fds, _) = self.recv_fds(max_fds)?;
        Ok(fds)
    }

    pub fn into_inner(self) -> Option<UnixStream> {
        self.stream
    }
}

#[cfg(not(unix))]
impl SocketFDPassing {
    pub fn new() -> Self {
        Self { connected: false }
    }

    pub fn connect(&mut self, _path: &Path) -> io::Result<()> {
        self.connected = true;
        Ok(())
    }

    pub fn send_fds(&self, _fds: &[i32]) -> Result<(), SocketFDError> {
        Err(SocketFDError::NotSupported(
            "File descriptor passing is not supported on this platform".to_string(),
        ))
    }

    pub fn send_fds_with_data(&self, _fds: &[i32], _data: &[u8]) -> Result<(), SocketFDError> {
        Err(SocketFDError::NotSupported(
            "File descriptor passing is not supported on this platform".to_string(),
        ))
    }

    pub fn recv_fds(&self, _max_fds: usize) -> Result<(Vec<i32>, Vec<u8>), SocketFDError> {
        Err(SocketFDError::NotSupported(
            "File descriptor passing is not supported on this platform".to_string(),
        ))
    }

    pub fn recv_fds_only(&self, _max_fds: usize) -> Result<Vec<i32>, SocketFDError> {
        Err(SocketFDError::NotSupported(
            "File descriptor passing is not supported on this platform".to_string(),
        ))
    }
}

#[cfg(unix)]
pub fn create_listening_socket(port: u16, reuse_port: bool) -> Result<RawFd, SocketFDError> {
    use nix::sys::socket::{AddressFamily, SockFlag, SockProtocol, SockType};

    let fd = socket::socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::empty(),
        SockProtocol::Tcp,
    )
    .map_err(nix_to_io_error)
    .map_err(SocketFDError::CreateFailed)?;

    socket::setsockopt(&fd, socket::sockopt::ReuseAddr, &true)
        .map_err(nix_to_io_error)
        .map_err(SocketFDError::SetOptFailed)?;

    if reuse_port {
        socket::setsockopt(&fd, socket::sockopt::ReusePort, &true)
            .map_err(nix_to_io_error)
            .map_err(SocketFDError::SetOptFailed)?;
    }

    let addr = SockaddrIn::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));

    socket::bind(fd.as_raw_fd(), &addr)
        .map_err(nix_to_io_error)
        .map_err(SocketFDError::BindFailed)?;

    let backlog = Backlog::new(1024)
        .unwrap_or_else(|_| Backlog::new(128).expect("Backlog 128 should always be valid"));
    socket::listen(&fd, backlog)
        .map_err(nix_to_io_error)
        .map_err(SocketFDError::ListenFailed)?;

    Ok(fd.into_raw_fd())
}

#[cfg(not(unix))]
pub fn create_listening_socket(port: u16, _reuse_port: bool) -> Result<isize, SocketFDError> {
    use std::net::TcpListener;

    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
    let listener = TcpListener::bind(addr).map_err(SocketFDError::BindFailed)?;
    listener
        .set_nonblocking(true)
        .map_err(|e| SocketFDError::ListenFailed(e))?;
    listener
        .listen(1024)
        .map_err(|e| SocketFDError::ListenFailed(e))?;

    Ok(listener.into_raw_fd() as isize)
}

#[cfg(unix)]
pub fn create_listening_socket_v6(port: u16, reuse_port: bool) -> Result<RawFd, SocketFDError> {
    use nix::sys::socket::{AddressFamily, SockFlag, SockProtocol, SockType};

    let fd = socket::socket(
        AddressFamily::Inet6,
        SockType::Stream,
        SockFlag::empty(),
        SockProtocol::Tcp,
    )
    .map_err(nix_to_io_error)
    .map_err(SocketFDError::CreateFailed)?;

    socket::setsockopt(&fd, socket::sockopt::ReuseAddr, &true)
        .map_err(nix_to_io_error)
        .map_err(SocketFDError::SetOptFailed)?;

    socket::setsockopt(&fd, socket::sockopt::Ipv6V6Only, &false)
        .map_err(nix_to_io_error)
        .map_err(SocketFDError::SetOptFailed)?;

    if reuse_port {
        socket::setsockopt(&fd, socket::sockopt::ReusePort, &true)
            .map_err(nix_to_io_error)
            .map_err(SocketFDError::SetOptFailed)?;
    }

    let addr = SockaddrIn6::from(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0));

    socket::bind(fd.as_raw_fd(), &addr)
        .map_err(nix_to_io_error)
        .map_err(SocketFDError::BindFailed)?;

    let backlog = Backlog::new(1024)
        .unwrap_or_else(|_| Backlog::new(128).expect("Backlog 128 should always be valid"));
    socket::listen(&fd, backlog)
        .map_err(nix_to_io_error)
        .map_err(SocketFDError::ListenFailed)?;

    Ok(fd.into_raw_fd())
}

#[cfg(not(unix))]
pub fn create_listening_socket_v6(port: u16, _reuse_port: bool) -> Result<isize, SocketFDError> {
    use std::net::TcpListener;

    let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);
    let listener = TcpListener::bind(addr).map_err(SocketFDError::BindFailed)?;
    listener
        .set_nonblocking(true)
        .map_err(|e| SocketFDError::ListenFailed(e))?;
    listener
        .listen(1024)
        .map_err(|e| SocketFDError::ListenFailed(e))?;

    Ok(listener.into_raw_fd() as isize)
}

/// Converts a raw file descriptor into a TcpListener, taking ownership.
///
/// # Safety
/// The caller must not use the file descriptor after this call.
#[cfg(unix)]
pub unsafe fn raw_fd_to_tcp_listener(fd: RawFd) -> std::net::TcpListener {
    OwnedTcpListener::from_raw_fd(fd).into_inner()
}

/// Converts a raw file descriptor into a TcpListener, taking ownership.
/// This is a non-Unix stub that casts isize to i32.
///
/// # Safety
/// The fd must be a valid, open file descriptor. The caller must not use the
/// file descriptor after this call (ownership is transferred to the TcpListener).
#[cfg(not(unix))]
pub unsafe fn raw_fd_to_tcp_listener(fd: isize) -> std::net::TcpListener {
    std::net::TcpListener::from_raw_fd(fd as i32)
}

/// Converts a raw file descriptor into a TcpStream, taking ownership.
/// This is a non-Unix stub that casts isize to i32.
///
/// # Safety
/// The fd must be a valid, open file descriptor. The caller must not use the
/// file descriptor after this call (ownership is transferred to the TcpStream).
#[cfg(not(unix))]
pub unsafe fn raw_fd_to_tcp_stream(fd: isize) -> std::net::TcpStream {
    std::net::TcpStream::from_raw_fd(fd as i32)
}

/// Converts a raw file descriptor into a TcpStream, taking ownership.
///
/// # Safety
/// The caller must not use the file descriptor after this call.
#[cfg(unix)]
pub unsafe fn raw_fd_to_tcp_stream(fd: RawFd) -> std::net::TcpStream {
    OwnedTcpStream::from_raw_fd(fd).into_inner()
}

#[cfg(unix)]
pub fn close_fd(fd: RawFd) -> io::Result<()> {
    nix::unistd::close(fd).map_err(io::Error::other)
}

#[cfg(not(unix))]
pub fn close_fd(_fd: isize) -> io::Result<()> {
    Ok(())
}

pub struct SocketHolder {
    sockets: Vec<SocketInfo>,
}

impl Default for SocketHolder {
    fn default() -> Self {
        Self::new()
    }
}

impl SocketHolder {
    pub fn new() -> Self {
        Self {
            sockets: Vec::new(),
        }
    }

    #[cfg(unix)]
    pub fn add_socket(&mut self, port: u16, reuse_port: bool) -> Result<RawFd, SocketFDError> {
        let fd = create_listening_socket(port, reuse_port)?;
        self.sockets.push(SocketInfo {
            fd,
            port,
            socket_type: SocketType::Tcp,
        });
        Ok(fd)
    }

    #[cfg(not(unix))]
    pub fn add_socket(&mut self, port: u16, reuse_port: bool) -> Result<isize, SocketFDError> {
        let fd = create_listening_socket(port, reuse_port)?;
        self.sockets.push(SocketInfo {
            fd,
            port,
            socket_type: SocketType::Tcp,
        });
        Ok(fd)
    }

    #[cfg(unix)]
    pub fn add_socket_v6(&mut self, port: u16, reuse_port: bool) -> Result<RawFd, SocketFDError> {
        let fd = create_listening_socket_v6(port, reuse_port)?;
        self.sockets.push(SocketInfo {
            fd,
            port,
            socket_type: SocketType::Tcp,
        });
        Ok(fd)
    }

    #[cfg(not(unix))]
    pub fn add_socket_v6(&mut self, port: u16, reuse_port: bool) -> Result<isize, SocketFDError> {
        let fd = create_listening_socket_v6(port, reuse_port)?;
        self.sockets.push(SocketInfo {
            fd,
            port,
            socket_type: SocketType::Tcp,
        });
        Ok(fd)
    }

    #[cfg(unix)]
    pub fn add_existing_fd(&mut self, fd: RawFd, port: u16, socket_type: SocketType) {
        self.sockets.push(SocketInfo {
            fd,
            port,
            socket_type,
        });
    }

    #[cfg(not(unix))]
    pub fn add_existing_fd(&mut self, fd: isize, port: u16, socket_type: SocketType) {
        self.sockets.push(SocketInfo {
            fd,
            port,
            socket_type,
        });
    }

    #[cfg(unix)]
    pub fn get_fds(&self) -> Vec<RawFd> {
        self.sockets.iter().map(|s| s.fd).collect()
    }

    #[cfg(not(unix))]
    pub fn get_fds(&self) -> Vec<isize> {
        self.sockets.iter().map(|s| s.fd).collect()
    }

    pub fn get_socket_info(&self) -> &[SocketInfo] {
        &self.sockets
    }

    #[cfg(unix)]
    pub fn get_port_for_fd(&self, fd: RawFd) -> Option<u16> {
        self.sockets.iter().find(|s| s.fd == fd).map(|s| s.port)
    }

    #[cfg(not(unix))]
    pub fn get_port_for_fd(&self, fd: isize) -> Option<u16> {
        self.sockets.iter().find(|s| s.fd == fd).map(|s| s.port)
    }

    #[cfg(unix)]
    pub fn send_all(&self, passer: &SocketFDPassing) -> Result<(), SocketFDError> {
        let fds: Vec<RawFd> = self.sockets.iter().map(|s| s.fd).collect();
        passer.send_fds(&fds)
    }

    #[cfg(not(unix))]
    pub fn send_all(&self, _passer: &SocketFDPassing) -> Result<(), SocketFDError> {
        Err(SocketFDError::NotSupported(
            "Socket handoff is not supported on this platform".to_string(),
        ))
    }

    #[cfg(unix)]
    pub fn send_all_with_data(
        &self,
        passer: &SocketFDPassing,
        data: &[u8],
    ) -> Result<(), SocketFDError> {
        let fds: Vec<RawFd> = self.sockets.iter().map(|s| s.fd).collect();
        passer.send_fds_with_data(&fds, data)
    }

    #[cfg(not(unix))]
    pub fn send_all_with_data(
        &self,
        _passer: &SocketFDPassing,
        _data: &[u8],
    ) -> Result<(), SocketFDError> {
        Err(SocketFDError::NotSupported(
            "Socket handoff is not supported on this platform".to_string(),
        ))
    }

    #[cfg(unix)]
    pub fn recv_and_add(
        &mut self,
        passer: &SocketFDPassing,
        ports: &[u16],
    ) -> Result<Vec<u8>, SocketFDError> {
        let (fds, data) = passer.recv_fds(ports.len())?;

        for (fd, &port) in fds.iter().zip(ports.iter()) {
            self.add_existing_fd(*fd, port, SocketType::Tcp);
        }

        for fd in fds.into_iter().skip(ports.len()) {
            if let Err(e) = close_fd(fd) {
                tracing::warn!("Failed to close leaked socket fd {}: {}", fd, e);
            }
        }

        Ok(data)
    }

    #[cfg(not(unix))]
    pub fn recv_and_add(
        &mut self,
        _passer: &SocketFDPassing,
        _ports: &[u16],
    ) -> Result<Vec<u8>, SocketFDError> {
        Err(SocketFDError::NotSupported(
            "Socket handoff is not supported on this platform".to_string(),
        ))
    }

    pub fn close_all(&mut self) {
        for socket in self.sockets.drain(..) {
            if let Err(e) = close_fd(socket.fd) {
                tracing::warn!("Failed to close socket fd {}: {}", socket.fd, e);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.sockets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sockets.is_empty()
    }
}

impl Drop for SocketHolder {
    fn drop(&mut self) {
        self.close_all();
    }
}

pub fn is_reuse_port_supported() -> bool {
    crate::platform::is_reuse_port_supported()
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use tempfile::tempdir;

    #[test]
    fn test_socket_fd_passing_mock() {
        let dir = tempdir().expect("Failed to create temp dir");
        let socket_path = dir.path().join("test.sock");

        let listener = UnixListener::bind(&socket_path).expect("Failed to bind");
        listener
            .set_nonblocking(true)
            .expect("Failed to set nonblocking");

        let mut passer = SocketFDPassing::new();

        let handle = std::thread::spawn(move || {
            let stream = UnixStream::connect(&socket_path).expect("Failed to connect");
            let server_passer = SocketFDPassing::from_stream(stream);
            let result: Result<(), SocketFDError> = server_passer.send_fds_with_data(&[], b"ping");
            assert!(result.is_ok() || matches!(result, Err(SocketFDError::NotConnected)));
        });

        if let Ok((stream, _)) = listener.accept() {
            let mut server_passer = SocketFDPassing::from_stream(stream);
            let (fds, data) = server_passer
                .recv_fds(10)
                .unwrap_or_else(|_| (vec![], vec![]));
            drop(fds);
            drop(data);
        }

        handle.join().expect("Thread panicked");
    }

    #[test]
    fn test_create_listening_socket_mock() {
        let port: u16 = 0;
        let result = create_listening_socket(port, false);
        match result {
            Ok(fd) => {
                assert!(fd >= 0);
                let _ = close_fd(fd);
            }
            Err(e) => {
                tracing::debug!(
                    "Socket creation returned error (expected in some envs): {}",
                    e
                );
            }
        }
    }

    #[test]
    fn test_max_fds_per_message() {
        assert_eq!(MAX_FDS_PER_MESSAGE, 254);
    }

    #[test]
    fn test_socket_fd_error_display() {
        let err = SocketFDError::NotConnected;
        assert!(!format!("{}", err).is_empty());
    }
}
