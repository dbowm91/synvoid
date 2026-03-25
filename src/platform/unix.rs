use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream};
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;

use nix::sys::socket::{self, Backlog, ControlMessage, MsgFlags, SockaddrIn, SockaddrIn6};

use super::socket::{OwnedTcpListener, OwnedTcpStream, SocketHandoffError, SocketInfo, SocketType};
use super::ipc::{IpcListener, IpcStream, IpcTransport};
use super::process::{ProcessControl, Signal, SignalHandler};
use super::{PlatformError, Platform};
use crate::RunningFlag;

const MAX_FDS_PER_MESSAGE: usize = 254;

fn nix_to_io_error(e: nix::errno::Errno) -> io::Error {
    io::Error::other(e.to_string())
}

pub struct UnixSocketHandle {
    fd: RawFd,
    owned: bool,
}

impl UnixSocketHandle {
    pub fn new(fd: RawFd) -> Self {
        Self { fd, owned: true }
    }
    
    pub fn borrowed(fd: RawFd) -> Self {
        Self { fd, owned: false }
    }
    
    pub fn fd(&self) -> RawFd {
        self.fd
    }
}

impl super::socket::SocketHandle for UnixSocketHandle {
    fn as_tcp_listener(&self) -> io::Result<TcpListener> {
        let fd_dup = nix::unistd::dup(self.fd)
            .map_err(io::Error::other)?;
        // SAFETY: fd_dup is a valid file descriptor from dup(), we transfer ownership to TcpListener
        Ok(unsafe { OwnedTcpListener::from_raw_fd(fd_dup).into_inner() })
    }
    
    fn as_tcp_stream(&self) -> io::Result<TcpStream> {
        let fd_dup = nix::unistd::dup(self.fd)
            .map_err(io::Error::other)?;
        // SAFETY: fd_dup is a valid file descriptor from dup(), we transfer ownership to TcpStream
        Ok(unsafe { OwnedTcpStream::from_raw_fd(fd_dup).into_inner() })
    }
    
    fn close(&mut self) -> io::Result<()> {
        if self.owned {
            let _ = nix::unistd::close(self.fd);
            self.owned = false;
        }
        Ok(())
    }
}

impl Drop for UnixSocketHandle {
    fn drop(&mut self) {
        if self.owned {
            let _ = nix::unistd::close(self.fd);
        }
    }
}

pub struct UnixSocketFDPassing {
    stream: Option<UnixStream>,
}

impl super::socket::SocketFDPassing for UnixSocketFDPassing {
    type Handle = UnixSocketHandle;
    
    fn new() -> Self {
        Self { stream: None }
    }
    
    fn connect(&mut self, path: &Path) -> io::Result<()> {
        let stream = UnixStream::connect(path)?;
        self.stream = Some(stream);
        Ok(())
    }
    
    fn send_sockets(&self, handles: &[Self::Handle]) -> Result<(), SocketHandoffError> {
        let stream = self.stream.as_ref().ok_or(SocketHandoffError::NotConnected)?;
        
        if handles.len() > MAX_FDS_PER_MESSAGE {
            return Err(SocketHandoffError::TooManySockets {
                got: handles.len(),
                max: MAX_FDS_PER_MESSAGE,
            });
        }
        
        let fds: Vec<RawFd> = handles.iter().map(|h| h.fd()).collect();
        let iov = [io::IoSlice::new(b"FD")];
        let cmsg = [ControlMessage::ScmRights(&fds)];
        
        socket::sendmsg::<SockaddrIn>(stream.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)
            .map_err(nix_to_io_error)
            .map_err(SocketHandoffError::SendFailed)?;
        
        Ok(())
    }
    
    fn recv_sockets(&self, max_count: usize) -> Result<Vec<Self::Handle>, SocketHandoffError> {
        let stream = self.stream.as_ref().ok_or(SocketHandoffError::NotConnected)?;
        
        let mut buf = vec![0u8; 4096];
        let mut iov = [io::IoSliceMut::new(&mut buf)];
        let mut cmsg_buffer = nix::cmsg_space!([RawFd; 254]);
        
        let msg = socket::recvmsg::<SockaddrIn>(
            stream.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_buffer),
            MsgFlags::empty(),
        )
        .map_err(nix_to_io_error)
        .map_err(SocketHandoffError::RecvFailed)?;
        
        let mut handles = Vec::new();
        
        for cmsg in msg.cmsgs().map_err(|e| SocketHandoffError::IpcError(e.to_string()))? {
            if let socket::ControlMessageOwned::ScmRights(fds) = cmsg {
                for fd in fds {
                    if handles.len() < max_count {
                        handles.push(UnixSocketHandle::new(fd));
                    } else {
                        let _ = nix::unistd::close(fd);
                    }
                }
            }
        }
        
        if handles.is_empty() {
            return Err(SocketHandoffError::NoSocketsReceived);
        }
        
        Ok(handles)
    }
}

pub fn create_listening_socket_unix(port: u16, reuse_port: bool) -> Result<SocketInfo, PlatformError> {
    use nix::sys::socket::{AddressFamily, SockFlag, SockProtocol, SockType};
    
    let fd = socket::socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::empty(),
        SockProtocol::Tcp,
    )
    .map_err(|e| PlatformError::Socket(e.to_string()))?;
    
    socket::setsockopt(&fd, socket::sockopt::ReuseAddr, &true)
        .map_err(|e| PlatformError::Socket(e.to_string()))?;
    
    if reuse_port && Platform::current().supports_reuse_port() {
        let _ = socket::setsockopt(&fd, socket::sockopt::ReusePort, &true);
    }
    
    let addr = SockaddrIn::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
    
    socket::bind(fd.as_raw_fd(), &addr)
        .map_err(|e| PlatformError::Socket(e.to_string()))?;
    
    let backlog = Backlog::new(1024).unwrap_or_else(|_| Backlog::new(128).unwrap());
    socket::listen(&fd, backlog)
        .map_err(|e| PlatformError::Socket(e.to_string()))?;
    
    Ok(SocketInfo {
        handle: fd.into_raw_fd(),
        port,
        socket_type: SocketType::Tcp,
    })
}

pub fn create_listening_socket_v6_unix(port: u16, reuse_port: bool) -> Result<SocketInfo, PlatformError> {
    use nix::sys::socket::{AddressFamily, SockFlag, SockProtocol, SockType};
    
    let fd = socket::socket(
        AddressFamily::Inet6,
        SockType::Stream,
        SockFlag::empty(),
        SockProtocol::Tcp,
    )
    .map_err(|e| PlatformError::Socket(e.to_string()))?;
    
    socket::setsockopt(&fd, socket::sockopt::ReuseAddr, &true)
        .map_err(|e| PlatformError::Socket(e.to_string()))?;
    
    socket::setsockopt(&fd, socket::sockopt::Ipv6V6Only, &false)
        .map_err(|e| PlatformError::Socket(e.to_string()))?;
    
    if reuse_port && Platform::current().supports_reuse_port() {
        let _ = socket::setsockopt(&fd, socket::sockopt::ReusePort, &true);
    }
    
    let addr = SockaddrIn6::from(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0));
    
    socket::bind(fd.as_raw_fd(), &addr)
        .map_err(|e| PlatformError::Socket(e.to_string()))?;
    
    let backlog = Backlog::new(1024).unwrap_or_else(|_| Backlog::new(128).unwrap());
    socket::listen(&fd, backlog)
        .map_err(|e| PlatformError::Socket(e.to_string()))?;
    
    Ok(SocketInfo {
        handle: fd.into_raw_fd(),
        port,
        socket_type: SocketType::Tcp,
    })
}

pub struct UnixIpcListener {
    listener: UnixListener,
    path: std::path::PathBuf,
}

impl IpcListener for UnixIpcListener {
    type Stream = UnixIpcStream;
    
    fn bind(path: &Path) -> Result<Self, PlatformError> {
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
        
        let listener = UnixListener::bind(path)
            .map_err(|e| PlatformError::Ipc(e.to_string()))?;
        
        listener.set_nonblocking(true)
            .map_err(|e| PlatformError::Ipc(e.to_string()))?;
        
        Ok(Self {
            listener,
            path: path.to_path_buf(),
        })
    }
    
    fn accept(&self) -> Result<Self::Stream, PlatformError> {
        let (stream, _addr) = self.listener.accept()
            .map_err(|e| PlatformError::Ipc(e.to_string()))?;
        
        stream.set_nonblocking(true)
            .map_err(|e| PlatformError::Ipc(e.to_string()))?;
        
        Ok(UnixIpcStream { stream })
    }
    
    fn path(&self) -> &Path {
        &self.path
    }
}

pub struct UnixIpcStream {
    stream: UnixStream,
}

impl IpcTransport for UnixIpcStream {
    fn send(&mut self, data: &[u8]) -> io::Result<()> {
        use std::io::Write;
        self.stream.write_all(data)
    }
    
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::io::Read;
        self.stream.read(buf)
    }
    
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.stream.set_nonblocking(nonblocking)
    }
    
    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl IpcStream for UnixIpcStream {
    fn connect(path: &Path) -> Result<Self, PlatformError> {
        let stream = UnixStream::connect(path)
            .map_err(|e| PlatformError::Ipc(e.to_string()))?;
        
        stream.set_nonblocking(true)
            .map_err(|e| PlatformError::Ipc(e.to_string()))?;
        
        Ok(Self { stream })
    }
    
    fn peer_pid(&self) -> Option<u32> {
        None
    }
}

pub struct UnixProcessControl;

impl ProcessControl for UnixProcessControl {
    fn send_signal(&self, pid: u32, signal: Signal) -> Result<(), PlatformError> {
        let sig = match signal {
            Signal::Terminate => nix::sys::signal::Signal::SIGTERM,
            Signal::Interrupt => nix::sys::signal::Signal::SIGINT,
            Signal::Reload => nix::sys::signal::Signal::SIGHUP,
            Signal::Status => nix::sys::signal::Signal::SIGUSR2,
            Signal::User1 => nix::sys::signal::Signal::SIGUSR1,
            Signal::User2 => nix::sys::signal::Signal::SIGUSR2,
        };
        
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), sig)
            .map_err(|e| PlatformError::NotSupported(e.to_string()))?;
        
        Ok(())
    }
    
    fn is_process_running(&self, pid: u32) -> bool {
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), None).is_ok()
    }
    
    fn daemonize(&self, pid_file: Option<&Path>) -> Result<(), PlatformError> {
        use daemonize2::Daemonize;
        
        let mut daemon = Daemonize::new();
        
        if let Some(path) = pid_file {
            daemon = daemon.pid_file(path);
        }
        
        unsafe { daemon.start() }
            // SAFETY: daemon.start() must be called before any threads exist.
            // This runs during early initialization before Tokio runtime starts.
            .map_err(|e| PlatformError::Io(io::Error::other(e)))?;
        
        Ok(())
    }
}

pub struct UnixSignalHandler {
    handlers: Vec<(Signal, Arc<dyn Fn() + Send + Sync>)>,
    running: RunningFlag,
}

impl UnixSignalHandler {
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
            running: RunningFlag::new(),
        }
    }
}

impl Default for UnixSignalHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SignalHandler for UnixSignalHandler {
    fn register(&mut self, signal: Signal, handler: Box<dyn Fn() + Send + Sync>) -> Result<(), PlatformError> {
        self.handlers.push((signal, Arc::from(handler)));
        Ok(())
    }
    
    fn start_listening(&mut self) {
        self.running.set(true);
        
        let handlers: Vec<(Signal, Arc<dyn Fn() + Send + Sync>)> = self.handlers.drain(..).collect();
        
        for (signal, handler) in handlers {
            let sig = match signal {
                Signal::Terminate => tokio::signal::unix::SignalKind::terminate(),
                Signal::Interrupt => tokio::signal::unix::SignalKind::interrupt(),
                Signal::User1 => tokio::signal::unix::SignalKind::user_defined1(),
                Signal::User2 => tokio::signal::unix::SignalKind::user_defined2(),
                Signal::Reload | Signal::Status => continue,
            };
            
            if let Ok(mut signal_stream) = tokio::signal::unix::signal(sig) {
                let handler = handler.clone();
                tokio::spawn(async move {
                    signal_stream.recv().await;
                    handler();
                });
            }
        }
    }
    
    fn stop_listening(&mut self) {
        self.running.stop();
    }
}

pub fn close_socket_fd(fd: RawFd) -> io::Result<()> {
    nix::unistd::close(fd)
        .map_err(io::Error::other)
}

/// Converts a raw file descriptor into an OwnedTcpListener, taking ownership.
///
/// # Safety
/// The caller must not use the file descriptor after this call.
pub unsafe fn raw_fd_to_tcp_listener(fd: RawFd) -> OwnedTcpListener { unsafe {
    OwnedTcpListener::from_raw_fd(fd)
}}

/// Converts a raw file descriptor into an OwnedTcpStream, taking ownership.
///
/// # Safety
/// The caller must not use the file descriptor after this call.
pub unsafe fn raw_fd_to_tcp_stream(fd: RawFd) -> OwnedTcpStream { unsafe {
    OwnedTcpStream::from_raw_fd(fd)
}}
