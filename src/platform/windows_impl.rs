use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream};
use std::os::windows::io::{AsRawSocket, RawSocket};
use std::path::Path;
use std::sync::Arc;

use super::socket::{OwnedTcpListener, OwnedTcpStream, SocketHandoffError, SocketInfo, SocketType};
use super::ipc::{IpcListener, IpcStream, IpcTransport};
use super::process::{ProcessControl, Signal, SignalHandler};
use super::{PlatformError, Platform};
use crate::RunningFlag;

const PIPE_BUFFER_SIZE: u32 = 65536;

pub struct WindowsSocketHandle {
    socket: RawSocket,
    owned: bool,
}

impl WindowsSocketHandle {
    pub fn new(socket: RawSocket) -> Self {
        Self { socket, owned: true }
    }
    
    pub fn borrowed(socket: RawSocket) -> Self {
        Self { socket, owned: false }
    }
    
    pub fn socket(&self) -> RawSocket {
        self.socket
    }
}

impl super::socket::SocketHandle for WindowsSocketHandle {
    fn as_tcp_listener(&self) -> io::Result<TcpListener> {
        // SAFETY: self.socket is a valid socket handle we own
        Ok(unsafe { OwnedTcpListener::from_raw_socket(self.socket).into_inner() })
    }
    
    fn as_tcp_stream(&self) -> io::Result<TcpStream> {
        // SAFETY: self.socket is a valid socket handle we own
        Ok(unsafe { OwnedTcpStream::from_raw_socket(self.socket).into_inner() })
    }
    
    fn close(&mut self) -> io::Result<()> {
        if self.owned && self.socket != 0 {
            // SAFETY: CloseHandle is called on a valid socket handle we own.
            // The `owned` flag ensures we have exclusive ownership, and the handle
            // is set to 0 (invalid) after closing via the owned=false flag.
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.socket as _);
            }
            self.owned = false;
        }
        Ok(())
    }
}

impl Drop for WindowsSocketHandle {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

pub struct WindowsSocketFDPassing {
    connected: bool,
}

impl super::socket::SocketFDPassing for WindowsSocketFDPassing {
    type Handle = WindowsSocketHandle;
    
    fn new() -> Self {
        Self { connected: false }
    }
    
    fn connect(&mut self, _path: &Path) -> io::Result<()> {
        self.connected = true;
        Ok(())
    }
    
    fn send_sockets(&self, _handles: &[Self::Handle]) -> Result<(), SocketHandoffError> {
        Err(SocketHandoffError::NotSupported(
            "Socket FD passing requires WSADuplicateSocket. Use port-swap upgrade mode instead.".into()
        ))
    }
    
    fn recv_sockets(&self, _max_count: usize) -> Result<Vec<Self::Handle>, SocketHandoffError> {
        Err(SocketHandoffError::NotSupported(
            "Socket FD passing requires WSADuplicateSocket. Use port-swap upgrade mode instead.".into()
        ))
    }
}

pub fn create_listening_socket_windows(port: u16) -> Result<SocketInfo, PlatformError> {
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
    let listener = TcpListener::bind(addr)
        .map_err(PlatformError::Io)?;
    
    listener.set_nonblocking(true)
        .map_err(PlatformError::Io)?;
    
    Ok(SocketInfo {
        handle: listener.as_raw_socket(),
        port,
        socket_type: SocketType::Tcp,
    })
}

pub fn create_listening_socket_v6_windows(port: u16) -> Result<SocketInfo, PlatformError> {
    let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);
    let listener = TcpListener::bind(addr)
        .map_err(PlatformError::Io)?;
    
    listener.set_nonblocking(true)
        .map_err(PlatformError::Io)?;
    
    Ok(SocketInfo {
        handle: listener.as_raw_socket(),
        port,
        socket_type: SocketType::Tcp,
    })
}

pub fn duplicate_socket_for_child(socket: RawSocket, target_pid: u32) -> io::Result<Vec<u8>> {
    use windows_sys::Win32::Networking::WinSock::{WSADuplicateSocketW, SOCKET, WSAPROTOCOL_INFOW};
    use std::mem::{size_of, MaybeUninit};
    
    let mut protocol_info = MaybeUninit::<WSAPROTOCOL_INFOW>::uninit();
    let result = WSADuplicateSocketW(socket as SOCKET, target_pid, protocol_info.as_mut_ptr());
    
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    
    let protocol_info = protocol_info.assume_init();
    // SAFETY: protocol_info is a valid WSAPROTOCOL_INFOW that was initialized by
    // WSADuplicateSocketW. Reinterpreting the struct as a byte slice is safe because:
    // 1. The struct is fully initialized (assume_init was called)
    // 2. The pointer is valid for size_of::<WSAPROTOCOL_INFOW>() bytes
    // 3. No alignment issues (reading bytes from a valid struct)
    let bytes = unsafe {
        std::slice::from_raw_parts(
            &protocol_info as *const _ as *const u8,
            size_of::<WSAPROTOCOL_INFOW>()
        )
    };
    
    Ok(bytes.to_vec())
}

pub fn create_socket_from_duplicate(info_bytes: &[u8]) -> io::Result<WindowsSocketHandle> {
    use windows_sys::Win32::Networking::WinSock::{WSASocketW, SOCKET, WSAPROTOCOL_INFOW, WSA_FLAG_OVERLAPPED};
    use std::mem;
    
    if info_bytes.len() != mem::size_of::<WSAPROTOCOL_INFOW>() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid protocol info size"));
    }
    
    let protocol_info: WSAPROTOCOL_INFOW = (info_bytes.as_ptr() as *const _ as *const WSAPROTOCOL_INFOW).read_unaligned();
    
    // SAFETY: WSASocketW is called with validated protocol info; result is checked for INVALID_SOCKET.
    let socket = unsafe {
        WSASocketW(
            0,
            0,
            0,
            &protocol_info as *const _ as *mut _,
            0,
            WSA_FLAG_OVERLAPPED
        )
    };
    
    if socket == windows_sys::Win32::Networking::WinSock::INVALID_SOCKET {
        return Err(io::Error::last_os_error());
    }
    
    Ok(WindowsSocketHandle::new(socket as RawSocket))
}

pub struct WindowsIpcListener {
    pipe_path: String,
}

impl WindowsIpcListener {
    fn create_named_pipe(&self) -> io::Result<std::fs::File> {
        use windows_sys::Win32::System::Pipes::{
            CreateNamedPipeW, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE,
            PIPE_READMODE_MESSAGE, PIPE_WAIT,
        };
        use windows_sys::Win32::Foundation::FILE_FLAG_OVERLAPPED;
        
        let wide_name: Vec<u16> = self.pipe_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        
        // SAFETY: CreateNamedPipeW is called with a valid pipe name; we check for zero handle.
        unsafe {
            let handle = CreateNamedPipeW(
                wide_name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                1,
                PIPE_BUFFER_SIZE,
                PIPE_BUFFER_SIZE,
                0,
                std::ptr::null_mut(),
            );
            
            if handle == 0 {
                return Err(io::Error::last_os_error());
            }
            
            Ok(std::fs::File::from_raw_handle(handle as _))
        }
    }
}

impl IpcListener for WindowsIpcListener {
    type Stream = WindowsIpcStream;
    
    fn bind(path: &Path) -> Result<Self, PlatformError> {
        let pipe_name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("maluwaf");
        
        Ok(Self {
            pipe_path: format!("\\\\.\\pipe\\{}", pipe_name),
        })
    }
    
    fn accept(&self) -> Result<Self::Stream, PlatformError> {
        let file = self.create_named_pipe()
            .map_err(|e| PlatformError::Ipc(e.to_string()))?;
        
        use windows_sys::Win32::System::Pipes::ConnectNamedPipe;
        use windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED;
        
        // SAFETY: ConnectNamedPipe is called with a valid pipe handle; we check return value.
        let connected = unsafe {
            ConnectNamedPipe(file.as_raw_handle() as *mut _, std::ptr::null_mut())
        };
        
        if connected == 0 {
            let error = windows_sys::Win32::Foundation::GetLastError();
            if error != ERROR_PIPE_CONNECTED {
                return Err(PlatformError::Ipc(format!("ConnectNamedPipe failed: {}", error)));
            }
        }
        
        Ok(WindowsIpcStream { file })
    }
    
    fn path(&self) -> &Path {
        Path::new(&self.pipe_path)
    }
}

pub struct WindowsIpcStream {
    file: std::fs::File,
}

impl IpcTransport for WindowsIpcStream {
    fn send(&mut self, data: &[u8]) -> io::Result<()> {
        use std::io::Write;
        self.file.write_all(data)
    }
    
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::io::Read;
        self.file.read(buf)
    }
    
    fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
        Ok(())
    }
    
    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl IpcStream for WindowsIpcStream {
    fn connect(path: &Path) -> Result<Self, PlatformError> {
        let pipe_name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("maluwaf");
        
        let pipe_path = format!("\\\\.\\pipe\\{}", pipe_name);
        
        let mut attempts = 0;
        let max_attempts = 10;
        
        loop {
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&pipe_path)
            {
                Ok(file) => return Ok(Self { file }),
                Err(e) if e.kind() == io::ErrorKind::NotFound && attempts < max_attempts => {
                    attempts += 1;
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => return Err(PlatformError::Ipc(e.to_string())),
            }
        }
    }
    
    fn peer_pid(&self) -> Option<u32> {
        None
    }
}

pub struct WindowsProcessControl;

impl ProcessControl for WindowsProcessControl {
    fn send_signal(&self, pid: u32, signal: Signal) -> Result<(), PlatformError> {
        match signal {
            Signal::Terminate | Signal::Interrupt => {
                use std::process::Command;
                let _ = Command::new("taskkill")
                    .args(["/PID", &pid.to_string(), "/F"])
                    .output();
                Ok(())
            }
            _ => Err(PlatformError::NotSupported(
                "Only terminate/interrupt signals supported on Windows. Use IPC for other commands.".into()
            )),
        }
    }
    
    fn is_process_running(&self, pid: u32) -> bool {
        std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid)])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()))
            .unwrap_or(false)
    }
    
    fn daemonize(&self, _pid_file: Option<&Path>) -> Result<(), PlatformError> {
        Err(PlatformError::NotSupported(
            "Daemonization not supported on Windows. Use Windows Service instead.".into()
        ))
    }
}

pub struct WindowsSignalHandler {
    handlers: Vec<(Signal, Box<dyn Fn() + Send + Sync>)>,
    running: RunningFlag,
}

impl WindowsSignalHandler {
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
            running: RunningFlag::new(),
        }
    }
}

impl Default for WindowsSignalHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SignalHandler for WindowsSignalHandler {
    fn register(&mut self, signal: Signal, handler: Box<dyn Fn() + Send + Sync>) -> Result<(), PlatformError> {
        if !matches!(signal, Signal::Terminate | Signal::Interrupt) {
            return Err(PlatformError::NotSupported(
                "Only Ctrl+C and terminate signals supported on Windows".into()
            ));
        }
        self.handlers.push((signal, handler));
        Ok(())
    }
    
    fn start_listening(&mut self) {
        self.running.set(true);
        
        let handlers: Vec<Arc<dyn Fn() + Send + Sync>> = self.handlers
            .drain(..)
            .map(|(_, h)| Arc::new(h))
            .collect();
        
        let running = self.running.clone();
        
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            if running.is_running() {
                for handler in &handlers {
                    handler();
                }
            }
        });
    }
    
    fn stop_listening(&mut self) {
        self.running.stop();
    }
}

pub fn close_socket(socket: RawSocket) -> io::Result<()> {
    // SAFETY: closesocket expects a valid socket; we ensure the socket is open.
    unsafe {
        windows_sys::Win32::Networking::WinSock::closesocket(socket as _);
    }
    Ok(())
}

/// Converts a raw socket into an OwnedTcpListener, taking ownership.
///
/// # Safety
/// The caller must not use the socket after this call.
pub unsafe fn raw_socket_to_tcp_listener(socket: RawSocket) -> OwnedTcpListener {
    OwnedTcpListener::from_raw_socket(socket)
}

/// Converts a raw socket into an OwnedTcpStream, taking ownership.
///
/// # Safety
/// The caller must not use the socket after this call.
pub unsafe fn raw_socket_to_tcp_stream(socket: RawSocket) -> OwnedTcpStream {
    OwnedTcpStream::from_raw_socket(socket)
}
