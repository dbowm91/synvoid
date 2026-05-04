use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream};
use std::os::windows::io::{AsRawSocket, RawSocket};
use std::path::Path;
use std::sync::Arc;

use super::ipc::{IpcListener, IpcStream, IpcTransport};
use super::process::{ProcessControl, Signal, SignalHandler};
use super::socket::{OwnedTcpListener, OwnedTcpStream, SocketHandoffError, SocketInfo, SocketType};
use super::{Platform, PlatformError};
use crate::RunningFlag;

const PIPE_BUFFER_SIZE: u32 = 65536;

pub struct WindowsSocketHandle {
    socket: RawSocket,
    owned: bool,
}

impl WindowsSocketHandle {
    pub fn new(socket: RawSocket) -> Self {
        Self {
            socket,
            owned: true,
        }
    }

    pub fn borrowed(socket: RawSocket) -> Self {
        Self {
            socket,
            owned: false,
        }
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
            "Socket FD passing requires WSADuplicateSocket. Use port-swap upgrade mode instead."
                .into(),
        ))
    }

    fn recv_sockets(&self, _max_count: usize) -> Result<Vec<Self::Handle>, SocketHandoffError> {
        Err(SocketHandoffError::NotSupported(
            "Socket FD passing requires WSADuplicateSocket. Use port-swap upgrade mode instead."
                .into(),
        ))
    }
}

pub fn create_listening_socket_windows(port: u16) -> Result<SocketInfo, PlatformError> {
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
    let listener = TcpListener::bind(addr).map_err(PlatformError::Io)?;

    listener.set_nonblocking(true).map_err(PlatformError::Io)?;

    Ok(SocketInfo {
        handle: listener.as_raw_socket(),
        port,
        socket_type: SocketType::Tcp,
    })
}

pub fn create_listening_socket_v6_windows(port: u16) -> Result<SocketInfo, PlatformError> {
    let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);
    let listener = TcpListener::bind(addr).map_err(PlatformError::Io)?;

    listener.set_nonblocking(true).map_err(PlatformError::Io)?;

    Ok(SocketInfo {
        handle: listener.as_raw_socket(),
        port,
        socket_type: SocketType::Tcp,
    })
}

pub fn duplicate_socket_for_child(socket: RawSocket, target_pid: u32) -> io::Result<Vec<u8>> {
    use std::mem::{size_of, MaybeUninit};
    use windows_sys::Win32::Networking::WinSock::{WSADuplicateSocketW, SOCKET, WSAPROTOCOL_INFOW};

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
            size_of::<WSAPROTOCOL_INFOW>(),
        )
    };

    Ok(bytes.to_vec())
}

pub fn create_socket_from_duplicate(info_bytes: &[u8]) -> io::Result<WindowsSocketHandle> {
    use std::mem;
    use windows_sys::Win32::Networking::WinSock::{
        WSASocketW, SOCKET, WSAPROTOCOL_INFOW, WSA_FLAG_NO_HANDLE_INHERIT, WSA_FLAG_OVERLAPPED,
    };

    if info_bytes.len() != mem::size_of::<WSAPROTOCOL_INFOW>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid protocol info size",
        ));
    }

    let protocol_info: WSAPROTOCOL_INFOW =
        (info_bytes.as_ptr() as *const _ as *const WSAPROTOCOL_INFOW).read_unaligned();

    // SAFETY: WSASocketW is called with validated protocol info; result is checked for INVALID_SOCKET.
    // WSA_FLAG_NO_HANDLE_INHERIT prevents child processes from inheriting the socket.
    let socket = unsafe {
        WSASocketW(
            0,
            0,
            0,
            &protocol_info as *const _ as *mut _,
            0,
            WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
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
        use windows_sys::Win32::Foundation::FILE_FLAG_OVERLAPPED;

        let wide_name: Vec<u16> = self
            .pipe_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let security = security::SecurityDescriptor::new_user_only()?;

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
                security.as_ptr(),
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
        let pipe_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("maluwaf");

        Ok(Self {
            pipe_path: format!("\\\\.\\pipe\\{}", pipe_name),
        })
    }

    fn accept(&self) -> Result<Self::Stream, PlatformError> {
        let file = self
            .create_named_pipe()
            .map_err(|e| PlatformError::Ipc(e.to_string()))?;

        use windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED;
        use windows_sys::Win32::System::Pipes::ConnectNamedPipe;

        // SAFETY: ConnectNamedPipe is called with a valid pipe handle; we check return value.
        let connected =
            unsafe { ConnectNamedPipe(file.as_raw_handle() as *mut _, std::ptr::null_mut()) };

        if connected == 0 {
            let error = windows_sys::Win32::Foundation::GetLastError();
            if error != ERROR_PIPE_CONNECTED {
                return Err(PlatformError::Ipc(format!(
                    "ConnectNamedPipe failed: {}",
                    error
                )));
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
        let pipe_name = path
            .file_name()
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

pub struct WindowsProcessControl {
    graceful_shutdown_timeout_secs: u64,
}

impl WindowsProcessControl {
    pub fn new() -> Self {
        Self {
            graceful_shutdown_timeout_secs: 30,
        }
    }

    pub fn with_graceful_shutdown_timeout(mut self, secs: u64) -> Self {
        self.graceful_shutdown_timeout_secs = secs;
        self
    }
}

impl Default for WindowsProcessControl {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessControl for WindowsProcessControl {
    fn send_signal(&self, pid: u32, signal: Signal) -> Result<(), PlatformError> {
        match signal {
            Signal::Terminate | Signal::Interrupt => {
                self.graceful_terminate(pid)
            }
            _ => Err(PlatformError::NotSupported(
                "Only terminate/interrupt signals supported on Windows. Use IPC for other commands.".into()
            )),
        }
    }

    fn is_process_running(&self, pid: u32) -> bool {
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, STILL_ACTIVE,
        };

        // SAFETY: OpenProcess is called with PROCESS_QUERY_LIMITED_INFORMATION access right.
        // We only need to check if the process exists, and CloseHandle properly releases the handle.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };

        if handle == 0 {
            return false;
        }

        // SAFETY: CloseHandle is called on a handle we just opened.
        unsafe { CloseHandle(handle) };
        true
    }

    fn daemonize(&self, _pid_file: Option<&Path>) -> Result<(), PlatformError> {
        Err(PlatformError::NotSupported(
            "Daemonization not supported on Windows. Use Windows Service instead.".into(),
        ))
    }
}

impl WindowsProcessControl {
    fn graceful_terminate(&self, pid: u32) -> Result<(), PlatformError> {
        use std::thread;
        use std::time::Duration;
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_TIMEOUT};
        use windows_sys::Win32::System::Threading::{
            OpenProcess, TerminateProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_TERMINATE,
        };

        // SAFETY: OpenProcess is called with PROCESS_TERMINATE access right for graceful termination.
        // We properly close the handle after use.
        let handle = unsafe {
            OpenProcess(
                PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                pid,
            )
        };

        if handle == 0 {
            return Err(PlatformError::NotSupported(format!(
                "Failed to open process {}: {}",
                pid,
                std::io::Error::last_os_error()
            )));
        }

        // First try graceful shutdown via Ctrl+C signal
        let ctrl_result = self.send_ctrl_c_to_process(pid);

        if ctrl_result.is_ok() {
            // Wait for graceful shutdown with timeout
            let timeout_ms = (self.graceful_shutdown_timeout_secs * 1000) as u32;
            let wait_result = unsafe { WaitForSingleObject(handle, timeout_ms) };

            if wait_result == WAIT_TIMEOUT {
                // Graceful shutdown timed out, force terminate
                tracing::warn!("Process {} did not terminate gracefully, forcing", pid);
                unsafe { TerminateProcess(handle, 1) };
            }
        } else {
            // Process doesn't respond to Ctrl+C, terminate directly
            tracing::warn!("Process {} does not respond to Ctrl+C, terminating", pid);
            unsafe { TerminateProcess(handle, 1) };
        }

        // SAFETY: CloseHandle is called on a handle we just opened.
        unsafe { CloseHandle(handle) };
        Ok(())
    }

    fn send_ctrl_c_to_process(&self, pid: u32) -> Result<(), PlatformError> {
        use std::process::Command;

        let output = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T"])
            .output()
            .map_err(|e| PlatformError::NotSupported(format!("Failed to send Ctrl+C: {}", e)))?;

        if !output.status.success() {
            return Err(PlatformError::NotSupported(format!(
                "Ctrl+C to process {} failed: {}",
                pid,
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }
}

pub struct WindowsSignalHandler {
    handlers: Vec<(Signal, Box<dyn Fn() + Send + Sync>)>,
    running: RunningFlag,
    #[cfg(windows)]
    ctrl_handler_handle: Option<windows_sys::Win32::System::Console::HANDLE>,
}

impl WindowsSignalHandler {
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
            running: RunningFlag::new(),
            #[cfg(windows)]
            ctrl_handler_handle: None,
        }
    }
}

#[cfg(windows)]
extern "system" fn windows_ctrl_handler(dw_ctrl_type: u32) -> i32 {
    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_C_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
    };

    let signal = match dw_ctrl_type {
        CTRL_C_EVENT | CTRL_BREAK_EVENT => Signal::Interrupt,
        CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => Signal::Terminate,
        _ => return 0, // Event not handled
    };

    tracing::info!("Received Windows console control event: {}", dw_ctrl_type);

    // Global handler will be invoked through the registered handlers
    unsafe {
        if let Some(ctx) = CURRENT_HANDLER.load(std::sync::atomic::Ordering::SeqCst) {
            (*ctx).invoke_handlers(signal);
        }
    }

    1 // Event handled
}

#[cfg(windows)]
static CURRENT_HANDLER: std::sync::atomic::AtomicPtr<()> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

#[cfg(windows)]
impl WindowsSignalHandler {
    unsafe fn invoke_handlers(&self, signal: Signal) {
        for (s, handler) in &self.handlers {
            if matches!(s, Signal::Terminate | Signal::Interrupt) {
                handler();
            }
        }
    }

    fn register_windows_ctrl_handler() -> Option<windows_sys::Win32::System::Console::HANDLE> {
        use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;

        // SAFETY: SetConsoleCtrlHandler is called with our handler function.
        // The handler properly handles all control events and calls registered Rust handlers.
        let result = unsafe { SetConsoleCtrlHandler(Some(windows_ctrl_handler), 1) };

        if result != 0 {
            None
        } else {
            Some(0) // Return dummy handle to indicate registration attempted
        }
    }
}

impl Default for WindowsSignalHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SignalHandler for WindowsSignalHandler {
    fn register(
        &mut self,
        signal: Signal,
        handler: Box<dyn Fn() + Send + Sync>,
    ) -> Result<(), PlatformError> {
        if !matches!(signal, Signal::Terminate | Signal::Interrupt) {
            return Err(PlatformError::NotSupported(
                "Only Ctrl+C and terminate signals supported on Windows".into(),
            ));
        }
        self.handlers.push((signal, handler));
        Ok(())
    }

    fn start_listening(&mut self) {
        self.running.set(true);

        let handlers: Vec<Arc<dyn Fn() + Send + Sync>> =
            self.handlers.drain(..).map(|(_, h)| Arc::new(h)).collect();

        let running = self.running.clone();

        #[cfg(windows)]
        {
            self.ctrl_handler_handle = Self::register_windows_ctrl_handler();
        }

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

        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
            if self.ctrl_handler_handle.is_some() {
                // SAFETY: SetConsoleCtrlHandler is called to remove our handler.
                unsafe { SetConsoleCtrlHandler(Some(windows_ctrl_handler), 0) };
                self.ctrl_handler_handle = None;
            }
        }
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

#[cfg(windows)]
pub mod security {
    use std::io;

    use windows_sys::Win32::Foundation::FILE_FLAG_OVERLAPPED;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, PSID};
    use windows_sys::Win32::Security::{
        AllocateAndInitializeSid, CopySid, EqualSid, FreeSid, GetLengthSid, GetNamedSecurityInfoW,
        GetSecurityDescriptorDacl, InitializeSecurityDescriptor, LookupAccountNameW,
        SetSecurityDescriptorDacl, ACL_SIZE_INFORMATION, DACL_SIZE_INFORMATION,
        PSECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR_REVISION, SID_NAME_USE,
    };
    use windows_sys::Win32::System::Memory::{LocalFree, RtlMoveMemory};
    use windows_sys::Win32::System::Pipes::{
        CreateNamedPipeW, PIPE_ACCESS_DUPLEX, PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_WAIT,
    };

    const FILE_ALL_ACCESS: u32 = 0x1_0000 | 0x1FF;
    const SECURITY_DESCRIPTOR_SIZE: usize = std::mem::size_of::<SECURITY_DESCRIPTOR>();
    const ACL_SIZE: usize = std::mem::size_of::<windows_sys::Win32::Security::ACL>();

    pub struct SecurityDescriptor {
        raw: Vec<u8>,
    }

    impl SecurityDescriptor {
        pub fn new_user_only() -> Result<Self, io::Error> {
            let mut sd_bytes = vec![0u8; SECURITY_DESCRIPTOR_SIZE + ACL_SIZE + 256];

            let sd = sd_bytes.as_mut_ptr() as *mut SECURITY_DESCRIPTOR;
            unsafe {
                if InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION) == 0 {
                    return Err(io::Error::last_os_error());
                }
            }

            let current_user_sid = get_current_user_sid()?;
            let dacl = build_dacl(current_user_sid)?;

            unsafe {
                if SetSecurityDescriptorDacl(sd, 1, Some(dacl), 0) == 0 {
                    FreeSid(current_user_sid);
                    return Err(io::Error::last_os_error());
                }
            }

            unsafe { FreeSid(current_user_sid) };

            Ok(Self { raw: sd_bytes })
        }

        pub fn as_ptr(&self) -> *mut std::ffi::c_void {
            self.raw.as_ptr() as *mut std::ffi::c_void
        }
    }

    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {}
    }

    fn get_current_user_sid() -> Result<PSID, io::Error> {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;

        let mut name_buf = vec![0u16; 128];
        let mut name_len = name_buf.len() as u32;

        let domain_buf = vec![0u16; 128];
        let mut domain_len = domain_buf.len() as u32;
        let mut sid_size = 256u32;
        let mut sid_buf = vec![0u8; 256];
        let mut use_ = SID_NAME_USE(0);

        let computer_name: Vec<u16> = OsString::from("localhost")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            if LookupAccountNameW(
                computer_name.as_ptr(),
                std::ptr::null(),
                sid_buf.as_mut_ptr() as PSID,
                &mut sid_size,
                domain_buf.as_mut_ptr(),
                &mut domain_len,
                &mut use_,
            ) != 0
            {
                return Ok(sid_buf.as_ptr() as PSID);
            }

            let err = GetLastError();
            if err != 122 {
                return Err(io::Error::from_raw_os_error(err as i32));
            }
        }

        let sid_size = (sid_size as usize) * std::mem::size_of::<u8>();
        let mut sid_buf = vec![0u8; sid_size];
        let mut actual_sid_size = sid_size as u32;

        unsafe {
            let result = LookupAccountNameW(
                std::ptr::null(),
                std::ptr::null(),
                sid_buf.as_mut_ptr() as PSID,
                &mut actual_sid_size,
                domain_buf.as_mut_ptr(),
                &mut domain_len,
                &mut use_,
            );

            if result == 0 {
                return Err(io::Error::last_os_error());
            }

            let sid = vec![0u8; actual_sid_size as usize * std::mem::size_of::<u8>()];
            let mut sid_ptr = sid.as_ptr() as *mut u8;
            CopySid(actual_sid_size, &mut sid_ptr, sid_buf.as_ptr() as PSID);

            let mut sid_result = vec![0u8; actual_sid_size as usize * std::mem::size_of::<u8>()];
            std::ptr::copy_nonoverlapping(sid_buf.as_ptr(), sid_result.as_mut_ptr(), sid_buf.len());

            let actual_sid_size_bytes = actual_sid_size as usize * std::mem::size_of::<u8>();
            let mut final_sid_vec = vec![0u8; actual_sid_size_bytes];
            std::ptr::copy_nonoverlapping(
                sid_buf.as_ptr(),
                final_sid_vec.as_mut_ptr(),
                sid_buf.len(),
            );

            let mut sid = vec![0u8; actual_sid_size as usize];
            std::ptr::copy_nonoverlapping(sid_buf.as_ptr(), sid.as_mut_ptr(), sid.len());

            return allocate_sid(&sid);
        }
    }

    fn allocate_sid(sid_bytes: &[u8]) -> Result<PSID, io::Error> {
        if sid_bytes.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Empty SID"));
        }

        unsafe {
            let sub_authority_count = *sid_bytes.offset(1) as u8;
            let sid_size = (8 + (sub_authority_count as usize) * 4) * std::mem::size_of::<u32>();
            let sid_mem = windows_sys::Win32::System::Memory::LocalAlloc(0x0000_0040, sid_size);

            if sid_mem.is_null() {
                return Err(io::Error::last_os_error());
            }

            let dest = std::slice::from_raw_parts_mut(sid_mem as *mut u8, sid_size);
            dest.copy_from_slice(sid_bytes);

            Ok(sid_mem as PSID)
        }
    }

    fn build_dacl(user_sid: PSID) -> Result<*mut windows_sys::Win32::Security::ACL, io::Error> {
        let sid_len = unsafe { GetLengthSid(user_sid) } as usize;

        let acl_size = ACL_SIZE
            + sid_len
            + std::mem::size_of::<windows_sys::Win32::Security::ACCESS_ALLOWED_ACE>()
            + 8;

        let dacl = unsafe { windows_sys::Win32::System::Memory::LocalAlloc(0x0000_0040, acl_size) };

        if dacl.is_null() {
            return Err(io::Error::last_os_error());
        }

        unsafe {
            let acl = dacl as *mut windows_sys::Win32::Security::ACL;
            (*acl).AclRevision = 2;
            (*acl).Sbz1 = 0;
            (*acl).AclSize = acl_size as u16;
            (*acl).AceCount = 1;
            (*acl).Sbz2 = 0;

            let ace = (acl as *mut u8).add(ACL_SIZE)
                as *mut windows_sys::Win32::Security::ACCESS_ALLOWED_ACE;
            (*ace).Header.AceType = windows_sys::Win32::Security::ACCESS_ALLOWED_ACE_TYPE;
            (*ace).Header.AceFlags = 0;
            (*ace).Header.AceSize = (std::mem::size_of::<
                windows_sys::Win32::Security::ACCESS_ALLOWED_ACE,
            >() + sid_len) as u16;
            (*ace).Mask = FILE_ALL_ACCESS;

            let sid_dest = (ace as *mut u8).add(std::mem::size_of::<
                windows_sys::Win32::Security::ACCESS_ALLOWED_ACE,
            >()) as *mut u8;
            let sid_src = user_sid as *const u8;
            std::ptr::copy_nonoverlapping(sid_src, sid_dest, sid_len);

            Ok(acl)
        }
    }
}
