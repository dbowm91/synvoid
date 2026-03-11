//! Windows Named Pipe IPC backend.
//!
//! This implementation uses Windows Named Pipes for inter-process communication
//! between the master process and worker processes. Named pipes are the Windows
//! equivalent of Unix domain sockets and provide similar semantics.
//!
//! Unlike Unix sockets, named pipes require explicit management of pipe instances
//! and connection handling. This implementation uses a similar framing protocol
//! (4-byte length prefix + JSON message) to maintain compatibility with the
//! Unix implementation.
//!
//! Signal handling note: On Windows, we cannot use Unix signals (SIGTERM, SIGUSR1, etc.).
//! Instead, we rely entirely on socket/pipe-based IPC for all communication.
//! This is more complex but provides better cross-platform consistency.
//! The master uses a heartbeat mechanism to detect worker crashes.

use std::io;
use std::path::Path;

use super::ipc_backend::{IpcBackend, IpcConnection};

pub struct WindowsIpcBackend {
    pipe_path: String,
    listener: Option<std::fs::File>,
    is_server: bool,
}

impl WindowsIpcBackend {
    pub fn new(pipe_path: String, listener: Option<std::fs::File>, is_server: bool) -> Self {
        Self {
            pipe_path,
            listener,
            is_server,
        }
    }

    fn pipe_name(path: &Path) -> String {
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("rustwaf");
        format!("\\\\.\\pipe\\{}", filename)
    }
}

impl IpcBackend for WindowsIpcBackend {
    fn connect(path: &Path) -> io::Result<Self>
    where
        Self: Sized,
    {
        let pipe_name = Self::pipe_name(path);

        let mut attempts = 0;
        let max_attempts = 10;

        loop {
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&pipe_name)
            {
                Ok(handle) => {
                    return Ok(Self::new(pipe_name, Some(handle), false));
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound && attempts < max_attempts => {
                    attempts += 1;
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn listen(path: &Path) -> io::Result<Self>
    where
        Self: Sized,
    {
        let pipe_name = Self::pipe_name(path);

        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            let wide: Vec<u16> = std::ffi::OsStr::new(&pipe_name)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let handle = unsafe {
                windows_sys::Win32::Foundation::CreateNamedPipeW(
                    wide.as_ptr(),
                    windows_sys::Win32::NamedPipes::PIPE_ACCESS_DUPLEX,
                    windows_sys::Win32::NamedPipes::PIPE_TYPE_MESSAGE
                        | windows_sys::Win32::NamedPipes::PIPE_READMODE_MESSAGE
                        | windows_sys::Win32::NamedPipes::PIPE_WAIT,
                    1,
                    65536,
                    65536,
                    0,
                    std::ptr::null_mut(),
                )
            };

            if handle == 0 {
                return Err(io::Error::last_os_error());
            }

            let file = unsafe { std::fs::File::from_raw_fd(handle as i32) };

            Ok(Self::new(pipe_name, Some(file), true))
        }

        #[cfg(not(windows))]
        {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "Windows named pipes not available on this platform",
            ))
        }
    }

    fn accept(&self) -> io::Result<IpcConnection> {
        #[cfg(windows)]
        {
            if !self.is_server {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Cannot accept on client connection",
                ));
            }

            // Wait for client connection
            let connected = unsafe {
                windows_sys::Win32::NamedPipes::ConnectNamedPipe(
                    self.listener.as_ref().unwrap().as_raw_fd() as *mut _,
                    std::ptr::null_mut(),
                )
            };

            if connected == 0 {
                let error = unsafe { *windows_sys::Win32::Foundation::GetLastError() };
                if error != windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("ConnectNamedPipe failed: {}", error),
                    ));
                }
            }

            // Clone the handle for the connection
            let handle = self.listener.as_ref().unwrap().try_clone()?;
            Ok(IpcConnection::new(handle))
        }

        #[cfg(not(windows))]
        {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "Not supported on this platform",
            ))
        }
    }

    fn platform_name(&self) -> &'static str {
        "windows"
    }
}
