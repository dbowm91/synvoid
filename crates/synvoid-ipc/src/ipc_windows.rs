//! Windows Named Pipe IPC utilities.
//!
//! Provides unified helper functions for Windows named pipe operations.

use std::io;
use std::os::windows::ffi::OsStrExt;

pub const PIPE_BUFFER_SIZE: u32 = 65536;
pub const MAX_PIPE_INSTANCES: u32 = 1;

pub fn pipe_name_to_wide(name: &str) -> Vec<u16> {
    std::ffi::OsStr::new(name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub fn create_named_pipe_server(pipe_name: &str) -> io::Result<std::fs::File> {
    let wide_name = pipe_name_to_wide(pipe_name);

    // SAFETY: CreateNamedPipeW is called with valid parameters; we check for zero handle.
    let handle = unsafe {
        windows_sys::Win32::System::Pipes::CreateNamedPipeW(
            wide_name.as_ptr(),
            windows_sys::Win32::System::Pipes::PIPE_ACCESS_DUPLEX,
            windows_sys::Win32::System::Pipes::PIPE_TYPE_MESSAGE
                | windows_sys::Win32::System::Pipes::PIPE_READMODE_MESSAGE
                | windows_sys::Win32::System::Pipes::PIPE_WAIT,
            MAX_PIPE_INSTANCES,
            PIPE_BUFFER_SIZE,
            PIPE_BUFFER_SIZE,
            0,
            std::ptr::null_mut(),
        )
    };

    if handle == 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: from_raw_handle takes ownership of the handle; we validated it above.
    Ok(unsafe { std::fs::File::from_raw_handle(handle as std::os::windows::io::RawHandle) })
}

pub fn accept_pipe_connection(handle: &std::fs::File) -> io::Result<()> {
    // SAFETY: ConnectNamedPipe is called with a valid pipe handle; we check return value.
    let connected = unsafe {
        windows_sys::Win32::System::Pipes::ConnectNamedPipe(
            handle.as_raw_handle() as *mut _,
            std::ptr::null_mut(),
        )
    };

    if connected == 0 {
        let error = windows_sys::Win32::Foundation::GetLastError();
        if error != windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("ConnectNamedPipe failed with error: {}", error),
            ));
        }
    }

    Ok(())
}

pub fn connect_to_named_pipe(pipe_name: &str, max_attempts: u32) -> io::Result<std::fs::File> {
    let mut attempts = 0;

    loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(pipe_name)
        {
            Ok(handle) => return Ok(handle),
            Err(e) if e.kind() == io::ErrorKind::NotFound && attempts < max_attempts => {
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => return Err(e),
        }
    }
}

pub fn close_pipe_handle(handle: &std::fs::File) {
    // SAFETY: CloseHandle is called on a valid handle we own.
    unsafe {
        windows_sys::Win32::Foundation::CloseHandle(handle.as_raw_handle() as _);
    }
}

pub trait RawHandleExt {
    fn as_raw_handle(&self) -> std::os::windows::io::RawHandle;
}

impl RawHandleExt for std::fs::File {
    fn as_raw_handle(&self) -> std::os::windows::io::RawHandle {
        std::os::windows::io::AsRawHandle::as_raw_handle(self)
    }
}

pub fn supervisor_pipe_name() -> String {
    "\\\\.\\pipe\\synvoid-supervisor".to_string()
}

pub fn static_worker_pipe_name() -> String {
    "\\\\.\\pipe\\synvoid-static-worker".to_string()
}

pub fn commands_pipe_name() -> String {
    "\\\\.\\pipe\\synvoid-commands".to_string()
}
