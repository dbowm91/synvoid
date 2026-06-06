use std::io;
use std::path::Path;

use crate::PlatformError;

pub trait IpcTransport: Send {
    fn send(&mut self, data: &[u8]) -> io::Result<()>;
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()>;
    fn close(&mut self) -> io::Result<()>;
}

pub trait IpcListener: Send {
    type Stream: IpcTransport;

    fn bind(path: &Path) -> Result<Self, PlatformError>
    where
        Self: Sized;
    fn accept(&self) -> Result<Self::Stream, PlatformError>;
    fn path(&self) -> &Path;
}

pub trait IpcStream: IpcTransport {
    fn connect(path: &Path) -> Result<Self, PlatformError>
    where
        Self: Sized;
    fn peer_pid(&self) -> Option<u32>;
}

#[cfg(unix)]
pub use crate::unix::UnixIpcListener as PlatformIpcListener;
#[cfg(unix)]
pub use crate::unix::UnixIpcStream as PlatformIpcStream;

#[cfg(windows)]
pub use crate::windows_impl::WindowsIpcListener as PlatformIpcListener;
#[cfg(windows)]
pub use crate::windows_impl::WindowsIpcStream as PlatformIpcStream;

#[cfg(not(any(unix, windows)))]
pub use stub::StubIpcListener as PlatformIpcListener;
#[cfg(not(any(unix, windows)))]
pub use stub::StubIpcStream as PlatformIpcStream;

#[cfg(not(any(unix, windows)))]
mod stub {
    use super::*;

    pub struct StubIpcListener {
        path: std::path::PathBuf,
    }

    impl IpcListener for StubIpcListener {
        type Stream = StubIpcStream;

        fn bind(path: &Path) -> Result<Self, PlatformError> {
            Ok(Self {
                path: path.to_path_buf(),
            })
        }

        fn accept(&self) -> Result<Self::Stream, PlatformError> {
            Err(PlatformError::NotSupported(
                "IPC not supported on this platform".into(),
            ))
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    pub struct StubIpcStream;

    impl IpcTransport for StubIpcStream {
        fn send(&mut self, _data: &[u8]) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Not implemented",
            ))
        }

        fn recv(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Not implemented",
            ))
        }

        fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
            Ok(())
        }

        fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl IpcStream for StubIpcStream {
        fn connect(_path: &Path) -> Result<Self, PlatformError> {
            Err(PlatformError::NotSupported(
                "IPC not supported on this platform".into(),
            ))
        }

        fn peer_pid(&self) -> Option<u32> {
            None
        }
    }
}

pub fn get_default_ipc_path(name: &str) -> std::path::PathBuf {
    use crate::fs::PlatformPaths;
    let paths = PlatformPaths::new();
    paths.ipc_path(name)
}
