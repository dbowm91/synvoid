use std::io;
use std::process::Child;

use crate::PlatformError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Terminate,
    Interrupt,
    Reload,
    Status,
    User1,
    User2,
}

pub trait ProcessControl: Send + Sync {
    fn send_signal(&self, pid: u32, signal: Signal) -> Result<(), PlatformError>;
    fn is_process_running(&self, pid: u32) -> bool;
    fn daemonize(&self, pid_file: Option<&std::path::Path>) -> Result<(), PlatformError>;
}

pub trait SignalHandler: Send + Sync {
    fn register(
        &mut self,
        signal: Signal,
        handler: Box<dyn Fn() + Send + Sync>,
    ) -> Result<(), PlatformError>;
    fn start_listening(&mut self);
    fn stop_listening(&mut self);
}

#[cfg(unix)]
pub use crate::unix::UnixProcessControl as PlatformProcessControl;
#[cfg(unix)]
pub use crate::unix::UnixSignalHandler as PlatformSignalHandler;

#[cfg(windows)]
pub use crate::windows_impl::WindowsProcessControl as PlatformProcessControl;
#[cfg(windows)]
pub use crate::windows_impl::WindowsSignalHandler as PlatformSignalHandler;

#[cfg(not(any(unix, windows)))]
pub use stub::StubProcessControl as PlatformProcessControl;
#[cfg(not(any(unix, windows)))]
pub use stub::StubSignalHandler as PlatformSignalHandler;

#[cfg(not(any(unix, windows)))]
mod stub {
    use super::*;

    pub struct StubProcessControl;

    impl ProcessControl for StubProcessControl {
        fn send_signal(&self, _pid: u32, _signal: Signal) -> Result<(), PlatformError> {
            Err(PlatformError::NotSupported(
                "Signals not supported on this platform".into(),
            ))
        }

        fn is_process_running(&self, pid: u32) -> bool {
            std::path::Path::new(&format!("/proc/{}", pid)).exists()
        }

        fn daemonize(&self, _pid_file: Option<&std::path::Path>) -> Result<(), PlatformError> {
            Err(PlatformError::NotSupported(
                "Daemonization not supported on this platform".into(),
            ))
        }
    }

    pub struct StubSignalHandler;

    impl SignalHandler for StubSignalHandler {
        fn register(
            &mut self,
            _signal: Signal,
            _handler: Box<dyn Fn() + Send + Sync>,
        ) -> Result<(), PlatformError> {
            Err(PlatformError::NotSupported(
                "Signals not supported on this platform".into(),
            ))
        }

        fn start_listening(&mut self) {}
        fn stop_listening(&mut self) {}
    }
}

pub fn terminate_process(child: &mut Child, graceful: bool, timeout_secs: u64) -> io::Result<()> {
    #[cfg(unix)]
    {
        if graceful {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(child.id() as i32),
                nix::sys::signal::Signal::SIGTERM,
            );

            let start = std::time::Instant::now();
            while start.elapsed().as_secs() < timeout_secs {
                match child.try_wait() {
                    Ok(Some(_)) => return Ok(()),
                    Ok(None) => std::thread::sleep(std::time::Duration::from_millis(100)),
                    Err(e) => return Err(e),
                }
            }
        }
    }

    let _ = child.kill();
    child.wait()?;
    Ok(())
}

pub fn is_process_running(pid: u32) -> bool {
    #[cfg(unix)]
    {
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), None).is_ok()
    }

    #[cfg(windows)]
    {
        std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid)])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()))
            .unwrap_or(false)
    }

    #[cfg(not(any(unix, windows)))]
    {
        std::path::Path::new(&format!("/proc/{}", pid)).exists()
    }
}
