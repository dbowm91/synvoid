#![allow(deprecated)]

#[cfg(unix)]
use nix::fcntl::{flock, FlockArg};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Read;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

const DEFAULT_SYNVOID_DIR: &str = ".synvoid";
const PID_FILE: &str = "synvoid.pid";
const STATUS_FILE: &str = "status.json";
const SOCKET_FILE: &str = "synvoid.sock";
const SUPERVISOR_LOCK_FILE: &str = "supervisor.lock";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PidFileContent {
    pub pid: u32,
    pub socket_path: String,
    pub started_at: u64,
    pub version: String,
}

pub struct PidFileManager {
    data_dir: PathBuf,
    lock_file: Option<File>,
}

impl PidFileManager {
    pub fn new() -> Self {
        let data_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(DEFAULT_SYNVOID_DIR);

        if !data_dir.exists() {
            if let Err(e) = fs::create_dir_all(&data_dir) {
                tracing::warn!("Failed to create synvoid data directory: {}", e);
            }
        }

        Self {
            data_dir,
            lock_file: None,
        }
    }

    pub fn with_custom_dir(dir: PathBuf) -> Self {
        if !dir.exists() {
            if let Err(e) = fs::create_dir_all(&dir) {
                tracing::warn!("Failed to create synvoid data directory: {}", e);
            }
        }
        Self {
            data_dir: dir,
            lock_file: None,
        }
    }

    pub fn pid_file_path(&self) -> PathBuf {
        self.data_dir.join(PID_FILE)
    }

    pub fn status_file_path(&self) -> PathBuf {
        self.data_dir.join(STATUS_FILE)
    }

    pub fn socket_file_path(&self) -> PathBuf {
        self.data_dir.join(SOCKET_FILE)
    }

    pub fn write_pid(&self, pid: u32, version: &str) -> std::io::Result<()> {
        let socket_path = self.socket_file_path().to_string_lossy().to_string();
        let started_at = synvoid_utils::safe_unix_timestamp();

        let content = PidFileContent {
            pid,
            socket_path,
            started_at,
            version: version.to_string(),
        };

        let json = serde_json::to_string_pretty(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        self.atomic_write(&self.pid_file_path(), json.as_bytes())
    }

    fn atomic_write(&self, path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
        let temp_path = path.with_extension("tmp");

        fs::write(&temp_path, contents)?;

        #[cfg(unix)]
        {
            std::fs::rename(&temp_path, path)?;
        }

        #[cfg(windows)]
        {
            std::fs::rename(&temp_path, path).or_else(|_| {
                if path.exists() {
                    let _ = fs::remove_file(path);
                }
                fs::rename(&temp_path, path)
            })?;
        }

        Ok(())
    }

    #[cfg(unix)]
    pub fn try_acquire(&mut self, pid: u32, version: &str) -> std::io::Result<bool> {
        use std::fs::OpenOptions;
        use std::io::{Seek, SeekFrom, Write};
        use std::os::unix::io::AsRawFd;

        let path = self.pid_file_path();

        let mut file = OpenOptions::new().write(true).create(true).open(&path)?;

        let fd = file.as_raw_fd();

        if flock(fd, FlockArg::LockExclusiveNonblock).is_err() {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(false);
            }
            return Err(err);
        }

        if self.is_running() {
            let _ = flock(fd, FlockArg::Unlock);
            return Ok(false);
        }

        let socket_path = self.socket_file_path().to_string_lossy().to_string();
        let started_at = synvoid_utils::safe_unix_timestamp();

        let content = PidFileContent {
            pid,
            socket_path,
            started_at,
            version: version.to_string(),
        };

        let json = serde_json::to_string_pretty(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(json.as_bytes())?;
        file.flush()?;

        self.lock_file = Some(file);
        Ok(true)
    }

    #[cfg(windows)]
    pub fn try_acquire(&mut self, pid: u32, version: &str) -> std::io::Result<bool> {
        use std::fs::OpenOptions;

        let path = self.pid_file_path();

        let mut file = OpenOptions::new().write(true).create(true).open(&path)?;

        if !lock_file_exclusive(&file) {
            return Ok(false);
        }

        if self.is_running() {
            return Ok(false);
        }

        let socket_path = self.socket_file_path().to_string_lossy().to_string();
        let started_at = synvoid_utils::safe_unix_timestamp();

        let content = PidFileContent {
            pid,
            socket_path,
            started_at,
            version: version.to_string(),
        };

        let json = serde_json::to_string_pretty(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        file.set_len(0)?;
        file.seek(std::io::SeekFrom::Start(0))?;
        file.write_all(json.as_bytes())?;
        file.flush()?;

        self.lock_file = Some(file);

        Ok(true)
    }

    #[cfg(windows)]
    fn lock_file_exclusive(file: &File) -> bool {
        use windows_sys::Win32::FileManagement::LockFileEx;
        use windows_sys::Win32::Foundation::OVERLAPPED;

        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        let result = unsafe {
            LockFileEx(
                file.as_raw_fd() as _,
                0x00000001,
                0,
                0,
                0xFFFFFFFF,
                &mut overlapped,
            )
        };
        result != 0
    }

    #[cfg(not(any(unix, windows)))]
    pub fn try_acquire(&mut self, pid: u32, version: &str) -> std::io::Result<bool> {
        use std::fs::OpenOptions;

        let path = self.pid_file_path();

        let mut file = OpenOptions::new().write(true).create(true).open(&path)?;

        if self.is_running() {
            return Ok(false);
        }

        let socket_path = self.socket_file_path().to_string_lossy().to_string();
        let started_at = synvoid_utils::safe_unix_timestamp();

        let content = PidFileContent {
            pid,
            socket_path,
            started_at,
            version: version.to_string(),
        };

        let json = serde_json::to_string_pretty(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        file.set_len(0)?;
        file.seek(std::io::SeekFrom::Start(0))?;
        file.write_all(json.as_bytes())?;
        file.flush()?;

        self.lock_file = Some(file);

        Ok(true)
    }

    pub fn release(&mut self) {
        self.lock_file = None;
        let path = self.pid_file_path();
        let _ = fs::remove_file(path);
    }

    pub fn read_pid(&self) -> Option<PidFileContent> {
        let path = self.pid_file_path();
        if !path.exists() {
            return None;
        }

        let content = fs::read_to_string(path).ok()?;
        serde_json::from_str(&content).ok()
    }

    /// Check if the process is running.
    ///
    /// Platform-specific implementation:
    /// - Unix: Uses `kill(pid, 0)` to check process existence without sending a signal
    /// - Windows: Uses `tasklist` command to check if process exists
    ///   Both approaches are standard for their platforms.
    pub fn is_running(&self) -> bool {
        if let Some(content) = self.read_pid() {
            #[cfg(unix)]
            {
                use nix::unistd::Pid;
                // Check if process exists by sending signal 0
                let pid = Pid::from_raw(content.pid as i32);
                return nix::sys::signal::kill(pid, None).is_ok();
            }
            #[cfg(windows)]
            {
                use windows_sys::Win32::Foundation::HANDLE;
                use windows_sys::Win32::System::Threading::{
                    GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
                    STILL_ACTIVE,
                };

                let pid = content.pid;
                let process_handle =
                    unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };

                if process_handle != 0 {
                    let mut exit_code: u32 = 0;
                    let result = unsafe { GetExitCodeProcess(process_handle, &mut exit_code) };
                    unsafe { windows_sys::Win32::Foundation::CloseHandle(process_handle) };
                    return result != 0 && exit_code == STILL_ACTIVE as u32;
                }
            }
        }
        false
    }

    pub fn get_pid(&self) -> Option<u32> {
        self.read_pid().map(|c| c.pid)
    }

    pub fn get_socket_path(&self) -> Option<String> {
        self.read_pid().map(|c| c.socket_path)
    }

    pub fn remove_pid(&self) -> std::io::Result<()> {
        let path = self.pid_file_path();
        if path.exists() {
            fs::remove_file(path)
        } else {
            Ok(())
        }
    }

    pub fn socket_exists(&self) -> bool {
        self.socket_file_path().exists()
    }

    pub fn remove_socket(&self) -> std::io::Result<()> {
        let path = self.socket_file_path();
        if path.exists() {
            fs::remove_file(path)
        } else {
            Ok(())
        }
    }

    pub fn data_dir(&self) -> &PathBuf {
        &self.data_dir
    }
}

impl Drop for PidFileManager {
    fn drop(&mut self) {
        self.release();
    }
}

impl Default for PidFileManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(unix)]
pub struct SupervisorLockFile {
    lock_path: PathBuf,
    lock_file: Option<File>,
}

#[cfg(unix)]
impl Default for SupervisorLockFile {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(unix)]
impl SupervisorLockFile {
    pub fn new() -> Self {
        let data_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(DEFAULT_SYNVOID_DIR);

        let lock_path = data_dir.join(SUPERVISOR_LOCK_FILE);

        Self {
            lock_path,
            lock_file: None,
        }
    }

    pub fn with_custom_dir(dir: PathBuf) -> Self {
        let lock_path = dir.join(SUPERVISOR_LOCK_FILE);
        Self {
            lock_path,
            lock_file: None,
        }
    }

    pub fn lock_path(&self) -> &PathBuf {
        &self.lock_path
    }

    pub fn acquire(&mut self) -> Result<(), SupervisorLockError> {
        use std::fs::OpenOptions;
        use std::io::{Seek, SeekFrom, Write};

        if let Some(parent) = self.lock_path.parent() {
            fs::create_dir_all(parent).map_err(SupervisorLockError::IoError)?;
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.lock_path)
            .map_err(SupervisorLockError::IoError)?;

        match flock(file.as_raw_fd(), FlockArg::LockExclusiveNonblock) {
            Ok(()) => {}
            Err(e) => {
                if e == nix::errno::Errno::EWOULDBLOCK {
                    return Err(SupervisorLockError::AlreadyLocked);
                }
                return Err(SupervisorLockError::LockError(format!(
                    "flock failed: {}",
                    e
                )));
            }
        }

        let pid = std::process::id();
        let content = format!("{}\n{}", pid, synvoid_utils::safe_unix_timestamp());

        let mut f = &file;
        f.set_len(0).map_err(SupervisorLockError::IoError)?;
        f.seek(SeekFrom::Start(0))
            .map_err(SupervisorLockError::IoError)?;
        f.write_all(content.as_bytes())
            .map_err(SupervisorLockError::IoError)?;
        f.flush().map_err(SupervisorLockError::IoError)?;

        self.lock_file = Some(file);
        Ok(())
    }

    pub fn release(&mut self) {
        if let Some(file) = self.lock_file.take() {
            let _ = flock(file.as_raw_fd(), FlockArg::Unlock);
        }
        let _ = fs::remove_file(&self.lock_path);
    }

    pub fn is_locked(&self) -> bool {
        self.check_lock(false)
    }

    pub fn cleanup_stale_locks(max_age_secs: u64) {
        let data_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(DEFAULT_SYNVOID_DIR);

        let lock_path = data_dir.join(SUPERVISOR_LOCK_FILE);

        if lock_path.exists() {
            if let Ok(metadata) = fs::metadata(&lock_path) {
                if let Ok(modified) = metadata.modified() {
                    let age = std::time::SystemTime::now()
                        .duration_since(modified)
                        .unwrap_or_default()
                        .as_secs();

                    if age > max_age_secs {
                        tracing::info!("Cleaning up stale supervisor lock (age: {}s)", age);
                        let _ = fs::remove_file(&lock_path);
                    }
                }
            }
        }
    }

    fn check_lock(&self, cleanup: bool) -> bool {
        if self.lock_path.exists() {
            if let Ok(mut file) = File::open(&self.lock_path) {
                let mut buf = [0u8; 64];
                if let Ok(n) = file.read(&mut buf) {
                    if n > 0 {
                        let content = String::from_utf8_lossy(&buf[..n]);
                        let parts: Vec<&str> = content.trim().split('\n').collect();
                        if let Some(pid_str) = parts.first() {
                            if let Ok(pid) = pid_str.parse::<u32>() {
                                let is_running = {
                                    #[cfg(unix)]
                                    {
                                        use nix::unistd::Pid;
                                        let check_pid = Pid::from_raw(pid as i32);
                                        nix::sys::signal::kill(check_pid, None).is_ok()
                                    }
                                    #[cfg(windows)]
                                    {
                                        use windows_sys::Win32::Foundation::HANDLE;
                                        use windows_sys::Win32::System::Threading::{
                                            GetExitCodeProcess, OpenProcess,
                                            PROCESS_QUERY_LIMITED_INFORMATION, STILL_ACTIVE,
                                        };

                                        let check_handle = unsafe {
                                            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
                                        };

                                        if check_handle != 0 {
                                            let mut exit_code: u32 = 0;
                                            let result = unsafe {
                                                GetExitCodeProcess(check_handle, &mut exit_code)
                                            };
                                            unsafe {
                                                windows_sys::Win32::Foundation::CloseHandle(
                                                    check_handle,
                                                )
                                            };
                                            result != 0 && exit_code == STILL_ACTIVE as u32
                                        } else {
                                            false
                                        }
                                    }
                                };

                                if is_running {
                                    return true;
                                }

                                if cleanup {
                                    tracing::debug!("Removing stale lock for dead PID {}", pid);
                                    let _ = fs::remove_file(&self.lock_path);
                                    return false;
                                }
                            }
                        }
                    }
                }
            }
            if cleanup {
                let _ = fs::remove_file(&self.lock_path);
            }
        }
        false
    }
}

#[cfg(unix)]
impl Drop for SupervisorLockFile {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(not(unix))]
pub struct SupervisorLockFile {
    lock_path: PathBuf,
}

#[cfg(not(unix))]
impl Default for SupervisorLockFile {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(unix))]
impl SupervisorLockFile {
    pub fn new() -> Self {
        let data_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(DEFAULT_SYNVOID_DIR);

        let lock_path = data_dir.join(SUPERVISOR_LOCK_FILE);

        Self { lock_path }
    }

    pub fn with_custom_dir(dir: PathBuf) -> Self {
        let lock_path = dir.join(SUPERVISOR_LOCK_FILE);
        Self { lock_path }
    }

    pub fn lock_path(&self) -> &PathBuf {
        &self.lock_path
    }

    pub fn acquire(&mut self) -> Result<(), SupervisorLockError> {
        Err(SupervisorLockError::LockError(
            "Supervisor lock file not supported on this platform".into(),
        ))
    }

    pub fn release(&mut self) {}

    pub fn is_locked(&self) -> bool {
        false
    }

    pub fn cleanup_stale_locks(_max_age_secs: u64) {}
}

#[cfg(not(unix))]
impl Drop for SupervisorLockFile {
    fn drop(&mut self) {
        self.release();
    }
}

#[derive(Debug)]
pub enum SupervisorLockError {
    IoError(std::io::Error),
    AlreadyLocked,
    LockError(String),
}

impl std::fmt::Display for SupervisorLockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SupervisorLockError::IoError(e) => write!(f, "IO error: {}", e),
            SupervisorLockError::AlreadyLocked => write!(f, "Supervisor is already running"),
            SupervisorLockError::LockError(e) => write!(f, "Lock error: {}", e),
        }
    }
}

impl std::error::Error for SupervisorLockError {}
