use nix::fcntl::{flock, FlockArg};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;

const DEFAULT_RUSTWAF_DIR: &str = ".maluwaf";
const PID_FILE: &str = "maluwaf.pid";
const STATUS_FILE: &str = "status.json";
const SOCKET_FILE: &str = "maluwaf.sock";
const OVERSEER_LOCK_FILE: &str = "overseer.lock";

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
            .join(DEFAULT_RUSTWAF_DIR);

        if !data_dir.exists() {
            if let Err(e) = fs::create_dir_all(&data_dir) {
                tracing::warn!("Failed to create maluwaf data directory: {}", e);
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
                tracing::warn!("Failed to create maluwaf data directory: {}", e);
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
        let started_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

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
        use std::os::unix::io::AsRawFd;

        let path = self.pid_file_path();

        // Try to open with O_EXCL to atomically check-and-create
        // This avoids the TOCTOU race between is_running() and write_pid()
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // File exists - check if the process is actually running
                if self.is_running() {
                    return Ok(false);
                }
                // Stale PID file - try to remove and recreate
                drop(fs::remove_file(&path));
                let file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)?;
                file
            }
            Err(e) => return Err(e),
        };

        // Acquire exclusive file lock using nix
        let fd = file.as_raw_fd();

        if flock(fd, FlockArg::LockExclusive).is_err() {
            return Err(std::io::Error::last_os_error());
        }

        // Now we have exclusive access - write the PID file
        let socket_path = self.socket_file_path().to_string_lossy().to_string();
        let started_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let content = PidFileContent {
            pid,
            socket_path,
            started_at,
            version: version.to_string(),
        };

        let json = serde_json::to_string_pretty(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        file.write_all(json.as_bytes())?;
        file.flush()?;

        // Keep the file open to hold the lock until process exits
        self.lock_file = Some(file);

        Ok(true)
    }

    #[cfg(windows)]
    pub fn try_acquire(&mut self, pid: u32, version: &str) -> std::io::Result<bool> {
        use std::fs::OpenOptions;

        let path = self.pid_file_path();

        // Try to open with O_EXCL to atomically check-and-create
        // On Windows, opening with write+exclusive access implicitly acquires a lock
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if self.is_running() {
                    return Ok(false);
                }
                drop(fs::remove_file(&path));
                let file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)?;
                file
            }
            Err(e) => return Err(e),
        };

        // On Windows, the file is opened with exclusive access implicitly
        // The O_CREATE_NEW flag ensures we get an error if file exists

        let socket_path = self.socket_file_path().to_string_lossy().to_string();
        let started_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let content = PidFileContent {
            pid,
            socket_path,
            started_at,
            version: version.to_string(),
        };

        let json = serde_json::to_string_pretty(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        file.write_all(json.as_bytes())?;
        file.flush()?;

        self.lock_file = Some(file);

        Ok(true)
    }

    #[cfg(not(any(unix, windows)))]
    pub fn try_acquire(&mut self, pid: u32, version: &str) -> std::io::Result<bool> {
        // Fallback for other platforms - use O_EXCL without file locking
        use std::fs::OpenOptions;

        let path = self.pid_file_path();

        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if self.is_running() {
                    return Ok(false);
                }
                drop(fs::remove_file(&path));
                let file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)?;
                file
            }
            Err(e) => return Err(e),
        };

        let socket_path = self.socket_file_path().to_string_lossy().to_string();
        let started_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let content = PidFileContent {
            pid,
            socket_path,
            started_at,
            version: version.to_string(),
        };

        let json = serde_json::to_string_pretty(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

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
    /// Both approaches are standard for their platforms.
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
                use std::process::Command;
                // On Windows, use tasklist to check if process exists
                let output = Command::new("tasklist")
                    .args(["/FI", &format!("PID eq {}", content.pid)])
                    .output()
                    .ok();

                if let Some(output) = output {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    return stdout.contains(&content.pid.to_string());
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

pub struct OverseerLockFile {
    lock_path: PathBuf,
    lock_file: Option<()>,
}

impl OverseerLockFile {
    pub fn new() -> Self {
        let data_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(DEFAULT_RUSTWAF_DIR);

        let lock_path = data_dir.join(OVERSEER_LOCK_FILE);

        Self {
            lock_path,
            lock_file: None,
        }
    }

    pub fn with_custom_dir(dir: PathBuf) -> Self {
        let lock_path = dir.join(OVERSEER_LOCK_FILE);
        Self {
            lock_path,
            lock_file: None,
        }
    }

    pub fn lock_path(&self) -> &PathBuf {
        &self.lock_path
    }

    pub fn acquire(&mut self) -> Result<(), OverseerLockError> {
        if let Some(parent) = self.lock_path.parent() {
            fs::create_dir_all(parent).map_err(|e| OverseerLockError::IoError(e))?;
        }

        OverseerLockFile::cleanup_stale_locks(300);

        if self.check_lock(true) {
            return Err(OverseerLockError::AlreadyLocked);
        }

        let pid = std::process::id();
        let content = format!(
            "{}\n{}",
            pid,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );

        let temp_path = self.lock_path.with_extension("lock.tmp");

        fs::write(&temp_path, content.as_bytes()).map_err(|e| OverseerLockError::IoError(e))?;

        fs::rename(&temp_path, &self.lock_path).map_err(|e| OverseerLockError::IoError(e))?;

        if !self.is_locked() {
            return Err(OverseerLockError::LockError(
                "Failed to verify lock".to_string(),
            ));
        }

        self.lock_file = Some(());
        Ok(())
    }

    pub fn release(&mut self) {
        self.lock_file = None;
        let _ = fs::remove_file(&self.lock_path);
    }

    pub fn is_locked(&self) -> bool {
        self.check_lock(false)
    }

    pub fn cleanup_stale_locks(max_age_secs: u64) {
        let data_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(DEFAULT_RUSTWAF_DIR);

        let lock_path = data_dir.join(OVERSEER_LOCK_FILE);

        if lock_path.exists() {
            if let Ok(metadata) = fs::metadata(&lock_path) {
                if let Ok(modified) = metadata.modified() {
                    let age = std::time::SystemTime::now()
                        .duration_since(modified)
                        .unwrap()
                        .as_secs();

                    if age > max_age_secs {
                        tracing::info!("Cleaning up stale overseer lock (age: {}s)", age);
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
                                        use std::process::Command;
                                        let output = Command::new("tasklist")
                                            .args(["/FI", &format!("PID eq {}", pid)])
                                            .output();
                                        if let Some(output) = output {
                                            let stdout = String::from_utf8_lossy(&output.stdout);
                                            stdout.contains(&pid.to_string())
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

impl Drop for OverseerLockFile {
    fn drop(&mut self) {
        self.release();
    }
}

#[derive(Debug)]
pub enum OverseerLockError {
    IoError(std::io::Error),
    AlreadyLocked,
    LockError(String),
}

impl std::fmt::Display for OverseerLockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OverseerLockError::IoError(e) => write!(f, "IO error: {}", e),
            OverseerLockError::AlreadyLocked => write!(f, "Overseer is already running"),
            OverseerLockError::LockError(e) => write!(f, "Lock error: {}", e),
        }
    }
}

impl std::error::Error for OverseerLockError {}
