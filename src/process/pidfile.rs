use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

const DEFAULT_RUSTWAF_DIR: &str = ".rustwaf";
const PID_FILE: &str = "rustwaf.pid";
const STATUS_FILE: &str = "status.json";
const SOCKET_FILE: &str = "rustwaf.sock";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PidFileContent {
    pub pid: u32,
    pub socket_path: String,
    pub started_at: u64,
    pub version: String,
}

pub struct PidFileManager {
    data_dir: PathBuf,
}

impl PidFileManager {
    pub fn new() -> Self {
        let data_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(DEFAULT_RUSTWAF_DIR);

        if !data_dir.exists() {
            if let Err(e) = fs::create_dir_all(&data_dir) {
                tracing::warn!("Failed to create rustwaf data directory: {}", e);
            }
        }

        Self { data_dir }
    }

    pub fn with_custom_dir(dir: PathBuf) -> Self {
        if !dir.exists() {
            if let Err(e) = fs::create_dir_all(&dir) {
                tracing::warn!("Failed to create rustwaf data directory: {}", e);
            }
        }
        Self { data_dir: dir }
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

        fs::write(self.pid_file_path(), json)
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

impl Default for PidFileManager {
    fn default() -> Self {
        Self::new()
    }
}
