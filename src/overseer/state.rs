use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::mode::UpgradeMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum UpgradeState {
    #[default]
    Idle,
    Staging,
    Spawning,
    Validating,
    Draining,
    Committed,
    RollingBack,
    Failed,
    RecoveryNeeded,
    DualMasterActive,
    DrainingOldMaster,
}

impl std::fmt::Display for UpgradeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpgradeState::Idle => write!(f, "IDLE"),
            UpgradeState::Staging => write!(f, "STAGING"),
            UpgradeState::Spawning => write!(f, "SPAWNING"),
            UpgradeState::Validating => write!(f, "VALIDATING"),
            UpgradeState::Draining => write!(f, "DRAINING"),
            UpgradeState::Committed => write!(f, "COMMITTED"),
            UpgradeState::RollingBack => write!(f, "ROLLING_BACK"),
            UpgradeState::Failed => write!(f, "FAILED"),
            UpgradeState::RecoveryNeeded => write!(f, "RECOVERY_NEEDED"),
            UpgradeState::DualMasterActive => write!(f, "DUAL_MASTER_ACTIVE"),
            UpgradeState::DrainingOldMaster => write!(f, "DRAINING_OLD_MASTER"),
        }
    }
}

impl UpgradeState {
    pub fn max_duration_secs(&self) -> Option<u64> {
        match self {
            UpgradeState::Staging => Some(300),
            UpgradeState::Spawning => Some(120),
            UpgradeState::Validating => Some(300),
            UpgradeState::Draining => Some(600),
            UpgradeState::RollingBack => Some(300),
            UpgradeState::DualMasterActive => Some(600),
            UpgradeState::DrainingOldMaster => Some(600),
            _ => None,
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            UpgradeState::Idle | UpgradeState::Committed | UpgradeState::Failed
        )
    }

    pub fn is_transition(&self) -> bool {
        !self.is_terminal()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OverseerState {
    pub state: UpgradeState,
    pub current_version: Option<String>,
    pub staged_version: Option<String>,
    pub staged_binary_path: Option<String>,
    pub staged_config_path: Option<String>,
    pub upgrade_mode: Option<UpgradeMode>,
    pub last_upgrade_timestamp: Option<u64>,
    pub last_rollback_timestamp: Option<u64>,
    pub last_error: Option<String>,
    pub worker_count: Option<usize>,
    pub worker_ports: Option<Vec<u16>>,
    pub validation_retries: u32,
    pub staged_binary_checksum: Option<String>,
    pub previous_binary_path: Option<String>,
    pub previous_binary_checksum: Option<String>,
    pub previous_version: Option<String>,
    pub old_master_pid: Option<u32>,
    pub new_master_pid: Option<u32>,
    pub dual_master_start_time: Option<u64>,
    pub active_connections_at_drain_start: Option<u64>,
    pub state_entered_at: Option<u64>,
}

impl OverseerState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn can_stage(&self) -> bool {
        matches!(
            self.state,
            UpgradeState::Idle
                | UpgradeState::Committed
                | UpgradeState::Failed
                | UpgradeState::RecoveryNeeded
        )
    }

    pub fn can_apply(&self) -> bool {
        matches!(self.state, UpgradeState::Staging)
    }

    pub fn can_rollback(&self) -> bool {
        matches!(
            self.state,
            UpgradeState::Validating | UpgradeState::Failed | UpgradeState::RecoveryNeeded
        )
    }

    pub fn needs_recovery(&self) -> bool {
        matches!(
            self.state,
            UpgradeState::RecoveryNeeded
                | UpgradeState::DualMasterActive
                | UpgradeState::DrainingOldMaster
                | UpgradeState::RollingBack
        )
    }

    pub fn is_dual_master_state(&self) -> bool {
        matches!(
            self.state,
            UpgradeState::DualMasterActive | UpgradeState::DrainingOldMaster
        )
    }

    pub fn can_abort_upgrade(&self) -> bool {
        matches!(
            self.state,
            UpgradeState::Staging
                | UpgradeState::Spawning
                | UpgradeState::DualMasterActive
                | UpgradeState::DrainingOldMaster
        )
    }

    pub fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    pub fn enter_state(&mut self, new_state: UpgradeState) {
        self.state = new_state;
        self.state_entered_at = Some(Self::current_timestamp());
    }

    pub fn time_in_current_state(&self) -> Option<Duration> {
        self.state_entered_at.map(|entered| {
            let now = Self::current_timestamp();
            Duration::from_secs(now.saturating_sub(entered))
        })
    }

    pub fn is_state_timed_out(&self) -> bool {
        if let Some(max_secs) = self.state.max_duration_secs() {
            if let Some(time_in_state) = self.time_in_current_state() {
                return time_in_state.as_secs() > max_secs;
            }
        }
        false
    }

    pub fn remaining_state_time(&self) -> Option<Duration> {
        if let Some(max_secs) = self.state.max_duration_secs() {
            if let Some(time_in_state) = self.time_in_current_state() {
                let elapsed = time_in_state.as_secs();
                if elapsed < max_secs {
                    return Some(Duration::from_secs(max_secs - elapsed));
                }
                return Some(Duration::ZERO);
            }
        }
        None
    }
}

pub struct Persistence {
    pub state_file: PathBuf,
    lock_file: PathBuf,
}

impl Persistence {
    pub fn new(data_dir: Option<PathBuf>) -> Self {
        let data_dir = data_dir.unwrap_or_else(|| {
            dirs::home_dir()
                .map(|h| h.join(".maluwaf"))
                .unwrap_or_else(|| PathBuf::from(".maluwaf"))
        });

        let state_file = data_dir.join("overseer-state.json");
        let lock_file = data_dir.join("overseer.lock");

        Self {
            state_file,
            lock_file,
        }
    }

    pub fn load(&self) -> std::io::Result<OverseerState> {
        if !self.state_file.exists() {
            return Ok(OverseerState::new());
        }

        let content = fs::read_to_string(&self.state_file)?;
        let mut state: OverseerState = serde_json::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        if matches!(
            state.state,
            UpgradeState::Spawning
                | UpgradeState::Validating
                | UpgradeState::Draining
                | UpgradeState::DualMasterActive
                | UpgradeState::DrainingOldMaster
        ) {
            tracing::warn!(
                "Detected incomplete upgrade in state: {}, marking for recovery",
                state.state
            );
            state.state = UpgradeState::RecoveryNeeded;
        }

        Ok(state)
    }

    pub fn save(&self, state: &OverseerState) -> std::io::Result<()> {
        if let Some(parent) = self.state_file.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(state)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let temp_path = self.state_file.with_extension("tmp");

        fs::write(&temp_path, content)?;
        fs::rename(&temp_path, &self.state_file)?;

        Ok(())
    }

    pub fn acquire_lock(&self) -> std::io::Result<LockGuard> {
        if let Some(parent) = self.lock_file.parent() {
            fs::create_dir_all(parent)?;
        }

        LockGuard::new(self.lock_file.clone())
    }

    pub fn state_file_path(&self) -> &PathBuf {
        &self.state_file
    }
}

pub struct LockGuard {
    lock_file: PathBuf,
}

impl LockGuard {
    fn new(lock_file: PathBuf) -> std::io::Result<Self> {
        let result = Self::try_open(&lock_file);

        match result {
            Ok(guard) => Ok(guard),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if let Ok(content) = fs::read_to_string(&lock_file) {
                    if let Ok(pid) = content.trim().parse::<u32>() {
                        if kill::process(pid as i32).is_ok() {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::AlreadyExists,
                                format!("Overseer already running with PID {}", pid),
                            ));
                        }
                    }
                }
                let _ = fs::remove_file(&lock_file);
                Self::new(lock_file)
            }
            Err(e) => Err(e),
        }
    }

    #[cfg(unix)]
    fn try_open(lock_file: &PathBuf) -> std::io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;

        let mut options = fs::OpenOptions::new();
        options.create(true).write(true).truncate(true).mode(0o644);

        match options.open(lock_file) {
            Ok(mut file) => {
                use std::io::Write;
                let pid = std::process::id();
                writeln!(file, "{}", pid)?;
                Ok(Self {
                    lock_file: lock_file.clone(),
                })
            }
            Err(e) => Err(e),
        }
    }

    #[cfg(not(unix))]
    fn try_open(lock_file: &PathBuf) -> std::io::Result<Self> {
        let mut options = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true);

        match options.open(lock_file) {
            Ok(mut file) => {
                use std::io::Write;
                let pid = std::process::id();
                writeln!(file, "{}", pid)?;
                Ok(Self {
                    lock_file: lock_file.clone(),
                })
            }
            Err(e) => Err(e),
        }
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_file);
    }
}

mod kill {
    use std::process::Command;

    pub fn process(pid: i32) -> std::io::Result<std::process::Child> {
        Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .output()
            .map(|_| std::process::Command::new("echo").spawn().unwrap())
            .map_err(std::io::Error::other)
    }
}
