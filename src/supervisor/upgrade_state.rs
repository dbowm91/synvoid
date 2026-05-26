use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpgradeState {
    Idle,
    Staging,
    Validating,
    Committing,
    RollingBack,
}

impl Default for UpgradeState {
    fn default() -> Self {
        UpgradeState::Idle
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagedBinary {
    pub path: PathBuf,
    pub checksum: [u8; 32],
    pub staged_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeStateData {
    pub version: u32,
    pub state: UpgradeState,
    pub staged_binary: Option<StagedBinary>,
    pub new_workers: Vec<usize>,
    pub original_workers: Vec<usize>,
    pub upgraded_count: usize,
    pub remaining_count: usize,
    pub rollback_reason: Option<String>,
    pub last_updated: u64,
}

impl Default for UpgradeStateData {
    fn default() -> Self {
        Self {
            version: 1,
            state: UpgradeState::Idle,
            staged_binary: None,
            new_workers: Vec::new(),
            original_workers: Vec::new(),
            upgraded_count: 0,
            remaining_count: 0,
            rollback_reason: None,
            last_updated: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UpgradeConfig {
    pub rolling_window_size: usize,
    pub health_check_timeout_secs: u64,
    pub health_check_retries: u32,
    pub health_check_interval_secs: u64,
    pub drain_timeout_secs: u64,
    pub max_retries: u32,
    pub rollback_on_health_failure: bool,
}

impl Default for UpgradeConfig {
    fn default() -> Self {
        Self {
            rolling_window_size: 1,
            health_check_timeout_secs: 30,
            health_check_retries: 5,
            health_check_interval_secs: 2,
            drain_timeout_secs: 60,
            max_retries: 3,
            rollback_on_health_failure: true,
        }
    }
}

impl UpgradeConfig {
    pub fn health_check_timeout(&self) -> Duration {
        Duration::from_secs(self.health_check_timeout_secs)
    }

    pub fn drain_timeout(&self) -> Duration {
        Duration::from_secs(self.drain_timeout_secs)
    }
}
