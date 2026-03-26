use std::path::PathBuf;

use super::checksum::compute_sha256;
use super::state::{OverseerState, Persistence, UpgradeState};
use super::upgrade::Orchestrator;

pub struct RollbackManager {
    persistence: Persistence,
    #[allow(dead_code)] // Reserved for future backup and rollback operations
    data_dir: PathBuf,
}

impl RollbackManager {
    pub fn new(data_dir: Option<PathBuf>) -> Self {
        let data_dir = data_dir.unwrap_or_else(|| {
            dirs::home_dir()
                .map(|h| h.join(".maluwaf"))
                .unwrap_or_else(|| PathBuf::from(".maluwaf"))
        });
        Self {
            persistence: Persistence::new(Some(data_dir.clone())),
            data_dir,
        }
    }

    pub async fn can_rollback(&self) -> bool {
        let state = self.persistence.load().unwrap_or_default();
        state.can_rollback()
    }

    pub async fn get_rollback_target(&self) -> Option<RollbackTarget> {
        let state = self.persistence.load().unwrap_or_default();

        state.current_version.as_ref()?;

        if let Some(last_error) = &state.last_error {
            Some(RollbackTarget {
                version: state.current_version.clone().unwrap(),
                reason: last_error.clone(),
                timestamp: state.last_upgrade_timestamp,
            })
        } else {
            None
        }
    }

    pub async fn perform_rollback(&self, orchestrator: &Orchestrator) -> Result<(), RollbackError> {
        let state = self.persistence.load().unwrap_or_default();

        if !state.can_rollback() {
            return Err(RollbackError::CannotRollback(state.state.to_string()));
        }

        tracing::info!("Performing rollback to version: {:?}", state.previous_version);

        // Get previous binary path
        let prev_binary_path = state.previous_binary_path.as_ref()
            .ok_or(RollbackError::NoVersion)?;

        // Verify previous binary checksum if available
        if let Some(expected_checksum) = &state.previous_binary_checksum {
            let path = PathBuf::from(prev_binary_path);
            if !path.exists() {
                return Err(RollbackError::BinaryNotFound(path));
            }
            
            let actual_checksum = compute_sha256(&path)
                .map_err(RollbackError::IoError)?;
            
            if &actual_checksum != expected_checksum {
                return Err(RollbackError::ChecksumMismatch);
            }
            tracing::info!("Previous binary checksum verified");
        }

        // Get ports to rollback from
        let ports = state.worker_ports.clone()
            .ok_or(RollbackError::NoWorkerPorts)?;

        // Spawn previous version workers
        let prev_path = PathBuf::from(prev_binary_path);
        let new_ports = orchestrator.spawn_workers_for_rollback(
            &prev_path.to_string_lossy(),
            state.staged_config_path.as_ref(),
            &ports,
            state.upgrade_mode.as_ref(),
        ).await?;

        // Validate rollback
        let validation_result = orchestrator.validate_rollback(&new_ports).await;

        match validation_result {
            Ok(metrics) => {
                tracing::info!(
                    "Rollback validation passed (success rate: {:.1}%)",
                    metrics.success_rate * 100.0
                );
                
                // Update state to reflect rollback
                let mut new_state = state.clone();
                new_state.state = UpgradeState::Committed;
                new_state.current_version = state.previous_version.clone();
                new_state.worker_ports = Some(new_ports);
                new_state.last_rollback_timestamp = Some(OverseerState::current_timestamp());
                new_state.staged_binary_path = None;
                new_state.staged_version = None;
                new_state.staged_config_path = None;
                
                self.persistence.save(&new_state)
                    .map_err(RollbackError::IoError)?;

                tracing::info!("Rollback completed successfully");
                Ok(())
            }
            Err(failures) => {
                Err(RollbackError::ValidationFailed(failures))
            }
        }
    }

    pub async fn recover(&self, orchestrator: &Orchestrator) -> Result<(), RollbackError> {
        let state = self.persistence.load().unwrap_or_default();

        if !state.needs_recovery() {
            return Err(RollbackError::CannotRollback(
                "System is not in recovery state".to_string()
            ));
        }

        tracing::info!("Attempting recovery from incomplete upgrade");

        // If we have a previous binary, try to rollback
        if let Some(prev_path) = &state.previous_binary_path {
            let path = PathBuf::from(prev_path);
            if path.exists() {
                // Try to restore previous version
                drop(self.perform_rollback(orchestrator).await);
            }
        }

        // If rollback not possible or failed, try to recover current state
        let mut new_state = state.clone();
        new_state.state = UpgradeState::Idle;
        new_state.last_error = Some("Recovered from incomplete upgrade".to_string());
        
        self.persistence.save(&new_state)
            .map_err(RollbackError::IoError)?;

        tracing::info!("Recovery completed");
        Ok(())
    }

    pub async fn get_previous_versions(&self, keep_count: usize) -> Vec<VersionInfo> {
        let data_dir = self.persistence.state_file.parent().map(|p| p.to_path_buf());
        let bin_dir = data_dir.map(|d| d.join("bin"));

        let mut versions = Vec::new();

        if let Some(bin_dir) = bin_dir {
            if let Ok(entries) = std::fs::read_dir(&bin_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        let filename = path.file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("");

                        if filename.starts_with("maluwaf-") {
                            let version = filename.trim_start_matches("maluwaf-").to_string();
                            let metadata = std::fs::metadata(&path).ok();

                            versions.push(VersionInfo {
                                version,
                                path,
                                created_at: metadata
                                    .and_then(|m| m.created().ok())
                                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                                    .map(|d| d.as_secs())
                                    .unwrap_or(0),
                            });
                        }
                    }
                }
            }
        }

        versions.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        versions.truncate(keep_count);

        versions
    }
}

#[derive(Debug, Clone)]
pub struct RollbackTarget {
    pub version: String,
    pub reason: String,
    pub timestamp: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct VersionInfo {
    pub version: String,
    pub path: PathBuf,
    pub created_at: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum RollbackError {
    #[error("Cannot rollback from state: {0}")]
    CannotRollback(String),

    #[error("No version to rollback to")]
    NoVersion,

    #[error("Binary not found: {0}")]
    BinaryNotFound(PathBuf),

    #[error("Checksum mismatch during rollback")]
    ChecksumMismatch,

    #[error("No worker ports available")]
    NoWorkerPorts,

    #[error("Validation failed: {0:?}")]
    ValidationFailed(Vec<(u16, super::health::HealthStatus)>),

    #[error("Upgrade error: {0}")]
    UpgradeError(#[from] super::upgrade::UpgradeError),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}
