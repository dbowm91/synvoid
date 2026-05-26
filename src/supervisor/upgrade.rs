use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

use crate::platform::fs::PlatformPaths;
use crate::process::{ProcessManager, WorkerId};
use crate::supervisor::health::{HealthChecker, HealthStatus};
use crate::supervisor::preflight::{PreflightConfig, PreflightValidator};
use crate::supervisor::upgrade_state::{StagedBinary, UpgradeConfig, UpgradeState, UpgradeStateData};

#[derive(Debug, thiserror::Error)]
pub enum UpgradeError {
    #[error("No staged binary")]
    NoStagedBinary,

    #[error("Upgrade already in progress")]
    AlreadyInProgress,

    #[error("Preflight validation failed: {0}")]
    PreflightFailed(String),

    #[error("Binary not found: {0}")]
    BinaryNotFound(PathBuf),

    #[error("Health check failed for worker {0}: {1}")]
    HealthCheckFailed(WorkerId, String),

    #[error("Drain timeout for worker {0}")]
    DrainTimeout(WorkerId),

    #[error("Rollback failed: {0}")]
    RollbackFailed(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("State serialization error: {0}")]
    SerializationError(String),
}

pub struct UpgradeOrchestrator {
    state: RwLock<UpgradeStateData>,
    config: UpgradeConfig,
    process_manager: Arc<ProcessManager>,
    health_checker: HealthChecker,
    preflight_validator: PreflightValidator,
    state_path: PathBuf,
}

impl UpgradeOrchestrator {
    pub fn new(
        process_manager: Arc<ProcessManager>,
        config: UpgradeConfig,
    ) -> Self {
        let health_checker = HealthChecker::new(
            Some("/__internal__/health".to_string()),
            Some(config.health_check_timeout_secs),
        );

        let preflight_validator = PreflightValidator::new(PreflightConfig {
            validation_timeout_secs: 30,
            require_config_check: false,
            require_capability_check: false,
            min_startup_time_ms: 100,
            max_startup_time_ms: 10000,
        });

        let paths = PlatformPaths::new();
        let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/run"))
            .join("synvoid");
        let state_path = runtime_dir.join("supervisor-upgrade-state.json");

        Self {
            state: RwLock::new(UpgradeStateData::default()),
            config,
            process_manager,
            health_checker,
            preflight_validator,
            state_path,
        }
    }

    pub async fn stage(&self, binary_path: PathBuf) -> Result<StagedBinary, UpgradeError> {
        let mut state = self.state.write().await;
        if state.state != UpgradeState::Idle {
            return Err(UpgradeError::AlreadyInProgress);
        }

        let preflight_result = self.preflight_validator.validate_binary(&binary_path, None);
        let result = match preflight_result {
            Ok(r) => r,
            Err(e) => {
                return Err(UpgradeError::PreflightFailed(e.to_string()));
            }
        };

        if !result.config_compatible {
            return Err(UpgradeError::PreflightFailed(format!(
                "Config compatibility check failed: {:?}",
                result.errors
            )));
        }

        if result.startup_time_ms > 5000 {
            return Err(UpgradeError::PreflightFailed(format!(
                "Binary startup too slow: {}ms (max 5000ms)",
                result.startup_time_ms
            )));
        }

        let checksum = compute_binary_checksum(&binary_path)?;
        let staged_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let staged_binary = StagedBinary {
            path: binary_path,
            checksum,
            staged_at,
        };

        state.state = UpgradeState::Staging;
        state.staged_binary = Some(staged_binary.clone());
        state.last_updated = staged_at;

        if let Err(e) = self.persist_state(&state).await {
            tracing::warn!("Failed to persist upgrade state: {}", e);
        }

        tracing::info!(
            "Binary staged for upgrade: {:?} (checksum: {:?})",
            staged_binary.path,
            &staged_binary.checksum[..8]
        );

        Ok(staged_binary)
    }

    pub async fn apply(&self) -> Result<usize, UpgradeError> {
        let staged_binary = {
            let state = self.state.read().await;
            if state.state != UpgradeState::Staging {
                return Err(UpgradeError::AlreadyInProgress);
            }
            state.staged_binary.clone()
        };

        let staged_binary = staged_binary.ok_or(UpgradeError::NoStagedBinary)?;

        let worker_ids = self.process_manager.get_unified_server_worker_ids();
        let original_workers: Vec<_> = worker_ids.iter().cloned().collect();
        let total_workers = original_workers.len();

        {
            let mut state = self.state.write().await;
            state.state = UpgradeState::Validating;
            state.original_workers = original_workers.iter().map(|w| w.as_usize()).collect();
            state.new_workers = Vec::new();
            state.upgraded_count = 0;
            state.remaining_count = total_workers;
        }

        tracing::info!(
            "Starting rolling upgrade of {} workers (window size: {})",
            total_workers,
            self.config.rolling_window_size
        );

        let mut upgraded = 0;
        for worker_id in original_workers {
            tracing::info!("Upgrading worker {} ({}/{})", worker_id, upgraded + 1, total_workers);

            let new_worker_id = self.spawn_upgrade_worker().await?;

            if !self.health_check_new_worker(new_worker_id).await {
                {
                    let mut state = self.state.write().await;
                    state.state = UpgradeState::RollingBack;
                    state.rollback_reason = Some("Health check failed for new worker".to_string());
                }
                self.process_manager.stop_unified_server_worker(new_worker_id).await.ok();
                return Err(UpgradeError::HealthCheckFailed(new_worker_id, "Health check failed".to_string()));
            }

            if !self.drain_and_stop_worker(worker_id).await {
                {
                    let mut state = self.state.write().await;
                    state.state = UpgradeState::RollingBack;
                    state.rollback_reason = Some("Drain timeout".to_string());
                }
                return Err(UpgradeError::DrainTimeout(worker_id));
            }

            upgraded += 1;
            {
                let mut state = self.state.write().await;
                state.state = UpgradeState::Committing;
                state.upgraded_count = upgraded;
                state.remaining_count = total_workers - upgraded;
                state.new_workers.push(worker_id.as_usize());
            }
        }

        {
            let mut state = self.state.write().await;
            state.state = UpgradeState::Idle;
            state.staged_binary = None;
            state.new_workers.clear();
        }
        let _ = std::fs::remove_file(&self.state_path);

        tracing::info!("Upgrade completed successfully: {} workers upgraded", upgraded);
        Ok(upgraded)
    }

    pub async fn rollback(&self) -> Result<(), UpgradeError> {
        tracing::info!("Rolling back upgrade...");

        let state = self.state.read().await;
        if state.state != UpgradeState::RollingBack {
            tracing::warn!("No upgrade in progress to roll back");
            return Ok(());
        }

        drop(state);

        {
            let mut state = self.state.write().await;
            state.state = UpgradeState::RollingBack;
            state.rollback_reason = Some("Manual rollback".to_string());
        }

        if let Err(e) = self.process_manager.stop_all_unified_server_workers().await {
            tracing::error!("Failed to stop workers during rollback: {}", e);
        }

        {
            let mut state = self.state.write().await;
            state.state = UpgradeState::Idle;
            state.staged_binary = None;
            state.new_workers.clear();
            state.upgraded_count = 0;
            state.remaining_count = 0;
            state.rollback_reason = None;
        }

        tracing::info!("Rollback completed");
        Ok(())
    }

    pub async fn get_state(&self) -> UpgradeStateData {
        self.state.read().await.clone()
    }

    async fn spawn_upgrade_worker(&self) -> Result<WorkerId, UpgradeError> {
        let worker_id = self.process_manager.spawn_upgrade_unified_server_worker().await
            .map_err(|e| UpgradeError::RollbackFailed(e.to_string()))?;
        Ok(worker_id)
    }

    async fn health_check_new_worker(&self, worker_id: WorkerId) -> bool {
        let port = self.process_manager.get_unified_server_worker_port(worker_id).unwrap_or(8080);

        for attempt in 0..self.config.health_check_retries {
            match self.health_checker.check_worker("127.0.0.1", port).await {
                HealthStatus::Healthy => {
                    tracing::info!("Worker {} health check passed", worker_id);
                    return true;
                }
                other => {
                    tracing::debug!(
                        "Worker {} health check attempt {}/{}: {}",
                        worker_id,
                        attempt + 1,
                        self.config.health_check_retries,
                        other
                    );
                }
            }
            tokio::time::sleep(Duration::from_secs(self.config.health_check_interval_secs)).await;
        }
        false
    }

    async fn drain_and_stop_worker(&self, worker_id: WorkerId) -> bool {
        let port = match self.process_manager.get_unified_server_worker_port(worker_id) {
            Some(p) => p,
            None => return true,
        };

        tokio::time::sleep(Duration::from_millis(100)).await;

        let start = Instant::now();
        let drain_timeout = Duration::from_secs(self.config.drain_timeout_secs);

        loop {
            match self.health_checker.check_worker_health_with_drain("127.0.0.1", port).await {
                HealthStatus::Draining { active_connections } => {
                    if active_connections == 0 {
                        tracing::info!("Worker {} drained successfully", worker_id);
                        break;
                    }
                    tracing::debug!(
                        "Worker {} draining: {} active connections",
                        worker_id,
                        active_connections
                    );
                }
                HealthStatus::Healthy => {
                    break;
                }
                other => {
                    tracing::debug!("Worker {} drain status: {}", worker_id, other);
                }
            }

            if start.elapsed() > drain_timeout {
                tracing::warn!("Worker {} drain timeout", worker_id);
                return false;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        self.process_manager.stop_unified_server_worker(worker_id).await.ok();
        true
    }

    async fn persist_state(&self, state: &UpgradeStateData) -> Result<(), UpgradeError> {
        use std::io::Write;

        let json = serde_json::to_string_pretty(state)
            .map_err(|e| UpgradeError::SerializationError(e.to_string()))?;

        let temp_path = self.state_path.with_extension("tmp");
        {
            let mut file = std::fs::File::create(&temp_path)
                .map_err(|e| UpgradeError::IoError(e))?;
            file.write_all(json.as_bytes())
                .map_err(|e| UpgradeError::IoError(e))?;
        }
        std::fs::rename(&temp_path, &self.state_path)
            .map_err(|e| UpgradeError::IoError(e))?;

        Ok(())
    }

    pub async fn recover_from_crash(&self) -> Result<(), UpgradeError> {
        if !self.state_path.exists() {
            return Ok(());
        }

        let data = std::fs::read_to_string(&self.state_path)
            .map_err(|e| UpgradeError::IoError(e))?;
        let state: UpgradeStateData = serde_json::from_str(&data)
            .map_err(|e| UpgradeError::SerializationError(e.to_string()))?;

        tracing::info!("Recovering from crashed upgrade state: {:?}", state.state);

        match state.state {
            UpgradeState::Staging | UpgradeState::Validating | UpgradeState::Committing => {
                tracing::info!("Rolling back incomplete upgrade...");
                let mut state_write = self.state.write().await;
                state_write.state = UpgradeState::RollingBack;
                state_write.rollback_reason = Some("Crash recovery".to_string());
                drop(state_write);
                self.rollback().await?;
            }
            UpgradeState::RollingBack => {
                tracing::info!("Rollback was in progress, resetting to idle");
                let mut state_write = self.state.write().await;
                state_write.state = UpgradeState::Idle;
            }
            UpgradeState::Idle => {}
        }

        Ok(())
    }
}

fn compute_binary_checksum(binary_path: &PathBuf) -> Result<[u8; 32], UpgradeError> {
    use std::io::Read;
    use sha2::{Digest, Sha256};

    let mut file = std::fs::File::open(binary_path)
        .map_err(|e| UpgradeError::BinaryNotFound(binary_path.clone()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file.read(&mut buffer)
            .map_err(|e| UpgradeError::IoError(e))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    let mut checksum = [0u8; 32];
    checksum.copy_from_slice(&result);
    Ok(checksum)
}
