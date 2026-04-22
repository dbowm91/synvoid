use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

use super::checksum::compute_sha256;
use super::constants::timeouts::WORKER_READY_TIMEOUT_SECS;
use super::health::{EnhancedHealthConfig, HealthChecker, ValidationMetrics};
use super::mode::{detect_upgrade_mode, UpgradeMode};
use super::preflight::{PreflightConfig, PreflightValidator};
use super::spawn::{cleanup_failed_spawns, ProcessMode, SpawnConfig};
use super::state::{OverseerState, Persistence, UpgradeState};
use crate::http_client::{
    create_simple_http_client, get_with_timeout, post_json_with_timeout, HttpClient,
};
use crate::process::get_secure_socket_path;

#[derive(Debug, Clone)]
pub struct AutoRollbackConfig {
    pub enabled: bool,
    pub health_check_retries: u32,
    pub health_check_interval_secs: u64,
    pub error_rate_threshold: f64,
    pub latency_degradation_threshold_percent: f64,
    pub min_sample_requests: usize,
    pub rollback_timeout_secs: u64,
}

impl Default for AutoRollbackConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            health_check_retries: 3,
            health_check_interval_secs: 5,
            error_rate_threshold: 0.1,
            latency_degradation_threshold_percent: 50.0,
            min_sample_requests: 5,
            rollback_timeout_secs: 30,
        }
    }
}

pub struct Orchestrator {
    pub state: Arc<RwLock<OverseerState>>,
    persistence: Persistence,
    health_checker: HealthChecker,
    data_dir: PathBuf,
    preflight_config: PreflightConfig,
    auto_rollback_config: AutoRollbackConfig,
}

impl Orchestrator {
    pub fn new(
        data_dir: Option<PathBuf>,
        health_path: Option<String>,
        timeout_secs: Option<u64>,
    ) -> Self {
        let data_dir = data_dir.unwrap_or_else(|| {
            dirs::home_dir()
                .map(|h| h.join(".maluwaf"))
                .unwrap_or_else(|| PathBuf::from(".maluwaf"))
        });
        let persistence = Persistence::new(Some(data_dir.clone()));
        let state = persistence.load().unwrap_or_default();

        Self {
            persistence,
            state: Arc::new(RwLock::new(state)),
            health_checker: HealthChecker::new(health_path, timeout_secs),
            data_dir,
            preflight_config: PreflightConfig::default(),
            auto_rollback_config: AutoRollbackConfig::default(),
        }
    }

    pub fn with_preflight_config(mut self, config: PreflightConfig) -> Self {
        self.preflight_config = config;
        self
    }

    pub fn with_auto_rollback_config(mut self, config: AutoRollbackConfig) -> Self {
        self.auto_rollback_config = config;
        self
    }

    pub async fn get_state(&self) -> OverseerState {
        self.state.read().await.clone()
    }

    pub async fn save_state(&self, state: &OverseerState) -> Result<(), UpgradeError> {
        let state_clone = state.clone();
        self.persistence
            .save(&state_clone)
            .map_err(UpgradeError::IoError)
    }

    pub async fn stage(
        &self,
        binary_path: PathBuf,
        config_path: Option<PathBuf>,
        expected_checksum: Option<String>,
    ) -> Result<(), UpgradeError> {
        let mut state = self.state.write().await;

        if !state.can_stage() {
            return Err(UpgradeError::InvalidState(format!(
                "Cannot stage in state: {}",
                state.state
            )));
        }

        if !binary_path.exists() {
            return Err(UpgradeError::BinaryNotFound(binary_path.clone()));
        }

        if let Some(ref expected) = expected_checksum {
            let actual = compute_sha256(&binary_path).map_err(UpgradeError::IoError)?;

            if &actual != expected {
                return Err(UpgradeError::ChecksumMismatch {
                    expected: expected.clone(),
                    actual,
                });
            }
            state.staged_binary_checksum = Some(expected.clone());
            tracing::info!("Binary checksum verified successfully");
        }

        drop(state);

        tracing::info!("Running preflight validation on binary: {:?}", binary_path);
        let validator = PreflightValidator::new(self.preflight_config.clone());
        let preflight_result = validator
            .validate_binary(&binary_path, config_path.as_ref())
            .map_err(|e| UpgradeError::PreflightFailed(e.to_string()))?;

        if !preflight_result.is_valid() {
            return Err(UpgradeError::PreflightFailed(format!(
                "Preflight validation failed: {:?}",
                preflight_result.errors
            )));
        }

        tracing::info!(
            "Preflight validation passed: version={}, startup_time={}ms, config_compatible={}",
            preflight_result.version,
            preflight_result.startup_time_ms,
            preflight_result.config_compatible
        );

        for warning in &preflight_result.warnings {
            tracing::warn!("Preflight warning: {}", warning);
        }

        let mut state = self.state.write().await;
        let version = preflight_result.version;

        if let Some(ref config) = config_path {
            if !config.exists() {
                return Err(UpgradeError::ConfigNotFound(config.clone()));
            }
        }

        state.state = UpgradeState::Staging;
        state.staged_version = Some(version);
        state.staged_binary_path = Some(binary_path.to_string_lossy().to_string());
        state.staged_config_path = config_path.map(|p| p.to_string_lossy().to_string());
        state.upgrade_mode = Some(detect_upgrade_mode());
        state.validation_retries = 0;
        state.last_error = None;

        self.save_state(&state).await?;

        tracing::info!(
            "Staged upgrade: version={}, mode={:?}",
            state.staged_version.as_deref().unwrap_or("unknown"),
            state.upgrade_mode
        );

        Ok(())
    }

    pub async fn apply(
        &self,
        worker_ports: Vec<u16>,
        timeout_secs: u64,
        drain_timeout_secs: u64,
    ) -> Result<UpgradeResult, UpgradeError> {
        let mut state = self.state.write().await;

        if !state.can_apply() {
            return Err(UpgradeError::InvalidState(format!(
                "Cannot apply in state: {}",
                state.state
            )));
        }

        let binary_path = state
            .staged_binary_path
            .as_ref()
            .ok_or(UpgradeError::NoStagedUpgrade)?
            .clone();

        let config_path = state.staged_config_path.clone();
        let version = state
            .staged_version
            .clone()
            .ok_or(UpgradeError::NoStagedUpgrade)?;
        let mode = state.upgrade_mode.unwrap_or_else(detect_upgrade_mode);

        // Create backup of current binary before upgrading
        if let Ok(current_exe) = std::env::current_exe() {
            let timestamp = crate::utils::current_timestamp();
            let bin_dir = self.data_dir.join("bin");
            let _ = fs::create_dir_all(&bin_dir);

            let backup_name = format!(
                "maluwaf-v{}-{}",
                state.current_version.as_deref().unwrap_or("unknown"),
                timestamp
            );
            let backup_path = bin_dir.join(&backup_name);

            if let Err(e) = fs::copy(&current_exe, &backup_path) {
                tracing::warn!("Failed to create backup of current binary: {}", e);
            } else {
                // Store previous binary info for rollback
                state.previous_binary_path = Some(backup_path.to_string_lossy().to_string());
                state.previous_version = state.current_version.clone();

                // Compute and store checksum of backup
                if let Ok(checksum) = compute_sha256(&backup_path) {
                    state.previous_binary_checksum = Some(checksum);
                }

                tracing::info!("Created backup at {:?}", backup_path);
            }
        }

        state.worker_ports = Some(worker_ports.clone());
        state.state = UpgradeState::Spawning;

        self.save_state(&state).await?;

        tracing::info!("Starting upgrade: version={}, mode={:?}", version, mode);

        let spawn_result = self
            .spawn_upgraded_workers(&binary_path, config_path.as_ref(), &worker_ports, &mode)
            .await;

        match spawn_result {
            Ok(new_ports) => {
                state.state = UpgradeState::Validating;
                state.worker_ports = Some(new_ports.clone());

                self.save_state(&state).await?;

                let validation_result = self.validate_upgrade(&new_ports, timeout_secs).await;

                match validation_result {
                    Ok(metrics) => {
                        state.state = UpgradeState::Draining;

                        self.save_state(&state).await?;

                        tracing::info!(
                            "Validation passed (success rate: {:.1}%)",
                            metrics.success_rate * 100.0
                        );

                        self.drain_old_workers(&worker_ports, drain_timeout_secs)
                            .await;

                        state.state = UpgradeState::Committed;
                        state.current_version = Some(version.clone());
                        state.last_upgrade_timestamp = Some(crate::utils::current_timestamp());
                        state.staged_binary_path = None;
                        state.staged_config_path = None;
                        state.staged_version = None;

                        let state_clone = state.clone();
                        self.persistence
                            .save(&state_clone)
                            .map_err(UpgradeError::IoError)?;

                        tracing::info!("Upgrade committed successfully");

                        Ok(UpgradeResult {
                            version,
                            mode,
                            metrics,
                            old_ports: worker_ports,
                            new_ports,
                        })
                    }
                    Err(failures) => {
                        state.state = UpgradeState::Failed;
                        state.current_version = state.previous_version.clone();
                        state.last_error = Some(format!("Validation failed: {:?}", failures));

                        let state_clone = state.clone();
                        self.persistence
                            .save(&state_clone)
                            .map_err(UpgradeError::IoError)?;

                        self.cleanup_failed_upgrade(&new_ports).await;

                        Err(UpgradeError::ValidationFailed(failures))
                    }
                }
            }
            Err(e) => {
                state.state = UpgradeState::Failed;
                state.last_error = Some(e.to_string());

                let state_clone = state.clone();
                self.persistence
                    .save(&state_clone)
                    .map_err(UpgradeError::IoError)?;

                Err(e)
            }
        }
    }

    pub async fn rollback(&self) -> Result<(), UpgradeError> {
        let mut state = self.state.write().await;

        if !state.can_rollback() {
            return Err(UpgradeError::InvalidState(format!(
                "Cannot rollback in state: {}",
                state.state
            )));
        }

        tracing::info!("Starting rollback");

        if let Some(ref ports) = state.worker_ports {
            self.cleanup_failed_upgrade(ports).await;
        }

        state.state = UpgradeState::RollingBack;
        state.last_rollback_timestamp = Some(crate::utils::current_timestamp());

        self.save_state(&state).await?;

        state.state = UpgradeState::Idle;

        self.save_state(&state).await?;

        tracing::info!("Rollback complete");

        Ok(())
    }

    pub async fn apply_with_auto_rollback(
        &self,
        worker_ports: Vec<u16>,
        timeout_secs: u64,
        drain_timeout_secs: u64,
    ) -> Result<UpgradeResult, UpgradeError> {
        let apply_result = self
            .apply(worker_ports.clone(), timeout_secs, drain_timeout_secs)
            .await;

        match apply_result {
            Ok(result) => {
                if self.auto_rollback_config.enabled {
                    tracing::info!("Performing post-upgrade health monitoring");

                    match self
                        .monitor_post_upgrade_health(&result.new_ports, &worker_ports)
                        .await
                    {
                        Ok(_) => {
                            tracing::info!("Post-upgrade health monitoring passed");
                            return Ok(result);
                        }
                        Err(health_error) => {
                            tracing::warn!(
                                "Post-upgrade health degradation detected: {}",
                                health_error
                            );

                            tracing::info!("Initiating automatic rollback");

                            if let Err(rollback_error) =
                                self.perform_auto_rollback(&worker_ports).await
                            {
                                tracing::error!("Automatic rollback failed: {}", rollback_error);
                                return Err(UpgradeError::AutoRollbackFailed(format!(
                                    "Health degraded: {}, Rollback also failed: {}",
                                    health_error, rollback_error
                                )));
                            }

                            return Err(UpgradeError::HealthDegradation(format!(
                                "Health degraded after upgrade, rolled back successfully: {}",
                                health_error
                            )));
                        }
                    }
                }

                Ok(result)
            }
            Err(e) => {
                let should_rollback = self.auto_rollback_config.enabled
                    && matches!(e, UpgradeError::ValidationFailed(_));

                if should_rollback {
                    tracing::warn!("Validation failed, attempting automatic rollback");

                    if let Err(rollback_error) = self.perform_auto_rollback(&worker_ports).await {
                        tracing::error!(
                            "Automatic rollback after validation failure also failed: {}",
                            rollback_error
                        );
                    }
                }

                Err(e)
            }
        }
    }

    async fn monitor_post_upgrade_health(
        &self,
        new_ports: &[u16],
        _old_ports: &[u16],
    ) -> Result<(), String> {
        let enhanced_config = EnhancedHealthConfig {
            sample_requests: self.auto_rollback_config.min_sample_requests,
            latency_threshold_ms: 1000,
            error_rate_threshold: self.auto_rollback_config.error_rate_threshold,
            compare_with_baseline: true,
            shadow_traffic_path: Some("/__internal__/health".to_string()),
        };

        for attempt in 1..=self.auto_rollback_config.health_check_retries {
            tracing::debug!(
                "Post-upgrade health check attempt {}/{}",
                attempt,
                self.auto_rollback_config.health_check_retries
            );

            let results = self
                .health_checker
                .validate_enhanced(new_ports, "127.0.0.1", &enhanced_config, 1, 1)
                .await;

            match results {
                Ok(health_results) => {
                    let mut has_degradation = false;
                    let mut degradation_reasons = Vec::new();

                    for result in &health_results {
                        if result.error_rate > self.auto_rollback_config.error_rate_threshold {
                            has_degradation = true;
                            degradation_reasons.push(format!(
                                "Port {} error rate {:.1}% exceeds threshold {:.1}%",
                                result.port,
                                result.error_rate * 100.0,
                                self.auto_rollback_config.error_rate_threshold * 100.0
                            ));
                        }

                        if let Some(ref comparison) = result.baseline_comparison {
                            if comparison.latency_degradation_percent
                                > self
                                    .auto_rollback_config
                                    .latency_degradation_threshold_percent
                            {
                                has_degradation = true;
                                degradation_reasons.push(format!(
                                    "Port {} latency degraded by {:.1}% (threshold: {:.1}%)",
                                    result.port,
                                    comparison.latency_degradation_percent,
                                    self.auto_rollback_config
                                        .latency_degradation_threshold_percent
                                ));
                            }
                        }
                    }

                    if has_degradation {
                        tracing::warn!(
                            "Health degradation detected on attempt {}: {:?}",
                            attempt,
                            degradation_reasons
                        );

                        if attempt < self.auto_rollback_config.health_check_retries {
                            tokio::time::sleep(Duration::from_secs(
                                self.auto_rollback_config.health_check_interval_secs,
                            ))
                            .await;
                            continue;
                        }

                        return Err(format!("Health degradation: {:?}", degradation_reasons));
                    }

                    tracing::info!("Post-upgrade health check passed on attempt {}", attempt);
                    return Ok(());
                }
                Err(failures) => {
                    let failure_summary: Vec<String> = failures
                        .iter()
                        .map(|f| {
                            format!(
                                "port {}: {:.1}% errors, {}ms avg latency",
                                f.port,
                                f.error_rate * 100.0,
                                f.avg_latency_ms
                            )
                        })
                        .collect();

                    tracing::warn!(
                        "Post-upgrade health check failed on attempt {}: {:?}",
                        attempt,
                        failure_summary
                    );

                    if attempt < self.auto_rollback_config.health_check_retries {
                        tokio::time::sleep(Duration::from_secs(
                            self.auto_rollback_config.health_check_interval_secs,
                        ))
                        .await;
                        continue;
                    }

                    return Err(format!("Health checks failed: {:?}", failure_summary));
                }
            }
        }

        Ok(())
    }

    async fn perform_auto_rollback(&self, worker_ports: &[u16]) -> Result<(), String> {
        tracing::info!("Starting automatic rollback procedure");

        let state = self.state.read().await.clone();

        let previous_binary = state
            .previous_binary_path
            .clone()
            .ok_or("No previous binary available for rollback")?;

        let previous_checksum = state.previous_binary_checksum.clone();
        let previous_version = state.previous_version.clone();

        tracing::info!(
            "Rolling back to previous version: {:?} from {:?}",
            previous_version,
            previous_binary
        );

        if !std::path::Path::new(&previous_binary).exists() {
            return Err(format!("Previous binary not found: {}", previous_binary));
        }

        if let Some(expected_checksum) = previous_checksum {
            match compute_sha256(&std::path::PathBuf::from(&previous_binary)) {
                Ok(actual_checksum) => {
                    if actual_checksum != expected_checksum {
                        return Err(format!(
                            "Previous binary checksum mismatch: expected {}, got {}",
                            expected_checksum, actual_checksum
                        ));
                    }
                }
                Err(e) => {
                    return Err(format!("Failed to verify previous binary checksum: {}", e));
                }
            }
        }

        self.cleanup_failed_upgrade(worker_ports).await;

        drop(state);

        let mut state = self.state.write().await;
        state.state = UpgradeState::RollingBack;
        state.last_rollback_timestamp = Some(crate::utils::current_timestamp());

        if let Err(e) = self.persistence.save(&state) {
            return Err(format!("Failed to save rollback state: {}", e));
        }

        state.state = UpgradeState::Idle;
        state.current_version = previous_version;
        state.last_error =
            Some("Automatic rollback performed due to health degradation".to_string());

        if let Err(e) = self.persistence.save(&state) {
            return Err(format!("Failed to save final rollback state: {}", e));
        }

        tracing::info!("Automatic rollback completed successfully");
        Ok(())
    }

    pub async fn cancel(&self) -> Result<(), UpgradeError> {
        let mut state = self.state.write().await;

        if !state.can_abort_upgrade() {
            return Err(UpgradeError::InvalidState(format!(
                "Cannot cancel in state: {}",
                state.state
            )));
        }

        state.state = UpgradeState::Idle;
        state.staged_version = None;
        state.staged_binary_path = None;
        state.staged_config_path = None;
        state.upgrade_mode = None;
        state.old_master_pid = None;
        state.new_master_pid = None;
        state.dual_master_start_time = None;

        self.save_state(&state).await?;

        tracing::info!("Staged upgrade cancelled");

        Ok(())
    }

    pub async fn prepare_dual_master_state(&self) -> Result<(), UpgradeError> {
        let mut state = self.state.write().await;

        if !state.can_apply() {
            return Err(UpgradeError::InvalidState(format!(
                "Cannot prepare dual-master in state: {}",
                state.state
            )));
        }

        state.state = UpgradeState::Spawning;

        self.save_state(&state).await?;

        tracing::info!("Prepared for dual-master upgrade");
        Ok(())
    }

    pub async fn set_dual_master_active(
        &self,
        old_pid: u32,
        new_pid: u32,
    ) -> Result<(), UpgradeError> {
        let mut state = self.state.write().await;

        state.state = UpgradeState::DualMasterActive;
        state.old_master_pid = Some(old_pid);
        state.new_master_pid = Some(new_pid);
        state.dual_master_start_time = Some(crate::utils::current_timestamp());

        self.save_state(&state).await?;

        tracing::info!("Dual-master mode active: old={}, new={}", old_pid, new_pid);
        Ok(())
    }

    pub async fn set_draining_old_master(
        &self,
        active_connections: Option<u64>,
    ) -> Result<(), UpgradeError> {
        let mut state = self.state.write().await;

        state.state = UpgradeState::DrainingOldMaster;
        state.active_connections_at_drain_start = active_connections;

        self.save_state(&state).await?;

        tracing::info!("Started draining old master");
        Ok(())
    }

    pub async fn commit_dual_master_upgrade(&self, version: String) -> Result<(), UpgradeError> {
        let mut state = self.state.write().await;

        state.state = UpgradeState::Committed;
        state.current_version = Some(version);
        state.last_upgrade_timestamp = Some(crate::utils::current_timestamp());
        state.old_master_pid = None;
        state.new_master_pid = None;
        state.staged_binary_path = None;
        state.staged_version = None;
        state.staged_config_path = None;
        state.dual_master_start_time = None;
        state.active_connections_at_drain_start = None;

        self.save_state(&state).await?;

        tracing::info!("Dual-master upgrade committed");
        Ok(())
    }

    pub async fn fail_dual_master_upgrade(&self, error: &str) -> Result<(), UpgradeError> {
        let mut state = self.state.write().await;

        state.state = UpgradeState::Failed;
        state.last_error = Some(error.to_string());
        state.new_master_pid = None;

        self.save_state(&state).await?;

        tracing::error!("Dual-master upgrade failed: {}", error);
        Ok(())
    }

    async fn spawn_workers_impl(
        &self,
        binary_path: &str,
        config_path: Option<&String>,
        ports: &[u16],
        mode: &UpgradeMode,
        timeout_message: &str,
    ) -> Result<Vec<u16>, UpgradeError> {
        let worker_binary = PathBuf::from(binary_path);

        if !worker_binary.exists() {
            return Err(UpgradeError::BinaryNotFound(worker_binary));
        }

        let new_ports: Vec<u16> = match mode {
            UpgradeMode::ReusePort => ports.to_vec(),
            UpgradeMode::PortSwap { temp_port_offset } => {
                ports.iter().map(|p| p + temp_port_offset).collect()
            }
        };

        let mut spawned_pids = Vec::new();

        for (i, &port) in new_ports.iter().enumerate() {
            let config = SpawnConfig {
                binary_path: worker_binary.clone(),
                config_path: PathBuf::from(config_path.unwrap_or(&"config".to_string())),
                mode: ProcessMode::Worker { worker_id: i, port },
                master_socket: Some(get_secure_socket_path("master.sock")),
                upgrade_mode: true,
                reuse_port: matches!(mode, UpgradeMode::ReusePort),
                socket_generation: None,
                versioned_socket: None,
                receive_sockets: false,
                socket_ports: Vec::new(),
            };

            match std::process::Command::new(&config.binary_path)
                .args([
                    "--worker",
                    "--worker-id",
                    &i.to_string(),
                    "--port",
                    &port.to_string(),
                ])
                .arg("--config-path")
                .arg(&config.config_path)
                .arg("--master-socket")
                .arg(get_secure_socket_path("master.sock"))
                .arg("--upgrade-mode")
                .spawn()
            {
                Ok(child) => {
                    spawned_pids.push(child.id());
                }
                Err(e) => {
                    cleanup_failed_spawns(&spawned_pids);
                    return Err(UpgradeError::SpawnFailed(e.to_string()));
                }
            }
        }

        self.wait_for_workers_ready(&new_ports, timeout_message)
            .await?;

        Ok(new_ports)
    }

    async fn wait_for_workers_ready(
        &self,
        ports: &[u16],
        timeout_message: &str,
    ) -> Result<(), UpgradeError> {
        let start = Instant::now();
        let timeout = Duration::from_secs(WORKER_READY_TIMEOUT_SECS);

        while start.elapsed() < timeout {
            tokio::time::sleep(Duration::from_secs(1)).await;

            let all_ready = self
                .health_checker
                .validate_all(ports, "127.0.0.1", 1, 1)
                .await
                .is_ok();

            if all_ready {
                return Ok(());
            }
        }

        Err(UpgradeError::Timeout(timeout_message.to_string()))
    }

    async fn spawn_upgraded_workers(
        &self,
        binary_path: &str,
        config_path: Option<&String>,
        ports: &[u16],
        mode: &UpgradeMode,
    ) -> Result<Vec<u16>, UpgradeError> {
        self.spawn_workers_impl(
            binary_path,
            config_path,
            ports,
            mode,
            "Workers failed to become ready",
        )
        .await
    }

    async fn validate_upgrade(
        &self,
        ports: &[u16],
        timeout_secs: u64,
    ) -> Result<ValidationMetrics, Vec<(u16, super::health::HealthStatus)>> {
        self.health_checker
            .validate_with_metrics(ports, "127.0.0.1", 3, timeout_secs / 3)
            .await
    }

    async fn drain_old_workers(&self, ports: &[u16], timeout_secs: u64) {
        tracing::info!("Draining old workers on ports: {:?}", ports);

        let drain_result = self
            .drain_old_workers_with_confirmation(ports, timeout_secs)
            .await;

        match drain_result {
            Ok(drained_count) => {
                tracing::info!("Successfully drained {} workers", drained_count);
            }
            Err(e) => {
                tracing::warn!("Drain completed with issues: {}", e);
            }
        }
    }

    async fn drain_old_workers_with_confirmation(
        &self,
        ports: &[u16],
        timeout_secs: u64,
    ) -> Result<usize, String> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct DrainStatusResponse {
            // SAFETY_REASON: serde field required for deserialization
            #[allow(dead_code)]
            drain_id: u64,
            // SAFETY_REASON: serde field required for deserialization
            #[allow(dead_code)]
            is_draining: bool,
            active_connections: u64,
            // SAFETY_REASON: serde field required for deserialization
            #[allow(dead_code)]
            idle_connections: u64,
            // SAFETY_REASON: serde field required for deserialization
            #[allow(dead_code)]
            connections_drained: u64,
            // SAFETY_REASON: serde field required for deserialization
            #[allow(dead_code)]
            drain_elapsed_secs: u64,
            drain_complete: bool,
            // SAFETY_REASON: serde field required for deserialization
            #[allow(dead_code)]
            stopped_accepting: bool,
        }

        let client: HttpClient = create_simple_http_client(Duration::from_secs(5));

        let drain_id = crate::utils::safe_unix_duration().as_millis() as u64;

        for port in ports {
            let drain_url = format!("http://127.0.0.1:{}/__internal__/drain", port);
            let drain_body = serde_json::json!({
                "timeout_secs": timeout_secs,
                "drain_id": drain_id,
            });

            match post_json_with_timeout(&client, &drain_url, &drain_body, Duration::from_secs(10))
                .await
            {
                Ok(resp) => {
                    if resp.status.is_success() {
                        tracing::debug!("Drain request sent to port {}", port);
                    } else {
                        tracing::warn!(
                            "Drain request to port {} returned status {}",
                            port,
                            resp.status
                        );
                    }
                }
                Err(e) => {
                    tracing::debug!("Failed to send drain request to port {}: {}", port, e);
                }
            }
        }

        let poll_interval = Duration::from_millis(200);
        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);
        let mut drained_count = 0;

        while start.elapsed() < timeout {
            let mut all_drained = true;
            drained_count = 0;

            for port in ports {
                let status_url = format!("http://127.0.0.1:{}/__internal__/drain-status", port);

                match get_with_timeout(&client, &status_url, Duration::from_secs(2)).await {
                    Ok(resp) => {
                        if let Ok(status) =
                            serde_json::from_slice::<DrainStatusResponse>(&resp.body)
                        {
                            if status.drain_complete || status.active_connections == 0 {
                                drained_count += 1;
                                tracing::debug!(
                                    "Port {} drained: active={}, complete={}",
                                    port,
                                    status.active_connections,
                                    status.drain_complete
                                );
                            } else {
                                all_drained = false;
                            }
                        } else {
                            all_drained = false;
                        }
                    }
                    Err(_) => {
                        all_drained = false;
                    }
                }
            }

            if all_drained {
                tracing::info!("All workers drained successfully");
                return Ok(drained_count);
            }

            tokio::time::sleep(poll_interval).await;
        }

        tracing::warn!(
            "Timeout waiting for workers to drain, drained {}/{}",
            drained_count,
            ports.len()
        );
        Ok(drained_count)
    }

    async fn cleanup_failed_upgrade(&self, ports: &[u16]) {
        tracing::info!("Cleaning up failed upgrade on ports: {:?}", ports);

        let client: HttpClient = create_simple_http_client(Duration::from_secs(5));

        for port in ports {
            let url = format!("http://127.0.0.1:{}/shutdown", port);

            let _ = post_json_with_timeout(
                &client,
                &url,
                &serde_json::json!({}),
                Duration::from_secs(5),
            )
            .await;
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    pub async fn spawn_workers_for_rollback(
        &self,
        binary_path: &str,
        config_path: Option<&String>,
        ports: &[u16],
        mode: Option<&UpgradeMode>,
    ) -> Result<Vec<u16>, UpgradeError> {
        let mode = mode.copied().unwrap_or_else(detect_upgrade_mode);

        self.spawn_workers_impl(
            binary_path,
            config_path,
            ports,
            &mode,
            "Rollback workers failed to become ready",
        )
        .await
    }

    pub async fn validate_rollback(
        &self,
        ports: &[u16],
    ) -> Result<ValidationMetrics, Vec<(u16, super::health::HealthStatus)>> {
        self.health_checker
            .validate_with_metrics(ports, "127.0.0.1", 3, 10)
            .await
    }
}

#[derive(Debug)]
pub struct UpgradeResult {
    pub version: String,
    pub mode: UpgradeMode,
    pub metrics: ValidationMetrics,
    pub old_ports: Vec<u16>,
    pub new_ports: Vec<u16>,
}

#[derive(Debug, thiserror::Error)]
pub enum UpgradeError {
    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("No staged upgrade found")]
    NoStagedUpgrade,

    #[error("Binary not found: {0}")]
    BinaryNotFound(PathBuf),

    #[error("Config not found: {0}")]
    ConfigNotFound(PathBuf),

    #[error("Checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },

    #[error("Validation failed: {0:?}")]
    ValidationFailed(Vec<(u16, super::health::HealthStatus)>),

    #[error("Spawn failed: {0}")]
    SpawnFailed(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Upgrade already in progress")]
    AlreadyInProgress,

    #[error("Dual master upgrade failed: {0}")]
    DualMasterFailed(String),

    #[error("Old master did not drain gracefully")]
    DrainTimeout,

    #[error("Preflight validation failed: {0}")]
    PreflightFailed(String),

    #[error("Automatic rollback failed: {0}")]
    AutoRollbackFailed(String),

    #[error("Health degradation detected: {0}")]
    HealthDegradation(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::super::preflight::PreflightResult;
    use super::*;

    #[test]
    fn test_auto_rollback_config_defaults() {
        let config = AutoRollbackConfig::default();
        assert!(config.enabled);
        assert_eq!(config.health_check_retries, 3);
        assert_eq!(config.health_check_interval_secs, 5);
        assert_eq!(config.error_rate_threshold, 0.1);
        assert_eq!(config.latency_degradation_threshold_percent, 50.0);
        assert_eq!(config.min_sample_requests, 5);
        assert_eq!(config.rollback_timeout_secs, 30);
    }

    #[test]
    fn test_upgrade_mode_detection() {
        let mode = detect_upgrade_mode();
        match mode {
            UpgradeMode::ReusePort => {}
            UpgradeMode::PortSwap { temp_port_offset } => {
                assert_eq!(temp_port_offset, 1000);
            }
        }
    }

    #[test]
    fn test_upgrade_mode_requires_temp_ports() {
        let reuse_port_mode = UpgradeMode::ReusePort;
        assert!(!reuse_port_mode.requires_temp_ports());

        let port_swap_mode = UpgradeMode::PortSwap {
            temp_port_offset: 1000,
        };
        assert!(port_swap_mode.requires_temp_ports());
    }

    #[test]
    fn test_upgrade_mode_name() {
        assert_eq!(UpgradeMode::ReusePort.name(), "SO_REUSEPORT");
        assert_eq!(
            UpgradeMode::PortSwap {
                temp_port_offset: 1000
            }
            .name(),
            "Port Swap"
        );
    }

    #[test]
    fn test_orchestrator_construction() {
        let orchestrator = Orchestrator::new(None, None, None);
        assert!(orchestrator.preflight_config.require_config_check);
        assert!(orchestrator.auto_rollback_config.enabled);
    }

    #[test]
    fn test_orchestrator_with_custom_configs() {
        let preflight_config = PreflightConfig {
            validation_timeout_secs: 60,
            require_config_check: false,
            require_capability_check: false,
            min_startup_time_ms: 200,
            max_startup_time_ms: 20000,
        };

        let auto_rollback_config = AutoRollbackConfig {
            enabled: false,
            health_check_retries: 5,
            health_check_interval_secs: 10,
            error_rate_threshold: 0.2,
            latency_degradation_threshold_percent: 75.0,
            min_sample_requests: 10,
            rollback_timeout_secs: 60,
        };

        let orchestrator = Orchestrator::new(None, None, None)
            .with_preflight_config(preflight_config.clone())
            .with_auto_rollback_config(auto_rollback_config.clone());

        assert!(!orchestrator.preflight_config.require_config_check);
        assert!(!orchestrator.auto_rollback_config.enabled);
        assert_eq!(orchestrator.preflight_config.validation_timeout_secs, 60);
        assert_eq!(orchestrator.auto_rollback_config.health_check_retries, 5);
    }

    #[test]
    fn test_upgrade_state_transitions() {
        use super::super::state::UpgradeState;

        assert!(UpgradeState::Idle.is_terminal());
        assert!(UpgradeState::Committed.is_terminal());
        assert!(UpgradeState::Failed.is_terminal());

        assert!(!UpgradeState::Staging.is_terminal());
        assert!(!UpgradeState::Spawning.is_terminal());
        assert!(!UpgradeState::Validating.is_terminal());
        assert!(!UpgradeState::Draining.is_terminal());
        assert!(!UpgradeState::RollingBack.is_terminal());

        assert!(UpgradeState::Staging.is_transition());
        assert!(!UpgradeState::Idle.is_transition());
    }

    #[test]
    fn test_overseer_state_can_stage() {
        use super::super::state::{OverseerState, UpgradeState};

        let state = OverseerState::new();
        assert!(state.can_stage());

        let mut staging_state = OverseerState::new();
        staging_state.state = UpgradeState::Staging;
        assert!(!staging_state.can_stage());

        let mut committed_state = OverseerState::new();
        committed_state.state = UpgradeState::Committed;
        assert!(committed_state.can_stage());

        let mut failed_state = OverseerState::new();
        failed_state.state = UpgradeState::Failed;
        assert!(failed_state.can_stage());
    }

    #[test]
    fn test_overseer_state_can_apply() {
        use super::super::state::{OverseerState, UpgradeState};

        let mut staging_state = OverseerState::new();
        staging_state.state = UpgradeState::Staging;
        assert!(staging_state.can_apply());

        let idle_state = OverseerState::new();
        assert!(!idle_state.can_apply());
    }

    #[test]
    fn test_overseer_state_can_rollback() {
        use super::super::state::{OverseerState, UpgradeState};

        let mut validating_state = OverseerState::new();
        validating_state.state = UpgradeState::Validating;
        assert!(validating_state.can_rollback());

        let mut failed_state = OverseerState::new();
        failed_state.state = UpgradeState::Failed;
        assert!(failed_state.can_rollback());

        let idle_state = OverseerState::new();
        assert!(!idle_state.can_rollback());
    }

    #[test]
    fn test_overseer_state_max_duration() {
        use super::super::state::UpgradeState;

        assert_eq!(UpgradeState::Staging.max_duration_secs(), Some(300));
        assert_eq!(UpgradeState::Spawning.max_duration_secs(), Some(120));
        assert_eq!(UpgradeState::Validating.max_duration_secs(), Some(300));
        assert_eq!(UpgradeState::Draining.max_duration_secs(), Some(600));
        assert_eq!(UpgradeState::RollingBack.max_duration_secs(), Some(300));
        assert!(UpgradeState::Idle.max_duration_secs().is_none());
        assert!(UpgradeState::Committed.max_duration_secs().is_none());
    }

    #[test]
    fn test_preflight_validation_logic() {
        let config = PreflightConfig::default();
        assert_eq!(config.validation_timeout_secs, 30);
        assert!(config.require_config_check);
        assert!(config.require_capability_check);
        assert_eq!(config.min_startup_time_ms, 100);
        assert_eq!(config.max_startup_time_ms, 10000);
    }

    #[test]
    fn test_preflight_result_validation() {
        let valid_result = PreflightResult {
            success: true,
            version: "1.0.0".to_string(),
            startup_time_ms: 500,
            config_compatible: true,
            capabilities: vec!["http1".to_string()],
            warnings: vec![],
            errors: vec![],
        };
        assert!(valid_result.is_valid());

        let invalid_result = PreflightResult {
            success: true,
            version: "1.0.0".to_string(),
            startup_time_ms: 500,
            config_compatible: true,
            capabilities: vec![],
            warnings: vec![],
            errors: vec!["Error 1".to_string()],
        };
        assert!(!invalid_result.is_valid());

        let failed_result = PreflightResult {
            success: false,
            version: "1.0.0".to_string(),
            startup_time_ms: 500,
            config_compatible: true,
            capabilities: vec![],
            warnings: vec![],
            errors: vec![],
        };
        assert!(!failed_result.is_valid());
    }

    #[test]
    fn test_validation_metrics() {
        let metrics = ValidationMetrics {
            total_checks: 100,
            successful_checks: 95,
            success_rate: 0.95,
        };
        assert_eq!(metrics.total_checks, 100);
        assert_eq!(metrics.successful_checks, 95);
        assert_eq!(metrics.success_rate, 0.95);
    }

    #[test]
    fn test_upgrade_result_struct() {
        let metrics = ValidationMetrics {
            total_checks: 10,
            successful_checks: 10,
            success_rate: 1.0,
        };

        let result = UpgradeResult {
            version: "2.0.0".to_string(),
            mode: UpgradeMode::ReusePort,
            metrics,
            old_ports: vec![8080, 8081],
            new_ports: vec![8080, 8081],
        };

        assert_eq!(result.version, "2.0.0");
        assert_eq!(result.old_ports, vec![8080, 8081]);
        assert_eq!(result.new_ports, vec![8080, 8081]);
    }

    #[test]
    fn test_upgrade_error_display() {
        let error = UpgradeError::NoStagedUpgrade;
        assert_eq!(error.to_string(), "No staged upgrade found");

        let error = UpgradeError::BinaryNotFound(PathBuf::from("/bin/fake"));
        assert_eq!(error.to_string(), "Binary not found: /bin/fake");

        let error = UpgradeError::ChecksumMismatch {
            expected: "abc123".to_string(),
            actual: "def456".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "Checksum mismatch: expected abc123, got def456"
        );
    }

    #[test]
    fn test_orchestrator_state_persistence() {
        use super::super::state::OverseerState;

        let state = OverseerState::new();
        assert!(state.staged_version.is_none());
        assert!(state.current_version.is_none());
        assert!(state.worker_ports.is_none());
    }

    // ── Phase L.4: Upgrade State Machine Tests ──────────────────────

    #[test]
    fn test_upgrade_state_is_terminal() {
        use super::super::state::UpgradeState;

        assert!(UpgradeState::Idle.is_terminal());
        assert!(UpgradeState::Committed.is_terminal());
        assert!(UpgradeState::Failed.is_terminal());

        assert!(!UpgradeState::Staging.is_terminal());
        assert!(!UpgradeState::Spawning.is_terminal());
        assert!(!UpgradeState::Validating.is_terminal());
        assert!(!UpgradeState::Draining.is_terminal());
        assert!(!UpgradeState::RollingBack.is_terminal());
        assert!(!UpgradeState::RecoveryNeeded.is_terminal());
        assert!(!UpgradeState::DualMasterActive.is_terminal());
        assert!(!UpgradeState::DrainingOldMaster.is_terminal());
    }

    #[test]
    fn test_upgrade_state_is_transition() {
        use super::super::state::UpgradeState;

        assert!(!UpgradeState::Idle.is_transition());
        assert!(!UpgradeState::Committed.is_transition());
        assert!(!UpgradeState::Failed.is_transition());

        assert!(UpgradeState::Staging.is_transition());
        assert!(UpgradeState::Spawning.is_transition());
        assert!(UpgradeState::Validating.is_transition());
        assert!(UpgradeState::Draining.is_transition());
        assert!(UpgradeState::RollingBack.is_transition());
        assert!(UpgradeState::RecoveryNeeded.is_transition());
        assert!(UpgradeState::DualMasterActive.is_transition());
        assert!(UpgradeState::DrainingOldMaster.is_transition());
    }

    #[test]
    fn test_upgrade_state_display() {
        use super::super::state::UpgradeState;

        assert_eq!(format!("{}", UpgradeState::Idle), "IDLE");
        assert_eq!(format!("{}", UpgradeState::Staging), "STAGING");
        assert_eq!(format!("{}", UpgradeState::Spawning), "SPAWNING");
        assert_eq!(format!("{}", UpgradeState::Validating), "VALIDATING");
        assert_eq!(format!("{}", UpgradeState::Draining), "DRAINING");
        assert_eq!(format!("{}", UpgradeState::Committed), "COMMITTED");
        assert_eq!(format!("{}", UpgradeState::RollingBack), "ROLLING_BACK");
        assert_eq!(format!("{}", UpgradeState::Failed), "FAILED");
        assert_eq!(format!("{}", UpgradeState::RecoveryNeeded), "RECOVERY_NEEDED");
        assert_eq!(format!("{}", UpgradeState::DualMasterActive), "DUAL_MASTER_ACTIVE");
        assert_eq!(format!("{}", UpgradeState::DrainingOldMaster), "DRAINING_OLD_MASTER");
    }

    #[test]
    fn test_upgrade_state_max_duration() {
        use super::super::state::UpgradeState;

        assert_eq!(UpgradeState::Staging.max_duration_secs(), Some(300));
        assert_eq!(UpgradeState::Spawning.max_duration_secs(), Some(120));
        assert_eq!(UpgradeState::Validating.max_duration_secs(), Some(300));
        assert_eq!(UpgradeState::Draining.max_duration_secs(), Some(600));
        assert_eq!(UpgradeState::RollingBack.max_duration_secs(), Some(300));
        assert_eq!(UpgradeState::DualMasterActive.max_duration_secs(), Some(600));
        assert_eq!(UpgradeState::DrainingOldMaster.max_duration_secs(), Some(600));

        assert!(UpgradeState::Idle.max_duration_secs().is_none());
        assert!(UpgradeState::Committed.max_duration_secs().is_none());
        assert!(UpgradeState::Failed.max_duration_secs().is_none());
        assert!(UpgradeState::RecoveryNeeded.max_duration_secs().is_none());
    }

    #[test]
    fn test_overseer_state_new() {
        use super::super::state::OverseerState;

        let state = OverseerState::new();
        assert_eq!(state.state, super::super::state::UpgradeState::Idle);
        assert!(state.current_version.is_none());
        assert!(state.staged_version.is_none());
        assert!(state.staged_binary_path.is_none());
        assert!(state.staged_config_path.is_none());
        assert!(state.upgrade_mode.is_none());
        assert!(state.last_upgrade_timestamp.is_none());
        assert!(state.last_rollback_timestamp.is_none());
        assert!(state.last_error.is_none());
        assert!(state.worker_count.is_none());
        assert!(state.worker_ports.is_none());
        assert_eq!(state.validation_retries, 0);
    }

    #[test]
    fn test_overseer_state_can_stage_idle() {
        use super::super::state::{OverseerState, UpgradeState};

        let state = OverseerState::new();
        assert!(state.can_stage());

        let mut staging = OverseerState::new();
        staging.state = UpgradeState::Staging;
        assert!(!staging.can_stage());

        let mut spawning = OverseerState::new();
        spawning.state = UpgradeState::Spawning;
        assert!(!spawning.can_stage());

        let mut validating = OverseerState::new();
        validating.state = UpgradeState::Validating;
        assert!(!validating.can_stage());

        let mut draining = OverseerState::new();
        draining.state = UpgradeState::Draining;
        assert!(!draining.can_stage());
    }

    #[test]
    fn test_overseer_state_can_stage_committed() {
        use super::super::state::{OverseerState, UpgradeState};

        let mut state = OverseerState::new();
        state.state = UpgradeState::Committed;
        assert!(state.can_stage());
    }

    #[test]
    fn test_overseer_state_can_stage_failed() {
        use super::super::state::{OverseerState, UpgradeState};

        let mut state = OverseerState::new();
        state.state = UpgradeState::Failed;
        assert!(state.can_stage());
    }

    #[test]
    fn test_overseer_state_can_stage_recovery_needed() {
        use super::super::state::{OverseerState, UpgradeState};

        let mut state = OverseerState::new();
        state.state = UpgradeState::RecoveryNeeded;
        assert!(state.can_stage());
    }

    #[test]
    fn test_overseer_state_cannot_stage_transient_states() {
        use super::super::state::{OverseerState, UpgradeState};

        for state_enum in [
            UpgradeState::Staging,
            UpgradeState::Spawning,
            UpgradeState::Validating,
            UpgradeState::Draining,
            UpgradeState::DualMasterActive,
            UpgradeState::DrainingOldMaster,
        ] {
            let mut state = OverseerState::new();
            state.state = state_enum;
            assert!(
                !state.can_stage(),
                "Should not be able to stage from {:?}",
                state_enum
            );
        }
    }

    #[test]
    fn test_overseer_state_can_apply_only_staging() {
        use super::super::state::{OverseerState, UpgradeState};

        let mut staging_state = OverseerState::new();
        staging_state.state = UpgradeState::Staging;
        assert!(staging_state.can_apply());

        let idle_state = OverseerState::new();
        assert!(!idle_state.can_apply());

        let mut spawning = OverseerState::new();
        spawning.state = UpgradeState::Spawning;
        assert!(!spawning.can_apply());

        let mut committed = OverseerState::new();
        committed.state = UpgradeState::Committed;
        assert!(!committed.can_apply());
    }

    #[test]
    fn test_overseer_state_can_rollback_from_validating() {
        use super::super::state::{OverseerState, UpgradeState};

        let mut validating = OverseerState::new();
        validating.state = UpgradeState::Validating;
        assert!(validating.can_rollback());
    }

    #[test]
    fn test_overseer_state_can_rollback_from_failed() {
        use super::super::state::{OverseerState, UpgradeState};

        let mut failed = OverseerState::new();
        failed.state = UpgradeState::Failed;
        assert!(failed.can_rollback());
    }

    #[test]
    fn test_overseer_state_can_rollback_from_recovery_needed() {
        use super::super::state::{OverseerState, UpgradeState};

        let mut recovery = OverseerState::new();
        recovery.state = UpgradeState::RecoveryNeeded;
        assert!(recovery.can_rollback());
    }

    #[test]
    fn test_overseer_state_cannot_rollback_from_idle() {
        use super::super::state::OverseerState;

        let state = OverseerState::new();
        assert!(!state.can_rollback());
    }

    #[test]
    fn test_overseer_state_cannot_rollback_from_committed() {
        use super::super::state::{OverseerState, UpgradeState};

        let mut committed = OverseerState::new();
        committed.state = UpgradeState::Committed;
        assert!(!committed.can_rollback());
    }

    #[test]
    fn test_overseer_state_cannot_rollback_from_staging() {
        use super::super::state::{OverseerState, UpgradeState};

        let mut staging = OverseerState::new();
        staging.state = UpgradeState::Staging;
        assert!(!staging.can_rollback());
    }

    #[test]
    fn test_overseer_state_needs_recovery_states() {
        use super::super::state::{OverseerState, UpgradeState};

        let mut recovery_needed = OverseerState::new();
        recovery_needed.state = UpgradeState::RecoveryNeeded;
        assert!(recovery_needed.needs_recovery());

        let mut dual_master = OverseerState::new();
        dual_master.state = UpgradeState::DualMasterActive;
        assert!(dual_master.needs_recovery());

        let mut draining_old = OverseerState::new();
        draining_old.state = UpgradeState::DrainingOldMaster;
        assert!(draining_old.needs_recovery());

        let mut rolling_back = OverseerState::new();
        rolling_back.state = UpgradeState::RollingBack;
        assert!(rolling_back.needs_recovery());
    }

    #[test]
    fn test_overseer_state_idle_does_not_need_recovery() {
        use super::super::state::OverseerState;

        let state = OverseerState::new();
        assert!(!state.needs_recovery());
    }

    #[test]
    fn test_overseer_state_is_dual_master_state() {
        use super::super::state::{OverseerState, UpgradeState};

        let mut dual_master_active = OverseerState::new();
        dual_master_active.state = UpgradeState::DualMasterActive;
        assert!(dual_master_active.is_dual_master_state());

        let mut draining_old = OverseerState::new();
        draining_old.state = UpgradeState::DrainingOldMaster;
        assert!(draining_old.is_dual_master_state());
    }

    #[test]
    fn test_overseer_state_not_dual_master_when_idle() {
        use super::super::state::OverseerState;

        let state = OverseerState::new();
        assert!(!state.is_dual_master_state());
    }

    #[test]
    fn test_overseer_state_can_abort_upgrade() {
        use super::super::state::{OverseerState, UpgradeState};

        let mut staging = OverseerState::new();
        staging.state = UpgradeState::Staging;
        assert!(staging.can_abort_upgrade());

        let mut spawning = OverseerState::new();
        spawning.state = UpgradeState::Spawning;
        assert!(spawning.can_abort_upgrade());

        let mut dual_master = OverseerState::new();
        dual_master.state = UpgradeState::DualMasterActive;
        assert!(dual_master.can_abort_upgrade());

        let mut draining_old = OverseerState::new();
        draining_old.state = UpgradeState::DrainingOldMaster;
        assert!(draining_old.can_abort_upgrade());
    }

    #[test]
    fn test_overseer_state_cannot_abort_from_idle() {
        use super::super::state::OverseerState;

        let state = OverseerState::new();
        assert!(!state.can_abort_upgrade());
    }

    #[test]
    fn test_overseer_state_cannot_abort_from_validating() {
        use super::super::state::{OverseerState, UpgradeState};

        let mut validating = OverseerState::new();
        validating.state = UpgradeState::Validating;
        assert!(!validating.can_abort_upgrade());
    }

    #[test]
    fn test_overseer_state_enter_state() {
        use super::super::state::{OverseerState, UpgradeState};

        let mut state = OverseerState::new();
        assert!(state.state_entered_at.is_none());

        state.enter_state(UpgradeState::Staging);
        assert_eq!(state.state, UpgradeState::Staging);
        assert!(state.state_entered_at.is_some());

        state.enter_state(UpgradeState::Spawning);
        assert_eq!(state.state, UpgradeState::Spawning);
    }

    #[test]
    fn test_overseer_state_time_in_current_state() {
        use super::super::state::{OverseerState, UpgradeState};

        let mut state = OverseerState::new();
        state.enter_state(UpgradeState::Staging);

        let time_in_state = state.time_in_current_state();
        assert!(time_in_state.is_some());
        assert_eq!(time_in_state.unwrap().as_secs(), 0);
    }

    #[test]
    fn test_overseer_state_time_in_current_state_none_when_not_entered() {
        use super::super::state::OverseerState;

        let state = OverseerState::new();
        assert!(state.time_in_current_state().is_none());
    }

    #[test]
    fn test_overseer_state_is_state_timed_out() {
        use super::super::state::{OverseerState, UpgradeState};

        let mut state = OverseerState::new();
        state.enter_state(UpgradeState::Staging);
        assert!(!state.is_state_timed_out());
    }

    #[test]
    fn test_overseer_state_remaining_state_time() {
        use super::super::state::{OverseerState, UpgradeState};

        let mut state = OverseerState::new();
        state.enter_state(UpgradeState::Staging);

        let remaining = state.remaining_state_time();
        assert!(remaining.is_some());
        assert!(remaining.unwrap().as_secs() > 0);
    }

    #[test]
    fn test_overseer_state_remaining_state_time_none_for_terminal() {
        use super::super::state::OverseerState;

        let state = OverseerState::new();
        assert!(state.remaining_state_time().is_none());
    }

    #[test]
    fn test_upgrade_mode_payload_serde() {
        use crate::process::ipc::UpgradeModePayload;

        let reuse = UpgradeModePayload::ReusePort;
        let json = serde_json::to_string(&reuse).unwrap();
        let decoded: UpgradeModePayload = serde_json::from_str(&json).unwrap();
        assert_eq!(reuse, decoded);

        let port_swap = UpgradeModePayload::PortSwap { temp_port_offset: 1000 };
        let json = serde_json::to_string(&port_swap).unwrap();
        let decoded: UpgradeModePayload = serde_json::from_str(&json).unwrap();
        assert_eq!(port_swap, decoded);
    }
}
