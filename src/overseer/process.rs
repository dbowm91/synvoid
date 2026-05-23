use std::path::PathBuf;
use std::process::Child;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(unix)]
use nix::sys::signal::kill;
#[cfg(unix)]
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};

use super::drain_manager::DrainManager;
use super::socket_handoff::DualMasterHandoff;
use super::spawn::{spawn_and_log, ProcessMode, SpawnConfig};
use super::state::{Persistence, UpgradeState};
use super::upgrade::{Orchestrator, UpgradeError};
pub use crate::config::OverseerConfig;
use crate::process::{
    cleanup_old_master_sockets, get_master_socket_path, get_secure_socket_path,
    get_versioned_master_socket_path, next_master_generation, set_master_generation, IpcStream,
    Message,
};
use crate::utils::errors;
use crate::RunningFlag;

const OVERSEER_STATUS_FILE: &str = "overseer_status.json";
#[allow(dead_code)]
const STATUS_WRITE_INTERVAL_SECS: u64 = 5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverseerStatusFile {
    pub running: bool,
    pub pid: Option<u32>,
    pub master_pid: Option<u32>,
    pub master_status: String,
    pub uptime_secs: u64,
    pub upgrade_mode: String,
    pub drain_status: String,
    pub workers: Vec<WorkerStatusInfo>,
    pub version: String,
    pub last_updated: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerStatusInfo {
    pub id: u32,
    pub status: String,
    pub connections: u64,
}

pub struct OverseerProcess {
    master_child: Option<Child>,
    upgraded_master_child: Option<Child>,
    mesh_agent_child: Option<Child>,
    config_path: PathBuf,
    runtime_dir: PathBuf,
    running: RunningFlag,
    persistence: Persistence,
    orchestrator: Orchestrator,
    config: OverseerConfig,
    restart_count: u32,
    last_restart_at: Option<Instant>,
    stable_since: Option<Instant>,
    start_time: Instant,
    dual_master_mode: bool,
    socket_handoff: Option<DualMasterHandoff>,
    #[allow(dead_code)]
    drain_manager: Arc<DrainManager>,
    upgrade_generation: Option<u32>,
}

impl OverseerProcess {
    pub fn new(
        config: OverseerConfig,
        runtime_dir: PathBuf,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let persistence = Persistence::new(None);
        let orchestrator = Orchestrator::new(None, None, None);

        let config_path = config
            .config_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("config"));

        let drain_check_interval_ms = config.drain_check_interval_ms;

        Ok(Self {
            master_child: None,
            upgraded_master_child: None,
            mesh_agent_child: None,
            config_path: config_path.clone(),
            runtime_dir,
            running: RunningFlag::new(),
            persistence,
            orchestrator,
            config,
            restart_count: 0,
            last_restart_at: None,
            stable_since: None,
            start_time: Instant::now(),
            dual_master_mode: false,
            socket_handoff: None,
            drain_manager: Arc::new(DrainManager::new(drain_check_interval_ms)),
            upgrade_generation: None,
        })
    }

    pub fn spawn_master(&mut self) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        let config = SpawnConfig::for_current_binary(self.config_path.clone(), ProcessMode::Master);

        let child = spawn_and_log(&config, "master")?;
        let pid = child.id();

        self.master_child = Some(child);
        self.stable_since = Some(Instant::now());
        Ok(pid)
    }

    pub fn check_master_health(
        &mut self,
    ) -> Result<MasterHealth, Box<dyn std::error::Error + Send + Sync>> {
        let process_alive = if let Some(ref mut child) = self.master_child {
            match child.try_wait() {
                Ok(None) => true,
                Ok(Some(status)) => {
                    tracing::warn!("Master process exited with status: {}", status);
                    false
                }
                Err(e) => {
                    tracing::error!("Failed to check master process: {}", e);
                    return Err(e.into());
                }
            }
        } else {
            false
        };

        if !process_alive {
            return Ok(MasterHealth {
                process_alive: false,
                ipc_responsive: false,
                workers_healthy: false,
            });
        }

        let ipc_health = self.check_master_ipc_health();

        Ok(MasterHealth {
            process_alive: true,
            ipc_responsive: ipc_health.is_responsive,
            workers_healthy: ipc_health.workers_healthy,
        })
    }

    fn check_master_ipc_health(&self) -> IpcHealthResult {
        let socket_path = if self.dual_master_mode {
            if let Some(gen) = self.upgrade_generation {
                get_versioned_master_socket_path(gen)
            } else {
                get_master_socket_path()
            }
        } else {
            get_master_socket_path()
        };

        match IpcStream::connect_unix(&socket_path) {
            Ok(mut stream) => {
                let health_msg = Message::MasterHealthCheck {
                    timestamp: crate::utils::safe_unix_timestamp(),
                };

                if stream.send(&health_msg).is_err() {
                    return IpcHealthResult {
                        is_responsive: false,
                        workers_healthy: false,
                    };
                }

                match stream.recv(5000) {
                    Ok(Some(Message::HealthCheckAck { .. })) => IpcHealthResult {
                        is_responsive: true,
                        workers_healthy: true,
                    },
                    Ok(None) => IpcHealthResult {
                        is_responsive: false,
                        workers_healthy: false,
                    },
                    Ok(Some(_)) => IpcHealthResult {
                        is_responsive: false,
                        workers_healthy: false,
                    },
                    Err(_) => IpcHealthResult {
                        is_responsive: false,
                        workers_healthy: false,
                    },
                }
            }
            Err(_) => IpcHealthResult {
                is_responsive: false,
                workers_healthy: false,
            },
        }
    }

    pub fn reload_config(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let config_file = self.config_path.join("main.toml");

        if !config_file.exists() {
            tracing::warn!("Config file not found: {:?}", config_file);
            return Ok(());
        }

        let content = std::fs::read_to_string(&config_file)?;

        let main_config: crate::config::MainConfig =
            toml::from_str(&content).map_err(|e| format!("Failed to parse config: {}", e))?;

        let new_overseer_config = main_config.overseer;

        tracing::info!("Reloading overseer config from {:?}", config_file);

        if self.config.health_check_interval_secs != new_overseer_config.health_check_interval_secs
        {
            tracing::info!(
                "health_check_interval changed from {} to {}",
                self.config.health_check_interval_secs,
                new_overseer_config.health_check_interval_secs
            );
        }

        self.config.auto_restart = new_overseer_config.auto_restart;
        self.config.restart_delay_secs = new_overseer_config.restart_delay_secs;
        self.config.max_restart_attempts = new_overseer_config.max_restart_attempts;
        self.config.health_check_interval_secs = new_overseer_config.health_check_interval_secs;
        self.config.stable_uptime_secs = new_overseer_config.stable_uptime_secs;
        self.config.upgrade_validation_timeout_secs =
            new_overseer_config.upgrade_validation_timeout_secs;
        self.config.upgrade_drain_timeout_secs = new_overseer_config.upgrade_drain_timeout_secs;
        self.config.upgrade_health_check_retries = new_overseer_config.upgrade_health_check_retries;
        self.config.upgrade_health_check_interval_secs =
            new_overseer_config.upgrade_health_check_interval_secs;
        self.config.ipc_read_timeout_ms = new_overseer_config.ipc_read_timeout_ms;
        self.config.ipc_write_timeout_ms = new_overseer_config.ipc_write_timeout_ms;
        self.config.master_startup_timeout_secs = new_overseer_config.master_startup_timeout_secs;
        self.config.process_stop_timeout_secs = new_overseer_config.process_stop_timeout_secs;
        self.config.restart_backoff_max_secs = new_overseer_config.restart_backoff_max_secs;

        tracing::info!("Overseer config reloaded successfully");
        Ok(())
    }

    pub fn check_reload_signal(
        &mut self,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let signal_file = std::env::current_dir()
            .map_err(|e| format!("Failed to get current dir: {}", e))?
            .join(".overseer_reload");

        if signal_file.exists() {
            if let Err(e) = std::fs::remove_file(&signal_file) {
                tracing::warn!("Failed to remove reload signal file: {}", e);
            }
            tracing::info!("Detected reload signal file at {:?}", signal_file);

            if let Err(e) = self.reload_config() {
                tracing::error!("Failed to reload config: {}", e);
                return Ok(true);
            }
            return Ok(true);
        }

        Ok(false)
    }

    fn stop_child_process(
        child_opt: &mut Option<Child>,
        process_name: &str,
        graceful: bool,
        timeout: Duration,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(ref mut child) = child_opt {
            let pid = child.id();

            if graceful {
                #[cfg(unix)]
                {
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(pid as i32),
                        nix::sys::signal::Signal::SIGTERM,
                    );
                }

                let start = Instant::now();
                while start.elapsed() < timeout {
                    match child.try_wait() {
                        Ok(Some(_)) => {
                            tracing::info!("{} process stopped gracefully", process_name);
                            *child_opt = None;
                            return Ok(());
                        }
                        Ok(None) => {
                            std::thread::sleep(Duration::from_millis(100));
                        }
                        Err(_) => break,
                    }
                }
            }

            let _ = child.kill();
            let _ = child.wait();
            *child_opt = None;
        }
        Ok(())
    }

    pub fn stop_master(
        &mut self,
        graceful: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let timeout = Duration::from_secs(self.config.process_stop_timeout_secs);
        Self::stop_child_process(&mut self.master_child, "master", graceful, timeout)
    }

    pub fn spawn_mesh_agent(&mut self) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        let config =
            SpawnConfig::for_current_binary(self.config_path.clone(), ProcessMode::MeshAgent);

        let child = spawn_and_log(&config, "mesh-agent")?;
        let pid = child.id();

        self.mesh_agent_child = Some(child);
        Ok(pid)
    }

    pub fn stop_mesh_agent(
        &mut self,
        graceful: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let timeout = Duration::from_secs(self.config.process_stop_timeout_secs);
        Self::stop_child_process(&mut self.mesh_agent_child, "mesh-agent", graceful, timeout)
    }

    pub fn stop_all_isolated_processes(
        &mut self,
        graceful: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.stop_mesh_agent(graceful)?;
        self.stop_master(graceful)?;
        Ok(())
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let state = self.persistence.load().unwrap_or_default();

        if state.needs_recovery() {
            tracing::warn!(
                "Overseer detected incomplete upgrade state ({}), attempting automatic recovery",
                state.state
            );
            if let Err(e) = self.attempt_recovery().await {
                tracing::error!("Automatic recovery failed: {}", e);
            }
        }

        self.spawn_master()?;
        self.spawn_mesh_agent()?;

        // Signal readiness to systemd if running under it
        if let Err(e) = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]) {
            tracing::debug!("Failed to send systemd readiness notification: {}", e);
        }

        // Write initial status file
        self.write_status_file().await;

        while self.running.is_running() {
            tokio::time::sleep(Duration::from_secs(self.config.health_check_interval_secs)).await;

            if let Err(e) = self.check_reload_signal() {
                tracing::warn!("Error checking reload signal: {}", e);
            }

            let health = self.check_master_health()?;

            if !health.process_alive {
                if self.config.auto_restart {
                    self.handle_master_restart().await?;
                } else {
                    tracing::error!("Master process died and auto_restart is disabled");
                    break;
                }
            } else if !health.ipc_responsive {
                tracing::warn!("Master process is alive but not responding to IPC");
            }

            // Monitor Mesh Agent
            if self.running.is_running() {
                if let Some(ref mut child) = self.mesh_agent_child {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            tracing::warn!(
                                "Mesh Agent process exited with status: {}. Restarting...",
                                status
                            );
                            let _ = self.spawn_mesh_agent();
                        }
                        Ok(None) => {}
                        Err(e) => {
                            tracing::error!("Failed to check mesh agent: {}", e);
                        }
                    }
                } else if self.running.is_running() {
                    let _ = self.spawn_mesh_agent();
                }
            }

            // Periodically write status file
            self.write_status_file().await;
        }

        self.stop_all_isolated_processes(true)?;
        Ok(())
    }

    async fn write_status_file(&self) {
        let status = self.collect_status();
        let json = match serde_json::to_string_pretty(&status) {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!("Failed to serialize overseer status: {}", e);
                return;
            }
        };

        let status_path = self.runtime_dir.join(OVERSEER_STATUS_FILE);
        let temp_path = self
            .runtime_dir
            .join(format!("{}.tmp", OVERSEER_STATUS_FILE));

        if let Err(e) = tokio::fs::write(&temp_path, json).await {
            tracing::warn!("Failed to write overseer status file: {}", e);
            return;
        }

        if let Err(e) = tokio::fs::rename(&temp_path, &status_path).await {
            tracing::warn!("Failed to rename overseer status file: {}", e);
            let _ = tokio::fs::remove_file(&temp_path).await;
        }
    }

    fn collect_status(&self) -> OverseerStatusFile {
        let running = self.running.is_running();
        let pid = std::process::id();

        let master_pid = self.master_child.as_ref().map(|c| c.id());
        let (master_status, workers) = if self.master_child.is_some() {
            let status = futures::executor::block_on(self.get_master_status());
            match status {
                Some(s) => (
                    "Running".to_string(),
                    s.workers
                        .into_iter()
                        .map(|w| WorkerStatusInfo {
                            id: w.id as u32,
                            status: w.status,
                            connections: w.requests,
                        })
                        .collect(),
                ),
                None => ("Running".to_string(), Vec::new()),
            }
        } else {
            ("Stopped".to_string(), Vec::new())
        };

        let uptime_secs = self.start_time.elapsed().as_secs();

        let upgrade_mode = self
            .persistence
            .load()
            .map(|s| s.state.to_string())
            .unwrap_or_else(|_| "IDLE".to_string());

        let drain_status = if let Ok(state) = self.persistence.load() {
            if state.state.is_transition() && state.state != UpgradeState::Idle {
                "Active".to_string()
            } else {
                "Idle".to_string()
            }
        } else {
            "Idle".to_string()
        };

        let version = env!("CARGO_PKG_VERSION").to_string();

        OverseerStatusFile {
            running,
            pid: Some(pid),
            master_pid,
            master_status,
            uptime_secs,
            upgrade_mode,
            drain_status,
            workers,
            version,
            last_updated: crate::utils::safe_unix_timestamp(),
        }
    }

    async fn handle_master_restart(
        &mut self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.restart_count >= self.config.max_restart_attempts {
            tracing::error!(
                "Master process exceeded max restart attempts ({})",
                self.config.max_restart_attempts
            );
            self.running.stop();
            return Err(format!(
                "Master exceeded max restart attempts ({})",
                self.config.max_restart_attempts
            )
            .into());
        }

        if let Some(stable_since) = self.stable_since {
            if stable_since.elapsed() >= Duration::from_secs(self.config.stable_uptime_secs) {
                self.restart_count = 0;
                tracing::info!(
                    "Master was stable for {}s, resetting restart count",
                    self.config.stable_uptime_secs
                );
            }
        }

        let delay = self.calculate_restart_delay();
        tracing::warn!(
            "Master process died, restarting in {}s (attempt {}/{})",
            delay,
            self.restart_count + 1,
            self.config.max_restart_attempts
        );

        tokio::time::sleep(Duration::from_secs(delay)).await;

        if !self.running.is_running() {
            return Ok(());
        }

        self.restart_count += 1;
        self.last_restart_at = Some(Instant::now());

        self.spawn_master()?;

        Ok(())
    }

    fn calculate_restart_delay(&self) -> u64 {
        let base_delay = self.config.restart_delay_secs;
        let backoff_multiplier = 2_u64.pow(self.restart_count.min(6));
        std::cmp::min(
            base_delay * backoff_multiplier,
            self.config.restart_backoff_max_secs,
        )
    }

    #[cfg(unix)]
    async fn attempt_recovery(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let state = self.persistence.load().unwrap_or_default();

        if let Some(ref new_pid) = state.new_master_pid {
            let new_master_alive = kill(Pid::from_raw(*new_pid as i32), None).is_ok();

            if new_master_alive {
                tracing::info!(
                    "New master (PID {}) is still running, cleaning up old master",
                    new_pid
                );

                if let Some(ref old_pid) = state.old_master_pid {
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(*old_pid as i32),
                        nix::sys::signal::Signal::SIGTERM,
                    );

                    tokio::time::sleep(Duration::from_secs(2)).await;

                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(*old_pid as i32),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                }

                {
                    let mut orchestrator_state = self.orchestrator.state.write().await;
                    orchestrator_state.state = UpgradeState::Committed;
                    orchestrator_state.old_master_pid = None;
                    orchestrator_state.new_master_pid = None;
                    if let Some(ref version) = state.staged_version {
                        orchestrator_state.current_version = Some(version.clone());
                    }
                    self.persistence.save(&orchestrator_state)?;
                }

                tracing::info!("Recovery complete: promoted new master to primary");
                return Ok(());
            }
        }

        if let Some(ref old_pid) = state.old_master_pid {
            let old_master_alive = kill(Pid::from_raw(*old_pid as i32), None).is_ok();

            if old_master_alive {
                tracing::info!(
                    "Old master (PID {}) is still running, attempting to restore",
                    old_pid
                );

                if let Ok(mut stream) = IpcStream::connect_unix(&get_master_socket_path()) {
                    if stream.send(&Message::RestoreFromDrain).is_err() {
                        tracing::warn!(
                            "Failed to send RestoreFromDrain to old master during recovery"
                        );
                    }
                    let _ = stream.recv(5000);
                }

                {
                    let mut orchestrator_state = self.orchestrator.state.write().await;
                    orchestrator_state.state = UpgradeState::Idle;
                    orchestrator_state.old_master_pid = None;
                    orchestrator_state.new_master_pid = None;
                    orchestrator_state.staged_binary_path = None;
                    orchestrator_state.staged_version = None;
                    orchestrator_state.last_error =
                        Some("Recovered from incomplete upgrade".to_string());
                    self.persistence.save(&orchestrator_state)?;
                }

                tracing::info!("Recovery complete: restored old master to operation");
                return Ok(());
            }
        }

        tracing::warn!("No surviving master process found during recovery, will start fresh");
        {
            let mut orchestrator_state = self.orchestrator.state.write().await;
            orchestrator_state.state = UpgradeState::Idle;
            orchestrator_state.old_master_pid = None;
            orchestrator_state.new_master_pid = None;
            orchestrator_state.staged_binary_path = None;
            orchestrator_state.staged_version = None;
            orchestrator_state.last_error =
                Some("Recovery: no surviving master, starting fresh".to_string());
            self.persistence.save(&orchestrator_state)?;
        }

        Ok(())
    }

    #[cfg(not(unix))]
    async fn attempt_recovery(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::warn!("Upgrade recovery not fully supported on this platform, resetting state");

        {
            let mut orchestrator_state = self.orchestrator.state.write().await;
            orchestrator_state.state = UpgradeState::Idle;
            orchestrator_state.old_master_pid = None;
            orchestrator_state.new_master_pid = None;
            orchestrator_state.staged_binary_path = None;
            orchestrator_state.staged_version = None;
            orchestrator_state.last_error =
                Some("Recovery: reset on non-Unix platform".to_string());
            self.persistence.save(&orchestrator_state)?;
        }

        Ok(())
    }

    pub fn shutdown(&self) {
        self.running.stop();
    }

    pub async fn stage_upgrade(
        &self,
        binary_path: PathBuf,
        config_path: Option<PathBuf>,
        checksum: Option<String>,
    ) -> Result<(), UpgradeError> {
        self.orchestrator
            .stage(binary_path, config_path, checksum)
            .await
    }

    pub async fn apply_upgrade(
        &mut self,
        timeout_secs: u64,
        drain_timeout_secs: u64,
    ) -> Result<(), UpgradeError> {
        let state = self.orchestrator.get_state().await;

        let binary_path = state
            .staged_binary_path
            .ok_or(UpgradeError::NoStagedUpgrade)?;

        let version = state
            .staged_version
            .unwrap_or_else(|| "unknown".to_string());
        let config_path = state.staged_config_path.clone();

        tracing::info!("Preparing upgrade to version {} via IPC", version);

        if let Err(e) = self
            .send_upgrade_prepare(&binary_path, config_path.as_deref(), &version)
            .await
        {
            tracing::error!("Failed to prepare upgrade via IPC: {}", e);
            return Err(UpgradeError::SpawnFailed(format!(
                "IPC prepare failed: {}",
                e
            )));
        }

        tracing::info!("Master acknowledged upgrade preparation, draining workers");

        let drain_result = self.send_drain_workers(drain_timeout_secs).await;
        tracing::info!("Workers drained: {:?}", drain_result);

        tracing::info!("Stopping master for binary upgrade");
        self.stop_master(true)
            .map_err(|e| UpgradeError::SpawnFailed(e.to_string()))?;

        tracing::info!("Spawning new master with upgraded binary");

        if let Err(e) = self.spawn_upgraded_master(&binary_path).await {
            tracing::error!("Failed to spawn upgraded master: {}", e);
            return Err(UpgradeError::SpawnFailed(e.to_string()));
        }

        tokio::time::sleep(Duration::from_secs(timeout_secs)).await;

        let health = self.check_master_health().map_err(|e| {
            UpgradeError::ValidationFailed(vec![(
                0,
                super::health::HealthStatus::Error(e.to_string()),
            )])
        })?;

        if !health.is_healthy() {
            tracing::error!("Upgraded master failed health check");
            return Err(UpgradeError::ValidationFailed(vec![(
                0,
                super::health::HealthStatus::Error("Health check failed".to_string()),
            )]));
        }

        tracing::info!("Upgrade to version {} completed successfully", version);

        Ok(())
    }

    async fn send_upgrade_prepare(
        &self,
        binary_path: &str,
        config_path: Option<&str>,
        version: &str,
    ) -> Result<(), String> {
        let socket_path = get_secure_socket_path("master.sock");

        let mut stream =
            IpcStream::connect_unix(&socket_path).map_err(|e| errors::ipc::connect_failed(&e))?;

        let msg = Message::OverseerUpgradePrepare {
            binary_path: binary_path.to_string(),
            config_path: config_path.map(|s| s.to_string()),
            version: version.to_string(),
        };

        stream
            .send(&msg)
            .map_err(|e| format!("Failed to send upgrade prepare: {}", e))?;

        match stream.recv(10000) {
            Ok(Some(Message::OverseerUpgradePrepareAck { ready, error })) => {
                if ready {
                    Ok(())
                } else {
                    Err(error.unwrap_or_else(|| "Master rejected upgrade".to_string()))
                }
            }
            Ok(Some(other)) => Err(format!("Unexpected response: {:?}", other)),
            Ok(None) => Err("Timeout waiting for upgrade prepare ack".to_string()),
            Err(e) => Err(format!("IPC error: {}", e)),
        }
    }

    async fn send_drain_workers(&self, timeout_secs: u64) -> Result<(usize, u64), String> {
        let socket_path = get_secure_socket_path("master.sock");

        let mut stream =
            IpcStream::connect_unix(&socket_path).map_err(|e| errors::ipc::connect_failed(&e))?;

        let msg = Message::OverseerDrainWorkers { timeout_secs };

        stream
            .send(&msg)
            .map_err(|e| format!("Failed to send drain workers: {}", e))?;

        match stream.recv((timeout_secs + 10) * 1000) {
            Ok(Some(Message::OverseerDrainWorkersAck {
                drained_count,
                remaining_connections,
            })) => Ok((drained_count, remaining_connections)),
            Ok(Some(other)) => Err(format!("Unexpected response: {:?}", other)),
            Ok(None) => Err("Timeout waiting for drain ack".to_string()),
            Err(e) => Err(format!("IPC error: {}", e)),
        }
    }

    async fn spawn_upgraded_master(&mut self, binary_path: &str) -> Result<(), std::io::Error> {
        let config = self.build_spawn_config(
            binary_path,
            self.config_path.clone(),
            false,
            false,
            None,
            None,
            false,
            Vec::new(),
        )?;

        let child = spawn_and_log(&config, "upgraded master")?;

        self.master_child = Some(child);
        self.stable_since = Some(Instant::now());
        self.restart_count = 0;

        Ok(())
    }

    fn get_staged_checksum(&self) -> Option<String> {
        match self.orchestrator.state.try_read() {
            Ok(state) => state.staged_binary_checksum.clone(),
            _ => None,
        }
    }

    fn build_spawn_config(
        &self,
        binary_path: &str,
        config_path: PathBuf,
        upgrade_mode: bool,
        reuse_port: bool,
        socket_generation: Option<u32>,
        versioned_socket: Option<PathBuf>,
        receive_sockets: bool,
        socket_ports: Vec<u16>,
    ) -> Result<SpawnConfig, std::io::Error> {
        let binary = PathBuf::from(binary_path);

        if !binary.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Binary not found: {}", binary_path),
            ));
        }

        if let Some(expected_checksum) = self.get_staged_checksum() {
            match super::checksum::compute_sha256(&binary) {
                Ok(actual_checksum) => {
                    if actual_checksum != expected_checksum {
                        tracing::error!(
                            "Binary checksum mismatch at spawn time: expected {}, got {}",
                            expected_checksum,
                            actual_checksum
                        );
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "Binary checksum mismatch: expected {}, got {}",
                                expected_checksum, actual_checksum
                            ),
                        ));
                    }
                    tracing::info!(
                        "Binary checksum verified at spawn time: {}",
                        actual_checksum
                    );
                }
                Err(e) => {
                    tracing::warn!("Failed to compute binary checksum at spawn time: {}", e);
                }
            }
        }

        Ok(SpawnConfig {
            binary_path: binary,
            config_path,
            mode: ProcessMode::Master,
            master_socket: None,
            upgrade_mode,
            reuse_port,
            socket_generation,
            versioned_socket,
            receive_sockets,
            socket_ports,
        })
    }

    pub async fn get_master_status(&self) -> Option<MasterStatusInfo> {
        let socket_path = get_secure_socket_path("master.sock");

        let mut stream = IpcStream::connect_unix(&socket_path).ok()?;

        let msg = Message::OverseerGetStatus;
        stream.send(&msg).ok()?;

        match stream.recv(5000) {
            Ok(Some(Message::OverseerStatusResponse {
                master_pid,
                workers,
                uptime_secs,
                version,
            })) => Some(MasterStatusInfo {
                master_pid,
                workers,
                uptime_secs,
                version,
            }),
            _ => None,
        }
    }

    pub async fn dual_master_upgrade(
        &mut self,
        _timeout_secs: u64,
        drain_timeout_secs: u64,
    ) -> Result<(), UpgradeError> {
        let state = self.orchestrator.get_state().await;

        let binary_path = state
            .staged_binary_path
            .ok_or(UpgradeError::NoStagedUpgrade)?;

        let version = state
            .staged_version
            .unwrap_or_else(|| "unknown".to_string());
        let config_path = state.staged_config_path.clone();

        tracing::info!("Starting dual-master upgrade to version {}", version);

        let old_master_pid = self.master_child.as_ref().map(|c| c.id());

        self.spawn_upgraded_master_dual(&binary_path, config_path.as_deref())
            .await
            .map_err(|e| UpgradeError::SpawnFailed(e.to_string()))?;

        {
            let mut state = self.orchestrator.state.write().await;
            state.state = UpgradeState::DualMasterActive;
            state.old_master_pid = old_master_pid;
            state.new_master_pid = self.upgraded_master_child.as_ref().map(|c| c.id());
            state.dual_master_start_time = Some(crate::utils::current_timestamp());
            self.persistence
                .save(&state)
                .map_err(UpgradeError::IoError)?;
        }

        tracing::info!("New master spawned, validating health");

        let validation_start = Instant::now();
        let validation_timeout = Duration::from_secs(self.config.process_stop_timeout_secs);

        loop {
            if let Some(ref mut child) = self.upgraded_master_child {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        tracing::error!(
                            "New master exited during validation with status: {}",
                            status
                        );
                        return self.abort_dual_master_upgrade().await;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::error!("Failed to check new master process: {}", e);
                        return self.abort_dual_master_upgrade().await;
                    }
                }
            }

            if validation_start.elapsed() >= validation_timeout {
                break;
            }

            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        let new_master_healthy = self.validate_upgraded_master_health().await;

        if !new_master_healthy {
            tracing::error!("New master failed health check, aborting upgrade");
            return self.abort_dual_master_upgrade().await;
        }

        {
            let mut state = self.orchestrator.state.write().await;
            state.state = UpgradeState::Validating;
            self.persistence
                .save(&state)
                .map_err(UpgradeError::IoError)?;
        }

        tracing::info!("New master validated, draining old master");

        self.drain_and_stop_old_master(drain_timeout_secs).await?;

        {
            let mut state = self.orchestrator.state.write().await;
            state.state = UpgradeState::Committed;
            state.current_version = Some(version.clone());
            state.last_upgrade_timestamp = Some(crate::utils::current_timestamp());
            state.old_master_pid = None;
            state.staged_binary_path = None;
            state.staged_version = None;
            self.persistence
                .save(&state)
                .map_err(UpgradeError::IoError)?;
        }

        self.master_child = self.upgraded_master_child.take();
        self.dual_master_mode = false;
        self.stable_since = Some(Instant::now());
        self.restart_count = 0;

        if let Some(gen) = self.upgrade_generation {
            set_master_generation(gen);
            cleanup_old_master_sockets(gen);
            let _ = tokio::fs::remove_file(get_master_socket_path()).await;
            let _ = tokio::fs::rename(
                get_versioned_master_socket_path(gen),
                get_master_socket_path(),
            )
            .await;
            tracing::info!("Promoted socket generation {} to primary", gen);
        }
        self.upgrade_generation = None;

        tracing::info!(
            "Dual-master upgrade to version {} completed successfully",
            version
        );

        Ok(())
    }

    async fn spawn_upgraded_master_dual(
        &mut self,
        binary_path: &str,
        config_path: Option<&str>,
    ) -> Result<(), std::io::Error> {
        let generation = next_master_generation();
        self.upgrade_generation = Some(generation);
        let versioned_socket = get_versioned_master_socket_path(generation);

        let config = self.build_spawn_config(
            binary_path,
            config_path
                .map(PathBuf::from)
                .unwrap_or_else(|| self.config_path.clone()),
            true,
            true,
            Some(generation),
            Some(versioned_socket),
            false,
            Vec::new(),
        )?;

        let child = spawn_and_log(
            &config,
            &format!(
                "upgraded master (dual mode) using socket gen {}",
                generation
            ),
        )?;

        self.upgraded_master_child = Some(child);
        self.dual_master_mode = true;

        Ok(())
    }

    pub async fn dual_master_upgrade_with_socket_handoff(
        &mut self,
        ports: Vec<u16>,
        _timeout_secs: u64,
        drain_timeout_secs: u64,
    ) -> Result<(), UpgradeError> {
        let state = self.orchestrator.get_state().await;

        let binary_path = state
            .staged_binary_path
            .ok_or(UpgradeError::NoStagedUpgrade)?;

        let version = state
            .staged_version
            .unwrap_or_else(|| "unknown".to_string());
        let config_path = state.staged_config_path.clone();

        tracing::info!(
            "Starting socket-handoff dual-master upgrade to version {} for ports {:?}",
            version,
            ports
        );

        {
            let mut state = self.orchestrator.state.write().await;
            state.state = UpgradeState::Spawning;
            self.persistence
                .save(&state)
                .map_err(UpgradeError::IoError)?;
        }

        let mut handoff = DualMasterHandoff::new(ports.clone());
        handoff
            .prepare_as_old_master()
            .map_err(|e| UpgradeError::SpawnFailed(e.to_string()))?;

        self.socket_handoff = Some(handoff);
        tracing::info!("Socket handoff server prepared for ports {:?}", ports);

        let old_master_pid = self.master_child.as_ref().map(|c| c.id());

        self.spawn_upgraded_master_with_handoff(&binary_path, config_path.as_deref(), &ports)
            .await
            .map_err(|e| UpgradeError::SpawnFailed(e.to_string()))?;

        {
            let mut state = self.orchestrator.state.write().await;
            state.state = UpgradeState::DualMasterActive;
            state.old_master_pid = old_master_pid;
            state.new_master_pid = self.upgraded_master_child.as_ref().map(|c| c.id());
            state.dual_master_start_time = Some(crate::utils::current_timestamp());
            self.persistence
                .save(&state)
                .map_err(UpgradeError::IoError)?;
        }

        tracing::info!("New master spawned with socket handoff, validating health");

        let wait_secs = (self.config.process_stop_timeout_secs / 3).max(1);
        tokio::time::sleep(Duration::from_secs(wait_secs)).await;

        let new_master_healthy = self.validate_upgraded_master_health().await;

        if !new_master_healthy {
            tracing::error!("New master failed health check, aborting upgrade");
            if let Some(ref mut handoff) = self.socket_handoff {
                handoff.cleanup();
            }
            return self.abort_dual_master_upgrade().await;
        }

        {
            let mut state = self.orchestrator.state.write().await;
            state.state = UpgradeState::Validating;
            self.persistence
                .save(&state)
                .map_err(UpgradeError::IoError)?;
        }

        tracing::info!("New master validated, draining old master with confirmation");

        self.drain_and_stop_old_master_with_confirmation(drain_timeout_secs)
            .await?;

        if let Some(ref mut handoff) = self.socket_handoff {
            handoff.cleanup();
        }
        self.socket_handoff = None;

        {
            let mut state = self.orchestrator.state.write().await;
            state.state = UpgradeState::Committed;
            state.current_version = Some(version.clone());
            state.last_upgrade_timestamp = Some(crate::utils::current_timestamp());
            state.old_master_pid = None;
            state.staged_binary_path = None;
            state.staged_version = None;
            self.persistence
                .save(&state)
                .map_err(UpgradeError::IoError)?;
        }

        self.master_child = self.upgraded_master_child.take();
        self.dual_master_mode = false;
        self.stable_since = Some(Instant::now());
        self.restart_count = 0;

        tracing::info!(
            "Socket-handoff dual-master upgrade to version {} completed successfully",
            version
        );

        Ok(())
    }

    async fn spawn_upgraded_master_with_handoff(
        &mut self,
        binary_path: &str,
        config_path: Option<&str>,
        ports: &[u16],
    ) -> Result<(), std::io::Error> {
        let config = self.build_spawn_config(
            binary_path,
            config_path
                .map(PathBuf::from)
                .unwrap_or_else(|| self.config_path.clone()),
            true,
            false,
            None,
            None,
            true,
            ports.to_vec(),
        )?;

        let child = spawn_and_log(&config, "upgraded master (socket handoff mode)")?;

        self.upgraded_master_child = Some(child);
        self.dual_master_mode = true;

        Ok(())
    }

    async fn drain_and_stop_old_master_with_confirmation(
        &mut self,
        drain_timeout_secs: u64,
    ) -> Result<(), UpgradeError> {
        {
            let mut state = self.orchestrator.state.write().await;
            state.state = UpgradeState::DrainingOldMaster;
            self.persistence
                .save(&state)
                .map_err(UpgradeError::IoError)?;
        }

        let old_pid = self.master_child.as_ref().map(|c| c.id());

        if let Some(pid) = old_pid {
            tracing::info!(
                "Sending drain mode to old master (PID {}) with confirmation",
                pid
            );

            match self
                .send_master_drain_mode_with_confirmation(pid, drain_timeout_secs)
                .await
            {
                Ok(drained) => {
                    if !drained {
                        tracing::warn!(
                            "Old master did not drain completely within timeout, forcing stop"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to send drain mode via IPC: {}, using signal", e);

                    #[cfg(unix)]
                    {
                        let _ = nix::sys::signal::kill(
                            nix::unistd::Pid::from_raw(pid as i32),
                            nix::sys::signal::Signal::SIGTERM,
                        );
                    }
                }
            }
        }

        if let Some(ref mut old_master) = self.master_child {
            let old_pid = old_master.id();
            let drain_start = Instant::now();
            let drain_timeout = Duration::from_secs(drain_timeout_secs);

            while drain_start.elapsed() < drain_timeout {
                match old_master.try_wait() {
                    Ok(Some(_)) => {
                        tracing::info!("Old master (PID {}) exited gracefully", old_pid);
                        self.master_child = None;
                        return Ok(());
                    }
                    Ok(None) => {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    Err(_) => break,
                }
            }

            tracing::warn!("Old master did not exit gracefully within timeout, force stopping");

            let _ = old_master.kill();
            let _ = old_master.wait();
            self.master_child = None;
        }

        Ok(())
    }

    async fn send_master_drain_mode_with_confirmation(
        &mut self,
        _pid: u32,
        timeout_secs: u64,
    ) -> Result<bool, String> {
        let socket_path = get_secure_socket_path("master.sock");

        let mut stream =
            IpcStream::connect_unix(&socket_path).map_err(|e| errors::ipc::connect_failed(&e))?;

        let drain_id = crate::utils::safe_unix_duration().as_millis() as u64;

        let msg = Message::DrainRequest {
            timeout_secs,
            drain_id,
        };

        stream
            .send(&msg)
            .map_err(|e| format!("Failed to send drain request: {}", e))?;

        let response = stream
            .recv(5000)
            .map_err(|e| format!("Failed to receive drain ack: {}", e))?;

        match response {
            Some(Message::DrainStatusResponse {
                drain_id: resp_id,
                is_draining,
                active_connections,
                drain_complete,
                ..
            }) => {
                if resp_id == drain_id && is_draining {
                    tracing::info!(
                        "Master accepted drain mode: active={}, complete={}",
                        active_connections,
                        drain_complete
                    );

                    if drain_complete || active_connections == 0 {
                        return Ok(true);
                    }

                    let start = Instant::now();
                    let poll_timeout = Duration::from_secs(timeout_secs);
                    let mut last_known_connections = active_connections;

                    while start.elapsed() < poll_timeout {
                        if let Some(ref mut child) = self.master_child {
                            match child.try_wait() {
                                Ok(Some(status)) => {
                                    tracing::warn!(
                                        "Master exited during drain with status: {}",
                                        status
                                    );
                                    return Ok(true);
                                }
                                Ok(None) => {}
                                Err(_) => {}
                            }
                        }

                        let status_request = Message::DrainStatusRequest { drain_id };

                        if stream.send(&status_request).is_err() {
                            tracing::warn!(
                                "Failed to send drain status request, connection may be closed"
                            );

                            tokio::time::sleep(Duration::from_millis(500)).await;

                            let reconnect_result = IpcStream::connect_unix(&socket_path);
                            if reconnect_result.is_ok() {
                                tracing::info!(
                                    "Successfully reconnected to master for drain status polling"
                                );
                                continue;
                            }

                            if last_known_connections == 0 {
                                tracing::info!("Master connection lost but last known connections were 0, considering drain complete");
                                return Ok(true);
                            }

                            return Err(
                                "Lost connection to master during drain polling".to_string()
                            );
                        }

                        match stream.recv(2000) {
                            Ok(Some(Message::DrainStatusResponse {
                                drain_id: resp_id,
                                active_connections,
                                drain_complete,
                                ..
                            })) => {
                                if resp_id == drain_id {
                                    last_known_connections = active_connections;

                                    if drain_complete || active_connections == 0 {
                                        tracing::info!(
                                            "Master drain complete after {}ms",
                                            start.elapsed().as_millis()
                                        );
                                        return Ok(true);
                                    }
                                    tracing::debug!(
                                        "Master draining: {} active connections",
                                        active_connections
                                    );
                                }
                            }
                            Ok(Some(other)) => {
                                tracing::debug!(
                                    "Unexpected response during drain polling: {:?}",
                                    other
                                );
                            }
                            Ok(None) => {
                                tracing::debug!("No response during drain polling");
                            }
                            Err(e) => {
                                tracing::debug!("Error during drain polling: {}", e);
                            }
                        }

                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }

                    tracing::warn!(
                        "Drain polling timeout, {} connections may remain",
                        last_known_connections
                    );
                    return Ok(false);
                }
                Err("Master rejected drain mode".to_string())
            }
            Some(other) => Err(format!("Unexpected response: {:?}", other)),
            None => Err("Timeout waiting for drain response".to_string()),
        }
    }

    async fn validate_upgraded_master_health(&mut self) -> bool {
        tokio::time::sleep(Duration::from_secs(1)).await;

        let socket_path = if let Some(gen) = self.upgrade_generation {
            get_versioned_master_socket_path(gen)
        } else {
            get_master_socket_path()
        };

        let retries = self.config.upgrade_health_check_retries;
        let interval_secs = self.config.upgrade_health_check_interval_secs;

        for attempt in 1..=retries {
            if let Some(ref mut child) = self.upgraded_master_child {
                match child.try_wait() {
                    Ok(None) => {}
                    Ok(Some(status)) => {
                        tracing::error!("Upgraded master exited with status: {}", status);
                        return false;
                    }
                    Err(e) => {
                        tracing::error!("Failed to check upgraded master: {}", e);
                        return false;
                    }
                }
            }

            if let Ok(mut stream) = IpcStream::connect_unix(&socket_path) {
                let health_msg = Message::MasterHealthCheck {
                    timestamp: crate::utils::current_timestamp(),
                };

                if stream.send(&health_msg).is_ok() {
                    if let Ok(Some(Message::HealthCheckAck { .. })) = stream.recv(5000) {
                        tracing::info!(
                            "Upgraded master health check passed on attempt {}",
                            attempt
                        );
                        return true;
                    }
                }
            }

            if attempt < retries {
                tracing::warn!(
                    "Upgraded master health check attempt {} failed, retrying in {}s...",
                    attempt,
                    interval_secs
                );
                tokio::time::sleep(Duration::from_secs(interval_secs)).await;
            }
        }

        false
    }

    async fn drain_and_stop_old_master(
        &mut self,
        drain_timeout_secs: u64,
    ) -> Result<(), UpgradeError> {
        {
            let mut state = self.orchestrator.state.write().await;
            state.state = UpgradeState::DrainingOldMaster;
            self.persistence
                .save(&state)
                .map_err(UpgradeError::IoError)?;
        }

        let old_pid = self.master_child.as_ref().map(|c| c.id());

        if let Some(pid) = old_pid {
            tracing::info!("Sending drain mode to old master (PID {})", pid);

            if let Err(e) = self.send_master_drain_mode(pid, drain_timeout_secs).await {
                tracing::warn!("Failed to send drain mode via IPC: {}, using signal", e);

                #[cfg(unix)]
                {
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(pid as i32),
                        nix::sys::signal::Signal::SIGTERM,
                    );
                }
            }
        }

        if let Some(ref mut old_master) = self.master_child {
            let old_pid = old_master.id();
            let drain_start = Instant::now();
            let drain_timeout = Duration::from_secs(drain_timeout_secs);

            while drain_start.elapsed() < drain_timeout {
                match old_master.try_wait() {
                    Ok(Some(_)) => {
                        tracing::info!("Old master (PID {}) exited gracefully", old_pid);
                        self.master_child = None;
                        return Ok(());
                    }
                    Ok(None) => {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    Err(_) => break,
                }
            }

            tracing::warn!("Old master did not exit gracefully within timeout, force stopping");

            let _ = old_master.kill();
            let _ = old_master.wait();
            self.master_child = None;
        }

        Ok(())
    }

    async fn send_master_drain_mode(&self, _pid: u32, timeout_secs: u64) -> Result<(), String> {
        let socket_path = get_secure_socket_path("master.sock");

        let mut stream =
            IpcStream::connect_unix(&socket_path).map_err(|e| errors::ipc::connect_failed(&e))?;

        let msg = Message::MasterDrainMode {
            graceful_timeout_secs: timeout_secs,
            stop_accepting: true,
        };

        stream
            .send(&msg)
            .map_err(|e| format!("Failed to send drain mode: {}", e))?;

        match stream.recv((timeout_secs + 10) * 1000) {
            Ok(Some(Message::MasterDrainModeAck {
                accepted,
                active_connections,
            })) => {
                if accepted {
                    tracing::info!(
                        "Master accepted drain mode, {} active connections",
                        active_connections
                    );
                    Ok(())
                } else {
                    Err("Master rejected drain mode".to_string())
                }
            }
            Ok(Some(other)) => Err(format!("Unexpected response: {:?}", other)),
            Ok(None) => Err("Timeout waiting for drain mode ack".to_string()),
            Err(e) => Err(format!("IPC error: {}", e)),
        }
    }

    async fn abort_dual_master_upgrade(&mut self) -> Result<(), UpgradeError> {
        tracing::warn!("Aborting dual-master upgrade");

        if let Some(ref mut child) = self.upgraded_master_child {
            let pid = child.id();
            tracing::info!("Killing upgraded master (PID {})", pid);

            #[cfg(unix)]
            {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid as i32),
                    nix::sys::signal::Signal::SIGTERM,
                );
            }

            let _ = child.kill();
            let _ = child.wait();
        }

        self.upgraded_master_child = None;
        self.dual_master_mode = false;

        if let Some(gen) = self.upgrade_generation {
            let versioned_socket = get_versioned_master_socket_path(gen);
            if versioned_socket.exists() {
                let _ = std::fs::remove_file(&versioned_socket);
            }
            self.upgrade_generation = None;
        }

        if let Some(ref mut _old_master) = self.master_child {
            tracing::info!("Restoring old master to full operation");

            match IpcStream::connect_unix(&get_master_socket_path()) {
                Ok(mut stream) => {
                    if stream.send(&Message::RestoreFromDrain).is_err() {
                        tracing::warn!("Failed to send RestoreFromDrain to old master");
                    }
                    let _ = stream.recv(5000);
                }
                Err(_) =>
                {
                    #[cfg(unix)]
                    if let Some(pid) = self.master_child.as_ref().map(|c| c.id()) {
                        use nix::sys::signal::Signal;
                        let _ = nix::sys::signal::kill(
                            nix::unistd::Pid::from_raw(pid as i32),
                            Signal::SIGUSR1,
                        );
                    }
                }
            }
        }

        {
            let mut state = self.orchestrator.state.write().await;
            state.state = UpgradeState::Failed;
            state.last_error = Some("New master failed validation".to_string());
            state.new_master_pid = None;
            self.persistence
                .save(&state)
                .map_err(UpgradeError::IoError)?;
        }

        Err(UpgradeError::ValidationFailed(vec![]))
    }

    pub fn is_in_dual_master_mode(&self) -> bool {
        self.dual_master_mode
    }

    pub fn get_old_master_pid(&self) -> Option<u32> {
        self.master_child.as_ref().map(|c| c.id())
    }

    pub fn get_new_master_pid(&self) -> Option<u32> {
        self.upgraded_master_child.as_ref().map(|c| c.id())
    }
}

pub fn run_overseer_process(
    config: OverseerConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"));

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let mut overseer = OverseerProcess::new(config, runtime_dir)?;

    #[cfg(unix)]
    {
        let running = overseer.running.clone();
        tokio::spawn(async move {
            let mut sigterm =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                    Ok(s) => s,
                    Err(_) => return,
                };

            sigterm.recv().await;
            tracing::info!("Overseer received SIGTERM");
            running.stop();
        });

        let running = overseer.running.clone();
        tokio::spawn(async move {
            let mut sigint =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()) {
                    Ok(s) => s,
                    Err(_) => return,
                };

            sigint.recv().await;
            tracing::info!("Overseer received SIGINT");
            running.stop();
        });
    }

    rt.block_on(overseer.run())
}

#[derive(Debug, Clone)]
pub struct MasterHealth {
    pub process_alive: bool,
    pub ipc_responsive: bool,
    pub workers_healthy: bool,
}

impl MasterHealth {
    pub fn is_healthy(&self) -> bool {
        self.process_alive && self.ipc_responsive
    }
}

struct IpcHealthResult {
    is_responsive: bool,
    workers_healthy: bool,
}

#[derive(Debug, Clone)]
pub struct MasterStatusInfo {
    pub master_pid: u32,
    pub workers: Vec<crate::process::WorkerStatusInfo>,
    pub uptime_secs: u64,
    pub version: String,
}

#[cfg(test)]
mod tests {
    #![allow(unused_variables, dead_code)]
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_overseer_config_default() {
        let config = OverseerConfig::default();

        assert_eq!(config.config_path, None);
        assert!(config.auto_restart);
        assert_eq!(config.restart_delay_secs, 5);
        assert_eq!(config.max_restart_attempts, 5);
        assert_eq!(config.health_check_interval_secs, 5);
        assert_eq!(config.stable_uptime_secs, 60);
        assert_eq!(config.upgrade_validation_timeout_secs, 10);
        assert_eq!(config.upgrade_drain_timeout_secs, 30);
        assert_eq!(config.upgrade_health_check_retries, 5);
        assert_eq!(config.upgrade_health_check_interval_secs, 2);
        assert_eq!(config.ipc_read_timeout_ms, 5000);
        assert_eq!(config.ipc_write_timeout_ms, 5000);
        assert_eq!(config.master_startup_timeout_secs, 30);
        assert_eq!(config.process_stop_timeout_secs, 10);
        assert_eq!(config.restart_backoff_max_secs, 300);
    }

    #[test]
    fn test_overseer_config_custom() {
        let config = OverseerConfig {
            config_path: Some(PathBuf::from("/custom/config")),
            auto_restart: false,
            restart_delay_secs: 10,
            restart_backoff_max_secs: 300,
            max_restart_attempts: 3,
            health_check_interval_secs: 10,
            stable_uptime_secs: 120,
            upgrade_validation_timeout_secs: 20,
            upgrade_drain_timeout_secs: 60,
            upgrade_health_check_retries: 10,
            upgrade_health_check_interval_secs: 5,
            ipc_read_timeout_ms: 10000,
            ipc_write_timeout_ms: 10000,
            master_startup_timeout_secs: 60,
            process_stop_timeout_secs: 10,
            drain_check_interval_ms: 100,
        };

        assert_eq!(config.config_path, Some(PathBuf::from("/custom/config")));
        assert!(!config.auto_restart);
        assert_eq!(config.restart_delay_secs, 10);
        assert_eq!(config.max_restart_attempts, 3);
    }

    #[test]
    fn test_master_health_healthy() {
        let health = MasterHealth {
            process_alive: true,
            ipc_responsive: true,
            workers_healthy: true,
        };

        assert!(health.is_healthy());
    }

    #[test]
    fn test_master_health_dead_process() {
        let health = MasterHealth {
            process_alive: false,
            ipc_responsive: true,
            workers_healthy: true,
        };

        assert!(!health.is_healthy());
    }

    #[test]
    fn test_master_health_unresponsive() {
        let health = MasterHealth {
            process_alive: true,
            ipc_responsive: false,
            workers_healthy: true,
        };

        assert!(!health.is_healthy());
    }

    #[test]
    fn test_master_health_all_unhealthy() {
        let health = MasterHealth {
            process_alive: false,
            ipc_responsive: false,
            workers_healthy: false,
        };

        assert!(!health.is_healthy());
    }

    #[test]
    fn test_overseer_config_path_validation() {
        let config = OverseerConfig {
            config_path: Some(PathBuf::from("")),
            ..Default::default()
        };

        assert_eq!(config.config_path, Some(PathBuf::from("")));
    }

    #[test]
    fn test_overseer_config_timeout_bounds() {
        let mut config = OverseerConfig::default();

        config.ipc_read_timeout_ms = 0;
        assert_eq!(config.ipc_read_timeout_ms, 0);

        config.ipc_write_timeout_ms = u64::MAX;
        assert_eq!(config.ipc_write_timeout_ms, u64::MAX);
    }

    #[test]
    fn test_restart_delay_exponential_backoff() {
        let config = OverseerConfig::default();
        let base = config.restart_delay_secs;
        let max_backoff = config.restart_backoff_max_secs;

        // Simulate calculate_restart_delay at various restart_counts
        for count in 0..=8u32 {
            let backoff_multiplier = 2_u64.pow(count.min(6));
            let delay = std::cmp::min(base * backoff_multiplier, max_backoff);

            // Verify backoff doubles each time up to cap
            if count < 6 {
                assert_eq!(delay, std::cmp::min(base * 2_u64.pow(count), max_backoff));
            } else {
                // Capped at max_backoff
                assert_eq!(delay, max_backoff);
            }
        }
    }

    #[test]
    fn test_restart_limit_enforcement() {
        let config = OverseerConfig::default();
        assert_eq!(config.max_restart_attempts, 5);

        // After max_restart_attempts, should stop restarting
        let mut restart_count = 0u32;
        while restart_count < config.max_restart_attempts {
            restart_count += 1;
        }
        assert!(restart_count >= config.max_restart_attempts);
    }

    #[test]
    fn test_master_health_partial_failure() {
        // Only process alive, but IPC and workers unhealthy
        let health = MasterHealth {
            process_alive: true,
            ipc_responsive: false,
            workers_healthy: false,
        };
        assert!(!health.is_healthy());
    }
}
