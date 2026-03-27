use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use utoipa::ToSchema;

pub struct Defaults;

impl Defaults {
    pub const fn true_() -> bool {
        true
    }
    pub const fn restart_delay() -> u64 {
        5
    }
    pub const fn max_restart_attempts() -> u32 {
        5
    }
    pub const fn health_check_interval() -> u64 {
        5
    }
    pub const fn stable_uptime() -> u64 {
        60
    }
    pub const fn upgrade_validation_timeout() -> u64 {
        10
    }
    pub const fn upgrade_drain_timeout() -> u64 {
        30
    }
    pub const fn upgrade_health_check_retries() -> u32 {
        5
    }
    pub const fn upgrade_health_check_interval() -> u64 {
        2
    }
    pub const fn ipc_read_timeout() -> u64 {
        5000
    }
    pub const fn ipc_write_timeout() -> u64 {
        5000
    }
    pub const fn master_startup_timeout() -> u64 {
        30
    }
    pub const fn min_workers() -> usize {
        2
    }
    pub const fn max_workers() -> usize {
        16
    }
    pub const fn restart_cooldown() -> u64 {
        60
    }
    pub const fn restart_backoff_max() -> u64 {
        300
    }
    pub const fn heartbeat_timeout() -> u64 {
        30
    }
    pub const fn graceful_shutdown_timeout() -> u64 {
        30
    }
    pub const fn worker_port_base() -> u16 {
        9000
    }
    pub const fn pre_spawn_workers() -> usize {
        0
    }
    pub const fn warm_workers_target() -> usize {
        2
    }
    pub const fn scale_up_threshold() -> f64 {
        0.8
    }
    pub const fn scale_down_threshold() -> f64 {
        0.2
    }
    pub const fn scale_up_cooldown() -> u64 {
        30
    }
    pub const fn scale_down_cooldown() -> u64 {
        60
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, ToSchema)]
pub struct OverseerConfig {
    #[serde(default, skip_deserializing)]
    pub config_path: Option<PathBuf>,
    #[serde(default = "default_true")]
    pub auto_restart: bool,
    #[serde(default = "default_restart_delay")]
    pub restart_delay_secs: u64,
    #[serde(default = "default_max_restart_attempts")]
    pub max_restart_attempts: u32,
    #[serde(default = "default_health_check_interval")]
    pub health_check_interval_secs: u64,
    #[serde(default = "default_stable_uptime")]
    pub stable_uptime_secs: u64,
    #[serde(default = "default_upgrade_validation_timeout")]
    pub upgrade_validation_timeout_secs: u64,
    #[serde(default = "default_upgrade_drain_timeout")]
    pub upgrade_drain_timeout_secs: u64,
    #[serde(default = "default_upgrade_health_check_retries")]
    pub upgrade_health_check_retries: u32,
    #[serde(default = "default_upgrade_health_check_interval")]
    pub upgrade_health_check_interval_secs: u64,
    #[serde(default = "default_ipc_read_timeout")]
    pub ipc_read_timeout_ms: u64,
    #[serde(default = "default_ipc_write_timeout")]
    pub ipc_write_timeout_ms: u64,
    #[serde(default = "default_master_startup_timeout")]
    pub master_startup_timeout_secs: u64,
}

impl Default for OverseerConfig {
    fn default() -> Self {
        Self {
            config_path: None,
            auto_restart: true,
            restart_delay_secs: 5,
            max_restart_attempts: 5,
            health_check_interval_secs: 5,
            stable_uptime_secs: 60,
            upgrade_validation_timeout_secs: 10,
            upgrade_drain_timeout_secs: 30,
            upgrade_health_check_retries: 5,
            upgrade_health_check_interval_secs: 2,
            ipc_read_timeout_ms: 5000,
            ipc_write_timeout_ms: 5000,
            master_startup_timeout_secs: 30,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, ToSchema)]
pub struct ProcessManagerConfig {
    #[serde(default = "default_min_workers")]
    pub min_workers: usize,
    #[serde(default = "default_max_workers")]
    pub max_workers: usize,
    #[serde(default = "default_max_restart_attempts")]
    pub max_restart_attempts: u32,
    #[serde(default = "default_restart_cooldown")]
    pub restart_cooldown_secs: u64,
    #[serde(default = "default_restart_backoff_max")]
    pub restart_backoff_max_secs: u64,
    #[serde(default = "default_heartbeat_timeout")]
    pub heartbeat_timeout_secs: u64,
    #[serde(default = "default_graceful_shutdown_timeout")]
    pub graceful_shutdown_timeout_secs: u64,
    #[serde(default = "default_worker_port_base")]
    pub worker_port_base: u16,
    #[serde(default = "default_pre_spawn_workers")]
    pub pre_spawn_workers: usize,
    #[serde(default = "default_warm_workers_target")]
    pub warm_workers_target: usize,
    #[serde(default = "default_health_check_interval")]
    pub health_check_interval_secs: u64,
}

impl Default for ProcessManagerConfig {
    fn default() -> Self {
        Self {
            min_workers: 2,
            max_workers: 16,
            max_restart_attempts: 5,
            restart_cooldown_secs: 60,
            restart_backoff_max_secs: 300,
            heartbeat_timeout_secs: 30,
            graceful_shutdown_timeout_secs: 30,
            worker_port_base: 9000,
            pre_spawn_workers: 0,
            warm_workers_target: 2,
            health_check_interval_secs: 5,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, ToSchema)]
pub struct SupervisorConfig {
    #[serde(default = "default_min_workers")]
    pub min_workers: usize,
    #[serde(default = "default_max_workers")]
    pub max_workers: usize,
    #[serde(default = "default_scale_up_threshold")]
    pub scale_up_threshold: f64,
    #[serde(default = "default_scale_down_threshold")]
    pub scale_down_threshold: f64,
    #[serde(default = "default_scale_up_cooldown")]
    pub scale_up_cooldown_secs: u64,
    #[serde(default = "default_scale_down_cooldown")]
    pub scale_down_cooldown_secs: u64,
    #[serde(default = "default_max_restart_attempts")]
    pub max_restart_attempts: u32,
    #[serde(default = "default_restart_cooldown")]
    pub restart_cooldown_secs: u64,
    #[serde(default = "default_health_check_interval")]
    pub health_check_interval_secs: u64,
    #[serde(default = "default_graceful_shutdown_timeout")]
    pub graceful_shutdown_timeout_secs: u64,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            min_workers: 2,
            max_workers: 16,
            scale_up_threshold: 0.8,
            scale_down_threshold: 0.2,
            scale_up_cooldown_secs: 30,
            scale_down_cooldown_secs: 60,
            max_restart_attempts: 5,
            restart_cooldown_secs: 300,
            health_check_interval_secs: 5,
            graceful_shutdown_timeout_secs: 30,
        }
    }
}

impl SupervisorConfig {
    pub fn builder() -> SupervisorConfigBuilder {
        SupervisorConfigBuilder::new()
    }
}

pub struct SupervisorConfigBuilder {
    config: SupervisorConfig,
}

impl SupervisorConfigBuilder {
    fn new() -> Self {
        Self {
            config: SupervisorConfig::default(),
        }
    }

    pub fn min_workers(mut self, min_workers: usize) -> Self {
        self.config.min_workers = min_workers;
        self
    }

    pub fn max_workers(mut self, max_workers: usize) -> Self {
        self.config.max_workers = max_workers;
        self
    }

    pub fn scale_up_threshold(mut self, threshold: f64) -> Self {
        self.config.scale_up_threshold = threshold;
        self
    }

    pub fn scale_down_threshold(mut self, threshold: f64) -> Self {
        self.config.scale_down_threshold = threshold;
        self
    }

    pub fn scale_up_cooldown_secs(mut self, secs: u64) -> Self {
        self.config.scale_up_cooldown_secs = secs;
        self
    }

    pub fn scale_down_cooldown_secs(mut self, secs: u64) -> Self {
        self.config.scale_down_cooldown_secs = secs;
        self
    }

    pub fn max_restart_attempts(mut self, attempts: u32) -> Self {
        self.config.max_restart_attempts = attempts;
        self
    }

    pub fn restart_cooldown_secs(mut self, secs: u64) -> Self {
        self.config.restart_cooldown_secs = secs;
        self
    }

    pub fn health_check_interval_secs(mut self, secs: u64) -> Self {
        self.config.health_check_interval_secs = secs;
        self
    }

    pub fn graceful_shutdown_timeout_secs(mut self, secs: u64) -> Self {
        self.config.graceful_shutdown_timeout_secs = secs;
        self
    }

    pub fn build(self) -> SupervisorConfig {
        self.config
    }
}

use super::defaults::default_true;
fn default_restart_delay() -> u64 {
    Defaults::restart_delay()
}
fn default_max_restart_attempts() -> u32 {
    Defaults::max_restart_attempts()
}
fn default_health_check_interval() -> u64 {
    Defaults::health_check_interval()
}
fn default_stable_uptime() -> u64 {
    Defaults::stable_uptime()
}
fn default_upgrade_validation_timeout() -> u64 {
    Defaults::upgrade_validation_timeout()
}
fn default_upgrade_drain_timeout() -> u64 {
    Defaults::upgrade_drain_timeout()
}
fn default_upgrade_health_check_retries() -> u32 {
    Defaults::upgrade_health_check_retries()
}
fn default_upgrade_health_check_interval() -> u64 {
    Defaults::upgrade_health_check_interval()
}
fn default_ipc_read_timeout() -> u64 {
    Defaults::ipc_read_timeout()
}
fn default_ipc_write_timeout() -> u64 {
    Defaults::ipc_write_timeout()
}
fn default_master_startup_timeout() -> u64 {
    Defaults::master_startup_timeout()
}
fn default_min_workers() -> usize {
    Defaults::min_workers()
}
fn default_max_workers() -> usize {
    Defaults::max_workers()
}
fn default_restart_cooldown() -> u64 {
    Defaults::restart_cooldown()
}
fn default_restart_backoff_max() -> u64 {
    Defaults::restart_backoff_max()
}
fn default_heartbeat_timeout() -> u64 {
    Defaults::heartbeat_timeout()
}
fn default_graceful_shutdown_timeout() -> u64 {
    Defaults::graceful_shutdown_timeout()
}
fn default_worker_port_base() -> u16 {
    Defaults::worker_port_base()
}
fn default_pre_spawn_workers() -> usize {
    Defaults::pre_spawn_workers()
}
fn default_warm_workers_target() -> usize {
    Defaults::warm_workers_target()
}
fn default_scale_up_threshold() -> f64 {
    Defaults::scale_up_threshold()
}
fn default_scale_down_threshold() -> f64 {
    Defaults::scale_down_threshold()
}
fn default_scale_up_cooldown() -> u64 {
    Defaults::scale_up_cooldown()
}
fn default_scale_down_cooldown() -> u64 {
    Defaults::scale_down_cooldown()
}
