use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use utoipa::ToSchema;

use crate::tls::TlsConfig;
use crate::validation::ConfigValidationError;

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
    pub const fn process_stop_timeout() -> u64 {
        10
    }
    pub const fn drain_poll_interval() -> u64 {
        100
    }
    pub const fn min_workers() -> usize {
        2
    }
    pub const fn max_workers() -> usize {
        16
    }
    pub const fn unified_server_workers() -> usize {
        1
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

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct OverseerConfig {
    #[serde(default, skip_deserializing)]
    pub config_path: Option<PathBuf>,
    #[serde(default = "default_true")]
    pub auto_restart: bool,
    #[serde(default = "default_restart_delay")]
    pub restart_delay_secs: u64,
    #[serde(default = "default_restart_backoff_max")]
    pub restart_backoff_max_secs: u64,
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
    #[serde(default = "default_process_stop_timeout")]
    pub process_stop_timeout_secs: u64,
    #[serde(default = "default_drain_poll_interval")]
    pub drain_check_interval_ms: u64,
}

impl Default for OverseerConfig {
    fn default() -> Self {
        Self {
            config_path: None,
            auto_restart: true,
            restart_delay_secs: 5,
            restart_backoff_max_secs: 300,
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
            process_stop_timeout_secs: 10,
            drain_check_interval_ms: 100,
        }
    }
}

fn default_control_api_addr() -> String {
    "127.0.0.1:50051".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct ProcessManagerConfig {
    #[serde(default = "default_min_workers")]
    pub min_workers: usize,
    #[serde(default = "default_max_workers")]
    pub max_workers: usize,
    #[serde(default = "default_unified_server_workers")]
    pub unified_server_workers: usize,
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
    #[serde(default = "default_control_api_addr")]
    pub control_api_addr: String,
    #[serde(default)]
    pub control_api_tls: Option<TlsConfig>,
}

impl Default for ProcessManagerConfig {
    fn default() -> Self {
        Self {
            min_workers: 2,
            max_workers: 16,
            unified_server_workers: 1,
            max_restart_attempts: 5,
            restart_cooldown_secs: 60,
            restart_backoff_max_secs: 300,
            heartbeat_timeout_secs: 30,
            graceful_shutdown_timeout_secs: 30,
            worker_port_base: 9000,
            pre_spawn_workers: 0,
            warm_workers_target: 2,
            health_check_interval_secs: 5,
            control_api_addr: default_control_api_addr(),
            control_api_tls: None,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
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
    #[serde(default = "default_control_api_addr")]
    pub control_api_addr: String,
    #[serde(default)]
    pub control_api_tls: Option<TlsConfig>,
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
            control_api_addr: default_control_api_addr(),
            control_api_tls: None,
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

    /// Validating constructor: fails closed instead of producing an
    /// invalid config that would only fail at runtime.
    pub fn try_build(self) -> Result<SupervisorConfig, ConfigValidationError> {
        self.config.validate()?;
        Ok(self.config)
    }
}

/// Hard process/IPC/resource bounds (Phase 41).
///
/// - `MAX_WORKERS` bounds the legacy worker pool (`min_workers`,
///   `max_workers`, `pre_spawn_workers`, `warm_workers_target`). 1024 keeps
///   `worker_port_base + max_workers` inside the u16 port range for the
///   default base and keeps per-worker FD/process counts operable.
/// - `MAX_UNIFIED_SERVER_WORKERS` bounds the `UnifiedServerWorker` data-plane
///   pool independently. 256 keeps the derived shared-memory capacities
///   (`(unified + 10) * 2048` connection slots) to a few megabytes and keeps
///   process spawn counts operable. It is intentionally independent of
///   `max_workers`: the two pools are separate capacities in
///   `synvoid-ipc` (`workers` vs `unified_server_workers`), so no
///   `unified_server_workers <= max_workers` invariant is enforced.
/// - `MAX_RESTART_ATTEMPTS` bounds restart counters against accidental
///   infinite-restart configuration.
pub const MAX_WORKERS: usize = 1024;
/// Independent hard maximum for the unified data-plane pool.
pub const MAX_UNIFIED_SERVER_WORKERS: usize = 256;
pub const MAX_RESTART_ATTEMPTS: u32 = 1000;
/// Upper bound for second-granularity timeouts (24h). Prevents accidental
/// zero/infinite durations where the runtime assumes a sane interval.
pub const MAX_TIMEOUT_SECS: u64 = 86_400;
/// Upper bound for millisecond-granularity IPC timeouts (1h).
pub const MAX_TIMEOUT_MS: u64 = 3_600_000;

fn invalid(field: &str, message: impl Into<String>) -> ConfigValidationError {
    ConfigValidationError {
        field: field.to_string(),
        message: message.into(),
    }
}

fn validate_timeout_secs(field: &str, value: u64) -> Result<(), ConfigValidationError> {
    if value == 0 {
        return Err(invalid(
            field,
            "timeout must be nonzero; zero has no defined runtime meaning",
        ));
    }
    if value > MAX_TIMEOUT_SECS {
        return Err(invalid(
            field,
            format!("timeout {value}s exceeds maximum {MAX_TIMEOUT_SECS}s"),
        ));
    }
    Ok(())
}

fn validate_timeout_ms(field: &str, value: u64) -> Result<(), ConfigValidationError> {
    if value == 0 {
        return Err(invalid(
            field,
            "timeout must be nonzero; zero has no defined runtime meaning",
        ));
    }
    if value > MAX_TIMEOUT_MS {
        return Err(invalid(
            field,
            format!("timeout {value}ms exceeds maximum {MAX_TIMEOUT_MS}ms"),
        ));
    }
    Ok(())
}

fn validate_control_api_addr(field: &str, addr: &str) -> Result<(), ConfigValidationError> {
    if addr.is_empty() {
        return Err(invalid(field, "control API address must not be empty"));
    }
    if addr.parse::<std::net::SocketAddr>().is_err() {
        return Err(invalid(
            field,
            format!("control API address '{addr}' must parse as host:port SocketAddr"),
        ));
    }
    Ok(())
}

impl ProcessManagerConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.min_workers == 0 {
            return Err(invalid(
                "process_manager.min_workers",
                "min_workers must be nonzero",
            ));
        }
        if self.max_workers == 0 {
            return Err(invalid(
                "process_manager.max_workers",
                "max_workers must be nonzero",
            ));
        }
        if self.max_workers > MAX_WORKERS {
            return Err(invalid(
                "process_manager.max_workers",
                format!("max_workers exceeds hard maximum {MAX_WORKERS}"),
            ));
        }
        if self.min_workers > self.max_workers {
            return Err(invalid(
                "process_manager.min_workers",
                format!(
                    "min_workers ({}) must not exceed max_workers ({})",
                    self.min_workers, self.max_workers
                ),
            ));
        }
        if self.unified_server_workers == 0 {
            return Err(invalid(
                "process_manager.unified_server_workers",
                "unified_server_workers must be nonzero; zero spawns no data plane",
            ));
        }
        if self.unified_server_workers > MAX_UNIFIED_SERVER_WORKERS {
            return Err(invalid(
                "process_manager.unified_server_workers",
                format!("unified_server_workers exceeds hard maximum {MAX_UNIFIED_SERVER_WORKERS}"),
            ));
        }
        // Warm/pre-spawn targets belong to the legacy worker pool governed by
        // max_workers (see `ensure_warm_workers`: `pre_spawn.max(min)` feeds
        // `spawn_worker`). They must not exceed that owning capacity.
        if self.pre_spawn_workers > self.max_workers {
            return Err(invalid(
                "process_manager.pre_spawn_workers",
                format!(
                    "pre_spawn_workers ({}) must not exceed max_workers ({})",
                    self.pre_spawn_workers, self.max_workers
                ),
            ));
        }
        if self.warm_workers_target > self.max_workers {
            return Err(invalid(
                "process_manager.warm_workers_target",
                format!(
                    "warm_workers_target ({}) must not exceed max_workers ({})",
                    self.warm_workers_target, self.max_workers
                ),
            ));
        }
        if self.max_restart_attempts > MAX_RESTART_ATTEMPTS {
            return Err(invalid(
                "process_manager.max_restart_attempts",
                format!("max_restart_attempts exceeds hard maximum {MAX_RESTART_ATTEMPTS}"),
            ));
        }
        validate_timeout_secs(
            "process_manager.restart_cooldown_secs",
            self.restart_cooldown_secs,
        )?;
        validate_timeout_secs(
            "process_manager.restart_backoff_max_secs",
            self.restart_backoff_max_secs,
        )?;
        if self.restart_backoff_max_secs < self.restart_cooldown_secs {
            return Err(invalid(
                "process_manager.restart_backoff_max_secs",
                format!(
                    "restart_backoff_max_secs ({}) must be >= restart_cooldown_secs ({})",
                    self.restart_backoff_max_secs, self.restart_cooldown_secs
                ),
            ));
        }
        validate_timeout_secs(
            "process_manager.heartbeat_timeout_secs",
            self.heartbeat_timeout_secs,
        )?;
        validate_timeout_secs(
            "process_manager.graceful_shutdown_timeout_secs",
            self.graceful_shutdown_timeout_secs,
        )?;
        validate_timeout_secs(
            "process_manager.health_check_interval_secs",
            self.health_check_interval_secs,
        )?;
        validate_control_api_addr("process_manager.control_api_addr", &self.control_api_addr)?;
        // Legacy worker ports derive as `worker_port_base + worker_id`.
        // Keep the configured capacity inside the u16 port range.
        let port_end = self.worker_port_base as usize + self.max_workers;
        if port_end > u16::MAX as usize {
            return Err(invalid(
                "process_manager.worker_port_base",
                format!(
                    "worker_port_base ({}) + max_workers ({}) exceeds u16 port range",
                    self.worker_port_base, self.max_workers
                ),
            ));
        }
        if let Some(ref tls) = self.control_api_tls {
            tls.validate()?;
        }
        Ok(())
    }
}

impl SupervisorConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.min_workers == 0 {
            return Err(invalid(
                "supervisor.min_workers",
                "min_workers must be nonzero",
            ));
        }
        if self.max_workers == 0 {
            return Err(invalid(
                "supervisor.max_workers",
                "max_workers must be nonzero",
            ));
        }
        if self.max_workers > MAX_WORKERS {
            return Err(invalid(
                "supervisor.max_workers",
                format!("max_workers exceeds hard maximum {MAX_WORKERS}"),
            ));
        }
        if self.min_workers > self.max_workers {
            return Err(invalid(
                "supervisor.min_workers",
                format!(
                    "min_workers ({}) must not exceed max_workers ({})",
                    self.min_workers, self.max_workers
                ),
            ));
        }
        if !(0.0 < self.scale_up_threshold && self.scale_up_threshold < 1.0) {
            return Err(invalid(
                "supervisor.scale_up_threshold",
                "scale_up_threshold must be in (0, 1)",
            ));
        }
        if !(0.0 < self.scale_down_threshold && self.scale_down_threshold < 1.0) {
            return Err(invalid(
                "supervisor.scale_down_threshold",
                "scale_down_threshold must be in (0, 1)",
            ));
        }
        if self.scale_down_threshold >= self.scale_up_threshold {
            return Err(invalid(
                "supervisor.scale_down_threshold",
                format!(
                    "scale_down_threshold ({}) must be < scale_up_threshold ({})",
                    self.scale_down_threshold, self.scale_up_threshold
                ),
            ));
        }
        validate_timeout_secs(
            "supervisor.scale_up_cooldown_secs",
            self.scale_up_cooldown_secs,
        )?;
        validate_timeout_secs(
            "supervisor.scale_down_cooldown_secs",
            self.scale_down_cooldown_secs,
        )?;
        if self.max_restart_attempts > MAX_RESTART_ATTEMPTS {
            return Err(invalid(
                "supervisor.max_restart_attempts",
                format!("max_restart_attempts exceeds hard maximum {MAX_RESTART_ATTEMPTS}"),
            ));
        }
        validate_timeout_secs(
            "supervisor.restart_cooldown_secs",
            self.restart_cooldown_secs,
        )?;
        validate_timeout_secs(
            "supervisor.health_check_interval_secs",
            self.health_check_interval_secs,
        )?;
        validate_timeout_secs(
            "supervisor.graceful_shutdown_timeout_secs",
            self.graceful_shutdown_timeout_secs,
        )?;
        validate_control_api_addr("supervisor.control_api_addr", &self.control_api_addr)?;
        if let Some(ref tls) = self.control_api_tls {
            tls.validate()?;
        }
        Ok(())
    }
}

impl OverseerConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        validate_timeout_secs("overseer.restart_delay_secs", self.restart_delay_secs)?;
        validate_timeout_secs(
            "overseer.restart_backoff_max_secs",
            self.restart_backoff_max_secs,
        )?;
        if self.restart_backoff_max_secs < self.restart_delay_secs {
            return Err(invalid(
                "overseer.restart_backoff_max_secs",
                format!(
                    "restart_backoff_max_secs ({}) must be >= restart_delay_secs ({})",
                    self.restart_backoff_max_secs, self.restart_delay_secs
                ),
            ));
        }
        if self.max_restart_attempts > MAX_RESTART_ATTEMPTS {
            return Err(invalid(
                "overseer.max_restart_attempts",
                format!("max_restart_attempts exceeds hard maximum {MAX_RESTART_ATTEMPTS}"),
            ));
        }
        validate_timeout_secs(
            "overseer.health_check_interval_secs",
            self.health_check_interval_secs,
        )?;
        validate_timeout_secs("overseer.stable_uptime_secs", self.stable_uptime_secs)?;
        validate_timeout_secs(
            "overseer.upgrade_validation_timeout_secs",
            self.upgrade_validation_timeout_secs,
        )?;
        validate_timeout_secs(
            "overseer.upgrade_drain_timeout_secs",
            self.upgrade_drain_timeout_secs,
        )?;
        if self.upgrade_health_check_retries > 10_000 {
            return Err(invalid(
                "overseer.upgrade_health_check_retries",
                "upgrade_health_check_retries exceeds hard maximum 10000",
            ));
        }
        validate_timeout_secs(
            "overseer.upgrade_health_check_interval_secs",
            self.upgrade_health_check_interval_secs,
        )?;
        validate_timeout_ms("overseer.ipc_read_timeout_ms", self.ipc_read_timeout_ms)?;
        validate_timeout_ms("overseer.ipc_write_timeout_ms", self.ipc_write_timeout_ms)?;
        validate_timeout_secs(
            "overseer.master_startup_timeout_secs",
            self.master_startup_timeout_secs,
        )?;
        validate_timeout_secs(
            "overseer.process_stop_timeout_secs",
            self.process_stop_timeout_secs,
        )?;
        validate_timeout_ms(
            "overseer.drain_check_interval_ms",
            self.drain_check_interval_ms,
        )?;
        Ok(())
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
fn default_process_stop_timeout() -> u64 {
    Defaults::process_stop_timeout()
}
fn default_drain_poll_interval() -> u64 {
    Defaults::drain_poll_interval()
}
fn default_min_workers() -> usize {
    Defaults::min_workers()
}
fn default_max_workers() -> usize {
    Defaults::max_workers()
}
fn default_unified_server_workers() -> usize {
    Defaults::unified_server_workers()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate() {
        ProcessManagerConfig::default()
            .validate()
            .expect("default process manager must validate");
        SupervisorConfig::default()
            .validate()
            .expect("default supervisor must validate");
        OverseerConfig::default()
            .validate()
            .expect("default overseer must validate");
    }

    #[test]
    fn rejects_zero_and_overflow_counts_without_panic() {
        let mut cfg = ProcessManagerConfig::default();
        cfg.unified_server_workers = 0;
        assert!(cfg.validate().is_err());

        let mut cfg = ProcessManagerConfig::default();
        cfg.unified_server_workers = usize::MAX;
        assert!(cfg.validate().is_err());

        let mut cfg = ProcessManagerConfig::default();
        cfg.min_workers = 0;
        assert!(cfg.validate().is_err());

        let mut cfg = ProcessManagerConfig::default();
        cfg.max_workers = usize::MAX;
        assert!(cfg.validate().is_err());

        let mut cfg = ProcessManagerConfig::default();
        cfg.min_workers = 8;
        cfg.max_workers = 2;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn warm_and_prespawn_bounded_by_max_workers() {
        let mut cfg = ProcessManagerConfig::default();
        cfg.max_workers = 4;
        cfg.min_workers = 2;
        cfg.pre_spawn_workers = 5;
        assert!(cfg.validate().is_err());

        let mut cfg = ProcessManagerConfig::default();
        cfg.max_workers = 4;
        cfg.min_workers = 2;
        cfg.warm_workers_target = 5;
        assert!(cfg.validate().is_err());

        // Unified pool is independent: exceeding max_workers is allowed.
        let mut cfg = ProcessManagerConfig::default();
        cfg.max_workers = 4;
        cfg.min_workers = 2;
        cfg.unified_server_workers = 16;
        cfg.pre_spawn_workers = 0;
        cfg.warm_workers_target = 0;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn unified_workers_hard_maximum() {
        let mut cfg = ProcessManagerConfig::default();
        cfg.unified_server_workers = MAX_UNIFIED_SERVER_WORKERS;
        assert!(cfg.validate().is_ok());
        cfg.unified_server_workers = MAX_UNIFIED_SERVER_WORKERS + 1;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn restart_and_timeout_relationships() {
        let mut cfg = ProcessManagerConfig::default();
        cfg.restart_backoff_max_secs = cfg.restart_cooldown_secs - 1;
        assert!(cfg.validate().is_err());

        let mut cfg = ProcessManagerConfig::default();
        cfg.heartbeat_timeout_secs = 0;
        assert!(cfg.validate().is_err());

        let mut cfg = ProcessManagerConfig::default();
        cfg.control_api_addr = "not-a-socket-addr".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn supervisor_scale_thresholds() {
        let mut cfg = SupervisorConfig::default();
        cfg.scale_down_threshold = 0.9;
        cfg.scale_up_threshold = 0.8;
        assert!(cfg.validate().is_err());

        let mut cfg = SupervisorConfig::default();
        cfg.scale_up_threshold = 0.0;
        assert!(cfg.validate().is_err());

        assert!(SupervisorConfig::builder().try_build().is_ok());
        assert!(SupervisorConfig::builder()
            .min_workers(10)
            .max_workers(2)
            .try_build()
            .is_err());
    }

    #[test]
    fn worker_port_base_capacity() {
        let mut cfg = ProcessManagerConfig::default();
        cfg.worker_port_base = u16::MAX;
        cfg.max_workers = 16;
        assert!(cfg.validate().is_err());
    }
}
