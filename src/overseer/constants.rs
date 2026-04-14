pub mod timeouts {
    pub const DEFAULT_IPC_READ_MS: u64 = 5000;
    pub const DEFAULT_IPC_WRITE_MS: u64 = 5000;
    pub const MASTER_STARTUP_TIMEOUT_SECS: u64 = 30;
    pub const HEALTH_CHECK_INTERVAL_SECS: u64 = 5;
    pub const DRAIN_POLL_INTERVAL_MS: u64 = 100;
    pub const UPGRADE_VALIDATION_TIMEOUT_SECS: u64 = 10;
    pub const UPGRADE_DRAIN_TIMEOUT_SECS: u64 = 30;
    pub const WORKER_READY_TIMEOUT_SECS: u64 = 30;
    pub const POST_UPGRADE_MONITORING_INTERVAL_SECS: u64 = 5;
    pub const ROLLBACK_TIMEOUT_SECS: u64 = 30;
}

pub mod restart {
    pub const DEFAULT_RESTART_DELAY_SECS: u64 = 5;
    pub const DEFAULT_MAX_RESTART_ATTEMPTS: u32 = 5;
    pub const DEFAULT_STABLE_UPTIME_SECS: u64 = 60;
    pub const MAX_RESTART_DELAY_SECS: u64 = 300;
}

pub mod upgrade {
    pub const DEFAULT_HEALTH_CHECK_RETRIES: u32 = 3;
    pub const DEFAULT_HEALTH_CHECK_INTERVAL_SECS: u64 = 2;
    pub const DEFAULT_UPGRADE_HEALTH_CHECK_RETRIES: u32 = 5;
    pub const DEFAULT_UPGRADE_HEALTH_CHECK_INTERVAL_SECS: u64 = 2;
    pub const MIN_SAMPLE_REQUESTS: usize = 5;
    pub const LATENCY_THRESHOLD_MS: u64 = 1000;
    pub const ERROR_RATE_THRESHOLD: f64 = 0.1;
    pub const LATENCY_DEGRADATION_THRESHOLD_PERCENT: f64 = 50.0;
}

pub mod drain {
    pub const GRACEFUL_STOP_TIMEOUT_SECS: u64 = 30;
    pub const POLL_INTERVAL_MS: u64 = 100;
    pub const RECONNECT_DELAY_MS: u64 = 500;
}
