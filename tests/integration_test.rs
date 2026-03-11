use std::path::PathBuf;
use std::time::Duration;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_message_types() {
        use maluwaf::process::{ErrorCode, ErrorSeverity, Message, WorkerId};

        let worker_started = Message::WorkerStarted {
            id: WorkerId(1),
            pid: 1234,
            port: 8080,
            timestamp: 1234567890,
        };

        assert!(matches!(worker_started, Message::WorkerStarted { .. }));

        let worker_ready = Message::WorkerReady { id: WorkerId(1) };
        assert!(matches!(worker_ready, Message::WorkerReady { .. }));

        let worker_error = Message::WorkerError {
            id: WorkerId(1),
            error: "test error".to_string(),
            severity: ErrorSeverity::Warning,
            error_code: ErrorCode::Unknown,
        };
        assert!(matches!(worker_error, Message::WorkerError { .. }));
    }

    #[test]
    fn test_worker_id_serialization() {
        use maluwaf::process::WorkerId;

        let id = WorkerId(42);
        assert_eq!(id.as_usize(), 42);
    }

    #[test]
    fn test_overseer_config_serialization() {
        use maluwaf::overseer::process::OverseerConfig;

        let config = OverseerConfig {
            config_path: PathBuf::from("/test/config"),
            auto_restart: true,
            restart_delay_secs: 10,
            max_restart_attempts: 3,
            health_check_interval_secs: 5,
            stable_uptime_secs: 120,
            upgrade_validation_timeout_secs: 15,
            upgrade_drain_timeout_secs: 45,
            upgrade_health_check_retries: 3,
            upgrade_health_check_interval_secs: 2,
            ipc_read_timeout_ms: 3000,
            ipc_write_timeout_ms: 3000,
            master_startup_timeout_secs: 30,
        };

        assert_eq!(config.restart_delay_secs, 10);
        assert_eq!(config.max_restart_attempts, 3);
    }

    #[test]
    fn test_drain_state_transitions() {
        use maluwaf::worker::drain_state::WorkerDrainState;

        let state = WorkerDrainState::new();

        assert!(!state.is_draining());

        state.start_drain(1);
        assert!(state.is_draining());

        let drain_id_value = state.get_drain_id();
        assert!(drain_id_value > 0);
    }

    #[test]
    fn test_master_health_check() {
        use maluwaf::overseer::process::MasterHealth;

        let healthy = MasterHealth {
            process_alive: true,
            ipc_responsive: true,
            workers_healthy: true,
        };

        assert!(healthy.is_healthy());

        let unhealthy = MasterHealth {
            process_alive: false,
            ipc_responsive: false,
            workers_healthy: false,
        };

        assert!(!unhealthy.is_healthy());
    }

    #[test]
    fn test_ipc_socket_path_generation() {
        use maluwaf::process::socket_path::{
            get_master_socket_path, get_versioned_master_socket_path,
        };

        let socket_path = get_master_socket_path();
        assert!(socket_path.to_string_lossy().contains("master"));

        let versioned = get_versioned_master_socket_path(1);
        assert!(versioned.to_string_lossy().contains("master"));
        assert!(versioned.to_string_lossy().contains("1"));
    }

    #[test]
    fn test_process_manager_config() {
        use maluwaf::process::manager::ProcessManagerConfig;

        let config = ProcessManagerConfig {
            min_workers: 2,
            max_workers: 4,
            max_restart_attempts: 3,
            restart_cooldown_secs: 2,
            restart_backoff_max_secs: 30,
            heartbeat_timeout_secs: 30,
            graceful_shutdown_timeout_secs: 60,
            worker_port_base: 8000,
            config_path: PathBuf::from("/test/config"),
            master_socket_path: PathBuf::from("/test/socket"),
            log_level: Some("info".to_string()),
            pre_spawn_workers: 1,
            warm_workers_target: 2,
            health_check_interval_secs: 5,
            ipc_session_key: None,
            ipc_enforce_signing: false,
            ipc_rate_limit: Default::default(),
        };

        assert_eq!(config.min_workers, 2);
        assert_eq!(config.max_workers, 4);
    }
}
