#[cfg(unix)]
mod process_lifecycle_tests {
    use synvoid::process::ipc::{
        ErrorCode, ErrorSeverity, Message, MessageCategory, ThreatIndicatorType,
        ThreatSeverityLevel, UpgradeModePayload, WorkerId,
    };
    use synvoid::process::IpcEndpoint;

    #[test]
    fn test_worker_id_display() {
        let id = WorkerId(42);
        assert_eq!(format!("{}", id), "42");
    }

    #[test]
    fn test_worker_id_equality() {
        let id1 = WorkerId(1);
        let id2 = WorkerId(2);
        let id3 = WorkerId(1);

        assert!(id1 == id3);
        assert!(id1 != id2);
    }

    #[test]
    fn test_ipc_endpoint_socket_path() {
        let endpoint = IpcEndpoint::new("test-worker");
        let path = endpoint.socket_path();

        let path_str = path.to_string_lossy();
        assert!(path_str.contains("test-worker"));
        assert!(path_str.contains("synvoid"));
    }

    #[test]
    fn test_message_is_lifecycle_worker() {
        let started = Message::WorkerStarted {
            id: WorkerId(0),
            pid: 1234,
            port: 8080,
            timestamp: 0,
        };
        let ready = Message::WorkerReady { id: WorkerId(0) };
        let heartbeat = Message::WorkerHeartbeat {
            id: WorkerId(0),
            timestamp: 0,
            metrics: Default::default(),
        };
        let shutdown = Message::WorkerShutdownComplete { id: WorkerId(0) };

        assert!(started.is_lifecycle());
        assert!(ready.is_lifecycle());
        assert!(heartbeat.is_lifecycle());
        assert!(shutdown.is_lifecycle());
    }

    #[test]
    fn test_message_is_lifecycle_cpu_worker() {
        let started = Message::CpuWorkerStarted {
            worker_id: 0,
            pid: 1234,
        };
        let ready = Message::CpuWorkerReady { worker_id: 0 };
        let heartbeat = Message::CpuWorkerHeartbeat {
            worker_id: 0,
            timestamp: 0,
            static_cache_hits: 0,
            static_cache_misses: 0,
            cpu_offload_stats: Default::default(),
        };
        let shutdown = Message::CpuWorkerShutdownComplete { worker_id: 0 };

        assert!(started.is_lifecycle());
        assert!(ready.is_lifecycle());
        assert!(heartbeat.is_lifecycle());
        assert!(shutdown.is_lifecycle());
    }

    #[test]
    fn test_message_is_lifecycle_unified_server() {
        let started = Message::UnifiedServerWorkerStarted {
            id: WorkerId(0),
            pid: 1234,
            timestamp: 0,
        };
        let ready = Message::UnifiedServerWorkerReady { id: WorkerId(0) };
        let heartbeat = Message::UnifiedServerWorkerHeartbeat {
            id: WorkerId(0),
            timestamp: 0,
            metrics: Default::default(),
        };
        let shutdown = Message::UnifiedServerWorkerShutdownComplete { id: WorkerId(0) };

        assert!(started.is_lifecycle());
        assert!(ready.is_lifecycle());
        assert!(heartbeat.is_lifecycle());
        assert!(shutdown.is_lifecycle());
    }

    #[test]
    fn test_message_is_drain_worker_drain() {
        let drain = Message::WorkerDrain {
            id: WorkerId(0),
            timeout_secs: 30,
        };
        let drained = Message::WorkerDrained {
            id: WorkerId(0),
            remaining_connections: 0,
        };
        let drain_complete = Message::WorkerDrainComplete {
            id: WorkerId(0),
            connections_handled: 100,
        };

        assert!(drain.is_drain());
        assert!(drained.is_drain());
        assert!(drain_complete.is_drain());
    }

    #[test]
    fn test_message_is_drain_master_drain() {
        let drain_mode = Message::MasterDrainMode {
            graceful_timeout_secs: 30,
            stop_accepting: true,
        };
        let stop_accepting = Message::MasterStopAccepting {};
        let drain_status = Message::MasterDrainStatus {
            is_draining: true,
            active_connections: 5,
            drain_elapsed_secs: 15,
        };

        assert!(drain_mode.is_drain());
        assert!(stop_accepting.is_drain());
        assert!(drain_status.is_drain());
    }

    #[test]
    fn test_message_is_drain_drain_protocol() {
        let drain_req = Message::DrainRequest {
            timeout_secs: 30,
            drain_id: 12345,
        };
        let drain_status = Message::DrainStatusRequest { drain_id: 12345 };
        let drain_complete = Message::DrainComplete {
            drain_id: 12345,
            worker_id: WorkerId(0),
            connections_drained: 15,
        };
        let stop_accepting = Message::StopAccepting { drain_id: 999 };
        let restore = Message::RestoreFromDrain;

        assert!(drain_req.is_drain());
        assert!(drain_status.is_drain());
        assert!(drain_complete.is_drain());
        assert!(stop_accepting.is_drain());
        assert!(restore.is_drain());
    }

    #[test]
    fn test_message_not_drain_non_drain_messages() {
        let msg = Message::MasterConfigReload {
            config_path: "/etc/synvoid/config.toml".to_string(),
        };

        assert!(!msg.is_drain());
    }

    #[test]
    fn test_message_not_lifecycle_upgrade_messages() {
        let upgrade_ready = Message::UpgradeReady {
            mode: UpgradeModePayload::ReusePort,
            new_worker_ids: vec![WorkerId(0)],
        };
        let upgrade_failed = Message::UpgradeFailed {
            error: "test error".to_string(),
        };

        assert!(!upgrade_ready.is_lifecycle());
        assert!(!upgrade_failed.is_lifecycle());
    }

    #[test]
    fn test_message_not_lifecycle_threat_intel_messages() {
        let announce = Message::ThreatIndicatorAnnounce {
            worker_id: 0,
            threat_type: ThreatIndicatorType::IpBlock,
            indicator_value: "1.2.3.4".to_string(),
            severity: ThreatSeverityLevel::High,
            reason: "test".to_string(),
            ttl_seconds: 3600,
            site_scope: "global".to_string(),
            rate_limit_requests: None,
            rate_limit_window_secs: None,
            suspicious_pattern: None,
        };

        assert!(!announce.is_lifecycle());
    }

    #[test]
    fn test_worker_lifecycle_category() {
        let started = Message::WorkerStarted {
            id: WorkerId(0),
            pid: 1234,
            port: 8080,
            timestamp: 0,
        };
        assert_eq!(started.category(), MessageCategory::WorkerLifecycle);

        let error = Message::WorkerError {
            id: WorkerId(0),
            error: "test".to_string(),
            severity: ErrorSeverity::Error,
            error_code: ErrorCode::Unknown,
        };
        assert_eq!(error.category(), MessageCategory::WorkerLifecycle);
    }

    #[test]
    fn test_cpu_worker_category() {
        let started = Message::CpuWorkerStarted {
            worker_id: 0,
            pid: 1234,
        };
        assert_eq!(started.category(), MessageCategory::CpuWorker);
    }

    #[test]
    fn test_unified_server_category() {
        let started = Message::UnifiedServerWorkerStarted {
            id: WorkerId(0),
            pid: 1234,
            timestamp: 0,
        };
        assert_eq!(started.category(), MessageCategory::UnifiedServer);
    }

    #[test]
    fn test_app_server_category() {
        let started = Message::AppServerStarted {
            id: WorkerId(0),
            site_id: "test".to_string(),
            socket_path: None,
            pid: 1234,
            timestamp: 0,
        };
        assert_eq!(started.category(), MessageCategory::AppServer);
    }

    #[test]
    fn test_upgrade_category() {
        let upgrade_ready = Message::UpgradeReady {
            mode: UpgradeModePayload::ReusePort,
            new_worker_ids: vec![],
        };
        assert_eq!(upgrade_ready.category(), MessageCategory::Upgrade);
    }

    #[test]
    fn test_master_command_category() {
        let shutdown = Message::MasterShutdown {
            graceful: true,
            timeout_secs: 30,
        };
        assert_eq!(shutdown.category(), MessageCategory::SupervisorCommand);

        let resize = Message::MasterResizeThreadpool { worker_threads: 4 };
        assert_eq!(resize.category(), MessageCategory::SupervisorCommand);
    }

    #[test]
    fn test_worker_drain_category() {
        let drain = Message::WorkerDrain {
            id: WorkerId(0),
            timeout_secs: 30,
        };
        assert_eq!(drain.category(), MessageCategory::WorkerDrain);
    }

    #[test]
    fn test_master_drain_category() {
        let drain_mode = Message::MasterDrainMode {
            graceful_timeout_secs: 30,
            stop_accepting: true,
        };
        assert_eq!(drain_mode.category(), MessageCategory::MasterDrain);
    }

    #[test]
    fn test_drain_protocol_category() {
        let drain_req = Message::DrainRequest {
            timeout_secs: 30,
            drain_id: 123,
        };
        assert_eq!(drain_req.category(), MessageCategory::DrainProtocol);
    }

    #[test]
    fn test_threat_intel_category() {
        let announce = Message::ThreatIndicatorAnnounce {
            worker_id: 0,
            threat_type: ThreatIndicatorType::IpBlock,
            indicator_value: "1.2.3.4".to_string(),
            severity: ThreatSeverityLevel::High,
            reason: "test".to_string(),
            ttl_seconds: 3600,
            site_scope: "global".to_string(),
            rate_limit_requests: None,
            rate_limit_window_secs: None,
            suspicious_pattern: None,
        };
        assert_eq!(announce.category(), MessageCategory::ThreatIntel);
    }

    #[test]
    fn test_blocklist_rules_category() {
        let update = Message::BlocklistUpdate {
            blocks: vec![],
            mesh_blocks: vec![],
            version: 1,
        };
        assert_eq!(update.category(), MessageCategory::BlocklistRules);
    }

    #[test]
    fn test_cpu_worker_task_category() {
        let minify_req = Message::MinifyRequest {
            request_id: 123,
            site_id: "test".to_string(),
            path: "/test.css".to_string(),
            encoding: None,
        };
        assert_eq!(minify_req.category(), MessageCategory::CpuWorker);
    }

    #[test]
    fn test_overseer_category() {
        let drain_workers = Message::SupervisorDrainWorkers { timeout_secs: 30 };
        assert_eq!(drain_workers.category(), MessageCategory::Supervisor);

        let get_status = Message::SupervisorGetStatus;
        assert_eq!(get_status.category(), MessageCategory::Supervisor);
    }

    #[test]
    fn test_socket_handoff_category() {
        let request = Message::SocketHandoffRequest {
            socket_path: "/tmp/test.sock".to_string(),
        };
        assert_eq!(request.category(), MessageCategory::SocketHandoff);
    }

    #[test]
    fn test_worker_restart_category() {
        let request = Message::RestartWorkerRequest { id: WorkerId(0) };
        assert_eq!(request.category(), MessageCategory::WorkerRestart);
    }

    #[test]
    fn test_plugin_category() {
        let sync = Message::PluginStateSync {
            plugin_name: "test".to_string(),
            wasm_module_data: vec![],
        };
        assert_eq!(sync.category(), MessageCategory::Plugin);
    }

    #[test]
    fn test_worker_error_serde() {
        let error = Message::WorkerError {
            id: WorkerId(1),
            error: "connection timeout".to_string(),
            severity: ErrorSeverity::Error,
            error_code: ErrorCode::Timeout,
        };

        let json = serde_json::to_string(&error).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();

        match decoded {
            Message::WorkerError {
                id,
                error,
                severity,
                error_code,
            } => {
                assert_eq!(id, WorkerId(1));
                assert_eq!(error, "connection timeout");
                assert_eq!(severity, ErrorSeverity::Error);
                assert_eq!(error_code, ErrorCode::Timeout);
            }
            _ => panic!("Expected WorkerError"),
        }
    }

    #[test]
    fn test_error_severity_display() {
        assert_eq!(format!("{}", ErrorSeverity::Warning), "warning");
        assert_eq!(format!("{}", ErrorSeverity::Error), "error");
        assert_eq!(format!("{}", ErrorSeverity::Critical), "critical");
    }

    #[test]
    fn test_error_code_display() {
        assert_eq!(format!("{}", ErrorCode::Unknown), "unknown");
        assert_eq!(format!("{}", ErrorCode::WorkerPanic), "worker_panic");
        assert_eq!(format!("{}", ErrorCode::Timeout), "timeout");
        assert_eq!(
            format!("{}", ErrorCode::AuthenticationFailed),
            "authentication_failed"
        );
    }

    #[test]
    fn test_health_check_ack_roundtrip() {
        let ack = Message::HealthCheckAck { timestamp: 9999999 };
        let json = serde_json::to_string(&ack).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            decoded,
            Message::HealthCheckAck { timestamp: 9999999 }
        ));
    }

    #[test]
    fn test_worker_resize_ack_roundtrip() {
        let ack = Message::WorkerResizeAck {
            id: WorkerId(5),
            worker_threads: 8,
        };
        let json = serde_json::to_string(&ack).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            decoded,
            Message::WorkerResizeAck {
                id: WorkerId(5),
                worker_threads: 8,
            }
        ));
    }
}
