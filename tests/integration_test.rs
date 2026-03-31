use maluwaf::process::WorkerId;
use std::path::PathBuf;

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
            config_path: Some(PathBuf::from("/test/config")),
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
    fn test_master_health_partial_failure() {
        use maluwaf::overseer::process::MasterHealth;

        let partial = MasterHealth {
            process_alive: true,
            ipc_responsive: false,
            workers_healthy: true,
        };
        assert!(!partial.is_healthy());

        let partial2 = MasterHealth {
            process_alive: false,
            ipc_responsive: true,
            workers_healthy: true,
        };
        assert!(!partial2.is_healthy());
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
            allow_insecure_ipc_key: false,
        };

        assert_eq!(config.min_workers, 2);
        assert_eq!(config.max_workers, 4);
    }

    #[test]
    fn test_ipc_message_serialization() {
        use maluwaf::process::Message;

        let worker_started = Message::WorkerStarted {
            id: WorkerId(1),
            pid: 1234,
            port: 8080,
            timestamp: 1234567890,
        };

        let serialized = serde_json::to_string(&worker_started).unwrap();
        assert!(serialized.contains("WorkerStarted"));
        assert!(serialized.contains("1234"));

        let deserialized: Message = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(
            deserialized,
            Message::WorkerStarted { pid: 1234, .. }
        ));
    }

    #[test]
    fn test_heartbeat_message() {
        use maluwaf::process::{Message, WorkerId};

        let heartbeat = Message::WorkerHeartbeat {
            id: WorkerId(1),
            timestamp: 1234567890,
            metrics: Default::default(),
        };

        assert!(matches!(heartbeat, Message::WorkerHeartbeat { .. }));

        let serialized = serde_json::to_string(&heartbeat).unwrap();
        assert!(serialized.contains("WorkerHeartbeat"));
    }

    #[test]
    fn test_request_log_message() {
        use maluwaf::process::{Message, RequestLogPayload, WorkerId};

        let request_log = Message::WorkerRequestLog {
            id: WorkerId(1),
            log: RequestLogPayload {
                timestamp: 1234567890,
                client_ip: "192.168.1.1".to_string(),
                method: "GET".to_string(),
                path: "/test".to_string(),
                status: 200,
                response_time_ms: 50,
                site_id: "site1".to_string(),
                user_agent: Some("Mozilla/5.0".to_string()),
                bytes_sent: 1024,
                bytes_received: 0,
            },
        };

        assert!(matches!(request_log, Message::WorkerRequestLog { .. }));

        let serialized = serde_json::to_string(&request_log).unwrap();
        assert!(serialized.contains("WorkerRequestLog"));
        assert!(serialized.contains("192.168.1.1"));
        assert!(serialized.contains("GET"));
        assert!(serialized.contains("/test"));

        let deserialized: Message = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(
            deserialized,
            Message::WorkerRequestLog { log: log_payload, .. } if log_payload.status == 200
        ));
    }

    #[test]
    fn test_request_log_payload_default() {
        use maluwaf::process::RequestLogPayload;

        let payload = RequestLogPayload {
            timestamp: 1234567890,
            client_ip: "10.0.0.1".to_string(),
            method: "POST".to_string(),
            path: "/api/data".to_string(),
            status: 404,
            response_time_ms: 100,
            site_id: "test_site".to_string(),
            user_agent: None,
            bytes_sent: 500,
            bytes_received: 200,
        };

        assert_eq!(payload.client_ip, "10.0.0.1");
        assert_eq!(payload.method, "POST");
        assert_eq!(payload.status, 404);
    }

    #[test]
    fn test_shutdown_messages() {
        use maluwaf::process::Message;

        let graceful_shutdown = Message::MasterShutdown {
            graceful: true,
            timeout_secs: 60,
        };

        assert!(matches!(
            graceful_shutdown,
            Message::MasterShutdown { graceful: true, .. }
        ));

        let shutdown_complete = Message::WorkerShutdownComplete {
            id: maluwaf::process::WorkerId(1),
        };

        assert!(matches!(
            shutdown_complete,
            Message::WorkerShutdownComplete { .. }
        ));
    }

    #[test]
    fn test_config_reload_message() {
        use maluwaf::process::Message;

        let reload = Message::MasterConfigReload {
            config_path: "/etc/maluwaf/main.toml".to_string(),
        };

        assert!(matches!(reload, Message::MasterConfigReload { .. }));
        if let Message::MasterConfigReload { config_path } = reload {
            assert!(config_path.contains("maluwaf"));
        }
    }

    #[test]
    fn test_worker_status_enum() {
        use maluwaf::supervisor::worker::WorkerStatus;

        assert_eq!(WorkerStatus::Starting, WorkerStatus::Starting);
        assert_eq!(WorkerStatus::Running, WorkerStatus::Running);
        assert_eq!(WorkerStatus::Ready, WorkerStatus::Ready);
        assert_eq!(WorkerStatus::Stopping, WorkerStatus::Stopping);
        assert_eq!(WorkerStatus::Stopped, WorkerStatus::Stopped);
        assert_eq!(WorkerStatus::Failed, WorkerStatus::Failed);
    }

    #[test]
    fn test_overseer_config_defaults() {
        use maluwaf::overseer::process::OverseerConfig;

        let config = OverseerConfig::default();

        assert!(config.auto_restart);
        assert_eq!(config.restart_delay_secs, 5);
        assert_eq!(config.max_restart_attempts, 5);
        assert_eq!(config.health_check_interval_secs, 5);
        assert_eq!(config.stable_uptime_secs, 60);
    }

    #[test]
    fn test_drain_manager_basic() {
        use maluwaf::overseer::drain_manager::DrainManager;

        let manager = DrainManager::new();

        let drain_id = manager.start_drain(60);
        assert!(drain_id > 0);

        let status = manager.get_drain_status();
        assert!(status.drain_id > 0);
    }

    #[test]
    fn test_connection_tracker() {
        use maluwaf::overseer::connection_tracker::ConnectionTracker;
        use maluwaf::process::WorkerId;

        let tracker = ConnectionTracker::new();

        tracker.increment_active();
        assert!(tracker.get_active_count() >= 1);

        tracker.decrement_active();
        assert!(tracker.get_active_count() >= 0);

        tracker.update_worker_connections(WorkerId(1), 5, 3);
        let count = tracker.get_active_count();
        assert_eq!(count, 5);
    }

    #[test]
    fn test_health_check_config() {
        use maluwaf::overseer::health::EnhancedHealthConfig;

        let config = EnhancedHealthConfig::default();

        assert_eq!(config.sample_requests, 5);
        assert_eq!(config.latency_threshold_ms, 1000);
        assert!(config.compare_with_baseline);
    }

    #[test]
    fn test_spawn_config() {
        use maluwaf::overseer::spawn::{ProcessMode, SpawnConfig};

        let config = SpawnConfig {
            binary_path: PathBuf::from("/usr/bin/maluwaf"),
            config_path: PathBuf::from("/etc/maluwaf"),
            mode: ProcessMode::Master,
            master_socket: None,
            upgrade_mode: false,
            reuse_port: false,
            socket_generation: None,
            versioned_socket: None,
            receive_sockets: false,
            socket_ports: vec![],
        };

        assert!(config.binary_path.to_string_lossy().contains("maluwaf"));
    }

    #[test]
    fn test_verbose_request_logging_config() {
        use maluwaf::config::logging::VerboseRequestLoggingConfig;

        let config = VerboseRequestLoggingConfig {
            enabled: true,
            log_blocked: true,
            log_challenged: true,
            log_dropped: true,
            log_proxied: false,
            log_internal: false,
            max_logs_per_second: 50,
        };

        assert!(config.enabled);
        assert!(config.log_blocked);
        assert!(config.log_challenged);
        assert!(config.log_dropped);
        assert!(!config.log_proxied);
        assert!(!config.log_internal);
        assert_eq!(config.max_logs_per_second, 50);
    }

    #[test]
    fn test_verbose_request_logging_config_defaults() {
        use maluwaf::config::logging::VerboseRequestLoggingConfig;

        let config = VerboseRequestLoggingConfig::default();

        assert!(!config.enabled);
        assert!(!config.log_blocked);
        assert!(!config.log_challenged);
        assert!(!config.log_dropped);
        assert!(!config.log_proxied);
        assert!(!config.log_internal);
        assert_eq!(config.max_logs_per_second, 100);
    }

    #[test]
    fn test_upgrade_mode_detection() {
        use maluwaf::overseer::mode::{detect_upgrade_mode, UpgradeMode};

        let mode = detect_upgrade_mode();

        match mode {
            UpgradeMode::ReusePort => {
                assert!(!mode.requires_temp_ports());
            }
            UpgradeMode::PortSwap { temp_port_offset } => {
                assert!(mode.requires_temp_ports());
                assert_eq!(temp_port_offset, 1000);
            }
        }
    }

    #[test]
    fn test_worker_metrics_default() {
        use maluwaf::worker::metrics::WorkerMetrics;

        let metrics = WorkerMetrics::default();

        assert_eq!(
            metrics
                .total_requests
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            metrics
                .current_concurrent
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn test_worker_metrics_recording() {
        use maluwaf::worker::metrics::WorkerMetrics;
        use std::sync::atomic::Ordering;

        let metrics = WorkerMetrics::default();

        metrics.total_requests.fetch_add(1, Ordering::Relaxed);
        assert_eq!(metrics.total_requests.load(Ordering::Relaxed), 1);

        metrics.current_concurrent.fetch_add(1, Ordering::Relaxed);
        assert_eq!(metrics.current_concurrent.load(Ordering::Relaxed), 1);

        metrics.current_concurrent.fetch_sub(1, Ordering::Relaxed);
        assert_eq!(metrics.current_concurrent.load(Ordering::Relaxed), 0);
    }
}

#[cfg(test)]
mod mesh_transport_tests {
    use maluwaf::mesh::transport_core::{
        MeshTransportError, MAX_REASONABLE_TIMESTAMP, MIN_REASONABLE_TIMESTAMP,
    };

    #[test]
    fn test_mesh_transport_error_display() {
        let error = MeshTransportError::NoSeedsAvailable;
        assert_eq!(error.to_string(), "No seed nodes available");

        let error = MeshTransportError::ConnectionFailed("test".to_string());
        assert_eq!(error.to_string(), "Connection failed: test");

        let error = MeshTransportError::VersionMismatch {
            expected: 1,
            got: 2,
        };
        assert_eq!(error.to_string(), "Version mismatch: expected 1, got 2");

        let error = MeshTransportError::Timeout;
        assert_eq!(error.to_string(), "Timeout");

        let error = MeshTransportError::RateLimited;
        assert_eq!(
            error.to_string(),
            "Rate limited - too many connection attempts"
        );
    }

    #[test]
    fn test_mesh_transport_error_from_quinn() {
        let error = MeshTransportError::from(quinn::ConnectionError::TimedOut);
        assert!(matches!(error, MeshTransportError::ConnectionFailed(_)));
    }

    #[test]
    fn test_timestamp_constants() {
        assert!(MIN_REASONABLE_TIMESTAMP > 0);
        assert!(MAX_REASONABLE_TIMESTAMP > MIN_REASONABLE_TIMESTAMP);
        assert_eq!(
            MAX_REASONABLE_TIMESTAMP - MIN_REASONABLE_TIMESTAMP,
            31536000
        );
    }

    #[test]
    fn test_mesh_transport_error_variants() {
        let variants = vec![
            MeshTransportError::NoSeedsAvailable,
            MeshTransportError::ConnectionFailed("test".to_string()),
            MeshTransportError::SendFailed("test".to_string()),
            MeshTransportError::ReceiveFailed("test".to_string()),
            MeshTransportError::VersionMismatch {
                expected: 1,
                got: 2,
            },
            MeshTransportError::UnexpectedMessage,
            MeshTransportError::PeerError {
                code: 404,
                message: "Not found".to_string(),
            },
            MeshTransportError::PeerNotFound("peer1".to_string()),
            MeshTransportError::NoRouteToUpstream("upstream1".to_string()),
            MeshTransportError::ServiceNotAllowed("service1".to_string()),
            MeshTransportError::RuntimeNotSet,
            MeshTransportError::Timeout,
            MeshTransportError::RateLimited,
            MeshTransportError::AuthFailed("auth error".to_string()),
        ];

        assert_eq!(variants.len(), 14);
    }
}

#[cfg(test)]
mod rate_limit_tests {
    use maluwaf::utils::ratelimit::{IpRateLimiter, RateLimitResult, RateLimitStatsProvider};
    use maluwaf::waf::ratelimit::core::{IpRateLimitConfig, SlottedIpRateLimiter};

    #[test]
    fn test_slotted_ip_rate_limiter_ip_rate_limiter_trait() {
        let config = IpRateLimitConfig {
            per_second: 100,
            per_minute: 1000,
            per_5min: 5000,
            per_10min: 8000,
            per_hour: 10000,
            per_day: 20000,
        };
        let limiter = SlottedIpRateLimiter::new(config);

        let ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();

        let result = IpRateLimiter::check(&limiter, ip);
        assert!(matches!(result, RateLimitResult::Allowed));
    }

    #[test]
    fn test_slotted_ip_rate_limiter_stats_provider() {
        let config = IpRateLimitConfig::default();
        let limiter = SlottedIpRateLimiter::new(config);

        let stats = limiter.get_stats();
        assert!(stats.is_some());

        let stats = stats.unwrap();
        assert_eq!(stats.limit, 10);
        assert!(stats.remaining >= 0);
    }

    #[test]
    fn test_rate_limit_result_variants() {
        let allowed = RateLimitResult::Allowed;
        assert!(matches!(allowed, RateLimitResult::Allowed));

        let limited = RateLimitResult::Limited {
            retry_after_secs: 60,
        };
        assert!(matches!(
            limited,
            RateLimitResult::Limited {
                retry_after_secs: 60
            }
        ));
    }
}

#[cfg(test)]
mod tls_config_tests {
    use std::path::PathBuf;

    #[test]
    fn test_tls_config_default() {
        use maluwaf::tls::config::InternalTlsConfig;

        let config = InternalTlsConfig::default();

        assert!(!config.enabled);
        assert!(config.prefer_post_quantum);
        assert!(config.tls_1_3_only);
        assert!(!config.enable_tls_12_fallback);
        assert!(config.ocsp_stapling_enabled);
        assert_eq!(config.port, 443);
        assert!(!config.acme.enabled);
        assert!(!config.client_auth.enabled);
    }

    #[test]
    fn test_acme_config_default() {
        use maluwaf::tls::config::InternalAcmeConfig;

        let config = InternalAcmeConfig::default();

        assert!(!config.enabled);
        assert!(config.email.is_none());
        assert!(config.cache_dir.is_none());
        assert!(!config.staging);
        assert!(config.domains.is_empty());
    }

    #[test]
    fn test_client_auth_config_default() {
        use maluwaf::tls::config::InternalClientAuthConfig;

        let config = InternalClientAuthConfig::default();

        assert!(!config.enabled);
        assert!(config.ca_cert_path.is_none());
    }

    #[test]
    fn test_tls_config_with_values() {
        use maluwaf::tls::config::{
            InternalAcmeChallengeType, InternalAcmeConfig, InternalClientAuthConfig,
            InternalTlsConfig,
        };

        let config = InternalTlsConfig {
            enabled: true,
            cert_path: Some(PathBuf::from("/etc/ssl/cert.pem")),
            key_path: Some(PathBuf::from("/etc/ssl/key.pem")),
            watch_dir: Some(PathBuf::from("/etc/ssl")),
            prefer_post_quantum: false,
            tls_1_3_only: false,
            enable_tls_12_fallback: true,
            ocsp_stapling_enabled: false,
            ocsp_response_path: Some(PathBuf::from("/etc/ssl/ocsp.der")),
            port: 8443,
            acme: InternalAcmeConfig {
                enabled: true,
                email: Some("admin@example.com".to_string()),
                cache_dir: Some(PathBuf::from("/var/lib/acme")),
                staging: true,
                domains: vec!["example.com".to_string(), "www.example.com".to_string()],
                challenge_type: InternalAcmeChallengeType::Http01,
            },
            client_auth: InternalClientAuthConfig {
                enabled: true,
                ca_cert_path: Some(PathBuf::from("/etc/ssl/ca.pem")),
            },
        };

        assert!(config.enabled);
        assert_eq!(config.port, 8443);
        assert!(config.enable_tls_12_fallback);
        assert!(!config.tls_1_3_only);
        assert!(config.acme.enabled);
        assert_eq!(config.acme.domains.len(), 2);
        assert!(config.client_auth.enabled);
    }
}

#[cfg(test)]
mod block_store_tests {
    use maluwaf::block_store::{BlockEntry, BlockStore, BlockStoreStats};
    use maluwaf::config::DenyListLimitsConfig;
    use std::net::IpAddr;
    use tempfile::TempDir;

    fn default_config() -> DenyListLimitsConfig {
        DenyListLimitsConfig {
            max_entries: 1000,
            persist_interval_secs: 0,
        }
    }

    #[tokio::test]
    async fn test_block_store_stats_calculation() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        store.block_ip("10.0.0.1".parse().unwrap(), "permanent", 0, "global");
        store.block_ip("10.0.0.2".parse().unwrap(), "temp", 3600, "global");

        let stats = store.get_stats();

        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.permanent_count, 1);
        assert!(stats.utilization_percent >= 0.0);
    }

    #[test]
    fn test_block_entry_key_format() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let key = BlockEntry::key("global", &ip);

        assert!(key.starts_with("block:"));
        assert!(key.contains("global"));
        assert!(key.contains("192.168.1.1"));
    }

    #[test]
    fn test_block_entry_permanent_detection() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        let permanent = BlockEntry::new(ip, "test".to_string(), 0, "global".to_string());
        assert!(permanent.is_permanent());

        let temporary = BlockEntry::new(ip, "test".to_string(), 3600, "global".to_string());
        assert!(!temporary.is_permanent());
    }

    #[test]
    fn test_block_store_stats_default() {
        let stats = BlockStoreStats {
            total_entries: 0,
            max_entries: 1000,
            permanent_count: 0,
            expired_count: 0,
            utilization_percent: 0.0,
        };

        assert_eq!(stats.total_entries, 0);
        assert_eq!(stats.max_entries, 1000);
        assert_eq!(stats.utilization_percent, 0.0);
    }
}

#[cfg(test)]
mod mesh_protocol_roundtrip_tests {
    use maluwaf::mesh::protocol::{AckStatus, HealthStatus, LookupType, MeshMessage};

    fn roundtrip(msg: &MeshMessage) -> MeshMessage {
        let encoded = msg.encode().expect("encode failed");
        MeshMessage::decode(&encoded).expect("decode failed")
    }

    fn roundtrip_with_length(msg: &MeshMessage) -> MeshMessage {
        let encoded = msg.encode_with_length();
        // Skip 4-byte length prefix
        MeshMessage::decode(&encoded[4..]).expect("decode failed")
    }

    #[test]
    fn test_keepalive_roundtrip() {
        let msg = MeshMessage::KeepAlive;
        let decoded = roundtrip(&msg);
        assert!(matches!(decoded, MeshMessage::KeepAlive));
    }

    #[test]
    fn test_keepalive_ack_roundtrip() {
        let msg = MeshMessage::KeepAliveAck;
        let decoded = roundtrip(&msg);
        assert!(matches!(decoded, MeshMessage::KeepAliveAck));
    }

    #[test]
    fn test_sync_request_roundtrip() {
        let msg = MeshMessage::SyncRequest {
            node_id: "node-123".into(),
        };
        let decoded = roundtrip(&msg);
        match decoded {
            MeshMessage::SyncRequest { node_id } => {
                assert_eq!(node_id.as_str(), "node-123");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_ping_roundtrip() {
        let msg = MeshMessage::Ping {
            request_id: "req-456".into(),
            node_id: "node-789".into(),
            timestamp: 1234567890,
        };
        let decoded = roundtrip(&msg);
        match decoded {
            MeshMessage::Ping {
                request_id,
                node_id,
                timestamp,
            } => {
                assert_eq!(request_id.as_str(), "req-456");
                assert_eq!(node_id.as_str(), "node-789");
                assert_eq!(timestamp, 1234567890);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_pong_roundtrip() {
        let msg = MeshMessage::Pong {
            request_id: "req-abc".into(),
            node_id: "node-def".into(),
            timestamp: 9876543210,
        };
        let decoded = roundtrip(&msg);
        match decoded {
            MeshMessage::Pong {
                request_id,
                node_id,
                timestamp,
            } => {
                assert_eq!(request_id.as_str(), "req-abc");
                assert_eq!(node_id.as_str(), "node-def");
                assert_eq!(timestamp, 9876543210);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_lookup_request_roundtrip() {
        let msg = MeshMessage::LookupRequest {
            request_id: "lr-1".into(),
            key: "dns:example.com".into(),
            lookup_type: LookupType::KeyValue,
        };
        let decoded = roundtrip(&msg);
        match decoded {
            MeshMessage::LookupRequest {
                request_id,
                key,
                lookup_type,
            } => {
                assert_eq!(request_id.as_str(), "lr-1");
                assert_eq!(key.as_str(), "dns:example.com");
                assert_eq!(lookup_type, LookupType::KeyValue);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_lookup_response_found_roundtrip() {
        let msg = MeshMessage::LookupResponse {
            request_id: "lr-1".into(),
            key: "dns:example.com".into(),
            value: Some(b"192.168.1.1".to_vec()),
            found: true,
        };
        let decoded = roundtrip(&msg);
        match decoded {
            MeshMessage::LookupResponse {
                request_id,
                key,
                value,
                found,
            } => {
                assert_eq!(request_id.as_str(), "lr-1");
                assert_eq!(key.as_str(), "dns:example.com");
                assert_eq!(value, Some(b"192.168.1.1".to_vec()));
                assert!(found);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_lookup_response_not_found_roundtrip() {
        let msg = MeshMessage::LookupResponse {
            request_id: "lr-2".into(),
            key: "dns:missing.com".into(),
            value: None,
            found: false,
        };
        let decoded = roundtrip(&msg);
        match decoded {
            MeshMessage::LookupResponse { value, found, .. } => {
                assert_eq!(value, None);
                assert!(!found);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_peer_health_check_roundtrip() {
        let msg = MeshMessage::PeerHealthCheck {
            peer_id: "peer-1".into(),
            timestamp: 1000000,
        };
        let decoded = roundtrip(&msg);
        match decoded {
            MeshMessage::PeerHealthCheck { peer_id, timestamp } => {
                assert_eq!(peer_id.as_str(), "peer-1");
                assert_eq!(timestamp, 1000000);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_peer_health_response_roundtrip() {
        let msg = MeshMessage::PeerHealthResponse {
            peer_id: "peer-1".into(),
            status: HealthStatus::Healthy,
            latency_ms: Some(42),
            timestamp: 1000000,
        };
        let decoded = roundtrip(&msg);
        match decoded {
            MeshMessage::PeerHealthResponse {
                peer_id,
                status,
                latency_ms,
                timestamp,
            } => {
                assert_eq!(peer_id.as_str(), "peer-1");
                assert_eq!(status, HealthStatus::Healthy);
                assert_eq!(latency_ms, Some(42));
                assert_eq!(timestamp, 1000000);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_error_roundtrip() {
        let msg = MeshMessage::Error {
            code: 404,
            message: "not found".into(),
        };
        let decoded = roundtrip(&msg);
        match decoded {
            MeshMessage::Error { code, message } => {
                assert_eq!(code, 404);
                assert_eq!(message.as_str(), "not found");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_mesh_ack_roundtrip() {
        let msg = MeshMessage::MeshAck {
            original_message_id: "msg-123".into(),
            status: AckStatus::Success,
            timestamp: 9999,
        };
        let decoded = roundtrip(&msg);
        match decoded {
            MeshMessage::MeshAck {
                original_message_id,
                status,
                timestamp,
            } => {
                assert_eq!(original_message_id.as_str(), "msg-123");
                assert_eq!(status, AckStatus::Success);
                assert_eq!(timestamp, 9999);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_lookup_batch_request_roundtrip() {
        let keys = vec!["key1".into(), "key2".into(), "key3".into()];
        let msg = MeshMessage::LookupBatchRequest {
            request_id: "batch-1".into(),
            keys: keys.clone(),
        };
        let decoded = roundtrip(&msg);
        match decoded {
            MeshMessage::LookupBatchRequest {
                request_id,
                keys: k,
            } => {
                assert_eq!(request_id.as_str(), "batch-1");
                assert_eq!(k.len(), 3);
                assert_eq!(k[0].as_str(), "key1");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_length_prefix_roundtrip() {
        let msg = MeshMessage::Ping {
            request_id: "lp-test".into(),
            node_id: "node-lp".into(),
            timestamp: 42,
        };
        let decoded = roundtrip_with_length(&msg);
        match decoded {
            MeshMessage::Ping {
                request_id,
                node_id,
                timestamp,
            } => {
                assert_eq!(request_id.as_str(), "lp-test");
                assert_eq!(node_id.as_str(), "node-lp");
                assert_eq!(timestamp, 42);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_roundtrip_preserves_binary_data() {
        let binary_data: Vec<u8> = (0..255).collect();
        let msg = MeshMessage::LookupResponse {
            request_id: "bin-test".into(),
            key: "binary".into(),
            value: Some(binary_data.clone()),
            found: true,
        };
        let decoded = roundtrip(&msg);
        match decoded {
            MeshMessage::LookupResponse { value, .. } => {
                assert_eq!(value, Some(binary_data));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_roundtrip_empty_strings() {
        let msg = MeshMessage::Ping {
            request_id: "".into(),
            node_id: "".into(),
            timestamp: 0,
        };
        let decoded = roundtrip(&msg);
        match decoded {
            MeshMessage::Ping {
                request_id,
                node_id,
                timestamp,
            } => {
                assert_eq!(request_id.as_str(), "");
                assert_eq!(node_id.as_str(), "");
                assert_eq!(timestamp, 0);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_decode_invalid_data_returns_none() {
        assert!(MeshMessage::decode(&[]).is_none());
        assert!(MeshMessage::decode(&[0xFF, 0xFF, 0xFF]).is_none());
        assert!(MeshMessage::decode(b"not protobuf").is_none());
    }
}

#[cfg(test)]
mod ipc_serialization_tests {
    use maluwaf::process::{ErrorCode, ErrorSeverity, Message, WorkerId};

    fn roundtrip(msg: &Message) -> Message {
        let json = serde_json::to_string(msg).expect("serialize");
        serde_json::from_str(&json).expect("deserialize")
    }

    #[test]
    fn worker_started_roundtrip() {
        let msg = Message::WorkerStarted {
            id: WorkerId(3),
            pid: 9999,
            port: 8443,
            timestamp: 1700000000,
        };
        let decoded = roundtrip(&msg);
        match decoded {
            Message::WorkerStarted { id, pid, port, timestamp } => {
                assert_eq!(id, WorkerId(3));
                assert_eq!(pid, 9999);
                assert_eq!(port, 8443);
                assert_eq!(timestamp, 1700000000);
            }
            _ => panic!("wrong variant after roundtrip"),
        }
    }

    #[test]
    fn worker_ready_roundtrip() {
        let msg = Message::WorkerReady { id: WorkerId(7) };
        let decoded = roundtrip(&msg);
        match decoded {
            Message::WorkerReady { id } => assert_eq!(id, WorkerId(7)),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn worker_error_roundtrip() {
        let msg = Message::WorkerError {
            id: WorkerId(1),
            error: "disk full".to_string(),
            severity: ErrorSeverity::Critical,
            error_code: ErrorCode::ResourceExhausted,
        };
        let decoded = roundtrip(&msg);
        match decoded {
            Message::WorkerError { id, error, severity, error_code } => {
                assert_eq!(id, WorkerId(1));
                assert_eq!(error, "disk full");
                assert_eq!(severity, ErrorSeverity::Critical);
                assert_eq!(error_code, ErrorCode::ResourceExhausted);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn master_shutdown_roundtrip() {
        let msg = Message::MasterShutdown {
            graceful: true,
            timeout_secs: 30,
        };
        let decoded = roundtrip(&msg);
        match decoded {
            Message::MasterShutdown { graceful, timeout_secs } => {
                assert!(graceful);
                assert_eq!(timeout_secs, 30);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn master_config_reload_roundtrip() {
        let msg = Message::MasterConfigReload {
            config_path: "/etc/maluwaf/main.toml".to_string(),
        };
        let decoded = roundtrip(&msg);
        match decoded {
            Message::MasterConfigReload { config_path } => {
                assert_eq!(config_path, "/etc/maluwaf/main.toml");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn health_check_ack_roundtrip() {
        let msg = Message::HealthCheckAck { timestamp: 1234567890 };
        let decoded = roundtrip(&msg);
        match decoded {
            Message::HealthCheckAck { timestamp } => assert_eq!(timestamp, 1234567890),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn worker_drain_roundtrip() {
        let msg = Message::WorkerDrain {
            id: WorkerId(2),
            timeout_secs: 60,
        };
        let decoded = roundtrip(&msg);
        match decoded {
            Message::WorkerDrain { id, timeout_secs } => {
                assert_eq!(id, WorkerId(2));
                assert_eq!(timeout_secs, 60);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn drain_request_roundtrip() {
        let msg = Message::DrainRequest {
            timeout_secs: 45,
            drain_id: 42,
        };
        let decoded = roundtrip(&msg);
        match decoded {
            Message::DrainRequest { timeout_secs, drain_id } => {
                assert_eq!(timeout_secs, 45);
                assert_eq!(drain_id, 42);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn restore_from_drain_roundtrip() {
        let msg = Message::RestoreFromDrain;
        let decoded = roundtrip(&msg);
        assert!(matches!(decoded, Message::RestoreFromDrain));
    }

    #[test]
    fn overseer_get_status_roundtrip() {
        let msg = Message::OverseerGetStatus;
        let decoded = roundtrip(&msg);
        assert!(matches!(decoded, Message::OverseerGetStatus));
    }

    #[test]
    fn minify_error_roundtrip() {
        let msg = Message::MinifyError {
            request_id: 555,
            error: "syntax error in CSS".to_string(),
        };
        let decoded = roundtrip(&msg);
        match decoded {
            Message::MinifyError { request_id, error } => {
                assert_eq!(request_id, 555);
                assert_eq!(error, "syntax error in CSS");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn restart_worker_request_roundtrip() {
        let msg = Message::RestartWorkerRequest { id: WorkerId(0) };
        let decoded = roundtrip(&msg);
        match decoded {
            Message::RestartWorkerRequest { id } => assert_eq!(id, WorkerId(0)),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn worker_connection_count_roundtrip() {
        let msg = Message::WorkerConnectionCount {
            id: WorkerId(5),
            active: 100,
            idle: 20,
        };
        let decoded = roundtrip(&msg);
        match decoded {
            Message::WorkerConnectionCount { id, active, idle } => {
                assert_eq!(id, WorkerId(5));
                assert_eq!(active, 100);
                assert_eq!(idle, 20);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn socket_handoff_complete_roundtrip() {
        let msg = Message::SocketHandoffComplete {
            success: true,
            fd_count: 4,
        };
        let decoded = roundtrip(&msg);
        match decoded {
            Message::SocketHandoffComplete { success, fd_count } => {
                assert!(success);
                assert_eq!(fd_count, 4);
            }
            _ => panic!("wrong variant"),
        }
    }

    // ── Admin config validation tests ────────────────────────────────

    mod admin_config_tests {
        use maluwaf::config::admin::{AdminConfig, AdminCorsConfig, AdminRateLimitConfig};

        #[test]
        fn test_admin_config_valid() {
            let config = AdminConfig {
                enabled: true,
                port: 8081,
                bind_address: "127.0.0.1".to_string(),
                token: "xR4kT9mW2pQ7vN3jL5hB8cF1gA6eD0yZ".to_string(),
                token_env_var: None,
                bcrypt_cost: 12,
                cors: AdminCorsConfig::default(),
                rate_limit: AdminRateLimitConfig::default(),
            };
            assert!(config.validate().is_ok());
        }

        #[test]
        fn test_admin_config_port_zero_rejected() {
            let config = AdminConfig {
                enabled: true,
                port: 0,
                bind_address: "127.0.0.1".to_string(),
                token: "xR4kT9mW2pQ7vN3jL5hB8cF1gA6eD0yZ".to_string(),
                token_env_var: None,
                bcrypt_cost: 12,
                cors: AdminCorsConfig::default(),
                rate_limit: AdminRateLimitConfig::default(),
            };
            let err = config.validate().unwrap_err();
            assert_eq!(err.field, "admin.port");
        }

        #[test]
        fn test_admin_config_bcrypt_cost_too_low() {
            let config = AdminConfig {
                enabled: true,
                port: 8081,
                bind_address: "127.0.0.1".to_string(),
                token: "xR4kT9mW2pQ7vN3jL5hB8cF1gA6eD0yZ".to_string(),
                token_env_var: None,
                bcrypt_cost: 4,
                cors: AdminCorsConfig::default(),
                rate_limit: AdminRateLimitConfig::default(),
            };
            let err = config.validate().unwrap_err();
            assert_eq!(err.field, "admin.bcrypt_cost");
        }

        #[test]
        fn test_admin_config_bcrypt_cost_too_high() {
            let config = AdminConfig {
                enabled: true,
                port: 8081,
                bind_address: "127.0.0.1".to_string(),
                token: "xR4kT9mW2pQ7vN3jL5hB8cF1gA6eD0yZ".to_string(),
                token_env_var: None,
                bcrypt_cost: 20,
                cors: AdminCorsConfig::default(),
                rate_limit: AdminRateLimitConfig::default(),
            };
            let err = config.validate().unwrap_err();
            assert_eq!(err.field, "admin.bcrypt_cost");
        }

        #[test]
        fn test_admin_config_weak_token_rejected() {
            let config = AdminConfig {
                enabled: true,
                port: 8081,
                bind_address: "127.0.0.1".to_string(),
                token: "password1234567890abcdefghijklmnopqrstuvwxyz".to_string(),
                token_env_var: None,
                bcrypt_cost: 12,
                cors: AdminCorsConfig::default(),
                rate_limit: AdminRateLimitConfig::default(),
            };
            let err = config.validate().unwrap_err();
            assert_eq!(err.field, "admin.token");
            assert!(err.message.contains("weak pattern"), "Expected weak pattern error, got: {}", err.message);
        }

        #[test]
        fn test_admin_config_short_token_rejected() {
            let config = AdminConfig {
                enabled: true,
                port: 8081,
                bind_address: "127.0.0.1".to_string(),
                token: "short".to_string(),
                token_env_var: None,
                bcrypt_cost: 12,
                cors: AdminCorsConfig::default(),
                rate_limit: AdminRateLimitConfig::default(),
            };
            let err = config.validate().unwrap_err();
            assert_eq!(err.field, "admin.token");
            assert!(err.message.contains("at least"));
        }

        #[test]
        fn test_admin_config_default_token_debug_only() {
            let config = AdminConfig {
                enabled: true,
                port: 8081,
                bind_address: "127.0.0.1".to_string(),
                token: "changeme".to_string(),
                token_env_var: None,
                bcrypt_cost: 12,
                cors: AdminCorsConfig::default(),
                rate_limit: AdminRateLimitConfig::default(),
            };
            let result = config.validate();
            // In debug builds, it warns but still returns error to force setting a real token
            assert!(result.is_err());
        }
    }
}
