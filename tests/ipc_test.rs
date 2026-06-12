#[cfg(unix)]
mod ipc_tests {
    use synvoid::process::ipc::{
        BlockEntryData, ErrorCode, ErrorSeverity, Message, RequestLogPayload, RulePatternData,
        ThreatIndicatorData, ThreatIndicatorType, ThreatSeverityLevel, UpgradeModePayload,
        WorkerId, WorkerMetricsPayload, WorkerStatusInfo,
    };
    use synvoid::process::{ipc_transport::IpcStream, IpcEndpoint};
    use tempfile::TempDir;
    use tokio::net::UnixListener;

    // ── Malformed deserialization tests ──────────────────────────────

    #[test]
    fn test_deserialize_truncated_json() {
        let json = r#"{"WorkerStarted":{"id":0,"pid":1234"#;
        let result: Result<Message, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_empty_string() {
        let result: Result<Message, _> = serde_json::from_str("");
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_invalid_json_syntax() {
        let result: Result<Message, _> = serde_json::from_str("{invalid json}");
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_wrong_field_type() {
        // pid should be u32, not string
        let json = r#"{"WorkerStarted":{"id":0,"pid":"not_a_number","port":8080,"timestamp":0}}"#;
        let result: Result<Message, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_missing_required_field() {
        // Missing 'id' field
        let json = r#"{"WorkerStarted":{"pid":1234,"port":8080,"timestamp":0}}"#;
        let result: Result<Message, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_unknown_variant() {
        let json = r#"{"NonExistentVariant":{"id":0}}"#;
        let result: Result<Message, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_extra_fields_allowed() {
        // serde(default) should allow extra fields
        let json = r#"{"WorkerStarted":{"id":0,"pid":1234,"port":8080,"timestamp":0,"extra_field":"ignored"}}"#;
        let result: Result<Message, _> = serde_json::from_str(json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_deserialize_nested_type_mismatch() {
        // WorkerError severity should be an enum, not a number
        let json =
            r#"{"WorkerError":{"id":0,"error":"test","severity":123,"error_code":"Unknown"}}"#;
        let result: Result<Message, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // ── Round-trip serialization tests ───────────────────────────────

    #[test]
    fn test_roundtrip_worker_started() {
        let msg = Message::WorkerStarted {
            id: WorkerId(1),
            pid: 1234,
            port: 8080,
            timestamp: 1234567890,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            decoded,
            Message::WorkerStarted {
                id: WorkerId(1),
                pid: 1234,
                port: 8080,
                timestamp: 1234567890,
            }
        ));
    }

    #[test]
    fn test_roundtrip_worker_ready() {
        let msg = Message::WorkerReady { id: WorkerId(42) };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, Message::WorkerReady { id: WorkerId(42) }));
    }

    #[test]
    fn test_roundtrip_worker_shutdown_complete() {
        let msg = Message::WorkerShutdownComplete { id: WorkerId(7) };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            decoded,
            Message::WorkerShutdownComplete { id: WorkerId(7) }
        ));
    }

    #[test]
    fn test_roundtrip_worker_error() {
        let msg = Message::WorkerError {
            id: WorkerId(3),
            error: "connection timeout".to_string(),
            severity: synvoid::process::ErrorSeverity::Error,
            error_code: synvoid::process::ErrorCode::Unknown,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        match decoded {
            Message::WorkerError {
                id,
                error,
                severity,
                error_code,
            } => {
                assert_eq!(id, WorkerId(3));
                assert_eq!(error, "connection timeout");
                assert_eq!(severity, synvoid::process::ErrorSeverity::Error);
                assert_eq!(error_code, synvoid::process::ErrorCode::Unknown);
            }
            _ => panic!("Expected WorkerError"),
        }
    }

    #[test]
    fn test_roundtrip_master_shutdown() {
        let msg = Message::MasterShutdown {
            graceful: true,
            timeout_secs: 30,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            decoded,
            Message::MasterShutdown {
                graceful: true,
                timeout_secs: 30,
            }
        ));
    }

    #[test]
    fn test_roundtrip_master_config_reload() {
        let msg = Message::MasterConfigReload {
            config_path: "/etc/synvoid/main.toml".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        match decoded {
            Message::MasterConfigReload { config_path } => {
                assert_eq!(config_path, "/etc/synvoid/main.toml");
            }
            _ => panic!("Expected MasterConfigReload"),
        }
    }

    #[test]
    fn test_roundtrip_health_check_ack() {
        let msg = Message::HealthCheckAck { timestamp: 9999999 };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            decoded,
            Message::HealthCheckAck { timestamp: 9999999 }
        ));
    }

    #[test]
    fn test_roundtrip_worker_resize_ack() {
        let msg = Message::WorkerResizeAck {
            id: WorkerId(5),
            worker_threads: 8,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            decoded,
            Message::WorkerResizeAck {
                id: WorkerId(5),
                worker_threads: 8,
            }
        ));
    }

    #[test]
    fn test_roundtrip_cpu_worker_started() {
        let msg = Message::CpuWorkerStarted {
            worker_id: 2,
            pid: 5678,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            decoded,
            Message::CpuWorkerStarted {
                worker_id: 2,
                pid: 5678,
            }
        ));
    }

    #[test]
    fn test_roundtrip_master_resize_threadpool() {
        let msg = Message::MasterResizeThreadpool { worker_threads: 16 };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            decoded,
            Message::MasterResizeThreadpool { worker_threads: 16 }
        ));
    }

    #[test]
    fn test_roundtrip_drain_messages() {
        let drain = Message::WorkerDrain {
            id: WorkerId(1),
            timeout_secs: 30,
        };
        let json = serde_json::to_string(&drain).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            decoded,
            Message::WorkerDrain {
                id: WorkerId(1),
                timeout_secs: 30,
            }
        ));

        let drained = Message::WorkerDrained {
            id: WorkerId(1),
            remaining_connections: 0,
        };
        let json = serde_json::to_string(&drained).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            decoded,
            Message::WorkerDrained {
                id: WorkerId(1),
                remaining_connections: 0,
            }
        ));
    }

    #[test]
    fn test_roundtrip_unified_server_messages() {
        let started = Message::UnifiedServerWorkerStarted {
            id: WorkerId(1),
            pid: 1111,
            timestamp: 100,
        };
        let json = serde_json::to_string(&started).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            decoded,
            Message::UnifiedServerWorkerStarted {
                id: WorkerId(1),
                pid: 1111,
                timestamp: 100,
            }
        ));

        let ready = Message::UnifiedServerWorkerReady { id: WorkerId(2) };
        let json = serde_json::to_string(&ready).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            decoded,
            Message::UnifiedServerWorkerReady { id: WorkerId(2) }
        ));
    }

    #[test]
    fn test_roundtrip_socket_handoff_messages() {
        let req = Message::SocketHandoffRequest {
            socket_path: "/tmp/handoff.sock".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            decoded,
            Message::SocketHandoffRequest {
                socket_path,
            } if socket_path == "/tmp/handoff.sock"
        ));

        let ready = Message::SocketHandoffReady {
            ports: vec![8080, 8443],
        };
        let json = serde_json::to_string(&ready).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            decoded,
            Message::SocketHandoffReady { ports } if ports == vec![8080, 8443]
        ));
    }

    #[tokio::test]
    async fn test_ipc_unix_socket_send_recv() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test_ipc.sock");

        let listener = UnixListener::bind(&socket_path).unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ipc_stream = IpcStream::from_unix_stream(stream);
            let msg: Message = ipc_stream.recv().await.unwrap().unwrap();
            ipc_stream.send(&msg).await.unwrap();
        });

        let socket_path_clone = socket_path.clone();
        let client = tokio::spawn(async move {
            let stream = tokio::net::UnixStream::connect(&socket_path_clone)
                .await
                .unwrap();
            let mut ipc_stream = IpcStream::from_unix_stream(stream);

            let msg = Message::WorkerStarted {
                id: WorkerId(1),
                pid: 1234,
                port: 8080,
                timestamp: 1234567890,
            };

            ipc_stream.send(&msg).await.unwrap();

            let received: Message = ipc_stream.recv().await.unwrap().unwrap();

            assert!(matches!(
                received,
                Message::WorkerStarted {
                    id: WorkerId(1),
                    pid: 1234,
                    ..
                }
            ));
        });

        server.await.unwrap();
        client.await.unwrap();
    }

    #[tokio::test]
    async fn test_ipc_multiple_messages() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test_multi.sock");

        let listener = UnixListener::bind(&socket_path).unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ipc_stream = IpcStream::from_unix_stream(stream);

            for _ in 0..3usize {
                let msg: Message = ipc_stream.recv().await.unwrap().unwrap();
                ipc_stream.send(&msg).await.unwrap();
            }
        });

        let socket_path_clone = socket_path.clone();
        let client: tokio::task::JoinHandle<()> = tokio::spawn(async move {
            let stream = tokio::net::UnixStream::connect(&socket_path_clone)
                .await
                .unwrap();
            let mut ipc_stream = IpcStream::from_unix_stream(stream);

            for i in 0..3usize {
                let msg = Message::WorkerReady { id: WorkerId(i) };
                ipc_stream.send(&msg).await.unwrap();

                let received: Message = ipc_stream.recv().await.unwrap().unwrap();
                assert!(matches!(received, Message::WorkerReady { id } if id == WorkerId(i)));
            }
        });

        server.await.unwrap();
        client.await.unwrap();
    }

    #[tokio::test]
    async fn test_ipc_bidirectional_communication() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test_bidi.sock");

        let listener = UnixListener::bind(&socket_path).unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ipc_stream = IpcStream::from_unix_stream(stream);

            let msg: Message = ipc_stream.recv().await.unwrap().unwrap();
            assert!(matches!(
                msg,
                Message::WorkerStarted {
                    id: WorkerId(5),
                    ..
                }
            ));

            ipc_stream
                .send(&Message::WorkerReady { id: WorkerId(5) })
                .await
                .unwrap();

            let msg: Message = ipc_stream.recv().await.unwrap().unwrap();
            assert!(matches!(
                msg,
                Message::WorkerShutdownComplete {
                    id: WorkerId(5),
                    ..
                }
            ));
        });

        let socket_path_clone = socket_path.clone();
        let client = tokio::spawn(async move {
            let stream = tokio::net::UnixStream::connect(&socket_path_clone)
                .await
                .unwrap();
            let mut ipc_stream = IpcStream::from_unix_stream(stream);

            ipc_stream
                .send(&Message::WorkerStarted {
                    id: WorkerId(5),
                    pid: 9999,
                    port: 3000,
                    timestamp: 100,
                })
                .await
                .unwrap();

            let received: Message = ipc_stream.recv().await.unwrap().unwrap();
            assert!(matches!(received, Message::WorkerReady { id: WorkerId(5) }));

            ipc_stream
                .send(&Message::WorkerShutdownComplete { id: WorkerId(5) })
                .await
                .unwrap();
        });

        server.await.unwrap();
        client.await.unwrap();
    }

    #[tokio::test]
    async fn test_ipc_endpoint_path_generation() {
        let endpoint = IpcEndpoint::new("test-socket");
        let path = endpoint.socket_path();

        assert!(path.to_string_lossy().contains("test-socket"));
        assert!(path.to_string_lossy().contains("synvoid"));
    }

    #[test]
    fn test_ipc_message_validation_rejects_long_strings() {
        use synvoid::process::{ErrorCode, ErrorSeverity, Message, WorkerId};

        let long_error = "x".repeat(100_000);
        let msg = Message::WorkerError {
            id: WorkerId(1),
            error: long_error,
            severity: ErrorSeverity::Error,
            error_code: ErrorCode::Unknown,
        };
        let result = msg.validate();
        assert!(result.is_err());

        let valid_msg = Message::WorkerError {
            id: WorkerId(1),
            error: "test error".to_string(),
            severity: ErrorSeverity::Error,
            error_code: ErrorCode::Unknown,
        };
        assert!(valid_msg.validate().is_ok());
    }

    #[test]
    fn test_ipc_message_validation_rejects_long_paths() {
        use synvoid::process::Message;

        let long_path = "/".repeat(5000);
        let msg = Message::MasterConfigReload {
            config_path: long_path,
        };
        let result = msg.validate();
        assert!(result.is_err());

        let valid_msg = Message::MasterConfigReload {
            config_path: "/etc/synvoid/config.toml".to_string(),
        };
        assert!(valid_msg.validate().is_ok());
    }

    #[test]
    fn test_ipc_signed_message_hmac_verification() {
        use synvoid::process::ipc_signed::{generate_session_key, IpcSigner, SignedIpcMessage};

        let key = generate_session_key();
        let signer = IpcSigner::new(&key);

        let msg = vec![1u8, 2, 3, 4];
        let signed = SignedIpcMessage::serialize_signed(&msg, &signer).unwrap();

        let decoded: Vec<u8> = SignedIpcMessage::deserialize_signed(&signed, &signer).unwrap();
        assert_eq!(msg, decoded);

        let wrong_key = generate_session_key();
        let wrong_signer = IpcSigner::new(&wrong_key);
        let result: Result<Vec<u8>, _> =
            SignedIpcMessage::deserialize_signed(&signed, &wrong_signer);
        assert!(result.is_err());

        let mut tampered = signed.clone();
        tampered[10] ^= 0xFF;
        let result: Result<Vec<u8>, _> = SignedIpcMessage::deserialize_signed(&tampered, &signer);
        assert!(result.is_err());
    }

    // ── Phase L.2: HMAC Signature Edge Case Tests ──────────────────

    #[test]
    fn test_hmac_signature_verification_empty_data() {
        use synvoid::process::ipc_signed::{generate_session_key, IpcSigner};

        let key = generate_session_key();
        let signer = IpcSigner::new(&key);

        let hmac = signer.sign(&[]);
        assert!(signer.verify(&[], &hmac));
    }

    #[test]
    fn test_hmac_signature_verification_very_long_data() {
        use synvoid::process::ipc_signed::{generate_session_key, IpcSigner};

        let key = generate_session_key();
        let signer = IpcSigner::new(&key);

        let long_data = vec![0x41u8; 1_000_000];
        let hmac = signer.sign(&long_data);
        assert!(signer.verify(&long_data, &hmac));
    }

    #[test]
    fn test_hmac_signature_verification_all_zero_data() {
        use synvoid::process::ipc_signed::{generate_session_key, IpcSigner};

        let key = generate_session_key();
        let signer = IpcSigner::new(&key);

        let zero_data = vec![0x00u8; 256];
        let hmac = signer.sign(&zero_data);
        assert!(signer.verify(&zero_data, &hmac));
    }

    #[test]
    fn test_hmac_signature_verification_all_ones_data() {
        use synvoid::process::ipc_signed::{generate_session_key, IpcSigner};

        let key = generate_session_key();
        let signer = IpcSigner::new(&key);

        let ones_data = vec![0xFFu8; 256];
        let hmac = signer.sign(&ones_data);
        assert!(signer.verify(&ones_data, &hmac));
    }

    #[test]
    fn test_hmac_signature_verification_partial_tamper() {
        use synvoid::process::ipc_signed::{generate_session_key, IpcSigner, SignedIpcMessage};

        let key = generate_session_key();
        let signer = IpcSigner::new(&key);

        let msg = b"important message that must not be tampered with".to_vec();
        let signed = SignedIpcMessage::serialize_signed(&msg, &signer).unwrap();

        let mut tampered = signed.clone();
        let mid = signed.len() / 2;
        tampered[mid] ^= 0x0F;
        let result: Result<Vec<u8>, _> = SignedIpcMessage::deserialize_signed(&tampered, &signer);
        assert!(result.is_err());
    }

    #[test]
    fn test_hmac_signature_verification_duplicate_nonce_rejected() {
        use synvoid::process::ipc_signed::{generate_session_key, IpcSigner, SignedIpcMessage};

        let key = generate_session_key();
        let signer = IpcSigner::new(&key);

        let msg = b"first message".to_vec();
        let signed = SignedIpcMessage::serialize_signed(&msg, &signer).unwrap();
        let _decoded: Vec<u8> = SignedIpcMessage::deserialize_signed(&signed, &signer).unwrap();

        let result: Result<Vec<u8>, _> = SignedIpcMessage::deserialize_signed(&signed, &signer);
        assert!(result.is_err());
    }

    #[test]
    fn test_hmac_signature_verification_wrong_key_rejected() {
        use synvoid::process::ipc_signed::{generate_session_key, IpcSigner, SignedIpcMessage};

        let key1 = generate_session_key();
        let key2 = generate_session_key();
        let signer1 = IpcSigner::new(&key1);
        let signer2 = IpcSigner::new(&key2);

        let msg = b"cross-key message".to_vec();
        let signed = SignedIpcMessage::serialize_signed(&msg, &signer1).unwrap();

        let result: Result<Vec<u8>, _> = SignedIpcMessage::deserialize_signed(&signed, &signer2);
        assert!(result.is_err());
    }

    #[test]
    fn test_hmac_signature_verification_single_bit_change_rejected() {
        use synvoid::process::ipc_signed::{generate_session_key, IpcSigner, SignedIpcMessage};

        let key = generate_session_key();
        let signer = IpcSigner::new(&key);

        let msg = b"test".to_vec();
        let signed = SignedIpcMessage::serialize_signed(&msg, &signer).unwrap();

        let mut tampered = signed.clone();
        let last_byte_idx = signed.len() - 1;
        tampered[last_byte_idx] ^= 0x01;
        let result: Result<Vec<u8>, _> = SignedIpcMessage::deserialize_signed(&tampered, &signer);
        assert!(result.is_err());
    }

    #[test]
    fn test_hmac_signature_verification_truncated_message() {
        use synvoid::process::ipc_signed::{generate_session_key, SignedIpcMessage};

        let key = generate_session_key();
        let signer = synvoid::process::ipc_signed::IpcSigner::new(&key);

        let short_data = vec![0x00; 10];
        let result: Result<Vec<u8>, _> = SignedIpcMessage::deserialize_signed(&short_data, &signer);
        assert!(result.is_err());
    }

    #[test]
    fn test_hmac_signature_verification_zero_hmac_rejected() {
        use synvoid::process::ipc_signed::{generate_session_key, IpcSigner};

        let key = generate_session_key();
        let signer = IpcSigner::new(&key);

        let data = b"test data";
        let zero_hmac = [0u8; 32];
        assert!(!signer.verify(data, &zero_hmac));
    }

    #[test]
    fn test_hmac_signature_verification_message_with_null_bytes() {
        use synvoid::process::ipc_signed::{generate_session_key, IpcSigner, SignedIpcMessage};

        let key = generate_session_key();
        let signer = IpcSigner::new(&key);

        let msg = b"null\x00bytes\x00in\x00message".to_vec();
        let signed = SignedIpcMessage::serialize_signed(&msg, &signer).unwrap();
        let decoded: Vec<u8> = SignedIpcMessage::deserialize_signed(&signed, &signer).unwrap();
        assert_eq!(msg, decoded);
    }

    // ── Phase L.1: Message Roundtrip Coverage ────────────────────────

    // Helper macro for simple roundtrip tests
    macro_rules! roundtrip_test {
        ($name:ident, $msg:expr) => {
            #[test]
            fn $name() {
                let json = serde_json::to_string(&$msg).unwrap();
                let decoded: Message = serde_json::from_str(&json).unwrap();
                assert!(matches!(decoded, _));
            }
        };
    }

    // Worker Lifecycle Messages
    roundtrip_test!(
        test_roundtrip_worker_started_full,
        Message::WorkerStarted {
            id: WorkerId(0),
            pid: 12345,
            port: 8080,
            timestamp: 1234567890,
        }
    );

    roundtrip_test!(
        test_roundtrip_worker_ready_full,
        Message::WorkerReady { id: WorkerId(0) }
    );

    roundtrip_test!(
        test_roundtrip_worker_shutdown_complete_full,
        Message::WorkerShutdownComplete { id: WorkerId(7) }
    );

    roundtrip_test!(
        test_roundtrip_worker_heartbeat_full,
        Message::WorkerHeartbeat {
            id: WorkerId(1),
            timestamp: 1000,
            metrics: WorkerMetricsPayload::default(),
        }
    );

    roundtrip_test!(
        test_roundtrip_worker_request_log,
        Message::WorkerRequestLog {
            id: WorkerId(1),
            log: RequestLogPayload {
                timestamp: 1000,
                client_ip: "192.168.1.1".to_string(),
                method: "GET".to_string(),
                path: "/test".to_string(),
                status: 200,
                response_time_ms: 50,
                site_id: "test-site".to_string(),
                user_agent: Some("TestAgent/1.0".to_string()),
                bytes_sent: 1024,
                bytes_received: 256,
            },
        }
    );

    // Master Command Messages
    roundtrip_test!(
        test_roundtrip_master_shutdown_full,
        Message::MasterShutdown {
            graceful: true,
            timeout_secs: 30,
        }
    );

    roundtrip_test!(
        test_roundtrip_master_config_reload_full,
        Message::MasterConfigReload {
            config_path: "/etc/synvoid/main.toml".to_string(),
        }
    );

    roundtrip_test!(
        test_roundtrip_master_health_check,
        Message::MasterHealthCheck { timestamp: 9999999 }
    );

    roundtrip_test!(
        test_roundtrip_master_resize_threadpool_full,
        Message::MasterResizeThreadpool { worker_threads: 16 }
    );

    roundtrip_test!(test_roundtrip_master_cert_reload, Message::MasterCertReload);

    // Static Worker Messages (renamed to CpuWorker)
    roundtrip_test!(
        test_roundtrip_cpu_worker_started_full,
        Message::CpuWorkerStarted {
            worker_id: 2,
            pid: 5678,
        }
    );

    roundtrip_test!(
        test_roundtrip_cpu_worker_ready_full,
        Message::CpuWorkerReady { worker_id: 42 }
    );

    roundtrip_test!(
        test_roundtrip_cpu_worker_heartbeat,
        Message::CpuWorkerHeartbeat {
            worker_id: 1,
            timestamp: 1000,
            static_cache_hits: 500,
            static_cache_misses: 50,
            cpu_offload_stats: synvoid::process::ipc::CpuOffloadStats::default(),
        }
    );

    roundtrip_test!(
        test_roundtrip_cpu_worker_request_log,
        Message::CpuWorkerRequestLog {
            worker_id: 1,
            log: RequestLogPayload {
                timestamp: 1000,
                client_ip: "10.0.0.1".to_string(),
                method: "POST".to_string(),
                path: "/api/upload".to_string(),
                status: 201,
                response_time_ms: 100,
                site_id: "static-site".to_string(),
                user_agent: None,
                bytes_sent: 2048,
                bytes_received: 512,
            },
        }
    );

    roundtrip_test!(
        test_roundtrip_cpu_worker_shutdown_complete_full,
        Message::CpuWorkerShutdownComplete { worker_id: 3 }
    );

    roundtrip_test!(
        test_roundtrip_cpu_worker_background_tasks_done,
        Message::CpuWorkerBackgroundTasksDone { worker_id: 5 }
    );

    roundtrip_test!(
        test_roundtrip_cpu_worker_resize_ack_full,
        Message::CpuWorkerResizeAck {
            worker_id: 2,
            worker_threads: 8,
        }
    );

    roundtrip_test!(
        test_roundtrip_cpu_worker_scan,
        Message::CpuWorkerScan {
            site_id: "test-site".to_string(),
        }
    );

    roundtrip_test!(
        test_roundtrip_cpu_worker_cache_update,
        Message::CpuWorkerCacheUpdate {
            site_id: "test-site".to_string(),
            path: "/var/www/html".to_string(),
            minified_path: "/var/www/html.min".to_string(),
        }
    );

    roundtrip_test!(
        test_roundtrip_cpu_worker_drain_full,
        Message::CpuWorkerDrain {
            timeout_secs: 30,
            drain_id: 12345,
        }
    );

    roundtrip_test!(
        test_roundtrip_cpu_worker_drained_full,
        Message::CpuWorkerDrained {
            worker_id: 1,
            remaining_tasks: 0,
            drain_id: 12345,
        }
    );

    roundtrip_test!(
        test_roundtrip_cpu_worker_drain_status,
        Message::CpuWorkerDrainStatus {
            drain_id: 999,
            is_draining: true,
            active_tasks: 5,
            drain_complete: false,
        }
    );

    // Threat Intel Messages
    roundtrip_test!(
        test_roundtrip_threat_indicator_announce,
        Message::ThreatIndicatorAnnounce {
            worker_id: 1,
            threat_type: ThreatIndicatorType::IpBlock,
            indicator_value: "192.168.1.100".to_string(),
            severity: ThreatSeverityLevel::High,
            reason: "brute force attack".to_string(),
            ttl_seconds: 3600,
            site_scope: "global".to_string(),
            rate_limit_requests: Some(100),
            rate_limit_window_secs: Some(60),
            suspicious_pattern: Some("rapid_login".to_string()),
        }
    );

    roundtrip_test!(
        test_roundtrip_threat_indicator_from_mesh,
        Message::ThreatIndicatorFromMesh {
            worker_id: 1,
            source_node_id: "global-node-1".to_string(),
            threat_type: ThreatIndicatorType::SuspiciousActivity,
            indicator_value: "10.0.0.50".to_string(),
            severity: ThreatSeverityLevel::Medium,
            reason: "anomaly detected".to_string(),
            ttl_seconds: 1800,
            site_scope: "test-site".to_string(),
        }
    );

    roundtrip_test!(
        test_roundtrip_threat_sync_request_full,
        Message::ThreatSyncRequest {
            worker_id: 1,
            from_version: 10,
        }
    );

    roundtrip_test!(
        test_roundtrip_threat_sync_response,
        Message::ThreatSyncResponse {
            worker_id: 1,
            indicators: vec![ThreatIndicatorData {
                threat_type: ThreatIndicatorType::IpBlock,
                indicator_value: "1.2.3.4".to_string(),
                severity: ThreatSeverityLevel::Critical,
                reason: "test".to_string(),
                ttl_seconds: 3600,
                source_node_id: "test".to_string(),
                timestamp: 1000,
                site_scope: "global".to_string(),
                rate_limit_requests: None,
                rate_limit_window_secs: None,
                suspicious_pattern: None,
            }],
            version: 11,
        }
    );

    roundtrip_test!(
        test_roundtrip_blocklist_request_full,
        Message::BlocklistRequest {
            worker_id: 1,
            from_version: 5,
        }
    );

    roundtrip_test!(
        test_roundtrip_blocklist_response,
        Message::BlocklistResponse {
            worker_id: 1,
            blocks: vec![BlockEntryData {
                ip: "5.6.7.8".to_string(),
                reason: "manual block".to_string(),
                blocked_at: 1000,
                ban_expire_seconds: 3600,
                site_scope: "global".to_string(),
                provenance_kind: Some("AdminManual".to_string()),
                provenance_source: Some("test".to_string()),
            }],
            mesh_blocks: vec![],
            version: 6,
        }
    );

    roundtrip_test!(
        test_roundtrip_blocklist_update,
        Message::BlocklistUpdate {
            blocks: vec![BlockEntryData {
                ip: "9.9.9.9".to_string(),
                reason: "threat".to_string(),
                blocked_at: 2000,
                ban_expire_seconds: 7200,
                site_scope: "test".to_string(),
                provenance_kind: Some("MeshThreatIntelPolicyGated".to_string()),
                provenance_source: Some("threat_sync".to_string()),
            }],
            mesh_blocks: vec![],
            version: 7,
        }
    );

    roundtrip_test!(
        test_roundtrip_rule_patterns_update,
        Message::RulePatternsUpdate {
            version: "1.0.0".to_string(),
            patterns: vec![RulePatternData {
                category: "sql_injection".to_string(),
                patterns: vec!["' OR 1=1".to_string(), "\" OR \"\"=\"".to_string()],
            }],
        }
    );

    roundtrip_test!(
        test_roundtrip_blocklist_write_complete_full,
        Message::BlocklistWriteComplete {
            worker_id: 1,
            success: true,
        }
    );

    // Static Content Messages
    roundtrip_test!(
        test_roundtrip_minify_request_full,
        Message::MinifyRequest {
            request_id: 123,
            site_id: "test".to_string(),
            path: "/static/style.css".to_string(),
            encoding: Some("gzip".to_string()),
        }
    );

    roundtrip_test!(
        test_roundtrip_minify_response,
        Message::MinifyResponse {
            request_id: 123,
            site_id: "test".to_string(),
            path: "/static/style.css".to_string(),
            content: vec![0x43, 0x6F, 0x6E, 0x74, 0x65, 0x6E, 0x74],
            content_type: "text/css".to_string(),
            encoding: Some("gzip".to_string()),
            queued_encodings: vec!["br".to_string(), "zstd".to_string()],
        }
    );

    roundtrip_test!(
        test_roundtrip_minify_error_full,
        Message::MinifyError {
            request_id: 456,
            error: "Failed to parse CSS".to_string(),
        }
    );

    roundtrip_test!(
        test_roundtrip_image_rights_request,
        Message::PoisonImageRequest {
            request_id: 789,
            site_id: "gallery".to_string(),
            body: vec![0xFF, 0xD8, 0xFF, 0xE0],
            last_modified: Some("2024-01-01T00:00:00Z".to_string()),
            level: Some("light".to_string()),
            intensity: Some(0.5),
            seed: Some(42),
            max_dimension: Some(1920),
            jpeg_quality: Some(85),
        }
    );

    roundtrip_test!(
        test_roundtrip_image_rights_response,
        Message::PoisonImageResponse {
            request_id: 789,
            poisoned_body: vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00],
        }
    );

    roundtrip_test!(
        test_roundtrip_image_rights_error_full,
        Message::PoisonImageError {
            request_id: 999,
            error: "Image too large".to_string(),
        }
    );

    roundtrip_test!(
        test_roundtrip_get_compressed_request_full,
        Message::GetCompressedRequest {
            request_id: 111,
            site_id: "cdn".to_string(),
            path: "/assets/bundle.js".to_string(),
            encoding: "br".to_string(),
        }
    );

    roundtrip_test!(
        test_roundtrip_get_compressed_response,
        Message::GetCompressedResponse {
            request_id: 111,
            content: vec![0x1F, 0x8B],
        }
    );

    // App Server Messages
    roundtrip_test!(
        test_roundtrip_app_server_started,
        Message::AppServerStarted {
            id: WorkerId(0),
            site_id: "python-app".to_string(),
            socket_path: Some("/tmp/gunicorn.sock".to_string()),
            pid: 12345,
            timestamp: 1000,
        }
    );

    roundtrip_test!(
        test_roundtrip_app_server_ready_full,
        Message::AppServerReady {
            id: WorkerId(0),
            site_id: "python-app".to_string(),
        }
    );

    roundtrip_test!(
        test_roundtrip_app_server_health,
        Message::AppServerHealth {
            id: WorkerId(1),
            site_id: "python-app".to_string(),
            healthy: true,
            timestamp: 2000,
        }
    );

    roundtrip_test!(
        test_roundtrip_app_server_stopped,
        Message::AppServerStopped {
            id: WorkerId(0),
            site_id: "python-app".to_string(),
        }
    );

    roundtrip_test!(
        test_roundtrip_app_server_restarted,
        Message::AppServerRestarted {
            id: WorkerId(0),
            site_id: "python-app".to_string(),
            new_pid: 54321,
            timestamp: 3000,
        }
    );

    roundtrip_test!(
        test_roundtrip_app_server_error_full,
        Message::AppServerError {
            id: WorkerId(0),
            site_id: "python-app".to_string(),
            error: "Connection refused".to_string(),
        }
    );

    // Unified Server Messages
    roundtrip_test!(
        test_roundtrip_unified_server_worker_started_full,
        Message::UnifiedServerWorkerStarted {
            id: WorkerId(0),
            pid: 1111,
            timestamp: 100,
        }
    );

    roundtrip_test!(
        test_roundtrip_unified_server_worker_ready_full,
        Message::UnifiedServerWorkerReady { id: WorkerId(2) }
    );

    roundtrip_test!(
        test_roundtrip_unified_server_worker_heartbeat_full,
        Message::UnifiedServerWorkerHeartbeat {
            id: WorkerId(1),
            timestamp: 5000,
            metrics: WorkerMetricsPayload::default(),
        }
    );

    roundtrip_test!(
        test_roundtrip_unified_server_worker_shutdown_complete_full,
        Message::UnifiedServerWorkerShutdownComplete { id: WorkerId(3) }
    );

    roundtrip_test!(
        test_roundtrip_unified_server_worker_error_full,
        Message::UnifiedServerWorkerError {
            id: WorkerId(1),
            error: "connection lost".to_string(),
            severity: ErrorSeverity::Error,
            error_code: ErrorCode::Timeout,
        }
    );

    roundtrip_test!(
        test_roundtrip_unified_server_worker_drain_full,
        Message::UnifiedServerWorkerDrain {
            timeout_secs: 60,
            drain_id: 999,
        }
    );

    roundtrip_test!(
        test_roundtrip_unified_server_worker_drained_full,
        Message::UnifiedServerWorkerDrained {
            id: WorkerId(1),
            remaining_connections: 5,
            drain_id: 999,
        }
    );

    roundtrip_test!(
        test_roundtrip_unified_server_worker_resize_full,
        Message::UnifiedServerWorkerResize { worker_threads: 4 }
    );

    roundtrip_test!(
        test_roundtrip_unified_server_worker_resize_ack_full,
        Message::UnifiedServerWorkerResizeAck {
            id: WorkerId(1),
            worker_threads: 4,
        }
    );

    // Upgrade Messages
    roundtrip_test!(
        test_roundtrip_upgrade_ready,
        Message::UpgradeReady {
            mode: UpgradeModePayload::ReusePort,
            new_worker_ids: vec![WorkerId(0), WorkerId(1)],
        }
    );

    roundtrip_test!(
        test_roundtrip_upgrade_failed_full,
        Message::UpgradeFailed {
            error: "validation timeout".to_string(),
        }
    );

    roundtrip_test!(
        test_roundtrip_overseer_upgrade_prepare,
        Message::SupervisorUpgradePrepare {
            binary_path: "/usr/bin/synvoid-new".to_string(),
            config_path: Some("/etc/synvoid/new.toml".to_string()),
            version: "2.0.0".to_string(),
        }
    );

    roundtrip_test!(
        test_roundtrip_overseer_upgrade_prepare_ack_success,
        Message::SupervisorUpgradePrepareAck {
            ready: true,
            error: None,
        }
    );

    roundtrip_test!(
        test_roundtrip_overseer_upgrade_prepare_ack_error,
        Message::SupervisorUpgradePrepareAck {
            ready: false,
            error: Some("Binary incompatible".to_string()),
        }
    );

    roundtrip_test!(
        test_roundtrip_overseer_upgrade_commit_full,
        Message::SupervisorUpgradeCommit { timeout_secs: 120 }
    );

    roundtrip_test!(
        test_roundtrip_overseer_upgrade_commit_ack_success,
        Message::SupervisorUpgradeCommitAck {
            success: true,
            error: None,
        }
    );

    roundtrip_test!(
        test_roundtrip_overseer_upgrade_rollback_full,
        Message::SupervisorUpgradeRollback {
            reason: "Health check failed".to_string(),
        }
    );

    roundtrip_test!(
        test_roundtrip_overseer_upgrade_rollback_ack_success,
        Message::SupervisorUpgradeRollbackAck {
            success: true,
            error: None,
        }
    );

    roundtrip_test!(
        test_roundtrip_overseer_commit_upgrade,
        Message::SupervisorCommitUpgrade {
            old_supervisor_timeout_secs: 60
        }
    );

    roundtrip_test!(
        test_roundtrip_overseer_commit_upgrade_ack_full,
        Message::SupervisorCommitUpgradeAck {
            success: true,
            error: None,
        }
    );

    // Overseer Messages
    roundtrip_test!(
        test_roundtrip_overseer_drain_workers,
        Message::SupervisorDrainWorkers { timeout_secs: 30 }
    );

    roundtrip_test!(
        test_roundtrip_overseer_drain_workers_ack,
        Message::SupervisorDrainWorkersAck {
            drained_count: 4,
            remaining_connections: 10,
        }
    );

    roundtrip_test!(
        test_roundtrip_overseer_get_status,
        Message::SupervisorGetStatus
    );

    roundtrip_test!(
        test_roundtrip_overseer_status_response,
        Message::SupervisorStatusResponse {
            master_pid: 12345,
            workers: vec![WorkerStatusInfo {
                id: 0,
                pid: 11111,
                port: 8080,
                status: "running".to_string(),
                requests: 5000,
                blocked: 50,
            }],
            uptime_secs: 3600,
            version: "1.0.0".to_string(),
        }
    );

    roundtrip_test!(
        test_roundtrip_overseer_dual_master_prepare,
        Message::SupervisorDualSupervisorPrepare {
            binary_path: "/usr/bin/synvoid".to_string(),
            config_path: Some("/etc/synvoid/config.toml".to_string()),
            version: "2.0.0".to_string(),
        }
    );

    roundtrip_test!(
        test_roundtrip_overseer_dual_master_prepare_ack_success,
        Message::SupervisorDualSupervisorPrepareAck {
            ready: true,
            error: None,
        }
    );

    // Master Drain Messages
    roundtrip_test!(
        test_roundtrip_master_drain_mode,
        Message::MasterDrainMode {
            graceful_timeout_secs: 30,
            stop_accepting: true,
        }
    );

    roundtrip_test!(
        test_roundtrip_master_drain_mode_ack,
        Message::MasterDrainModeAck {
            accepted: true,
            active_connections: 5,
        }
    );

    roundtrip_test!(
        test_roundtrip_master_report_connections,
        Message::MasterReportConnections {}
    );

    roundtrip_test!(
        test_roundtrip_master_connections_report,
        Message::MasterConnectionsReport {
            active_connections: 10,
            idle_connections: 20,
            by_worker: vec![(WorkerId(0), 15), (WorkerId(1), 15)],
        }
    );

    roundtrip_test!(
        test_roundtrip_master_stop_accepting,
        Message::MasterStopAccepting {}
    );

    roundtrip_test!(
        test_roundtrip_master_stop_accepting_ack_full,
        Message::MasterStopAcceptingAck { success: true }
    );

    roundtrip_test!(
        test_roundtrip_master_drain_status,
        Message::MasterDrainStatus {
            is_draining: true,
            active_connections: 5,
            drain_elapsed_secs: 15,
        }
    );

    // Drain Protocol Messages
    roundtrip_test!(
        test_roundtrip_drain_request,
        Message::DrainRequest {
            timeout_secs: 30,
            drain_id: 12345,
        }
    );

    roundtrip_test!(
        test_roundtrip_drain_status_request,
        Message::DrainStatusRequest { drain_id: 12345 }
    );

    roundtrip_test!(
        test_roundtrip_drain_status_response,
        Message::DrainStatusResponse {
            drain_id: 12345,
            is_draining: true,
            active_connections: 3,
            idle_connections: 2,
            connections_drained: 10,
            drain_elapsed_secs: 20,
            drain_complete: false,
        }
    );

    roundtrip_test!(
        test_roundtrip_drain_complete_full,
        Message::DrainComplete {
            drain_id: 12345,
            worker_id: WorkerId(0),
            connections_drained: 15,
        }
    );

    roundtrip_test!(
        test_roundtrip_stop_accepting_full,
        Message::StopAccepting { drain_id: 999 }
    );

    roundtrip_test!(
        test_roundtrip_stop_accepting_ack_full,
        Message::StopAcceptingAck {
            drain_id: 999,
            accepted: true,
            active_connections: 2,
        }
    );

    roundtrip_test!(test_roundtrip_restore_from_drain, Message::RestoreFromDrain);

    roundtrip_test!(
        test_roundtrip_restore_from_drain_ack_success,
        Message::RestoreFromDrainAck { success: true }
    );

    // Worker Drain Messages
    roundtrip_test!(
        test_roundtrip_worker_drain_full,
        Message::WorkerDrain {
            id: WorkerId(0),
            timeout_secs: 30,
        }
    );

    roundtrip_test!(
        test_roundtrip_worker_drained_full,
        Message::WorkerDrained {
            id: WorkerId(0),
            remaining_connections: 0,
        }
    );

    roundtrip_test!(
        test_roundtrip_worker_connection_count,
        Message::WorkerConnectionCount {
            id: WorkerId(1),
            active: 10,
            idle: 5,
        }
    );

    roundtrip_test!(
        test_roundtrip_worker_drain_complete_full,
        Message::WorkerDrainComplete {
            id: WorkerId(0),
            connections_handled: 100,
        }
    );

    roundtrip_test!(
        test_roundtrip_worker_ready_for_traffic,
        Message::WorkerReadyForTraffic { id: WorkerId(0) }
    );

    roundtrip_test!(
        test_roundtrip_worker_resize_ack_full,
        Message::WorkerResizeAck {
            id: WorkerId(5),
            worker_threads: 8,
        }
    );

    roundtrip_test!(
        test_roundtrip_worker_cert_reload,
        Message::WorkerCertReload {
            id: WorkerId(0),
            domains: vec!["example.com".to_string(), "www.example.com".to_string()],
        }
    );

    // Socket Handoff Messages
    roundtrip_test!(
        test_roundtrip_socket_handoff_request_full,
        Message::SocketHandoffRequest {
            socket_path: "/tmp/handoff.sock".to_string(),
        }
    );

    roundtrip_test!(
        test_roundtrip_socket_handoff_ready_full,
        Message::SocketHandoffReady {
            ports: vec![8080, 8443]
        }
    );

    roundtrip_test!(
        test_roundtrip_socket_handoff_complete,
        Message::SocketHandoffComplete {
            success: true,
            fd_count: 3,
        }
    );

    roundtrip_test!(
        test_roundtrip_socket_handoff_failed_full,
        Message::SocketHandoffFailed {
            error: "Connection reset".to_string(),
        }
    );

    roundtrip_test!(
        test_roundtrip_windows_socket_info,
        Message::WindowsSocketInfo {
            protocol_info: vec![0x00, 0x01, 0x02],
            port: 8080,
        }
    );

    // Worker Restart Messages
    roundtrip_test!(
        test_roundtrip_restart_worker_request,
        Message::RestartWorkerRequest { id: WorkerId(0) }
    );

    roundtrip_test!(
        test_roundtrip_restart_worker_response_success,
        Message::RestartWorkerResponse {
            id: WorkerId(0),
            success: true,
            error: None,
        }
    );

    roundtrip_test!(
        test_roundtrip_restart_worker_response_failure,
        Message::RestartWorkerResponse {
            id: WorkerId(0),
            success: false,
            error: Some("Worker not responding".to_string()),
        }
    );

    // Plugin Messages
    roundtrip_test!(
        test_roundtrip_plugin_state_sync,
        Message::PluginStateSync {
            plugin_name: "rate_limiter".to_string(),
            wasm_module_data: vec![0x00, 0x61, 0x73, 0x6D],
        }
    );

    #[test]
    fn test_message_category_classification() {
        let worker_msg = Message::WorkerStarted {
            id: WorkerId(1),
            pid: 100,
            port: 8080,
            timestamp: 0,
        };
        assert!(worker_msg.is_lifecycle());
        assert!(!worker_msg.is_drain());

        let shutdown = Message::WorkerShutdownComplete { id: WorkerId(1) };
        assert!(shutdown.is_lifecycle());
        assert!(!shutdown.is_drain());
    }

    #[test]
    fn test_ipc_message_validation_edge_cases() {
        use synvoid::process::Message;

        let empty_error = Message::WorkerError {
            id: WorkerId(1),
            error: String::new(),
            severity: synvoid::process::ErrorSeverity::Warning,
            error_code: synvoid::process::ErrorCode::Unknown,
        };
        assert!(empty_error.validate().is_ok());

        let max_path = Message::MasterConfigReload {
            config_path: "/a".repeat(100),
        };
        assert!(max_path.validate().is_ok());

        let very_long_path = Message::MasterConfigReload {
            config_path: "x".repeat(10000),
        };
        assert!(very_long_path.validate().is_err());
    }

    // ── Iteration 50: IPC provenance preservation tests ──────────────

    #[test]
    fn test_block_entry_data_preserves_provenance_roundtrip() {
        let entry = BlockEntryData {
            ip: "10.0.0.1".to_string(),
            reason: "admin ban".to_string(),
            blocked_at: 1000,
            ban_expire_seconds: 3600,
            site_scope: "global".to_string(),
            provenance_kind: Some("AdminManual".to_string()),
            provenance_source: Some("admin_ban_ip".to_string()),
        };

        let msg = Message::BlocklistResponse {
            worker_id: 1,
            blocks: vec![entry],
            mesh_blocks: vec![],
            version: 1,
        };

        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: Message = serde_json::from_str(&json).unwrap();

        match deserialized {
            Message::BlocklistResponse { blocks, .. } => {
                assert_eq!(blocks.len(), 1);
                assert_eq!(blocks[0].provenance_kind, Some("AdminManual".to_string()));
                assert_eq!(
                    blocks[0].provenance_source,
                    Some("admin_ban_ip".to_string())
                );
            }
            _ => panic!("Expected BlocklistResponse"),
        }
    }

    #[test]
    fn test_block_entry_data_legacy_missing_provenance_defaults() {
        // Legacy messages without provenance fields should deserialize with None
        let json = r#"{"BlocklistResponse":{"worker_id":1,"blocks":[{"ip":"1.2.3.4","reason":"test","blocked_at":0,"ban_expire_seconds":3600,"site_scope":"global"}],"mesh_blocks":[],"version":1}}"#;
        let msg: Message = serde_json::from_str(json).unwrap();

        match msg {
            Message::BlocklistResponse { blocks, .. } => {
                assert_eq!(blocks.len(), 1);
                assert_eq!(blocks[0].provenance_kind, None);
                assert_eq!(blocks[0].provenance_source, None);
            }
            _ => panic!("Expected BlocklistResponse"),
        }
    }

    #[test]
    fn test_mesh_block_entry_data_preserves_provenance_roundtrip() {
        let entry = synvoid::process::ipc::MeshBlockEntryData {
            mesh_id: "node-abc".to_string(),
            reason: "threat intel".to_string(),
            blocked_at: 2000,
            ban_expire_seconds: 7200,
            site_scope: "global".to_string(),
            provenance_kind: Some("MeshThreatIntelPolicyGated".to_string()),
            provenance_source: Some("threat_sync".to_string()),
        };

        let msg = Message::BlocklistResponse {
            worker_id: 1,
            blocks: vec![],
            mesh_blocks: vec![entry],
            version: 1,
        };

        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: Message = serde_json::from_str(&json).unwrap();

        match deserialized {
            Message::BlocklistResponse { mesh_blocks, .. } => {
                assert_eq!(mesh_blocks.len(), 1);
                assert_eq!(
                    mesh_blocks[0].provenance_kind,
                    Some("MeshThreatIntelPolicyGated".to_string())
                );
                assert_eq!(
                    mesh_blocks[0].provenance_source,
                    Some("threat_sync".to_string())
                );
            }
            _ => panic!("Expected BlocklistResponse"),
        }
    }

    #[test]
    fn test_blocklist_update_preserves_provenance_roundtrip() {
        let msg = Message::BlocklistUpdate {
            blocks: vec![BlockEntryData {
                ip: "10.0.0.2".to_string(),
                reason: "threat".to_string(),
                blocked_at: 3000,
                ban_expire_seconds: 1800,
                site_scope: "global".to_string(),
                provenance_kind: Some("LocalWaf".to_string()),
                provenance_source: Some("waf_block".to_string()),
            }],
            mesh_blocks: vec![],
            version: 2,
        };

        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: Message = serde_json::from_str(&json).unwrap();

        match deserialized {
            Message::BlocklistUpdate { blocks, .. } => {
                assert_eq!(blocks[0].provenance_kind, Some("LocalWaf".to_string()));
                assert_eq!(blocks[0].provenance_source, Some("waf_block".to_string()));
            }
            _ => panic!("Expected BlocklistUpdate"),
        }
    }
}
