#[cfg(unix)]
mod ipc_tests {
    use maluwaf::process::ipc_transport::IpcStream;
    use maluwaf::process::{IpcEndpoint, Message, WorkerId};
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
            severity: maluwaf::process::ErrorSeverity::Error,
            error_code: maluwaf::process::ErrorCode::Unknown,
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
                assert_eq!(severity, maluwaf::process::ErrorSeverity::Error);
                assert_eq!(error_code, maluwaf::process::ErrorCode::Unknown);
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
            config_path: "/etc/maluwaf/main.toml".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        match decoded {
            Message::MasterConfigReload { config_path } => {
                assert_eq!(config_path, "/etc/maluwaf/main.toml");
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
    fn test_roundtrip_static_worker_started() {
        let msg = Message::StaticWorkerStarted {
            worker_id: 2,
            pid: 5678,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            decoded,
            Message::StaticWorkerStarted {
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
        assert!(path.to_string_lossy().contains("maluwaf"));
    }

    #[test]
    fn test_ipc_message_validation_rejects_long_strings() {
        use maluwaf::process::{ErrorCode, ErrorSeverity, Message, WorkerId};

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
        use maluwaf::process::Message;

        let long_path = "/".repeat(5000);
        let msg = Message::MasterConfigReload {
            config_path: long_path,
        };
        let result = msg.validate();
        assert!(result.is_err());

        let valid_msg = Message::MasterConfigReload {
            config_path: "/etc/maluwaf/config.toml".to_string(),
        };
        assert!(valid_msg.validate().is_ok());
    }

    #[test]
    fn test_ipc_signed_message_hmac_verification() {
        use maluwaf::process::ipc_signed::{generate_session_key, IpcSigner, SignedIpcMessage};

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

    #[test]
    fn test_ipc_message_category_classification() {
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
        use maluwaf::process::Message;

        let empty_error = Message::WorkerError {
            id: WorkerId(1),
            error: String::new(),
            severity: maluwaf::process::ErrorSeverity::Warning,
            error_code: maluwaf::process::ErrorCode::Unknown,
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
}
