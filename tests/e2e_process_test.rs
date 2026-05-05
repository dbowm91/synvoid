#[cfg(unix)]
mod e2e_process_tests {
    use std::sync::Arc;

    use synvoid::config::OverseerConfig;
    use synvoid::process::ipc::{MessageCategory, UpgradeModePayload};
    use synvoid::process::ipc_transport::{IpcEndpoint, IpcListener, IpcStream};
    use synvoid::process::{
        generate_session_key, ErrorCode, ErrorSeverity, IpcSigner, Message, WorkerId,
    };
    use tempfile::TempDir;

    fn temp_endpoint(temp_dir: &TempDir, name: &str) -> IpcEndpoint {
        let socket_path = temp_dir.path().join(format!("{}.sock", name));
        let endpoint_str = socket_path.to_string_lossy().to_string();
        IpcEndpoint::new(&endpoint_str)
    }

    // --- IPC Transport Tests ---

    #[tokio::test]
    async fn test_ipc_listener_bind_accept() {
        let temp_dir = TempDir::new().unwrap();
        let endpoint = temp_endpoint(&temp_dir, "bind-accept");

        let listener = IpcListener::bind(&endpoint).await.unwrap();

        let connect_handle = tokio::spawn(async move { endpoint.connect().await.unwrap() });

        let server_stream = listener.accept().await.unwrap();
        let client_stream = connect_handle.await.unwrap();

        assert!(!server_stream.is_signed());
        assert!(!client_stream.is_signed());
    }

    #[tokio::test]
    async fn test_ipc_stream_signed_send_recv() {
        let temp_dir = TempDir::new().unwrap();
        let endpoint = temp_endpoint(&temp_dir, "signed");

        let key = generate_session_key();
        let server_signer = Arc::new(IpcSigner::new(&key));
        let client_signer = Arc::new(IpcSigner::new(&key));

        let listener = IpcListener::bind(&endpoint).await.unwrap();

        let signer_clone = client_signer.clone();
        let connect_handle =
            tokio::spawn(async move { endpoint.connect_with_signer(signer_clone).await.unwrap() });

        let server_stream = listener.accept().await.unwrap();
        let mut server_stream = IpcStream::from_unix_stream_with_signer(
            server_stream.into_inner().unix,
            server_signer.clone(),
        );
        let client_stream = connect_handle.await.unwrap();

        assert!(server_stream.is_signed());
        assert!(client_stream.is_signed());

        let msg = Message::WorkerStarted {
            id: WorkerId(1),
            pid: 42,
            port: 8080,
            timestamp: 1000,
        };
        let signed_data =
            synvoid::process::SignedIpcMessage::serialize_signed(&msg, &client_signer).unwrap();
        let decoded: Message =
            synvoid::process::SignedIpcMessage::deserialize_signed(&signed_data, &server_signer)
                .unwrap();
        match decoded {
            Message::WorkerStarted {
                id,
                pid,
                port,
                timestamp,
            } => {
                assert_eq!(id, WorkerId(1));
                assert_eq!(pid, 42);
                assert_eq!(port, 8080);
                assert_eq!(timestamp, 1000);
            }
            _ => panic!("expected WorkerStarted"),
        }

        let wrong_key = generate_session_key();
        let wrong_signer = IpcSigner::new(&wrong_key);
        let bad_result: Result<Message, _> =
            synvoid::process::SignedIpcMessage::deserialize_signed(&signed_data, &wrong_signer);
        assert!(bad_result.is_err());
    }

    #[tokio::test]
    async fn test_ipc_stream_recv_timeout() {
        let temp_dir = TempDir::new().unwrap();
        let endpoint = temp_endpoint(&temp_dir, "timeout");

        let listener = IpcListener::bind(&endpoint).await.unwrap();

        let connect_handle = tokio::spawn(async move { endpoint.connect().await.unwrap() });

        let mut server_stream = listener.accept().await.unwrap();
        let _client_stream = connect_handle.await.unwrap();

        let result: Option<Message> = server_stream.recv_with_timeout(50).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_ipc_endpoint_connect_failure() {
        let temp_dir = TempDir::new().unwrap();
        let endpoint = temp_endpoint(&temp_dir, "nonexistent");

        let result = endpoint.connect().await;
        assert!(result.is_err());
    }

    // --- Process Config Tests ---

    #[test]
    fn test_overseer_config_defaults() {
        let config = OverseerConfig::default();
        assert!(config.auto_restart);
        assert_eq!(config.restart_delay_secs, 5);
        assert_eq!(config.max_restart_attempts, 5);
        assert_eq!(config.health_check_interval_secs, 5);
        assert_eq!(config.stable_uptime_secs, 60);
        assert_eq!(config.ipc_read_timeout_ms, 5000);
        assert_eq!(config.ipc_write_timeout_ms, 5000);
        assert_eq!(config.master_startup_timeout_secs, 30);
    }

    #[test]
    fn test_overseer_config_auto_restart() {
        let config = OverseerConfig::default();
        assert!(config.auto_restart);
    }

    // --- State Tracking Tests ---

    #[test]
    fn test_worker_id_operations() {
        let id0 = WorkerId(0);
        let id1 = WorkerId(1);
        let id0_copy = WorkerId(0);

        assert_eq!(id0, id0_copy);
        assert_ne!(id0, id1);
        assert_eq!(id0.as_usize(), 0);
        assert_eq!(id1.as_usize(), 1);
        assert_eq!(id0.to_string(), "0");
        assert_eq!(id1.to_string(), "1");
    }

    #[test]
    fn test_message_serialization_roundtrip() {
        let messages = vec![
            Message::WorkerStarted {
                id: WorkerId(1),
                pid: 1234,
                port: 8080,
                timestamp: 42,
            },
            Message::WorkerReady { id: WorkerId(2) },
            Message::WorkerError {
                id: WorkerId(3),
                error: "something broke".to_string(),
                severity: ErrorSeverity::Critical,
                error_code: ErrorCode::WorkerPanic,
            },
            Message::WorkerShutdownComplete { id: WorkerId(4) },
            Message::MasterConfigReload {
                config_path: "/etc/synvoid/config.toml".to_string(),
            },
            Message::MasterHealthCheck { timestamp: 9999 },
            Message::HealthCheckAck { timestamp: 10000 },
        ];

        for msg in messages {
            let serialized = serde_json::to_string(&msg).unwrap();
            let deserialized: Message = serde_json::from_str(&serialized).unwrap();
            assert_eq!(
                format!("{:?}", msg),
                format!("{:?}", deserialized),
                "roundtrip failed for variant"
            );
        }
    }

    #[test]
    fn test_message_category() {
        assert_eq!(
            Message::WorkerStarted {
                id: WorkerId(0),
                pid: 0,
                port: 0,
                timestamp: 0,
            }
            .category(),
            MessageCategory::WorkerLifecycle
        );

        assert_eq!(
            Message::WorkerReady { id: WorkerId(0) }.category(),
            MessageCategory::WorkerLifecycle
        );

        assert_eq!(
            Message::MasterShutdown {
                graceful: true,
                timeout_secs: 30,
            }
            .category(),
            MessageCategory::MasterCommand
        );

        assert_eq!(
            Message::MasterConfigReload {
                config_path: "x".into()
            }
            .category(),
            MessageCategory::MasterCommand
        );

        assert_eq!(
            Message::OverseerGetStatus.category(),
            MessageCategory::Overseer
        );

        assert_eq!(
            Message::WorkerDrain {
                id: WorkerId(0),
                timeout_secs: 30,
            }
            .category(),
            MessageCategory::WorkerDrain
        );

        assert_eq!(
            Message::UpgradeReady {
                mode: UpgradeModePayload::ReusePort,
                new_worker_ids: vec![],
            }
            .category(),
            MessageCategory::Upgrade
        );

        assert_eq!(
            Message::SocketHandoffRequest {
                socket_path: "/tmp/test".into()
            }
            .category(),
            MessageCategory::SocketHandoff
        );
    }

    #[test]
    fn test_message_is_lifecycle() {
        assert!(Message::WorkerStarted {
            id: WorkerId(0),
            pid: 0,
            port: 0,
            timestamp: 0,
        }
        .is_lifecycle());

        assert!(Message::WorkerReady { id: WorkerId(0) }.is_lifecycle());

        assert!(Message::WorkerShutdownComplete { id: WorkerId(0) }.is_lifecycle());

        assert!(Message::StaticWorkerStarted {
            worker_id: 0,
            pid: 0,
        }
        .is_lifecycle());

        assert!(Message::UnifiedServerWorkerStarted {
            id: WorkerId(0),
            pid: 0,
            timestamp: 0,
        }
        .is_lifecycle());

        assert!(!Message::MasterShutdown {
            graceful: true,
            timeout_secs: 30,
        }
        .is_lifecycle());

        assert!(!Message::MasterHealthCheck { timestamp: 0 }.is_lifecycle());

        assert!(!Message::OverseerGetStatus.is_lifecycle());

        assert!(!Message::WorkerDrain {
            id: WorkerId(0),
            timeout_secs: 30,
        }
        .is_lifecycle());
    }

    // --- Process Lifecycle Simulation Tests ---

    #[tokio::test]
    async fn test_worker_lifecycle_messages() {
        let temp_dir = TempDir::new().unwrap();
        let endpoint = temp_endpoint(&temp_dir, "lifecycle");

        let listener = IpcListener::bind(&endpoint).await.unwrap();

        let worker_handle = tokio::spawn(async move {
            let mut stream = endpoint.connect().await.unwrap();

            let started = Message::WorkerStarted {
                id: WorkerId(0),
                pid: std::process::id(),
                port: 9000,
                timestamp: 1000,
            };
            stream.send(&started).await.unwrap();

            let ack: Message = stream.recv().await.unwrap().unwrap();
            match ack {
                Message::HealthCheckAck { timestamp } => assert_eq!(timestamp, 1000),
                other => panic!("expected HealthCheckAck, got {:?}", format!("{:?}", other)),
            }

            let ready = Message::WorkerReady { id: WorkerId(0) };
            stream.send(&ready).await.unwrap();
        });

        let mut master_stream = listener.accept().await.unwrap();

        let started_msg: Message = master_stream.recv().await.unwrap().unwrap();
        match started_msg {
            Message::WorkerStarted {
                id,
                pid,
                port,
                timestamp,
            } => {
                assert_eq!(id, WorkerId(0));
                assert!(pid > 0);
                assert_eq!(port, 9000);
                assert_eq!(timestamp, 1000);
            }
            _ => panic!("expected WorkerStarted"),
        }

        let ack = Message::HealthCheckAck { timestamp: 1000 };
        master_stream.send(&ack).await.unwrap();

        let ready_msg: Message = master_stream.recv().await.unwrap().unwrap();
        match ready_msg {
            Message::WorkerReady { id } => assert_eq!(id, WorkerId(0)),
            _ => panic!("expected WorkerReady"),
        }

        worker_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_multiple_worker_connections() {
        let temp_dir = TempDir::new().unwrap();
        let endpoint = temp_endpoint(&temp_dir, "multi-worker");

        let listener = IpcListener::bind(&endpoint).await.unwrap();

        let worker_count = 4;
        let mut worker_handles = Vec::new();

        for i in 0..worker_count {
            let endpoint_clone = IpcEndpoint::new(&endpoint.name().to_string());
            let handle = tokio::spawn(async move {
                let mut stream = endpoint_clone.connect().await.unwrap();
                let msg = Message::WorkerStarted {
                    id: WorkerId(i),
                    pid: std::process::id(),
                    port: 9000 + i as u16,
                    timestamp: (i as u64) * 1000,
                };
                stream.send(&msg).await.unwrap();

                let ack: Message = stream.recv().await.unwrap().unwrap();
                match ack {
                    Message::HealthCheckAck { .. } => {}
                    other => panic!("unexpected response: {:?}", format!("{:?}", other)),
                }
            });
            worker_handles.push(handle);
        }

        let mut master_streams = Vec::new();
        for _ in 0..worker_count {
            let stream = listener.accept().await.unwrap();
            master_streams.push(stream);
        }

        for (i, stream) in master_streams.iter_mut().enumerate() {
            let msg: Message = stream.recv().await.unwrap().unwrap();
            match msg {
                Message::WorkerStarted { id, port, .. } => {
                    assert_eq!(id.as_usize(), i);
                    assert_eq!(port, 9000 + i as u16);
                }
                _ => panic!("expected WorkerStarted"),
            }

            let ack = Message::HealthCheckAck {
                timestamp: (i as u64) * 1000,
            };
            stream.send(&ack).await.unwrap();
        }

        for handle in worker_handles {
            handle.await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_graceful_shutdown_sequence() {
        let temp_dir = TempDir::new().unwrap();
        let endpoint = temp_endpoint(&temp_dir, "shutdown");

        let listener = IpcListener::bind(&endpoint).await.unwrap();

        let worker_handle = tokio::spawn(async move {
            let mut stream = endpoint.connect().await.unwrap();

            let started = Message::WorkerStarted {
                id: WorkerId(0),
                pid: std::process::id(),
                port: 9000,
                timestamp: 0,
            };
            stream.send(&started).await.unwrap();

            let _ack: Message = stream.recv().await.unwrap().unwrap();

            let ready = Message::WorkerReady { id: WorkerId(0) };
            stream.send(&ready).await.unwrap();

            let shutdown: Message = stream.recv().await.unwrap().unwrap();
            match shutdown {
                Message::WorkerDrain { id, timeout_secs } => {
                    assert_eq!(id, WorkerId(0));
                    assert_eq!(timeout_secs, 30);
                }
                other => panic!("expected WorkerDrain, got {:?}", format!("{:?}", other)),
            }

            let drained = Message::WorkerDrained {
                id: WorkerId(0),
                remaining_connections: 0,
            };
            stream.send(&drained).await.unwrap();

            let shutdown_complete = Message::WorkerShutdownComplete { id: WorkerId(0) };
            stream.send(&shutdown_complete).await.unwrap();
        });

        let mut master_stream = listener.accept().await.unwrap();

        let _: Message = master_stream.recv().await.unwrap().unwrap();
        master_stream
            .send(&Message::HealthCheckAck { timestamp: 0 })
            .await
            .unwrap();
        let _: Message = master_stream.recv().await.unwrap().unwrap();

        let drain = Message::WorkerDrain {
            id: WorkerId(0),
            timeout_secs: 30,
        };
        master_stream.send(&drain).await.unwrap();

        let drained_msg: Message = master_stream.recv().await.unwrap().unwrap();
        match drained_msg {
            Message::WorkerDrained {
                id,
                remaining_connections,
            } => {
                assert_eq!(id, WorkerId(0));
                assert_eq!(remaining_connections, 0);
            }
            _ => panic!("expected WorkerDrained"),
        }

        let shutdown_complete: Message = master_stream.recv().await.unwrap().unwrap();
        match shutdown_complete {
            Message::WorkerShutdownComplete { id } => assert_eq!(id, WorkerId(0)),
            _ => panic!("expected WorkerShutdownComplete"),
        }

        worker_handle.await.unwrap();
    }
}
