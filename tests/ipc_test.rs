#[cfg(unix)]
mod ipc_tests {
    use maluwaf::process::ipc_transport::IpcStream;
    use maluwaf::process::{IpcEndpoint, Message, WorkerId};
    use tempfile::TempDir;
    use tokio::net::UnixListener;

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
