#[cfg(unix)]
mod ipc_tests {
    use maluwaf::process::ipc_transport::IpcStream;
    use maluwaf::process::{IpcEndpoint, Message, WorkerId};
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn test_ipc_unix_socket_send_recv() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test_ipc.sock");

        let listener = UnixListener::bind(&socket_path).unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_be_bytes(len_buf) as usize;

            let mut data = vec![0u8; len];
            stream.read_exact(&mut data).await.unwrap();

            stream.write_all(&len_buf).await.unwrap();
            stream.write_all(&data).await.unwrap();
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
            let (mut stream, _) = listener.accept().await.unwrap();

            for _ in 0..3usize {
                let mut len_buf = [0u8; 4];
                stream.read_exact(&mut len_buf).await.unwrap();
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut data: Vec<u8> = vec![0u8; len];
                stream.read_exact(&mut data).await.unwrap();

                stream.write_all(&len_buf).await.unwrap();
                stream.write_all(&data).await.unwrap();
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

                let _received: Message = ipc_stream.recv().await.unwrap().unwrap();
            }
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

        // Test WorkerError with too long error string
        let long_error = "x".repeat(100_000);
        let msg = Message::WorkerError {
            id: WorkerId(1),
            error: long_error,
            severity: ErrorSeverity::Error,
            error_code: ErrorCode::Unknown,
        };
        let result = msg.validate();
        assert!(result.is_err());

        // Test with valid length
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

        // Verify it works
        let decoded: Vec<u8> = SignedIpcMessage::deserialize_signed(&signed, &signer).unwrap();
        assert_eq!(msg, decoded);

        // Verify wrong key fails
        let wrong_key = generate_session_key();
        let wrong_signer = IpcSigner::new(&wrong_key);
        let result: Result<Vec<u8>, _> =
            SignedIpcMessage::deserialize_signed(&signed, &wrong_signer);
        assert!(result.is_err());

        // Verify tampered message fails
        let mut tampered = signed.clone();
        tampered[10] ^= 0xFF;
        let result: Result<Vec<u8>, _> = SignedIpcMessage::deserialize_signed(&tampered, &signer);
        assert!(result.is_err());
    }
}
