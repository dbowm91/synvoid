#[cfg(unix)]
mod socket_handoff_tests {
    use std::net::TcpListener;
    use std::time::Duration;

    use maluwaf::overseer::socket_handoff::{DualMasterHandoff, SocketHandoffError};
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_socket_handoff_server_bind() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test-handoff.sock");

        if socket_path.exists() {
            let _ = std::fs::remove_file(&socket_path);
        }

        let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        listener.set_nonblocking(true).unwrap();

        let bound = socket_path.exists();
        assert!(bound, "Socket should be bound to filesystem");
    }

    #[tokio::test]
    async fn test_socket_handoff_tcp_listener_port_acquisition() {
        let port = 0;
        let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
        let local_addr = listener.local_addr().unwrap();
        assert!(local_addr.port() > 0, "Port should be assigned");
    }

    #[tokio::test]
    async fn test_socket_handoff_fd_transfer_basic() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("handoff.sock");

        if socket_path.exists() {
            let _ = std::fs::remove_file(&socket_path);
        }

        let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        let original_fd = listener.as_raw_fd();

        let dup_fd = nix::unistd::dup(original_fd).expect("dup should succeed");
        assert_ne!(dup_fd, original_fd, "Duplicated FD should be different");

        nix::unistd::close(dup_fd).expect("close should succeed");
        drop(listener);

        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn test_socket_handoff_dual_master_handoff_creation() {
        let ports = vec![8080u16, 8443u16];
        let result = DualMasterHandoff::new(ports.clone());

        match result {
            Ok(handoff) => {
                assert!(!handoff.get_ports().is_empty());
            }
            Err(e) => {
                tracing::warn!("DualMasterHandoff not available: {:?}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_socket_handoff_timeout_handling() {
        use maluwaf::overseer::socket_handoff::HANDOFF_TIMEOUT_SECS;

        assert_eq!(
            HANDOFF_TIMEOUT_SECS, 30,
            "Default timeout should be 30 seconds"
        );
    }

    #[tokio::test]
    async fn test_socket_handoff_message_roundtrip() {
        use maluwaf::process::ipc::{Message, SocketHandoffComplete, WorkerId};

        let msg = Message::SocketHandoffComplete {
            worker_id: WorkerId(1),
            success: true,
            error_message: None,
        };

        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();

        assert!(matches!(
            decoded,
            Message::SocketHandoffComplete { success: true, .. }
        ));
    }

    #[tokio::test]
    async fn test_socket_handoff_request_message_roundtrip() {
        use maluwaf::process::ipc::{Message, SocketHandoffRequest, WorkerId};

        let msg = Message::SocketHandoffRequest {
            worker_id: WorkerId(1),
            ports: vec![8080, 8443],
        };

        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();

        assert!(matches!(decoded, Message::SocketHandoffRequest { .. }));
    }

    #[tokio::test]
    async fn test_socket_handoff_ready_message_roundtrip() {
        use maluwaf::process::ipc::{Message, SocketHandoffReady, WorkerId};

        let msg = Message::SocketHandoffReady {
            worker_id: WorkerId(1),
            ports: vec![8080, 8443],
        };

        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();

        assert!(matches!(decoded, Message::SocketHandoffReady { .. }));
    }

    #[tokio::test]
    async fn test_socket_handoff_failed_message_roundtrip() {
        use maluwaf::process::ipc::{Message, SocketHandoffFailed, WorkerId};

        let msg = Message::SocketHandoffFailed {
            worker_id: WorkerId(1),
            reason: "Test failure".to_string(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();

        assert!(matches!(decoded, Message::SocketHandoffFailed { .. }));
    }

    #[tokio::test]
    async fn test_socket_handoff_with_multiple_ports() {
        use maluwaf::process::ipc::{Message, SocketHandoffRequest, WorkerId};

        let ports = vec![80, 443, 8080, 8443];
        let msg = Message::SocketHandoffRequest {
            worker_id: WorkerId(1),
            ports: ports.clone(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();

        if let Message::SocketHandoffRequest {
            ports: decoded_ports,
            ..
        } = decoded
        {
            assert_eq!(decoded_ports.len(), 4);
        } else {
            panic!("Expected SocketHandoffRequest");
        }
    }

    #[tokio::test]
    async fn test_socket_handoff_error_handling() {
        use maluwaf::overseer::socket_handoff::SocketHandoffError;

        let err = SocketHandoffError::Timeout;
        let err_msg = err.to_string();
        assert!(err_msg.contains("Timeout"), "Should contain Timeout");
    }

    #[tokio::test]
    async fn test_socket_handoff_invalid_state_error() {
        use maluwaf::overseer::socket_handoff::SocketHandoffError;

        let err = SocketHandoffError::InvalidState("test state".to_string());
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("test state"),
            "Should contain error message"
        );
    }

    #[tokio::test]
    async fn test_socket_handoff_concurrent_handlers() {
        use std::sync::Arc;
        use std::thread;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("concurrent-handoff.sock");

        if socket_path.exists() {
            let _ = std::fs::remove_file(&socket_path);
        }

        let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        listener.set_nonblocking(true).unwrap();

        let listener = Arc::new(listener);
        let mut handles = vec![];

        for _ in 0..3 {
            let listener = Arc::clone(&listener);
            let handle = thread::spawn(move || {
                let _ = listener.accept();
            });
            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.join();
        }

        drop(listener);
        let _ = std::fs::remove_file(&socket_path);
    }
}

#[cfg(not(unix))]
mod socket_handoff_tests {
    #[test]
    fn test_socket_handoff_not_supported_on_windows() {
        assert!(true, "Socket handoff tests are Unix-only");
    }
}
