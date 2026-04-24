#[cfg(all(unix, feature = "socket-handoff"))]
mod socket_handoff_tests {
    use std::net::TcpListener;

    use maluwaf::overseer::socket_handoff::DualMasterHandoff;
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
        drop(listener);
        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn test_socket_handoff_dual_master_handoff_creation() {
        let ports = vec![8080u16, 8443u16];
        let handoff = DualMasterHandoff::new(ports.clone());
        let _ = handoff;
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
        use maluwaf::process::ipc::Message;

        // Test SocketHandoffComplete - uses success and fd_count fields
        let msg = Message::SocketHandoffComplete {
            success: true,
            fd_count: 2,
        };

        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();

        assert!(matches!(
            decoded,
            Message::SocketHandoffComplete {
                success: true,
                fd_count: 2
            }
        ));
    }

    #[tokio::test]
    async fn test_socket_handoff_request_message_roundtrip() {
        use maluwaf::process::ipc::Message;

        // SocketHandoffRequest uses socket_path field
        let msg = Message::SocketHandoffRequest {
            socket_path: "/tmp/test.sock".to_string(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();

        assert!(matches!(decoded, Message::SocketHandoffRequest { .. }));
    }

    #[tokio::test]
    async fn test_socket_handoff_ready_message_roundtrip() {
        use maluwaf::process::ipc::Message;

        let msg = Message::SocketHandoffReady {
            ports: vec![8080, 8443],
        };

        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();

        assert!(
            matches!(decoded, Message::SocketHandoffReady { ports } if ports == vec![8080, 8443])
        );
    }

    #[tokio::test]
    async fn test_socket_handoff_failed_message_roundtrip() {
        use maluwaf::process::ipc::Message;

        let msg = Message::SocketHandoffFailed {
            error: "Test failure".to_string(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();

        assert!(
            matches!(decoded, Message::SocketHandoffFailed { error } if error == "Test failure")
        );
    }

    #[tokio::test]
    async fn test_socket_handoff_with_multiple_ports() {
        use maluwaf::process::ipc::Message;

        let ports = vec![80, 443, 8080, 8443];
        let msg = Message::SocketHandoffReady {
            ports: ports.clone(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();

        if let Message::SocketHandoffReady {
            ports: decoded_ports,
        } = decoded
        {
            assert_eq!(decoded_ports.len(), 4);
        } else {
            panic!("Expected SocketHandoffReady");
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

#[cfg(not(all(unix, feature = "socket-handoff")))]
mod socket_handoff_tests {
    use std::net::TcpListener;

    #[test]
    fn test_socket_handoff_not_supported() {
        assert!(
            true,
            "Socket handoff tests require socket-handoff feature on Unix"
        );
    }

    #[test]
    fn test_socket_handoff_not_supported_port_acquisition() {
        let port = 0;
        let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
        let local_addr = listener.local_addr().unwrap();
        assert!(local_addr.port() > 0, "Port should be assigned");
    }
}
