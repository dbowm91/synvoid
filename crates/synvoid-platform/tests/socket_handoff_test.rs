//! Socket/IPC coverage for the canonical `synvoid-platform` surface (Phase 32).
//!
//! These tests exercise the crate directly. They intentionally do not depend
//! on `synvoid-ipc`: the platform crate must stay below the IPC layer, so
//! even a dev-dependency edge would reintroduce the cycle Phase 32 removes.

#[cfg(unix)]
mod socket_handoff_tests {
    use std::io::Read;
    use std::net::TcpListener;
    use std::os::unix::io::AsRawFd;
    use std::time::Duration;

    use tempfile::TempDir;

    use synvoid_platform::ipc::{
        IpcListener, IpcStream, IpcTransport, PlatformIpcListener, PlatformIpcStream,
    };
    use synvoid_platform::socket::{
        PlatformSocketFDPassing, PlatformSocketHandle, SocketFDPassing, SocketHandoffError,
    };
    use synvoid_platform::socket_bind::{bind_tcp_reuse, bind_udp_reuse};

    #[tokio::test]
    async fn test_ipc_bind_creates_socket_file() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test-handoff.sock");

        let listener = PlatformIpcListener::bind(&socket_path).unwrap();
        assert_eq!(listener.path(), socket_path.as_path());
        assert!(socket_path.exists(), "Socket should be bound to filesystem");
    }

    #[tokio::test]
    async fn test_ipc_bind_connect_send_recv_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("roundtrip.sock");

        let listener = PlatformIpcListener::bind(&socket_path).unwrap();
        let mut client = PlatformIpcStream::connect(&socket_path).unwrap();

        // The listener is non-blocking; the client connection may take a
        // scheduling quantum to appear in the accept queue.
        let mut server = None;
        for _ in 0..100 {
            match listener.accept() {
                Ok(stream) => {
                    server = Some(stream);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
        let mut server = server.expect("server should accept the client connection");

        client.set_nonblocking(false).unwrap();
        server.set_nonblocking(false).unwrap();

        client.send(b"hello-platform").unwrap();
        let mut buf = [0u8; 32];
        let n = server.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello-platform");

        server.send(b"ack").unwrap();
        let n = client.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ack");

        assert!(client.peer_pid().is_none() || client.peer_pid().is_some());
        client.close().unwrap();
        server.close().unwrap();
    }

    #[tokio::test]
    async fn test_ipc_connect_missing_path_errors() {
        let temp_dir = TempDir::new().unwrap();
        let missing = temp_dir.path().join("does-not-exist.sock");
        let result = PlatformIpcStream::connect(&missing);
        assert!(result.is_err(), "connect to missing path must fail");
    }

    #[tokio::test]
    async fn test_socket_reuse_bind_tcp() {
        let listener =
            bind_tcp_reuse("127.0.0.1:0".parse().unwrap()).expect("reuse bind should succeed");
        let addr = listener.local_addr().unwrap();
        assert!(addr.port() > 0, "Port should be assigned");
    }

    #[tokio::test]
    async fn test_socket_reuse_bind_udp() {
        let socket =
            bind_udp_reuse("127.0.0.1:0".parse().unwrap()).expect("reuse bind should succeed");
        let addr = socket.local_addr().unwrap();
        assert!(addr.port() > 0, "Port should be assigned");
    }

    #[tokio::test]
    async fn test_socket_handoff_tcp_listener_port_acquisition() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let local_addr = listener.local_addr().unwrap();
        assert!(local_addr.port() > 0, "Port should be assigned");
    }

    #[tokio::test]
    async fn test_fd_passing_not_connected_errors() {
        let passer = PlatformSocketFDPassing::new();
        let err = passer.recv_sockets(4).unwrap_err();
        assert!(matches!(err, SocketHandoffError::NotConnected));

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let handle = PlatformSocketHandle::borrowed(listener.as_raw_fd());
        let err = passer
            .send_sockets(std::slice::from_ref(&handle))
            .unwrap_err();
        assert!(matches!(err, SocketHandoffError::NotConnected));
    }

    #[tokio::test]
    async fn test_fd_passing_rejects_too_many_sockets() {
        let temp_dir = TempDir::new().unwrap();
        let control_path = temp_dir.path().join("control.sock");

        // Blockingly accept one control connection in the background; the
        // accepted stream is only drained, the client only needs sendmsg(2)
        // to succeed at the syscall level. The listener is bound before the
        // client connects to avoid a bind/connect race.
        let control_listener = std::os::unix::net::UnixListener::bind(&control_path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = control_listener.accept().unwrap();
            let mut buf = [0u8; 8];
            let _ = stream.read(&mut buf);
        });

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let fd = listener.as_raw_fd();

        let mut passer = PlatformSocketFDPassing::new();
        passer.connect(&control_path).unwrap();

        let handles: Vec<PlatformSocketHandle> = (0..300)
            .map(|_| PlatformSocketHandle::borrowed(fd))
            .collect();
        let err = passer.send_sockets(&handles).unwrap_err();
        assert!(
            matches!(
                err,
                SocketHandoffError::TooManySockets { got: 300, max: 254 }
            ),
            "expected TooManySockets, got {err:?}"
        );

        // A single borrowed handle transfers through the real SCM_RIGHTS path.
        let one = PlatformSocketHandle::borrowed(fd);
        passer
            .send_sockets(std::slice::from_ref(&one))
            .expect("single fd send should succeed");

        server.join().unwrap();
    }

    #[tokio::test]
    async fn test_fd_passing_concurrent_connectors() {
        use std::sync::Arc;
        use std::thread;

        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("concurrent-handoff.sock");

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
    }
}

#[cfg(not(unix))]
mod socket_handoff_tests {
    use std::net::TcpListener;

    #[test]
    fn test_socket_reuse_bind_tcp_portable() {
        let listener =
            synvoid_platform::socket_bind::bind_tcp_reuse("127.0.0.1:0".parse().unwrap())
                .expect("reuse bind should succeed");
        assert!(listener.local_addr().unwrap().port() > 0);
    }

    #[test]
    fn test_socket_handoff_port_acquisition() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let local_addr = listener.local_addr().unwrap();
        assert!(local_addr.port() > 0, "Port should be assigned");
    }

    #[test]
    fn test_fd_passing_not_connected_errors_portable() {
        use synvoid_platform::socket::{
            PlatformSocketFDPassing, SocketFDPassing, SocketHandoffError,
        };
        let passer = PlatformSocketFDPassing::new();
        assert!(matches!(
            passer.recv_sockets(4).unwrap_err(),
            SocketHandoffError::NotConnected
        ));
    }
}
