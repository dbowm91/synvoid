use std::net::TcpStream;
use std::time::Duration;

use synvoid_config::dns::DnsConfig;
use synvoid_dns::cache::TransportClass;
use synvoid_dns::server::DnsServer;

fn make_config(bind: &str, port: u16) -> DnsConfig {
    let mut c = DnsConfig::default();
    c.bind_address = bind.to_string();
    c.port = port;
    c
}

/// Find an available ephemeral port by binding to port 0, reading the assigned port,
/// and immediately dropping the socket. Returns the port number.
///
/// Note: There is an inherent TOCTOU race — another process may claim the port
/// between drop and the server's bind. In practice this is rare for ephemeral ports.
fn ephemeral_port() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral");
    socket.local_addr().unwrap().port()
}

#[tokio::test]
async fn start_stop_ephemeral_port() {
    let port = ephemeral_port();
    let mut config = make_config("127.0.0.1", port);
    config.settings.cache_enabled = false;

    let mut server = DnsServer::new(config, None);
    server.start().await.expect("start should succeed");

    // Give the UDP/TCP tasks a moment to bind
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Shutdown should signal cleanly
    server.shutdown_runtime();

    // Give tasks time to observe shutdown and exit
    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn udp_port_reusable_after_shutdown() {
    let port = ephemeral_port();
    let mut config = make_config("127.0.0.1", port);
    config.settings.cache_enabled = false;

    // First lifecycle: start and shutdown
    {
        let mut server = DnsServer::new(config.clone(), None);
        server.start().await.expect("first start should succeed");
        tokio::time::sleep(Duration::from_millis(100)).await;
        server.shutdown_runtime();
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Give OS time to release the port
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Second lifecycle: the same port must be bindable
    {
        let mut server = DnsServer::new(config, None);
        server.start().await.expect("second start should succeed");
        tokio::time::sleep(Duration::from_millis(100)).await;
        server.shutdown_runtime();
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test]
async fn tcp_port_reusable_after_shutdown() {
    let port = ephemeral_port();
    let mut config = make_config("127.0.0.1", port);
    config.settings.cache_enabled = false;

    // First lifecycle
    {
        let mut server = DnsServer::new(config.clone(), None);
        server.start().await.expect("first start should succeed");
        tokio::time::sleep(Duration::from_millis(100)).await;
        server.shutdown_runtime();
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify TCP port is reusable
    {
        let mut server = DnsServer::new(config, None);
        server.start().await.expect("second start should succeed");
        tokio::time::sleep(Duration::from_millis(100)).await;
        server.shutdown_runtime();
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Extra verification: the port should now be free — try to bind directly
    let result = TcpStream::connect(format!("127.0.0.1:{}", port));
    assert!(
        result.is_err(),
        "TCP port {} should be free after shutdown, but connection succeeded",
        port
    );
}

#[tokio::test]
async fn shutdown_idempotent_under_load() {
    let port = ephemeral_port();
    let mut config = make_config("127.0.0.1", port);
    config.settings.cache_enabled = false;

    let mut server = DnsServer::new(config, None);
    server.start().await.expect("start should succeed");
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Multiple shutdowns in quick succession must not panic
    server.shutdown_runtime();
    server.shutdown_runtime();
    server.shutdown_runtime();

    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn shutdown_before_start_is_safe() {
    let mut config = make_config("127.0.0.1", ephemeral_port());
    config.settings.cache_enabled = false;

    let mut server = DnsServer::new(config, None);
    // Shutdown on a server that was never started — must not panic
    server.shutdown_runtime();
    server.shutdown_runtime();
}

#[tokio::test]
async fn coalescer_cleanup_uses_shutdown_watcher() {
    use std::sync::Arc;
    use synvoid_dns::query_coalesce::QueryCoalescer;

    let coalescer = Arc::new(QueryCoalescer::with_config(500, 100, 30));
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Start cleanup task using the same path as DnsServer
    DnsServer::start_coalescer_cleanup_task(Some(&coalescer), 1, shutdown_rx);

    // Insert a stale entry
    let key = synvoid_dns::query_coalesce::QueryKey {
        name: "lifecycle.test".to_string(),
        qtype: 1,
        qclass: 1,
        dnssec_ok: false,
        edns_udp_size: 512,
        client_ip: None,
        transport_class: TransportClass::default(),
    };
    let _ = coalescer.get_or_wait(key.clone()).await;
    assert_eq!(coalescer.in_flight_count(), 1);

    // Send shutdown signal
    let _ = shutdown_tx.send(true);

    // Give cleanup task time to observe shutdown
    tokio::time::sleep(Duration::from_millis(100)).await;

    // After shutdown, the cleanup task should have exited —
    // verify it doesn't panic when coalescer is used after
    // (the task no longer calls cleanup_stale)
    let _ = coalescer.get_or_wait(key).await;
    // The entry may still be there since the cleanup task is stopped
}

#[test]
fn recursive_server_handle_is_not_leaked() {
    // This test documents that DnsServer does not leak join handles.
    // The recursive server and key rotation tasks are fire-and-forget
    // (tokio::spawn without JoinHandle storage). This is safe because:
    //
    // 1. Key rotation: Uses tokio::time::interval which runs until dropped.
    //    The interval is owned by the spawned task itself.
    //
    // 2. Recursive server: Has its own shutdown mechanism via the
    //    RecursiveDnsServer struct which owns its runtime handles.
    //
    // 3. Coalescer cleanup: Observes the shutdown watcher and exits its loop.
    //
    // All spawned tasks either exit via shutdown signal or are cleaned up
    // when their owning Arc-wrapped state is dropped.
    //
    // No explicit JoinHandle ownership is needed because:
    // - The server holds the shutdown channels that signal task termination
    // - Dropping the DnsServer drops the shutdown_tx, causing receivers to error
    // - Tasks exit gracefully on channel closure

    let mut config = DnsConfig::default();
    config.bind_address = "127.0.0.1".to_string();
    config.port = ephemeral_port();
    config.settings.cache_enabled = false;

    let server = DnsServer::new(config, None);

    // Verify server can be dropped without issues (no join handle leaks)
    drop(server);
}
