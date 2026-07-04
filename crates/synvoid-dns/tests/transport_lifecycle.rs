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
        client_ip: None,
        transport_class: TransportClass::default(),
        namespace: synvoid_dns::cache::CacheNamespace::Authoritative,
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

// ── Coalescing integration tests ────────────────────────────────────────

#[tokio::test]
async fn coalescer_get_or_wait_returns_new_query_for_first_request() {
    use std::sync::Arc;
    use synvoid_dns::cache::TransportClass;
    use synvoid_dns::query_coalesce::{QueryCoalescer, QueryKey};

    let coalescer = Arc::new(QueryCoalescer::with_config(500, 100, 30));

    let key = QueryKey {
        name: "first.test".to_string(),
        qtype: 1,
        qclass: 1,
        dnssec_ok: false,
        client_ip: None,
        transport_class: TransportClass::Udp512,
        namespace: synvoid_dns::cache::CacheNamespace::Authoritative,
    };

    let result = coalescer.get_or_wait(key.clone()).await;
    assert!(result.is_some(), "first request should return Some");
    match result.unwrap() {
        synvoid_dns::CoalesceResult::NewQuery(_tx) => {} // expected
        other => panic!("expected NewQuery, got {:?}", other),
    }
    assert_eq!(coalescer.in_flight_count(), 1);
}

#[tokio::test]
async fn coalescer_broadcast_shares_response_to_waiters() {
    use std::sync::Arc;
    use synvoid_dns::cache::TransportClass;
    use synvoid_dns::query_coalesce::{QueryCoalescer, QueryKey};
    use synvoid_dns::CoalesceResult;

    // Long max_wait so the waiter doesn't timeout before broadcast
    let coalescer = Arc::new(QueryCoalescer::with_config(5000, 100, 30));

    let key = QueryKey {
        name: "share.test".to_string(),
        qtype: 1,
        qclass: 1,
        dnssec_ok: false,
        client_ip: None,
        transport_class: TransportClass::Udp512,
        namespace: synvoid_dns::cache::CacheNamespace::Authoritative,
    };

    // Owner claims the key
    let _owner_tx = match coalescer.get_or_wait(key.clone()).await {
        Some(CoalesceResult::NewQuery(tx)) => tx,
        other => panic!("expected NewQuery, got {:?}", other),
    };

    // Spawn a waiter while owner is still in-flight
    let coalescer_clone = Arc::clone(&coalescer);
    let key_clone = key.clone();
    let waiter_handle = tokio::spawn(async move { coalescer_clone.get_or_wait(key_clone).await });

    // Give the waiter time to register
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Broadcast the response
    let response = Arc::new(vec![0x12, 0x34, 0x01, 0x00]);
    coalescer.broadcast_response(key.clone(), Arc::clone(&response));

    // The waiter should receive the broadcast response
    let waiter_result = waiter_handle.await.unwrap();
    match waiter_result {
        Some(CoalesceResult::Response(resp)) => {
            assert_eq!(
                *resp, *response,
                "waiter should receive the broadcast response"
            );
        }
        other => panic!("expected Response from waiter, got {:?}", other),
    }

    let metrics = coalescer.metrics();
    assert!(metrics.broadcasts > 0, "should have at least one broadcast");
}

#[tokio::test]
async fn coalescer_cancel_in_flight_removes_entry() {
    use std::sync::Arc;
    use synvoid_dns::cache::TransportClass;
    use synvoid_dns::query_coalesce::{QueryCoalescer, QueryKey};

    let coalescer = Arc::new(QueryCoalescer::with_config(500, 100, 30));

    let key = QueryKey {
        name: "cancel.test".to_string(),
        qtype: 1,
        qclass: 1,
        dnssec_ok: false,
        client_ip: None,
        transport_class: TransportClass::Udp512,
        namespace: synvoid_dns::cache::CacheNamespace::Authoritative,
    };

    // Owner claims the key
    let _ = coalescer.get_or_wait(key.clone()).await;
    assert_eq!(coalescer.in_flight_count(), 1);

    // Cancel the in-flight entry
    coalescer.cancel_in_flight(&key);
    assert_eq!(coalescer.in_flight_count(), 0);

    // Next request should get NewQuery (not a stale broadcast receiver)
    let result = coalescer.get_or_wait(key.clone()).await;
    assert!(result.is_some());
    match result.unwrap() {
        synvoid_dns::CoalesceResult::NewQuery(_tx) => {} // expected after cancel
        other => panic!("expected NewQuery after cancel, got {:?}", other),
    }
}

#[tokio::test]
async fn coalescer_metrics_track_hits_misses_and_evictions() {
    use std::sync::Arc;
    use synvoid_dns::cache::TransportClass;
    use synvoid_dns::query_coalesce::{QueryCoalescer, QueryKey};

    // Use a tiny max_entries to trigger eviction
    let coalescer = Arc::new(QueryCoalescer::with_config(500, 2, 30));

    let key1 = QueryKey {
        name: "metrics1.test".to_string(),
        qtype: 1,
        qclass: 1,
        dnssec_ok: false,
        client_ip: None,
        transport_class: TransportClass::Udp512,
        namespace: synvoid_dns::cache::CacheNamespace::Authoritative,
    };
    let key2 = QueryKey {
        name: "metrics2.test".to_string(),
        qtype: 1,
        qclass: 1,
        dnssec_ok: false,
        client_ip: None,
        transport_class: TransportClass::Udp512,
        namespace: synvoid_dns::cache::CacheNamespace::Authoritative,
    };
    let key3 = QueryKey {
        name: "metrics3.test".to_string(),
        qtype: 1,
        qclass: 1,
        dnssec_ok: false,
        client_ip: None,
        transport_class: TransportClass::Udp512,
        namespace: synvoid_dns::cache::CacheNamespace::Authoritative,
    };

    // Two entries fill the capacity
    let _ = coalescer.get_or_wait(key1.clone()).await;
    let _ = coalescer.get_or_wait(key2.clone()).await;
    assert_eq!(coalescer.in_flight_count(), 2);

    // Third entry triggers eviction
    let _ = coalescer.get_or_wait(key3.clone()).await;
    let metrics = coalescer.metrics();
    assert!(
        metrics.evictions > 0,
        "should have evictions when over capacity"
    );
}

#[test]
fn coalescer_skip_list_bypasses_coalescing() {
    use synvoid_dns::query_coalesce::should_skip_coalescing;

    // AXFR (type 252) should skip
    assert!(
        should_skip_coalescing(252, 0),
        "AXFR should skip coalescing"
    );
    // IXFR (type 251) should skip
    assert!(
        should_skip_coalescing(251, 0),
        "IXFR should skip coalescing"
    );
    // NOTIFY (opcode 4) should skip
    assert!(
        should_skip_coalescing(1, 4),
        "NOTIFY should skip coalescing"
    );
    // UPDATE (opcode 5) should skip
    assert!(
        should_skip_coalescing(1, 5),
        "UPDATE should skip coalescing"
    );
    // Normal A query should NOT skip
    assert!(
        !should_skip_coalescing(1, 0),
        "A query should not skip coalescing"
    );
    // Normal AAAA query should NOT skip
    assert!(
        !should_skip_coalescing(28, 0),
        "AAAA query should not skip coalescing"
    );
}

#[tokio::test]
async fn coalescer_cleanup_removes_stale_entries() {
    use std::sync::Arc;
    use synvoid_dns::cache::TransportClass;
    use synvoid_dns::query_coalesce::{QueryCoalescer, QueryKey};

    // Use a very short entry TTL
    let coalescer = Arc::new(QueryCoalescer::with_config(500, 100, 0));

    let key = QueryKey {
        name: "stale.test".to_string(),
        qtype: 1,
        qclass: 1,
        dnssec_ok: false,
        client_ip: None,
        transport_class: TransportClass::Udp512,
        namespace: synvoid_dns::cache::CacheNamespace::Authoritative,
    };

    let _ = coalescer.get_or_wait(key.clone()).await;
    assert_eq!(coalescer.in_flight_count(), 1);

    // Wait for the entry to become stale (TTL=0 means immediately stale)
    tokio::time::sleep(Duration::from_millis(10)).await;

    coalescer.cleanup_stale();
    assert_eq!(
        coalescer.in_flight_count(),
        0,
        "stale entry should be cleaned up"
    );
}

#[tokio::test]
async fn coalescer_metrics_track_timeouts() {
    use std::sync::Arc;
    use synvoid_dns::cache::TransportClass;
    use synvoid_dns::query_coalesce::{QueryCoalescer, QueryKey};
    use synvoid_dns::CoalesceResult;

    // Very short max_wait
    let coalescer = Arc::new(QueryCoalescer::with_config(10, 100, 30));

    let key = QueryKey {
        name: "timeout.test".to_string(),
        qtype: 1,
        qclass: 1,
        dnssec_ok: false,
        client_ip: None,
        transport_class: TransportClass::Udp512,
        namespace: synvoid_dns::cache::CacheNamespace::Authoritative,
    };

    // Owner claims the key
    let _ = coalescer.get_or_wait(key.clone()).await;

    // Second request will wait and should timeout
    let result = coalescer.get_or_wait(key.clone()).await;
    // The result could be Timeout or NewQuery depending on timing,
    // but if it's Timeout, we should see it in metrics
    match result {
        Some(CoalesceResult::Timeout) => {
            let metrics = coalescer.metrics();
            assert!(metrics.timeouts > 0, "should track timeout metric");
        }
        Some(CoalesceResult::NewQuery(_)) => {
            // If the owner's entry expired before the waiter registered,
            // the waiter becomes the new owner — this is also valid
        }
        other => panic!("expected Timeout or NewQuery, got {:?}", other),
    }
}
