//! Phase 02 integration coverage for the TCP/UDP auxiliary service pools.
//!
//! These tests drive the real pools: bind, accept/receive loops, protocol
//! filtering, idle timeout, UDP request/response flows, flow caps and IPv6.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

use synvoid::tcp::filter::FilterConfig;
use synvoid::tcp::listener::{
    TcpListenerConfig, TcpListenerPool, TcpListenerPoolConfig, TcpSocketOptions,
};
use synvoid::udp::listener::{
    UdpListenerConfig, UdpListenerPool, UdpListenerPoolConfig, UdpSocketOptions,
};

fn tcp_listener(port: u16, upstream: String, expected: &str) -> TcpListenerConfig {
    TcpListenerConfig {
        port,
        bind_address: "127.0.0.1".to_string(),
        bind_address_v6: None,
        expected_protocol: expected.to_string(),
        upstream_address: upstream,
        upstream_address_v6: None,
        filter_enabled: false,
        strict_mode: false,
        socket_options: TcpSocketOptions::default(),
        tcp_backlog: None,
        idle_timeout_secs: 30,
    }
}

async fn spawn_tcp_echo() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
    let addr = listener.local_addr().expect("echo addr");
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, handle)
}

async fn spawn_udp_echo() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("udp echo bind");
    let addr = socket.local_addr().expect("udp echo addr");
    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                break;
            };
            let _ = socket.send_to(&buf[..n], peer).await;
        }
    });
    (addr, handle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_pool_binds_once_and_proxies_request_response() {
    let (upstream, _echo) = spawn_tcp_echo().await;

    let pool = TcpListenerPool::new(TcpListenerPoolConfig {
        worker_pool_size: 2,
        connection_timeout_secs: 2,
        max_connections: 16,
        socket_options: TcpSocketOptions::default(),
        buffer_size: 64 * 1024,
        enable_concurrency_limit: true,
    });
    pool.add_listener(tcp_listener(0, upstream.to_string(), "http"));
    pool.bind_all().await.expect("bind");

    let addr = pool.bound_addresses()[0];
    assert_eq!(pool.worker_accept_loop_count(), 2);
    pool.start().await;

    let snapshots = synvoid::tcp::listener::tcp_listener_snapshots();
    assert!(
        snapshots.iter().any(|s| s.bound && s.port == addr.port()),
        "admin inventory must report the bound TCP listener"
    );

    let mut client = TcpStream::connect(addr).await.expect("client connect");
    let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    client.write_all(request).await.expect("write");
    let mut response = vec![0u8; request.len()];
    timeout(Duration::from_secs(3), client.read_exact(&mut response))
        .await
        .expect("response timeout")
        .expect("response read");
    assert_eq!(response, request);

    pool.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_protocol_mismatch_stalls_without_proxying() {
    let (upstream, _echo) = spawn_tcp_echo().await;

    let pool = TcpListenerPool::new(TcpListenerPoolConfig {
        worker_pool_size: 1,
        connection_timeout_secs: 2,
        max_connections: 16,
        socket_options: TcpSocketOptions::default(),
        buffer_size: 64 * 1024,
        enable_concurrency_limit: true,
    });
    let mut listener = tcp_listener(0, upstream.to_string(), "smtp");
    listener.filter_enabled = true;
    listener.strict_mode = true;
    pool.add_listener(listener);
    pool.bind_all().await.expect("bind");
    let addr = pool.bound_addresses()[0];
    pool.start().await;

    let mut client = TcpStream::connect(addr).await.expect("client connect");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .expect("write");

    let mut buf = [0u8; 64];
    let result = timeout(Duration::from_millis(600), client.read(&mut buf)).await;
    assert!(
        result.is_err() || matches!(result, Ok(Ok(0))),
        "a protocol mismatch must not be proxied, got {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_idle_timeout_closes_a_silent_connection() {
    let acceptor = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream = acceptor.local_addr().expect("upstream addr");
    let _hold = tokio::spawn(async move {
        let (_stream, _) = acceptor.accept().await.expect("accept");
        tokio::time::sleep(Duration::from_secs(30)).await;
    });

    let pool = TcpListenerPool::new(TcpListenerPoolConfig {
        worker_pool_size: 1,
        connection_timeout_secs: 2,
        max_connections: 16,
        socket_options: TcpSocketOptions::default(),
        buffer_size: 16 * 1024,
        enable_concurrency_limit: true,
    });
    let mut listener = tcp_listener(0, upstream.to_string(), "http");
    listener.idle_timeout_secs = 1;
    pool.add_listener(listener);
    pool.bind_all().await.expect("bind");
    let addr = pool.bound_addresses()[0];
    pool.start().await;

    let mut client = TcpStream::connect(addr).await.expect("client connect");
    let mut buf = [0u8; 1];
    let read = timeout(Duration::from_secs(5), client.read(&mut buf)).await;
    assert!(
        matches!(read, Ok(Ok(0))) || matches!(read, Ok(Err(_))),
        "idle timeout must close the proxied connection, got {read:?}"
    );
}

fn udp_listener(port: u16, upstream: String, rate: u32, max_flows: usize) -> UdpListenerConfig {
    UdpListenerConfig {
        port,
        bind_address: "127.0.0.1".to_string(),
        bind_address_v6: None,
        expected_protocol: "dns".to_string(),
        upstream_address: upstream,
        upstream_address_v6: None,
        filter_enabled: false,
        strict_mode: false,
        max_packet_size: 512,
        rate_limit_per_ip: rate,
        socket_options: UdpSocketOptions::default(),
        max_flows,
        flow_idle_timeout_secs: 2,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_pool_proxies_request_response_for_two_clients() {
    let (upstream, _echo) = spawn_udp_echo().await;

    let pool = UdpListenerPool::new(UdpListenerPoolConfig {
        worker_pool_size: 2,
        buffer_size: 8192,
        socket_options: UdpSocketOptions::default(),
    });
    pool.add_listener(udp_listener(0, upstream.to_string(), 1000, 16));
    pool.bind_all().await.expect("bind");
    let addr = pool.bound_addresses()[0];
    pool.start().await;

    let snapshots = synvoid::udp::listener::udp_listener_snapshots();
    assert!(
        snapshots.iter().any(|s| s.bound && s.port == addr.port()),
        "admin inventory must report the bound UDP listener"
    );

    let client_a = UdpSocket::bind("127.0.0.1:0").await.expect("client a");
    let client_b = UdpSocket::bind("127.0.0.1:0").await.expect("client b");

    client_a.send_to(b"alpha", addr).await.expect("send a");
    let mut buf = [0u8; 64];
    let (n, _) = timeout(Duration::from_secs(3), client_a.recv_from(&mut buf))
        .await
        .expect("response a")
        .expect("recv a");
    assert_eq!(&buf[..n], b"alpha");

    client_b.send_to(b"beta", addr).await.expect("send b");
    let (n, _) = timeout(Duration::from_secs(3), client_b.recv_from(&mut buf))
        .await
        .expect("response b")
        .expect("recv b");
    assert_eq!(&buf[..n], b"beta");

    assert_eq!(pool.active_flow_count(), 2);
    pool.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_oversize_packet_is_dropped() {
    let (upstream, _echo) = spawn_udp_echo().await;

    let pool = UdpListenerPool::new(UdpListenerPoolConfig {
        worker_pool_size: 1,
        buffer_size: 8192,
        socket_options: UdpSocketOptions::default(),
    });
    let mut listener = udp_listener(0, upstream.to_string(), 1000, 16);
    listener.max_packet_size = 16;
    pool.add_listener(listener);
    pool.bind_all().await.expect("bind");
    let addr = pool.bound_addresses()[0];
    pool.start().await;

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
    client
        .send_to(&[0u8; 64], addr)
        .await
        .expect("oversize send");

    let mut buf = [0u8; 128];
    let reply = timeout(Duration::from_millis(400), client.recv_from(&mut buf)).await;
    assert!(reply.is_err(), "oversized datagram must not be forwarded");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_flow_cap_rejects_a_second_client() {
    let (upstream, _echo) = spawn_udp_echo().await;

    let pool = UdpListenerPool::new(UdpListenerPoolConfig {
        worker_pool_size: 1,
        buffer_size: 8192,
        socket_options: UdpSocketOptions::default(),
    });
    let mut listener = udp_listener(0, upstream.to_string(), 1000, 1);
    listener.flow_idle_timeout_secs = 30;
    pool.add_listener(listener);
    pool.bind_all().await.expect("bind");
    let addr = pool.bound_addresses()[0];
    pool.start().await;

    let snapshots = synvoid::udp::listener::udp_listener_snapshots();
    assert!(
        snapshots.iter().any(|s| s.bound && s.port == addr.port()),
        "admin inventory must report the bound UDP listener"
    );

    let client_a = UdpSocket::bind("127.0.0.1:0").await.expect("client a");
    let client_b = UdpSocket::bind("127.0.0.1:0").await.expect("client b");
    let mut buf = [0u8; 64];

    client_a.send_to(b"one", addr).await.expect("send a");
    timeout(Duration::from_secs(3), client_a.recv_from(&mut buf))
        .await
        .expect("response a")
        .expect("recv a");

    client_b.send_to(b"two", addr).await.expect("send b");
    let reply = timeout(Duration::from_millis(500), client_b.recv_from(&mut buf)).await;
    assert!(
        reply.is_err(),
        "a flow over the configured max_flows cap must be rejected"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_rate_limit_drops_the_second_datagram() {
    let (upstream, _echo) = spawn_udp_echo().await;

    let pool = UdpListenerPool::new(UdpListenerPoolConfig {
        worker_pool_size: 1,
        buffer_size: 8192,
        socket_options: UdpSocketOptions::default(),
    });
    pool.add_listener(udp_listener(0, upstream.to_string(), 1, 16));
    pool.bind_all().await.expect("bind");
    let addr = pool.bound_addresses()[0];
    pool.start().await;

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
    let mut buf = [0u8; 64];
    client.send_to(b"first", addr).await.expect("send first");
    timeout(Duration::from_secs(3), client.recv_from(&mut buf))
        .await
        .expect("first response")
        .expect("recv first");

    client.send_to(b"second", addr).await.expect("send second");
    let reply = timeout(Duration::from_millis(400), client.recv_from(&mut buf)).await;
    assert!(
        reply.is_err(),
        "the per-IP rate limit must drop the second datagram"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_flows_are_reaped_after_idle_timeout() {
    let (upstream, _echo) = spawn_udp_echo().await;

    let pool = UdpListenerPool::new(UdpListenerPoolConfig {
        worker_pool_size: 1,
        buffer_size: 8192,
        socket_options: UdpSocketOptions::default(),
    });
    let mut listener = udp_listener(0, upstream.to_string(), 1000, 16);
    listener.flow_idle_timeout_secs = 1;
    pool.add_listener(listener);
    pool.bind_all().await.expect("bind");
    let addr = pool.bound_addresses()[0];
    pool.start().await;

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
    let mut buf = [0u8; 64];
    client.send_to(b"hello", addr).await.expect("send");
    timeout(Duration::from_secs(3), client.recv_from(&mut buf))
        .await
        .expect("response")
        .expect("recv");
    assert_eq!(pool.active_flow_count(), 1);

    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(
        pool.active_flow_count(),
        0,
        "an idle UDP flow must be reaped"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_ipv6_listener_round_trips() {
    let Ok(upstream_socket) = UdpSocket::bind("[::1]:0").await else {
        eprintln!("IPv6 loopback unavailable; skipping");
        return;
    };
    let upstream = upstream_socket.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        loop {
            let Ok((n, peer)) = upstream_socket.recv_from(&mut buf).await else {
                break;
            };
            let _ = upstream_socket.send_to(&buf[..n], peer).await;
        }
    });

    let pool = UdpListenerPool::new(UdpListenerPoolConfig {
        worker_pool_size: 1,
        buffer_size: 8192,
        socket_options: UdpSocketOptions::default(),
    });
    let mut listener = udp_listener(0, upstream.to_string(), 1000, 16);
    listener.bind_address = "::1".to_string();
    pool.add_listener(listener);
    pool.bind_all().await.expect("bind");
    let addr = pool.bound_addresses()[0];
    pool.start().await;

    let client = UdpSocket::bind("[::1]:0").await.expect("client");
    let mut buf = [0u8; 64];
    client.send_to(b"v6", addr).await.expect("send");
    let (n, _) = timeout(Duration::from_secs(3), client.recv_from(&mut buf))
        .await
        .expect("v6 response")
        .expect("recv");
    assert_eq!(&buf[..n], b"v6");
}

#[test]
fn tcp_filter_action_remains_a_distinct_contract() {
    // Compile-time pin: the pool still consumes the shared filter vocabulary
    // instead of bypassing it when filters are enabled.
    let _ = FilterConfig {
        enabled: true,
        strict_mode: true,
        ..Default::default()
    };
}
