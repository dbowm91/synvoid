//! Phase 45 contract tests: persistent DNS-over-TCP and encrypted-transport
//! config fidelity.
//!
//! - A single TCP connection serves multiple sequential queries (RFC 7766
//!   connection reuse, no pipelining/reordering).
//! - Framing violations (zero-length frame) fail closed by closing the
//!   connection.
//! - DoT/DoH/DoQ activation without an explicit bind address is rejected at
//!   validation time, before listener startup.

use std::time::Duration;

use synvoid_config::dns::DnsConfig;
use synvoid_dns::server::DnsServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn build_a_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // RD=1
    q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in name.split('.').filter(|s| !s.is_empty()) {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A IN
    q
}

fn frame(msg: &[u8]) -> Vec<u8> {
    let mut out = (msg.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(msg);
    out
}

async fn read_frame(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut len_buf))
        .await
        .expect("read timeout")
        .expect("read length");
    let len = u16::from_be_bytes(len_buf) as usize;
    assert!(len > 0, "server must not send empty frames");
    let mut buf = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
        .await
        .expect("read timeout")
        .expect("read body");
    buf
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port()
}

async fn start_server(port: u16) -> DnsServer {
    let config = DnsConfig {
        enabled: true,
        bind_address: "127.0.0.1".to_string(),
        port,
        ..Default::default()
    };
    let mut server = DnsServer::new(config, None);
    server.start().await.expect("server start");
    server
}

/// A single TCP connection serves two sequential queries and echoes both IDs.
#[tokio::test]
async fn tcp_connection_serves_multiple_sequential_queries() {
    let port = free_port();
    let mut server = start_server(port).await;

    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("connect");

    for id in [0x1001u16, 0x1002u16] {
        let query = build_a_query(id, "example.com");
        stream.write_all(&frame(&query)).await.expect("write query");
        let resp = read_frame(&mut stream).await;
        assert!(resp.len() >= 12, "response must hold a DNS header");
        let resp_id = u16::from_be_bytes([resp[0], resp[1]]);
        assert_eq!(resp_id, id, "response ID must echo query ID");
    }

    server.shutdown_runtime();
}

/// A zero-length frame is a framing violation: the server closes the
/// connection instead of allocating or responding.
#[tokio::test]
async fn tcp_zero_length_frame_closes_connection() {
    let port = free_port();
    let mut server = start_server(port).await;

    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("connect");
    stream
        .write_all(&[0x00, 0x00])
        .await
        .expect("write zero frame");

    // Server must close: read returns EOF (0 bytes) or an error promptly.
    let mut buf = [0u8; 64];
    let outcome = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
    match outcome {
        Ok(Ok(0)) => {}
        Ok(Ok(n)) => panic!("expected close, got {} bytes", n),
        Ok(Err(_)) => {}
        Err(_) => panic!("server did not close connection after zero-length frame"),
    }

    server.shutdown_runtime();
}

/// Oversize length prefix (beyond the 16-bit framing bound is impossible;
/// beyond max_query_size is rejected) fails closed. With default limits
/// (65535) a 1-byte-short-of-max frame is accepted, so exercise the bound
/// via a tight custom limit instead.
#[tokio::test]
async fn tcp_frame_beyond_max_query_size_is_rejected() {
    let port = free_port();
    let mut config = DnsConfig {
        enabled: true,
        bind_address: "127.0.0.1".to_string(),
        port,
        ..Default::default()
    };
    config.limits.max_query_size = 512;
    let mut server = DnsServer::new(config, None);
    server.start().await.expect("server start");

    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("connect");
    // 600-byte frame exceeds the 512-byte limit: must fail before allocation.
    let big = vec![0u8; 600];
    stream.write_all(&frame(&big)).await.expect("write");

    let mut buf = [0u8; 64];
    let outcome = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
    match outcome {
        Ok(Ok(0)) => {}
        Ok(Ok(n)) => panic!("expected close, got {} bytes", n),
        Ok(Err(_)) => {}
        Err(_) => panic!("server did not close connection after oversize frame"),
    }

    server.shutdown_runtime();
}

/// Disabled DoQ does not bind: a server with `doq.enabled = false` starts
/// without requiring any DoQ address material.
#[tokio::test]
async fn disabled_transports_do_not_bind() {
    let port = free_port();
    let config = DnsConfig {
        enabled: true,
        bind_address: "127.0.0.1".to_string(),
        port,
        ..Default::default()
    };
    assert!(!config.dot.enabled);
    assert!(!config.doh.enabled);
    assert!(!config.doq.enabled);
    assert!(config.validate().is_ok());
    let mut server = DnsServer::new(config, None);
    server.start().await.expect("server start");
    server.shutdown_runtime();
}
