//! Root-test ownership: COMPOSITION
//! Rationale: validates echo server test utility (test_utils::echo) used by proxy and integration tests

use synvoid::test_utils::echo::{start_echo_server, EchoResponse};

#[tokio::test]
async fn test_echo_server_starts_and_captures() {
    let server = start_echo_server().await;
    assert_ne!(server.addr.port(), 0);

    let stream = tokio::net::TcpStream::connect(server.addr).await.unwrap();
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    let mut stream = stream;

    server.push_response(EchoResponse::new(200, "hello"));

    stream.write_all(b"GET /test/path?q=1 HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer token123\r\n\r\n").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let _ = stream.read(&mut buf).await;

    let captured = server.take_captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].method, "GET");
    assert_eq!(captured[0].path, "/test/path");
    assert_eq!(captured[0].query.as_deref(), Some("q=1"));

    let auth_header = captured[0]
        .headers
        .iter()
        .find(|(k, _)| k == "Authorization");
    assert!(auth_header.is_some());
    assert_eq!(auth_header.unwrap().1, "Bearer token123");
}

#[tokio::test]
async fn test_echo_server_custom_status_and_headers() {
    let server = start_echo_server().await;

    server.push_response(
        EchoResponse::new(201, r#"{"id":42}"#)
            .with_header("content-type", "application/json")
            .with_header("x-custom", "value"),
    );

    let stream = tokio::net::TcpStream::connect(server.addr).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = stream;

    stream
        .write_all(b"POST /api/items HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();

    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);

    assert!(response.starts_with("HTTP/1.1 201 Created"));
    assert!(response.contains("content-type: application/json"));
    assert!(response.contains("x-custom: value"));
    assert!(response.contains(r#"{"id":42}"#));
}

#[tokio::test]
async fn test_echo_server_delayed_response() {
    let server = start_echo_server().await;

    server.push_response(EchoResponse::new(200, "delayed").with_delay(50));

    let stream = tokio::net::TcpStream::connect(server.addr).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = stream;

    let start = std::time::Instant::now();
    stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let mut buf = vec![0u8; 4096];
    let _ = stream.read(&mut buf).await;
    let elapsed = start.elapsed();

    assert!(elapsed.as_millis() >= 40);
}

#[tokio::test]
async fn test_echo_server_multiple_requests() {
    let server = start_echo_server().await;

    for i in 0..3 {
        server.push_response(EchoResponse::new(200, format!("response {}", i)));
    }

    for i in 0..3 {
        let stream = tokio::net::TcpStream::connect(server.addr).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = stream;
        stream
            .write_all(format!("GET /req{} HTTP/1.1\r\n\r\n", i).as_bytes())
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = stream.read(&mut buf).await;
    }

    let captured = server.take_captured();
    assert_eq!(captured.len(), 3);
    assert_eq!(captured[0].path, "/req0");
    assert_eq!(captured[1].path, "/req1");
    assert_eq!(captured[2].path, "/req2");
}
