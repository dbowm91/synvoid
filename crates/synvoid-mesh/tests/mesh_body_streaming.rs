//! Bounded body streaming for mesh forwarding (Phase 04).
//!
//! The helpers copy request/response bodies incrementally with the same
//! framing bytes the backend produced, so response transforms and framing are
//! preserved while memory stays bounded per stream.

use std::time::Duration;

use synvoid_mesh::transport_peer::{
    stream_chunked_http_body, stream_close_delimited_http_body, stream_fixed_http_body,
    HttpResponseFramingError,
};
use tokio::io::AsyncWriteExt;

const IDLE: Duration = Duration::from_secs(5);
const TOTAL: Duration = Duration::from_secs(30);

#[tokio::test]
async fn fixed_body_over_64_kib_streams_whole_payload() {
    let body = vec![b'x'; 100 * 1024];
    let body_for_writer = body.clone();
    let (mut client, server) = tokio::io::duplex(8 * 1024);

    let writer = tokio::spawn(async move {
        client.write_all(&body_for_writer).await.unwrap();
        client.shutdown().await.unwrap();
    });

    let mut out = Vec::new();
    let written = stream_fixed_http_body(
        server,
        Vec::new(),
        body.len(),
        &mut out,
        IDLE,
        TOTAL,
        body.len(),
    )
    .await
    .unwrap();
    writer.await.unwrap();

    assert_eq!(written, body.len());
    assert_eq!(out, body);
}

#[tokio::test]
async fn fixed_body_cap_is_enforced_before_copying() {
    let (mut client, server) = tokio::io::duplex(1024);
    let mut out = Vec::new();
    let error = stream_fixed_http_body(server, Vec::new(), 2048, &mut out, IDLE, TOTAL, 1024)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        HttpResponseFramingError::BodyTooLarge { limit: 1024, .. }
    ));
    assert!(out.is_empty());
    let _ = client.shutdown().await;
}

#[tokio::test]
async fn chunked_body_preserves_framing_and_trailers() {
    let wire = b"5\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: yes\r\n\r\n";
    let wire_vec = wire.to_vec();
    let (mut client, server) = tokio::io::duplex(1024);
    let writer = tokio::spawn(async move {
        client.write_all(&wire_vec).await.unwrap();
        client.shutdown().await.unwrap();
    });

    let mut out = Vec::new();
    let written = stream_chunked_http_body(
        server,
        Vec::new(),
        &mut out,
        IDLE,
        TOTAL,
        wire.len(),
        wire.len(),
    )
    .await
    .unwrap();
    writer.await.unwrap();

    assert_eq!(written, wire.len());
    assert_eq!(out, wire);
}

#[tokio::test]
async fn chunked_body_with_coalesced_prefix_is_not_duplicated() {
    let wire = b"4\r\nbody\r\n0\r\n\r\n";
    let prefix = wire[..10].to_vec();
    let rest = wire[10..].to_vec();
    let (mut client, server) = tokio::io::duplex(1024);
    let writer = tokio::spawn(async move {
        client.write_all(&rest).await.unwrap();
        client.shutdown().await.unwrap();
    });

    let mut out = Vec::new();
    stream_chunked_http_body(
        server,
        prefix,
        &mut out,
        IDLE,
        TOTAL,
        wire.len(),
        wire.len(),
    )
    .await
    .unwrap();
    writer.await.unwrap();

    assert_eq!(out, wire);
}

#[tokio::test]
async fn chunked_body_exceeding_cap_fails_closed() {
    let wire = b"5\r\nhello\r\n0\r\n\r\n";
    let wire_vec = wire.to_vec();
    let (mut client, server) = tokio::io::duplex(1024);
    let writer = tokio::spawn(async move {
        let _ = client.write_all(&wire_vec).await;
        let _ = client.shutdown().await;
    });

    let mut out = Vec::new();
    let error = stream_chunked_http_body(server, Vec::new(), &mut out, IDLE, TOTAL, 8, 64)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        HttpResponseFramingError::BodyTooLarge { limit: 8, .. }
    ));
    let _ = writer.await;
}

#[tokio::test]
async fn close_delimited_body_streams_until_eof() {
    let body = b"close-delimited payload".to_vec();
    let body_for_writer = body.clone();
    let (mut client, server) = tokio::io::duplex(1024);
    let writer = tokio::spawn(async move {
        client.write_all(&body_for_writer).await.unwrap();
        client.shutdown().await.unwrap();
    });

    let mut out = Vec::new();
    let written = stream_close_delimited_http_body(server, Vec::new(), &mut out, IDLE, TOTAL, 1024)
        .await
        .unwrap();
    writer.await.unwrap();

    assert_eq!(written, body.len());
    assert_eq!(out, body);
}
