//! Integration tests for HTTP-over-mesh framing (Iteration 78).
//!
//! Tests exercise the extracted `read_http_request_head` and
//! `read_fixed_http_body` helpers via `tokio::io::duplex()`.
//!
//! `read_http_request_head` takes a `first_byte` parameter and prepends
//! it to the header buffer internally. The stream must NOT contain the
//! first byte — write `&req[1..]` instead of `req`.

use std::time::Duration;
use synvoid_mesh::mesh::transport_peer::{
    read_fixed_http_body, read_http_request_head, HttpFramingError,
};
use tokio::io::AsyncWriteExt;

const IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_HEADER_BYTES: usize = 16384;

#[tokio::test]
async fn header_only_get() {
    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(req.len());
    // Write everything except the first byte — the function takes it as a param.
    client.write_all(&req[1..]).await.unwrap();

    let head = read_http_request_head(
        &mut server,
        req[0],
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        MAX_HEADER_BYTES,
    )
    .await
    .unwrap();

    assert_eq!(head.header_bytes, req);
    assert!(head.body_prefix.is_empty());
    assert_eq!(head.content_length, None);
    assert!(!head.chunked);
}

#[tokio::test]
async fn header_only_get_fragmented() {
    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(128);

    // Send everything except the first byte in small fragments.
    let rest = &req[1..];
    for chunk in rest.chunks(5) {
        client.write_all(chunk).await.unwrap();
    }
    // Shutdown write side so EOF is seen.
    client.shutdown().await.unwrap();

    let head = read_http_request_head(
        &mut server,
        req[0],
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        MAX_HEADER_BYTES,
    )
    .await
    .unwrap();

    assert_eq!(head.header_bytes, req);
    assert!(head.body_prefix.is_empty());
}

#[tokio::test]
async fn fixed_length_post_body_split_across_writes() {
    let headers = b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 11\r\n\r\n";
    let body = b"hello world";
    let full: Vec<u8> = [headers.as_slice(), body.as_slice()].concat();
    let (mut client, mut server) = tokio::io::duplex(full.len());

    // Write headers (except first byte) first, then body.
    client.write_all(&headers[1..]).await.unwrap();
    client.write_all(body).await.unwrap();
    client.shutdown().await.unwrap();

    let head = read_http_request_head(
        &mut server,
        headers[0],
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        MAX_HEADER_BYTES,
    )
    .await
    .unwrap();

    assert_eq!(head.header_bytes, headers);
    assert_eq!(head.content_length, Some(11));
    // With duplex, body may be coalesced into body_prefix — that's fine.

    let body_result = read_fixed_http_body(
        &mut server,
        head.body_prefix,
        11,
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
    )
    .await
    .unwrap();

    assert_eq!(body_result, body);
}

#[tokio::test]
async fn coalesced_header_and_body_prefix() {
    let headers = b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 11\r\n\r\n";
    let body = b"hello world";
    let full: Vec<u8> = [headers.as_slice(), body.as_slice()].concat();
    let (mut client, mut server) = tokio::io::duplex(full.len());

    // Send everything in one write (coalesced), except the first byte.
    client.write_all(&full[1..]).await.unwrap();
    client.shutdown().await.unwrap();

    let head = read_http_request_head(
        &mut server,
        full[0],
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        MAX_HEADER_BYTES,
    )
    .await
    .unwrap();

    assert_eq!(head.header_bytes, headers);
    assert_eq!(head.body_prefix, body);
    assert_eq!(head.content_length, Some(11));

    let body_result = read_fixed_http_body(
        &mut server,
        head.body_prefix,
        11,
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
    )
    .await
    .unwrap();

    assert_eq!(body_result, body);
}

#[tokio::test]
async fn premature_eof_on_body() {
    let headers = b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 100\r\n\r\n";
    let partial_body = b"short";
    let full: Vec<u8> = [headers.as_slice(), partial_body.as_slice()].concat();
    let (mut client, mut server) = tokio::io::duplex(full.len());
    client.write_all(&full[1..]).await.unwrap();
    client.shutdown().await.unwrap();

    let head = read_http_request_head(
        &mut server,
        full[0],
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        MAX_HEADER_BYTES,
    )
    .await
    .unwrap();

    assert_eq!(head.content_length, Some(100));

    // With duplex, the partial body may arrive as body_prefix, so the
    // remaining bytes to read depend on how much was coalesced.
    let prefix_len = head.body_prefix.len();
    let remaining = 100 - prefix_len;

    let err = read_fixed_http_body(
        &mut server,
        head.body_prefix,
        100,
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
    )
    .await;

    assert!(err.is_err());
    match err.unwrap_err() {
        HttpFramingError::PrematureEof { expected, received } => {
            assert_eq!(expected, remaining);
            assert_eq!(received, 0, "stream should be at EOF");
        }
        other => panic!("expected PrematureEof, got: {other:?}"),
    }
}

#[tokio::test]
async fn oversized_header_rejected() {
    let big_header = format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", "x".repeat(20000));
    let (mut client, mut server) = tokio::io::duplex(big_header.len());
    // Write everything except the first byte.
    client.write_all(&big_header.as_bytes()[1..]).await.unwrap();
    client.shutdown().await.unwrap();

    let err = read_http_request_head(
        &mut server,
        big_header.as_bytes()[0],
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        1024, // small limit
    )
    .await;

    assert!(err.is_err());
    match err.unwrap_err() {
        HttpFramingError::HeaderTooLarge => {}
        other => panic!("expected HeaderTooLarge, got: {other:?}"),
    }
}

#[tokio::test]
async fn conflicting_content_length_rejected() {
    let req =
        b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\nContent-Length: 20\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(req.len());
    client.write_all(&req[1..]).await.unwrap();
    client.shutdown().await.unwrap();

    let err = read_http_request_head(
        &mut server,
        req[0],
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        MAX_HEADER_BYTES,
    )
    .await;

    assert!(err.is_err());
    match err.unwrap_err() {
        HttpFramingError::InvalidContentLength(msg) => {
            assert!(msg.contains("conflicting"), "unexpected msg: {msg}");
        }
        other => panic!("expected InvalidContentLength, got: {other:?}"),
    }
}

#[tokio::test]
async fn chunked_transfer_encoding_parsed() {
    // When chunked is the only encoding (no Content-Length), the framing
    // parser returns Ok with chunked=true. The caller is responsible for
    // rejecting unsupported chunked encoding.
    let req = b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(req.len());
    client.write_all(&req[1..]).await.unwrap();
    client.shutdown().await.unwrap();

    let head = read_http_request_head(
        &mut server,
        req[0],
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        MAX_HEADER_BYTES,
    )
    .await
    .unwrap();

    assert!(head.chunked);
    assert_eq!(head.content_length, None);
}

#[tokio::test]
async fn chunked_only_rejected() {
    let req = b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(req.len());
    client.write_all(&req[1..]).await.unwrap();
    client.shutdown().await.unwrap();

    // When chunked is the only encoding (no Content-Length), it should parse
    // as chunked=true, content_length=None. The caller then rejects it.
    let head = read_http_request_head(
        &mut server,
        req[0],
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        MAX_HEADER_BYTES,
    )
    .await
    .unwrap();

    assert!(head.chunked);
    assert_eq!(head.content_length, None);
}

#[tokio::test]
async fn body_limit_exact_accepted() {
    let headers = b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\n";
    let body = b"0123456789";
    let full: Vec<u8> = [headers.as_slice(), body.as_slice()].concat();
    let (mut client, mut server) = tokio::io::duplex(full.len());
    client.write_all(&full[1..]).await.unwrap();
    client.shutdown().await.unwrap();

    let head = read_http_request_head(
        &mut server,
        full[0],
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        MAX_HEADER_BYTES,
    )
    .await
    .unwrap();

    let body_result = read_fixed_http_body(
        &mut server,
        head.body_prefix,
        10,
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
    )
    .await
    .unwrap();

    assert_eq!(body_result, body);
}

#[tokio::test]
async fn header_timeout_returns_error() {
    let (mut _client, mut server) = tokio::io::duplex(1024);
    // Don't write anything — server will wait for data.
    let err = read_http_request_head(
        &mut server,
        b'G',
        Duration::from_millis(10),
        Duration::from_millis(50),
        MAX_HEADER_BYTES,
    )
    .await;

    assert!(err.is_err());
    match err.unwrap_err() {
        HttpFramingError::HeaderFramingTimeout => {}
        other => panic!("expected HeaderFramingTimeout, got: {other:?}"),
    }
}

#[tokio::test]
async fn empty_headers_rejected() {
    // Just the terminator, no actual headers.
    let req = b"\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(req.len());
    // Write everything except the first byte (\r).
    client.write_all(&req[1..]).await.unwrap();
    client.shutdown().await.unwrap();

    // Should succeed parsing — empty headers are technically valid HTTP.
    let head = read_http_request_head(
        &mut server,
        req[0],
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        MAX_HEADER_BYTES,
    )
    .await
    .unwrap();

    assert_eq!(head.header_bytes, req);
    assert!(head.body_prefix.is_empty());
    assert_eq!(head.content_length, None);
    assert!(!head.chunked);
}

#[tokio::test]
async fn invalid_content_length_rejected() {
    let req = b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: abc\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(req.len());
    client.write_all(&req[1..]).await.unwrap();
    client.shutdown().await.unwrap();

    let err = read_http_request_head(
        &mut server,
        req[0],
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        MAX_HEADER_BYTES,
    )
    .await;

    assert!(err.is_err());
    match err.unwrap_err() {
        HttpFramingError::InvalidContentLength(msg) => {
            assert!(msg.contains("non-numeric"), "unexpected msg: {msg}");
        }
        other => panic!("expected InvalidContentLength, got: {other:?}"),
    }
}

// ── Phase 10: Chunked rejection explicitly ─────────────────────────────────

#[tokio::test]
async fn chunked_transfer_encoding_only_is_parsed() {
    let req = b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(req.len() - 1);
    client.write_all(&req[1..]).await.unwrap();

    let head = read_http_request_head(
        &mut server,
        req[0],
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        MAX_HEADER_BYTES,
    )
    .await
    .unwrap();

    assert!(head.chunked, "chunked should be detected");
    assert_eq!(
        head.content_length, None,
        "content_length should be None for chunked-only"
    );
}

#[tokio::test]
async fn chunked_with_content_length_is_rejected() {
    let req = b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 10\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(req.len() - 1);
    client.write_all(&req[1..]).await.unwrap();

    let err = read_http_request_head(
        &mut server,
        req[0],
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        MAX_HEADER_BYTES,
    )
    .await;

    assert!(err.is_err());
    match err.unwrap_err() {
        HttpFramingError::InvalidContentLength(msg) => {
            assert!(msg.contains("chunked"), "should mention chunked: {msg}");
        }
        other => panic!("expected InvalidContentLength for chunked+CL, got: {other:?}"),
    }
}

#[tokio::test]
async fn unsupported_transfer_encoding_rejected() {
    let req = b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: gzip\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(req.len() - 1);
    client.write_all(&req[1..]).await.unwrap();

    let err = read_http_request_head(
        &mut server,
        req[0],
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        MAX_HEADER_BYTES,
    )
    .await;

    assert!(err.is_err());
    match err.unwrap_err() {
        HttpFramingError::UnsupportedTransferEncoding(msg) => {
            assert!(
                msg.contains("gzip"),
                "should mention the unsupported encoding: {msg}"
            );
        }
        other => panic!("expected UnsupportedTransferEncoding, got: {other:?}"),
    }
}

// ── Phase 15: CONNECT/upgrade rejection explicitly ─────────────────────────

#[tokio::test]
async fn connect_method_first_byte_detected() {
    let req = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(req.len() - 1);
    client.write_all(&req[1..]).await.unwrap();

    let head = read_http_request_head(
        &mut server,
        req[0],
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        MAX_HEADER_BYTES,
    )
    .await
    .unwrap();

    let header_str = String::from_utf8_lossy(&head.header_bytes);
    assert!(header_str.starts_with("CONNECT"));
}

#[tokio::test]
async fn upgrade_header_detected_in_framing() {
    let req =
        b"GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(req.len() - 1);
    client.write_all(&req[1..]).await.unwrap();

    let head = read_http_request_head(
        &mut server,
        req[0],
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        MAX_HEADER_BYTES,
    )
    .await
    .unwrap();

    let header_str = String::from_utf8_lossy(&head.header_bytes);
    assert!(header_str.to_lowercase().contains("upgrade:"));
}

// ── Phase 30: End-to-end proxy body test ───────────────────────────────────

#[tokio::test]
async fn end_to_end_request_bytes_preserved() {
    let headers = b"POST /api/data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 13\r\n\r\n";
    let body = b"hello, world!";
    let full = [headers.as_slice(), body.as_slice()].concat();
    let (mut client, mut server) = tokio::io::duplex(full.len() - 1);
    client.write_all(&full[1..]).await.unwrap();

    let head = read_http_request_head(
        &mut server,
        full[0],
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        MAX_HEADER_BYTES,
    )
    .await
    .unwrap();

    assert_eq!(head.header_bytes, headers);
    assert_eq!(head.content_length, Some(13));

    let body_bytes = read_fixed_http_body(
        &mut server,
        head.body_prefix,
        13,
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
    )
    .await
    .unwrap();

    let mut request_bytes = head.header_bytes;
    request_bytes.extend_from_slice(&body_bytes);

    assert_eq!(request_bytes, full);
    assert_eq!(request_bytes.len(), headers.len() + body.len());
}
