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
    parse_http_request_meta, read_chunked_http_response_body, read_fixed_http_body,
    read_fixed_http_response_body, read_http_request_head, read_http_response_head,
    HttpFramingError, HttpResponseFramingError,
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

// ── Phase 34: Binary Request Body Test ─────────────────────────────────────

#[tokio::test]
async fn binary_request_body_parsing_succeeds() {
    let headers = b"POST /api/data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\n";
    let body: Vec<u8> = vec![0x48, 0x65, 0x6C, 0x6C, 0x6F, 0xFF, 0xFE, 0x00, 0xAB, 0xCD];
    let full: Vec<u8> = [headers.as_slice(), body.as_slice()].concat();
    let (mut client, mut server) = tokio::io::duplex(full.len());
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
    assert_eq!(head.content_length, Some(10));

    let meta = parse_http_request_meta(&head.header_bytes).unwrap();
    assert_eq!(meta.method, "POST");
    assert_eq!(meta.target, "/api/data");
    assert_eq!(meta.host, "example.com");

    let body_bytes = read_fixed_http_body(
        &mut server,
        head.body_prefix,
        10,
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
    )
    .await
    .unwrap();

    assert_eq!(body_bytes.len(), 10);
    assert_eq!(body_bytes, body.as_slice());
}

// ── Phase 35: No-Body Trailing Bytes Test ──────────────────────────────────

#[tokio::test]
async fn no_body_request_trailing_bytes_detected() {
    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nEXTRA";
    let (mut client, mut server) = tokio::io::duplex(req.len());
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

    assert_eq!(
        head.header_bytes,
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    );
    assert_eq!(head.content_length, None);
    assert_eq!(head.body_prefix, b"EXTRA");
    assert!(!head.body_prefix.is_empty());
}

// ── Phase 36: Exact Upgrade Parsing Tests ──────────────────────────────────

#[test]
fn parse_request_meta_upgrade_exact() {
    // Case 1: exact "Upgrade: websocket" header -> upgrade_requested = true
    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n\r\n";
    let meta = parse_http_request_meta(req).unwrap();
    assert!(
        meta.upgrade_requested,
        "Upgrade header must set upgrade_requested"
    );
    assert!(
        !meta.connection_upgrade,
        "Upgrade header alone must not set connection_upgrade"
    );

    // Case 2: "Connection: keep-alive, Upgrade" plus "Upgrade: websocket" -> both flags true
    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n";
    let meta = parse_http_request_meta(req).unwrap();
    assert!(
        meta.upgrade_requested,
        "Upgrade header must set upgrade_requested"
    );
    assert!(
        meta.connection_upgrade,
        "Connection: Upgrade must set connection_upgrade"
    );

    // Case 3: unrelated header value containing text "upgrade:" -> not falsely detected
    let req =
        b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Custom: this is not upgrade: related\r\n\r\n";
    let meta = parse_http_request_meta(req).unwrap();
    assert!(
        !meta.upgrade_requested,
        "non-Upgrade header must not trigger upgrade"
    );
    assert!(
        !meta.connection_upgrade,
        "non-Connection header must not trigger connection_upgrade"
    );

    // Case 4: header names with mixed case -> parsed correctly
    let req =
        b"GET / HTTP/1.1\r\nHost: example.com\r\nupgrade: websocket\r\nconnection: Upgrade\r\n\r\n";
    let meta = parse_http_request_meta(req).unwrap();
    assert!(
        meta.upgrade_requested,
        "mixed-case upgrade: must be detected"
    );
    assert!(
        meta.connection_upgrade,
        "mixed-case connection: Upgrade must be detected"
    );
}

// ── Phase 37: Response Framing Tests ───────────────────────────────────────

#[tokio::test]
async fn response_head_basic() {
    let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nhello, world!";
    let (mut client, mut server) = tokio::io::duplex(resp.len());
    client.write_all(resp).await.unwrap();

    let head = read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
        .await
        .unwrap();

    assert_eq!(head.status_code, 200);
    assert_eq!(head.content_length, Some(13));
    assert!(!head.chunked);
    assert!(!head.connection_close);
    assert_eq!(head.header_bytes, &resp[..head.header_bytes.len()]);
}

#[tokio::test]
async fn response_head_chunked() {
    let resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(resp.len());
    client.write_all(resp).await.unwrap();

    let head = read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
        .await
        .unwrap();

    assert_eq!(head.status_code, 200);
    assert!(head.chunked);
    assert_eq!(head.content_length, None);
}

#[tokio::test]
async fn response_head_connection_close() {
    let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
    let (mut client, mut server) = tokio::io::duplex(resp.len());
    client.write_all(resp).await.unwrap();

    let head = read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
        .await
        .unwrap();

    assert_eq!(head.status_code, 200);
    assert!(head.connection_close);
    assert_eq!(head.content_length, Some(5));
}

#[tokio::test]
async fn response_fixed_body_exact() {
    let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabcde";
    let (mut client, mut server) = tokio::io::duplex(resp.len());
    client.write_all(resp).await.unwrap();

    let head = read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
        .await
        .unwrap();

    assert_eq!(head.status_code, 200);
    assert_eq!(head.content_length, Some(5));

    let body = read_fixed_http_response_body(
        &mut server,
        head.body_prefix,
        5,
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        65536,
    )
    .await
    .unwrap();

    assert_eq!(body, b"abcde");
}

#[tokio::test]
async fn response_fixed_body_premature_eof() {
    let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort";
    let (mut client, mut server) = tokio::io::duplex(resp.len());
    client.write_all(resp).await.unwrap();
    client.shutdown().await.unwrap();

    let head = read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
        .await
        .unwrap();

    assert_eq!(head.content_length, Some(100));
    let prefix_len = head.body_prefix.len();

    let err = read_fixed_http_response_body(
        &mut server,
        head.body_prefix,
        100,
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        65536,
    )
    .await;

    assert!(err.is_err());
    match err.unwrap_err() {
        HttpResponseFramingError::PrematureEof { expected, received } => {
            assert_eq!(expected, 100 - prefix_len);
            assert_eq!(received, 0);
        }
        other => panic!("expected PrematureEof, got: {other:?}"),
    }
}

#[tokio::test]
async fn response_chunked_body() {
    // 3-byte chunk "abc", 2-byte chunk "de", zero chunk, empty trailer
    let headers = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    let body = b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(headers.len() + body.len());

    // Write headers first, read them, then write body separately
    // so body_prefix is empty and the chunked parser reads from the reader.
    client.write_all(headers).await.unwrap();

    let head = read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
        .await
        .unwrap();

    assert_eq!(head.status_code, 200);
    assert!(head.chunked);
    assert!(head.body_prefix.is_empty());

    // Now write the chunked body data
    client.write_all(body).await.unwrap();
    client.shutdown().await.unwrap();

    let result = read_chunked_http_response_body(
        &mut server,
        head.body_prefix,
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        65536,
        4096,
    )
    .await
    .unwrap();

    let body_str = String::from_utf8_lossy(&result);
    assert!(
        body_str.contains("3\r\nabc\r\n"),
        "must contain first chunk"
    );
    assert!(
        body_str.contains("2\r\nde\r\n"),
        "must contain second chunk"
    );
    assert!(
        body_str.contains("0\r\n\r\n"),
        "must contain terminating chunk"
    );
}

#[tokio::test]
async fn response_chunked_malformed_size() {
    let headers = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    let body = b"ZZ\r\n";
    let (mut client, mut server) = tokio::io::duplex(headers.len() + body.len());

    client.write_all(headers).await.unwrap();

    let head = read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
        .await
        .unwrap();

    assert!(head.chunked);

    // Write the malformed body
    client.write_all(body).await.unwrap();
    client.shutdown().await.unwrap();

    let err = read_chunked_http_response_body(
        &mut server,
        head.body_prefix,
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        65536,
        4096,
    )
    .await;

    assert!(err.is_err());
    match err.unwrap_err() {
        HttpResponseFramingError::MalformedChunkedBody(msg) => {
            assert!(msg.contains("ZZ"), "must mention the bad hex: {msg}");
        }
        other => panic!("expected MalformedChunkedBody, got: {other:?}"),
    }
}

#[tokio::test]
async fn response_no_body_head() {
    // HEAD response: has Content-Length header but no body bytes
    let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(resp.len());
    client.write_all(resp).await.unwrap();

    let head = read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
        .await
        .unwrap();

    assert_eq!(head.status_code, 200);
    assert_eq!(head.content_length, Some(42));
    assert!(head.body_prefix.is_empty());
    // HEAD responses have no body even if Content-Length is present.
    // The caller is responsible for not calling read_fixed_http_response_body for HEAD.
}

#[tokio::test]
async fn response_no_body_204() {
    let resp = b"HTTP/1.1 204 No Content\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(resp.len());
    client.write_all(resp).await.unwrap();

    let head = read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
        .await
        .unwrap();

    assert_eq!(head.status_code, 204);
    assert_eq!(head.content_length, None);
    assert!(!head.chunked);
    assert!(head.body_prefix.is_empty());
}

#[tokio::test]
async fn response_no_body_304() {
    let resp = b"HTTP/1.1 304 Not Modified\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(resp.len());
    client.write_all(resp).await.unwrap();

    let head = read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
        .await
        .unwrap();

    assert_eq!(head.status_code, 304);
    assert_eq!(head.content_length, None);
    assert!(!head.chunked);
    assert!(head.body_prefix.is_empty());
}

// ── Phase 38: Close-Delimited Response ─────────────────────────────────────

#[tokio::test]
async fn response_close_delimited_body() {
    // HTTP/1.0 without Content-Length -> close-delimited
    let resp = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\ndata";
    let (mut client, mut server) = tokio::io::duplex(resp.len());
    client.write_all(resp).await.unwrap();

    let head = read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
        .await
        .unwrap();

    assert_eq!(head.status_code, 200);
    assert!(head.connection_close);
    assert_eq!(head.content_length, None);
    // The body_prefix contains "data" which was coalesced with the headers.
    assert_eq!(head.body_prefix, b"data");
}

// ── Phase 39: Response Body Too Large ──────────────────────────────────────

#[tokio::test]
async fn response_body_too_large() {
    let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(resp.len());
    client.write_all(resp).await.unwrap();

    let head = read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
        .await
        .unwrap();

    assert_eq!(head.content_length, Some(1000));

    let err = read_fixed_http_response_body(
        &mut server,
        head.body_prefix,
        1000,
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        100, // small max_body_bytes
    )
    .await;

    assert!(err.is_err());
    match err.unwrap_err() {
        HttpResponseFramingError::BodyTooLarge { limit, declared } => {
            assert_eq!(limit, 100);
            assert_eq!(declared, 1000);
        }
        other => panic!("expected BodyTooLarge, got: {other:?}"),
    }
}

// ── Phase 40: Conflicting Content-Length in Response ────────────────────────

#[tokio::test]
async fn response_conflicting_content_length_rejected() {
    let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nContent-Length: 20\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(resp.len());
    client.write_all(resp).await.unwrap();

    let err =
        read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES).await;

    assert!(err.is_err());
    match err.unwrap_err() {
        HttpResponseFramingError::InvalidContentLength(msg) => {
            assert!(msg.contains("conflicting"), "unexpected msg: {msg}");
        }
        other => panic!("expected InvalidContentLength, got: {other:?}"),
    }
}

// ── Phase 37: Persistent Backend Fixed-Length Response Test ───────────────
//
// The most important regression test in the pass: a real TCP backend sends
// a complete HTTP/1.1 response with Content-Length and keeps the connection
// open. Synvoid must return the complete response immediately after the
// declared body WITHOUT waiting for TCP EOF.

#[tokio::test]
async fn persistent_backend_returns_without_waiting_for_eof() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Server task: accept one request, send Content-Length response, keep open.
    let server_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // Read the incoming request (read until we see the header terminator).
        let mut req_buf = vec![0u8; 4096];
        let mut req_len = 0;
        loop {
            let n = stream.read(&mut req_buf[req_len..]).await.unwrap();
            req_len += n;
            if req_buf[..req_len].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }

        // Send a complete HTTP/1.1 response with Content-Length.
        // Keep the TCP connection open — do NOT close it.
        let response =
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nhello";
        stream.write_all(response).await.unwrap();
        stream.flush().await.unwrap();

        // Keep the connection alive for 60 seconds (longer than any timeout).
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    // Client: connect and send a request.
    let mut stream = tokio::net::TcpStream::connect(&addr).await.unwrap();
    let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    stream.write_all(request).await.unwrap();

    // Read response using the framing helpers.
    let mut read_buf = [0u8; 1];
    stream.read_exact(&mut read_buf).await.unwrap();

    let start = std::time::Instant::now();
    let head = read_http_response_head(
        &mut stream,
        Duration::from_secs(5),
        Duration::from_secs(10),
        MAX_HEADER_BYTES,
    )
    .await
    .unwrap();

    assert_eq!(head.status_code, 200);
    assert_eq!(head.content_length, Some(5));

    let body = read_fixed_http_response_body(
        &mut stream,
        head.body_prefix,
        5,
        Duration::from_secs(5),
        Duration::from_secs(10),
        65536,
    )
    .await
    .unwrap();

    let elapsed = start.elapsed();

    assert_eq!(body, b"hello");
    assert!(
        elapsed < Duration::from_secs(5),
        "response should return immediately after Content-Length body, not wait for EOF (took {elapsed:?})"
    );

    // Clean up.
    drop(stream);
    server_handle.abort();
}
