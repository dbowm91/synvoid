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
    parse_http_request_meta, read_chunked_http_response_body, read_close_delimited_http_response_body,
    read_fixed_http_body, read_fixed_http_response_body, read_http_request_head,
    read_http_response_head, read_http_response_sequence, HttpFramingError,
    HttpResponseBodyEncoding, HttpResponseFramingError, HttpVersion,
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

// ── Close-Delimited Body Overflow Test (Criterion 5) ────────────────────

#[tokio::test]
async fn close_delimited_body_exceeds_limit_returns_body_too_large() {
    use tokio::io::AsyncWriteExt;

    // Send body data exceeding max_body_bytes through a duplex stream.
    let max_body = 5;
    let body_data = b"this body is ten bytes";

    let (mut client, mut server) = tokio::io::duplex(body_data.len());
    client.write_all(body_data).await.unwrap();
    client.shutdown().await.unwrap();

    let result = read_close_delimited_http_response_body(
        &mut server,
        Vec::new(),
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        max_body,
    )
    .await;

    match result {
        Err(HttpResponseFramingError::BodyTooLarge { limit, declared }) => {
            assert_eq!(limit, max_body);
            assert!(declared > max_body);
        }
        other => panic!("expected BodyTooLarge, got: {other:?}"),
    }
}

#[tokio::test]
async fn close_delimited_prefix_exceeds_limit_returns_body_too_large() {
    // Prefix alone exceeds max_body_bytes — rejected immediately.
    let prefix = b"this body is ten bytes".to_vec();
    let max_body = 5;

    let result = read_close_delimited_http_response_body(
        &mut &prefix[..],
        prefix.clone(),
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        max_body,
    )
    .await;

    match result {
        Err(HttpResponseFramingError::BodyTooLarge { limit, declared }) => {
            assert_eq!(limit, max_body);
            assert!(declared > max_body);
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

// ── Phase 38: Chunked Backend Response — Keep-Alive Without EOF ────────────
//
// Verifies the chunked response parser returns the complete response
// (including zero chunk and trailers) without waiting for TCP EOF.
// Uses duplex to avoid real-TCP timing issues while still exercising
// the full parser path.

#[tokio::test]
async fn persistent_backend_chunked_response_returns_without_eof() {
    let headers =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n";
    let body = b"3\r\nabc\r\n2\r\nde\r\n0\r\nX-Checksum: deadbeef\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(headers.len() + body.len());

    // Write headers, read them, then write the chunked body separately
    // so body_prefix is empty and the parser reads from the reader.
    client.write_all(headers).await.unwrap();

    let head = read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
        .await
        .unwrap();

    assert_eq!(head.status_code, 200);
    assert!(head.chunked, "must detect chunked Transfer-Encoding");
    assert!(
        head.body_prefix.is_empty(),
        "body_prefix should be empty when headers read separately"
    );

    // Write the chunked body.
    client.write_all(body).await.unwrap();

    // Do NOT close the client side — proving the parser returns after
    // trailers without waiting for EOF / connection close.
    let start = std::time::Instant::now();
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
    let elapsed = start.elapsed();

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
        body_str.contains("0\r\nX-Checksum: deadbeef\r\n\r\n"),
        "must contain terminating chunk with trailer"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "chunked response should return immediately after trailers, not wait for EOF (took {elapsed:?})"
    );
}

// ── Phase 38: Chunked Backend Response — Premature EOF Test ───────────────
//
// Backend sends a partial chunked response (missing zero chunk) and then
// closes the connection. The parser must reject this as an error rather
// than silently accepting incomplete data.

#[tokio::test]
async fn response_chunked_premature_eof() {
    // Headers + a chunk without the terminating zero chunk. Client side
    // is dropped immediately to simulate backend close.
    let headers = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    let partial_body = b"3\r\nabc\r\n";
    let (mut client, mut server) = tokio::io::duplex(headers.len() + partial_body.len());

    client.write_all(headers).await.unwrap();

    let head = read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
        .await
        .unwrap();

    assert!(head.chunked);

    // Write partial chunked body and close immediately (premature EOF).
    client.write_all(partial_body).await.unwrap();
    client.shutdown().await.unwrap();

    let result = read_chunked_http_response_body(
        &mut server,
        head.body_prefix,
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        65536,
        4096,
    )
    .await;

    assert!(
        result.is_err(),
        "premature EOF must produce an error, got: {result:?}"
    );

    match result.unwrap_err() {
        HttpResponseFramingError::PrematureEof { expected, received } => {
            assert!(
                expected > 0,
                "must indicate expected byte count: expected={expected} received={received}"
            );
        }
        HttpResponseFramingError::MalformedChunkedBody(msg) => {
            assert!(
                msg.contains("EOF") || msg.contains("incomplete"),
                "malformed error must indicate incomplete data: {msg}"
            );
        }
        HttpResponseFramingError::BackendClosedBeforeCompleteResponse => {
            // Acceptable — backend closed before all chunks were received.
        }
        other => {
            panic!("expected PrematureEof, MalformedChunkedBody, or BackendClosed, got: {other:?}")
        }
    }
}

// ── Iteration 80: Fragmented Chunked Body Tests (Criterion 2) ────────────
//
// Verify the prefix-aware chunked parser handles every prefix/socket split
// of chunk-size lines, payloads, CRLFs, zero chunks, and trailers.

/// Helper: build a complete chunked wire body from (size_hex, payload) pairs.
fn build_chunked_wire_body(chunks: &[(&str, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    for (size_hex, payload) in chunks {
        body.extend_from_slice(size_hex.as_bytes());
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(payload);
        body.extend_from_slice(b"\r\n");
    }
    // Zero chunk + empty trailer
    body.extend_from_slice(b"0\r\n\r\n");
    body
}

#[tokio::test]
async fn chunked_prefix_contains_complete_first_chunk_size_line() {
    // Prefix contains: "3\r\n" — a complete chunk-size line.
    let full_wire = build_chunked_wire_body(&[("3", b"abc")]);
    let prefix_end = full_wire.windows(3).position(|w| w == b"3\r\n").unwrap() + 3;
    let prefix = full_wire[..prefix_end].to_vec();
    let rest = &full_wire[prefix_end..];

    let (mut client, mut server) = tokio::io::duplex(prefix.len() + rest.len());
    client.write_all(&prefix).await.unwrap();
    client.write_all(rest).await.unwrap();
    client.shutdown().await.unwrap();

    // Provide empty body_prefix (all bytes in prefix).
    let result = read_chunked_http_response_body(
        &mut server,
        Vec::new(),
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        65536,
        4096,
    )
    .await
    .unwrap();

    assert!(result.windows(3).any(|w| w == b"abc"));
}

#[tokio::test]
async fn chunked_prefix_contains_partial_chunk_size_line() {
    // Prefix contains: "3\r" — missing the trailing \n.
    let full_wire = build_chunked_wire_body(&[("3", b"abc")]);
    let split = full_wire.windows(2).position(|w| w == b"3\r").unwrap() + 2;
    let prefix = full_wire[..split].to_vec();
    let rest = &full_wire[split..];

    let (mut client, mut server) = tokio::io::duplex(prefix.len() + rest.len());
    client.write_all(&prefix).await.unwrap();
    client.write_all(rest).await.unwrap();
    client.shutdown().await.unwrap();

    let result = read_chunked_http_response_body(
        &mut server,
        Vec::new(),
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        65536,
        4096,
    )
    .await
    .unwrap();

    assert!(result.windows(3).any(|w| w == b"abc"));
}

#[tokio::test]
async fn chunked_prefix_contains_size_line_plus_partial_payload() {
    // Prefix contains: "3\r\nab" — size line + 2 of 3 payload bytes.
    let full_wire = build_chunked_wire_body(&[("3", b"abc")]);
    // "3\r\n" is at index 0, then "ab" is 2 more bytes → prefix ends at index 5
    let split = 5;
    let prefix = full_wire[..split].to_vec();
    let rest = &full_wire[split..];

    let (mut client, mut server) = tokio::io::duplex(prefix.len() + rest.len());
    client.write_all(&prefix).await.unwrap();
    client.write_all(rest).await.unwrap();
    client.shutdown().await.unwrap();

    let result = read_chunked_http_response_body(
        &mut server,
        Vec::new(),
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        65536,
        4096,
    )
    .await
    .unwrap();

    assert!(result.windows(3).any(|w| w == b"abc"));
}

#[tokio::test]
async fn chunked_prefix_contains_multiple_complete_chunks() {
    // Prefix contains two complete chunks (size + payload + CRLF for each).
    let full_wire = build_chunked_wire_body(&[("3", b"abc"), ("2", b"de")]);
    let chunk2_payload_end = full_wire.windows(4).position(|w| w == b"de\r\n").unwrap() + 4;
    let prefix = full_wire[..chunk2_payload_end].to_vec();
    let rest = &full_wire[chunk2_payload_end..];

    let (mut client, mut server) = tokio::io::duplex(prefix.len() + rest.len());
    client.write_all(&prefix).await.unwrap();
    client.write_all(rest).await.unwrap();
    client.shutdown().await.unwrap();

    let result = read_chunked_http_response_body(
        &mut server,
        Vec::new(),
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        65536,
        4096,
    )
    .await
    .unwrap();

    assert!(result.windows(3).any(|w| w == b"abc"));
    assert!(result.windows(2).any(|w| w == b"de"));
}

#[tokio::test]
async fn chunked_prefix_contains_entire_body_including_trailers() {
    // All bytes in prefix — parser returns immediately without reading from socket.
    let full_wire = build_chunked_wire_body(&[("3", b"abc")]);
    let (mut _client, mut server) = tokio::io::duplex(1);
    // No socket write needed — all data is in prefix.
    _client.shutdown().await.unwrap();

    let result = read_chunked_http_response_body(
        &mut server,
        full_wire.clone(),
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        65536,
        4096,
    )
    .await
    .unwrap();

    assert_eq!(result, full_wire);
}

#[tokio::test]
async fn chunked_malformed_prefix_still_fails() {
    // Prefix contains garbage — parser must still detect malformed input.
    let prefix = b"ZZ\r\n";
    let (_client, mut server) = tokio::io::duplex(1);
    // No socket write needed — all data is in prefix.

    let result = read_chunked_http_response_body(
        &mut server,
        prefix.to_vec(),
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        65536,
        4096,
    )
    .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn chunked_zero_size_chunk_split_between_prefix_and_socket() {
    // Prefix contains everything up to "0\r\n" (zero chunk size) but not the trailers.
    let full_wire = build_chunked_wire_body(&[("3", b"abc")]);
    let zero_pos = full_wire.windows(3).position(|w| w == b"0\r\n").unwrap();
    let prefix = full_wire[..zero_pos].to_vec();
    let rest = &full_wire[zero_pos..];

    let (mut client, mut server) = tokio::io::duplex(prefix.len() + rest.len());
    client.write_all(&prefix).await.unwrap();
    client.write_all(rest).await.unwrap();
    client.shutdown().await.unwrap();

    let result = read_chunked_http_response_body(
        &mut server,
        Vec::new(),
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        65536,
        4096,
    )
    .await
    .unwrap();

    assert!(result.windows(3).any(|w| w == b"abc"));
}

#[tokio::test]
async fn chunked_trailer_terminator_split_between_prefix_and_socket() {
    // Prefix contains trailers but not the final \r\n terminator.
    let full_wire = build_chunked_wire_body(&[("3", b"abc")]);
    let _trailer_start = full_wire.windows(3).position(|w| w == b"0\r\n").unwrap();
    // Take up to one byte before the final \r\n\r\n.
    let prefix = full_wire[..full_wire.len() - 1].to_vec();
    let rest = &full_wire[full_wire.len() - 1..];

    let (mut client, mut server) = tokio::io::duplex(prefix.len() + rest.len());
    client.write_all(&prefix).await.unwrap();
    client.write_all(rest).await.unwrap();
    client.shutdown().await.unwrap();

    let result = read_chunked_http_response_body(
        &mut server,
        Vec::new(),
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        65536,
        4096,
    )
    .await
    .unwrap();

    assert!(result.windows(3).any(|w| w == b"abc"));
}

// ── Iteration 80: Informational Response Tests (Criterion 6) ────────────
//
// Verify read_http_response_sequence consumes informational responses
// until a final response (>= 200) is obtained.

#[tokio::test]
async fn informational_100_continue_followed_by_fixed_200() {
    let response = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
    let (mut client, mut server) = tokio::io::duplex(response.len());
    client.write_all(response).await.unwrap();
    client.shutdown().await.unwrap();

    let head =
        read_http_response_sequence(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
            .await
            .unwrap();

    assert_eq!(head.status_code, 200);
    assert_eq!(head.content_length, Some(2));
}

#[tokio::test]
async fn informational_103_early_hints_followed_by_chunked_200() {
    let response = b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload; as=style\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(response.len());
    client.write_all(response).await.unwrap();
    client.shutdown().await.unwrap();

    let head =
        read_http_response_sequence(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
            .await
            .unwrap();

    assert_eq!(head.status_code, 200);
    assert!(head.chunked);
}

#[tokio::test]
async fn multiple_informational_before_final() {
    let response = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 102 Processing\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(response.len());
    client.write_all(response).await.unwrap();
    client.shutdown().await.unwrap();

    let head =
        read_http_response_sequence(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
            .await
            .unwrap();

    assert_eq!(head.status_code, 200);
}

#[tokio::test]
async fn informational_101_switching_protocols_rejected() {
    let response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(response.len());
    client.write_all(response).await.unwrap();
    client.shutdown().await.unwrap();

    let result =
        read_http_response_sequence(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
            .await;

    match result {
        Err(HttpResponseFramingError::MalformedStatusLine(msg)) => {
            assert!(msg.contains("101"), "error must mention 101: {msg}");
        }
        other => panic!("expected MalformedStatusLine for 101, got: {other:?}"),
    }
}

#[tokio::test]
async fn informational_backend_closes_without_final_response() {
    // Backend sends 100 Continue then closes without a final response.
    let response = b"HTTP/1.1 100 Continue\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(response.len());
    client.write_all(response).await.unwrap();
    client.shutdown().await.unwrap();

    let result =
        read_http_response_sequence(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
            .await;

    assert!(
        result.is_err(),
        "backend closing after informational must produce error"
    );
}

#[tokio::test]
async fn informational_coalesced_with_final_in_one_read() {
    // All informational + final response in a single write (common case).
    let response = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(response.len());
    client.write_all(response).await.unwrap();
    client.shutdown().await.unwrap();

    let head =
        read_http_response_sequence(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
            .await
            .unwrap();

    assert_eq!(head.status_code, 204);
}

// ── Iteration 80: Chunked Transform-Skip Test (Criterion 8) ────────────
//
// Verify that the response body encoding metadata correctly identifies
// chunked encoding so transforms can be skipped.

#[tokio::test]
async fn response_head_chunked_encoding_detected() {
    let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(response.len());
    client.write_all(response).await.unwrap();
    client.shutdown().await.unwrap();

    let head = read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
        .await
        .unwrap();

    assert!(head.chunked);
    assert_eq!(head.body_encoding, HttpResponseBodyEncoding::Chunked);
}

#[tokio::test]
async fn response_head_content_length_not_chunked() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    let (mut client, mut server) = tokio::io::duplex(response.len());
    client.write_all(response).await.unwrap();
    client.shutdown().await.unwrap();

    let head = read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
        .await
        .unwrap();

    assert!(!head.chunked);
    assert_eq!(head.body_encoding, HttpResponseBodyEncoding::FixedLength);
}

#[tokio::test]
async fn response_head_close_delimited_encoding() {
    let response = b"HTTP/1.0 200 OK\r\n\r\nhello";
    let (mut client, mut server) = tokio::io::duplex(response.len());
    client.write_all(response).await.unwrap();
    client.shutdown().await.unwrap();

    let head = read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
        .await
        .unwrap();

    assert_eq!(head.http_version, HttpVersion::Http10);
    assert_eq!(head.body_encoding, HttpResponseBodyEncoding::CloseDelimited);
}

#[tokio::test]
async fn response_head_version_validated() {
    // Valid HTTP/1.0
    let response = b"HTTP/1.0 200 OK\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(response.len());
    client.write_all(response).await.unwrap();
    client.shutdown().await.unwrap();
    let head = read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
        .await
        .unwrap();
    assert_eq!(head.http_version, HttpVersion::Http10);
    assert_eq!(head.status_code, 200);

    // Valid HTTP/1.1
    let response = b"HTTP/1.1 200 OK\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(response.len());
    client.write_all(response).await.unwrap();
    client.shutdown().await.unwrap();
    let head = read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
        .await
        .unwrap();
    assert_eq!(head.http_version, HttpVersion::Http11);
    assert_eq!(head.status_code, 200);
}

// ── Iteration 80: Close-Delimited Rejection Test (Criterion 9) ─────────
//
// Verify HTTP/1.1 ambiguous close-delimited (no Content-Length, no chunked,
// no Connection: close) is rejected immediately.

// NOTE: The close-delimited rejection logic is in handle_http_proxy_stream which
// requires a full mesh transport setup. These tests verify the version/connection
// metadata that drives the rejection decision.

#[tokio::test]
async fn response_http11_connection_close_detected() {
    let response = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello";
    let (mut client, mut server) = tokio::io::duplex(response.len());
    client.write_all(response).await.unwrap();
    client.shutdown().await.unwrap();

    let head = read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
        .await
        .unwrap();

    assert_eq!(head.http_version, HttpVersion::Http11);
    assert!(head.connection_close);
    assert_eq!(head.body_encoding, HttpResponseBodyEncoding::CloseDelimited);
}

#[tokio::test]
async fn response_http11_token_list_connection_close() {
    // Connection: keep-alive, close — must detect close via token parsing.
    let response = b"HTTP/1.1 200 OK\r\nConnection: keep-alive, close\r\n\r\nhello";
    let (mut client, mut server) = tokio::io::duplex(response.len());
    client.write_all(response).await.unwrap();
    client.shutdown().await.unwrap();

    let head = read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
        .await
        .unwrap();

    assert!(head.connection_close);
}

#[tokio::test]
async fn response_http11_no_length_no_chunked_no_close_ambiguous() {
    // HTTP/1.1 with no Content-Length, no chunked, no Connection: close.
    // This is ambiguous framing — the metadata must reflect this.
    let response = b"HTTP/1.1 200 OK\r\n\r\nhello";
    let (mut client, mut server) = tokio::io::duplex(response.len());
    client.write_all(response).await.unwrap();
    client.shutdown().await.unwrap();

    let head = read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
        .await
        .unwrap();

    assert_eq!(head.http_version, HttpVersion::Http11);
    assert!(!head.chunked);
    assert!(head.content_length.is_none());
    assert!(!head.connection_close);
    // The body_encoding reflects no known framing — handle_http_proxy_stream
    // must reject this as ambiguous for HTTP/1.1.
    assert_eq!(head.body_encoding, HttpResponseBodyEncoding::None);
}

#[tokio::test]
async fn response_version_malformed_rejected() {
    // Invalid HTTP version string.
    let response = b"HTTP/2.0 200 OK\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(response.len());
    client.write_all(response).await.unwrap();
    client.shutdown().await.unwrap();

    let result =
        read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES).await;

    assert!(result.is_err(), "malformed HTTP version must be rejected");
}

// ── Phase 12: Trailer Limit Tests ──────────────────────────────────────
//
// Verify that `read_chunked_http_response_body` enforces
// `max_trailer_bytes` independently of `max_body_bytes`.

#[tokio::test]
async fn trailer_empty_trailer_accepted() {
    let wire = build_chunked_wire_body(&[("3", b"abc")]);
    let result = read_chunked_http_response_body(
        &wire[..],
        Vec::new(),
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        65536,
        4096,
    )
    .await
    .unwrap();

    // Parser includes raw wire bytes; chunk payloads are present.
    assert!(result.windows(3).any(|w| w == b"abc"));
}

#[tokio::test]
async fn trailer_exact_limit_accepted() {
    // Trailer section: "X-C: V\r\n\r\n" = 10 bytes. max_trailer_bytes = 11.
    // The `>` guard at 11 bytes does not fire for 10 trailer bytes.
    let mut wire = Vec::new();
    wire.extend_from_slice(b"3\r\nabc\r\n");
    wire.extend_from_slice(b"0\r\n");
    wire.extend_from_slice(b"X-C: V\r\n\r\n");

    let result = read_chunked_http_response_body(
        &wire[..],
        Vec::new(),
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        65536,
        11,
    )
    .await
    .unwrap();

    assert!(result.windows(3).any(|w| w == b"abc"));
    assert!(result.windows(6).any(|w| w == b"X-C: V"));
}

#[tokio::test]
async fn trailer_limit_plus_one_rejected() {
    // Trailer section: "X-C: VV\r\n\r\n" = 11 bytes. max_trailer_bytes = 10.
    // The `>` guard fires at 11 bytes (11 > 10).
    let mut wire = Vec::new();
    wire.extend_from_slice(b"3\r\nabc\r\n");
    wire.extend_from_slice(b"0\r\n");
    wire.extend_from_slice(b"X-C: VV\r\n\r\n");

    let result = read_chunked_http_response_body(
        &wire[..],
        Vec::new(),
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        65536,
        10,
    )
    .await;

    match result {
        Err(HttpResponseFramingError::TrailerTooLarge { limit, observed }) => {
            assert_eq!(limit, 10);
            assert!(
                observed > limit,
                "observed ({observed}) must exceed limit ({limit})"
            );
        }
        other => panic!("expected TrailerTooLarge, got: {other:?}"),
    }
}

#[tokio::test]
async fn trailer_multiple_fields_counted_cumulatively() {
    // Two trailer fields: "X-A: 1\r\nX-B: 2\r\n\r\n" = 19 bytes.
    // max_trailer_bytes = 15, so the second field pushes over.
    let mut wire = Vec::new();
    wire.extend_from_slice(b"3\r\nabc\r\n");
    wire.extend_from_slice(b"0\r\n");
    wire.extend_from_slice(b"X-A: 1\r\nX-B: 2\r\n\r\n");

    let result = read_chunked_http_response_body(
        &wire[..],
        Vec::new(),
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        65536,
        15,
    )
    .await;

    match result {
        Err(HttpResponseFramingError::TrailerTooLarge { limit, observed }) => {
            assert_eq!(limit, 15);
            assert!(observed > limit);
        }
        other => panic!("expected TrailerTooLarge, got: {other:?}"),
    }
}

#[tokio::test]
async fn trailer_terminator_split_across_prefix_and_socket() {
    // Trailer section "X-C: V\r\n\r\n" = 11 bytes.
    // Prefix holds everything except the final \r\n (10 bytes).
    let mut full_wire = Vec::new();
    full_wire.extend_from_slice(b"3\r\nabc\r\n");
    full_wire.extend_from_slice(b"0\r\n");
    full_wire.extend_from_slice(b"X-C: V\r\n\r\n");

    let prefix = full_wire[..full_wire.len() - 2].to_vec();
    let rest = &full_wire[full_wire.len() - 2..];

    let (mut client, mut server) = tokio::io::duplex(prefix.len() + rest.len());
    client.write_all(&prefix).await.unwrap();
    client.write_all(rest).await.unwrap();
    client.shutdown().await.unwrap();

    let result = read_chunked_http_response_body(
        &mut server,
        Vec::new(),
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        65536,
        4096,
    )
    .await
    .unwrap();

    assert!(result.windows(6).any(|w| w == b"X-C: V"));
}

#[tokio::test]
async fn trailer_oversized_entirely_in_prefix() {
    // Entire oversized trailer is in the prefix — no socket reads needed.
    let mut wire = Vec::new();
    wire.extend_from_slice(b"3\r\nabc\r\n");
    wire.extend_from_slice(b"0\r\n");
    wire.extend_from_slice(b"X-Long: very_long_value\r\n\r\n");

    let result = read_chunked_http_response_body(
        &wire[..],
        Vec::new(),
        IDLE_TIMEOUT,
        TOTAL_TIMEOUT,
        65536,
        10,
    )
    .await;

    match result {
        Err(HttpResponseFramingError::TrailerTooLarge { limit, observed }) => {
            assert_eq!(limit, 10);
            assert!(observed > limit);
        }
        other => panic!("expected TrailerTooLarge, got: {other:?}"),
    }
}

#[tokio::test]
async fn trailer_oversized_slow_drip_bounded_by_total_deadline() {
    use tokio::io::AsyncReadExt;

    // Initial chunk + zero chunk prefix sent immediately.
    let initial = b"3\r\nabc\r\n0\r\n";
    // Trailer byte + terminator sent slowly (one byte at a time).
    let trailer_byte = b'X';
    let terminator = b"\r\n\r\n";
    let total_size = initial.len() + 1 + terminator.len();

    let (mut client, mut server) = tokio::io::duplex(total_size);
    client.write_all(initial).await.unwrap();

    // Spawn a task that dribbles the remaining bytes with real pauses.
    // First byte at ~200ms, second byte at ~400ms — exceeding the 300ms total deadline.
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _ = client.write_all(&[trailer_byte]).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _ = client.write_all(terminator).await;
    });

    let result = read_chunked_http_response_body(
        &mut server,
        Vec::new(),
        Duration::from_millis(100),
        Duration::from_millis(300),
        65536,
        65536,
    )
    .await;

    match result {
        Err(HttpResponseFramingError::Io(msg)) if msg.contains("timeout") => {}
        Err(HttpResponseFramingError::BackendClosedBeforeCompleteResponse) => {}
        other => panic!("expected timeout or backend-closed for slow-drip trailer, got: {other:?}"),
    }
}

// ── Phase 16: Strict Status-Line Parser Tests ──────────────────────────
//
// Verify parse_http_response_status_line validates version and status code.

#[tokio::test]
async fn status_line_valid_100_200_599() {
    // Valid HTTP/1.1 100 Continue
    let resp = b"HTTP/1.1 100 Continue\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(resp.len());
    client.write_all(resp).await.unwrap();
    client.shutdown().await.unwrap();
    let head = read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
        .await
        .unwrap();
    assert_eq!(head.status_code, 100);

    // Valid HTTP/1.1 200 OK
    let resp = b"HTTP/1.1 200 OK\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(resp.len());
    client.write_all(resp).await.unwrap();
    client.shutdown().await.unwrap();
    let head = read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
        .await
        .unwrap();
    assert_eq!(head.status_code, 200);

    // Valid HTTP/1.1 599
    let resp = b"HTTP/1.1 599 Unknown\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(resp.len());
    client.write_all(resp).await.unwrap();
    client.shutdown().await.unwrap();
    let head = read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
        .await
        .unwrap();
    assert_eq!(head.status_code, 599);
}

#[tokio::test]
async fn status_line_invalid_99_600_rejected() {
    // Status 99 — below 100 range.
    let resp = b"HTTP/1.1 099 Bad\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(resp.len());
    client.write_all(resp).await.unwrap();
    client.shutdown().await.unwrap();
    let result =
        read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES).await;
    assert!(result.is_err(), "status 99 must be rejected");

    // Status 600 — above 599 range.
    let resp = b"HTTP/1.1 600 Bad\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(resp.len());
    client.write_all(resp).await.unwrap();
    client.shutdown().await.unwrap();
    let result =
        read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES).await;
    assert!(result.is_err(), "status 600 must be rejected");
}

#[tokio::test]
async fn status_line_non_digit_rejected() {
    let resp = b"HTTP/1.1 abc Bad\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(resp.len());
    client.write_all(resp).await.unwrap();
    client.shutdown().await.unwrap();
    let result =
        read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES).await;
    assert!(result.is_err(), "non-digit status must be rejected");
}

#[tokio::test]
async fn status_line_two_digit_rejected() {
    let resp = b"HTTP/1.1 20 OK\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(resp.len());
    client.write_all(resp).await.unwrap();
    client.shutdown().await.unwrap();
    let result =
        read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES).await;
    assert!(result.is_err(), "two-digit status must be rejected");
}

#[tokio::test]
async fn status_line_four_digit_rejected() {
    let resp = b"HTTP/1.1 1000 Bad\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(resp.len());
    client.write_all(resp).await.unwrap();
    client.shutdown().await.unwrap();
    let result =
        read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES).await;
    assert!(result.is_err(), "four-digit status must be rejected");
}

#[tokio::test]
async fn status_line_unsupported_version_rejected() {
    // HTTP/2.0
    let resp = b"HTTP/2.0 200 OK\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(resp.len());
    client.write_all(resp).await.unwrap();
    client.shutdown().await.unwrap();
    let result =
        read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES).await;
    assert!(result.is_err(), "HTTP/2.0 must be rejected");

    // HTTP/0.9
    let resp = b"HTTP/0.9 200 OK\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(resp.len());
    client.write_all(resp).await.unwrap();
    client.shutdown().await.unwrap();
    let result =
        read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES).await;
    assert!(result.is_err(), "HTTP/0.9 must be rejected");
}

#[tokio::test]
async fn status_line_missing_status_rejected() {
    // Version only, no status code.
    let resp = b"HTTP/1.1 \r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(resp.len());
    client.write_all(resp).await.unwrap();
    client.shutdown().await.unwrap();
    let result =
        read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES).await;
    assert!(result.is_err(), "missing status must be rejected");
}

#[tokio::test]
async fn status_line_empty_reason_phrase_accepted() {
    // Valid with empty reason phrase.
    let resp = b"HTTP/1.1 200 \r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(resp.len());
    client.write_all(resp).await.unwrap();
    client.shutdown().await.unwrap();
    let head = read_http_response_head(&mut server, IDLE_TIMEOUT, TOTAL_TIMEOUT, MAX_HEADER_BYTES)
        .await
        .unwrap();
    assert_eq!(head.status_code, 200);
}
